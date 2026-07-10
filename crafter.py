"""
Packet crafter.

Builds packets from a JSON spec sent by the UI and transmits them with Scapy.
Supports layer 2 (Ethernet) and layer 3 (IP/IPv6) sends so it works both for
crafted frames on a lab segment and ordinary routed packets.

Intended for authorised testing on networks and hosts you own or are permitted
to test (lab VMs, your own segment, IDS/firewall validation).
"""

import random
import time
from typing import Optional

from scapy.all import send, sendp, srp1, conf
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw

import selftraffic

_mac_cache: dict = {}


def _arp_target_and_iface(dst_ip: str, iface):
    """Pick the IP to ARP for (gateway if off-subnet, else the destination) and
    the interface to use (the route's interface when none was chosen)."""
    gw = "0.0.0.0"
    route_iface = None
    try:
        route_iface, _src, gw = conf.route.route(dst_ip)
    except Exception:
        pass
    if not iface:
        iface = route_iface
    target = dst_ip if (not gw or gw == "0.0.0.0") else gw
    return target, iface


def _resolve_mac(target_ip: str, iface) -> Optional[str]:
    key = (target_ip, iface)
    if key in _mac_cache:
        return _mac_cache[key]
    mac = None
    try:
        ans = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip),
                   iface=iface, timeout=2, retry=1, verbose=0)
        if ans is not None and ans.haslayer(ARP):
            mac = ans[ARP].hwsrc
    except Exception:
        mac = None
    if mac:
        _mac_cache[key] = mac
    return mac


def _build(spec: dict):
    """Turn a spec dict into a Scapy packet. Returns (packet, uses_layer2)."""
    pkt = None
    uses_l2 = False
    ip_src_set = False
    ipv4_dst = None

    eth = spec.get("ether")
    if eth:
        uses_l2 = True
        e = Ether()
        if eth.get("src"):
            e.src = eth["src"]
        if eth.get("dst"):
            e.dst = eth["dst"]
        pkt = e

    net = spec.get("ip")
    ipv6 = spec.get("ipv6")
    if net:
        layer = IP()
        if net.get("src"):
            layer.src = net["src"]
            ip_src_set = True
        if not net.get("dst"):
            raise ValueError("IP destination address is required.")
        layer.dst = net["dst"]
        ipv4_dst = net["dst"]
        if net.get("ttl") not in (None, ""):
            layer.ttl = int(net["ttl"])
        pkt = layer if pkt is None else pkt / layer
    elif ipv6:
        layer = IPv6()
        if ipv6.get("src"):
            layer.src = ipv6["src"]
        if not ipv6.get("dst"):
            raise ValueError("IPv6 destination address is required.")
        layer.dst = ipv6["dst"]
        pkt = layer if pkt is None else pkt / layer

    transport = spec.get("transport")
    if transport:
        kind = transport.get("kind")
        if kind == "tcp":
            t = TCP()
            if transport.get("sport") not in (None, ""):
                t.sport = int(transport["sport"])
            else:
                # Pin a concrete source port ourselves (instead of leaving
                # Scapy's volatile RandShort() default) so it can be
                # registered as Network Companion's own traffic before send.
                t.sport = random.randint(20000, 60000)
            if transport.get("dport") not in (None, ""):
                t.dport = int(transport["dport"])
            if transport.get("flags"):
                t.flags = transport["flags"]
            if transport.get("seq") not in (None, ""):
                t.seq = int(transport["seq"])
            pkt = t if pkt is None else pkt / t
        elif kind == "udp":
            u = UDP()
            if transport.get("sport") not in (None, ""):
                u.sport = int(transport["sport"])
            else:
                u.sport = random.randint(20000, 60000)
            if transport.get("dport") not in (None, ""):
                u.dport = int(transport["dport"])
            pkt = u if pkt is None else pkt / u
        elif kind == "icmp":
            ic = ICMP()
            if transport.get("icmp_type") not in (None, ""):
                ic.type = int(transport["icmp_type"])
            if transport.get("icmp_code") not in (None, ""):
                ic.code = int(transport["icmp_code"])
            pkt = ic if pkt is None else pkt / ic

    payload = spec.get("payload")
    if payload:
        as_hex = spec.get("payload_is_hex", False)
        try:
            data = bytes.fromhex(payload.replace(" ", "")) if as_hex else payload.encode()
        except ValueError:
            raise ValueError("Payload is not valid hex.")
        pkt = Raw(load=data) if pkt is None else pkt / Raw(load=data)

    if pkt is None:
        raise ValueError("Nothing to send: add at least one layer.")
    return pkt, uses_l2, ip_src_set, ipv4_dst


def _mark_self(pkt, ttl: float):
    """Register this packet's TCP/UDP source port so the capture engine can
    recognise it as Network Companion's own traffic (see selftraffic.py)."""
    try:
        if pkt.haslayer(TCP):
            selftraffic.mark_port(pkt[TCP].sport, ttl=ttl)
        elif pkt.haslayer(UDP):
            selftraffic.mark_port(pkt[UDP].sport, ttl=ttl)
    except Exception:
        pass


def craft_and_send(spec: dict) -> dict:
    """Build and transmit a packet. Returns a summary of what was sent.

    If a custom IPv4 source is set, the packet is sent at layer 2 (with a
    crafted Ethernet header) so the operating system cannot rewrite the source
    address to the outgoing interface's real IP. That is the only way to put an
    arbitrary source on the wire.
    """
    count = int(spec.get("count", 1) or 1)
    if count < 1 or count > 1000:
        raise ValueError("Count must be between 1 and 1000.")
    interval = float(spec.get("interval", 0) or 0) / 1000.0  # ms -> seconds
    if interval < 0 or interval > 60:
        raise ValueError("Interval must be between 0 and 60000 ms.")

    pkt, uses_l2, ip_src_set, ipv4_dst = _build(spec)
    iface = spec.get("iface") or None
    note = None

    # A custom source only survives on the wire if we build the L2 frame
    # ourselves. Promote to layer 2 and address the frame to the next hop.
    if ip_src_set and not uses_l2 and ipv4_dst:
        src_ip = spec.get("ip", {}).get("src")
        target_ip, iface = _arp_target_and_iface(ipv4_dst, iface)
        mac = _resolve_mac(target_ip, iface)
        if mac is None:
            mac = "ff:ff:ff:ff:ff:ff"
            note = (f"Source {src_ip} kept by sending at layer 2, but {target_ip} "
                    f"did not answer ARP, so the broadcast MAC was used. That still "
                    f"reaches hosts on this segment; an off-subnet target may not get it. "
                    f"Check that the crafter interface is on the target's network.")
        else:
            note = (f"Source {src_ip} preserved by sending at layer 2 "
                    f"(next hop {target_ip} is {mac}).")
        pkt = Ether(dst=mac) / pkt
        uses_l2 = True

    _mark_self(pkt, ttl=max(10.0, count * interval + 5.0))
    start = time.time()
    if uses_l2:
        sendp(pkt, count=count, inter=interval, iface=iface, verbose=False)
    else:
        send(pkt, count=count, inter=interval, iface=iface, verbose=False)
    elapsed = time.time() - start

    out = {
        "sent": count,
        "elapsed": round(elapsed, 4),
        "layer": "L2 (sendp)" if uses_l2 else "L3 (send)",
        "summary": pkt.summary(),
        "length": len(pkt),
    }
    if note:
        out["note"] = note
    return out


def resend(pkt, count: int = 1, interval: float = 0.0, iface=None) -> dict:
    """Re-transmit an already-captured Scapy packet as-is (replay).

    Sends at layer 2 when the captured frame still has its Ethernet header
    (the usual case for sniffed packets), otherwise at layer 3.
    """
    count = int(count or 1)
    if count < 1 or count > 1000:
        raise ValueError("Count must be between 1 and 1000.")
    has_l2 = pkt.haslayer(Ether)
    _mark_self(pkt, ttl=max(10.0, count * interval + 5.0))
    start = time.time()
    if has_l2:
        sendp(pkt, count=count, inter=interval, iface=iface, verbose=False)
    else:
        send(pkt, count=count, inter=interval, iface=iface, verbose=False)
    return {
        "sent": count,
        "elapsed": round(time.time() - start, 4),
        "layer": "L2 (sendp)" if has_l2 else "L3 (send)",
        "summary": pkt.summary(),
        "length": len(pkt),
    }


def preview(spec: dict) -> dict:
    """Build a packet without sending it, for the crafter preview panel."""
    pkt, uses_l2, ip_src_set, ipv4_dst = _build(spec)
    layer = "L2 (sendp)" if uses_l2 else "L3 (send)"
    note = None
    if ip_src_set and not uses_l2 and ipv4_dst:
        layer = "L2 (sendp) - auto"
        note = ("A custom source is set, so this is sent at layer 2 to keep that "
                "source address on the wire.")
    out = {
        "summary": pkt.summary(),
        "length": len(pkt),
        "layer": layer,
        "show": pkt.show(dump=True),
    }
    if note:
        out["note"] = note
    return out
