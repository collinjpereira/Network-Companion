"""
Process attribution.

Maps a captured packet back to the local process that owns the socket, so an
analyst can see which program on this host is responsible for a flow, which
is handy for spotting a beaconing process during malware triage.

This only works for the machine actually running the capture; it can't name
processes on a PlayStation, phone, or any other device on the network. The
socket table is also just a live snapshot, so very short-lived connections
may be gone by the time you click a packet, making any match best-effort.
"""

from typing import Optional

try:
    import psutil
except Exception:
    psutil = None

from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.inet6 import IPv6


def _local_endpoints(pkt):
    """Yield candidate (ip, port) local endpoints from the packet."""
    ip = None
    if pkt.haslayer(IP):
        ip = pkt[IP]
    elif pkt.haslayer(IPv6):
        ip = pkt[IPv6]
    if ip is None:
        return []
    port_layer = pkt[TCP] if pkt.haslayer(TCP) else (pkt[UDP] if pkt.haslayer(UDP) else None)
    if port_layer is None:
        return []
    # Either side could be the local socket; try both.
    return [(ip.src, port_layer.sport), (ip.dst, port_layer.dport)]


def process_for(pkt) -> Optional[dict]:
    """Best-effort lookup of the local process behind this packet."""
    if psutil is None:
        return {"available": False, "reason": "psutil not installed"}

    candidates = _local_endpoints(pkt)
    if not candidates:
        return None

    proto_kind = "tcp" if pkt.haslayer(TCP) else ("udp" if pkt.haslayer(UDP) else None)
    if proto_kind is None:
        return None

    try:
        conns = psutil.net_connections(kind=proto_kind)
    except Exception as exc:
        return {"available": False, "reason": str(exc)}

    wanted = {(ip, port) for ip, port in candidates}
    for c in conns:
        if not c.laddr:
            continue
        laddr = (c.laddr.ip, c.laddr.port)
        # Match either on exact local IP or on port with a wildcard bind.
        if laddr in wanted or (("0.0.0.0", laddr[1]) and any(laddr[1] == p for _, p in wanted)):
            if laddr[1] not in {p for _, p in wanted}:
                continue
            pid = c.pid
            name = "unknown"
            if pid:
                try:
                    name = psutil.Process(pid).name()
                except Exception:
                    name = "unknown"
            return {
                "available": True,
                "pid": pid,
                "name": name,
                "laddr": f"{c.laddr.ip}:{c.laddr.port}",
                "status": getattr(c, "status", ""),
            }
    return {"available": True, "pid": None, "name": None,
            "note": "No matching local socket (flow may have closed or is on another host)."}
