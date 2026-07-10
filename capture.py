"""
Capture engine.

Wraps Scapy's AsyncSniffer so packets can be streamed to the web UI over a
WebSocket in real time, while the raw Scapy packet objects are retained in
memory so full detail views and PCAP export stay accurate.
"""

import time
import threading
from typing import Optional, List, Callable

from scapy.all import AsyncSniffer, get_working_ifaces, wrpcap, conf
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw

try:
    from scapy.layers.dns import DNS
except Exception:  # pragma: no cover - DNS layer should always be present
    DNS = None

import threat as threat_mod
import procmap
import selftraffic


# TCP flag bit -> readable name, in the order Wireshark shows them.
_TCP_FLAG_NAMES = [
    ("F", "FIN"),
    ("S", "SYN"),
    ("R", "RST"),
    ("P", "PSH"),
    ("A", "ACK"),
    ("U", "URG"),
    ("E", "ECE"),
    ("C", "CWR"),
]

# Well-known ports used to give a packet a more descriptive protocol label than
# just "TCP"/"UDP". Kept small on purpose; the detail view carries the rest.
_TCP_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 587: "SMTP", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP", 8443: "HTTPS",
}
_UDP_PORTS = {
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 123: "NTP",
    137: "NBNS", 161: "SNMP", 162: "SNMP", 500: "IKE", 514: "Syslog",
    1900: "SSDP", 5353: "mDNS",
}

_HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ",
                 b"OPTIONS ", b"PATCH ", b"CONNECT ")


def _parse_http_request(data: bytes):
    """Pull the request line and Host header out of a plaintext HTTP request.

    Returns (request_line, host) or None. Only looks at the first packet of
    a request, so a Host header split across TCP segments won't be found.
    """
    if not data.startswith(_HTTP_METHODS):
        return None
    head = data.split(b"\r\n\r\n", 1)[0]
    try:
        lines = head.decode("latin-1").split("\r\n")
    except Exception:
        return None
    request_line = lines[0].strip()
    host = None
    for line in lines[1:]:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            break
    return request_line, host


def _parse_tls_sni(data: bytes):
    """Pull the SNI hostname out of a TLS ClientHello, if this packet has one.

    The hostname in a TLS ClientHello travels in cleartext even over HTTPS,
    so this is the main way to see what site a device is reaching without
    breaking the TLS session. Only handles a ClientHello that fits in a
    single TCP segment, which covers the normal case.
    """
    if len(data) < 6 or data[0] != 0x16 or data[1] != 0x03:
        return None
    try:
        record_len = int.from_bytes(data[3:5], "big")
        body = data[5:5 + record_len]
        if not body or body[0] != 0x01:  # ClientHello
            return None
        pos = 4 + 2 + 32  # handshake header + client version + random
        sid_len = body[pos]
        pos += 1 + sid_len
        cs_len = int.from_bytes(body[pos:pos + 2], "big")
        pos += 2 + cs_len
        cm_len = body[pos]
        pos += 1 + cm_len
        if pos + 2 > len(body):
            return None
        ext_total = int.from_bytes(body[pos:pos + 2], "big")
        pos += 2
        end = pos + ext_total
        while pos + 4 <= end and pos + 4 <= len(body):
            ext_type = int.from_bytes(body[pos:pos + 2], "big")
            ext_len = int.from_bytes(body[pos + 2:pos + 4], "big")
            pos += 4
            if ext_type == 0:  # server_name
                sni = body[pos:pos + ext_len]
                name_len = int.from_bytes(sni[3:5], "big")
                return sni[5:5 + name_len].decode("ascii", errors="replace")
            pos += ext_len
    except Exception:
        return None
    return None


def _payload_hint(pkt):
    """Best-effort (label, host) pulled from an HTTP request or TLS
    ClientHello riding on this packet, or None if neither applies."""
    if not pkt.haslayer(TCP):
        return None
    raw = pkt.getlayer(Raw)
    if raw is None:
        return None
    data = bytes(raw.load)
    if not data:
        return None
    http = _parse_http_request(data)
    if http:
        request_line, host = http
        return ("HTTP", host, request_line)
    sni = _parse_tls_sni(data)
    if sni:
        return ("TLS SNI", sni, None)
    return None


def _safe(value):
    """Coerce a Scapy field value into something JSON serialisable."""
    if isinstance(value, (int, float, str, bool)) or value is None:
        return value
    if isinstance(value, bytes):
        # Show short byte strings as hex, longer ones truncated.
        h = value.hex()
        return h if len(h) <= 96 else h[:96] + "..."
    if isinstance(value, (list, tuple)):
        return [_safe(v) for v in value]
    try:
        return str(value)
    except Exception:
        return "<unreadable>"


def _tcp_flag_list(flags) -> List[str]:
    names = []
    fstr = str(flags)
    for bit, name in _TCP_FLAG_NAMES:
        if bit in fstr:
            names.append(name)
    return names


def get_protocol(pkt) -> str:
    """Return the most descriptive protocol label for the summary row."""
    if DNS is not None and pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        return _TCP_PORTS.get(tcp.dport) or _TCP_PORTS.get(tcp.sport) or "TCP"
    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        return _UDP_PORTS.get(udp.dport) or _UDP_PORTS.get(udp.sport) or "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(IPv6):
        return "IPv6"
    if pkt.haslayer(IP):
        return "IPv4"
    if pkt.haslayer(Ether):
        return "Ethernet"
    try:
        return pkt.lastlayer().name
    except Exception:
        return "Unknown"


def _addresses(pkt):
    """Best-effort (source, destination) pair, preferring L3 over L2."""
    if pkt.haslayer(IP):
        return pkt[IP].src, pkt[IP].dst
    if pkt.haslayer(IPv6):
        return pkt[IPv6].src, pkt[IPv6].dst
    if pkt.haslayer(ARP):
        return pkt[ARP].psrc, pkt[ARP].pdst
    if pkt.haslayer(Ether):
        return pkt[Ether].src, pkt[Ether].dst
    return "", ""


def _ptr_qname_to_ip(qname: str):
    """Reverse an IPv4 in-addr.arpa PTR query name back into an IP, or None.

    IPv6 (ip6.arpa nibble format) reverse queries aren't handled; the
    "Resolve names" feature is the only source of these self-generated
    queries and misclassifying one just leaves it in the main capture.
    """
    qname = qname.rstrip(".")
    if not qname.endswith(".in-addr.arpa"):
        return None
    octets = qname[: -len(".in-addr.arpa")].split(".")
    if len(octets) != 4:
        return None
    try:
        if not all(0 <= int(o) <= 255 for o in octets):
            return None
    except ValueError:
        return None
    return ".".join(reversed(octets))


def classify_self_traffic(pkt, service_port):
    """Return a short reason string if this packet is traffic Network
    Companion generated about itself, else None. See selftraffic.py for the
    marking side of this."""
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        if service_port and (tcp.sport == service_port or tcp.dport == service_port):
            return "Network Companion UI/API traffic"
        if selftraffic.is_self_port(tcp.sport) or selftraffic.is_self_port(tcp.dport):
            return "Sent by a Network Companion tool (crafter/scan/transfer)"
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        if selftraffic.is_self_port(udp.sport) or selftraffic.is_self_port(udp.dport):
            return "Sent by a Network Companion tool (crafter/scan/transfer)"

    src, dst = _addresses(pkt)
    if selftraffic.is_intel_host_ip(src) or selftraffic.is_intel_host_ip(dst):
        return "IP intel lookup (ip-api.com / AbuseIPDB)"

    if DNS is not None and pkt.haslayer(DNS):
        dns = pkt[DNS]
        if dns.qr == 0 and dns.qd is not None:
            try:
                qname = dns.qd.qname.decode(errors="replace")
            except Exception:
                qname = None
            if qname:
                ip = _ptr_qname_to_ip(qname)
                if ip and selftraffic.is_pending_ptr(ip):
                    return "Reverse-DNS lookup (Resolve names)"
    return None


def _info_string(pkt, proto) -> str:
    """A compact human-readable summary, similar to Wireshark's Info column."""
    if DNS is not None and pkt.haslayer(DNS):
        dns = pkt[DNS]
        if dns.qr == 0 and dns.qd is not None:
            try:
                qname = dns.qd.qname.decode(errors="replace").rstrip(".")
            except Exception:
                qname = str(dns.qd.qname)
            return f"Standard query for {qname}"
        return f"Standard query response ({dns.ancount} answers)"
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        flags = ",".join(_tcp_flag_list(tcp.flags)) or "none"
        base = f"{tcp.sport} \u2192 {tcp.dport} [{flags}] seq={tcp.seq} win={tcp.window}"
        hint = _payload_hint(pkt)
        if hint:
            label, host, request_line = hint
            if request_line:
                base += f"  {request_line}" + (f"  Host: {host}" if host else "")
            elif host:
                base += f"  {label}: {host}"
        return base
    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        return f"{udp.sport} \u2192 {udp.dport} len={udp.len}"
    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        return f"type={icmp.type} code={icmp.code}"
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        if arp.op == 1:
            return f"Who has {arp.pdst}? Tell {arp.psrc}"
        return f"{arp.psrc} is at {arp.hwsrc}"
    return proto


def summarize(pkt, number: int, base_time: float) -> dict:
    """Build the lightweight dict shown in the live packet table."""
    src, dst = _addresses(pkt)
    proto = get_protocol(pkt)
    ts = float(getattr(pkt, "time", time.time()))
    transport = None
    if pkt.haslayer(TCP):
        transport = "tcp"
    elif pkt.haslayer(UDP):
        transport = "udp"
    elif pkt.haslayer(ICMP):
        transport = "icmp"
    elif pkt.haslayer(ARP):
        transport = "arp"
    domain = None
    if pkt.haslayer(TCP):
        hint = _payload_hint(pkt)
        if hint:
            domain = hint[1]
    if domain is None and DNS is not None and pkt.haslayer(DNS):
        dns = pkt[DNS]
        if dns.qr == 0 and dns.qd is not None:
            try:
                domain = dns.qd.qname.decode(errors="replace").rstrip(".")
            except Exception:
                domain = None
    row = {
        "number": number,
        "time": round(ts - base_time, 6),
        "epoch": ts,
        "src": src,
        "dst": dst,
        "proto": proto,
        "transport": transport,
        "length": len(pkt),
        "info": _info_string(pkt, proto),
        "domain": domain,
        "sport": None,
        "dport": None,
        "flags": [],
    }
    if pkt.haslayer(TCP):
        row["sport"] = pkt[TCP].sport
        row["dport"] = pkt[TCP].dport
        row["flags"] = _tcp_flag_list(pkt[TCP].flags)
    elif pkt.haslayer(UDP):
        row["sport"] = pkt[UDP].sport
        row["dport"] = pkt[UDP].dport
    return row


def _layer_fields(layer) -> dict:
    fields = {}
    for fd in layer.fields_desc:
        name = fd.name
        try:
            val = layer.getfieldval(name)
        except Exception:
            continue
        # Represent the value the way Scapy displays it where possible.
        try:
            repr_val = fd.i2repr(layer, val)
        except Exception:
            repr_val = _safe(val)
        fields[name] = _safe(repr_val)
    return fields


def _hex_dump(raw: bytes) -> List[dict]:
    """Return rows of {offset, hex, ascii} for the hex viewer."""
    rows = []
    for off in range(0, len(raw), 16):
        chunk = raw[off:off + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append({
            "offset": f"{off:04x}",
            "hex": hex_part,
            "ascii": ascii_part,
        })
    return rows


def detail(pkt) -> dict:
    """Full layer-by-layer breakdown plus a hex dump for the detail panel."""
    layers = []
    counter = 0
    while True:
        layer = pkt.getlayer(counter)
        if layer is None:
            break
        layers.append({
            "name": layer.name,
            "fields": _layer_fields(layer),
        })
        counter += 1
    domain = None
    if pkt.haslayer(TCP):
        hint = _payload_hint(pkt)
        if hint:
            domain = hint[1]
    return {
        "layers": layers,
        "hex": _hex_dump(bytes(pkt)),
        "length": len(pkt),
        "domain": domain,
        "process": procmap.process_for(pkt),
        "threat": threat_mod.assess(pkt),
    }


class CaptureEngine:
    """Owns the live sniffer and the buffer of captured packets. Unbounded by
    design: nothing is ever dropped from a running capture, no matter how
    long it runs or how large it gets. Appending to the end of a Python list
    is O(1), so this doesn't cost anything per packet; it only costs memory,
    which is the analyst's call to manage (stop and export, or clear)."""

    def __init__(self, on_packet: Optional[Callable[[dict], None]] = None,
                 on_nc_packet: Optional[Callable[[dict], None]] = None,
                 service_port: Optional[int] = None):
        self._sniffer: Optional[AsyncSniffer] = None
        self._packets = []           # raw Scapy packets, index == packet number
        self._lock = threading.Lock()
        self._base_time: Optional[float] = None
        self._on_packet = on_packet  # called from the sniffer thread per packet
        self._scan = threat_mod.ScanTracker()
        self.iface = None
        self.bpf = None

        # "NC Traffic" side buffer: packets Network Companion generated about
        # itself (see classify_self_traffic). Kept entirely separate from
        # self._packets so PCAP export never includes them.
        self._on_nc_packet = on_nc_packet
        self._service_port = service_port
        self._nc_packets: dict = {}   # id -> raw Scapy packet
        self._nc_next_id = 0
        self._nc_base_time: Optional[float] = None

    @property
    def running(self) -> bool:
        return self._sniffer is not None and self._sniffer.running

    def list_interfaces(self):
        result = []
        try:
            for iface in get_working_ifaces():
                result.append({
                    "name": iface.name,
                    "description": getattr(iface, "description", "") or iface.name,
                    "mac": getattr(iface, "mac", "") or "",
                    "ip": getattr(iface, "ip", "") or "",
                })
        except Exception:
            # Fall back to Scapy's simpler interface list.
            from scapy.all import get_if_list
            for name in get_if_list():
                result.append({"name": name, "description": name, "mac": "", "ip": ""})
        return result

    def _handle(self, pkt):
        try:
            reason = classify_self_traffic(pkt, self._service_port)
        except Exception:
            reason = None

        if reason is not None:
            with self._lock:
                if self._nc_base_time is None:
                    self._nc_base_time = float(getattr(pkt, "time", time.time()))
                nc_id = self._nc_next_id
                self._nc_next_id += 1
                self._nc_packets[nc_id] = pkt
                base = self._nc_base_time
            row = summarize(pkt, nc_id, base)
            row["reason"] = reason
            if self._on_nc_packet is not None:
                try:
                    self._on_nc_packet(row)
                except Exception:
                    pass
            return

        with self._lock:
            if self._base_time is None:
                self._base_time = float(getattr(pkt, "time", time.time()))
            number = len(self._packets)
            self._packets.append(pkt)
            base = self._base_time
        row = summarize(pkt, number, base)
        try:
            row["threat"] = threat_mod.assess(pkt, self._scan)
        except Exception:
            row["threat"] = {"level": "none", "reasons": []}
        if self._on_packet is not None:
            try:
                self._on_packet(row)
            except Exception:
                pass

    def start(self, iface: Optional[str] = None, bpf: Optional[str] = None,
              promisc: bool = True):
        if self.running:
            raise RuntimeError("A capture is already running.")
        self.iface = iface or None
        self.bpf = (bpf or "").strip() or None
        conf.sniff_promisc = 1 if promisc else 0
        kwargs = {"prn": self._handle, "store": False}
        if self.iface:
            kwargs["iface"] = self.iface
        if self.bpf:
            kwargs["filter"] = self.bpf
        self._sniffer = AsyncSniffer(**kwargs)
        self._sniffer.start()

    def stop(self):
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        self._sniffer = None

    def clear(self):
        with self._lock:
            self._packets = []
            self._base_time = None

    def count(self) -> int:
        with self._lock:
            return len(self._packets)

    def get_detail(self, index: int) -> Optional[dict]:
        with self._lock:
            if index < 0 or index >= len(self._packets):
                return None
            pkt = self._packets[index]
        return detail(pkt)

    def get_packet(self, index: int):
        """Return the raw Scapy packet at an index (for replay), or None."""
        with self._lock:
            if index < 0 or index >= len(self._packets):
                return None
            return self._packets[index]

    def nc_count(self) -> int:
        with self._lock:
            return len(self._nc_packets)

    def clear_nc(self):
        with self._lock:
            self._nc_packets = {}
            self._nc_next_id = 0
            self._nc_base_time = None

    def delete_nc(self, nc_id: int) -> bool:
        with self._lock:
            return self._nc_packets.pop(nc_id, None) is not None

    def get_nc_detail(self, nc_id: int) -> Optional[dict]:
        with self._lock:
            pkt = self._nc_packets.get(nc_id)
        if pkt is None:
            return None
        return detail(pkt)

    def get_nc_packet(self, nc_id: int):
        """Return the raw Scapy packet for an NC Traffic entry (for replay)."""
        with self._lock:
            return self._nc_packets.get(nc_id)

    def export_pcap(self, path: str) -> int:
        with self._lock:
            pkts = list(self._packets)
        wrpcap(path, pkts)
        return len(pkts)

    def export_pcap_all(self, path: str) -> int:
        """Export the main capture plus everything diverted into NC Traffic,
        merged back into chronological order. Opt-in: the analyst asked for
        this explicitly (a different button from the default export), since
        normally NC Traffic is kept out of saved captures on purpose."""
        with self._lock:
            pkts = list(self._packets) + list(self._nc_packets.values())
        pkts.sort(key=lambda p: float(getattr(p, "time", 0)))
        wrpcap(path, pkts)
        return len(pkts)

    def load(self, pkts) -> list:
        """Replace the buffer with packets from a loaded PCAP; return summaries."""
        pkts = list(pkts)
        with self._lock:
            self._packets = pkts
            self._base_time = float(getattr(pkts[0], "time", time.time())) if pkts else None
            base = self._base_time or time.time()
        tracker = threat_mod.ScanTracker()
        rows = []
        for i, p in enumerate(pkts):
            row = summarize(p, i, base)
            try:
                row["threat"] = threat_mod.assess(p, tracker)
            except Exception:
                row["threat"] = {"level": "none", "reasons": []}
            rows.append(row)
        return rows
