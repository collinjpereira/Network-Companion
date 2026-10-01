"""
Capture engine.

Reads frames off the capture driver (see rawcapture.py), streams a summary
of each to the web UI over a WebSocket in real time, and keeps every raw
frame in memory so full detail views and PCAP export stay accurate.
"""

import time
import threading
from collections import deque
from typing import Optional, List, Callable

from scapy.all import PcapWriter, get_working_ifaces, conf
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
import rawcapture


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


def _wire_len(pkt) -> int:
    """Packet length without re-serialising it. len(pkt) on a Scapy packet
    rebuilds its bytes, which is a real cost on every captured packet; a
    dissected packet still holds the original bytes it was built from."""
    original = getattr(pkt, "original", None)
    if original:
        return len(original)
    return len(pkt)


_NO_HINT = object()


def _info_string(pkt, proto, hint=_NO_HINT) -> str:
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
        if hint is _NO_HINT:
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
    hint = None
    if transport == "tcp":
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
        "length": _wire_len(pkt),
        "info": _info_string(pkt, proto, hint),
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


class _Frame:
    """A captured frame kept as raw bytes rather than a dissected Scapy
    packet. A dissected packet costs several KB of Python objects; the raw
    bytes cost roughly their own size, so long captures don't run the
    machine out of memory. Dissected again on demand (detail view, replay,
    export), which is quick for a single packet."""

    __slots__ = ("time", "data", "wirelen", "ll")

    def __init__(self, ts, data, wirelen, ll):
        self.time = ts
        self.data = data
        self.wirelen = wirelen
        self.ll = ll


def _dissect(ll, data: bytes, ts: float, wirelen: int):
    try:
        pkt = ll(data)
    except Exception:
        pkt = conf.raw_layer(data)
    pkt.time = ts
    pkt.wirelen = wirelen
    return pkt


def _materialize(item):
    """A Scapy packet for a stored item (a _Frame, or a packet that came
    from a loaded PCAP and is already dissected)."""
    if isinstance(item, _Frame):
        return _dissect(item.ll, item.data, item.time, item.wirelen)
    return item


def _fallback_row(item, number: int, base: float) -> dict:
    """Bare-bones row for a packet the summary code couldn't handle, so it
    still shows up in the table instead of silently going missing."""
    ts = float(getattr(item, "time", 0) or 0)
    data = getattr(item, "data", None)
    return {
        "number": number, "time": round(ts - base, 6), "epoch": ts,
        "src": "", "dst": "", "proto": "Unknown", "transport": None,
        "length": len(data) if data is not None else 0,
        "info": "(could not decode)", "domain": None,
        "sport": None, "dport": None, "flags": [],
    }


class CaptureEngine:
    """Owns the live capture and the buffer of captured packets. Unbounded by
    design: nothing is ever dropped from a running capture, no matter how
    long it runs or how large it gets.

    Two threads per capture: a reader (rawcapture.py) that only copies frames
    off the driver into self._raw, and a worker that dissects, classifies and
    stores them. If the worker falls behind, frames wait in self._raw rather
    than overflowing the driver, and `backlog` says how far behind it is.
    Stopping a capture stops the reader immediately but lets the worker
    finish everything already read, so nothing captured is thrown away."""

    def __init__(self, on_packet: Optional[Callable[[dict], None]] = None,
                 on_nc_packet: Optional[Callable[[dict], None]] = None,
                 service_port: Optional[int] = None):
        self._reader = None
        self._worker: Optional[threading.Thread] = None
        self._raw: deque = deque()
        self._packets = []           # _Frame or Scapy packet, index == packet number
        self._lock = threading.Lock()
        self._base_time: Optional[float] = None
        self._on_packet = on_packet  # called from the worker thread per packet
        self._scan = threat_mod.ScanTracker()
        self.iface = None
        self.bpf = None
        # Bumped whenever packet numbering restarts (clear / new capture /
        # PCAP load) so the UI can ignore rows from a previous session.
        self.session = 0
        # Frames timestamped before this are skipped by the worker: they were
        # captured before the user hit Clear but hadn't been decoded yet.
        self._discard_before = 0.0
        # Whether the current capture has packets that haven't been exported.
        # The capture file is never deleted while this is set.
        self.unsaved = False
        self._file_path: Optional[str] = None
        # Unsaved capture files found at startup and moved to Documents.
        self.recovered = rawcapture.rescue_leftovers()

        # "NC Traffic" side buffer: packets Network Companion generated about
        # itself (see classify_self_traffic). Kept entirely separate from
        # self._packets so PCAP export never includes them.
        self._on_nc_packet = on_nc_packet
        self._service_port = service_port
        self._nc_packets: dict = {}   # id -> _Frame
        self._nc_next_id = 0
        self._nc_base_time: Optional[float] = None

    @property
    def running(self) -> bool:
        return self._reader is not None and self._reader.capturing

    def list_interfaces(self, refresh: bool = False):
        if refresh:
            try:
                conf.ifaces.reload()
            except Exception:
                pass
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

    def _work(self, raw: deque, reader):
        """Worker thread: drain frames until the reader has stopped and the
        backlog is empty."""
        while True:
            try:
                ts, data, wirelen, ll = raw.popleft()
                if ts < self._discard_before:
                    continue
            except IndexError:
                if not reader.alive:
                    if not raw:
                        return
                    continue
                time.sleep(0.002)
                continue
            try:
                self._ingest(_Frame(ts, data, wirelen, ll))
            except Exception:
                pass

    def _ingest(self, frame: _Frame):
        pkt = _dissect(frame.ll, frame.data, frame.time, frame.wirelen)
        try:
            reason = classify_self_traffic(pkt, self._service_port)
        except Exception:
            reason = None

        if reason is not None:
            with self._lock:
                if self._nc_base_time is None:
                    self._nc_base_time = frame.time
                nc_id = self._nc_next_id
                self._nc_next_id += 1
                self._nc_packets[nc_id] = frame
                base = self._nc_base_time
            try:
                row = summarize(pkt, nc_id, base)
            except Exception:
                row = _fallback_row(frame, nc_id, base)
            row["reason"] = reason
            if self._on_nc_packet is not None:
                try:
                    self._on_nc_packet(row)
                except Exception:
                    pass
            return

        # Store first, so a packet that trips up the summary code is still
        # in the capture and the export.
        with self._lock:
            if self._base_time is None:
                self._base_time = frame.time
            number = len(self._packets)
            self._packets.append(frame)
            self.unsaved = True
            base = self._base_time
            session = self.session
        try:
            row = summarize(pkt, number, base)
        except Exception:
            row = _fallback_row(frame, number, base)
        try:
            row["threat"] = threat_mod.assess(pkt, self._scan)
        except Exception:
            row["threat"] = {"level": "none", "reasons": []}
        row["session"] = session
        if self._on_packet is not None:
            try:
                self._on_packet(row)
            except Exception:
                pass

    def start(self, iface: Optional[str] = None, bpf: Optional[str] = None,
              promisc: bool = True, buffer_mb: Optional[int] = None):
        if self.running:
            raise RuntimeError("A capture is already running.")
        # Starting over: stop decoding whatever's left of the previous
        # capture (it's all in that capture's file regardless).
        if self._reader is not None:
            self._reader.abandon()
        self._raw.clear()
        self._finish_worker()
        self._retire_file()
        self.iface = iface or None
        self.bpf = (bpf or "").strip() or None
        conf.sniff_promisc = 1 if promisc else 0
        mb = buffer_mb if buffer_mb in rawcapture.DRIVER_BUFFER_CHOICES_MB else None
        buffer_bytes = mb * 1024 * 1024 if mb else rawcapture.DRIVER_BUFFER_BYTES
        raw: deque = deque()
        path = rawcapture.new_capture_path()
        reader = rawcapture.open_reader(raw, self.iface, self.bpf, promisc, path, buffer_bytes)
        self._file_path = path if getattr(reader, "spool", None) is not None else None
        self.buffer_mb = buffer_bytes // (1024 * 1024)
        self._raw = raw
        self._reader = reader
        self._worker = threading.Thread(target=self._work, args=(raw, reader),
                                        name="nc-worker", daemon=True)
        reader.start()
        self._worker.start()

    def stop(self):
        reader = self._reader
        if reader is not None:
            try:
                reader.stop()
            except Exception:
                pass
        # The reader object is kept for its final counters, and the worker
        # keeps going until it has processed everything already captured.

    def _retire_file(self):
        """Done with the previous capture's file: delete it if everything in
        it was saved (or the user chose to discard it), otherwise move it to
        Documents. Never just deletes unsaved packets."""
        path, self._file_path = self._file_path, None
        if not path:
            return
        if self.unsaved:
            dest = rawcapture.keep_file(path)
            if dest:
                self.recovered.append(dest)
        else:
            rawcapture.delete_file(path)

    def discard(self):
        """The user chose not to save the current capture. If it's no longer
        running, its file can go right away."""
        self.unsaved = False
        if not self.running and not (self._worker is not None and self._worker.is_alive()):
            self._retire_file()

    def shutdown(self):
        """App is closing: stop capturing; the capture file is deleted only
        if it was saved or discarded, otherwise moved to Documents."""
        self.stop()
        if self._reader is not None:
            try:
                self._reader.abandon()
            except Exception:
                pass
        self._retire_file()

    def _finish_worker(self):
        if self._worker is not None:
            self._worker.join()
            self._worker = None

    def capture_status(self) -> dict:
        """Driver drop counters plus how far the worker is behind."""
        reader = self._reader
        stats = reader.stats if reader is not None else None
        error = reader.error if reader is not None else None
        spool = reader.spool if reader is not None else None
        on_disk = reader.on_disk if reader is not None else 0
        return {
            "driver": stats,
            "backlog": len(self._raw) + on_disk,
            "buffer_mb": getattr(self, "buffer_mb", None),
            "unsaved": self.unsaved,
            "recovered": self.recovered,
            "processing": self._worker is not None and self._worker.is_alive(),
            "error": error,
            "file": None if spool is None else {
                "path": spool.path, "bytes": spool.bytes, "error": spool.error,
            },
        }

    def clear(self):
        with self._lock:
            self._raw.clear()  # frames read before the clear belong to the old capture
            self._discard_before = time.time()
            self._packets = []
            self._base_time = None
            self.session += 1

    def count(self) -> int:
        with self._lock:
            return len(self._packets)

    def rows(self, start: int, end: int):
        """Summaries for packets [start, end), so the UI can fill in anything
        it missed (e.g. after a dropped WebSocket). Scan detection isn't
        re-run for these; the other threat checks are."""
        start = max(0, start)
        with self._lock:
            items = self._packets[start:max(start, end)]
            base = self._base_time or 0.0
            session = self.session
        out = []
        for i, item in enumerate(items, start=start):
            pkt = _materialize(item)
            try:
                row = summarize(pkt, i, base)
            except Exception:
                row = _fallback_row(item, i, base)
            try:
                row["threat"] = threat_mod.assess(pkt)
            except Exception:
                row["threat"] = {"level": "none", "reasons": []}
            row["session"] = session
            row["channel"] = "capture"
            out.append(row)
        return session, out

    def get_detail(self, index: int) -> Optional[dict]:
        with self._lock:
            if index < 0 or index >= len(self._packets):
                return None
            item = self._packets[index]
        return detail(_materialize(item))

    def get_packet(self, index: int):
        """Return the Scapy packet at an index (for replay), or None."""
        with self._lock:
            if index < 0 or index >= len(self._packets):
                return None
            item = self._packets[index]
        return _materialize(item)

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
            item = self._nc_packets.get(nc_id)
        if item is None:
            return None
        return detail(_materialize(item))

    def get_nc_packet(self, nc_id: int):
        """Return the Scapy packet for an NC Traffic entry (for replay)."""
        with self._lock:
            item = self._nc_packets.get(nc_id)
        return None if item is None else _materialize(item)

    @staticmethod
    def _write_pcap(path: str, items) -> int:
        # Stream to disk one packet at a time rather than building a list of
        # dissected packets, which for a big capture could need gigabytes.
        with PcapWriter(path, sync=False) as writer:
            for item in items:
                writer.write(_materialize(item))
        return len(items)

    def export_pcap(self, path: str) -> int:
        with self._lock:
            items = list(self._packets)
        n = self._write_pcap(path, items)
        with self._lock:
            # Saved, unless more packets arrived while writing.
            if len(self._packets) == len(items):
                self.unsaved = False
        return n

    def export_pcap_all(self, path: str) -> int:
        """Export the main capture plus everything diverted into NC Traffic,
        merged back into chronological order. Opt-in: the analyst asked for
        this explicitly (a different button from the default export), since
        normally NC Traffic is kept out of saved captures on purpose."""
        with self._lock:
            items = list(self._packets) + list(self._nc_packets.values())
        items.sort(key=lambda p: float(getattr(p, "time", 0)))
        n = self._write_pcap(path, items)
        with self._lock:
            if len(self._packets) + len(self._nc_packets) == len(items):
                self.unsaved = False
        return n

    def load(self, pkts) -> list:
        """Replace the buffer with packets from a loaded PCAP; return summaries."""
        pkts = list(pkts)
        with self._lock:
            self._raw.clear()
            self.unsaved = False  # it came from a file, so it's already saved
            self._packets = pkts
            self._base_time = float(getattr(pkts[0], "time", time.time())) if pkts else None
            base = self._base_time or time.time()
            self.session += 1
            session = self.session
        tracker = threat_mod.ScanTracker()
        rows = []
        for i, p in enumerate(pkts):
            row = summarize(p, i, base)
            try:
                row["threat"] = threat_mod.assess(p, tracker)
            except Exception:
                row["threat"] = {"level": "none", "reasons": []}
            row["session"] = session
            rows.append(row)
        return rows
