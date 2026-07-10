"""
Threat heuristics.

Lightweight, explainable signals meant to catch an analyst's eye, not
replace a real IDS: suspicious TCP flag combos (NULL/FIN/XMAS/SYN+FIN
scans), cleartext protocols like Telnet and FTP, ports commonly tied to
backdoors and C2 frameworks, unusually long or high-entropy DNS queries
that might be tunnelling, and basic port-scan/host-sweep tracking.
Everything here is heuristic and will throw false positives; every flag
just comes with a plain-English reason so you can judge it yourself.
"""

import time
import math
import threading
from collections import defaultdict, deque

from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.inet6 import IPv6

try:
    from scapy.layers.dns import DNS, DNSQR
except Exception:
    DNS = None
    DNSQR = None

# Severity ordering for rolling up a packet's overall level.
_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}

# Ports frequently seen with backdoors / offensive tooling. Heuristic only;
# plenty of legitimate software uses high ports too.
_SUSPECT_PORTS = {
    31337: "Back Orifice", 12345: "NetBus", 12346: "NetBus",
    27374: "SubSeven", 4444: "Metasploit default", 4445: "Metasploit alt",
    5555: "Android ADB / malware", 6666: "IRC / C2", 6667: "IRC / C2",
    6668: "IRC / C2", 6669: "IRC / C2", 1337: "leet / misc backdoor",
    9001: "Tor OR port", 9050: "Tor SOCKS", 9150: "Tor Browser SOCKS",
    4443: "alt-C2", 1080: "SOCKS proxy", 2222: "alt-SSH / backdoor",
    65000: "high-port C2", 54321: "backdoor", 1234: "backdoor",
    3127: "MyDoom", 5554: "Sasser", 9999: "misc backdoor",
}

_CLEARTEXT = {21: "FTP", 23: "Telnet", 25: "SMTP", 110: "POP3", 143: "IMAP",
              512: "rexec", 513: "rlogin", 514: "rsh"}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = defaultdict(int)
    for ch in s:
        counts[ch] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class ScanTracker:
    """Rolling per-source view of SYN targets, for scan / sweep detection."""

    WINDOW = 10.0          # seconds
    PORT_THRESHOLD = 15    # distinct dst ports on a single host -> port scan
    HOST_THRESHOLD = 15    # distinct dst hosts -> host sweep
    MAX_SOURCES = 4096     # bound memory

    def __init__(self):
        self._lock = threading.Lock()
        # src -> deque[(ts, dst_ip, dst_port)]
        self._events = defaultdict(deque)

    def record(self, src, dst, dport):
        now = time.time()
        with self._lock:
            if src not in self._events and len(self._events) >= self.MAX_SOURCES:
                # Drop the largest bucket to make room rather than grow forever.
                victim = max(self._events, key=lambda k: len(self._events[k]))
                del self._events[victim]
            dq = self._events[src]
            dq.append((now, dst, dport))
            cutoff = now - self.WINDOW
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            ports = {p for _, _, p in dq}
            hosts = {h for _, h, _ in dq}
            return len(ports), len(hosts)


def assess(pkt, scan: ScanTracker = None) -> dict:
    """Return {'level': str, 'reasons': [str]} for a single packet."""
    reasons = []
    level = "none"

    def add(sev, msg):
        nonlocal level
        reasons.append(msg)
        if _ORDER[sev] > _ORDER[level]:
            level = sev

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        f = str(tcp.flags)
        fset = set(f)
        if f == "" or fset == set():
            add("high", "NULL scan: TCP packet with no flags set")
        elif fset == {"F"}:
            add("high", "FIN scan: lone FIN flag")
        elif fset == {"F", "P", "U"}:
            add("high", "XMAS scan: FIN+PSH+URG set together")
        elif {"S", "F"} <= fset:
            add("high", "Illegal SYN+FIN flag combination")
        # backdoor / C2 ports
        for port in (tcp.dport, tcp.sport):
            if port in _SUSPECT_PORTS:
                add("medium", f"Port {port} associated with {_SUSPECT_PORTS[port]}")
                break
        # cleartext protocols (only if this looks like the service side)
        for port in (tcp.dport, tcp.sport):
            if port in _CLEARTEXT:
                add("low", f"Cleartext protocol {_CLEARTEXT[port]} (port {port})")
                break
        # scan/sweep tracking on SYN without ACK (connection attempts)
        if scan is not None and "S" in fset and "A" not in fset:
            src = pkt[IP].src if pkt.haslayer(IP) else (pkt[IPv6].src if pkt.haslayer(IPv6) else None)
            dst = pkt[IP].dst if pkt.haslayer(IP) else (pkt[IPv6].dst if pkt.haslayer(IPv6) else None)
            if src and dst:
                nports, nhosts = scan.record(src, dst, tcp.dport)
                if nports >= ScanTracker.PORT_THRESHOLD:
                    add("high", f"Possible port scan: {nports} ports from {src} in 10s")
                elif nhosts >= ScanTracker.HOST_THRESHOLD:
                    add("high", f"Possible host sweep: {nhosts} hosts from {src} in 10s")

    if DNS is not None and pkt.haslayer(DNS):
        dns = pkt[DNS]
        if dns.qr == 0 and dns.qd is not None:
            try:
                qname = dns.qd.qname.decode(errors="replace").rstrip(".")
            except Exception:
                qname = ""
            if qname:
                labels = qname.split(".")
                longest = max((len(l) for l in labels), default=0)
                if len(qname) > 60 or longest > 40 or _entropy(qname) > 4.0:
                    add("medium", "Unusually long / high-entropy DNS query (possible tunnelling)")

    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        try:
            itype = int(icmp.type)
        except Exception:
            itype = None
        # An echo request/reply carrying an oversized payload is a classic
        # covert channel (ICMP tunnel). Normal pings carry ~32-56 bytes.
        if itype in (0, 8):
            plen = len(bytes(icmp.payload)) if icmp.payload else 0
            if plen > 100:
                add("medium", f"Large ICMP echo payload ({plen} bytes) — possible ICMP tunnel")

    return {"level": level, "reasons": reasons}
