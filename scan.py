"""
Port scanner.

Two scan types: connect does a full TCP connect() to each port (reliable,
works without raw sockets, can grab a service banner, and is the default),
while syn does a half-open SYN scan via Scapy (faster and stealthier, but
needs raw-socket privileges, so root or Administrator).

Scan only hosts you own or are explicitly authorised to test.
"""

import socket
from concurrent.futures import ThreadPoolExecutor

import selftraffic

# A compact top-ports list (well-known services + commonly exposed ports).
TOP_100 = [
    7, 20, 21, 22, 23, 25, 53, 67, 69, 80, 88, 110, 111, 123, 135, 137, 138,
    139, 143, 161, 162, 179, 389, 443, 445, 465, 500, 512, 513, 514, 515, 543,
    544, 548, 554, 587, 631, 636, 646, 873, 990, 993, 995, 1025, 1080, 1194,
    1433, 1434, 1521, 1723, 1900, 2049, 2082, 2083, 2181, 2222, 2375, 2376,
    3128, 3268, 3306, 3389, 3690, 4444, 4786, 5000, 5060, 5222, 5432, 5555,
    5601, 5672, 5900, 5901, 5985, 5986, 6000, 6379, 6443, 6666, 6667, 7001,
    8000, 8008, 8080, 8081, 8443, 8888, 9000, 9001, 9042, 9092, 9200, 9300,
    9418, 9999, 11211, 27017, 31337,
]

COMMON = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
          1433, 3306, 3389, 5432, 5900, 8080, 8443]

SERVICES = {
    7: "echo", 20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 69: "tftp", 80: "http", 88: "kerberos",
    110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    162: "snmptrap", 179: "bgp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 500: "isakmp", 512: "rexec", 513: "rlogin", 514: "rsh/syslog",
    515: "printer", 548: "afp", 554: "rtsp", 587: "submission", 631: "ipp",
    636: "ldaps", 873: "rsync", 990: "ftps", 993: "imaps", 995: "pop3s",
    1080: "socks", 1194: "openvpn", 1433: "mssql", 1434: "mssql-m",
    1521: "oracle", 1723: "pptp", 1900: "upnp", 2049: "nfs", 2181: "zookeeper",
    2222: "ssh-alt", 2375: "docker", 2376: "docker-tls", 3128: "squid",
    3268: "ldap-gc", 3306: "mysql", 3389: "rdp", 3690: "svn", 4444: "metasploit",
    4786: "cisco-smi", 5000: "upnp/flask", 5060: "sip", 5222: "xmpp",
    5432: "postgres", 5555: "adb", 5601: "kibana", 5672: "amqp", 5900: "vnc",
    5901: "vnc-1", 5985: "winrm", 5986: "winrm-tls", 6000: "x11", 6379: "redis",
    6443: "kubernetes", 6666: "irc", 6667: "irc", 7001: "weblogic",
    8000: "http-alt", 8008: "http-alt", 8080: "http-proxy", 8081: "http-alt",
    8443: "https-alt", 8888: "http-alt", 9000: "http-alt", 9001: "tor",
    9042: "cassandra", 9092: "kafka", 9200: "elasticsearch", 9300: "es-transport",
    9418: "git", 9999: "http-alt", 11211: "memcached", 27017: "mongodb",
    31337: "back-orifice",
}


def parse_ports(spec: str):
    spec = (spec or "").strip().lower()
    if spec in ("top", "top100", "top-100", "top 100"):
        return sorted(set(TOP_100))
    if spec in ("common", "quick"):
        return sorted(set(COMMON))
    if spec in ("all", "1-65535", "full"):
        return list(range(1, 65536))
    ports = set()
    for part in spec.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            lo, hi = int(a), int(b)
            # Clamp to the valid port range before expanding the range, so a
            # spec like "1-4000000000" can't blow up into billions of set
            # insertions before the final filter below ever runs.
            lo, hi = max(1, min(lo, hi)), min(65535, max(lo, hi))
            for p in range(lo, hi + 1):
                ports.add(p)
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


def _probe(host, port, timeout, grab):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except ConnectionRefusedError:
        return {"port": port, "state": "closed", "banner": None}
    except (socket.timeout, OSError):
        return {"port": port, "state": "filtered", "banner": None}
    # The handshake already happened by the time connect() returns (the OS
    # picks the local port synchronously), so this only classifies whatever
    # comes after — banner grab and teardown — as Network Companion's own.
    try:
        selftraffic.mark_port(s.getsockname()[1], ttl=5.0)
    except Exception:
        pass
    banner = None
    if grab:
        try:
            s.settimeout(1.0)
            data = s.recv(160)
            banner = data.decode("latin-1", "replace").strip()[:100] or None
        except Exception:
            pass
    try:
        s.close()
    except Exception:
        pass
    return {"port": port, "state": "open", "banner": banner}


def connect_scan(host, ports, timeout=1.0, grab=False, workers=200):
    results = []
    workers = min(workers, max(1, len(ports)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(lambda p: _probe(host, p, timeout, grab), ports):
            results.append(r)
    results.sort(key=lambda r: r["port"])
    return results


def syn_scan(host, ports, timeout=2.0):
    from scapy.all import IP, TCP, sr, conf
    import random
    conf.verb = 0
    # A raw packet, so (unlike connect_scan) we choose the source port
    # ourselves and can register it before anything goes out.
    sport = random.randint(20000, 60000)
    selftraffic.mark_port(sport, ttl=timeout + 5.0)
    ans, unans = sr(IP(dst=host) / TCP(sport=sport, dport=ports, flags="S"),
                    timeout=timeout, verbose=0)
    open_ports, closed = set(), set()
    for snd, rcv in ans:
        try:
            if rcv.haslayer(TCP):
                fl = int(rcv["TCP"].flags)
                if fl & 0x12 == 0x12:      # SYN+ACK
                    open_ports.add(int(snd["TCP"].dport))
                elif fl & 0x04:            # RST
                    closed.add(int(snd["TCP"].dport))
        except Exception:
            pass
    results = []
    for p in ports:
        state = "open" if p in open_ports else ("closed" if p in closed else "filtered")
        results.append({"port": p, "state": state, "banner": None})
    return results
