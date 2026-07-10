"""
Local network discovery.

Actively enumerates hosts on a local subnet with an ARP sweep (Scapy), then
enriches each with a best-effort vendor name from the MAC OUI prefix and a
device-type guess (PlayStation, Xbox, Nintendo, phone, router, IoT, etc).
Falls back to the system neighbour table when raw sockets aren't available.

This is device inventory for a network you operate, "what's on my LAN", not
identity resolution. It maps hardware vendors, not people.
"""

import ipaddress
import re
import socket
import subprocess

import intel as intel_mod

# --- OUI prefixes -> vendor -------------------------------------------------
# Curated subset (first three MAC octets, lowercase "aa:bb:cc"). Not the full
# IEEE registry, just enough to recognise consoles, phones, network gear and
# common IoT. Unknown prefixes simply return an empty vendor.
OUI = {}


def _add(vendor, *prefixes):
    for p in prefixes:
        OUI[p.lower()] = vendor


_add("Sony Interactive (PlayStation)", "00:04:1f", "00:13:15", "00:15:c1", "00:19:c5",
     "00:1d:0d", "00:1f:a7", "00:24:8d", "00:d9:d1", "28:0d:fc", "5c:96:56", "70:9e:29",
     "78:c8:81", "a8:e3:ee", "ac:89:95", "b0:05:94", "bc:60:a7", "c0:29:f3", "d4:4b:5e",
     "f8:46:1c", "fc:0f:e6", "00:04:1F")
_add("Microsoft (Xbox / Surface)", "00:12:5a", "00:15:5d", "00:17:fa", "00:1d:d8",
     "00:22:48", "00:25:ae", "00:50:f2", "28:18:78", "60:45:bd", "7c:1e:52", "98:5f:d3",
     "9c:aa:1b", "c8:3f:26", "f0:6e:0b", "b4:ae:2b", "50:1a:c5")
_add("Nintendo", "00:09:bf", "00:16:56", "00:17:ab", "00:19:1d", "00:19:fd", "00:1a:e9",
     "00:1b:7a", "00:1b:ea", "00:1c:be", "00:1d:bc", "00:1e:35", "00:1f:32", "00:21:47",
     "00:21:bd", "00:22:4c", "00:22:aa", "00:23:31", "00:23:cc", "00:24:1e", "00:24:44",
     "00:24:f3", "00:25:a0", "00:26:59", "00:27:09", "04:03:d6", "18:2a:7b", "2c:10:c1",
     "34:af:2c", "40:d2:8a", "58:bd:a3", "5c:52:1e", "60:6b:ff", "78:a2:a0", "8c:56:c5",
     "98:b6:e9", "9c:e6:35", "a4:5c:27", "b8:8a:ec", "cc:9e:00", "cc:fb:65", "d8:6b:f7",
     "dc:68:eb", "e0:0c:7f", "e0:e7:51", "e8:4e:ce")
_add("Apple", "00:03:93", "00:05:02", "00:0a:27", "00:0a:95", "00:0d:93", "00:16:cb",
     "00:17:f2", "00:19:e3", "00:1b:63", "00:1e:c2", "00:1f:5b", "00:1f:f3", "00:21:e9",
     "00:22:41", "00:23:12", "00:23:df", "00:24:36", "00:25:00", "00:25:bc", "00:26:08",
     "00:26:4a", "00:26:b0", "00:26:bb", "3c:07:54", "3c:2e:ff", "40:cb:c0", "70:56:81",
     "a4:83:e7", "ac:bc:32", "b8:e8:56", "dc:2b:2a", "f0:18:98", "f4:1b:a1", "f8:1e:df")
_add("Samsung", "00:07:ab", "00:12:47", "00:15:b9", "00:16:32", "00:17:c9", "00:1a:8a",
     "00:1d:25", "00:21:19", "00:23:39", "08:37:3d", "34:23:ba", "5c:0a:5b", "78:1f:db",
     "8c:77:12", "e8:50:8b", "f0:25:b7", "bc:44:86")
_add("Google / Nest", "00:1a:11", "3c:5a:b4", "54:60:09", "6c:ad:f8", "94:eb:2c",
     "a4:77:33", "d8:6c:63", "da:a1:19", "f4:f5:d8", "f4:f5:e8", "f8:8f:ca")
_add("Amazon", "00:fc:8b", "0c:47:c9", "34:d2:70", "38:f7:3d", "40:b4:cd", "44:65:0d",
     "4c:ef:c0", "50:dc:e7", "68:37:e9", "68:54:fd", "74:75:48", "74:c2:46", "84:d6:d0",
     "88:71:e5", "a0:02:dc", "ac:63:be", "f0:27:2d", "f0:81:73", "fc:65:de")
_add("Raspberry Pi", "b8:27:eb", "dc:a6:32", "e4:5f:01", "28:cd:c1", "d8:3a:dd", "2c:cf:67")
_add("Espressif (ESP IoT)", "24:0a:c4", "30:ae:a4", "3c:71:bf", "5c:cf:7f", "84:0d:8e",
     "84:f3:eb", "a0:20:a6", "a4:cf:12", "ac:d0:74", "b4:e6:2d", "bc:dd:c2", "c8:2b:96",
     "cc:50:e3", "dc:4f:22", "ec:fa:bc")
_add("Roku", "00:0d:4b", "ac:3a:7a", "b0:a7:37", "b8:3e:59", "cc:6d:a0", "d0:4d:2c", "dc:3a:5e")
_add("Sonos", "00:0e:58", "34:7e:5c", "48:a6:b8", "5c:aa:fd", "78:28:ca", "94:9f:3e", "b8:e9:37")
_add("Philips Hue", "00:17:88")
_add("Cisco", "00:00:0c", "00:01:42", "00:01:63", "00:0a:41", "00:1a:2f", "00:1b:0c",
     "00:1d:45", "00:23:04", "58:97:bd", "f4:0f:1b")
_add("Cisco Meraki", "00:18:0a", "0c:8d:db", "88:15:44", "e0:55:3d", "ac:17:c8")
_add("Ubiquiti", "00:15:6d", "04:18:d6", "24:a4:3c", "44:d9:e7", "68:72:51", "74:83:c2",
     "78:8a:20", "80:2a:a8", "b4:fb:e4", "dc:9f:db", "f0:9f:c2", "fc:ec:da")
_add("Netgear", "00:09:5b", "00:0f:b5", "00:14:6c", "00:1b:2f", "00:1e:2a", "00:22:3f",
     "00:24:b2", "00:26:f2", "20:e5:2a", "28:c6:8e", "2c:30:33", "44:94:fc", "84:1b:5e",
     "a0:40:a0", "c0:3f:0e")
_add("TP-Link", "00:27:19", "14:cc:20", "30:b5:c2", "50:c7:bf", "54:c8:0f", "60:e3:27",
     "64:70:02", "a0:f3:c1", "ac:84:c6", "b0:48:7a", "c0:4a:00", "d8:0d:17", "ec:08:6b", "f4:f2:6d")
_add("D-Link", "00:05:5d", "00:0d:88", "00:0f:3d", "00:13:46", "00:15:e9", "00:17:9a",
     "00:19:5b", "00:1b:11", "00:1c:f0", "00:1e:58", "00:21:91", "00:22:b0", "00:24:01",
     "14:d6:4d", "1c:af:f7")
_add("ASUS", "00:0c:6e", "00:0e:a6", "00:11:2f", "00:13:d4", "00:15:f2", "00:17:31",
     "00:1a:92", "00:1b:fc", "00:1d:60", "00:1e:8c", "00:22:15", "00:23:54", "00:24:8c",
     "00:26:18", "04:d4:c4", "08:60:6e", "1c:87:2c", "2c:56:dc", "30:5a:3a", "38:d5:47", "50:46:5d")
_add("Linksys", "00:04:5a", "00:06:25", "00:0c:41", "00:0f:66", "00:12:17", "00:13:10",
     "00:14:bf", "00:16:b6", "00:18:39", "00:18:f8", "00:1a:70", "00:1c:10", "00:1d:7e",
     "00:1e:e5", "00:21:29", "00:22:6b", "00:23:69", "00:25:9c")
_add("Aruba / HPE", "00:0b:86", "00:1a:1e", "24:de:c6", "6c:f3:7f", "94:b4:0f", "d8:c7:c8")
_add("Huawei", "00:18:82", "00:1e:10", "00:25:9e", "00:46:4b", "04:bd:70", "10:47:80",
     "28:31:52", "48:46:fb", "5c:4c:a9", "70:72:3c", "80:fb:06", "e0:24:7f")
_add("Xiaomi", "0c:1d:af", "10:2a:b3", "14:f6:5a", "28:6c:07", "34:ce:00", "50:8f:4c",
     "64:09:80", "68:df:dd", "74:23:44", "78:11:dc", "8c:be:be", "f0:b4:29")
_add("Intel", "00:1b:21", "00:1e:67", "00:21:6a", "00:24:d7", "34:13:e8", "3c:a9:f4",
     "5c:51:4f", "7c:7a:91", "8c:a9:82", "94:65:9c", "a0:88:b4", "34:f3:9a", "e4:a4:71")
_add("Realtek", "00:e0:4c", "52:54:ab")
_add("Dell", "00:06:5b", "00:08:74", "00:0b:db", "00:11:43", "00:14:22", "00:19:b9",
     "00:1e:4f", "00:21:9b", "00:24:e8", "18:03:73", "b8:2a:72", "f8:bc:12")
_add("Hewlett-Packard", "00:0e:7f", "00:11:0a", "00:14:38", "00:17:08", "00:1f:29",
     "00:21:5a", "00:23:7d", "00:25:b3", "3c:d9:2b", "9c:8e:99")
_add("Lenovo", "00:06:1b", "00:59:07", "50:7b:9d", "54:ee:75", "8c:16:45", "e8:6a:64")
_add("VMware (virtual)", "00:05:69", "00:0c:29", "00:1c:14", "00:50:56")
_add("VirtualBox (virtual)", "08:00:27")
_add("QEMU / KVM (virtual)", "52:54:00")

# --- device classification --------------------------------------------------
VENDOR_DEVICE = {
    "Sony Interactive (PlayStation)": "PlayStation console",
    "Microsoft (Xbox / Surface)": "Xbox / Windows device",
    "Nintendo": "Nintendo console",
    "Apple": "Apple device (Mac / iPhone / iPad)",
    "Samsung": "Samsung device (phone / TV)",
    "Google / Nest": "Google / Nest device",
    "Amazon": "Amazon device (Echo / Fire)",
    "Raspberry Pi": "Raspberry Pi",
    "Espressif (ESP IoT)": "IoT device (ESP)",
    "Roku": "Roku streaming device",
    "Sonos": "Sonos speaker",
    "Philips Hue": "Smart lighting (Hue)",
    "Cisco": "Network gear (router / switch)",
    "Cisco Meraki": "Network gear (AP / switch)",
    "Ubiquiti": "Network gear (router / AP)",
    "Netgear": "Router / access point",
    "TP-Link": "Router / access point",
    "D-Link": "Router / access point",
    "ASUS": "Router or PC",
    "Linksys": "Router / access point",
    "Aruba / HPE": "Network gear (AP / switch)",
    "Huawei": "Router / phone",
    "Xiaomi": "Phone / IoT device",
    "Intel": "PC (Intel NIC)",
    "Realtek": "PC (Realtek NIC)",
    "Dell": "PC / server",
    "Hewlett-Packard": "PC / printer / server",
    "Lenovo": "PC / laptop",
    "VMware (virtual)": "Virtual machine",
    "VirtualBox (virtual)": "Virtual machine",
    "QEMU / KVM (virtual)": "Virtual machine",
}

# Hostname keywords refine the guess when reverse DNS / mDNS gives a name.
HOST_HINTS = [
    ("playstation", "PlayStation console"), ("ps4", "PlayStation console"), ("ps5", "PlayStation console"),
    ("xbox", "Xbox console"), ("nintendo", "Nintendo console"), ("switch", "Nintendo Switch"),
    ("iphone", "iPhone"), ("ipad", "iPad"), ("macbook", "MacBook"), ("android", "Android device"),
    ("galaxy", "Samsung Galaxy"), ("pixel", "Google Pixel"), ("echo", "Amazon Echo"),
    ("firetv", "Amazon Fire TV"), ("roku", "Roku"), ("chromecast", "Chromecast"),
    ("raspberry", "Raspberry Pi"), ("router", "Router"), ("gateway", "Gateway / router"),
    ("printer", "Printer"), ("camera", "IP camera"), ("tv", "Smart TV"),
]


def _norm_mac(mac):
    return (mac or "").lower().replace("-", ":").strip()


def oui_lookup(mac):
    return OUI.get(_norm_mac(mac)[:8], "")


def classify(vendor, hostname):
    h = (hostname or "").lower()
    for kw, label in HOST_HINTS:
        if kw in h:
            return label
    return VENDOR_DEVICE.get(vendor, "Unknown device")


# --- discovery --------------------------------------------------------------
def _default_cidr(iface):
    try:
        from scapy.all import get_if_addr
        ip = get_if_addr(iface) if iface else get_if_addr(__import__("scapy.all", fromlist=["conf"]).conf.iface)
    except Exception:
        ip = None
    if not ip or ip == "0.0.0.0":
        return None
    try:
        return str(ipaddress.ip_network(ip + "/24", strict=False))
    except Exception:
        return None


def _local_ip(iface):
    try:
        from scapy.all import get_if_addr
        return get_if_addr(iface) if iface else None
    except Exception:
        return None


def _arp_scan(iface, cidr, timeout):
    """Active ARP sweep. Raises PermissionError without raw-socket rights."""
    from scapy.all import srp, Ether, ARP, conf
    conf.verb = 0
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    kwargs = {"timeout": timeout, "verbose": 0, "retry": 1}
    if iface:
        kwargs["iface"] = iface
    ans, _ = srp(pkt, **kwargs)
    seen = {}
    for _snd, rcv in ans:
        seen[rcv.psrc] = {"ip": rcv.psrc, "mac": _norm_mac(rcv.hwsrc)}
    return list(seen.values())


def _neighbour_table():
    """Passive fallback: read the OS neighbour/ARP cache."""
    out = []
    try:
        res = subprocess.run(["ip", "neigh"], capture_output=True, text=True, timeout=5)
        for line in res.stdout.splitlines():
            m = re.match(r"(\S+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]{17})", line)
            if m:
                out.append({"ip": m.group(1), "mac": _norm_mac(m.group(2))})
    except Exception:
        pass
    if not out:
        try:
            with open("/proc/net/arp") as fh:
                for line in fh.readlines()[1:]:
                    cols = line.split()
                    if len(cols) >= 4 and cols[3] != "00:00:00:00:00:00":
                        out.append({"ip": cols[0], "mac": _norm_mac(cols[3])})
        except Exception:
            pass
    return out


def _sort_key(ip):
    try:
        return (0,) + tuple(int(x) for x in ip.split("."))
    except Exception:
        return (1, ip)


def scan(iface=None, cidr=None, resolve=True, timeout=3):
    cidr = (cidr or "").strip() or _default_cidr(iface) or "192.168.1.0/24"
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except Exception:
        raise ValueError(f"'{cidr}' is not a valid network (use e.g. 192.168.1.0/24).")
    cidr = str(net)

    method = "arp"
    note = None
    try:
        hosts = _arp_scan(iface, cidr, timeout)
    except PermissionError:
        hosts, method = [], "table"
        note = "Active ARP scan needs root; showing the neighbour cache instead. Run with sudo for a full sweep."
    except Exception as exc:
        hosts, method = [], "table"
        note = f"ARP scan unavailable ({exc}); showing the neighbour cache instead."

    if not hosts and method == "arp":
        # Nothing answered; supplement with the neighbour table.
        method = "table"
    if method == "table":
        hosts = [h for h in _neighbour_table()
                 if _in_net(h["ip"], net)]

    own_ip = _local_ip(iface)
    for h in hosts:
        h["vendor"] = oui_lookup(h["mac"])
        h["hostname"] = None
        h["is_self"] = (own_ip is not None and h["ip"] == own_ip)

    if resolve and hosts:
        names = intel_mod.resolve_names([h["ip"] for h in hosts])
        for h in hosts:
            h["hostname"] = names.get(h["ip"])

    for h in hosts:
        h["device"] = classify(h["vendor"], h.get("hostname"))

    hosts.sort(key=lambda h: _sort_key(h["ip"]))
    return {"cidr": cidr, "iface": iface, "method": method, "note": note,
            "count": len(hosts), "hosts": hosts}


def _in_net(ip, net):
    try:
        return ipaddress.ip_address(ip) in net
    except Exception:
        return False
