"""
Transparent interception and traffic shaping (MITM).

Redirects a target host's traffic through this machine with ARP poisoning so
it can be captured and shaped without touching the target itself. Meant for
a malware-analysis VM whose traffic you want to record, or your own device
on your own network.

The target stays online because IP forwarding is switched on for the
duration (this box just routes for it), and the previous setting is restored
on stop. Stopping also re-ARPs the correct MAC mappings for the target and
gateway to heal the caches, and tears down any traffic shaping (tc netem)
that was applied. Capture itself is just the normal capture engine sniffing
the same interface, so once traffic is redirected here it shows up in the
live table and PCAP export like anything else.

Primarily developed and tested on Linux, where enabling/restoring IP
forwarding is exact (the real /proc/sys value is read back and restored).
macOS and Windows are supported on a best-effort basis (sysctl and netsh,
respectively); status()/the UI surface a warning if forwarding couldn't be
confirmed on either, since that's the most common way this looks like it
"isn't doing anything" — the ARP poisoning can succeed while the box never
actually relays the traffic.

Only run this against your own devices or a network/engagement you're
explicitly authorised to test. Intercepting traffic without authorisation is
illegal in most places and is not what this tool is for.
"""

import os
import platform
import subprocess
import threading
import time
from typing import Optional

IP_FORWARD = "/proc/sys/net/ipv4/ip_forward"
PLATFORM = platform.system()  # 'Linux', 'Darwin', or 'Windows'


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
        # Forwarding + health diagnostics, surfaced in status() so a silent
        # failure (wrong privileges, unsupported OS mechanism, poisoning
        # that stops landing) shows up in the UI instead of just "nothing
        # happens".
        self._forwarding_prev = None
        self._forwarding_ok = False
        self._warnings: list = []
        self._last_error: Optional[str] = None

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
        """ARP-resolve an IP to a MAC, or None if nothing answered.

        Deliberately does NOT catch PermissionError: that means Scapy
        couldn't open a raw socket (not root/administrator), which is a
        completely different problem from "the target didn't answer" and
        needs to surface as its own error instead of being reported as a
        dead host.
        """
        from scapy.all import srp1, Ether, ARP
        try:
            ans = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                       iface=self.iface, timeout=2, retry=2, verbose=0)
        except PermissionError:
            raise
        except Exception:
            return None
        if ans is not None and ans.haslayer(ARP):
            return ans[ARP].hwsrc
        return None

    def _write_sysctl(self, path, value):
        """Set a /proc/sys value on Linux, remembering the old one for restore."""
        try:
            with open(path) as f:
                prev = f.read().strip()
            if path not in self._sysctl_saved:
                self._sysctl_saved[path] = prev
            with open(path, "w") as f:
                f.write(str(value) + "\n")
            return True
        except Exception:
            return False

    def _restore_sysctls(self):
        for path, prev in self._sysctl_saved.items():
            try:
                with open(path, "w") as f:
                    f.write(prev + "\n")
            except Exception:
                pass
        self._sysctl_saved = {}

    # --- IP forwarding (cross-platform) -----------------------------------
    # ARP-poisoning only redirects traffic to us; without IP forwarding
    # turned on for the duration, this host just silently drops it instead
    # of relaying it, which looks exactly like "interception isn't doing
    # anything" from the UI. Linux is handled precisely (read/write the
    # real sysctl and restore the exact previous value). macOS and Windows
    # use their own toggles; since this project is mainly run and tested on
    # Linux, those paths are best-effort and their success is verified and
    # reported back in status()/warnings rather than assumed.
    def _get_forwarding_state(self):
        if PLATFORM == "Linux":
            try:
                with open(IP_FORWARD) as f:
                    return f.read().strip()
            except Exception:
                return None
        if PLATFORM == "Darwin":
            try:
                r = subprocess.run(["sysctl", "-n", "net.inet.ip.forwarding"],
                                   capture_output=True, text=True, timeout=3)
                return r.stdout.strip() if r.returncode == 0 else None
            except Exception:
                return None
        if PLATFORM == "Windows":
            try:
                r = subprocess.run(
                    ["netsh", "interface", "ipv4", "show", "interface", self.iface],
                    capture_output=True, text=True, timeout=5)
                for line in r.stdout.splitlines():
                    if "forward" in line.lower():
                        return "1" if "enabled" in line.lower() else "0"
            except Exception:
                pass
            return None
        return None

    def _set_forwarding_state(self, enabled: bool) -> bool:
        if PLATFORM == "Linux":
            ok = self._write_sysctl(IP_FORWARD, 1 if enabled else 0)
            # Also stop the kernel telling the target to bypass us via ICMP
            # redirects; best-effort, doesn't affect the ok/fail result.
            for path in ("/proc/sys/net/ipv4/conf/all/send_redirects",
                         "/proc/sys/net/ipv4/conf/default/send_redirects",
                         f"/proc/sys/net/ipv4/conf/{self.iface}/send_redirects"):
                self._write_sysctl(path, 0)
            return ok
        if PLATFORM == "Darwin":
            try:
                r = subprocess.run(
                    ["sysctl", "-w", f"net.inet.ip.forwarding={1 if enabled else 0}"],
                    capture_output=True, text=True, timeout=3)
                return r.returncode == 0
            except Exception:
                return False
        if PLATFORM == "Windows":
            try:
                state = "enabled" if enabled else "disabled"
                r = subprocess.run(
                    ["netsh", "interface", "ipv4", "set", "interface", self.iface,
                     f"forwarding={state}"], capture_output=True, text=True, timeout=5)
                return r.returncode == 0
            except Exception:
                return False
        return False

    def _apply_forwarding(self):
        self._forwarding_prev = self._get_forwarding_state()
        self._forwarding_ok = self._set_forwarding_state(True)
        if not self._forwarding_ok:
            self._warnings.append(
                f"Could not confirm IP forwarding turned on for this OS ({PLATFORM}). "
                "Without it, the target may just lose connectivity instead of being "
                "relayed through this host — enable IP forwarding for this interface "
                "manually and retry.")

    def _restore_forwarding(self):
        if PLATFORM == "Linux":
            self._restore_sysctls()
            return
        was_enabled = self._forwarding_prev in ("1", "enabled")
        self._set_forwarding_state(was_enabled)
        self._forwarding_prev = None

    # --- lifecycle -------------------------------------------------------
    def start(self, iface, target_ip, gateway_ip=None, bidirectional=True):
        with self._lock:
            if self.active:
                raise RuntimeError("Interception is already running. Stop it first.")
            target_ip = (target_ip or "").strip()
            if not target_ip:
                raise ValueError("A target IP address is required.")
            from scapy.all import get_if_hwaddr, get_if_addr

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

            try:
                our_ip = get_if_addr(self.iface)
            except Exception:
                our_ip = None
            if our_ip and our_ip not in ("0.0.0.0", "") and our_ip in (self.target_ip, self.gateway_ip):
                raise ValueError(f"{our_ip} is this machine's own address on {self.iface}, "
                                 "not something it can meaningfully poison.")

            self.target_mac = self._resolve_mac(self.target_ip)
            if not self.target_mac:
                raise ValueError(f"No ARP reply from target {self.target_ip}. "
                                 f"Is it online and on the same subnet as {self.iface}?")
            self.gateway_mac = self._resolve_mac(self.gateway_ip)
            if not self.gateway_mac:
                raise ValueError(f"No ARP reply from gateway {self.gateway_ip}.")
            if self.target_mac == self.our_mac or self.gateway_mac == self.our_mac:
                raise ValueError("The target or gateway resolved to this machine's own MAC "
                                 "address; double-check the IPs.")

            self._warnings = []
            self._last_error = None
            self._apply_forwarding()
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
        consecutive_errors = 0
        while not self._stop.is_set():
            try:
                # Tell the target that the gateway IP is at our MAC.
                self._send_arp(self.target_ip, self.target_mac, self.gateway_ip, self.our_mac)
                self._arp_sent += 1
                if self.bidirectional:
                    # Tell the gateway that the target IP is at our MAC.
                    self._send_arp(self.gateway_ip, self.gateway_mac, self.target_ip, self.our_mac)
                    self._arp_sent += 1
                consecutive_errors = 0
            except Exception as exc:
                consecutive_errors += 1
                self._last_error = str(exc)
                # One-shot warnings so it doesn't spam status() every loop.
                if consecutive_errors == 3:
                    self._warnings.append(f"ARP poisoning is failing to send: {exc}")
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
            self._restore_forwarding()
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
            "platform": PLATFORM, "forwarding_ok": self._forwarding_ok,
            "warnings": list(self._warnings), "last_error": self._last_error,
        }
