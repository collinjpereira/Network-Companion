"""
Self-traffic registry.

Network Companion generates real network traffic of its own: IP-intel
lookups, reverse-DNS for the "Resolve names" toggle, and (optionally)
packets sent by the Crafter, Port Scan, and Transfer tools. When capturing
on a real interface, all of that looks just like any other packet on the
wire. This module lets those senders mark what they're about to do *before*
they do it, so capture.py can recognise and divert it into the "NC Traffic"
tab instead of the analyst's main capture.

Marking has to happen before the packet goes out, not after: the OS assigns
an outbound TCP/UDP source port synchronously inside connect()/send(), often
before Python control returns to the caller. reserve_local_port() exists so
callers can learn a free port from the OS, register it, and then bind their
real socket(s) to that same port before dialing out.
"""

import socket
import threading
import time

_lock = threading.Lock()
_ports: dict[int, float] = {}      # local port -> expiry epoch
_ptr_pending: dict[str, float] = {}  # ip -> expiry epoch
_host_cache: dict[str, tuple[set, float]] = {}  # hostname -> (ips, expiry epoch)

PORT_TTL_DEFAULT = 30.0
PTR_TTL_DEFAULT = 8.0
HOST_TTL = 300.0

# Hostnames intel.py calls out to. Kept here (not imported from intel.py) so
# this module has no dependency on it.
INTEL_HOSTNAMES = ("ip-api.com", "api.abuseipdb.com")


def mark_port(port, ttl: float = PORT_TTL_DEFAULT):
    """Register a local TCP/UDP port as ours for the next `ttl` seconds."""
    if not port:
        return
    with _lock:
        _ports[int(port)] = time.time() + ttl


def is_self_port(port) -> bool:
    if not port:
        return False
    port = int(port)
    now = time.time()
    with _lock:
        exp = _ports.get(port)
        if exp is None:
            return False
        if exp < now:
            del _ports[port]
            return False
        return True


def reserve_local_port() -> int:
    """Ask the OS for a free ephemeral port, mark it as ours, and return it
    so the caller can bind its real socket(s) to the same port before
    connecting. Small unavoidable race: something else could grab the port
    between this call and the caller's bind(); acceptable for a best-effort
    classification heuristic."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("", 0))
        port = probe.getsockname()[1]
    finally:
        probe.close()
    mark_port(port, ttl=120.0)
    return port


def mark_ptr(ip: str, ttl: float = PTR_TTL_DEFAULT):
    """Register that we're about to send a reverse-DNS (PTR) query for ip."""
    if not ip:
        return
    with _lock:
        _ptr_pending[ip] = time.time() + ttl


def is_pending_ptr(ip: str) -> bool:
    if not ip:
        return False
    now = time.time()
    with _lock:
        exp = _ptr_pending.get(ip)
        if exp is None:
            return False
        if exp < now:
            del _ptr_pending[ip]
            return False
        return True


def _resolve_host(host: str) -> set:
    now = time.time()
    cached = _host_cache.get(host)
    if cached and cached[1] > now:
        return cached[0]
    try:
        infos = socket.getaddrinfo(host, None)
        ips = {info[4][0] for info in infos}
    except Exception:
        ips = cached[0] if cached else set()
    _host_cache[host] = (ips, now + HOST_TTL)
    return ips


def is_intel_host_ip(ip: str) -> bool:
    if not ip:
        return False
    for host in INTEL_HOSTNAMES:
        if ip in _resolve_host(host):
            return True
    return False
