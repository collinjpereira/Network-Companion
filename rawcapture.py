"""
Raw packet readers.

The capture engine used to hand everything to Scapy's AsyncSniffer, which
reads a packet and fully dissects it on the same thread before reading the
next one. On a busy link that's slow enough for the capture driver's buffer
to overflow, and anything that overflows is gone for good. On Windows it's
worse than it needs to be: Scapy never sets Npcap's buffer size (so it stays
at the ~1 MB default) and copies each frame out of the driver one byte at a
time through a Python list.

This follows the same split Wireshark uses with dumpcap: capture happens in
its own process (see ProcessReader below) that does as little as possible
per packet. It pulls the raw bytes and timestamp off the driver and appends
them straight to a pcap file on disk (the "spool"); the app follows that
file and dissects from it at its own pace. So:

  * a slow moment in dissection or the UI only grows the backlog waiting
    in the file; it can't make the driver drop packets,
  * everything captured is on disk as it arrives, so a crash, a frozen
    window or running low on memory doesn't lose the capture, and
  * the driver's own drop counter is reported, so "nothing was lost" is
    something you can check rather than assume.
"""

import os
import select
import socket
import struct
import threading
import time
from collections import deque
from ctypes import POINTER, byref, c_ubyte, create_string_buffer, string_at
from typing import Optional

from scapy.all import conf
from scapy.interfaces import network_name

# Per-capture kernel buffer (adjustable per capture from the UI). Npcap's
# default is 1 MB, which a gigabit burst fills in under 10 ms; 256 MB rides
# out several seconds of a stall.
DRIVER_BUFFER_BYTES = 256 * 1024 * 1024
DRIVER_BUFFER_CHOICES_MB = (64, 256, 512, 1024)
SNAPLEN = 262144          # whole frames, including jumbo / offloaded ones
READ_TIMEOUT_MS = 100     # how often a quiet reader wakes to check for stop
STATS_INTERVAL = 0.1      # seconds between driver counter reads / spool flushes

_PCAP_HEADER = struct.Struct("<IHHiIII")
_PCAP_RECORD = struct.Struct("<IIII")


class Spool:
    """Append-only classic pcap file, written by the reader thread."""

    def __init__(self, path: str, linktype: int):
        self.path = path
        self._fh = open(path, "wb", buffering=1024 * 1024)
        self._fh.write(_PCAP_HEADER.pack(0xA1B2C3D4, 2, 4, 0, 0, SNAPLEN, linktype))
        self.bytes = _PCAP_HEADER.size
        self.count = 0
        self.error: Optional[str] = None

    def write(self, sec: int, usec: int, data: bytes, wirelen: int):
        if self._fh is None:
            return
        try:
            self._fh.write(_PCAP_RECORD.pack(sec, usec, len(data), wirelen))
            self._fh.write(data)
            self.bytes += _PCAP_RECORD.size + len(data)
            self.count += 1
        except OSError as exc:
            # Disk full or similar: keep capturing to memory and say so.
            self.error = str(exc)
            self.close()

    def flush(self):
        if self._fh is not None:
            try:
                self._fh.flush()
            except OSError as exc:
                self.error = str(exc)

    def close(self):
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None


class _ReaderBase:
    """Common bits: the output deque, the optional spool, the stop flag, the
    thread, and the driver stats ({received, dropped, ifdropped}, or None
    where the OS doesn't expose them)."""

    def __init__(self, out: deque, spool_path: Optional[str]):
        self.out = out
        self.error: Optional[str] = None
        self.stats: Optional[dict] = None
        self.spool: Optional[Spool] = None
        self._spool_path = spool_path
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _open_spool(self, linktype: int):
        if not self._spool_path:
            return
        try:
            self.spool = Spool(self._spool_path, linktype)
        except OSError as exc:
            self.error = f"Could not create capture file: {exc}"

    def start(self):
        self._thread = threading.Thread(target=self._run_safe, name="nc-reader", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    @property
    def alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    capturing = alive
    on_disk = 0

    def abandon(self):
        """Stop delivering frames (the capture is being discarded)."""
        self.stop()

    def _run_safe(self):
        try:
            self._run()
        except Exception as exc:
            self.error = str(exc)
        finally:
            if self.spool is not None:
                self.spool.close()
            self._close()

    def _run(self):
        raise NotImplementedError

    def _close(self):
        pass


class NpcapReader(_ReaderBase):
    """Reads straight from Npcap/libpcap via Scapy's ctypes bindings, with a
    large driver buffer and a fast copy of each frame."""

    def __init__(self, out: Optional[deque], iface, bpf: Optional[str], promisc: bool,
                 spool_path: Optional[str] = None,
                 buffer_bytes: int = DRIVER_BUFFER_BYTES):
        super().__init__(out, spool_path)
        self.shared = None  # set in the capture child process
        from scapy.libs import winpcapy as wp
        self._wp = wp
        errbuf = create_string_buffer(wp.PCAP_ERRBUF_SIZE)
        dev = network_name(iface or conf.iface).encode("utf8")
        self._p = wp.pcap_create(dev, errbuf)
        if not self._p:
            raise OSError(errbuf.value.decode(errors="replace") or "pcap_create failed")
        wp.pcap_set_snaplen(self._p, SNAPLEN)
        wp.pcap_set_promisc(self._p, 1 if promisc else 0)
        wp.pcap_set_timeout(self._p, READ_TIMEOUT_MS)
        wp.pcap_set_buffer_size(self._p, int(buffer_bytes))
        status = wp.pcap_activate(self._p)
        if status < 0:
            msg = self._geterr()
            self._close()
            if "denied" in msg.lower() or "access" in msg.lower():
                raise PermissionError(msg)
            raise OSError(msg or f"pcap_activate failed ({status})")
        if bpf:
            prog = wp.bpf_program()
            if wp.pcap_compile(self._p, byref(prog), bpf.encode(), 1, 0xFFFFFFFF) != 0:
                msg = self._geterr()
                self._close()
                raise ValueError(f"Invalid capture filter: {msg}")
            rc = wp.pcap_setfilter(self._p, byref(prog))
            wp.pcap_freecode(byref(prog))
            if rc != 0:
                msg = self._geterr()
                self._close()
                raise OSError(msg)
        dlt = wp.pcap_datalink(self._p)
        self.ll = conf.l2types.get(dlt, conf.default_l2)
        self.stats = {"received": 0, "dropped": 0, "ifdropped": 0}
        self._open_spool(dlt)

    def _geterr(self) -> str:
        raw = self._wp.pcap_geterr(self._p) or b""
        return raw.decode(errors="replace") if isinstance(raw, bytes) else str(raw)

    def _read_stats(self):
        st = self._wp.pcap_stat()
        if self._wp.pcap_stats(self._p, byref(st)) == 0:
            self.stats = {"received": st.ps_recv, "dropped": st.ps_drop,
                          "ifdropped": st.ps_ifdrop}

    def _publish(self):
        """Child process only: share counters with the app process."""
        sh = self.shared
        if sh is None:
            return
        st = self.stats or {}
        sh[0] = st.get("received", 0)
        sh[1] = st.get("dropped", 0)
        sh[2] = st.get("ifdropped", 0)
        if self.spool is not None:
            sh[3] = self.spool.count
            sh[4] = self.spool.bytes

    def _run(self):
        wp, p, out, ll, spool = self._wp, self._p, self.out, self.ll, self.spool
        hdr = POINTER(wp.pcap_pkthdr)()
        data = POINTER(c_ubyte)()
        next_ex = wp.pcap_next_ex

        def take():
            rc = next_ex(p, byref(hdr), byref(data))
            if rc == 1:
                h = hdr.contents
                sec, usec = h.ts.tv_sec, h.ts.tv_usec
                frame = string_at(data, h.caplen)
                if spool is not None:
                    spool.write(sec, usec, frame, h.len)
                if out is not None:
                    out.append((sec + usec / 1e6, frame, h.len, ll))
            elif rc < 0:
                raise OSError(self._geterr() or f"pcap_next_ex failed ({rc})")
            return rc

        next_stats = time.monotonic() + STATS_INTERVAL
        while not self._stop.is_set():
            take()
            now = time.monotonic()
            if now >= next_stats:
                self._read_stats()
                if spool is not None:
                    spool.flush()
                self._publish()
                next_stats = now + STATS_INTERVAL
        # Stopping: take the final counters, then drain everything the driver
        # had already buffered by then, so every packet it counted is kept.
        self._read_stats()
        wp.pcap_setnonblock(p, 1, create_string_buffer(wp.PCAP_ERRBUF_SIZE))
        while take() == 1:
            pass

    def _close(self):
        if self._p:
            self._wp.pcap_close(self._p)
            self._p = None


class SocketReader(_ReaderBase):
    """Fallback for platforms without libpcap (e.g. Linux using Scapy's
    native sockets): Scapy's L2 listen socket, read without dissection."""

    def __init__(self, out: deque, iface, bpf: Optional[str], promisc: bool,
                 spool_path: Optional[str] = None):
        super().__init__(out, spool_path)
        kwargs = {"promisc": promisc}
        if iface:
            kwargs["iface"] = iface
        if bpf:
            kwargs["filter"] = bpf
        self._sock = conf.L2listen(**kwargs)
        ins = getattr(self._sock, "ins", None)
        if isinstance(ins, socket.socket):
            try:
                ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, DRIVER_BUFFER_BYTES)
            except OSError:
                pass

    def _run(self):
        sock, out = self._sock, self.out
        next_flush = time.monotonic() + STATS_INTERVAL
        while not self._stop.is_set():
            ready, _, _ = select.select([sock], [], [], READ_TIMEOUT_MS / 1000)
            if ready:
                cls, data, ts = sock.recv_raw()
                if data is not None:
                    cls = cls or conf.default_l2
                    ts = ts or time.time()
                    if self.spool is None and self._spool_path and not self.error:
                        self._open_spool(conf.l2types.layer2num.get(cls, 1))
                    if self.spool is not None:
                        sec = int(ts)
                        self.spool.write(sec, int(round((ts - sec) * 1e6)), data, len(data))
                    out.append((ts, data, len(data), cls))
            now = time.monotonic()
            if now >= next_flush and self.spool is not None:
                self.spool.flush()
                next_flush = now + STATS_INTERVAL

    def _close(self):
        try:
            self._sock.close()
        except Exception:
            pass


def open_reader(out: deque, iface, bpf: Optional[str], promisc: bool,
                spool_path: Optional[str] = None,
                buffer_bytes: int = DRIVER_BUFFER_BYTES):
    """Pick the most robust reader available on this machine: a separate
    capture process where libpcap/Npcap is available, falling back to an
    in-process reader thread if the child process can't be started."""
    if conf.use_pcap or getattr(conf, "use_npcap", False):
        if spool_path:
            try:
                return ProcessReader(out, iface, bpf, promisc, spool_path, buffer_bytes)
            except (PermissionError, ValueError):
                raise  # a real capture problem (no rights, bad filter)
            except Exception:
                pass
        return NpcapReader(out, iface, bpf, promisc, spool_path, buffer_bytes)
    return SocketReader(out, iface, bpf, promisc, spool_path)


# --- capture in a separate process (the dumpcap approach) -----------------
#
# Even with the reader on its own thread, it still shares Python's GIL with
# the thread dissecting packets, so during a sustained flood it only gets a
# share of the CPU and the driver buffer slowly fills. Wireshark avoids this
# by capturing in a separate program (dumpcap) that does nothing but move
# packets from the driver to a file, while the GUI reads that file. This is
# the same thing: a child process drains the driver into the capture file,
# and the app follows the file and dissects from it at whatever pace it can.
# The file on disk is the queue, so dissection speed can't cause drops.

MAX_QUEUED = 50000   # frames read from the file ahead of the dissector; the
                     # rest of any backlog waits on disk instead of in RAM

_SHARED_RECEIVED, _SHARED_DROPPED, _SHARED_IFDROPPED, _SHARED_WRITTEN, _SHARED_BYTES = range(5)


def _capture_process(iface, bpf, promisc, buffer_bytes, path, shared, stop, status_q):
    """Entry point of the capture child process."""
    try:
        reader = NpcapReader(None, iface, bpf, promisc, path, buffer_bytes)
        if reader.spool is None:
            raise OSError(reader.error or "Could not create the capture file.")
    except Exception as exc:
        status_q.put(("error", type(exc).__name__, str(exc)))
        return
    reader._stop = stop
    reader.shared = shared
    # If the app dies without stopping us (killed, crashed), stop capturing
    # rather than run on forever in the background.
    import multiprocessing as mp
    parent = mp.parent_process()
    if parent is not None:
        def _watch_parent():
            parent.join()
            stop.set()
        threading.Thread(target=_watch_parent, daemon=True).start()
    status_q.put(("ready", None, None))
    try:
        reader._run()
    except Exception as exc:
        status_q.put(("error", type(exc).__name__, str(exc)))
    finally:
        reader.spool.close()
        reader._publish()
        reader._close()


class _SpoolInfo:
    """What the engine shows about the capture file the child is writing."""

    def __init__(self, path, shared):
        self.path = path
        self._shared = shared
        self.error = None

    @property
    def bytes(self):
        return self._shared[_SHARED_BYTES]


class ProcessReader:
    """Main-process side of the capture child: starts it, follows the file
    it writes, and exposes the same interface as the in-process readers."""

    def __init__(self, out: deque, iface, bpf: Optional[str], promisc: bool,
                 spool_path: str, buffer_bytes: int = DRIVER_BUFFER_BYTES):
        import multiprocessing as mp
        ctx = mp.get_context("spawn")
        self.out = out
        self.path = spool_path
        self._shared = ctx.Array("q", 5, lock=False)
        self._stop = ctx.Event()
        self._status = ctx.Queue()
        self._proc = ctx.Process(
            target=_capture_process, name="nc-capture", daemon=True,
            args=(iface, bpf, promisc, buffer_bytes, spool_path,
                  self._shared, self._stop, self._status))
        self._proc.start()
        self._error: Optional[str] = None
        kind, etype, msg = self._next_status(timeout=60)
        if kind != "ready":
            self._proc.join(5)
            exc = {"PermissionError": PermissionError, "ValueError": ValueError}.get(etype, OSError)
            raise exc(msg or "The capture process failed to start.")
        self.spool = _SpoolInfo(spool_path, self._shared)
        self.tailed = 0
        self._abandoned = False
        self._tail_thread = threading.Thread(target=self._tail_safe, name="nc-tail", daemon=True)

    def _next_status(self, timeout):
        import queue
        try:
            return self._status.get(timeout=timeout)
        except queue.Empty:
            if not self._proc.is_alive():
                return ("error", "OSError", "The capture process exited unexpectedly.")
            return ("error", "OSError", "The capture process didn't start in time.")

    @property
    def error(self) -> Optional[str]:
        import queue
        while True:
            try:
                kind, _, msg = self._status.get_nowait()
            except (queue.Empty, OSError, ValueError):
                break
            if kind == "error":
                self._error = msg
                self.spool.error = msg
        if self._error is None and not self._stop.is_set() and not self._proc.is_alive():
            self._error = "The capture process stopped unexpectedly."
        return self._error

    @property
    def stats(self) -> dict:
        s = self._shared
        return {"received": s[_SHARED_RECEIVED], "dropped": s[_SHARED_DROPPED],
                "ifdropped": s[_SHARED_IFDROPPED]}

    @property
    def on_disk(self) -> int:
        """Packets written to the file that haven't been read back yet."""
        return max(0, self._shared[_SHARED_WRITTEN] - self.tailed)

    @property
    def capturing(self) -> bool:
        return self._proc.is_alive() and not self._stop.is_set()

    @property
    def alive(self) -> bool:
        return self._tail_thread.is_alive()

    def start(self):
        self._tail_thread.start()

    def stop(self):
        self._stop.set()
        self._proc.join(15)
        if self._proc.is_alive():
            self._proc.terminate()
        # The tail thread keeps going until it has read the whole file.

    def abandon(self):
        """Stop the capture and stop reading its file (it's being discarded;
        the file itself is left on disk)."""
        self._abandoned = True
        self.stop()
        self._tail_thread.join(5)

    def _tail_safe(self):
        try:
            self._tail()
        except Exception as exc:
            self._error = f"Reading the capture file failed: {exc}"

    def _tail(self):
        out = self.out
        rec = _PCAP_RECORD
        with open(self.path, "rb") as f:
            head = b""
            while len(head) < _PCAP_HEADER.size:
                more = f.read(_PCAP_HEADER.size - len(head))
                if more:
                    head += more
                elif not self._proc.is_alive():
                    return
                else:
                    time.sleep(0.02)
            linktype = _PCAP_HEADER.unpack(head)[6]
            ll = conf.l2types.get(linktype, conf.default_l2)
            buf = bytearray()
            while not self._abandoned:
                if len(out) >= MAX_QUEUED:
                    time.sleep(0.01)
                    continue
                chunk = f.read(1 << 20)
                if not chunk:
                    if not self._proc.is_alive():
                        # Writer is done; one last read catches anything
                        # flushed between the previous read and its exit.
                        chunk = f.read()
                        if not chunk:
                            return
                    else:
                        time.sleep(0.02)
                        continue
                buf += chunk
                pos, n, size = 0, 0, len(buf)
                while size - pos >= rec.size:
                    sec, usec, caplen, wirelen = rec.unpack_from(buf, pos)
                    end = pos + rec.size + caplen
                    if end > size:
                        break  # rest of this record isn't flushed yet
                    out.append((sec + usec / 1e6, bytes(buf[pos + rec.size:end]), wirelen, ll))
                    pos = end
                    n += 1
                del buf[:pos]
                self.tailed += n


# --- where capture files go ------------------------------------------------

def capture_dir() -> str:
    """Per-user folder for the capture file (created on first use)."""
    base = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), ".local", "share")
    path = os.path.join(base, "Network Companion", "captures")
    os.makedirs(path, exist_ok=True)
    return path


def recovered_dir() -> str:
    """Where capture files that were never saved end up (Documents)."""
    path = os.path.join(os.path.expanduser("~"), "Documents", "Network Companion Recovered")
    os.makedirs(path, exist_ok=True)
    return path


def keep_file(path: str) -> Optional[str]:
    """Move an unsaved capture file out of the temp folder into Documents so
    it can't be cleaned up. Returns the new path, or None if it failed."""
    try:
        folder = recovered_dir()
        stem, ext = os.path.splitext(os.path.basename(path))
        dest = os.path.join(folder, stem + ext)
        n = 1
        while os.path.exists(dest):  # never overwrite an earlier recovery
            dest = os.path.join(folder, f"{stem}_{n}{ext}")
            n += 1
        os.replace(path, dest)
        return dest
    except OSError:
        return None


def delete_file(path: Optional[str]):
    """Delete one capture file the user has saved or chosen to discard."""
    if path:
        try:
            os.remove(path)
        except OSError:
            pass


def rescue_leftovers() -> list:
    """Run at startup: any capture file still in the temp folder is from a
    session that ended without saving or discarding it (crash, killed, power
    loss). Never delete those; move them to Documents and report them."""
    try:
        folder = capture_dir()
        names = [n for n in os.listdir(folder) if n.endswith(".pcap")]
    except OSError:
        return []
    moved = []
    for name in names:
        path = os.path.join(folder, name)
        try:
            if os.path.getsize(path) <= _PCAP_HEADER.size:
                os.remove(path)  # empty capture, nothing to keep
                continue
        except OSError:
            continue
        dest = keep_file(path)
        if dest:
            moved.append(dest)
    return moved


def new_capture_path() -> Optional[str]:
    """Path for the next capture's file (a temporary file, like Wireshark's).
    It's only ever deleted once its packets have been saved or the user has
    chosen to discard them; see CaptureEngine."""
    try:
        folder = capture_dir()
    except OSError:
        return None
    return os.path.join(folder, time.strftime("capture_%Y-%m-%d_%H-%M-%S.pcap"))
