"""
File transfer.

Sends a file to another host two ways. TCP stream is netcat style: it opens
an ordinary TCP connection to host:port and streams the bytes, so the
receiving side needs to already be listening, e.g. `nc -l -p 9000 >
received.bin`. FTP upload STOREs the file on an FTP server you have
credentials for.

send_data can also push an arbitrary payload over a plain TCP or TLS
connection, for generating cleartext or encrypted application traffic
toward a host on your network.

These use normal OS sockets rather than raw packet crafting, since a real
transfer or an encrypted session needs an actual TCP connection. Use only
against hosts you own or are authorised to transfer to.
"""

import io
import os
import socket
import ssl
import tempfile
from ftplib import FTP

import selftraffic


def _mark_self(sock, ttl: float = 30.0):
    """Best-effort: the handshake already happened by the time connect()
    returns, but this still classifies the data/teardown that follows."""
    try:
        selftraffic.mark_port(sock.getsockname()[1], ttl=ttl)
    except Exception:
        pass


def tcp_send(host: str, port: int, data: bytes, timeout: float = 15.0) -> dict:
    if not host:
        raise ValueError("A destination host is required.")
    port = int(port)
    if not (0 < port < 65536):
        raise ValueError("Port must be between 1 and 65535.")
    sock = socket.create_connection((host, port), timeout=timeout)
    _mark_self(sock, ttl=timeout + 5.0)
    try:
        sock.sendall(data)
    finally:
        try:
            sock.shutdown(socket.SHUT_WR)
        except Exception:
            pass
        sock.close()
    return {"sent": len(data), "host": host, "port": port, "mode": "tcp"}


def send_data(host: str, port: int, data: bytes, use_tls: bool = False,
              read_response: bool = True, server_name: str = None,
              timeout: float = 12.0) -> dict:
    """Open a plain-TCP or TLS connection, send bytes, optionally read a reply.

    For TLS, also captures that session's key log (NSS key log format) and
    returns it as "keylog". Point Wireshark's TLS preferences at a file with
    that text (Preferences > Protocols > TLS > (Pre)-Master-Secret log
    filename) and it can decrypt the capture of this exact connection. Every
    connection gets its own fresh handshake and keys, so a new send means a
    new key log; nothing here is reused across requests.
    """
    if not host:
        raise ValueError("A destination host is required.")
    port = int(port)
    if not (0 < port < 65536):
        raise ValueError("Port must be between 1 and 65535.")
    raw = socket.create_connection((host, port), timeout=timeout)
    _mark_self(raw, ttl=timeout + 5.0)
    sock = raw
    tls_info = None
    keylog_path = None
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            # Lab tooling: don't fail the connection on self-signed / hostname
            # mismatch, which are common on internal test hosts.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                fd, keylog_path = tempfile.mkstemp(suffix=".keylog")
                os.close(fd)
                ctx.keylog_filename = keylog_path
            except Exception:
                keylog_path = None
            sock = ctx.wrap_socket(raw, server_hostname=(server_name or host))
            tls_info = {"cipher": sock.cipher()[0] if sock.cipher() else None,
                        "version": sock.version()}
        if data:
            sock.sendall(data)
        reply = b""
        if read_response:
            sock.settimeout(3.0)
            try:
                while len(reply) < 8192:
                    chunk = sock.recv(2048)
                    if not chunk:
                        break
                    reply += chunk
            except Exception:
                pass
        out = {"sent": len(data), "host": host, "port": port,
               "mode": "tls" if use_tls else "tcp",
               "received": len(reply),
               "response_preview": reply[:600].decode("latin-1", "replace")}
        if tls_info:
            out["tls"] = tls_info
        if keylog_path:
            try:
                with open(keylog_path) as f:
                    keylog = f.read().strip()
                if keylog:
                    out["keylog"] = keylog
            except Exception:
                pass
        return out
    finally:
        try:
            sock.close()
        except Exception:
            pass
        if keylog_path:
            try:
                os.remove(keylog_path)
            except Exception:
                pass


def ftp_upload(host: str, port: int, user: str, password: str,
               remote_name: str, data: bytes, timeout: float = 20.0) -> dict:
    if not host:
        raise ValueError("An FTP host is required.")
    if not remote_name:
        raise ValueError("A remote filename is required.")
    port = int(port or 21)
    ftp = FTP()
    ftp.connect(host, port, timeout=timeout)
    _mark_self(ftp.sock, ttl=timeout + 5.0)
    try:
        ftp.login(user or "anonymous", password or "anonymous@")
        ftp.storbinary(f"STOR {remote_name}", io.BytesIO(data))
    finally:
        try:
            ftp.quit()
        except Exception:
            ftp.close()
    return {"sent": len(data), "host": host, "port": port,
            "remote": remote_name, "mode": "ftp"}
