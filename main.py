"""
Network Companion backend.

Serves the single-page UI plus a small REST API and a WebSocket that streams
live captured packets to the browser.

Run:
    sudo ./run.sh
or:
    sudo -E python3 -m uvicorn main:app --host 127.0.0.1 --port 8787

Environment:
    NC_HOST   bind address (default 127.0.0.1; use 0.0.0.0 to reach it remotely)
    NC_PORT   port (default 8787)
    NC_AUTH   'user:password' to require HTTP Basic auth (recommended when the
              bind address is not localhost)
"""

import asyncio
import base64
import ipaddress
import os
import secrets
import tempfile
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, File, Form, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from scapy.all import PcapReader

import capture as capture_mod
import crafter as crafter_mod
import intel as intel_mod
import transfer as transfer_mod
import scan as scan_mod
import netdiscover as netdiscover_mod
import mitm as mitm_mod
import ipnotes as ipnotes_mod

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(HERE, "static")


class BasicAuthMiddleware:
    """Guards every HTTP and WebSocket request with HTTP Basic auth.

    Only installed when NC_AUTH is set (format 'user:password'). This exists so
    the tool can be reached from another machine without leaving an
    unauthenticated, root-privileged packet sender open on the network.
    """

    def __init__(self, app, user: str, password: str):
        self.app = app
        self.user = user
        self.password = password

    def _ok(self, header: str) -> bool:
        if not header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(header[6:]).decode()
            u, _, p = decoded.partition(":")
            return (secrets.compare_digest(u, self.user)
                    and secrets.compare_digest(p, self.password))
        except Exception:
            return False

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            headers = dict(scope.get("headers") or [])
            auth = headers.get(b"authorization", b"").decode()
            if not self._ok(auth):
                if scope["type"] == "http":
                    await send({"type": "http.response.start", "status": 401,
                                "headers": [(b"www-authenticate", b'Basic realm="Network Companion"'),
                                            (b"content-type", b"text/plain")]})
                    await send({"type": "http.response.body", "body": b"Authentication required"})
                    return
                try:
                    await receive()  # consume websocket.connect
                except Exception:
                    pass
                await send({"type": "websocket.close", "code": 1008})
                return
        await self.app(scope, receive, send)


app = FastAPI(title="Network Companion")

_auth = os.environ.get("NC_AUTH", "").strip()
if _auth and ":" in _auth:
    _u, _, _p = _auth.partition(":")
    app.add_middleware(BasicAuthMiddleware, user=_u, password=_p)

# --- live packet fan-out ---------------------------------------------------
# The Scapy sniffer runs in its own thread. We hand each packet to the asyncio
# loop via call_soon_threadsafe, which drops it onto every connected client's
# queue. Each WebSocket drains its own queue.

_loop: Optional[asyncio.AbstractEventLoop] = None
_subscribers: set[asyncio.Queue] = set()


def _dispatch(row: dict):
    """Called from the sniffer thread for every captured packet."""
    if _loop is None:
        return
    row["channel"] = "capture"
    _loop.call_soon_threadsafe(_fanout, row)


def _dispatch_nc(row: dict):
    """Called from the sniffer thread for packets classified as Network
    Companion's own traffic (see selftraffic.py / capture.classify_self_traffic)."""
    if _loop is None:
        return
    row["channel"] = "nc"
    _loop.call_soon_threadsafe(_fanout, row)


def _fanout(row: dict):
    for q in list(_subscribers):
        try:
            q.put_nowait(row)
        except asyncio.QueueFull:
            pass  # slow client; drop rather than block the loop


NC_PORT = int(os.environ.get("NC_PORT", "8787"))
engine = capture_mod.CaptureEngine(on_packet=_dispatch, on_nc_packet=_dispatch_nc,
                                   service_port=NC_PORT)
mitm_engine = mitm_mod.MitmEngine()


@app.on_event("startup")
async def _capture_loop():
    global _loop
    _loop = asyncio.get_running_loop()


@app.on_event("shutdown")
async def _cleanup():
    # Never leave the network in a poisoned / forwarding state.
    try:
        mitm_engine.stop()
    except Exception:
        pass


# --- request models --------------------------------------------------------

class StartRequest(BaseModel):
    iface: Optional[str] = None
    bpf: Optional[str] = None
    promisc: bool = True


class IntelRequest(BaseModel):
    ip: str
    api_key: Optional[str] = None


class ReplayRequest(BaseModel):
    count: int = 1
    interval: float = 0.0
    iface: Optional[str] = None


# --- API -------------------------------------------------------------------

@app.get("/api/interfaces")
async def interfaces():
    return {"interfaces": engine.list_interfaces()}


@app.get("/api/capture/status")
async def status():
    return {"running": engine.running, "count": engine.count(),
            "iface": engine.iface, "bpf": engine.bpf}


@app.post("/api/capture/start")
async def start(req: StartRequest):
    try:
        engine.start(iface=req.iface, bpf=req.bpf, promisc=req.promisc)
    except PermissionError:
        return JSONResponse(
            {"error": "Permission denied. Run with sudo so it can open "
                      "a raw socket for capture."}, status_code=403)
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    return {"running": True, "iface": engine.iface, "bpf": engine.bpf}


@app.post("/api/capture/stop")
async def stop():
    engine.stop()
    return {"running": False, "count": engine.count()}


@app.post("/api/capture/clear")
async def clear():
    engine.clear()
    return {"cleared": True}


@app.get("/api/nc/status")
async def nc_status():
    return {"count": engine.nc_count()}


@app.post("/api/nc/clear")
async def nc_clear():
    engine.clear_nc()
    return {"cleared": True}


@app.get("/api/nc/packet/{nc_id}")
async def nc_packet(nc_id: int):
    d = engine.get_nc_detail(nc_id)
    if d is None:
        return JSONResponse({"error": "No packet at that id."}, status_code=404)
    return d


@app.delete("/api/nc/packet/{nc_id}")
async def nc_packet_delete(nc_id: int):
    ok = engine.delete_nc(nc_id)
    if not ok:
        return JSONResponse({"error": "No packet at that id."}, status_code=404)
    return {"deleted": nc_id}


@app.post("/api/nc/packet/{nc_id}/replay")
async def nc_packet_replay(nc_id: int, req: ReplayRequest):
    pkt = engine.get_nc_packet(nc_id)
    if pkt is None:
        return JSONResponse({"error": "No packet at that id."}, status_code=404)
    try:
        return await asyncio.to_thread(crafter_mod.resend, pkt, req.count,
                                       (req.interval or 0) / 1000.0, req.iface or None)
    except PermissionError:
        return JSONResponse({"error": "Replaying packets needs sudo (raw socket)."}, status_code=403)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


class IpNoteRequest(BaseModel):
    color: Optional[str] = None
    tags: Optional[list[str]] = None
    description: Optional[str] = None


@app.get("/api/ip-notes")
async def ip_notes():
    return {"notes": ipnotes_mod.all_notes()}


@app.put("/api/ip-notes/{ip}")
async def ip_notes_upsert(ip: str, req: IpNoteRequest):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return JSONResponse({"error": f"'{ip}' is not a valid IP address."}, status_code=400)
    entry = ipnotes_mod.upsert(ip, color=req.color, tags=req.tags, description=req.description)
    return {"ip": ip, "note": entry}


@app.delete("/api/ip-notes/{ip}")
async def ip_notes_delete(ip: str):
    ipnotes_mod.delete(ip)
    return {"deleted": ip}


@app.get("/api/packet/{index}")
async def packet(index: int):
    d = engine.get_detail(index)
    if d is None:
        return JSONResponse({"error": "No packet at that index."}, status_code=404)
    return d


@app.get("/api/export")
async def export():
    if engine.count() == 0:
        return JSONResponse({"error": "No packets captured yet."}, status_code=400)
    fd, path = tempfile.mkstemp(suffix=".pcap", prefix="netco_")
    os.close(fd)
    engine.export_pcap(path)
    return FileResponse(path, filename="capture.pcap",
                        media_type="application/vnd.tcpdump.pcap")


@app.get("/api/export/all")
async def export_all():
    """Same as /api/export, but also includes everything diverted into NC
    Traffic. Opt-in via a separate button since NC Traffic is excluded by
    default."""
    if engine.count() == 0 and engine.nc_count() == 0:
        return JSONResponse({"error": "No packets captured yet."}, status_code=400)
    fd, path = tempfile.mkstemp(suffix=".pcap", prefix="netco_all_")
    os.close(fd)
    engine.export_pcap_all(path)
    return FileResponse(path, filename="capture_all_traffic.pcap",
                        media_type="application/vnd.tcpdump.pcap")


class CraftRequest(BaseModel):
    spec: dict


@app.post("/api/craft/preview")
async def craft_preview(req: CraftRequest):
    try:
        return crafter_mod.preview(req.spec)
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


@app.post("/api/craft/send")
async def craft_send(req: CraftRequest):
    try:
        return crafter_mod.craft_and_send(req.spec)
    except PermissionError:
        return JSONResponse(
            {"error": "Permission denied. Sending raw packets needs sudo."},
            status_code=403)
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


@app.post("/api/intel")
async def intel(req: IntelRequest):
    try:
        return intel_mod.lookup(req.ip, req.api_key)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


class FlagsRequest(BaseModel):
    ips: list[str]


@app.post("/api/geo-flags")
async def geo_flags(req: FlagsRequest):
    # Cap per request so a flood of unique IPs can't stall the loop.
    return {"countries": intel_mod.batch_country(req.ips[:200])}


@app.post("/api/resolve")
async def resolve(req: FlagsRequest):
    names = await asyncio.to_thread(intel_mod.resolve_names, req.ips[:100])
    return {"names": names}


@app.post("/api/geo-points")
async def geo_points(req: FlagsRequest):
    # Cap per request; batch_geo itself chunks to ip-api's 100-per-call limit.
    points = await asyncio.to_thread(intel_mod.batch_geo, req.ips[:300])
    return {"points": points}


@app.post("/api/pcap/load")
async def pcap_load(file: UploadFile = File(...)):
    data = await file.read()
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    with open(path, "wb") as fh:
        fh.write(data)
    pkts = []
    try:
        with PcapReader(path) as pr:
            for p in pr:
                pkts.append(p)
    except Exception as exc:
        os.remove(path)
        return JSONResponse({"error": f"Could not read capture file: {exc}"}, status_code=400)
    os.remove(path)
    if not pkts:
        return JSONResponse({"error": "No packets found in that file."}, status_code=400)
    engine.stop()  # don't mix a loaded file with a live capture
    rows = engine.load(pkts)
    return {"count": len(rows), "packets": rows, "name": file.filename}


class BpfRequest(BaseModel):
    filter: str


@app.post("/api/validate-bpf")
async def validate_bpf(req: BpfRequest):
    expr = (req.filter or "").strip()
    if not expr:
        return {"status": "empty"}
    try:
        from scapy.arch.common import compile_filter
        compile_filter(expr)
        return {"status": "valid"}
    except ImportError:
        return {"status": "unknown"}  # libpcap not available to validate against
    except Exception as exc:
        return {"status": "invalid", "error": str(exc)[:200]}


@app.post("/api/transfer/tcp")
async def transfer_tcp(host: str = Form(...), port: int = Form(...),
                       file: UploadFile = File(...)):
    data = await file.read()
    try:
        res = await asyncio.to_thread(transfer_mod.tcp_send, host, port, data)
        res["name"] = file.filename
        return res
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


@app.post("/api/transfer/ftp")
async def transfer_ftp(host: str = Form(...), port: int = Form(21),
                       user: str = Form(""), password: str = Form(""),
                       remote: str = Form(""), file: UploadFile = File(...)):
    data = await file.read()
    remote_name = remote or file.filename
    try:
        res = await asyncio.to_thread(transfer_mod.ftp_upload, host, port,
                                      user, password, remote_name, data)
        res["name"] = file.filename
        return res
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


class SendDataRequest(BaseModel):
    host: str
    port: int
    payload: str = ""
    payload_is_hex: bool = False
    tls: bool = False
    read_response: bool = True
    server_name: Optional[str] = None


@app.post("/api/transfer/send")
async def transfer_send(req: SendDataRequest):
    try:
        if req.payload_is_hex:
            cleaned = "".join(req.payload.split())
            data = bytes.fromhex(cleaned) if cleaned else b""
        else:
            data = req.payload.encode("utf-8", "replace")
    except ValueError:
        return JSONResponse({"error": "Payload is not valid hex."}, status_code=400)
    try:
        res = await asyncio.to_thread(transfer_mod.send_data, req.host, req.port,
                                      data, req.tls, req.read_response, req.server_name)
        return res
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


class ScanRequest(BaseModel):
    host: str
    ports: str = "top100"
    scan_type: str = "connect"
    banner: bool = False


@app.post("/api/scan")
async def scan(req: ScanRequest):
    host = (req.host or "").strip()
    if not host:
        return JSONResponse({"error": "A target host is required."}, status_code=400)
    try:
        ports = scan_mod.parse_ports(req.ports)
    except Exception:
        return JSONResponse({"error": "Could not parse that port range."}, status_code=400)
    if not ports:
        return JSONResponse({"error": "No valid ports in that range."}, status_code=400)
    if len(ports) > 5000:
        return JSONResponse({"error": f"That is {len(ports)} ports; keep a single scan to 5000 or fewer."}, status_code=400)
    import time as _time
    start = _time.time()
    try:
        if req.scan_type == "syn":
            results = await asyncio.to_thread(scan_mod.syn_scan, host, ports)
        else:
            results = await asyncio.to_thread(scan_mod.connect_scan, host, ports, 1.0, req.banner)
    except Exception as exc:
        return JSONResponse({"error": f"Scan failed: {exc}"}, status_code=400)
    for r in results:
        r["service"] = scan_mod.SERVICES.get(r["port"], "")
    return {"host": host, "scanned": len(ports),
            "open": sum(1 for r in results if r["state"] == "open"),
            "elapsed": round(_time.time() - start, 2),
            "scan_type": req.scan_type, "results": results}


class NetScanRequest(BaseModel):
    iface: Optional[str] = None
    cidr: Optional[str] = None
    resolve: bool = True


@app.post("/api/netscan")
async def netscan(req: NetScanRequest):
    try:
        return await asyncio.to_thread(netdiscover_mod.scan, req.iface, req.cidr, req.resolve)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except Exception as exc:
        return JSONResponse({"error": f"Network scan failed: {exc}"}, status_code=400)


@app.post("/api/packet/{index}/replay")
async def replay(index: int, req: ReplayRequest):
    pkt = engine.get_packet(index)
    if pkt is None:
        return JSONResponse({"error": "No packet at that index."}, status_code=404)
    try:
        return await asyncio.to_thread(crafter_mod.resend, pkt, req.count,
                                       (req.interval or 0) / 1000.0, req.iface or None)
    except PermissionError:
        return JSONResponse({"error": "Replaying packets needs sudo (raw socket)."}, status_code=403)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


class MitmStartRequest(BaseModel):
    iface: Optional[str] = None
    target: str
    gateway: Optional[str] = None
    bidirectional: bool = True


class ShapeRequest(BaseModel):
    rate_kbit: Optional[float] = None
    delay_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    loss_pct: Optional[float] = None


@app.get("/api/mitm/status")
async def mitm_status():
    return mitm_engine.status()


@app.post("/api/mitm/start")
async def mitm_start(req: MitmStartRequest):
    try:
        return await asyncio.to_thread(mitm_engine.start, req.iface, req.target,
                                       req.gateway, req.bidirectional)
    except PermissionError:
        return JSONResponse(
            {"error": "Interception needs sudo (raw sockets + IP forwarding)."},
            status_code=403)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


@app.post("/api/mitm/stop")
async def mitm_stop():
    return await asyncio.to_thread(mitm_engine.stop)


@app.post("/api/mitm/shape")
async def mitm_shape(req: ShapeRequest):
    try:
        return await asyncio.to_thread(mitm_engine.set_shaping, req.rate_kbit,
                                       req.delay_ms, req.jitter_ms, req.loss_pct)
    except RuntimeError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


@app.websocket("/ws")
async def ws(websocket: WebSocket):
    await websocket.accept()
    q: asyncio.Queue = asyncio.Queue(maxsize=5000)
    _subscribers.add(q)
    try:
        while True:
            row = await q.get()
            await websocket.send_json(row)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        _subscribers.discard(q)


# Static UI (mounted last so it doesn't shadow the API routes).
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")


if __name__ == "__main__":
    import uvicorn
    host = os.environ.get("NC_HOST", "127.0.0.1")
    port = int(os.environ.get("NC_PORT", "8787"))
    uvicorn.run(app, host=host, port=port, log_level="info")
