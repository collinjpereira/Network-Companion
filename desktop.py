"""
Network Companion desktop launcher (Windows).

Runs the existing FastAPI app (main:app) exactly as the browser version
does, but hosts it in a native window via pywebview instead of a browser
tab, so this can be packaged into a real Windows .exe. See
packaging/windows for the PyInstaller build script.

Packet capture, sending, and ARP interception all need raw-socket access,
so this self-elevates via a UAC prompt (ShellExecuteW ... "runas") if not
already running as administrator. A Windows process elevated this way still
runs in the same interactive session and can show windows on the user's
desktop normally.

The packaged .exe is a windowed (console-less) build, which means
sys.stdout/sys.stderr are None at startup -- any bare print() would crash
the whole process instantly with no visible error. Every diagnostic in this
file goes through _log()/_fatal() instead, which write to a log file next
to (or above, when frozen) this script and, for _fatal(), also show a
message box so a failure is actually visible instead of the window just
vanishing.

Run directly with:
    python desktop.py
"""

import ctypes
import os
import socket
import sys
import threading
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(
    os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"),
    "Network Companion", "desktop.log")


def _ensure_std_streams():
    """A windowed (console=False) build has sys.stdout/sys.stderr set to
    None -- there is no console to write to. That's not just a print()
    trap: uvicorn's own logging setup calls sys.stderr.isatty() while
    configuring itself, which raises AttributeError on None and takes the
    whole server down before it ever binds a port. Give both real
    file-like objects (backed by the log file) so anything that touches
    them -- our own prints, uvicorn's, click's -- behaves normally."""
    if sys.stdout is not None and sys.stderr is not None:
        return
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    stream = open(LOG_PATH, "a", buffering=1, encoding="utf-8")
    if sys.stdout is None:
        sys.stdout = stream
    if sys.stderr is None:
        sys.stderr = stream


_ensure_std_streams()


def _log(message: str):
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
    except OSError:
        pass


def _fatal(message: str):
    """Log an unrecoverable startup error and show it to the user -- a
    windowed build has no console, so this is the only way they'd ever see
    it -- then exit."""
    _log("FATAL: " + message)
    try:
        ctypes.windll.user32.MessageBoxW(
            None,
            f"{message}\n\nDetails were written to:\n{LOG_PATH}",
            "Network Companion", 0x10)  # MB_ICONERROR
    except Exception:
        pass
    sys.exit(1)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_until_up(host: str, port: int, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _run_server(host: str, port: int, holder: list, errors: list):
    """Run the existing FastAPI app (main.py's `app`) with uvicorn. Blocks.
    Runs on a background thread, whose exceptions are otherwise swallowed
    silently -- stash any into `errors` so the main thread can report them."""
    try:
        import uvicorn
        sys.path.insert(0, HERE)
        import main as backend
        config = uvicorn.Config(backend.app, host=host, port=port, log_level="warning")
        server = uvicorn.Server(config)
        holder.append(server)
        server.run()
    except Exception:
        errors.append(traceback.format_exc())


def _ensure_elevated_windows():
    """Self-elevate via a UAC prompt if not already running as administrator."""
    try:
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        is_admin = False
    if is_admin:
        return
    # sys.argv[0] is the script path when running unfrozen (python.exe needs
    # it to know what to run) but the .exe's own path when frozen (where
    # sys.executable already *is* that path) -- include it only in the
    # former case, or the relaunched process ends up with its own path
    # duplicated as an argument.
    args = sys.argv[1:] if getattr(sys, "frozen", False) else sys.argv
    params = " ".join(f'"{a}"' for a in args)
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, HERE, 1)
    # ShellExecuteW returns <= 32 on failure (e.g. the user cancelled UAC).
    if ret <= 32:
        _fatal("Administrator privileges are required for packet capture; "
               "the UAC prompt was cancelled or failed.")
    sys.exit(0)


class _Api:
    """Exposed to the page as window.pywebview.api. Lets the frontend (see
    app.js) hand external links off to the system's actual browser, since
    the embedded webview has no "new tab" to open them in."""

    def open_external(self, url: str):
        if not (url.startswith("http://") or url.startswith("https://")):
            return  # only ever open real web URLs, never a local file:// etc.
        import webbrowser
        webbrowser.open(url)


def main():
    _log("starting")

    if sys.platform != "win32":
        print("This desktop launcher only supports Windows. On Linux/macOS, "
              "run the web app instead: sudo ./run.sh, then open "
              "http://127.0.0.1:8787 in a browser.")
        sys.exit(1)

    _ensure_elevated_windows()

    host = "127.0.0.1"
    port = _free_port()
    server_holder: list = []
    server_errors: list = []
    threading.Thread(target=_run_server, args=(host, port, server_holder, server_errors),
                     daemon=True).start()

    if not _wait_until_up(host, port):
        if server_errors:
            _fatal("Network Companion's server failed to start:\n\n" + server_errors[0])
        else:
            _fatal(f"Network Companion's server never came up on {host}:{port}.")

    try:
        import webview
    except Exception:
        _fatal("Could not load the desktop window toolkit (pywebview):\n\n"
               + traceback.format_exc())

    def _on_closed():
        if server_holder:
            server_holder[0].should_exit = True

    try:
        window = webview.create_window(
            "Network Companion", url=f"http://{host}:{port}",
            width=1440, height=900, resizable=True, js_api=_Api(),
        )
        window.events.closed += _on_closed
        # NC_DEBUG=1 opens the inspector (right-click -> Inspect Element)
        # for troubleshooting; off by default since most people never need it.
        webview.start(debug=bool(os.environ.get("NC_DEBUG")))
    except Exception:
        if server_holder:
            server_holder[0].should_exit = True
        _fatal("Could not open the desktop window. This usually means the "
               "Microsoft Edge WebView2 Runtime isn't installed -- get it "
               "from https://developer.microsoft.com/microsoft-edge/webview2/ "
               "(most Windows 10/11 machines already have it).\n\n"
               + traceback.format_exc())

    _log("window closed, shutting down")
    if server_holder:
        server_holder[0].should_exit = True


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        _fatal("Network Companion hit an unexpected error on startup:\n\n"
               + traceback.format_exc())
