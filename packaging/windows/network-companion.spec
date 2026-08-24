# PyInstaller spec for the Windows build of Network Companion.
#
# Build from the repo root with:
#   pyinstaller packaging/windows/network-companion.spec
#
# Produces dist/Network Companion.exe as a single windowed executable (no
# console window) that requests administrator elevation on launch via a UAC
# manifest (uac_admin=True below) — packet capture needs it, so this avoids
# relying solely on desktop.py's own runtime ShellExecuteW re-launch.

import os

block_cipher = None
SCRIPT_DIR = os.path.dirname(os.path.abspath(SPEC))
ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))

a = Analysis(
    [os.path.join(ROOT, "desktop.py")],
    pathex=[ROOT],
    binaries=[],
    datas=[(os.path.join(ROOT, "static"), "static")],
    hiddenimports=[
        "uvicorn.logging",
        "uvicorn.loops",
        "uvicorn.loops.auto",
        "uvicorn.protocols",
        "uvicorn.protocols.http",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.websockets",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.lifespan",
        "uvicorn.lifespan.on",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="Network Companion",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    uac_admin=True,
    icon=os.path.join(SCRIPT_DIR, "icon.ico"),
)
