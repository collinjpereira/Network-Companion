#!/usr/bin/env bash
# Network Companion launcher. Capture and packet sending need raw-socket
# access, so this must run as root. The web UI stays bound to localhost only.
set -e

HOST="${NC_HOST:-127.0.0.1}"
PORT="${NC_PORT:-8787}"

cd "$(dirname "$0")"

if [ "$(id -u)" -ne 0 ]; then
  echo "Network Companion needs root for packet capture. Re-run with:  sudo ./run.sh"
  exit 1
fi

# Prefer the project's virtualenv Python so packages installed there are found
# when running as root. Fall back to system python3 otherwise.
if [ -x ".venv/bin/python" ]; then
  PY=".venv/bin/python"
else
  PY="python3"
fi

exec "$PY" -m uvicorn main:app --host "$HOST" --port "$PORT"
