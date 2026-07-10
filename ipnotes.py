"""
Saved IP notes.

A small persistent address book so an analyst can mark an IP with a color,
free-form tags, and a description that survives across sessions and PCAP
loads. Stored as a flat JSON file next to this module; every write is
atomic (write to a temp file, then os.replace) so a crash mid-write can't
corrupt it.
"""

import json
import os
import threading
import time
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__))
STORE_PATH = os.path.join(HERE, "ip_notes.json")

_lock = threading.Lock()


def _load() -> dict:
    if not os.path.exists(STORE_PATH):
        return {}
    try:
        with open(STORE_PATH, "r") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


_notes: dict = _load()


def _save():
    tmp = STORE_PATH + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(_notes, fh, indent=2, sort_keys=True)
    os.replace(tmp, STORE_PATH)


def all_notes() -> dict:
    with _lock:
        return {ip: dict(entry) for ip, entry in _notes.items()}


def get(ip: str) -> Optional[dict]:
    with _lock:
        entry = _notes.get(ip)
        return dict(entry) if entry is not None else None


def upsert(ip: str, color: Optional[str] = None, tags: Optional[list] = None,
           description: Optional[str] = None) -> dict:
    with _lock:
        entry = dict(_notes.get(ip, {}))
        if color is not None:
            if color == "":
                entry.pop("color", None)
            else:
                entry["color"] = color
        if tags is not None:
            entry["tags"] = [t.strip() for t in tags if t and t.strip()]
        if description is not None:
            entry["description"] = description
        entry["updated"] = time.time()
        _notes[ip] = entry
        _save()
        return dict(entry)


def delete(ip: str):
    with _lock:
        _notes.pop(ip, None)
        _save()
