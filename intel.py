"""
IP intelligence lookups.

Two sources:
  * ip-api.com    - geolocation, ISP, organisation, ASN, and hosting/proxy
                    flags. Free, no key, ~45 requests/minute.
  * AbuseIPDB     - abuse confidence score and report history. Needs a free
                    API key (1000 checks/day on the free tier). Optional: if no
                    key is configured the location data is still returned.

Both calls need outbound internet access from this machine.
"""

import os
import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

import requests
from requests.adapters import HTTPAdapter

import selftraffic


class _SourcePortAdapter(HTTPAdapter):
    """Forces outbound connections through a specific local port, so
    capture.py's classify_self_traffic() can reliably recognise this
    traffic as ours via selftraffic.is_self_port() — the same mechanism
    crafter.py/scan.py/transfer.py already use. Matching purely on
    ip-api.com's/AbuseIPDB's IP (the alternative, in classify_self_traffic)
    is fragile: both are served from multiple/rotating IPs, so a request
    can easily land on an IP a few minutes' stale DNS cache doesn't have,
    and the traffic leaks into the analyst's real capture instead of NC
    Traffic."""

    def __init__(self, port, *args, **kwargs):
        self._port = port
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["source_address"] = ("", self._port)
        return super().init_poolmanager(*args, **kwargs)


def _self_traffic_session() -> requests.Session:
    port = selftraffic.reserve_local_port()
    session = requests.Session()
    adapter = _SourcePortAdapter(port)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


IPAPI_URL = "http://ip-api.com/json/{ip}"
IPAPI_FIELDS = ("status,message,continent,country,countryCode,region,regionName,"
                "city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,"
                "proxy,hosting,query")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# Numeric AbuseIPDB category ids -> readable labels (the common ones).
ABUSE_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
    4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
    7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam",
    11: "Email Spam", 12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
    15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
    18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}


def _validate_ip(ip: str) -> str:
    ip = (ip or "").strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError(f"'{ip}' is not a valid IP address.")
    return ip


def _is_private(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return addr.is_private or addr.is_loopback or addr.is_link_local


def geolocate(ip: str) -> dict:
    try:
        resp = _self_traffic_session().get(
            IPAPI_URL.format(ip=ip),
            params={"fields": IPAPI_FIELDS},
            timeout=8,
        )
        data = resp.json()
    except Exception as exc:
        return {"ok": False, "error": f"Geolocation lookup failed: {exc}"}

    if data.get("status") != "success":
        return {"ok": False, "error": data.get("message", "Lookup failed.")}

    return {
        "ok": True,
        "country": data.get("country"),
        "countryCode": data.get("countryCode"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "zip": data.get("zip"),
        "lat": data.get("lat"),
        "lon": data.get("lon"),
        "timezone": data.get("timezone"),
        "isp": data.get("isp"),
        "org": data.get("org"),
        "asn": data.get("as"),
        "asname": data.get("asname"),
        "reverse": data.get("reverse"),
        "mobile": data.get("mobile"),
        "proxy": data.get("proxy"),
        "hosting": data.get("hosting"),
    }


def check_abuse(ip: str, api_key: Optional[str]) -> dict:
    key = (api_key or "").strip() or os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    if not key:
        return {"ok": False, "configured": False,
                "error": "No AbuseIPDB API key set. Add one to enable abuse scoring."}
    try:
        resp = _self_traffic_session().get(
            ABUSEIPDB_URL,
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            timeout=8,
        )
    except Exception as exc:
        return {"ok": False, "configured": True, "error": f"AbuseIPDB request failed: {exc}"}

    if resp.status_code == 401:
        return {"ok": False, "configured": True, "error": "AbuseIPDB rejected the API key (401)."}
    if resp.status_code == 429:
        return {"ok": False, "configured": True, "error": "AbuseIPDB rate limit reached (429)."}
    if resp.status_code != 200:
        return {"ok": False, "configured": True, "error": f"AbuseIPDB returned HTTP {resp.status_code}."}

    data = resp.json().get("data", {})

    # Collect distinct category labels from the recent reports.
    cats = set()
    for report in data.get("reports", []) or []:
        for cid in report.get("categories", []) or []:
            cats.add(ABUSE_CATEGORIES.get(cid, f"Category {cid}"))

    return {
        "ok": True,
        "configured": True,
        "score": data.get("abuseConfidenceScore", 0),
        "totalReports": data.get("totalReports", 0),
        "distinctUsers": data.get("numDistinctUsers", 0),
        "lastReported": data.get("lastReportedAt"),
        "isWhitelisted": data.get("isWhitelisted"),
        "usageType": data.get("usageType"),
        "domain": data.get("domain"),
        "categories": sorted(cats),
    }


def lookup(ip: str, api_key: Optional[str] = None) -> dict:
    ip = _validate_ip(ip)
    result = {"ip": ip, "private": _is_private(ip)}
    if result["private"]:
        result["geo"] = {"ok": False, "error": "Private / local address, not routable on the internet."}
        result["abuse"] = {"ok": False, "configured": True,
                           "error": "Private addresses are not tracked by abuse feeds."}
        return result
    result["geo"] = geolocate(ip)
    result["abuse"] = check_abuse(ip, api_key)
    return result


# --- batch country lookup (for the flag column in the live table) ----------
# Cached so repeated IPs cost nothing, and batched via ip-api's bulk endpoint
# (up to 100 per request). Purely cosmetic: if offline, callers get "private"
# for local addresses and nothing for the rest, and the UI simply omits flags.

IPAPI_BATCH_URL = "http://ip-api.com/batch"
_country_cache: dict = {}


def batch_country(ips) -> dict:
    """Return {ip: countryCode|'PRIVATE'|None} for the given IPs, cached."""
    out = {}
    to_query = []
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            out[ip] = None
            continue
        if _is_private(ip):
            out[ip] = "PRIVATE"
            _country_cache[ip] = "PRIVATE"
        elif ip in _country_cache:
            out[ip] = _country_cache[ip]
        else:
            to_query.append(ip)

    # ip-api bulk allows 100 per call; chunk defensively.
    for i in range(0, len(to_query), 100):
        chunk = to_query[i:i + 100]
        payload = [{"query": ip, "fields": "countryCode,query,status"} for ip in chunk]
        try:
            resp = _self_traffic_session().post(IPAPI_BATCH_URL, json=payload, timeout=8)
            data = resp.json()
            for entry in data:
                ip = entry.get("query")
                cc = entry.get("countryCode") if entry.get("status") == "success" else None
                _country_cache[ip] = cc
                out[ip] = cc
        except Exception:
            for ip in chunk:
                out[ip] = None  # leave uncached so a later attempt can retry
    return out


# --- batch geolocation (for the "where in the world" dot map) --------------
# Same shape as batch_country, but keeps lat/lon/city so every public IP in a
# capture can be dropped onto the map in one shot instead of one lookup per IP.

_geo_point_cache: dict = {}


def batch_geo(ips) -> list:
    """Return [{ip, lat, lon, country, countryCode, city}, ...] for the public
    IPs among the given ones. Private/invalid addresses are skipped. Cached
    per IP, same as batch_country."""
    out = {}
    to_query = []
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        if _is_private(ip):
            continue
        cached = _geo_point_cache.get(ip)
        if cached:
            out[ip] = cached
        elif ip not in _geo_point_cache:
            to_query.append(ip)

    for i in range(0, len(to_query), 100):
        chunk = to_query[i:i + 100]
        payload = [{"query": ip, "fields": "status,query,lat,lon,country,countryCode,city"} for ip in chunk]
        try:
            resp = _self_traffic_session().post(IPAPI_BATCH_URL, json=payload, timeout=10)
            data = resp.json()
            for entry in data:
                ip = entry.get("query")
                if entry.get("status") == "success" and entry.get("lat") is not None:
                    point = {"ip": ip, "lat": entry["lat"], "lon": entry["lon"],
                             "country": entry.get("country"),
                             "countryCode": entry.get("countryCode"),
                             "city": entry.get("city")}
                    _geo_point_cache[ip] = point
                    out[ip] = point
                else:
                    _geo_point_cache[ip] = None
        except Exception:
            pass  # leave uncached so a later attempt can retry
    return list(out.values())


# --- reverse DNS name resolution (for the optional name-resolve toggle) -----
# Cached, bounded, and off by default in the UI. Reverse lookups generate their
# own DNS traffic from the analysis host and can be slow, which is exactly why
# an analyst wants to be able to turn them off.

_name_cache: dict = {}


def _reverse_one(ip: str):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def resolve_names(ips) -> dict:
    """Return {ip: hostname|None} for the given IPs, cached, with a time budget."""
    out = {}
    todo = []
    for ip in ips:
        if ip in _name_cache:
            out[ip] = _name_cache[ip]
        else:
            todo.append(ip)
    if todo:
        for ip in todo:
            selftraffic.mark_ptr(ip, ttl=8.0)
        with ThreadPoolExecutor(max_workers=16) as ex:
            futs = {ip: ex.submit(_reverse_one, ip) for ip in todo}
            deadline = time.time() + 4.0
            for ip, fut in futs.items():
                try:
                    host = fut.result(timeout=max(0.1, deadline - time.time()))
                except Exception:
                    host = None
                _name_cache[ip] = host
                out[ip] = host
    return out
