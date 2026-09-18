"""
Threat intelligence enrichment.

Every lookup here passes an indicator as a STRING to a vendor API.
Nothing in this module ever requests the suspicious URL itself.

Auth headers differ per vendor and getting one wrong returns a 401 that
looks like a bad key:
    VirusTotal -> x-apikey
    AbuseIPDB  -> Key
    urlscan.io -> API-Key
"""

import concurrent.futures
import os

import requests

from email_parser import SHORTENERS

VT_KEY = os.getenv("VT_API_KEY", "")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
URLSCAN_KEY = os.getenv("URLSCAN_API_KEY", "")

TIMEOUT = 15

# VirusTotal free tier allows 4 requests/minute. Stay under it.
MAX_DOMAIN_LOOKUPS = 4
MAX_IP_LOOKUPS = 3

_cache = {}


def _blank(source, indicator):
    return {"source": source, "indicator": indicator, "status": "unavailable", "detail": ""}


def _get_with_retry(url, **kwargs):
    """One retry on a timeout only -- other failures (DNS, connection reset,
    4xx/5xx) are surfaced immediately rather than doubling the wait."""
    try:
        return requests.get(url, **kwargs)
    except requests.exceptions.Timeout:
        return requests.get(url, **kwargs)


def vt_domain(domain: str) -> dict:
    ck = f"vt:{domain}"
    if ck in _cache:
        return _cache[ck]
    out = _blank("VirusTotal", domain)
    if not VT_KEY:
        out["detail"] = "no API key configured"
        return out
    try:
        r = _get_with_retry(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VT_KEY},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"].get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            sus = stats.get("suspicious", 0)
            # A couple of stray vendor hits (e.g. 2/0) on an otherwise
            # widely-trusted domain is normal noise, not a real signal --
            # only treat it as a detection once it clears a real bar.
            is_detection = mal >= 4 or (mal >= 2 and sus >= 2)
            if is_detection:
                detail = f"{mal} malicious / {sus} suspicious vendor detections"
            elif mal or sus:
                detail = (
                    f"{mal} malicious / {sus} suspicious — low-confidence "
                    "detections (likely vendor noise)"
                )
            else:
                detail = f"{mal} malicious / {sus} suspicious vendor detections"
            out.update(
                status="ok",
                malicious=mal,
                suspicious=sus,
                detection=is_detection,
                detail=detail,
            )
        elif r.status_code == 404:
            out.update(status="not_found", detail="domain not present in VirusTotal dataset")
        elif r.status_code == 429:
            out.update(status="rate_limited", detail="VirusTotal rate limit hit (4/min free tier)")
        else:
            out["detail"] = f"HTTP {r.status_code}"
    except requests.RequestException as exc:
        out["detail"] = f"request failed: {exc.__class__.__name__}"
    _cache[ck] = out
    return out


def abuseipdb(ip: str) -> dict:
    ck = f"abuse:{ip}"
    if ck in _cache:
        return _cache[ck]
    out = _blank("AbuseIPDB", ip)
    if not ABUSE_KEY:
        out["detail"] = "no API key configured"
        return out
    try:
        r = _get_with_retry(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 365},
            headers={"Key": ABUSE_KEY, "Accept": "application/json"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            d = r.json()["data"]
            score = d.get("abuseConfidenceScore", 0)
            out.update(
                status="ok",
                score=score,
                detail=(
                    f"abuse confidence {score}/100, {d.get('totalReports', 0)} reports, "
                    f"country {d.get('countryCode') or 'unknown'}, ISP {d.get('isp') or 'unknown'}"
                ),
            )
        elif r.status_code == 429:
            out.update(status="rate_limited", detail="AbuseIPDB daily quota reached")
        else:
            out["detail"] = f"HTTP {r.status_code}"
    except requests.RequestException as exc:
        out["detail"] = f"request failed: {exc.__class__.__name__}"
    _cache[ck] = out
    return out


def urlscan_domain(domain: str) -> dict:
    """
    Search urlscan's existing corpus. Deliberately uses /search/ rather than
    /scan/ so we never cause urlscan infrastructure to visit attacker pages,
    which would tip them off and can burn the sample.
    """
    ck = f"urlscan:{domain}"
    if ck in _cache:
        return _cache[ck]
    out = _blank("urlscan.io", domain)
    if not URLSCAN_KEY:
        out["detail"] = "no API key configured"
        return out
    try:
        r = _get_with_retry(
            "https://urlscan.io/api/v1/search/",
            params={"q": f'page.domain:"{domain}"', "size": 5},
            headers={"API-Key": URLSCAN_KEY},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            results = r.json().get("results", [])
            if results:
                newest = results[0]
                out.update(
                    status="ok",
                    scan_count=len(results),
                    detail=(
                        f"{len(results)} prior scan(s); most recent "
                        f"{newest.get('task', {}).get('time', 'unknown')}"
                    ),
                )
            else:
                out.update(status="not_found", detail="no prior scans recorded")
        elif r.status_code == 429:
            out.update(status="rate_limited", detail="urlscan quota reached")
        else:
            out["detail"] = f"HTTP {r.status_code}"
    except requests.RequestException as exc:
        out["detail"] = f"request failed: {exc.__class__.__name__}"
    _cache[ck] = out
    return out


def enrich(parsed: dict) -> list:
    """Run capped lookups across the indicators the parser extracted, concurrently."""
    lookup_domains = [d for d in parsed.get("domains", []) if d not in SHORTENERS]
    tasks = []
    for domain in lookup_domains[:MAX_DOMAIN_LOOKUPS]:
        tasks.append((vt_domain, domain))
        tasks.append((urlscan_domain, domain))
    for ip in parsed.get("ips", [])[:MAX_IP_LOOKUPS]:
        tasks.append((abuseipdb, ip))

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(fn, arg) for fn, arg in tasks]
        return [future.result() for future in futures]
