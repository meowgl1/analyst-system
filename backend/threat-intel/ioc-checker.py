#!/usr/bin/env python3
# ioc-checker.py
# What: Checks an IP, domain, or SHA256 hash against public threat intelligence feeds.
#       Uses AbuseIPDB, AlienVault OTX, and URLhaus (all have free public APIs).
#       If VIRUSTOTAL_API_KEY env var is set, also queries VirusTotal.
# When to use: When investigating a suspicious IP/domain found in forensics or network audit.
# Expected output: JSON to backend/outputs/YYYY-MM-DD-ioc-checker-<ioc>.json
#
# Usage:
#   python3 ioc-checker.py 1.2.3.4
#   python3 ioc-checker.py malicious.example.com
#   python3 ioc-checker.py a3f5c8e9d0b1...  (SHA256)

import sys
import json
import urllib.request
import urllib.error
import datetime
import os
import re
import socket

# Optional env var — no key = skip VirusTotal
VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")

TIMEOUT = 10
UA = "SecurityAudit/1.0 (internal-use)"


def detect_ioc_type(ioc: str) -> str:
    """Detect whether input is IP, domain, or hash."""
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ioc):
        return "ip"
    if re.match(r"^[a-fA-F0-9]{64}$", ioc):
        return "hash_sha256"
    if re.match(r"^[a-fA-F0-9]{40}$", ioc):
        return "hash_sha1"
    if re.match(r"^[a-fA-F0-9]{32}$", ioc):
        return "hash_md5"
    return "domain"


def fetch_json(url: str, headers: dict = None) -> dict | None:
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", UA)
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {"_http_error": e.code}
    except Exception as e:
        return {"_error": str(e)}


def check_abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_API_KEY:
        return {"skipped": "no ABUSEIPDB_API_KEY env var"}
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    data = fetch_json(url, {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"})
    if not data or "_error" in data:
        return {"error": str(data)}
    d = data.get("data", {})
    return {
        "source": "AbuseIPDB",
        "abuse_confidence": d.get("abuseConfidenceScore", 0),
        "total_reports": d.get("totalReports", 0),
        "last_reported": d.get("lastReportedAt"),
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "malicious": d.get("abuseConfidenceScore", 0) >= 25,
    }


def check_otx(ioc: str, ioc_type: str) -> dict:
    """AlienVault OTX — no API key required for basic lookups."""
    if ioc_type == "ip":
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general"
    elif ioc_type == "domain":
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{ioc}/general"
    elif "hash" in ioc_type:
        hash_type = "SHA256" if "sha256" in ioc_type else "MD5"
        url = f"https://otx.alienvault.com/api/v1/indicators/file/{ioc}/general"
    else:
        return {"skipped": "unsupported type for OTX"}

    data = fetch_json(url)
    if not data or "_error" in data:
        return {"error": str(data)}

    pulses = data.get("pulse_info", {}).get("count", 0)
    return {
        "source": "AlienVault OTX",
        "pulse_count": pulses,
        "malicious": pulses > 0,
        "country": data.get("country_name"),
        "asn": data.get("asn"),
    }


def check_urlhaus(ioc: str, ioc_type: str) -> dict:
    """URLhaus by abuse.ch — checks URLs/domains/hashes."""
    if ioc_type == "domain":
        url = "https://urlhaus-api.abuse.ch/v1/host/"
        payload = f"host={ioc}".encode()
    elif "hash" in ioc_type:
        url = "https://urlhaus-api.abuse.ch/v1/payload/"
        payload = f"sha256_hash={ioc}".encode() if "sha256" in ioc_type else f"md5_hash={ioc}".encode()
    elif ioc_type == "ip":
        url = "https://urlhaus-api.abuse.ch/v1/host/"
        payload = f"host={ioc}".encode()
    else:
        return {"skipped": "unsupported type"}

    try:
        req = urllib.request.Request(url, data=payload, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("User-Agent", UA)
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
        query_status = data.get("query_status", "")
        return {
            "source": "URLhaus",
            "status": query_status,
            "malicious": query_status in ("is_host", "found"),
            "url_count": data.get("urls_count", 0),
        }
    except Exception as e:
        return {"error": str(e)}


def check_virustotal(ioc: str, ioc_type: str) -> dict:
    if not VT_API_KEY:
        return {"skipped": "no VIRUSTOTAL_API_KEY env var"}

    if ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    elif "hash" in ioc_type:
        url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    else:
        return {"skipped": "unsupported type"}

    data = fetch_json(url, {"x-apikey": VT_API_KEY})
    if not data or "_error" in data:
        return {"error": str(data)}

    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) if stats else 0

    return {
        "source": "VirusTotal",
        "malicious_engines": malicious,
        "suspicious_engines": suspicious,
        "total_engines": total,
        "malicious": malicious > 2,
        "verdict": f"{malicious}/{total} engines flagged" if total else "unknown",
    }


def analyze(ioc: str) -> dict:
    ioc_type = detect_ioc_type(ioc)
    print(f"\n=== IoC Checker: {ioc} ({ioc_type}) ===\n")

    results = {}

    if ioc_type == "ip":
        results["abuseipdb"] = check_abuseipdb(ioc)
        results["otx"] = check_otx(ioc, ioc_type)
        results["urlhaus"] = check_urlhaus(ioc, ioc_type)
        results["virustotal"] = check_virustotal(ioc, ioc_type)
    elif ioc_type == "domain":
        results["otx"] = check_otx(ioc, ioc_type)
        results["urlhaus"] = check_urlhaus(ioc, ioc_type)
        results["virustotal"] = check_virustotal(ioc, ioc_type)
    elif "hash" in ioc_type:
        results["urlhaus"] = check_urlhaus(ioc, ioc_type)
        results["virustotal"] = check_virustotal(ioc, ioc_type)
        results["otx"] = check_otx(ioc, ioc_type)

    # Determine overall verdict
    malicious_sources = [src for src, r in results.items() if r.get("malicious")]
    if len(malicious_sources) >= 2:
        verdict = "MALICIOUS"
        severity = "CRITICAL"
    elif len(malicious_sources) == 1:
        verdict = "SUSPICIOUS"
        severity = "HIGH"
    else:
        verdict = "CLEAN"
        severity = "LOW"

    print(f"  Verdict: {verdict}")
    for src, r in results.items():
        if "skipped" in r:
            print(f"  ⚪ {src}: skipped ({r['skipped']})")
        elif r.get("malicious"):
            print(f"  🔴 {src}: MALICIOUS")
        elif "error" in r:
            print(f"  ⚠️  {src}: error — {r['error']}")
        else:
            print(f"  ✅ {src}: clean")

    return {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "verdict": verdict,
        "severity": severity,
        "malicious_sources": malicious_sources,
        "results": results,
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ioc-checker.py <ip|domain|hash>")
        print("  Optional env vars: VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY")
        sys.exit(1)

    ioc = sys.argv[1].strip()
    result = analyze(ioc)

    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    safe_ioc = ioc.replace("/", "_").replace(":", "_")
    output_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{date_str}-ioc-checker-{safe_ioc}.json")

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n  Full output: {output_file}")


if __name__ == "__main__":
    main()
