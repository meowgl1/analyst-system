#!/usr/bin/env python3
# security-headers.py
# What: Checks HTTP security headers on a web page. Tuned for frontend sites (vs API).
# When to use: First step in web security audit. Run before form-scanner.
# Expected output: JSON to backend/outputs/YYYY-MM-DD-security-headers-<host>.json
#
# Usage: python3 security-headers.py <hostname>
#   e.g. python3 security-headers.py mowgli.studio

import sys
import json
import urllib.request
import urllib.error
import datetime
import os

REQUIRED_HEADERS = {
    "strict-transport-security": {
        "description": "HSTS — forces HTTPS for all connections",
        "severity": "HIGH",
        "guidance": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "check": lambda v: "max-age=" in v.lower() and int(v.lower().split("max-age=")[1].split(";")[0].strip()) >= 31536000,
        "check_detail": "max-age must be >= 31536000 (1 year)",
    },
    "content-security-policy": {
        "description": "CSP — primary XSS mitigation",
        "severity": "HIGH",
        "guidance": "Define a CSP policy. At minimum: default-src 'self'",
        "check": lambda v: "default-src" in v.lower() or "script-src" in v.lower(),
        "check_detail": "must define default-src or script-src",
    },
    "x-frame-options": {
        "description": "Prevents clickjacking",
        "severity": "MEDIUM",
        "guidance": "Add: X-Frame-Options: SAMEORIGIN",
        "check": lambda v: v.upper() in ("DENY", "SAMEORIGIN"),
        "check_detail": "must be DENY or SAMEORIGIN",
    },
    "x-content-type-options": {
        "description": "Prevents MIME-type sniffing",
        "severity": "MEDIUM",
        "guidance": "Add: X-Content-Type-Options: nosniff",
        "check": lambda v: v.lower() == "nosniff",
        "check_detail": "must be nosniff",
    },
    "referrer-policy": {
        "description": "Controls what referrer info is sent",
        "severity": "LOW",
        "guidance": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "check": lambda v: len(v) > 0,
        "check_detail": "any value is acceptable",
    },
    "permissions-policy": {
        "description": "Controls browser feature access (camera, mic, etc.)",
        "severity": "LOW",
        "guidance": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
        "check": lambda v: len(v) > 0,
        "check_detail": "any value is acceptable",
    },
}

DISCLOSURE_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-generator"]


def fetch_headers(host: str) -> tuple[int, dict]:
    url = f"https://{host}"
    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "SecurityAudit/1.0 (internal-use)")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers) if hasattr(e, 'headers') else {}
    except Exception as e:
        return -1, {}


def audit_web_headers(host: str) -> dict:
    status, headers = fetch_headers(host)
    headers_lower = {k.lower(): v for k, v in headers.items()}

    findings = []
    clean = []

    for header_name, config in REQUIRED_HEADERS.items():
        value = headers_lower.get(header_name, "")
        if not value:
            findings.append({
                "header": header_name,
                "status": "MISSING",
                "severity": config["severity"],
                "description": config["description"],
                "guidance": config["guidance"],
            })
        else:
            try:
                ok = config["check"](value)
            except Exception:
                ok = False

            if not ok:
                findings.append({
                    "header": header_name,
                    "status": "WEAK",
                    "severity": config["severity"],
                    "value": value,
                    "description": config["description"],
                    "guidance": config.get("check_detail", ""),
                })
            else:
                clean.append({"header": header_name, "value": value})

    # Info disclosure
    for dh in DISCLOSURE_HEADERS:
        if dh in headers_lower:
            findings.append({
                "header": dh,
                "status": "DISCLOSURE",
                "severity": "LOW",
                "value": headers_lower[dh],
                "description": f"Technology disclosure via {dh}",
                "guidance": f"Remove or obscure the {dh} header",
            })

    return {
        "target": host,
        "url": f"https://{host}",
        "http_status": status,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "findings": findings,
        "clean_headers": clean,
        "all_headers": headers_lower,
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 security-headers.py <hostname>")
        sys.exit(1)

    host = sys.argv[1].strip().lstrip("https://").lstrip("http://").rstrip("/")
    result = audit_web_headers(host)

    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    output_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{date_str}-security-headers-{host}.json")

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    findings = result["findings"]
    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    high = [f for f in findings if f["severity"] == "HIGH"]
    medium = [f for f in findings if f["severity"] == "MEDIUM"]
    low = [f for f in findings if f["severity"] == "LOW"]

    print(f"\n=== Security Headers: {host} ===")
    print(f"HTTP Status: {result['http_status']}")
    print(f"Critical: {len(critical)} | High: {len(high)} | Medium: {len(medium)} | Low: {len(low)}")
    for f in findings:
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(f["severity"], "⚪")
        val = f" = {f['value']}" if "value" in f else ""
        print(f"  {icon} [{f['severity']}] {f['header']}: {f['status']}{val}")
    print(f"\nFull output: {output_file}")


if __name__ == "__main__":
    main()
