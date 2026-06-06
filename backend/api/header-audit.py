#!/usr/bin/env python3
# header-audit.py
# What: Checks HTTP security headers on a target host (API or web).
# When to use: First step in any API security audit. Run before endpoint-discovery.
# Expected output: JSON to backend/outputs/YYYY-MM-DD-header-audit-<host>.json
#
# Usage: python3 header-audit.py <hostname>
#   e.g. python3 header-audit.py bagheera.mowgli.studio

import sys
import json
import subprocess
import datetime
import os
import re

SECURITY_HEADERS = {
    "strict-transport-security": {
        "description": "HSTS — forces HTTPS",
        "severity_if_missing": "HIGH",
        "check": lambda v: "max-age=" in v.lower(),
        "check_detail": "must include max-age directive",
    },
    "content-security-policy": {
        "description": "CSP — mitigates XSS",
        "severity_if_missing": "MEDIUM",
        "check": lambda v: len(v) > 5,
        "check_detail": "must be non-empty",
    },
    "x-frame-options": {
        "description": "Clickjacking protection",
        "severity_if_missing": "MEDIUM",
        "check": lambda v: v.upper() in ("DENY", "SAMEORIGIN"),
        "check_detail": "must be DENY or SAMEORIGIN",
    },
    "x-content-type-options": {
        "description": "MIME-type sniffing prevention",
        "severity_if_missing": "LOW",
        "check": lambda v: v.lower() == "nosniff",
        "check_detail": "must be nosniff",
    },
    "referrer-policy": {
        "description": "Controls referrer information",
        "severity_if_missing": "LOW",
        "check": lambda v: len(v) > 0,
        "check_detail": "must be set",
    },
    "permissions-policy": {
        "description": "Controls browser features access",
        "severity_if_missing": "LOW",
        "check": lambda v: len(v) > 0,
        "check_detail": "must be set",
    },
    "access-control-allow-origin": {
        "description": "CORS policy",
        "severity_if_wildcard": "HIGH",
        "check": lambda v: v != "*",
        "check_detail": "must not be wildcard *",
    },
    "access-control-allow-credentials": {
        "description": "CORS credentials flag",
        "severity_if_issue": "CRITICAL",
        "check": lambda v: True,
        "check_detail": "CRITICAL if true + ACAO is wildcard",
    },
}

DISCLOSURE_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]


def run_curl(url: str) -> tuple[int, dict]:
    """Run curl -sI and return (status_code, headers_dict)."""
    result = subprocess.run(
        ["curl", "-sI", "--max-time", "10", "--location", url],
        capture_output=True,
        text=True,
    )
    lines = result.stdout.strip().split("\n")
    headers = {}
    status_code = 0

    for line in lines:
        line = line.strip()
        if line.startswith("HTTP/"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    status_code = int(parts[1])
                except ValueError:
                    pass
        elif ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()

    return status_code, headers


def audit_headers(host: str) -> dict:
    url = f"https://{host}"
    status_code, headers = run_curl(url)

    findings = []
    present = []

    # Check security headers
    for header_name, config in SECURITY_HEADERS.items():
        value = headers.get(header_name, "")
        if not value:
            severity = config.get("severity_if_missing", "LOW")
            findings.append({
                "header": header_name,
                "status": "MISSING",
                "severity": severity,
                "description": config["description"],
                "detail": f"Header not present",
            })
        else:
            # Check value quality
            check_fn = config.get("check")
            if check_fn and not check_fn(value):
                severity = config.get("severity_if_wildcard") or config.get("severity_if_issue", "MEDIUM")
                findings.append({
                    "header": header_name,
                    "status": "MISCONFIGURED",
                    "severity": severity,
                    "value": value,
                    "description": config["description"],
                    "detail": config.get("check_detail", ""),
                })
            else:
                present.append({"header": header_name, "value": value})

    # Check CORS credentials + wildcard combination
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")
    if acao == "*" and acac.lower() == "true":
        findings.append({
            "header": "access-control-allow-credentials + access-control-allow-origin",
            "status": "CRITICAL_COMBINATION",
            "severity": "CRITICAL",
            "value": f"ACAO: {acao}, ACAC: {acac}",
            "description": "Wildcard CORS + credentials = any site can make authenticated requests",
            "detail": "Browsers block this by spec, but some non-browser clients may exploit it",
        })

    # Information disclosure
    disclosure = []
    for dh in DISCLOSURE_HEADERS:
        if dh in headers:
            disclosure.append({"header": dh, "value": headers[dh]})
            findings.append({
                "header": dh,
                "status": "DISCLOSURE",
                "severity": "LOW",
                "value": headers[dh],
                "description": f"Server technology disclosure via {dh}",
                "detail": "Reveals stack details that help attackers fingerprint the server",
            })

    return {
        "target": host,
        "url": url,
        "http_status": status_code,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "findings": findings,
        "present_headers": present,
        "all_response_headers": headers,
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 header-audit.py <hostname>")
        sys.exit(1)

    host = sys.argv[1].strip().lstrip("https://").lstrip("http://").rstrip("/")
    result = audit_headers(host)

    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    output_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{date_str}-header-audit-{host}.json")

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    # Summary to stdout
    findings = result["findings"]
    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    high = [f for f in findings if f["severity"] == "HIGH"]
    medium = [f for f in findings if f["severity"] == "MEDIUM"]
    low = [f for f in findings if f["severity"] == "LOW"]

    print(f"\n=== Header Audit: {host} ===")
    print(f"HTTP Status: {result['http_status']}")
    print(f"Critical: {len(critical)} | High: {len(high)} | Medium: {len(medium)} | Low: {len(low)}")
    for f in findings:
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(f["severity"], "⚪")
        print(f"  {icon} [{f['severity']}] {f['header']}: {f['status']}")
    print(f"\nFull output: {output_file}")


if __name__ == "__main__":
    main()
