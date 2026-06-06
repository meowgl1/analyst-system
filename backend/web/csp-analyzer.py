#!/usr/bin/env python3
# csp-analyzer.py
# What: Parses and grades the Content-Security-Policy header of a web page.
# When to use: Fourth step in web audit. CSP is the primary XSS mitigation — weak CSP = high XSS risk.
# Expected output: JSON to backend/outputs/YYYY-MM-DD-csp-analyzer-<host>.json
#
# Usage: python3 csp-analyzer.py <hostname>
#   e.g. python3 csp-analyzer.py mowgli.studio

import sys
import json
import urllib.request
import urllib.error
import datetime
import os
import re

DANGEROUS_DIRECTIVES = {
    "unsafe-inline": {
        "severity": "HIGH",
        "description": "Allows inline scripts/styles — primary XSS bypass vector",
        "guidance": "Use nonces or hashes instead of 'unsafe-inline'",
    },
    "unsafe-eval": {
        "severity": "HIGH",
        "description": "Allows eval() and similar — enables code injection",
        "guidance": "Refactor code to avoid eval(). Use JSON.parse() instead.",
    },
    "unsafe-hashes": {
        "severity": "MEDIUM",
        "description": "Allows inline event handlers — limited XSS risk",
        "guidance": "Move event handlers to external scripts",
    },
}

REQUIRED_DIRECTIVES = {
    "default-src": "Fallback for all resource types — critical",
    "script-src": "Controls script loading — most important for XSS",
    "object-src": "Controls plugins (Flash, etc.) — set to 'none'",
    "frame-ancestors": "Controls who can embed this page (replaces X-Frame-Options)",
    "upgrade-insecure-requests": "Upgrades HTTP sub-resources to HTTPS",
}


def fetch_csp_header(host: str) -> tuple[str, str, int]:
    """Returns (csp_value, csp_ro_value, http_status)."""
    url = f"https://{host}"
    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "SecurityAudit/1.0 (internal-use)")
        with urllib.request.urlopen(req, timeout=10) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return (
                headers.get("content-security-policy", ""),
                headers.get("content-security-policy-report-only", ""),
                resp.status,
            )
    except urllib.error.HTTPError as e:
        headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        return (
            headers.get("content-security-policy", ""),
            headers.get("content-security-policy-report-only", ""),
            e.code,
        )
    except Exception:
        return "", "", -1


def parse_csp(csp_string: str) -> dict:
    """Parse a CSP string into a dict of directive → list of values."""
    directives = {}
    if not csp_string:
        return directives
    for directive in csp_string.split(";"):
        directive = directive.strip()
        if not directive:
            continue
        parts = directive.split()
        if parts:
            directive_name = parts[0].lower()
            values = parts[1:] if len(parts) > 1 else []
            directives[directive_name] = values
    return directives


def grade_csp(directives: dict) -> tuple[str, list]:
    """Returns (grade: A/B/C/D/F, findings: list)."""
    findings = []
    score = 100

    if not directives:
        return "F", [{
            "type": "NO_CSP",
            "severity": "HIGH",
            "description": "No Content-Security-Policy header present",
            "guidance": "Implement a CSP. Start with: default-src 'self'",
        }]

    # Check for dangerous values in all directives
    for directive_name, values in directives.items():
        for dangerous, info in DANGEROUS_DIRECTIVES.items():
            if f"'{dangerous}'" in values or dangerous in values:
                findings.append({
                    "type": f"DANGEROUS_KEYWORD_{dangerous.upper().replace('-', '_')}",
                    "severity": info["severity"],
                    "directive": directive_name,
                    "description": f"'{dangerous}' in {directive_name}: {info['description']}",
                    "guidance": info["guidance"],
                })
                score -= 20 if info["severity"] == "HIGH" else 10

    # Check for wildcard * in script-src or default-src
    for critical_dir in ("script-src", "default-src"):
        if critical_dir in directives:
            if "*" in directives[critical_dir]:
                findings.append({
                    "type": "WILDCARD_IN_SCRIPT_SRC",
                    "severity": "HIGH",
                    "directive": critical_dir,
                    "description": f"Wildcard '*' in {critical_dir} allows loading scripts from anywhere",
                    "guidance": f"Replace '*' with explicit trusted domains in {critical_dir}",
                })
                score -= 25

    # Check for missing recommended directives
    for rec_dir, rec_desc in REQUIRED_DIRECTIVES.items():
        if rec_dir not in directives:
            # default-src absence is most critical
            severity = "HIGH" if rec_dir in ("default-src", "script-src") else "MEDIUM"
            findings.append({
                "type": f"MISSING_{rec_dir.upper().replace('-', '_')}",
                "severity": severity,
                "directive": rec_dir,
                "description": f"Missing '{rec_dir}' directive: {rec_desc}",
                "guidance": f"Add '{rec_dir}' directive to CSP",
            })
            score -= 10 if severity == "HIGH" else 5

    # Check object-src is 'none'
    if "object-src" in directives and "'none'" not in directives["object-src"]:
        findings.append({
            "type": "OBJECT_SRC_NOT_NONE",
            "severity": "MEDIUM",
            "directive": "object-src",
            "description": "object-src should be 'none' to block plugins",
            "guidance": "Set object-src 'none'",
        })
        score -= 5

    # Grade
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    return grade, findings


def analyze_csp(host: str) -> dict:
    csp_value, csp_ro_value, status = fetch_csp_header(host)

    directives = parse_csp(csp_value)
    grade, findings = grade_csp(directives)

    result = {
        "target": host,
        "url": f"https://{host}",
        "http_status": status,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "csp_present": bool(csp_value),
        "csp_report_only": bool(csp_ro_value),
        "raw_csp": csp_value,
        "raw_csp_report_only": csp_ro_value,
        "grade": grade,
        "parsed_directives": directives,
        "findings": findings,
    }

    if csp_ro_value and not csp_value:
        result["findings"].insert(0, {
            "type": "CSP_REPORT_ONLY_NOT_ENFORCED",
            "severity": "HIGH",
            "description": "CSP is in Report-Only mode — it logs violations but doesn't block anything",
            "guidance": "Change Content-Security-Policy-Report-Only to Content-Security-Policy",
        })

    return result


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 csp-analyzer.py <hostname>")
        sys.exit(1)

    host = sys.argv[1].strip().lstrip("https://").lstrip("http://").rstrip("/")
    result = analyze_csp(host)

    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    output_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{date_str}-csp-analyzer-{host}.json")

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n=== CSP Analyzer: {host} ===")
    print(f"CSP present: {'✅' if result['csp_present'] else '🔴 NO'}")
    print(f"Grade: {result['grade']}")
    for f in result["findings"]:
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(f["severity"], "⚪")
        print(f"  {icon} [{f['severity']}] {f['type']}: {f.get('directive', '')}")
    if not result["findings"]:
        print("  ✅ CSP looks solid — no major issues")
    print(f"\nFull output: {output_file}")


if __name__ == "__main__":
    main()
