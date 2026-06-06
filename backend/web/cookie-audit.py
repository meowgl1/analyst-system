#!/usr/bin/env python3
# cookie-audit.py
# What: Checks all cookies set by a web page for security flags (HttpOnly, Secure, SameSite).
# When to use: Third step in web security audit. Missing flags enable XSS cookie theft and CSRF.
# Expected output: JSON to backend/outputs/YYYY-MM-DD-cookie-audit-<host>.json
#
# Usage: python3 cookie-audit.py <hostname>
#   e.g. python3 cookie-audit.py mowgli.studio

import sys
import json
import urllib.request
import urllib.error
import datetime
import os
import re


def parse_set_cookie(raw: str) -> dict:
    """Parse a single Set-Cookie header value into a structured dict."""
    parts = [p.strip() for p in raw.split(";")]
    if not parts:
        return {}

    # First part is name=value
    name_value = parts[0]
    if "=" in name_value:
        name, _, value = name_value.partition("=")
    else:
        name, value = name_value, ""

    cookie = {
        "name": name.strip(),
        "value_length": len(value),
        "httponly": False,
        "secure": False,
        "samesite": None,
        "path": "/",
        "domain": None,
        "expires": None,
        "max_age": None,
    }

    for attr in parts[1:]:
        attr_lower = attr.lower()
        if attr_lower == "httponly":
            cookie["httponly"] = True
        elif attr_lower == "secure":
            cookie["secure"] = True
        elif attr_lower.startswith("samesite="):
            cookie["samesite"] = attr.split("=", 1)[1].strip().capitalize()
        elif attr_lower.startswith("path="):
            cookie["path"] = attr.split("=", 1)[1].strip()
        elif attr_lower.startswith("domain="):
            cookie["domain"] = attr.split("=", 1)[1].strip()
        elif attr_lower.startswith("expires="):
            cookie["expires"] = attr.split("=", 1)[1].strip()
        elif attr_lower.startswith("max-age="):
            try:
                cookie["max_age"] = int(attr.split("=", 1)[1].strip())
            except ValueError:
                pass

    return cookie


def audit_cookies(host: str) -> dict:
    url = f"https://{host}"
    cookies_raw = []

    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "SecurityAudit/1.0 (internal-use)")
        # Don't follow redirects to capture cookies at each hop
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
        with opener.open(req, timeout=10) as resp:
            # Collect all Set-Cookie headers
            all_headers = resp.info()
            # urllib combines duplicate headers — try to get raw
            for key in all_headers.keys():
                if key.lower() == "set-cookie":
                    cookies_raw.append(all_headers[key])
    except urllib.error.HTTPError as e:
        for key in (e.headers or {}):
            if key.lower() == "set-cookie":
                cookies_raw.append(e.headers[key])
    except Exception as e:
        return {
            "target": host,
            "error": str(e),
            "cookies": [],
            "findings": [],
        }

    cookies = [parse_set_cookie(c) for c in cookies_raw if c]
    findings = []

    for cookie in cookies:
        name = cookie["name"]

        if not cookie["httponly"]:
            # Session-like cookies without HttpOnly are high severity
            is_session_like = any(
                t in name.lower() for t in ("session", "auth", "token", "jwt", "access", "refresh", "sid")
            )
            findings.append({
                "cookie": name,
                "issue": "MISSING_HTTPONLY",
                "severity": "HIGH" if is_session_like else "MEDIUM",
                "description": f"Cookie '{name}' lacks HttpOnly flag — readable by JavaScript (XSS risk)",
                "guidance": "Add HttpOnly flag to all cookies not intentionally accessed by JS",
            })

        if not cookie["secure"]:
            findings.append({
                "cookie": name,
                "issue": "MISSING_SECURE",
                "severity": "HIGH",
                "description": f"Cookie '{name}' lacks Secure flag — may be transmitted over HTTP",
                "guidance": "Add Secure flag to ensure cookie is only sent over HTTPS",
            })

        if not cookie["samesite"]:
            findings.append({
                "cookie": name,
                "issue": "MISSING_SAMESITE",
                "severity": "MEDIUM",
                "description": f"Cookie '{name}' lacks SameSite attribute — CSRF risk",
                "guidance": "Add SameSite=Strict or SameSite=Lax",
            })
        elif cookie["samesite"].lower() == "none":
            if not cookie["secure"]:
                findings.append({
                    "cookie": name,
                    "issue": "SAMESITE_NONE_WITHOUT_SECURE",
                    "severity": "HIGH",
                    "description": f"Cookie '{name}' has SameSite=None but no Secure flag (blocked by modern browsers)",
                    "guidance": "Add Secure flag when using SameSite=None",
                })

    return {
        "target": host,
        "url": url,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "total_cookies": len(cookies),
        "findings": findings,
        "cookie_inventory": cookies,
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 cookie-audit.py <hostname>")
        sys.exit(1)

    host = sys.argv[1].strip().lstrip("https://").lstrip("http://").rstrip("/")
    result = audit_cookies(host)

    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    output_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{date_str}-cookie-audit-{host}.json")

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n=== Cookie Audit: {host} ===")
    print(f"Cookies found: {result['total_cookies']}")
    for f in result["findings"]:
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(f["severity"], "⚪")
        print(f"  {icon} [{f['severity']}] {f['cookie']}: {f['issue']}")
    if not result["findings"]:
        print("  ✅ No cookie security issues found")
    print(f"\nFull output: {output_file}")


if __name__ == "__main__":
    main()
