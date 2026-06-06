#!/usr/bin/env python3
# osint-domain.py
# What: Passive OSINT collection for a domain. Runs: whois, DNS records, certificate
#       transparency (via crt.sh), security.txt, robots.txt, headers fingerprint.
#       Entirely read-only and non-intrusive.
# When to use: Recon on own domains before a security audit, or investigating a suspicious domain.
# Expected output: JSON to backend/outputs/YYYY-MM-DD-osint-domain-<domain>.json
#
# Usage: python3 osint-domain.py <domain>
#   e.g. python3 osint-domain.py mowgli.studio

import sys
import json
import urllib.request
import urllib.error
import subprocess
import datetime
import os
import re

TIMEOUT = 10
UA = "SecurityAudit/1.0 (internal-use)"


def fetch_url(url: str, method: str = "GET") -> tuple[int, dict, str]:
    """Returns (status, headers_dict, body_text)."""
    try:
        req = urllib.request.Request(url, method=method)
        req.add_header("User-Agent", UA)
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read(8192).decode("utf-8", errors="replace")
            return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        return e.code, {}, ""
    except Exception as e:
        return -1, {}, str(e)


def run_whois(domain: str) -> str:
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=15
        )
        return result.stdout[:3000]
    except Exception as e:
        return f"whois error: {e}"


def run_dig(domain: str, rtype: str) -> list[str]:
    try:
        result = subprocess.run(
            ["dig", "+short", domain, rtype],
            capture_output=True, text=True, timeout=10
        )
        return [l.strip() for l in result.stdout.strip().splitlines() if l.strip()]
    except Exception:
        return []


def fetch_crt_sh(domain: str) -> list[dict]:
    """Query crt.sh certificate transparency for subdomains."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", UA)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            # Deduplicate by common_name
            seen = set()
            subdomains = []
            for entry in data[:200]:  # cap at 200
                name = entry.get("common_name", "").lower().strip()
                if name and name not in seen and domain in name:
                    seen.add(name)
                    subdomains.append({
                        "name": name,
                        "issuer": entry.get("issuer_name", "")[:80],
                        "not_before": entry.get("not_before", ""),
                        "not_after": entry.get("not_after", ""),
                    })
            return sorted(subdomains, key=lambda x: x["name"])
    except Exception as e:
        return [{"error": str(e)}]


def extract_whois_fields(whois_text: str) -> dict:
    fields = {}
    patterns = {
        "registrar": r"Registrar:\s*(.+)",
        "created": r"Creation Date:\s*(.+)",
        "expires": r"Registry Expiry Date:\s*(.+)",
        "updated": r"Updated Date:\s*(.+)",
        "status": r"Domain Status:\s*(.+)",
        "registrant_email": r"Registrant Email:\s*(.+)",
    }
    for key, pattern in patterns.items():
        m = re.search(pattern, whois_text, re.IGNORECASE)
        if m:
            fields[key] = m.group(1).strip()[:100]
    return fields


def analyze(domain: str) -> dict:
    print(f"\n=== OSINT Domain: {domain} ===\n")
    findings = []

    # DNS records
    print("  DNS records...")
    dns = {
        "A": run_dig(domain, "A"),
        "AAAA": run_dig(domain, "AAAA"),
        "MX": run_dig(domain, "MX"),
        "NS": run_dig(domain, "NS"),
        "TXT": run_dig(domain, "TXT"),
    }

    # Whois
    print("  Whois...")
    whois_raw = run_whois(domain)
    whois_parsed = extract_whois_fields(whois_raw)

    # Certificate transparency
    print("  Certificate transparency (crt.sh)...")
    subdomains = fetch_crt_sh(domain)
    print(f"    Found {len(subdomains)} certificate entries")

    # security.txt
    print("  security.txt...")
    sec_status, _, sec_body = fetch_url(f"https://{domain}/.well-known/security.txt")
    has_security_txt = sec_status == 200 and "contact" in sec_body.lower()
    if not has_security_txt:
        findings.append({
            "type": "NO_SECURITY_TXT",
            "severity": "LOW",
            "description": "No security.txt — no disclosed responsible disclosure policy",
            "guidance": "Add /.well-known/security.txt with contact and policy fields",
        })

    # robots.txt
    print("  robots.txt...")
    robots_status, _, robots_body = fetch_url(f"https://{domain}/robots.txt")
    interesting_disallows = []
    if robots_status == 200:
        for line in robots_body.splitlines():
            if line.lower().startswith("disallow:") and len(line) > 12:
                path = line.split(":", 1)[1].strip()
                if path not in ("/", ""):
                    interesting_disallows.append(path)

    # Response headers fingerprint
    print("  Headers fingerprint...")
    _, main_headers, _ = fetch_url(f"https://{domain}")
    server = main_headers.get("Server") or main_headers.get("server", "")
    x_powered = main_headers.get("X-Powered-By") or main_headers.get("x-powered-by", "")
    if server:
        findings.append({
            "type": "SERVER_HEADER_DISCLOSURE",
            "severity": "LOW",
            "value": server,
            "description": f"Server header discloses: {server}",
            "guidance": "Remove or genericize the Server header",
        })

    # Interesting subdomains
    interesting_subdomains = []
    risky_prefixes = ["admin", "dev", "staging", "test", "api", "internal", "vpn", "jenkins", "git"]
    for sub in subdomains:
        name = sub.get("name", "")
        for prefix in risky_prefixes:
            if name.startswith(prefix + ".") or f".{prefix}." in name:
                interesting_subdomains.append(sub)
                break

    if interesting_subdomains:
        findings.append({
            "type": "INTERESTING_SUBDOMAINS",
            "severity": "MEDIUM",
            "subdomains": [s["name"] for s in interesting_subdomains[:10]],
            "description": f"Subdomains found with interesting prefixes: {[s['name'] for s in interesting_subdomains[:3]]}...",
            "guidance": "Verify these subdomains are intentional and properly secured",
        })

    print(f"\n  Results:")
    print(f"    IPs: {dns['A']}")
    print(f"    NS: {dns['NS'][:2]}")
    print(f"    Subdomains via CT: {len(subdomains)}")
    print(f"    security.txt: {'✅' if has_security_txt else '🟢 missing (low)'}")
    print(f"    robots.txt disallows: {len(interesting_disallows)}")

    return {
        "domain": domain,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "dns": dns,
        "whois": whois_parsed,
        "whois_raw_excerpt": whois_raw[:1500],
        "subdomains_ct": subdomains,
        "interesting_subdomains": interesting_subdomains,
        "has_security_txt": has_security_txt,
        "robots_disallows": interesting_disallows,
        "server_header": server,
        "x_powered_by": x_powered,
        "findings": findings,
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 osint-domain.py <domain>")
        sys.exit(1)

    domain = sys.argv[1].strip().lstrip("https://").lstrip("http://").rstrip("/")
    result = analyze(domain)

    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    output_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{date_str}-osint-domain-{domain}.json")

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n  Full output: {output_file}")


if __name__ == "__main__":
    main()
