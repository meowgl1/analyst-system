#!/usr/bin/env python3
# dns-enum.py
# What: Enumerates DNS records for a domain (A, AAAA, MX, TXT, NS, CNAME, SOA).
#       Identifies misconfigurations, zone transfer attempts, SPF/DMARC/DKIM gaps.
# When to use: First step in network audit or external recon on own domains.
# Expected output: JSON to backend/outputs/YYYY-MM-DD-dns-enum-<domain>.json
#
# Usage: python3 dns-enum.py <domain>
#   e.g. python3 dns-enum.py mowgli.studio

import sys
import json
import subprocess
import datetime
import os

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA"]

EMAIL_SECURITY = {
    "spf": {"check": "v=spf1", "description": "SPF — authorizes mail senders"},
    "dmarc": {"check": "v=DMARC1", "subdomain": "_dmarc", "description": "DMARC — email policy + reporting"},
    "dkim": {"check": "v=DKIM1", "description": "DKIM — cryptographic mail signature"},
}


def query_dns(domain: str, record_type: str) -> list[str]:
    """Run dig and return list of answer strings."""
    try:
        result = subprocess.run(
            ["dig", "+short", domain, record_type],
            capture_output=True, text=True, timeout=10
        )
        lines = [l.strip() for l in result.stdout.strip().splitlines() if l.strip()]
        return lines
    except Exception:
        return []


def check_zone_transfer(domain: str, nameservers: list[str]) -> dict:
    """Attempt AXFR on each nameserver — should always be refused."""
    results = []
    for ns in nameservers[:3]:  # limit to 3 NS
        ns_clean = ns.rstrip(".")
        try:
            result = subprocess.run(
                ["dig", "axfr", domain, f"@{ns_clean}"],
                capture_output=True, text=True, timeout=10
            )
            transfer_refused = "Transfer failed" in result.stdout or "REFUSED" in result.stdout
            records_returned = result.stdout.count("\n") > 5 and not transfer_refused
            results.append({
                "nameserver": ns_clean,
                "transfer_refused": transfer_refused,
                "transfer_succeeded": records_returned,
            })
        except Exception as e:
            results.append({"nameserver": ns_clean, "error": str(e)})
    return results


def analyze(domain: str) -> dict:
    findings = []
    records = {}

    print(f"\n=== DNS Enumeration: {domain} ===\n")

    # Query all record types
    for rtype in RECORD_TYPES:
        answers = query_dns(domain, rtype)
        records[rtype] = answers
        if answers:
            print(f"  {rtype:8s}: {' | '.join(answers[:3])}{' ...' if len(answers) > 3 else ''}")

    # Email security checks
    print(f"\n  Email security:")
    txt_records = " ".join(records.get("TXT", []))

    # SPF
    spf_found = any("v=spf1" in t for t in records.get("TXT", []))
    if not spf_found:
        findings.append({
            "type": "MISSING_SPF",
            "severity": "HIGH",
            "description": "No SPF record — anyone can spoof email from this domain",
            "guidance": "Add TXT record: v=spf1 include:_spf.google.com ~all",
        })
        print(f"    🟠 SPF: MISSING")
    else:
        print(f"    ✅ SPF: present")

    # DMARC
    dmarc_records = query_dns(f"_dmarc.{domain}", "TXT")
    dmarc_found = any("v=DMARC1" in t for t in dmarc_records)
    if not dmarc_found:
        findings.append({
            "type": "MISSING_DMARC",
            "severity": "HIGH",
            "description": "No DMARC record — email spoofing not blocked by policy",
            "guidance": "Add TXT record at _dmarc: v=DMARC1; p=quarantine; rua=mailto:dmarc@domain",
        })
        print(f"    🟠 DMARC: MISSING")
    else:
        dmarc_str = " ".join(dmarc_records)
        if "p=none" in dmarc_str.lower():
            findings.append({
                "type": "DMARC_POLICY_NONE",
                "severity": "MEDIUM",
                "description": "DMARC policy is 'none' — monitors but doesn't block spoofing",
                "guidance": "Change p=none to p=quarantine or p=reject",
            })
            print(f"    🟡 DMARC: p=none (monitoring only)")
        else:
            print(f"    ✅ DMARC: present with enforcement")

    # CAA
    caa_records = records.get("CAA", [])
    if not caa_records:
        findings.append({
            "type": "MISSING_CAA",
            "severity": "LOW",
            "description": "No CAA record — any CA can issue certificates for this domain",
            "guidance": "Add CAA record: 0 issue 'letsencrypt.org'",
        })
        print(f"    🟢 CAA: MISSING (low)")
    else:
        print(f"    ✅ CAA: {caa_records[0]}")

    # Zone transfer
    nameservers = records.get("NS", [])
    zt_results = []
    if nameservers:
        print(f"\n  Zone transfer check:")
        zt_results = check_zone_transfer(domain, nameservers)
        for zt in zt_results:
            if zt.get("transfer_succeeded"):
                findings.append({
                    "type": "ZONE_TRANSFER_ALLOWED",
                    "severity": "CRITICAL",
                    "nameserver": zt["nameserver"],
                    "description": f"Zone transfer (AXFR) succeeded on {zt['nameserver']} — full DNS exposed",
                    "guidance": "Restrict AXFR to authorized secondary nameservers only",
                })
                print(f"    🔴 AXFR succeeded on {zt['nameserver']}!")
            elif zt.get("transfer_refused"):
                print(f"    ✅ {zt['nameserver']}: AXFR refused (correct)")

    # Subdomain indicators
    wildcard = query_dns(f"*.{domain}", "A")
    if wildcard:
        findings.append({
            "type": "WILDCARD_DNS",
            "severity": "MEDIUM",
            "value": wildcard[0],
            "description": "Wildcard DNS record — all subdomains resolve to an IP",
            "guidance": "Verify this is intentional — wildcard DNS can obscure infrastructure",
        })

    return {
        "domain": domain,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "records": records,
        "dmarc": dmarc_records,
        "zone_transfer_tests": zt_results,
        "findings": findings,
        "summary": {
            "critical": len([f for f in findings if f["severity"] == "CRITICAL"]),
            "high": len([f for f in findings if f["severity"] == "HIGH"]),
            "medium": len([f for f in findings if f["severity"] == "MEDIUM"]),
            "low": len([f for f in findings if f["severity"] == "LOW"]),
        }
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 dns-enum.py <domain>")
        sys.exit(1)

    domain = sys.argv[1].strip().lstrip("https://").lstrip("http://").rstrip("/")
    result = analyze(domain)

    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    output_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{date_str}-dns-enum-{domain}.json")

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    s = result["summary"]
    print(f"\n--- Summary ---")
    print(f"  Critical: {s['critical']} | High: {s['high']} | Medium: {s['medium']} | Low: {s['low']}")
    print(f"  Full output: {output_file}")


if __name__ == "__main__":
    main()
