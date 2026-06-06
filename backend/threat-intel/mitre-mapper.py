#!/usr/bin/env python3
# mitre-mapper.py
# What: Maps security findings (from any JSON report) to MITRE ATT&CK techniques.
#       Uses a local keyword→technique mapping (no external API needed).
#       Outputs a MITRE coverage table and detection gap analysis.
# When to use: After a forensic, network, or security audit — to contextualize findings
#              in the ATT&CK framework and identify detection gaps.
# Expected output: JSON to backend/outputs/YYYY-MM-DD-mitre-mapper-<slug>.json
#
# Usage: python3 mitre-mapper.py <findings.json> [--slug custom-name]
#   e.g. python3 mitre-mapper.py backend/outputs/2026-06-07-dns-enum-mowgli.studio.json

import sys
import json
import datetime
import os
import re

# Keyword → (technique_id, technique_name, tactic) mapping
# Covers the most common techniques without external API
KEYWORD_TECHNIQUE_MAP = [
    # Discovery
    (["port scan", "port profiler", "listening port", "open port"],
     "T1046", "Network Service Discovery", "Discovery"),
    (["dns enum", "dns record", "subdomain", "zone transfer"],
     "T1018", "Remote System Discovery", "Discovery"),
    (["osint", "whois", "certificate transparency"],
     "T1596", "Search Open Technical Databases", "Reconnaissance"),
    (["process list", "ps aux", "running process"],
     "T1057", "Process Discovery", "Discovery"),
    (["lsof", "connection", "network connection", "established"],
     "T1049", "System Network Connections Discovery", "Discovery"),
    (["launchagent", "launchdaemon", "persistence", "login item", "crontab"],
     "T1543", "Create or Modify System Process", "Persistence"),
    (["kernel extension", "kext", "kmutil"],
     "T1547", "Boot or Logon Autostart Execution", "Persistence"),
    # Credential Access
    (["auth bypass", "no auth", "unauthenticated", "401", "403"],
     "T1110", "Brute Force", "Credential Access"),
    (["cookie", "session", "httponly", "secure flag", "jwt"],
     "T1539", "Steal Web Session Cookie", "Credential Access"),
    (["password", "credential", "login form", "csrf"],
     "T1185", "Browser Session Hijacking", "Credential Access"),
    # Defense Evasion
    (["codesign", "unsigned", "invalid signature", "code signing"],
     "T1553", "Subvert Trust Controls", "Defense Evasion"),
    (["base64", "obfuscated", "encoded payload"],
     "T1027", "Obfuscated Files or Information", "Defense Evasion"),
    # Command and Control
    (["c2 port", "4444", "1337", "31337", "beacon", "cobalt strike"],
     "T1071", "Application Layer Protocol", "Command and Control"),
    (["dns tunneling", "dns exfil"],
     "T1071.004", "DNS", "Command and Control"),
    # Exfiltration
    (["data exfil", "high connection", "unusual traffic"],
     "T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    # Initial Access
    (["phishing", "spf missing", "dmarc missing", "email spoof"],
     "T1566", "Phishing", "Initial Access"),
    (["supply chain", "package", "npm", "pip", "dependency"],
     "T1195", "Supply Chain Compromise", "Initial Access"),
    # Execution
    (["eval(", "exec(", "subprocess", "shell injection", "command injection"],
     "T1059", "Command and Scripting Interpreter", "Execution"),
    # Collection
    (["cors wildcard", "cors open", "cross-origin"],
     "T1185", "Browser Session Hijacking", "Collection"),
    # Impact
    (["rate limit", "no rate limit", "dos", "burst"],
     "T1498", "Network Denial of Service", "Impact"),
    # Privilege Escalation
    (["sudo", "privilege", "root", "escalation"],
     "T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation"),
    # Lateral Movement
    (["smb", "rdp", "vnc", "lateral"],
     "T1021", "Remote Services", "Lateral Movement"),
    # Collection
    (["sensitive path", ".env exposed", "config exposed", "git exposed"],
     "T1552", "Unsecured Credentials", "Credential Access"),
    # Reconnaissance
    (["endpoint discovery", "common path", "admin panel", "swagger"],
     "T1595", "Active Scanning", "Reconnaissance"),
    # Defense Evasion
    (["missing csp", "unsafe-inline", "xss", "injection"],
     "T1059.007", "JavaScript", "Execution"),
    (["missing hsts", "http", "unencrypted"],
     "T1557", "Adversary-in-the-Middle", "Collection"),
]


def extract_text(obj, depth: int = 0) -> str:
    """Recursively extract all string values from a JSON object."""
    if depth > 5:
        return ""
    if isinstance(obj, str):
        return obj.lower()
    if isinstance(obj, dict):
        return " ".join(extract_text(v, depth + 1) for v in obj.values())
    if isinstance(obj, list):
        return " ".join(extract_text(item, depth + 1) for item in obj[:50])
    return ""


def map_to_mitre(findings_text: str) -> list[dict]:
    """Return list of matched MITRE techniques."""
    matched = []
    seen_ids = set()

    for keywords, technique_id, technique_name, tactic in KEYWORD_TECHNIQUE_MAP:
        for kw in keywords:
            if kw.lower() in findings_text:
                if technique_id not in seen_ids:
                    matched.append({
                        "technique_id": technique_id,
                        "technique_name": technique_name,
                        "tactic": tactic,
                        "triggered_by": kw,
                        "mitre_url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
                    })
                    seen_ids.add(technique_id)
                break

    return sorted(matched, key=lambda x: x["tactic"])


def group_by_tactic(techniques: list[dict]) -> dict:
    by_tactic: dict[str, list] = {}
    for t in techniques:
        tactic = t["tactic"]
        by_tactic.setdefault(tactic, []).append(t)
    return by_tactic


def analyze(input_file: str, slug: str = None) -> dict:
    print(f"\n=== MITRE ATT&CK Mapper ===")
    print(f"  Input: {input_file}\n")

    with open(input_file) as f:
        data = json.load(f)

    # Extract all text from the report
    full_text = extract_text(data)
    techniques = map_to_mitre(full_text)
    by_tactic = group_by_tactic(techniques)

    # Print coverage table
    print(f"  {'Tactic':<30s} Techniques")
    print(f"  {'-'*30} {'-'*40}")
    for tactic, techs in by_tactic.items():
        tech_str = ", ".join(f"{t['technique_id']} {t['technique_name']}" for t in techs)
        print(f"  {tactic:<30s} {tech_str}")

    if not techniques:
        print("  No MITRE techniques mapped — findings may not contain recognized keywords")

    print(f"\n  Total techniques mapped: {len(techniques)}")
    print(f"  Tactics covered: {len(by_tactic)}")

    return {
        "input_file": input_file,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "total_techniques": len(techniques),
        "tactics_covered": list(by_tactic.keys()),
        "techniques": techniques,
        "by_tactic": {tactic: techs for tactic, techs in by_tactic.items()},
        "coverage_note": "Mapping is keyword-based — verify each technique applies to your findings",
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 mitre-mapper.py <findings.json> [--slug name]")
        sys.exit(1)

    input_file = sys.argv[1]
    slug = None
    if "--slug" in sys.argv:
        idx = sys.argv.index("--slug")
        if idx + 1 < len(sys.argv):
            slug = sys.argv[idx + 1]

    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found")
        sys.exit(1)

    slug = slug or os.path.basename(input_file).replace(".json", "")
    result = analyze(input_file, slug)

    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    output_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{date_str}-mitre-mapper-{slug}.json")

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n  Full output: {output_file}")


if __name__ == "__main__":
    main()
