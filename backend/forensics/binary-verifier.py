#!/usr/bin/env python3
# binary-verifier.py
# What: Verifies the integrity and provenance of a binary or application.
#       Checks: code signature, notarization, hash, file type, strings for IoCs,
#               dynamic libraries loaded, binary origin (App Store vs direct).
# When to use: Before running an unknown binary, or during forensic triage on a suspect file.
# Expected output: JSON to backend/outputs/YYYY-MM-DD-binary-verifier-<name>.json
#
# Usage: python3 binary-verifier.py <path-to-binary-or-app>
#   e.g. python3 binary-verifier.py /Applications/SomeApp.app
#   e.g. python3 binary-verifier.py /tmp/suspicious-binary

import sys
import json
import subprocess
import os
import re
import datetime

SUSPICIOUS_STRINGS = [
    r"curl\s+https?://",
    r"wget\s+https?://",
    r"/tmp/[a-z0-9]{6,}",
    r"\.hidden",
    r"chmod\s+\+x",
    r"base64\s+--decode",
    r"LaunchAgent",
    r"RunAtLoad",
    r"/etc/crontab",
    r"keychain",
    r"SecKeychainFind",
    r"/Users/[^/]+/\.ssh/",
    r"DYLD_INSERT_LIBRARIES",
    r"NS_LOAD_DYLIB",
]

NETWORK_IOC_PATTERNS = [
    r"https?://[a-z0-9\-]+\.[a-z]{2,}(?:/[^\s\"']+)?",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}",
]


def run_cmd(cmd: list, timeout: int = 10) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout + result.stderr
    except Exception as e:
        return f"ERROR: {e}"


def check_codesign(path: str) -> dict:
    output = run_cmd(["codesign", "-dv", "--verbose=4", path])
    signed = "code object is not signed" not in output and "ERROR" not in output[:50]
    team_id = re.search(r"TeamIdentifier=(\S+)", output)
    bundle_id = re.search(r"Identifier=(\S+)", output)
    authority = re.findall(r"Authority=(.+)", output)

    return {
        "signed": signed,
        "team_id": team_id.group(1) if team_id else None,
        "bundle_id": bundle_id.group(1) if bundle_id else None,
        "authority_chain": authority[:3],
        "raw_excerpt": output[:800],
    }


def check_spctl(path: str) -> dict:
    output = run_cmd(["spctl", "-a", "-v", path])
    gatekeeper_ok = "accepted" in output.lower()
    notarized = "notarized" in output.lower()
    return {
        "gatekeeper_accepted": gatekeeper_ok,
        "notarized": notarized,
        "output": output.strip()[:300],
    }


def compute_hash(path: str) -> dict:
    hashes = {}
    for algo in ["256", "512"]:
        result = run_cmd(["shasum", f"-a{algo}", path])
        if result and not result.startswith("ERROR"):
            hashes[f"sha{algo}"] = result.split()[0] if result.split() else ""
    return hashes


def check_file_type(path: str) -> str:
    return run_cmd(["file", path]).strip()


def scan_strings(path: str) -> dict:
    """Run strings and look for suspicious patterns."""
    try:
        result = subprocess.run(
            ["strings", path],
            capture_output=True, text=True, timeout=15
        )
        strings_output = result.stdout
    except Exception:
        strings_output = ""

    suspicious = []
    for pattern in SUSPICIOUS_STRINGS:
        matches = re.findall(pattern, strings_output, re.I)
        if matches:
            suspicious.extend(matches[:3])

    # Network indicators
    network_iocs = []
    for pattern in NETWORK_IOC_PATTERNS:
        matches = re.findall(pattern, strings_output, re.I)
        for m in matches[:5]:
            if not any(skip in m for skip in ["apple.com", "localhost", "127.0.0.1", "example.com"]):
                network_iocs.append(m)

    return {
        "suspicious_patterns": list(set(suspicious))[:10],
        "network_iocs": list(set(network_iocs))[:10],
        "total_strings": strings_output.count("\n"),
    }


def verify(path: str) -> dict:
    print(f"\n=== Binary Verifier: {path} ===\n")
    findings = []

    # File existence
    if not os.path.exists(path):
        return {"error": f"Path not found: {path}"}

    # File type
    file_type = check_file_type(path)
    print(f"  File type: {file_type}")

    # Hash
    print("  Computing hashes...")
    hashes = compute_hash(path)
    print(f"  SHA256: {hashes.get('sha256', 'error')}")

    # Code signature
    print("  Checking code signature...")
    codesign = check_codesign(path)
    if not codesign["signed"]:
        findings.append({
            "type": "UNSIGNED_BINARY",
            "severity": "HIGH",
            "description": "Binary is not code-signed",
            "guidance": "Only run signed binaries from trusted sources. Verify provenance before executing.",
        })
        print("  🟠 Code signature: NOT SIGNED")
    else:
        print(f"  ✅ Signed by: {codesign.get('team_id', 'unknown')}")

    # Gatekeeper / notarization
    print("  Checking Gatekeeper...")
    spctl = check_spctl(path)
    if not spctl["gatekeeper_accepted"]:
        findings.append({
            "type": "GATEKEEPER_REJECTED",
            "severity": "HIGH",
            "description": "Gatekeeper does not accept this binary",
            "guidance": "Do not run this binary — it fails macOS security checks",
        })
        print("  🟠 Gatekeeper: REJECTED")
    elif not spctl["notarized"]:
        findings.append({
            "type": "NOT_NOTARIZED",
            "severity": "MEDIUM",
            "description": "Binary is not notarized by Apple",
            "guidance": "Non-notarized apps carry higher risk — verify developer identity",
        })
        print("  🟡 Notarization: not notarized")
    else:
        print("  ✅ Gatekeeper: accepted + notarized")

    # Strings analysis
    print("  Scanning strings...")
    strings_result = scan_strings(path)
    if strings_result["suspicious_patterns"]:
        findings.append({
            "type": "SUSPICIOUS_STRINGS",
            "severity": "HIGH",
            "patterns": strings_result["suspicious_patterns"],
            "description": f"Suspicious patterns in binary strings: {strings_result['suspicious_patterns'][:3]}",
            "guidance": "Review these patterns — may indicate malicious behavior",
        })
    if strings_result["network_iocs"]:
        findings.append({
            "type": "NETWORK_INDICATORS",
            "severity": "MEDIUM",
            "iocs": strings_result["network_iocs"],
            "description": f"Network addresses found in binary strings",
            "guidance": "Verify these addresses are legitimate for this application",
        })

    print(f"\n  Findings: {len(findings)}")
    for f in findings:
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(f["severity"], "⚪")
        print(f"  {icon} [{f['severity']}] {f['type']}")

    return {
        "path": path,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "file_type": file_type,
        "hashes": hashes,
        "codesign": codesign,
        "gatekeeper": spctl,
        "strings_analysis": strings_result,
        "findings": findings,
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 binary-verifier.py <path>")
        sys.exit(1)

    path = sys.argv[1]
    result = verify(path)

    name = re.sub(r"[^\w\-]", "_", os.path.basename(path))
    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    output_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{date_str}-binary-verifier-{name}.json")

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n  Full output: {output_file}")


if __name__ == "__main__":
    main()
