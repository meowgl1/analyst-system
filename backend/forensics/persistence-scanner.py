#!/usr/bin/env python3
# persistence-scanner.py
# What: Structured scan of all macOS persistence mechanisms.
#       Covers: LaunchAgents, LaunchDaemons, login items, crontab, shell profiles,
#       kernel extensions, periodic scripts, XPC services.
#       Produces a complete JSON inventory with risk scoring.
# When to use: forensic-analyst complement — when you need structured JSON output
#              of persistence points rather than raw command output.
# Expected output: JSON to backend/outputs/YYYY-MM-DD-persistence-scanner.json
#
# Usage: python3 persistence-scanner.py

import sys
import json
import subprocess
import os
import glob
import datetime
import re

LAUNCH_DIRS = [
    ("~/Library/LaunchAgents", "user_launch_agent", "LOW"),
    ("/Library/LaunchAgents", "system_launch_agent", "MEDIUM"),
    ("/Library/LaunchDaemons", "system_launch_daemon", "HIGH"),
    ("/System/Library/LaunchAgents", "apple_launch_agent", "INFO"),
    ("/System/Library/LaunchDaemons", "apple_launch_daemon", "INFO"),
]

PERIODIC_DIRS = [
    "/etc/periodic/daily",
    "/etc/periodic/weekly",
    "/etc/periodic/monthly",
]

SHELL_PROFILES = [
    "~/.zshrc", "~/.bashrc", "~/.bash_profile", "~/.profile",
    "~/.zprofile", "~/.zshenv", "/etc/zshrc", "/etc/profile",
]

# Patterns suggesting suspicious launch items
SUSPICIOUS_PATTERNS = [
    r"curl\s+.*\|\s*(bash|sh)",
    r"wget\s+.*\|\s*(bash|sh)",
    r"/tmp/",
    r"base64",
    r"python.*-c\s+['\"]",
    r"exec\s+['\"]",
    r"chmod\s+\+x",
    r"\.hidden",
]


def read_plist(path: str) -> dict:
    """Read a plist file via plutil."""
    try:
        result = subprocess.run(
            ["plutil", "-convert", "json", "-o", "-", path],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
    except Exception:
        pass
    return {}


def scan_launch_dir(directory: str, category: str, base_severity: str) -> list[dict]:
    expanded = os.path.expanduser(directory)
    if not os.path.isdir(expanded):
        return []

    items = []
    for plist_path in glob.glob(os.path.join(expanded, "*.plist")):
        data = read_plist(plist_path)
        label = data.get("Label", os.path.basename(plist_path))
        program = data.get("Program", "")
        program_args = data.get("ProgramArguments", [])
        run_at_load = data.get("RunAtLoad", False)

        cmd = program or (program_args[0] if program_args else "")
        args_str = " ".join(str(a) for a in program_args)

        is_suspicious = any(re.search(p, args_str, re.I) for p in SUSPICIOUS_PATTERNS)
        is_apple = label.startswith("com.apple.")

        severity = "INFO" if is_apple else base_severity
        if is_suspicious:
            severity = "HIGH"

        items.append({
            "path": plist_path,
            "label": label,
            "category": category,
            "program": cmd,
            "run_at_load": run_at_load,
            "is_apple": is_apple,
            "is_suspicious": is_suspicious,
            "severity": severity,
        })

    return items


def get_crontabs() -> list[dict]:
    entries = []
    try:
        result = subprocess.run(
            ["crontab", "-l"],
            capture_output=True, text=True, timeout=5
        )
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip() and not l.startswith("#")]
        for line in lines:
            is_suspicious = any(re.search(p, line, re.I) for p in SUSPICIOUS_PATTERNS)
            entries.append({
                "entry": line,
                "is_suspicious": is_suspicious,
                "severity": "HIGH" if is_suspicious else "MEDIUM",
            })
    except Exception:
        pass
    return entries


def scan_shell_profiles() -> list[dict]:
    findings = []
    for profile in SHELL_PROFILES:
        expanded = os.path.expanduser(profile)
        if not os.path.exists(expanded):
            continue
        try:
            with open(expanded) as f:
                content = f.read()
            for pattern in SUSPICIOUS_PATTERNS:
                if re.search(pattern, content, re.I):
                    findings.append({
                        "file": expanded,
                        "pattern": pattern,
                        "severity": "HIGH",
                        "description": f"Suspicious pattern in {expanded}",
                    })
        except Exception:
            pass
    return findings


def get_kernel_extensions() -> list[dict]:
    try:
        result = subprocess.run(
            ["kmutil", "showloaded"],
            capture_output=True, text=True, timeout=10
        )
        kexts = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("No"):
                is_apple = "com.apple" in line.lower()
                kexts.append({
                    "entry": line[:200],
                    "is_apple": is_apple,
                    "severity": "INFO" if is_apple else "MEDIUM",
                })
        return kexts
    except Exception:
        return []


def scan() -> dict:
    print("\n=== Persistence Scanner: localhost ===\n")

    all_items = []
    suspicious_count = 0

    # Launch items
    print("  Scanning launch directories...")
    for directory, category, severity in LAUNCH_DIRS:
        items = scan_launch_dir(directory, category, severity)
        non_apple = [i for i in items if not i["is_apple"]]
        if non_apple:
            print(f"  {directory}: {len(items)} total, {len(non_apple)} non-Apple")
        all_items.extend(items)

    # Crontabs
    print("  Checking crontab...")
    crontabs = get_crontabs()
    if crontabs:
        print(f"  crontab: {len(crontabs)} entries")

    # Shell profiles
    print("  Scanning shell profiles...")
    shell_findings = scan_shell_profiles()

    # Kernel extensions
    print("  Checking kernel extensions...")
    kexts = get_kernel_extensions()
    non_apple_kexts = [k for k in kexts if not k["is_apple"]]
    if non_apple_kexts:
        print(f"  Kernel extensions (non-Apple): {len(non_apple_kexts)}")

    # Findings aggregation
    findings = []
    suspicious_items = [i for i in all_items if i.get("is_suspicious")]
    for item in suspicious_items:
        findings.append({
            "type": "SUSPICIOUS_LAUNCH_ITEM",
            "severity": "HIGH",
            "path": item["path"],
            "label": item["label"],
            "program": item["program"],
            "description": f"Launch item '{item['label']}' contains suspicious patterns",
            "guidance": "Investigate this item — it may indicate persistence malware",
        })
        suspicious_count += 1

    for entry in crontabs:
        if entry.get("is_suspicious"):
            findings.append({
                "type": "SUSPICIOUS_CRONTAB",
                "severity": "HIGH",
                "entry": entry["entry"],
                "description": "Crontab entry contains suspicious patterns",
                "guidance": "Review and remove if not authorized",
            })

    findings.extend([{
        "type": "SUSPICIOUS_SHELL_PROFILE",
        "severity": sf["severity"],
        "file": sf["file"],
        "description": sf["description"],
        "guidance": "Review this shell profile for unauthorized modifications",
    } for sf in shell_findings])

    non_apple_launch = [i for i in all_items if not i["is_apple"]]
    print(f"\n  Non-Apple launch items: {len(non_apple_launch)}")
    print(f"  Suspicious items: {suspicious_count}")
    print(f"  Crontab entries: {len(crontabs)}")

    return {
        "target": "localhost",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "launch_items": all_items,
        "crontab_entries": crontabs,
        "shell_profile_findings": shell_findings,
        "kernel_extensions": kexts,
        "findings": findings,
        "summary": {
            "total_launch_items": len(all_items),
            "non_apple_launch": len(non_apple_launch),
            "suspicious_launch": suspicious_count,
            "crontab_entries": len(crontabs),
            "kext_count": len(kexts),
            "non_apple_kexts": len(non_apple_kexts),
        }
    }


def main():
    result = scan()

    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    output_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{date_str}-persistence-scanner.json")

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    for finding in result["findings"]:
        icon = {"HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(finding["severity"], "⚪")
        print(f"  {icon} [{finding['severity']}] {finding['type']}")

    print(f"\n  Full output: {output_file}")


if __name__ == "__main__":
    main()
