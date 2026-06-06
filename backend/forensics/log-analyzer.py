#!/usr/bin/env python3
# log-analyzer.py
# What: Analyzes macOS system logs for suspicious patterns.
#       Searches for: auth failures, privilege escalation, process crashes,
#       network anomalies, malware indicators, unexpected sudo usage.
# When to use: Forensic triage — review recent system activity for IOCs.
# Expected output: JSON to backend/outputs/YYYY-MM-DD-log-analyzer.json
#
# Usage: python3 log-analyzer.py [--hours N]
#   --hours N: look back N hours (default: 24)
#   e.g. python3 log-analyzer.py --hours 48

import sys
import json
import subprocess
import datetime
import os
import re

DEFAULT_HOURS = 24

LOG_QUERIES = [
    {
        "name": "auth_failures",
        "predicate": 'eventMessage CONTAINS "authentication error" OR eventMessage CONTAINS "Failed password" OR eventMessage CONTAINS "pam_unix" AND eventMessage CONTAINS "failure"',
        "severity": "HIGH",
        "description": "Authentication failures",
    },
    {
        "name": "sudo_usage",
        "predicate": 'process == "sudo" OR eventMessage CONTAINS "sudo"',
        "severity": "MEDIUM",
        "description": "Sudo usage",
    },
    {
        "name": "privilege_escalation",
        "predicate": 'eventMessage CONTAINS "privilege" OR eventMessage CONTAINS "setuid" OR eventMessage CONTAINS "escalation"',
        "severity": "HIGH",
        "description": "Privilege escalation indicators",
    },
    {
        "name": "crashes",
        "predicate": 'eventType == "faultEvent" OR eventMessage CONTAINS "crash" OR eventMessage CONTAINS "killed"',
        "severity": "LOW",
        "description": "Process crashes and kills",
    },
    {
        "name": "network_anomalies",
        "predicate": 'eventMessage CONTAINS "connection refused" OR eventMessage CONTAINS "network unreachable" OR process == "tcpd"',
        "severity": "MEDIUM",
        "description": "Network anomalies",
    },
    {
        "name": "malware_indicators",
        "predicate": 'eventMessage CONTAINS "LaunchAgent" OR eventMessage CONTAINS "RunAtLoad" OR eventMessage CONTAINS "base64"',
        "severity": "HIGH",
        "description": "Potential malware/persistence indicators",
    },
    {
        "name": "disk_errors",
        "predicate": 'eventMessage CONTAINS "I/O error" OR eventMessage CONTAINS "disk full" OR subsystem == "com.apple.DiskArbitration"',
        "severity": "MEDIUM",
        "description": "Disk I/O issues",
    },
    {
        "name": "security_framework",
        'predicate': 'subsystem == "com.apple.security" AND (eventType == "faultEvent" OR eventType == "error")',
        "severity": "HIGH",
        "description": "Security framework errors",
    },
]


def run_log_query(predicate: str, hours: int) -> list[str]:
    """Run 'log show' with a predicate, return list of log lines."""
    start_time = (datetime.datetime.utcnow() - datetime.timedelta(hours=hours)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    try:
        result = subprocess.run(
            [
                "log", "show",
                "--start", start_time,
                "--predicate", predicate,
                "--style", "compact",
            ],
            capture_output=True, text=True, timeout=30
        )
        lines = [l for l in result.stdout.splitlines() if l.strip() and not l.startswith("Filtering")]
        return lines[:200]  # cap to avoid huge output
    except Exception as e:
        return [f"ERROR: {e}"]


def analyze(hours: int) -> dict:
    print(f"\n=== Log Analyzer: last {hours} hours ===\n")
    findings = []
    results = {}

    for query in LOG_QUERIES:
        name = query["name"]
        print(f"  Querying: {query['description']}...", end=" ", flush=True)
        lines = run_log_query(query["predicate"], hours)
        count = len(lines)
        results[name] = {
            "description": query["description"],
            "count": count,
            "severity": query["severity"],
            "lines": lines[:20],  # store only first 20 in output
        }
        print(f"{count} events")

        if count > 0:
            # Threshold-based findings
            threshold = {"HIGH": 3, "MEDIUM": 10, "LOW": 50}.get(query["severity"], 5)
            if count >= threshold:
                findings.append({
                    "type": f"ELEVATED_{name.upper()}",
                    "severity": query["severity"],
                    "count": count,
                    "description": f"{query['description']}: {count} events in {hours}h",
                    "guidance": f"Review the log entries for this category — {count} events may warrant investigation",
                    "sample": lines[:3],
                })

    # Cross-analysis: auth failures + sudo = escalation attempt
    auth_count = results.get("auth_failures", {}).get("count", 0)
    sudo_count = results.get("sudo_usage", {}).get("count", 0)
    if auth_count > 5 and sudo_count > 3:
        findings.append({
            "type": "AUTH_FAILURE_WITH_SUDO",
            "severity": "HIGH",
            "auth_failures": auth_count,
            "sudo_events": sudo_count,
            "description": f"Combination of {auth_count} auth failures and {sudo_count} sudo events — possible privilege escalation attempt",
            "guidance": "Review both auth log and sudo log for correlating timestamps",
        })

    print(f"\n  Findings: {len(findings)}")
    for f in findings:
        icon = {"HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(f["severity"], "⚪")
        print(f"  {icon} [{f['severity']}] {f['type']}: {f.get('count', '')} events")

    return {
        "target": "localhost",
        "hours_analyzed": hours,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "query_results": results,
        "findings": findings,
    }


def main():
    hours = DEFAULT_HOURS
    if "--hours" in sys.argv:
        idx = sys.argv.index("--hours")
        if idx + 1 < len(sys.argv):
            try:
                hours = int(sys.argv[idx + 1])
            except ValueError:
                pass

    result = analyze(hours)

    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    output_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{date_str}-log-analyzer.json")

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n  Full output: {output_file}")


if __name__ == "__main__":
    main()
