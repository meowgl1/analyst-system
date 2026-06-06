#!/usr/bin/env python3
# report-builder.py
# What: Converts one or more JSON outputs from backend/ scripts into a formatted
#       markdown report. Used by agents to standardize final report output.
#       Groups findings by severity, adds summary table, formats evidence blocks.
# When to use: After running backend scripts — convert JSON findings to .md report.
# Expected output: Markdown file at the specified --output path
#
# Usage:
#   python3 backend/tools/report-builder.py \
#     --inputs backend/outputs/2026-06-07-*.json \
#     --output security-audits/2026-06-07-full.md \
#     --title "Full Security Audit" \
#     [--author "forensic-analyst"]

import sys
import json
import os
import re
import datetime
import glob

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    "INFO": "⚪",
}


def collect_findings(data: dict) -> list[dict]:
    """Recursively find all 'findings' arrays in a JSON structure."""
    found = []
    if isinstance(data, dict):
        if "findings" in data and isinstance(data["findings"], list):
            found.extend(data["findings"])
        for v in data.values():
            found.extend(collect_findings(v))
    elif isinstance(data, list):
        for item in data:
            found.extend(collect_findings(item))
    return found


def get_target(data: dict) -> str:
    for key in ("target", "domain", "root", "path", "package", "ioc"):
        if key in data and data[key]:
            return str(data[key])
    return "unknown"


def severity_sort_key(finding: dict) -> int:
    return SEVERITY_ORDER.get(finding.get("severity", "INFO"), 99)


def build_report(input_files: list[str], title: str, author: str) -> str:
    now = datetime.datetime.utcnow()
    date_str = now.strftime("%Y-%m-%d")
    time_str = now.strftime("%Y-%m-%d %H:%MZ")

    all_findings = []
    sources = []
    targets = []
    summaries = []

    for path in input_files:
        try:
            with open(path) as f:
                data = json.load(f)
        except Exception:
            continue

        target = get_target(data)
        targets.append(target)
        source_name = os.path.basename(path)

        findings = collect_findings(data)
        for f in findings:
            f["_source"] = source_name
            f["_target"] = target

        all_findings.extend(findings)

        # Collect summary
        summary = data.get("summary", {})
        if isinstance(summary, dict):
            summaries.append((source_name, target, summary))

        sources.append(source_name)

    # Sort findings by severity
    all_findings.sort(key=severity_sort_key)

    # Count by severity
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        sev = f.get("severity", "")
        if sev in counts:
            counts[sev] += 1

    # Build markdown
    lines = []

    # Header
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"> Generated: {time_str}")
    if author:
        lines.append(f"> Agent: `{author}`")
    lines.append(f"> Sources: {', '.join(sources)}")
    lines.append("")

    # TL;DR
    lines.append("## TL;DR")
    lines.append("")
    if counts["CRITICAL"] > 0:
        lines.append(f"**{counts['CRITICAL']} CRITICAL** findings require immediate action.")
    if counts["HIGH"] > 0:
        lines.append(f"**{counts['HIGH']} HIGH** severity findings need prompt remediation.")
    if counts["MEDIUM"] + counts["LOW"] > 0:
        lines.append(f"{counts['MEDIUM']} medium and {counts['LOW']} low severity findings for review.")
    if not any(counts.values()):
        lines.append("No findings detected.")
    lines.append("")

    # Summary table
    lines.append("## Summary")
    lines.append("")
    lines.append("| Source | Target | Critical | High | Medium | Low |")
    lines.append("|---|---|---|---|---|---|")
    for source_name, target, summary in summaries:
        c = summary.get("critical", 0)
        h = summary.get("high", 0)
        m = summary.get("medium", 0)
        l = summary.get("low", 0)
        lines.append(f"| `{source_name}` | `{target}` | {c} | {h} | {m} | {l} |")
    if not summaries:
        lines.append(f"| combined | {', '.join(set(targets))[:50]} | {counts['CRITICAL']} | {counts['HIGH']} | {counts['MEDIUM']} | {counts['LOW']} |")
    lines.append("")

    # Findings by severity
    lines.append("## Findings")
    lines.append("")

    current_sev = None
    for finding in all_findings:
        sev = finding.get("severity", "INFO")
        if sev != current_sev:
            current_sev = sev
            emoji = SEVERITY_EMOJI.get(sev, "⚪")
            lines.append(f"### {emoji} {sev}")
            lines.append("")

        ftype = finding.get("type", "FINDING")
        desc = finding.get("description", "")
        guidance = finding.get("guidance", "")
        source = finding.get("_source", "")
        target = finding.get("_target", "")

        lines.append(f"#### {ftype}")
        lines.append("")
        if desc:
            lines.append(f"**Finding**: {desc}")
        if guidance:
            lines.append(f"**Guidance**: {guidance}")

        # Include relevant evidence fields
        for key in ("path", "file", "header", "cookie", "port", "value", "command"):
            if key in finding and finding[key]:
                lines.append(f"**{key.capitalize()}**: `{str(finding[key])[:200]}`")

        if source:
            lines.append(f"**Source**: `{source}`")

        lines.append("")

    # Audit trail
    lines.append("## Audit Trail")
    lines.append("")
    lines.append(f"- **Date**: {date_str}")
    lines.append(f"- **Total findings**: {len(all_findings)}")
    lines.append(f"- **Sources**: {len(sources)} scripts")
    lines.append(f"- **Targets**: {', '.join(set(targets))[:200]}")
    lines.append("")

    return "\n".join(lines)


def main():
    args = sys.argv[1:]

    title = "Security Audit Report"
    output_path = None
    author = ""
    input_patterns = []

    i = 0
    while i < len(args):
        if args[i] == "--title" and i + 1 < len(args):
            title = args[i + 1]
            i += 2
        elif args[i] == "--output" and i + 1 < len(args):
            output_path = args[i + 1]
            i += 2
        elif args[i] == "--author" and i + 1 < len(args):
            author = args[i + 1]
            i += 2
        elif args[i] == "--inputs":
            i += 1
            while i < len(args) and not args[i].startswith("--"):
                input_patterns.append(args[i])
                i += 1
        else:
            i += 1

    if not input_patterns:
        print("Usage: python3 report-builder.py --inputs <files...> --output <path.md> --title <title>")
        sys.exit(1)

    # Expand globs
    input_files = []
    for pattern in input_patterns:
        expanded = glob.glob(pattern)
        if expanded:
            input_files.extend(expanded)
        elif os.path.exists(pattern):
            input_files.append(pattern)

    if not input_files:
        print(f"No input files found")
        sys.exit(1)

    print(f"\n=== Report Builder ===")
    print(f"  Inputs: {len(input_files)} files")
    print(f"  Title: {title}")

    report = build_report(input_files, title, author)

    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w") as f:
            f.write(report)
        print(f"  Output: {output_path}")
    else:
        print(report)


if __name__ == "__main__":
    main()
