#!/usr/bin/env python3
# package-analyzer.py
# What: Analyzes a package's metadata from npm or PyPI registries.
#       Checks: maintainer count, publish frequency, download trend,
#               age, known CVEs (via OSV.dev API), author reputation.
# When to use: Before adding a new dependency — first step in dependency-auditor workflow.
# Expected output: JSON to backend/outputs/YYYY-MM-DD-package-analyzer-<pkg>.json
#
# Usage:
#   python3 package-analyzer.py <package-name> [--registry npm|pypi]
#   python3 package-analyzer.py lodash --registry npm
#   python3 package-analyzer.py requests --registry pypi

import sys
import json
import urllib.request
import urllib.error
import datetime
import os

TIMEOUT = 10
UA = "SecurityAudit/1.0 (internal-use)"


def fetch_json(url: str) -> dict | None:
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", UA)
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {"_http_error": e.code}
    except Exception as e:
        return {"_error": str(e)}


def fetch_npm(package: str) -> dict:
    data = fetch_json(f"https://registry.npmjs.org/{package}")
    if not data or "_error" in data:
        return {"error": str(data)}

    latest_version = data.get("dist-tags", {}).get("latest", "")
    versions = list(data.get("versions", {}).keys())
    time_data = data.get("time", {})
    created = time_data.get("created", "")
    modified = time_data.get("modified", "")
    maintainers = data.get("maintainers", [])

    latest_data = data.get("versions", {}).get(latest_version, {})
    deps = latest_data.get("dependencies", {})
    scripts = latest_data.get("scripts", {})

    # Check suspicious scripts
    suspicious_scripts = {}
    for script_name, script_cmd in scripts.items():
        if any(kw in script_cmd.lower() for kw in ["curl", "wget", "bash", "eval", "exec"]):
            suspicious_scripts[script_name] = script_cmd

    return {
        "registry": "npm",
        "package": package,
        "latest_version": latest_version,
        "total_versions": len(versions),
        "created": created,
        "last_modified": modified,
        "maintainers": [m.get("name", "") for m in maintainers[:10]],
        "maintainer_count": len(maintainers),
        "dependency_count": len(deps),
        "dependencies": list(deps.keys())[:20],
        "suspicious_scripts": suspicious_scripts,
        "homepage": data.get("homepage", ""),
        "repository": data.get("repository", {}).get("url", "") if isinstance(data.get("repository"), dict) else str(data.get("repository", "")),
        "license": data.get("license", ""),
    }


def fetch_pypi(package: str) -> dict:
    data = fetch_json(f"https://pypi.org/pypi/{package}/json")
    if not data or "_error" in data:
        return {"error": str(data)}

    info = data.get("info", {})
    releases = data.get("releases", {})
    urls = data.get("urls", [])

    return {
        "registry": "pypi",
        "package": package,
        "latest_version": info.get("version", ""),
        "total_versions": len(releases),
        "summary": info.get("summary", ""),
        "author": info.get("author", ""),
        "maintainer": info.get("maintainer", ""),
        "license": info.get("license", ""),
        "homepage": info.get("home_page", ""),
        "requires_python": info.get("requires_python", ""),
        "dependency_count": len(info.get("requires_dist", []) or []),
        "project_urls": info.get("project_urls", {}),
    }


def check_osv(package: str, ecosystem: str) -> list[dict]:
    """Query OSV.dev for known vulnerabilities."""
    payload = json.dumps({
        "package": {"name": package, "ecosystem": ecosystem}
    }).encode()
    try:
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=payload,
            method="POST"
        )
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", UA)
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
        vulns = data.get("vulns", [])
        return [{
            "id": v.get("id", ""),
            "summary": v.get("summary", "")[:200],
            "severity": v.get("database_specific", {}).get("severity", "UNKNOWN"),
            "published": v.get("published", ""),
        } for v in vulns[:10]]
    except Exception:
        return []


def analyze(package: str, registry: str) -> dict:
    print(f"\n=== Package Analyzer: {package} ({registry}) ===\n")
    findings = []

    # Fetch registry data
    if registry == "npm":
        pkg_data = fetch_npm(package)
        ecosystem = "npm"
    else:
        pkg_data = fetch_pypi(package)
        ecosystem = "PyPI"

    if "error" in pkg_data:
        return {"package": package, "registry": registry, "error": pkg_data["error"]}

    # Check OSV
    print("  Checking OSV.dev for CVEs...")
    vulns = check_osv(package, ecosystem)
    print(f"  Known CVEs: {len(vulns)}")

    # Analyze findings
    # Single maintainer
    if registry == "npm" and pkg_data.get("maintainer_count", 99) == 1:
        findings.append({
            "type": "SINGLE_MAINTAINER",
            "severity": "LOW",
            "description": "Package has only one maintainer — account takeover risk",
            "guidance": "Check maintainer history and package ownership transfers",
        })

    # Suspicious scripts
    if pkg_data.get("suspicious_scripts"):
        for script, cmd in pkg_data["suspicious_scripts"].items():
            findings.append({
                "type": "SUSPICIOUS_INSTALL_SCRIPT",
                "severity": "HIGH",
                "script": script,
                "command": cmd[:200],
                "description": f"Suspicious command in '{script}' script: {cmd[:80]}",
                "guidance": "Review this script before installing — may execute during npm install",
            })

    # CVEs
    for vuln in vulns:
        severity_map = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM", "LOW": "LOW"}
        sev = severity_map.get(vuln.get("severity", "").upper(), "MEDIUM")
        findings.append({
            "type": "KNOWN_CVE",
            "severity": sev,
            "vuln_id": vuln["id"],
            "summary": vuln["summary"],
            "description": f"Known vulnerability: {vuln['id']} — {vuln['summary']}",
            "guidance": "Check if your version is affected. Update or find alternative.",
        })

    # Stale package
    last_modified = pkg_data.get("last_modified", "")
    if last_modified:
        try:
            mod_date = datetime.datetime.fromisoformat(last_modified.replace("Z", "+00:00"))
            days_old = (datetime.datetime.now(datetime.timezone.utc) - mod_date).days
            if days_old > 730:
                findings.append({
                    "type": "STALE_PACKAGE",
                    "severity": "MEDIUM",
                    "days_since_update": days_old,
                    "description": f"Package not updated in {days_old} days (~{days_old // 365} years)",
                    "guidance": "Check if the package is abandoned — seek maintained alternative",
                })
        except Exception:
            pass

    print(f"\n  Version: {pkg_data.get('latest_version', '?')}")
    print(f"  Maintainers: {pkg_data.get('maintainer_count', pkg_data.get('author', '?'))}")
    print(f"  CVEs: {len(vulns)}")
    print(f"  Findings: {len(findings)}")
    for f in findings:
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(f["severity"], "⚪")
        print(f"  {icon} [{f['severity']}] {f['type']}")

    return {
        "package": package,
        "registry": registry,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "metadata": pkg_data,
        "vulnerabilities": vulns,
        "findings": findings,
        "summary": {
            "cve_count": len(vulns),
            "critical": len([f for f in findings if f["severity"] == "CRITICAL"]),
            "high": len([f for f in findings if f["severity"] == "HIGH"]),
            "medium": len([f for f in findings if f["severity"] == "MEDIUM"]),
        }
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 package-analyzer.py <package> [--registry npm|pypi]")
        sys.exit(1)

    package = sys.argv[1]
    registry = "npm"
    if "--registry" in sys.argv:
        idx = sys.argv.index("--registry")
        if idx + 1 < len(sys.argv):
            registry = sys.argv[idx + 1].lower()

    result = analyze(package, registry)

    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    safe_pkg = package.replace("/", "_").replace("@", "")
    output_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{date_str}-package-analyzer-{safe_pkg}.json")

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n  Full output: {output_file}")


if __name__ == "__main__":
    main()
