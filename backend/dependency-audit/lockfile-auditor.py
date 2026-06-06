#!/usr/bin/env python3
# lockfile-auditor.py
# What: Parses package-lock.json, yarn.lock, or requirements.txt and checks each
#       dependency against OSV.dev for known CVEs.
# When to use: Before deploying a project — bulk vulnerability scan of all dependencies.
# Expected output: JSON to backend/outputs/YYYY-MM-DD-lockfile-auditor-<slug>.json
#
# Usage: python3 lockfile-auditor.py <lockfile-path>
#   e.g. python3 lockfile-auditor.py /path/to/project/package-lock.json
#   e.g. python3 lockfile-auditor.py /path/to/project/requirements.txt

import sys
import json
import urllib.request
import urllib.error
import datetime
import os
import re

TIMEOUT = 8
UA = "SecurityAudit/1.0 (internal-use)"


def parse_package_lock(path: str) -> list[tuple[str, str]]:
    """Parse package-lock.json v2/v3 → list of (name, version)."""
    with open(path) as f:
        data = json.load(f)
    packages = data.get("packages", {})
    deps = []
    for key, info in packages.items():
        if not key:
            continue
        name = key.replace("node_modules/", "", 1)
        if name.startswith("node_modules/"):
            name = name.split("/", 1)[1]
        version = info.get("version", "")
        if name and version:
            deps.append((name, version))
    return deps


def parse_requirements_txt(path: str) -> list[tuple[str, str]]:
    """Parse requirements.txt → list of (name, version)."""
    deps = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([=<>!~]+)\s*([\d\.]+)", line)
            if m:
                deps.append((m.group(1), m.group(3)))
            else:
                name = re.match(r"^([a-zA-Z0-9_\-\.]+)", line)
                if name:
                    deps.append((name.group(1), ""))
    return deps


def check_osv_batch(packages: list[tuple[str, str]], ecosystem: str) -> dict:
    """Query OSV.dev for each package. Returns {name: [vulns]}."""
    results = {}
    batch_size = 20
    total = len(packages)

    for i in range(0, total, batch_size):
        batch = packages[i:i + batch_size]
        print(f"  Checking {min(i + batch_size, total)}/{total}...", end="\r")

        queries = []
        for name, version in batch:
            q = {"package": {"name": name, "ecosystem": ecosystem}}
            if version:
                q["version"] = version
            queries.append(q)

        payload = json.dumps({"queries": queries}).encode()
        try:
            req = urllib.request.Request(
                "https://api.osv.dev/v1/querybatch",
                data=payload, method="POST"
            )
            req.add_header("Content-Type", "application/json")
            req.add_header("User-Agent", UA)
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
            for j, result in enumerate(data.get("results", [])):
                name = batch[j][0]
                vulns = result.get("vulns", [])
                if vulns:
                    results[name] = [{
                        "id": v.get("id", ""),
                        "summary": v.get("summary", "")[:200],
                    } for v in vulns[:5]]
        except Exception:
            pass

    print()
    return results


def audit(lockfile_path: str) -> dict:
    print(f"\n=== Lockfile Auditor: {lockfile_path} ===\n")
    filename = os.path.basename(lockfile_path).lower()

    if "package-lock" in filename:
        ecosystem = "npm"
        packages = parse_package_lock(lockfile_path)
    elif "requirements" in filename:
        ecosystem = "PyPI"
        packages = parse_requirements_txt(lockfile_path)
    else:
        return {"error": f"Unsupported lockfile format: {filename}"}

    print(f"  Ecosystem: {ecosystem}")
    print(f"  Packages to check: {len(packages)}")

    vuln_map = check_osv_batch(packages, ecosystem)

    findings = []
    for name, vulns in vuln_map.items():
        version = next((v for n, v in packages if n == name), "unknown")
        for vuln in vulns:
            findings.append({
                "type": "KNOWN_CVE",
                "severity": "HIGH",
                "package": name,
                "version": version,
                "vuln_id": vuln["id"],
                "summary": vuln["summary"],
                "description": f"{name}@{version}: {vuln['id']} — {vuln['summary'][:100]}",
                "guidance": f"Update {name} to a patched version",
            })

    print(f"\n  Vulnerable packages: {len(vuln_map)}")
    print(f"  Total findings: {len(findings)}")
    for pkg, vulns in list(vuln_map.items())[:10]:
        print(f"  🟠 {pkg}: {', '.join(v['id'] for v in vulns)}")

    return {
        "lockfile": lockfile_path,
        "ecosystem": ecosystem,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "total_packages": len(packages),
        "vulnerable_count": len(vuln_map),
        "vulnerable_packages": vuln_map,
        "findings": findings,
        "summary": {
            "total": len(packages),
            "vulnerable": len(vuln_map),
            "cve_count": len(findings),
        }
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 lockfile-auditor.py <lockfile>")
        print("  Supports: package-lock.json, requirements.txt")
        sys.exit(1)

    path = sys.argv[1]
    if not os.path.exists(path):
        print(f"Error: {path} not found")
        sys.exit(1)

    result = audit(path)

    slug = os.path.basename(os.path.dirname(os.path.abspath(path)))
    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    output_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{date_str}-lockfile-auditor-{slug}.json")

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n  Full output: {output_file}")


if __name__ == "__main__":
    main()
