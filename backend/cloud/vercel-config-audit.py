#!/usr/bin/env python3
# vercel-config-audit.py
# What: Audits a Vercel project configuration for security issues.
#       Checks: vercel.json headers, redirects, rewrites, functions config,
#               next.config.ts/js security settings, exposed env vars.
# When to use: Before deploying or reviewing a Next.js/Vercel project.
# Expected output: JSON to backend/outputs/YYYY-MM-DD-vercel-config-audit-<slug>.json
#
# Usage: python3 vercel-config-audit.py <project-root>
#   e.g. python3 vercel-config-audit.py /Users/thomas/Documents/Claude/Projects/baloo

import sys
import json
import os
import re
import datetime

SECURITY_HEADERS_REQUIRED = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": ("DENY", "SAMEORIGIN"),
    "Strict-Transport-Security": None,  # any value OK
    "Content-Security-Policy": None,
    "Referrer-Policy": None,
}


def read_json(path: str) -> dict | None:
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def read_text(path: str) -> str:
    try:
        with open(path) as f:
            return f.read()
    except Exception:
        return ""


def audit_vercel_json(data: dict) -> list[dict]:
    findings = []

    # Check headers
    headers_config = data.get("headers", [])
    source_headers: dict[str, dict] = {}
    for entry in headers_config:
        src = entry.get("source", "")
        for h in entry.get("headers", []):
            key = h.get("key", "")
            source_headers[key.lower()] = h.get("value", "")

    for header, required_value in SECURITY_HEADERS_REQUIRED.items():
        val = source_headers.get(header.lower(), "")
        if not val:
            severity = "HIGH" if header in ("Strict-Transport-Security", "Content-Security-Policy") else "MEDIUM"
            findings.append({
                "type": f"MISSING_HEADER_{header.upper().replace('-', '_')}",
                "severity": severity,
                "description": f"Security header '{header}' not set in vercel.json headers config",
                "guidance": f"Add '{header}' to the headers array in vercel.json",
            })
        elif isinstance(required_value, tuple) and val.upper() not in required_value:
            findings.append({
                "type": f"WEAK_HEADER_{header.upper().replace('-', '_')}",
                "severity": "MEDIUM",
                "value": val,
                "description": f"'{header}' has unexpected value: {val}",
                "guidance": f"Expected: {' or '.join(required_value)}",
            })

    # Check redirects for open redirect risk
    redirects = data.get("redirects", [])
    for r in redirects:
        destination = r.get("destination", "")
        if destination.startswith("http") and ":destination" in destination:
            findings.append({
                "type": "POTENTIAL_OPEN_REDIRECT",
                "severity": "HIGH",
                "destination": destination,
                "description": "Dynamic redirect destination — potential open redirect vulnerability",
                "guidance": "Validate destination against an allowlist before redirecting",
            })

    # Check functions config
    functions = data.get("functions", {})
    for fn_pattern, fn_config in functions.items():
        memory = fn_config.get("memory", 0)
        max_duration = fn_config.get("maxDuration", 0)
        if max_duration > 300:
            findings.append({
                "type": "HIGH_FUNCTION_TIMEOUT",
                "severity": "LOW",
                "function": fn_pattern,
                "max_duration": max_duration,
                "description": f"Function '{fn_pattern}' has maxDuration={max_duration}s — risk of abuse",
                "guidance": "Keep function timeouts as short as possible",
            })

    return findings


def audit_next_config(path: str) -> list[dict]:
    findings = []
    content = read_text(path)
    if not content:
        return []

    # Check for dangerouslyAllowSVG without contentDispositionType
    if "dangerouslyAllowSVG" in content and "contentDispositionType" not in content:
        findings.append({
            "type": "DANGEROUS_SVG_WITHOUT_DISPOSITION",
            "severity": "HIGH",
            "description": "dangerouslyAllowSVG enabled without contentDispositionType — XSS risk",
            "guidance": "Add contentDispositionType: 'attachment' alongside dangerouslyAllowSVG",
        })

    # Check for disabled security features
    if "eslint" in content and "ignoreDuringBuilds" in content:
        findings.append({
            "type": "ESLINT_DISABLED_IN_BUILD",
            "severity": "MEDIUM",
            "description": "ESLint is disabled during builds — security lint rules won't run",
            "guidance": "Remove ignoreDuringBuilds: true to enforce lint rules in CI",
        })

    if "typescript" in content and "ignoreBuildErrors" in content:
        findings.append({
            "type": "TYPESCRIPT_ERRORS_IGNORED",
            "severity": "MEDIUM",
            "description": "TypeScript build errors are ignored — type safety disabled",
            "guidance": "Remove ignoreBuildErrors: true — fix TS errors instead",
        })

    # Check for exposed domains in images
    remote_patterns = re.findall(r'hostname["\s:]+["\']([^"\']+)["\']', content)
    if remote_patterns:
        findings.append({
            "type": "REMOTE_IMAGE_DOMAINS",
            "severity": "LOW",
            "domains": remote_patterns[:10],
            "description": f"Remote image domains allowed: {', '.join(remote_patterns[:3])}",
            "guidance": "Verify all allowed image domains are trusted — broad domains increase risk",
        })

    return findings


def audit_project(root: str) -> dict:
    print(f"\n=== Vercel Config Audit: {root} ===\n")
    all_findings = []
    files_checked = []

    # vercel.json
    vercel_json_path = os.path.join(root, "vercel.json")
    vercel_data = read_json(vercel_json_path)
    if vercel_data:
        files_checked.append("vercel.json")
        vf = audit_vercel_json(vercel_data)
        all_findings.extend(vf)
        print(f"  vercel.json: {len(vf)} findings")
    else:
        all_findings.append({
            "type": "NO_VERCEL_JSON",
            "severity": "MEDIUM",
            "description": "No vercel.json found — security headers not configured",
            "guidance": "Create vercel.json with headers config for security headers",
        })
        print("  vercel.json: NOT FOUND")

    # next.config.*
    for cfg_name in ["next.config.ts", "next.config.js", "next.config.mjs"]:
        cfg_path = os.path.join(root, cfg_name)
        if os.path.exists(cfg_path):
            files_checked.append(cfg_name)
            nf = audit_next_config(cfg_path)
            all_findings.extend(nf)
            print(f"  {cfg_name}: {len(nf)} findings")
            break

    # .env.production existence check
    for env_file in [".env.production", ".env"]:
        env_path = os.path.join(root, env_file)
        if os.path.exists(env_path):
            content = read_text(env_path)
            # Check for real values (not placeholders)
            real_values = [
                l for l in content.splitlines()
                if "=" in l and not l.startswith("#")
                and not any(p in l.lower() for p in ["placeholder", "example", "changeme", "todo", "<"])
                and len(l.split("=", 1)[-1].strip()) > 0
            ]
            if real_values:
                all_findings.append({
                    "type": "ENV_FILE_WITH_VALUES",
                    "severity": "HIGH",
                    "file": env_file,
                    "value_count": len(real_values),
                    "description": f"{env_file} contains {len(real_values)} non-empty values — ensure not committed",
                    "guidance": "Use Vercel Dashboard or 'vercel env add' for production secrets",
                })

    for f in all_findings:
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(f["severity"], "⚪")
        print(f"  {icon} [{f['severity']}] {f['type']}")

    return {
        "root": root,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "files_checked": files_checked,
        "findings": all_findings,
        "summary": {
            "critical": len([f for f in all_findings if f["severity"] == "CRITICAL"]),
            "high": len([f for f in all_findings if f["severity"] == "HIGH"]),
            "medium": len([f for f in all_findings if f["severity"] == "MEDIUM"]),
            "low": len([f for f in all_findings if f["severity"] == "LOW"]),
        }
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 vercel-config-audit.py <project-root>")
        sys.exit(1)

    root = os.path.abspath(sys.argv[1])
    result = audit_project(root)

    slug = os.path.basename(root)
    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    output_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{date_str}-vercel-config-audit-{slug}.json")

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    s = result["summary"]
    print(f"\n  Critical: {s['critical']} | High: {s['high']} | Medium: {s['medium']} | Low: {s['low']}")
    print(f"  Full output: {output_file}")


if __name__ == "__main__":
    main()
