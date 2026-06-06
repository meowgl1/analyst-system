#!/usr/bin/env python3
# auth-flow-analyzer.py
# What: Static analysis of a project's authentication/authorization implementation.
#       Searches for: JWT handling, session config, password hashing, RBAC patterns,
#       OAuth config, common auth anti-patterns.
# When to use: Security review of a web project's auth layer before deploy or audit.
# Expected output: JSON to backend/outputs/YYYY-MM-DD-auth-flow-analyzer-<slug>.json
#
# Usage: python3 auth-flow-analyzer.py <project-root>
#   e.g. python3 auth-flow-analyzer.py /Users/thomas/Documents/Claude/Projects/baloo

import sys
import json
import os
import re
import datetime

SCAN_EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".jsx", ".mjs"}
SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "__pycache__", ".venv", "venv"}

# Patterns for auth anti-patterns
AUTH_ANTIPATTERNS = [
    # JWT
    (r'(?i)algorithm\s*[=:]\s*["\']none["\']',
     "JWT 'none' algorithm — allows signature bypass", "CRITICAL"),
    (r'(?i)jwt\.verify\s*\([^,]+,\s*["\']["\']',
     "Empty JWT secret — any token accepted", "CRITICAL"),
    (r'(?i)ignore.*expir|expir.*ignore|verify.*\{\s*\}',
     "JWT expiration check may be disabled", "HIGH"),
    # Password
    (r'(?i)(md5|sha1)\s*\([^)]+password',
     "MD5/SHA1 used for password hashing — use bcrypt/argon2", "CRITICAL"),
    (r'(?i)password\s*==\s*|==\s*password',
     "Plain string comparison for password — use constant-time comparison", "HIGH"),
    (r'(?i)hashlib\.(md5|sha1)\s*\([^)]+\bpassword\b',
     "MD5/SHA1 password hashing in Python", "CRITICAL"),
    # Session
    (r'(?i)secret\s*[=:]\s*["\'][a-z]{1,10}["\']',
     "Weak/short session secret", "HIGH"),
    (r'(?i)session.*httponly\s*[=:]\s*false',
     "HttpOnly disabled for session cookie", "HIGH"),
    (r'(?i)session.*secure\s*[=:]\s*false',
     "Secure flag disabled for session cookie", "HIGH"),
    # Authorization
    (r'(?i)role\s*===?\s*["\']admin["\']',
     "Role check by string comparison — ensure server-side validation", "MEDIUM"),
    (r'(?i)isAdmin\s*=\s*req\.body|isAdmin\s*=\s*req\.query',
     "isAdmin set from user input — privilege escalation risk", "CRITICAL"),
    # OAuth
    (r'(?i)redirect_uri\s*[=:]\s*req\.(query|body|params)',
     "OAuth redirect_uri taken from user input — open redirect risk", "HIGH"),
    (r'(?i)state\s*parameter.*skip|skip.*state\s*parameter',
     "OAuth state parameter check may be skipped — CSRF risk", "HIGH"),
    # Misc
    (r'(?i)sql.*\+.*userid|userid.*\+.*sql',
     "Potential SQL injection in user ID lookup", "CRITICAL"),
    (r'(?i)eval\s*\(.*req\.(body|query|params)',
     "eval with user input — RCE risk", "CRITICAL"),
]

# Positive patterns to detect (good auth practices)
GOOD_PATTERNS = [
    (r'(?i)bcrypt|argon2|scrypt|pbkdf2', "Password hashing: bcrypt/argon2/scrypt"),
    (r'(?i)csrf|csurf|_csrf', "CSRF protection detected"),
    (r'(?i)rate.?limit|rateLimit|throttle', "Rate limiting detected"),
    (r'(?i)helmet|security.headers', "Security headers middleware (helmet)"),
    (r'(?i)passport|auth0|clerk|nextauth|next.auth', "Auth framework detected"),
    (r'(?i)jwt\.verify|jsonwebtoken', "JWT verification present"),
    (r'(?i)row.level.security|rls', "Row Level Security detected"),
]


def scan_file_for_auth(path: str) -> tuple[list, list]:
    """Returns (antipatterns, good_patterns) for a file."""
    found_bad = []
    found_good = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            content = f.read()
            lines = content.splitlines()
    except Exception:
        return [], []

    for pattern, description, severity in AUTH_ANTIPATTERNS:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line):
                found_bad.append({
                    "file": path,
                    "line": i,
                    "type": description,
                    "severity": severity,
                    "preview": line.strip()[:120],
                })

    for pattern, description in GOOD_PATTERNS:
        if re.search(pattern, content):
            found_good.append({"description": description, "file": path})

    return found_bad, found_good


def analyze(root: str) -> dict:
    print(f"\n=== Auth Flow Analyzer: {root} ===\n")
    all_bad = []
    all_good = []
    files_scanned = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            _, ext = os.path.splitext(filename)
            if ext.lower() not in SCAN_EXTENSIONS:
                continue
            # Prioritize auth-related files
            path = os.path.join(dirpath, filename)
            bad, good = scan_file_for_auth(path)
            all_bad.extend(bad)
            all_good.extend(good)
            files_scanned += 1

    # Deduplicate good patterns by description
    good_unique = list({g["description"]: g for g in all_good}.values())

    print(f"  Files scanned: {files_scanned}")
    print(f"\n  Auth mechanisms found:")
    for g in good_unique:
        print(f"  ✅ {g['description']}")

    if not good_unique:
        print("  ⚠️  No known auth framework detected")
        all_bad.append({
            "type": "NO_AUTH_FRAMEWORK_DETECTED",
            "severity": "MEDIUM",
            "description": "No recognized auth library/pattern found — manual review required",
            "guidance": "Consider using established auth frameworks: NextAuth, Clerk, Auth0, Passport",
        })

    print(f"\n  Anti-patterns found: {len(all_bad)}")
    for f in all_bad[:10]:
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(f["severity"], "⚪")
        rel = os.path.relpath(f.get("file", ""), root)
        print(f"  {icon} [{f['severity']}] {f['type']} — {rel}:{f.get('line', '')}")

    return {
        "root": root,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "files_scanned": files_scanned,
        "auth_mechanisms": good_unique,
        "antipatterns": all_bad,
        "summary": {
            "critical": len([f for f in all_bad if f["severity"] == "CRITICAL"]),
            "high": len([f for f in all_bad if f["severity"] == "HIGH"]),
            "medium": len([f for f in all_bad if f["severity"] == "MEDIUM"]),
        }
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 auth-flow-analyzer.py <project-root>")
        sys.exit(1)

    root = os.path.abspath(sys.argv[1])
    result = analyze(root)

    slug = os.path.basename(root)
    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    output_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{date_str}-auth-flow-analyzer-{slug}.json")

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    s = result["summary"]
    print(f"\n  Critical: {s['critical']} | High: {s['high']} | Medium: {s['medium']}")
    print(f"  Full output: {output_file}")


if __name__ == "__main__":
    main()
