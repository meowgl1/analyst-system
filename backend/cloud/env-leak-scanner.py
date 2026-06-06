#!/usr/bin/env python3
# env-leak-scanner.py
# What: Scans a project directory for credential and secret leaks.
#       Checks: .env files, hardcoded API keys/tokens in source code,
#       committed secrets, git history (shallow check), insecure config patterns.
# When to use: Before any deployment or when auditing a project for secrets exposure.
# Expected output: JSON to backend/outputs/YYYY-MM-DD-env-leak-scanner-<slug>.json
#
# Usage: python3 env-leak-scanner.py <project-root>
#   e.g. python3 env-leak-scanner.py /Users/thomas/Documents/Claude/Projects/baloo

import sys
import json
import os
import re
import subprocess
import datetime

# Secret patterns to search in source files
SECRET_PATTERNS = [
    # Generic high-entropy tokens
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?',
     "API key", "CRITICAL"),
    (r'(?i)(secret[_-]?key|secret)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?',
     "Secret key", "CRITICAL"),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{8,})["\']?',
     "Hardcoded password", "CRITICAL"),
    (r'(?i)(access[_-]?token|auth[_-]?token)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{20,})["\']?',
     "Auth token", "CRITICAL"),
    # Provider-specific
    (r'(?i)sk-[A-Za-z0-9]{20,}', "OpenAI API key", "CRITICAL"),
    (r'(?i)AKIA[A-Z0-9]{16}', "AWS Access Key ID", "CRITICAL"),
    (r'(?i)ghp_[A-Za-z0-9]{36}', "GitHub Personal Access Token", "CRITICAL"),
    (r'(?i)xoxb-[A-Za-z0-9\-]+', "Slack Bot Token", "CRITICAL"),
    (r'(?i)ya29\.[A-Za-z0-9_\-]+', "Google OAuth Token", "CRITICAL"),
    (r'(?i)eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}',
     "JWT token (may be sensitive)", "HIGH"),
    # DB connection strings
    (r'(?i)(postgresql|mysql|mongodb)://[^@\s]+:[^@\s]+@',
     "Database connection string with credentials", "CRITICAL"),
    (r'(?i)redis://:[^@\s]+@',
     "Redis connection string with password", "HIGH"),
]

# File extensions to scan
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".env", ".yaml", ".yml",
    ".json", ".toml", ".ini", ".conf", ".config", ".sh", ".bash",
    ".rb", ".go", ".java", ".php", ".cs",
}

# Files to always skip
SKIP_DIRS = {
    "node_modules", ".git", ".next", ".nuxt", "dist", "build",
    "__pycache__", ".venv", "venv", "vendor",
}
SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
}

# .env files that should not exist in the repo
ENV_PATTERNS = [".env", ".env.local", ".env.production", ".env.development"]


def scan_file(path: str) -> list[dict]:
    """Scan a single file for secret patterns."""
    findings = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            content = f.read()
            lines = content.splitlines()
    except Exception:
        return []

    for pattern, description, severity in SECRET_PATTERNS:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line):
                # Avoid flagging obvious placeholders
                if any(p in line.lower() for p in ["example", "placeholder", "your_", "<", "xxx", "todo", "changeme"]):
                    continue
                findings.append({
                    "file": path,
                    "line": i,
                    "type": description,
                    "severity": severity,
                    "line_preview": line.strip()[:120],
                })

    return findings


def check_gitignore(root: str) -> list[dict]:
    """Check that sensitive files are gitignored."""
    issues = []
    gitignore_path = os.path.join(root, ".gitignore")
    gitignore_content = ""
    if os.path.exists(gitignore_path):
        with open(gitignore_path) as f:
            gitignore_content = f.read()

    for pattern in ENV_PATTERNS:
        if not any(pattern.replace(".", "\\.") in gitignore_content or pattern in gitignore_content
                   for _ in [1]):
            if os.path.exists(os.path.join(root, pattern)):
                issues.append({
                    "type": "ENV_FILE_NOT_GITIGNORED",
                    "severity": "HIGH",
                    "file": pattern,
                    "description": f"{pattern} exists but may not be in .gitignore",
                    "guidance": f"Add {pattern} to .gitignore immediately",
                })

    return issues


def check_git_history(root: str) -> list[dict]:
    """Shallow check of recent git commits for secret-looking content."""
    findings = []
    try:
        result = subprocess.run(
            ["git", "-C", root, "log", "--oneline", "-20", "--all"],
            capture_output=True, text=True, timeout=10
        )
        commits = result.stdout.strip().splitlines()
        if not commits:
            return []

        # Check commit messages for accidental secret hints
        for commit in commits:
            msg = commit.lower()
            if any(kw in msg for kw in ["secret", "password", "credential", "api key", "token", "remove key"]):
                findings.append({
                    "type": "SUSPICIOUS_COMMIT_MESSAGE",
                    "severity": "MEDIUM",
                    "commit": commit,
                    "description": "Commit message suggests a secret may have been committed or removed",
                    "guidance": "Check this commit and rotate any secrets that may have been exposed",
                })
    except Exception:
        pass

    return findings


def scan_project(root: str) -> dict:
    print(f"\n=== Env Leak Scanner: {root} ===\n")
    all_findings = []
    files_scanned = 0

    # Check gitignore
    gitignore_issues = check_gitignore(root)
    all_findings.extend(gitignore_issues)

    # Check git history
    git_findings = check_git_history(root)
    all_findings.extend(git_findings)

    # Walk directory and scan files
    for dirpath, dirnames, filenames in os.walk(root):
        # Skip unwanted dirs
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        for filename in filenames:
            if filename in SKIP_FILES:
                continue
            _, ext = os.path.splitext(filename)
            if ext.lower() not in SCAN_EXTENSIONS and filename not in ENV_PATTERNS:
                continue

            filepath = os.path.join(dirpath, filename)
            file_findings = scan_file(filepath)
            all_findings.extend(file_findings)
            files_scanned += 1

    # Deduplicate
    seen = set()
    unique = []
    for f in all_findings:
        key = (f.get("file", ""), f.get("line", 0), f.get("type", ""))
        if key not in seen:
            seen.add(key)
            unique.append(f)

    critical = [f for f in unique if f["severity"] == "CRITICAL"]
    high = [f for f in unique if f["severity"] == "HIGH"]

    print(f"  Files scanned: {files_scanned}")
    print(f"  Findings: {len(unique)} ({len(critical)} critical, {len(high)} high)")
    for f in unique[:10]:
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(f["severity"], "⚪")
        loc = f"{os.path.relpath(f.get('file', ''), root)}:{f.get('line', '')}"
        print(f"  {icon} [{f['severity']}] {f['type']} → {loc}")
    if len(unique) > 10:
        print(f"  ... and {len(unique) - 10} more")

    return {
        "root": root,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "files_scanned": files_scanned,
        "total_findings": len(unique),
        "findings": unique,
        "summary": {
            "critical": len(critical),
            "high": len(high),
            "medium": len([f for f in unique if f.get("severity") == "MEDIUM"]),
        }
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 env-leak-scanner.py <project-root>")
        sys.exit(1)

    root = os.path.abspath(sys.argv[1])
    if not os.path.isdir(root):
        print(f"Error: {root} is not a directory")
        sys.exit(1)

    result = scan_project(root)

    slug = os.path.basename(root)
    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    output_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{date_str}-env-leak-scanner-{slug}.json")

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n  Full output: {output_file}")


if __name__ == "__main__":
    main()
