#!/usr/bin/env python3
# auth-probe.py
# What: Tests likely-protected API endpoints without authentication.
# Flags any 200 responses on routes that should require auth — potential auth bypass.
# When to use: Third step in API audit. Run after endpoint-discovery to focus on auth gaps.
# Expected output: JSON to backend/outputs/YYYY-MM-DD-auth-probe-<host>.json
#
# Usage: python3 auth-probe.py <hostname>
#   e.g. python3 auth-probe.py bagheera.mowgli.studio

import sys
import json
import urllib.request
import urllib.error
import datetime
import os

# Paths that should require authentication
PROTECTED_PATHS = [
    # User data
    "/api/v1/users",
    "/api/v1/user",
    "/api/v1/profile",
    "/api/v1/me",
    "/api/v1/account",
    "/api/users",
    "/api/user",
    "/api/profile",
    "/api/me",
    "/users",
    "/user",
    "/profile",
    "/me",
    "/account",
    # Admin
    "/api/v1/admin",
    "/api/admin",
    "/admin",
    "/api/v1/dashboard",
    "/dashboard",
    # Sensitive operations
    "/api/v1/settings",
    "/api/v1/config",
    "/api/settings",
    "/settings",
    "/api/v1/keys",
    "/api/keys",
    "/api/v1/tokens",
    "/api/tokens",
    "/api/v1/secrets",
    # Data endpoints
    "/api/v1/data",
    "/api/data",
    "/api/v1/export",
    "/api/export",
    "/api/v1/analytics",
    "/api/analytics",
    # Internal
    "/internal",
    "/api/internal",
    "/_internal",
    "/api/v1/internal",
]


def probe_without_auth(base_url: str, path: str, timeout: int = 8) -> dict:
    url = base_url.rstrip("/") + path
    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "SecurityAudit/1.0 (internal-use)")
        # Explicitly NO Authorization header
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content_type = resp.headers.get("Content-Type", "")
            body = resp.read(512).decode("utf-8", errors="replace")
            return {
                "path": path,
                "url": url,
                "status": resp.status,
                "content_type": content_type,
                "body_preview": body[:300],
                "auth_bypassed": resp.status in (200, 201, 202),
            }
    except urllib.error.HTTPError as e:
        return {
            "path": path,
            "url": url,
            "status": e.code,
            "auth_bypassed": False,
            "expected": e.code in (401, 403),
        }
    except Exception as e:
        return {
            "path": path,
            "url": url,
            "status": -1,
            "error": str(e),
            "auth_bypassed": False,
        }


def run_probe(host: str) -> dict:
    base_url = f"https://{host}"
    results = []

    print(f"\n=== Auth Bypass Probe: {host} ===")
    print(f"Testing {len(PROTECTED_PATHS)} protected paths without auth...\n")

    for path in PROTECTED_PATHS:
        result = probe_without_auth(base_url, path)
        results.append(result)

        status = result.get("status", -1)
        if result.get("auth_bypassed"):
            print(f"  🔴 BYPASS [{status}] {path}  ← should require auth!")
        elif status == 403:
            print(f"  🔒 [403] {path}  (forbidden — auth enforced)")
        elif status == 401:
            print(f"  ✅ [401] {path}  (unauthorized — correct behavior)")
        # 404, -1: silent

    bypassed = [r for r in results if r.get("auth_bypassed")]
    properly_protected = [r for r in results if r.get("status") in (401, 403)]

    return {
        "target": host,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "total_tested": len(PROTECTED_PATHS),
        "auth_bypassed": bypassed,
        "properly_protected": len(properly_protected),
        "all_results": results,
        "summary": {
            "critical_bypasses": len(bypassed),
            "protected_count": len(properly_protected),
        },
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 auth-probe.py <hostname>")
        sys.exit(1)

    host = sys.argv[1].strip().lstrip("https://").lstrip("http://").rstrip("/")
    result = run_probe(host)

    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    output_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{date_str}-auth-probe-{host}.json")

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n--- Summary ---")
    bypasses = result["summary"]["critical_bypasses"]
    if bypasses > 0:
        print(f"  🔴 {bypasses} potential auth bypass(es) found!")
    else:
        print(f"  ✅ No auth bypasses detected")
    print(f"  Protected: {result['summary']['protected_count']}")
    print(f"\nFull output: {output_file}")


if __name__ == "__main__":
    main()
