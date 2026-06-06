#!/usr/bin/env python3
# endpoint-discovery.py
# What: Probes common API paths on a target host, catalogues status codes and response types.
# When to use: Second step in API security audit. Identifies exposed endpoints, docs, admin panels.
# Expected output: JSON to backend/outputs/YYYY-MM-DD-endpoint-discovery-<host>.json
#
# Usage: python3 endpoint-discovery.py <hostname>
#   e.g. python3 endpoint-discovery.py bagheera.mowgli.studio

import sys
import json
import urllib.request
import urllib.error
import datetime
import os

COMMON_PATHS = [
    # API versioning
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/v1",
    "/v2",
    # Documentation / schema
    "/swagger",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger-ui.html",
    "/swagger-ui",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api/docs",
    "/docs",
    "/redoc",
    "/graphql",
    "/graphiql",
    # Health / status
    "/health",
    "/healthz",
    "/health/live",
    "/health/ready",
    "/status",
    "/ping",
    "/metrics",
    "/actuator",
    "/actuator/health",
    # Admin / debug
    "/admin",
    "/admin/login",
    "/dashboard",
    "/debug",
    "/trace",
    "/env",
    "/_debug",
    "/__debug",
    "/console",
    # Sensitive files
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.git/config",
    "/.git/HEAD",
    "/robots.txt",
    "/sitemap.xml",
    "/humans.txt",
    "/security.txt",
    "/.well-known/security.txt",
    # Auth endpoints
    "/auth",
    "/auth/login",
    "/auth/token",
    "/login",
    "/logout",
    "/register",
    "/signup",
    "/oauth",
    "/oauth/token",
    "/oauth/authorize",
    # Common resources
    "/users",
    "/user",
    "/profile",
    "/account",
    "/settings",
    "/config",
    "/upload",
    "/files",
    "/media",
]

SENSITIVE_PATHS = {
    "/.env", "/.env.local", "/.env.production",
    "/.git/config", "/.git/HEAD",
    "/admin", "/admin/login", "/dashboard",
    "/debug", "/trace", "/console",
    "/actuator", "/actuator/health",
    "/metrics",
}


def probe_path(base_url: str, path: str, timeout: int = 8) -> dict:
    url = base_url.rstrip("/") + path
    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "SecurityAudit/1.0 (internal-use)")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content_type = resp.headers.get("Content-Type", "")
            content_length = resp.headers.get("Content-Length", "unknown")
            body_preview = resp.read(256).decode("utf-8", errors="replace")
            return {
                "path": path,
                "url": url,
                "status": resp.status,
                "content_type": content_type,
                "content_length": content_length,
                "body_preview": body_preview[:200],
                "sensitive": path in SENSITIVE_PATHS,
            }
    except urllib.error.HTTPError as e:
        return {
            "path": path,
            "url": url,
            "status": e.code,
            "content_type": "",
            "content_length": "0",
            "body_preview": "",
            "sensitive": path in SENSITIVE_PATHS,
        }
    except Exception as e:
        return {
            "path": path,
            "url": url,
            "status": -1,
            "error": str(e),
            "sensitive": path in SENSITIVE_PATHS,
        }


def discover_endpoints(host: str) -> dict:
    base_url = f"https://{host}"
    results = []

    print(f"\n=== Endpoint Discovery: {host} ===")
    print(f"Probing {len(COMMON_PATHS)} paths...\n")

    for path in COMMON_PATHS:
        result = probe_path(base_url, path)
        results.append(result)

        status = result.get("status", -1)
        if status in (200, 201, 202, 301, 302, 307, 308):
            flag = "⚠️  EXPOSED" if result["sensitive"] else "✅ FOUND"
            print(f"  {flag} [{status}] {path}  ({result.get('content_type', '')})")
        elif status == 403:
            print(f"  🔒 [403] {path}  (forbidden — exists but protected)")
        # 404, -1: silent

    # Findings
    exposed = [r for r in results if r.get("status", 0) in (200, 201, 202) and r.get("sensitive")]
    reachable = [r for r in results if r.get("status", 0) in (200, 201, 202)]
    server_errors = [r for r in results if r.get("status", 0) in (500, 501, 502, 503)]

    return {
        "target": host,
        "base_url": base_url,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "total_probed": len(COMMON_PATHS),
        "reachable": reachable,
        "sensitive_exposed": exposed,
        "server_errors": server_errors,
        "all_results": results,
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 endpoint-discovery.py <hostname>")
        sys.exit(1)

    host = sys.argv[1].strip().lstrip("https://").lstrip("http://").rstrip("/")
    result = discover_endpoints(host)

    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    output_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{date_str}-endpoint-discovery-{host}.json")

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n--- Summary ---")
    print(f"Reachable (2xx): {len(result['reachable'])}")
    print(f"Sensitive exposed: {len(result['sensitive_exposed'])}")
    print(f"Server errors (5xx): {len(result['server_errors'])}")
    print(f"\nFull output: {output_file}")


if __name__ == "__main__":
    main()
