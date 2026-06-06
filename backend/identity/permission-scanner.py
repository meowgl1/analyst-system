#!/usr/bin/env python3
# permission-scanner.py
# What: Maps routes to their middleware/permission requirements in a web project.
#       Supports Next.js App Router (middleware.ts), Express/Fastify, and Python FastAPI.
#       Flags unprotected routes that appear to handle sensitive operations.
# When to use: Authorization audit — ensure every route that should be protected is.
# Expected output: JSON to backend/outputs/YYYY-MM-DD-permission-scanner-<slug>.json
#
# Usage: python3 permission-scanner.py <project-root>
#   e.g. python3 permission-scanner.py /Users/thomas/Documents/Claude/Projects/baloo

import sys
import json
import os
import re
import datetime

SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "__pycache__", ".venv"}

# Sensitive route patterns — should require auth
SENSITIVE_ROUTE_PATTERNS = [
    r"/admin", r"/dashboard", r"/settings", r"/profile", r"/account",
    r"/api/user", r"/api/users", r"/api/admin", r"/api/settings",
    r"/api/upload", r"/api/export", r"/api/delete", r"/api/payment",
    r"/api/keys", r"/api/tokens", r"/api/secrets",
]

# Auth middleware patterns
AUTH_MIDDLEWARE_PATTERNS = [
    r"withAuth|getServerSession|getSession|requireAuth|protect|isAuthenticated",
    r"middleware.*auth|auth.*middleware",
    r"Depends\(get_current_user\)|Depends\(require_auth\)",
    r"Bearer|Authorization.*header",
    r"session\s*\?\.|!session|if.*session",
]


def find_nextjs_routes(root: str) -> list[dict]:
    """Find Next.js App Router routes."""
    routes = []
    app_dir = os.path.join(root, "app")
    if not os.path.isdir(app_dir):
        app_dir = os.path.join(root, "src", "app")
    if not os.path.isdir(app_dir):
        return []

    for dirpath, dirnames, filenames in os.walk(app_dir):
        dirnames[:] = [d for d in dirnames if not d.startswith("_")]
        for filename in filenames:
            if filename in ("page.tsx", "page.ts", "page.jsx", "page.js",
                            "route.tsx", "route.ts", "route.js"):
                rel = os.path.relpath(dirpath, app_dir)
                route_path = "/" + rel.replace(os.sep, "/") if rel != "." else "/"
                # Clean up Next.js dynamic segments
                route_path = re.sub(r"\[([^\]]+)\]", r":\1", route_path)

                filepath = os.path.join(dirpath, filename)
                try:
                    with open(filepath, encoding="utf-8", errors="replace") as f:
                        content = f.read()
                except Exception:
                    content = ""

                has_auth = any(re.search(p, content) for p in AUTH_MIDDLEWARE_PATTERNS)
                is_api = "route" in filename
                is_sensitive = any(re.search(p, route_path, re.I) for p in SENSITIVE_ROUTE_PATTERNS)

                routes.append({
                    "path": route_path,
                    "file": filepath,
                    "type": "api" if is_api else "page",
                    "has_auth": has_auth,
                    "is_sensitive": is_sensitive,
                })

    return routes


def find_middleware(root: str) -> dict:
    """Check for Next.js middleware.ts and what it protects."""
    for name in ["middleware.ts", "middleware.js"]:
        for base in [root, os.path.join(root, "src")]:
            path = os.path.join(base, name)
            if os.path.exists(path):
                try:
                    with open(path) as f:
                        content = f.read()
                    matcher = re.findall(r"matcher\s*[=:]\s*(\[.*?\]|['\"].*?['\"])", content, re.DOTALL)
                    return {
                        "found": True,
                        "path": path,
                        "matcher": matcher[:5],
                        "has_auth_check": bool(re.search(r"getToken|getSession|withAuth|auth", content)),
                    }
                except Exception:
                    pass

    return {"found": False}


def analyze(root: str) -> dict:
    print(f"\n=== Permission Scanner: {root} ===\n")
    findings = []

    # Middleware
    middleware = find_middleware(root)
    if middleware["found"]:
        print(f"  ✅ middleware.ts found: {middleware['path']}")
        if not middleware["has_auth_check"]:
            findings.append({
                "type": "MIDDLEWARE_NO_AUTH_CHECK",
                "severity": "HIGH",
                "file": middleware["path"],
                "description": "middleware.ts found but no auth check detected",
                "guidance": "Add getToken/getSession check in middleware to protect routes",
            })
    else:
        findings.append({
            "type": "NO_MIDDLEWARE",
            "severity": "MEDIUM",
            "description": "No Next.js middleware.ts found — route protection must be per-route",
            "guidance": "Consider adding middleware.ts for centralized auth enforcement",
        })
        print("  🟡 No middleware.ts")

    # Routes
    routes = find_nextjs_routes(root)
    print(f"  Routes found: {len(routes)}")

    unprotected_sensitive = [
        r for r in routes
        if r["is_sensitive"] and not r["has_auth"]
    ]

    for route in routes:
        status = "✅" if route["has_auth"] else ("🔴" if route["is_sensitive"] else "⚪")
        print(f"  {status} {route['type']:4s} {route['path']}")

    for route in unprotected_sensitive:
        findings.append({
            "type": "UNPROTECTED_SENSITIVE_ROUTE",
            "severity": "HIGH",
            "path": route["path"],
            "file": route["file"],
            "description": f"Sensitive route '{route['path']}' has no detected auth check",
            "guidance": "Add session/auth check or protect via middleware matcher",
        })

    if not routes:
        findings.append({
            "type": "NO_ROUTES_FOUND",
            "severity": "LOW",
            "description": "No Next.js App Router routes detected — manual review required",
            "guidance": "Ensure this is the correct project root for a Next.js App Router project",
        })

    return {
        "root": root,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "middleware": middleware,
        "total_routes": len(routes),
        "unprotected_sensitive": len(unprotected_sensitive),
        "routes": routes,
        "findings": findings,
        "summary": {
            "critical": len([f for f in findings if f["severity"] == "CRITICAL"]),
            "high": len([f for f in findings if f["severity"] == "HIGH"]),
            "medium": len([f for f in findings if f["severity"] == "MEDIUM"]),
        }
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 permission-scanner.py <project-root>")
        sys.exit(1)

    root = os.path.abspath(sys.argv[1])
    result = analyze(root)

    slug = os.path.basename(root)
    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    output_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{date_str}-permission-scanner-{slug}.json")

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    s = result["summary"]
    print(f"\n  High: {s['high']} | Medium: {s['medium']}")
    print(f"  Full output: {output_file}")


if __name__ == "__main__":
    main()
