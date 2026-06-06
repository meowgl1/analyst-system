#!/usr/bin/env python3
# rate-limit-test.py
# What: Sends a burst of requests to detect rate limiting on an API endpoint.
# When to use: Fourth step in API audit. Missing rate limiting enables brute force and DoS.
# Expected output: JSON to backend/outputs/YYYY-MM-DD-rate-limit-<host>.json
#
# Usage: python3 rate-limit-test.py <hostname> [--requests N] [--path /api/v1/...]
#   e.g. python3 rate-limit-test.py bagheera.mowgli.studio
#   e.g. python3 rate-limit-test.py bagheera.mowgli.studio --requests 30 --path /api/v1/login
#
# NOTE: Sends max 30 requests by default. Intentionally conservative to avoid DoS.

import sys
import json
import urllib.request
import urllib.error
import datetime
import os
import time

DEFAULT_PATHS_TO_TEST = [
    "/",
    "/api",
    "/api/v1",
    "/health",
    "/api/v1/login",
    "/login",
    "/auth/token",
]
DEFAULT_BURST = 20
MAX_BURST = 30  # hard limit — never exceed to avoid DoS


def burst_test(base_url: str, path: str, n_requests: int, timeout: int = 5) -> dict:
    url = base_url.rstrip("/") + path
    responses = []
    start_time = time.time()

    for i in range(n_requests):
        req_start = time.time()
        try:
            req = urllib.request.Request(url, method="GET")
            req.add_header("User-Agent", "SecurityAudit/1.0 (internal-use)")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                headers = dict(resp.headers)
                elapsed = time.time() - req_start
                responses.append({
                    "request_num": i + 1,
                    "status": resp.status,
                    "elapsed_ms": round(elapsed * 1000),
                    "rate_limit_remaining": headers.get("X-RateLimit-Remaining") or headers.get("x-ratelimit-remaining"),
                    "retry_after": headers.get("Retry-After") or headers.get("retry-after"),
                    "x_ratelimit_limit": headers.get("X-RateLimit-Limit") or headers.get("x-ratelimit-limit"),
                })
        except urllib.error.HTTPError as e:
            elapsed = time.time() - req_start
            responses.append({
                "request_num": i + 1,
                "status": e.code,
                "elapsed_ms": round(elapsed * 1000),
                "rate_limit_remaining": None,
                "retry_after": None,
            })
            if e.code == 429:
                break  # rate limit hit — no need to continue
        except Exception as e:
            responses.append({
                "request_num": i + 1,
                "status": -1,
                "error": str(e),
                "elapsed_ms": 0,
            })

    total_elapsed = time.time() - start_time
    status_codes = [r["status"] for r in responses]
    rate_limited = 429 in status_codes
    first_429 = next((r["request_num"] for r in responses if r["status"] == 429), None)

    return {
        "path": path,
        "url": url,
        "requests_sent": len(responses),
        "total_elapsed_ms": round(total_elapsed * 1000),
        "rate_limited": rate_limited,
        "first_429_at_request": first_429,
        "status_distribution": {str(k): status_codes.count(k) for k in set(status_codes)},
        "responses": responses,
    }


def run_rate_limit_test(host: str, burst: int = DEFAULT_BURST, path: str = None) -> dict:
    base_url = f"https://{host}"
    burst = min(burst, MAX_BURST)
    paths = [path] if path else DEFAULT_PATHS_TO_TEST

    print(f"\n=== Rate Limit Test: {host} ===")
    print(f"Sending {burst} requests per endpoint (max {MAX_BURST})\n")

    results = []
    for p in paths:
        print(f"  Testing {p}...", end=" ", flush=True)
        result = burst_test(base_url, p, burst)
        results.append(result)
        if result["rate_limited"]:
            print(f"✅ Rate limited at request #{result['first_429_at_request']}")
        else:
            first_status = result["responses"][0]["status"] if result["responses"] else -1
            if first_status == 404:
                print(f"⚪ 404 (endpoint not found)")
            else:
                print(f"🟠 NO rate limit detected ({burst} requests, all returned {first_status})")

    no_limit = [r for r in results if not r["rate_limited"] and r["responses"] and r["responses"][0]["status"] not in (404, -1)]
    has_limit = [r for r in results if r["rate_limited"]]

    return {
        "target": host,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "burst_size": burst,
        "paths_tested": len(paths),
        "rate_limited_paths": len(has_limit),
        "unprotected_paths": len(no_limit),
        "unprotected_details": no_limit,
        "all_results": results,
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 rate-limit-test.py <hostname> [--requests N] [--path /path]")
        sys.exit(1)

    host = sys.argv[1].strip().lstrip("https://").lstrip("http://").rstrip("/")
    burst = DEFAULT_BURST
    path = None

    args = sys.argv[2:]
    for i, arg in enumerate(args):
        if arg == "--requests" and i + 1 < len(args):
            burst = min(int(args[i + 1]), MAX_BURST)
        elif arg == "--path" and i + 1 < len(args):
            path = args[i + 1]

    result = run_rate_limit_test(host, burst, path)

    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    output_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{date_str}-rate-limit-{host}.json")

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n--- Summary ---")
    unprotected = result["unprotected_paths"]
    if unprotected > 0:
        print(f"  🟠 {unprotected} endpoint(s) without rate limiting")
    else:
        print(f"  ✅ All reachable endpoints are rate limited")
    print(f"\nFull output: {output_file}")


if __name__ == "__main__":
    main()
