#!/usr/bin/env python3
# form-scanner.py
# What: Crawls a web page, finds all forms and inputs, checks for CSRF tokens and security flags.
# When to use: Second step in web security audit. Identifies attack surface for CSRF and XSS.
# Expected output: JSON to backend/outputs/YYYY-MM-DD-form-scanner-<host>.json
#
# Usage: python3 form-scanner.py <hostname>
#   e.g. python3 form-scanner.py mowgli.studio

import sys
import json
import urllib.request
import urllib.error
import html.parser
import datetime
import os
import re

CSRF_TOKEN_NAMES = {
    "csrf", "csrftoken", "_csrf", "_token", "csrf_token", "authenticity_token",
    "token", "nonce", "__requestverificationtoken", "x-csrf-token",
}


class FormParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self._current_form = None
        self._links = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "form":
            self._current_form = {
                "action": attrs_dict.get("action", ""),
                "method": attrs_dict.get("method", "GET").upper(),
                "inputs": [],
                "has_csrf_token": False,
                "enctype": attrs_dict.get("enctype", ""),
            }
        elif tag == "input" and self._current_form is not None:
            input_info = {
                "type": attrs_dict.get("type", "text"),
                "name": attrs_dict.get("name", ""),
                "id": attrs_dict.get("id", ""),
                "autocomplete": attrs_dict.get("autocomplete", ""),
                "required": "required" in attrs_dict,
            }
            self._current_form["inputs"].append(input_info)

            # Check if this looks like a CSRF token
            name_lower = input_info["name"].lower()
            id_lower = input_info["id"].lower()
            if (name_lower in CSRF_TOKEN_NAMES or id_lower in CSRF_TOKEN_NAMES
                    or input_info["type"] == "hidden"):
                if any(t in name_lower or t in id_lower for t in CSRF_TOKEN_NAMES):
                    self._current_form["has_csrf_token"] = True

        elif tag == "a":
            href = attrs_dict.get("href", "")
            if href and not href.startswith("#") and not href.startswith("javascript:"):
                self._links.append(href)

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def fetch_html(url: str, timeout: int = 10) -> str:
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "SecurityAudit/1.0 (internal-use)")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content_type = resp.headers.get("Content-Type", "")
            if "html" not in content_type.lower():
                return ""
            return resp.read(500_000).decode("utf-8", errors="replace")
    except Exception:
        return ""


def is_same_origin(base_host: str, url: str) -> bool:
    if url.startswith("/"):
        return True
    return base_host in url


def scan_forms(host: str) -> dict:
    base_url = f"https://{host}"
    pages_to_scan = [base_url]
    scanned_pages = set()
    all_forms = []
    findings = []

    print(f"\n=== Form Scanner: {host} ===")

    for page_url in pages_to_scan[:5]:  # limit to 5 pages
        if page_url in scanned_pages:
            continue
        scanned_pages.add(page_url)

        print(f"  Scanning: {page_url}")
        html_content = fetch_html(page_url)
        if not html_content:
            continue

        parser = FormParser()
        parser.feed(html_content)

        # Check for HTTP forms on HTTPS pages (mixed content)
        http_form_actions = [
            f for f in parser.forms
            if f.get("action", "").startswith("http://")
        ]

        for form in parser.forms:
            form["page_url"] = page_url
            all_forms.append(form)

            # Flag POST forms without CSRF token
            if form["method"] == "POST" and not form["has_csrf_token"]:
                findings.append({
                    "type": "MISSING_CSRF_TOKEN",
                    "severity": "HIGH",
                    "page": page_url,
                    "form_action": form["action"],
                    "form_method": form["method"],
                    "description": "POST form without visible CSRF token",
                    "guidance": "Add a CSRF token to all state-changing forms",
                })

            # Flag HTTP form actions on HTTPS page
            if form.get("action", "").startswith("http://"):
                findings.append({
                    "type": "FORM_ACTION_HTTP",
                    "severity": "HIGH",
                    "page": page_url,
                    "form_action": form["action"],
                    "description": "Form submits to HTTP endpoint (credential exposure risk)",
                    "guidance": "Change form action to HTTPS",
                })

            # Flag password fields without autocomplete=off
            for inp in form["inputs"]:
                if inp["type"] == "password" and inp.get("autocomplete") not in ("off", "new-password", "current-password"):
                    findings.append({
                        "type": "PASSWORD_AUTOCOMPLETE",
                        "severity": "LOW",
                        "page": page_url,
                        "input_name": inp.get("name", ""),
                        "description": "Password field without explicit autocomplete attribute",
                        "guidance": "Set autocomplete='current-password' or 'new-password'",
                    })

        # Add same-origin links for next-level crawl
        for link in parser._links:
            if link.startswith("/"):
                full_url = base_url + link
                if full_url not in scanned_pages and len(pages_to_scan) < 10:
                    pages_to_scan.append(full_url)
            elif is_same_origin(host, link):
                if link not in scanned_pages and len(pages_to_scan) < 10:
                    pages_to_scan.append(link)

    # Check for mixed HTTP content in any forms
    post_forms = [f for f in all_forms if f["method"] == "POST"]
    login_forms = [f for f in all_forms if any(
        inp["type"] in ("password",) or "login" in inp.get("name", "").lower()
        for inp in f["inputs"]
    )]

    print(f"  Found {len(all_forms)} form(s) across {len(scanned_pages)} page(s)")

    return {
        "target": host,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "pages_scanned": list(scanned_pages),
        "total_forms": len(all_forms),
        "post_forms": len(post_forms),
        "login_forms": len(login_forms),
        "findings": findings,
        "form_inventory": all_forms,
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 form-scanner.py <hostname>")
        sys.exit(1)

    host = sys.argv[1].strip().lstrip("https://").lstrip("http://").rstrip("/")
    result = scan_forms(host)

    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    output_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{date_str}-form-scanner-{host}.json")

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n--- Summary ---")
    print(f"  Forms found: {result['total_forms']}")
    print(f"  POST forms: {result['post_forms']}")
    print(f"  Login forms: {result['login_forms']}")
    for f in result["findings"]:
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(f["severity"], "⚪")
        print(f"  {icon} [{f['severity']}] {f['type']}: {f['page']}")
    print(f"\nFull output: {output_file}")


if __name__ == "__main__":
    main()
