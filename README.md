# Analyst-system

> **A multi-agent security analysis platform built on Claude Code.**  
> 11 specialized agents · 27 Python backend scripts · 8 security departments · 754 cybersecurity skills

[![Claude Code](https://img.shields.io/badge/Built%20with-Claude%20Code-6B5CF6?style=flat-square)](https://claude.ai/code)
[![Skills](https://img.shields.io/badge/Cybersecurity%20Skills-754-0EA5E9?style=flat-square)](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)
[![Python](https://img.shields.io/badge/Python-3%20stdlib%20only-3776AB?style=flat-square)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=flat-square)](LICENSE)

---

## Overview

Analyst-system is a personal security operations platform that orchestrates specialized AI agents for on-demand security analysis. Built as a portfolio project under [Mowgli Studio](https://mowgli.studio), it demonstrates how Claude Code's multi-agent architecture can be applied to real-world security workflows: forensic triage, threat intelligence, dependency auditing, identity analysis, and live service testing.

### Design principles

| Principle | Implementation |
|---|---|
| **Read-only by default** | No agent executes destructive operations; all findings require human approval before remediation |
| **Evidence-first** | Every finding cites the exact command, script, and raw output that produced it |
| **Severity-ranked output** | Every report ranks findings Critical / High / Medium / Low |
| **Persistent reports** | All outputs go to versioned folders — never printed and lost |
| **Skill-augmented** | 754 domain-specific cybersecurity skills available on-demand via a librarian agent |

---

## Agent network

```
analyst (global orchestrator)
├── cybersecurity ──── api-security-tester
│                  └── web-security-scanner
├── forensics ──────── forensic-analyst
├── network ────────── network-analyst
├── threat-intel ───── threat-hunter
├── cloud ──────────── cloud-auditor
├── identity ───────── identity-auditor
├── dependency-audit ── dependency-auditor
└── requirements ───── requirements-validator
```

### Agent reference

| Agent | Department | Purpose |
|---|---|---|
| `analyst` | Global | Orchestrates all departments based on goal — `full`, `external`, `local`, `pre-deploy`, `project` |
| `cybersecurity` | cybersecurity | Department orchestrator — runs API + web security scans in parallel |
| `api-security-tester` | cybersecurity | Unauthenticated API audit: headers, auth bypass, rate limiting, endpoint discovery |
| `web-security-scanner` | cybersecurity | Web security audit: cookies, CSP, forms, security headers |
| `forensic-analyst` | forensics | macOS triage: persistence mechanisms, active processes, log analysis, binary verification |
| `network-analyst` | network | DNS enumeration, port profiling, active connection snapshot, anomaly detection |
| `threat-hunter` | threat-intel | IoC correlation (OTX/AbuseIPDB/VirusTotal), MITRE ATT&CK mapping, passive OSINT |
| `cloud-auditor` | cloud | Dockerfile security, env variable leak scanning, Vercel/Next.js config audit |
| `identity-auditor` | identity | Auth flow analysis: JWT anti-patterns, password hashing, unprotected routes, RBAC gaps |
| `dependency-auditor` | dependency-audit | Package and lockfile CVE audit — returns GO / NO-GO / REVIEW verdict |
| `requirements-validator` | requirements | Spec coherence review using Speckit: completeness, ambiguity, calculation errors |

### Orchestrator activation matrix

| Mode | Departments activated | When to use |
|---|---|---|
| `full` | all 7 departments | Comprehensive posture review |
| `external` | cybersecurity + network + threat-intel | Attack surface audit from outside |
| `local` | forensics + identity | Incident investigation on the local machine |
| `pre-deploy` | cybersecurity + cloud + dependency-audit | Pre-release security gate |
| `project` | requirements + dependency-audit + identity | New project review before build |

---

## Quick start

```bash
# Full security posture review
> Use analyst for a full posture review

# External attack surface audit
> Use analyst for an external audit of mowgli.studio

# Pre-deploy check
> Use analyst for a pre-deploy check on /path/to/project

# Single department — forensics
> Use forensic-analyst to run a full triage

# Single script — DNS enumeration
python3 backend/network/dns-enum.py mowgli.studio

# Check a package before installing
python3 backend/dependency-audit/package-analyzer.py lodash --registry npm

# Verify a binary's code signing
python3 backend/forensics/binary-verifier.py /Applications/SomeApp.app

# Aggregate JSON outputs into a markdown report
python3 backend/tools/report-builder.py --inputs "backend/outputs/2026-06-08-*.json" --output security-audits/2026-06-08-analyst-report.md
```

---

## Backend scripts (27 total)

All scripts: Python 3 · stdlib only · no pip install · read-only · JSON output.

### cybersecurity — api (4 scripts)

| Script | Input | Purpose |
|---|---|---|
| `backend/api/auth-probe.py` | `<host>` | Test unauthenticated access to protected endpoints |
| `backend/api/endpoint-discovery.py` | `<host>` | Discover API endpoints via common paths |
| `backend/api/header-audit.py` | `<host>` | Check security headers on API responses |
| `backend/api/rate-limit-test.py` | `<host>` | Test rate limiting and throttling behavior |

### cybersecurity — web (4 scripts)

| Script | Input | Purpose |
|---|---|---|
| `backend/web/cookie-audit.py` | `<url>` | Cookie flags: HttpOnly, Secure, SameSite |
| `backend/web/csp-analyzer.py` | `<url>` | Content-Security-Policy analysis and gap detection |
| `backend/web/form-scanner.py` | `<url>` | Form security: CSRF tokens, autocomplete, encoding |
| `backend/web/security-headers.py` | `<url>` | Full HTTP security headers audit |

### network (3 scripts)

| Script | Input | Purpose |
|---|---|---|
| `backend/network/dns-enum.py` | `<domain>` | DNS records, SPF/DMARC validation, zone transfer attempt |
| `backend/network/port-profiler.py` | `<host>` | Port profiling, service detection, suspicious port flagging |
| `backend/network/connection-monitor.py` | — | Snapshot active TCP connections grouped by process |

### threat-intel (3 scripts)

| Script | Input | Purpose |
|---|---|---|
| `backend/threat-intel/ioc-checker.py` | `<ip\|domain\|sha256>` | IoC lookup against OTX, URLhaus, AbuseIPDB, VirusTotal |
| `backend/threat-intel/osint-domain.py` | `<domain>` | Passive OSINT: WHOIS, crt.sh, robots.txt, headers |
| `backend/threat-intel/mitre-mapper.py` | `<findings.json>` | Map audit findings to MITRE ATT&CK techniques |

### cloud (3 scripts)

| Script | Input | Purpose |
|---|---|---|
| `backend/cloud/dockerfile-audit.py` | `<dockerfile>` | USER privilege, base image CVEs, hardcoded secrets, suspicious RUN |
| `backend/cloud/env-leak-scanner.py` | `<project-root>` | Secrets in code, .env files committed, git history scan |
| `backend/cloud/vercel-config-audit.py` | `<project-root>` | vercel.json, next.config, open redirects, header misconfigurations |

### identity (2 scripts)

| Script | Input | Purpose |
|---|---|---|
| `backend/identity/auth-flow-analyzer.py` | `<project-root>` | JWT anti-patterns, weak hashing algorithms, session config |
| `backend/identity/permission-scanner.py` | `<project-root>` | Route → auth protection map for Next.js App Router |

### forensics (3 scripts)

| Script | Input | Purpose |
|---|---|---|
| `backend/forensics/persistence-scanner.py` | — | LaunchAgents, daemons, login items, crontab entries |
| `backend/forensics/binary-verifier.py` | `<path>` | Code signing, notarization status, hash, IoC string scan |
| `backend/forensics/log-analyzer.py` | `[--hours N]` | Auth failures, sudo events, crashes, malware indicators in system logs |

### dependency-audit (2 scripts)

| Script | Input | Purpose |
|---|---|---|
| `backend/dependency-audit/package-analyzer.py` | `<pkg> [--registry npm\|pypi]` | CVE lookup, maintainer reputation, install script audit |
| `backend/dependency-audit/lockfile-auditor.py` | `<lockfile>` | Bulk CVE scan of `package-lock.json` or `requirements.txt` |

### tools (1 shared utility)

| Script | Input | Purpose |
|---|---|---|
| `backend/tools/report-builder.py` | `--inputs <glob> --output <path.md>` | Aggregate JSON outputs from multiple scripts into a single markdown report |

---

## Architecture

```
Analyst-system/
├── .studio/
│   ├── agents/                  # Agent definitions — source of truth
│   │   ├── analyst.md           # Global orchestrator
│   │   ├── cybersecurity/       # API + web security (3 agents)
│   │   ├── forensics/           # macOS forensic triage
│   │   ├── network/             # DNS, ports, connections
│   │   ├── threat-intel/        # IoC, MITRE ATT&CK, OSINT
│   │   ├── cloud/               # Dockerfile, env, Vercel config
│   │   ├── identity/            # Auth flows, route permissions
│   │   ├── dependency-audit/    # Package CVE audit
│   │   └── requirements/        # Spec validation
│   └── skills/librarian/        # Skill router for 754 cybersecurity skills
│       ├── SKILL.md             # Routing instructions
│       ├── skills-index.json    # Pre-computed index (452KB, 30 subdomains)
│       └── library/             # Symlink → .agents/skills/
│
├── .claude/
│   ├── agents/                  # Symlinks → .studio/agents/ (Claude Code discovery)
│   └── settings.json            # Tool permissions
│
├── .agents/skills/              # 754 cybersecurity skills — never move
│
├── app/                         # Next.js 15 dashboard — report viewer (port 3001)
│
├── backend/                     # Python scripts (stdlib only, read-only)
│   ├── api/, web/               # Cybersecurity scripts
│   ├── network/                 # Network analysis scripts
│   ├── threat-intel/            # Threat intelligence scripts
│   ├── cloud/                   # Cloud/config audit scripts
│   ├── identity/                # Identity & permissions scripts
│   ├── forensics/               # macOS forensics scripts
│   ├── dependency-audit/        # Dependency audit scripts
│   ├── tools/                   # Shared utilities
│   └── outputs/                 # JSON outputs (gitignored)
│
├── security-audits/             # Markdown reports (gitignored except top-level)
├── forensic-reports/            # macOS triage reports (gitignored)
└── dependency-audits/           # Dependency audit outputs (gitignored)
```

---

## Cybersecurity skill library

754 domain-specific skills across 30 subdomains, aligned to NIST CSF. Always route through the **librarian** — never load skills directly.

```
> Find skills for API gateway log analysis
> Which skill handles Cobalt Strike detection?
> Skills for NIST DE.CM-01
> Find malware analysis skills
```

| Subdomain | Skills | Subdomain | Skills |
|---|---|---|---|
| cloud-security | 63 | threat-hunting | 56 |
| threat-intelligence | 50 | network-security | 43 |
| web-application-security | 42 | malware-analysis | 39 |
| digital-forensics | 37 | soc-operations | 33 |
| identity-access-management | 33 | container-security | 29 |
| api-security | 28 | incident-response | 26 |
| vulnerability-management | 25 | red-teaming | 24 |
| penetration-testing | 20 | zero-trust-architecture | 17 |
| endpoint-security | 17 | devsecops | 17 |
| phishing-defense | 15 | cryptography | 15 |
| ransomware-defense | 13 | mobile-security | 13 |

---

## Output folders

| Folder | Contents | Versioned |
|---|---|---|
| `security-audits/` | Executive reports from `analyst` | Yes |
| `security-audits/api/` | API security reports | Gitignored |
| `security-audits/web/` | Web security reports | Gitignored |
| `security-audits/network/` | Network audit reports | Gitignored |
| `security-audits/threat-intel/` | Threat intelligence reports | Gitignored |
| `security-audits/cloud/` | Cloud/config audit reports | Gitignored |
| `security-audits/identity/` | Auth/permissions reports | Gitignored |
| `backend/outputs/` | Raw JSON from scripts | Gitignored |
| `forensic-reports/` | macOS triage reports | Gitignored |
| `dependency-audits/` | Dependency audit outputs | Gitignored |

---

## Severity schema

| Level | Meaning |
|---|---|
| **CRITICAL** | Confirmed compromise, active exfiltration, or secret exposed in production |
| **HIGH** | Exploitable vulnerability, serious misconfiguration, or CVE affecting the current version |
| **MEDIUM** | Suboptimal security practice, outdated dependency, or missing hardening control |
| **LOW** | Minor improvement opportunity, informational finding, or optional cleanup |

---

## Dashboard

```bash
npm run dev          # http://localhost:3001 — development mode
npm run build && npm start  # production build
```

The Next.js dashboard renders all markdown reports grouped by department. Outputs are picked up automatically from the output folders when present.

---

## Adding a new department

1. Create `backend/<dept>/` with Python scripts following the standard pattern.
2. Create `.studio/agents/<dept>/<agent-name>.md` with frontmatter and workflow.
3. Symlink: `ln -s ../../.studio/agents/<dept> .claude/agents/<dept>`
4. Create output folder: `security-audits/<dept>/` with `.gitkeep`.
5. Update `.gitignore` with `security-audits/<dept>/`.
6. Add the agent row to `.studio/STUDIO.md` agent table.
7. Wire the department into `analyst.md` activation matrix.

### Script template

```python
#!/usr/bin/env python3
# script-name.py — <purpose>
# Usage: python3 backend/<dept>/script-name.py <target> [--options]
# Output: JSON → backend/outputs/YYYY-MM-DD-<script>-<target>.json

import sys, json, os, datetime

def analyze(target: str) -> dict:
    findings = []
    # ... read-only analysis ...
    return {
        "target": target,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "findings": findings,
        "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0}
    }

def main():
    result = analyze(sys.argv[1])
    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    output_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, f"{date_str}-script-name-{sys.argv[1]}.json")
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"Output written to {out_path}")

if __name__ == "__main__":
    main()
```

---

## Acknowledgements

The cybersecurity skill library powering this system (754 skills, 30 subdomains) is sourced from:

> **[mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)**  
> A comprehensive collection of cybersecurity skills built for Anthropic's Claude SDK, covering cloud security, threat hunting, digital forensics, malware analysis, red teaming, identity management, and more. The library is NIST CSF-aligned and provides both skill definitions and executable agent scripts.

All skills in `.agents/skills/` originate from this repository. The local librarian (`skills-lock.json`) tracks source hashes to ensure integrity.

---

*Built with [Claude Code](https://claude.ai/code) · [Mowgli Studio](https://mowgli.studio)*
