# Analyst-system

> A multi-agent security analysis platform built on Claude Code — 11 specialized agents, 27 backend scripts, 8 departments.

```
analyst (global orchestrator)
├── cybersecurity ── api-security-tester + web-security-scanner
├── forensics ────── forensic-analyst
├── network ──────── network-analyst
├── threat-intel ─── threat-hunter
├── cloud ────────── cloud-auditor
├── identity ─────── identity-auditor
└── dependency-audit─ dependency-auditor
```

---

## Quick start

```bash
# Full security posture review (all departments)
> Use analyst for a full posture review

# External attack surface audit
> Use analyst for an external audit of mowgli.studio

# Pre-deploy check on a project
> Use analyst for a pre-deploy check on /path/to/project

# Single department — forensics
> Use forensic-analyst to run a full triage

# Single script — check a domain
python3 backend/network/dns-enum.py mowgli.studio

# Check a package for CVEs
python3 backend/dependency-audit/package-analyzer.py lodash --registry npm

# Verify a binary
python3 backend/forensics/binary-verifier.py /Applications/SomeApp.app
```

---

## Agents

| Agent | Department | Model | Purpose |
|---|---|---|---|
| `analyst` | — | sonnet | **Global orchestrator** — activates departments by goal |
| `cybersecurity` | cybersecurity | sonnet | Dept orchestrator — API + web security in parallel |
| `api-security-tester` | cybersecurity | sonnet | Unauthenticated API audit (bagheera.mowgli.studio) |
| `web-security-scanner` | cybersecurity | sonnet | Web security (mowgli.studio, baloo.mowgli.studio) |
| `forensic-analyst` | forensics | sonnet | macOS forensic triage — persistence, processes, logs |
| `network-analyst` | network | sonnet | DNS enum, port profiling, connection snapshot |
| `threat-hunter` | threat-intel | sonnet | IoC check, MITRE ATT&CK mapping, passive OSINT |
| `cloud-auditor` | cloud | sonnet | Dockerfile, env secrets, Vercel/Next.js config |
| `identity-auditor` | identity | sonnet | Auth flow analysis, route permission mapping |
| `dependency-auditor` | dependency-audit | sonnet | Package/lockfile CVE audit — GO / NO-GO verdict |
| `requirements-validator` | requirements | sonnet | Speckit-based spec coherence review |

### Orchestrator activation matrix

| Command | Departments activated |
|---|---|
| `full` | all 7 departments |
| `external` | cybersecurity + network + threat-intel |
| `local` | forensics + identity |
| `pre-deploy` | cybersecurity + cloud + dependency-audit |
| `project` | requirements + dependency-audit + identity |

---

## Backend scripts (27 total)

All scripts: Python 3 stdlib only · read-only · JSON output to `backend/outputs/`

### cybersecurity/api (4 scripts)

| Script | Input | Purpose |
|---|---|---|
| `backend/api/auth-probe.py` | `<host>` | Test unauthenticated access to protected endpoints |
| `backend/api/endpoint-discovery.py` | `<host>` | Discover API endpoints via common paths |
| `backend/api/header-audit.py` | `<host>` | Check security headers on API responses |
| `backend/api/rate-limit-test.py` | `<host>` | Test rate limiting behavior |

### cybersecurity/web (4 scripts)

| Script | Input | Purpose |
|---|---|---|
| `backend/web/cookie-audit.py` | `<url>` | Cookie flags: HttpOnly, Secure, SameSite |
| `backend/web/csp-analyzer.py` | `<url>` | Content-Security-Policy analysis |
| `backend/web/form-scanner.py` | `<url>` | Form security: CSRF, autocomplete, encoding |
| `backend/web/security-headers.py` | `<url>` | Full HTTP security headers audit |

### network (3 scripts)

| Script | Input | Purpose |
|---|---|---|
| `backend/network/dns-enum.py` | `<domain>` | DNS records, SPF/DMARC, zone transfer attempt |
| `backend/network/port-profiler.py` | `<host>` | Local/remote port profiling, suspicious port detection |
| `backend/network/connection-monitor.py` | — | Snapshot active TCP connections by process |

### threat-intel (3 scripts)

| Script | Input | Purpose |
|---|---|---|
| `backend/threat-intel/ioc-checker.py` | `<ip\|domain\|sha256>` | IoC check vs OTX, URLhaus, AbuseIPDB, VT |
| `backend/threat-intel/osint-domain.py` | `<domain>` | Passive OSINT: whois, crt.sh, robots.txt, headers |
| `backend/threat-intel/mitre-mapper.py` | `<findings.json>` | Map findings to MITRE ATT&CK techniques |

### cloud (3 scripts)

| Script | Input | Purpose |
|---|---|---|
| `backend/cloud/dockerfile-audit.py` | `<dockerfile>` | USER, base image, secrets, suspicious RUN |
| `backend/cloud/env-leak-scanner.py` | `<project-root>` | Secrets in code, .env committed, git history |
| `backend/cloud/vercel-config-audit.py` | `<project-root>` | vercel.json, next.config, open redirects |

### identity (2 scripts)

| Script | Input | Purpose |
|---|---|---|
| `backend/identity/auth-flow-analyzer.py` | `<project-root>` | JWT anti-patterns, hashing, session config |
| `backend/identity/permission-scanner.py` | `<project-root>` | Route → auth protection map (App Router) |

### forensics (3 scripts)

| Script | Input | Purpose |
|---|---|---|
| `backend/forensics/persistence-scanner.py` | — | LaunchAgents, daemons, login items, crontab |
| `backend/forensics/binary-verifier.py` | `<path>` | Code signing, notarization, hash, strings IoC |
| `backend/forensics/log-analyzer.py` | `[--hours N]` | Auth failures, sudo, crashes, malware indicators |

### dependency-audit (2 scripts)

| Script | Input | Purpose |
|---|---|---|
| `backend/dependency-audit/package-analyzer.py` | `<pkg> [--registry npm\|pypi]` | CVEs, maintainer, suspicious scripts |
| `backend/dependency-audit/lockfile-auditor.py` | `<lockfile>` | Bulk CVE scan of package-lock.json / requirements.txt |

### tools (1 utility)

| Script | Input | Purpose |
|---|---|---|
| `backend/tools/report-builder.py` | `--inputs <glob> --output <path.md>` | Aggregate JSON outputs into markdown report |

---

## Output folders

| Folder | Contents |
|---|---|
| `security-audits/` | Executive reports (analyst) + full audit |
| `security-audits/api/` | API security reports (gitignored) |
| `security-audits/web/` | Web security reports (gitignored) |
| `security-audits/network/` | Network audit reports (gitignored) |
| `security-audits/threat-intel/` | Threat intel reports (gitignored) |
| `security-audits/cloud/` | Cloud/config audit reports (gitignored) |
| `security-audits/identity/` | Auth/permissions reports (gitignored) |
| `backend/outputs/` | Raw JSON from scripts (gitignored) |
| `forensic-reports/` | macOS triage reports (gitignored) |
| `dependency-audits/` | Dependency audit outputs (gitignored) |

---

## Architecture

```
.studio/agents/          # Agent definitions (source of truth)
│   analyst.md           # Global orchestrator
│   cybersecurity/       # API + web security
│   forensics/           # macOS forensics
│   network/             # Network analysis
│   threat-intel/        # Threat intelligence
│   cloud/               # Cloud/container audit
│   identity/            # Auth & permissions
│   dependency-audit/    # Package audit
│   requirements/        # Spec validation
│
.claude/agents/          # Symlinks → .studio/agents/ (discovered by Claude Code)
│
backend/                 # Python scripts (stdlib only, read-only)
│   api/, web/           # Cybersecurity scripts
│   network/             # Network scripts
│   threat-intel/        # Threat intel scripts
│   cloud/               # Cloud/config scripts
│   identity/            # Identity scripts
│   forensics/           # Forensics scripts
│   dependency-audit/    # Dependency scripts
│   tools/               # Shared utilities (report-builder)
│   outputs/             # JSON outputs (gitignored)
│
.studio/skills/librarian/   # Skill router for 754 cybersecurity skills
│   SKILL.md                # Instructions: search index, load only relevant skills
│   skills-index.json       # Pre-computed index (452KB, 45 subdomains)
│   library/ → .agents/skills/  # Symlink to actual skills
```

### Skill library

754 cybersecurity skills organized in 45 subdomains (NIST CSF aligned). Always route through the **librarian** — never load skills directly:

```
> Find skills for API gateway log analysis
> Which skill handles cobalt strike detection?
> Skills for NIST DE.CM-01
```

---

## Running the dashboard

```bash
npm run dev    # http://localhost:3001
npm run build && npm start
```

The dashboard shows all reports grouped by type, rendered from markdown files in the output folders.

---

## Adding a new department

1. Create `backend/<dept>/` with Python scripts following the existing pattern.
2. Create `.studio/agents/<dept>/<agent-name>.md` with frontmatter + workflow.
3. Symlink: `ln -s ../../.studio/agents/<dept> .claude/agents/<dept>`
4. Add output folder: `security-audits/<dept>/` with `.gitkeep`.
5. Update `.gitignore` with `security-audits/<dept>/`.
6. Add agent to the table in `.studio/STUDIO.md`.
7. Wire the new agent into `analyst.md` activation matrix.

### Script pattern

```python
#!/usr/bin/env python3
# script-name.py
# What: <purpose>
# When to use: <trigger>
# Expected output: JSON to backend/outputs/YYYY-MM-DD-<script>-<target>.json
#
# Usage: python3 backend/<dept>/script-name.py <target> [--options]

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
    with open(os.path.join(output_dir, f"{date_str}-script-name-{sys.argv[1]}.json"), "w") as f:
        json.dump(result, f, indent=2)

if __name__ == "__main__":
    main()
```

---

## Severity schema

| Level | Symbol | Meaning |
|---|---|---|
| CRITICAL | 🔴 | Confirmed compromise, active exfiltration, exposed secret in prod |
| HIGH | 🟠 | Exploitable vulnerability, serious misconfiguration, CVE affecting current version |
| MEDIUM | 🟡 | Suboptimal security practice, outdated dependency, missing hardening |
| LOW | 🟢 | Minor improvement, informational finding, optional cleanup |

---

*Built with [Claude Code](https://claude.ai/code)*
