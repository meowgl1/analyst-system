---
project: analyst
type: security-analysis
version: 2.1
---

# Analyst-system — Project Context

## Identity

Personal system for **security review** and **software requirements validation**, built on specialized Claude Code agents and Python backend scripts.

- **What it does**: hosts specialized agents for on-demand audits of (a) the operating system, (b) new dependencies/skills before installing them, (c) software projects to verify spec coherence, (d) live security testing of mowgli.studio services, (e) network and DNS analysis, (f) threat intelligence and IoC correlation, (g) cloud/container config audit, (h) auth/permissions code review.
- **What it does NOT do**: no automated destructive actions, no outreach, no runtime services.
- **Core principle**: Read-only by default. Evidence-first. Human-approves-remediation.

## Architecture

```
Analyst-system/
├── .studio/                    # Studio structure (context, agents, librarian, memory)
│   ├── agents/                 # Agent definitions — source of truth
│   │   ├── analyst.md          # Global orchestrator
│   │   ├── cybersecurity/      # API + web security (3 agents)
│   │   ├── forensics/          # macOS forensic triage
│   │   ├── network/            # DNS, ports, connections
│   │   ├── threat-intel/       # IoC, MITRE, OSINT
│   │   ├── cloud/              # Dockerfile, env, Vercel config
│   │   ├── identity/           # Auth flows, route permissions
│   │   ├── dependency-audit/   # Package CVE audit
│   │   └── requirements/       # Spec validation
│   ├── skills/librarian/       # Skill router for 754 cybersecurity skills
│   ├── changelog/              # Versioned change log
│   └── memory/                 # Studio memory (persistent notes)
├── .claude/
│   ├── agents/                 # Symlinks → .studio/agents/ (Claude Code discovery)
│   └── settings.json           # Tool permissions
├── .agents/skills/             # 754 cybersecurity skills (source of truth, never move)
├── app/                        # Next.js 15 — report viewer dashboard (port 3001)
├── backend/                    # Python security scripts (stdlib only, read-only)
│   ├── api/                    # 4 scripts: auth-probe, endpoint-discovery, header-audit, rate-limit
│   ├── web/                    # 4 scripts: cookie-audit, csp-analyzer, form-scanner, security-headers
│   ├── network/                # 3 scripts: dns-enum, port-profiler, connection-monitor
│   ├── threat-intel/           # 3 scripts: ioc-checker, mitre-mapper, osint-domain
│   ├── cloud/                  # 3 scripts: dockerfile-audit, env-leak-scanner, vercel-config-audit
│   ├── identity/               # 2 scripts: auth-flow-analyzer, permission-scanner
│   ├── forensics/              # 3 scripts: persistence-scanner, binary-verifier, log-analyzer
│   ├── dependency-audit/       # 2 scripts: package-analyzer, lockfile-auditor
│   ├── tools/                  # Shared utilities: report-builder.py
│   └── outputs/                # JSON outputs (gitignored)
├── security-audits/            # Security report outputs
│   ├── api/                    # API security (gitignored)
│   ├── web/                    # Web security (gitignored)
│   ├── network/                # Network audits (gitignored)
│   ├── threat-intel/           # Threat intel (gitignored)
│   ├── cloud/                  # Cloud/config audits (gitignored)
│   └── identity/               # Auth/permissions audits (gitignored)
├── forensic-reports/           # macOS triage outputs (gitignored)
├── dependency-audits/          # Dependency audit outputs (gitignored)
└── requirements-reviews/       # Project review outputs (versioned)
```

## Agent network

```
analyst (global orchestrator)
├── cybersecurity ──── api-security-tester + web-security-scanner
├── forensic-analyst
├── network-analyst
├── threat-hunter
├── cloud-auditor
├── identity-auditor
├── dependency-auditor
└── requirements-validator
```

### Orchestrator activation matrix

| Mode | Departments |
|---|---|
| `full` | all 7 |
| `external` | cybersecurity + network + threat-intel |
| `local` | forensics + identity |
| `pre-deploy` | cybersecurity + cloud + dependency-audit |
| `project` | requirements + dependency-audit + identity |

## Non-negotiable rules

1. **Read-only by default** — no `rm`, no mutating `sudo`, no `kill -9`. Propose, don't execute.
2. **Evidence-first** — every finding cites command + output or `file:line`. No claims without proof.
3. **Severity ranking** — Critical / High / Medium / Low on every report.
4. **Persistent output** — reports in their respective output folders, never printed and lost.
5. **report-builder** — use `backend/tools/report-builder.py` to convert JSON outputs to markdown. Never hand-format aggregated reports.
6. **Speckit authority** — for requirements review, use `speckit-analyze`, `speckit-clarify`, `speckit-checklist`.

## Targets

| Target | URL |
|---|---|
| API | bagheera.mowgli.studio |
| Web (portfolio) | mowgli.studio |
| Web (app) | baloo.mowgli.studio |

## Constraints

- Python scripts: stdlib only — no `pip install`
- All security testing is unauthenticated unless `BAGHEERA_API_KEY` is set
- IoC check: `ABUSEIPDB_API_KEY` and `VIRUSTOTAL_API_KEY` env vars optional (scripts degrade gracefully)
- Frontend runs on port 3001 (`npm run dev` / `npm run build && npm start`)
- `skills-lock.json` tracks `.agents/skills/` — never move those directories
- GitHub: `https://github.com/meowgl1/analyst-system`
