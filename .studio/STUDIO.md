---
studio: mowgli
version: 2.0
scope: project
project: analyst
---

@~/.studio/STUDIO.md

## Load — project context

@.studio/context.md

## Load — librarian (skill router for 754 cybersecurity skills)

@.studio/skills/librarian/SKILL.md

---

## Agents available

Invoke by name — discoverable in `.claude/agents/` (symlinked from `.studio/agents/`):

| Agent | Department | Purpose |
|---|---|---|
| `analyst` | — | Global orchestrator — activates departments by goal (full/external/pre-deploy/local) |
| `cybersecurity` | cybersecurity | Orchestrator — launches api-security-tester + web-security-scanner in parallel |
| `api-security-tester` | cybersecurity | Unauthenticated testing of bagheera.mowgli.studio API |
| `web-security-scanner` | cybersecurity | Security testing of mowgli.studio + baloo.mowgli.studio |
| `forensic-analyst` | forensics | macOS forensic triage: processes, persistence, network, code signing, logs |
| `network-analyst` | network | DNS enum, port profiling, active connection snapshot |
| `threat-hunter` | threat-intel | IoC check, MITRE ATT&CK mapping, passive OSINT on domains |
| `cloud-auditor` | cloud | Dockerfile, env secrets, Vercel/Next.js config audit |
| `identity-auditor` | identity | Auth flow analysis, route permission mapping |
| `dependency-auditor` | dependency-audit | Pre-install audit of packages/skills/repos — GO / NO-GO / REVIEW verdict |
| `requirements-validator` | requirements | Speckit-based spec coherence review |

## Skills available

**Cybersecurity library** (754 skills): always route through the `librarian`.
Never load skills directly from `.studio/skills/librarian/library/` without using the librarian first.

```
> Find skills for API gateway log analysis
> Find malware analysis skills
> Which skill handles cobalt strike detection?
> Skills for NIST DE.CM-01
```

---

## Stack

- **Frontend**: Next.js 15 App Router · Tailwind CSS · gray-matter · marked (port 3001)
- **Backend**: Python 3 stdlib only — no pip install. Scripts in `backend/`
- **Language rules**: Python + JS/TS (load from `~/.studio/rules/`)

---

## Output folders

| Type | Folder |
|---|---|
| Forensic reports | `forensic-reports/YYYY-MM-DD-<subject>.md` |
| Dependency audits | `dependency-audits/YYYY-MM-DD-<pkg>.md` |
| Requirements reviews | `requirements-reviews/<project>/YYYY-MM-DD.md` |
| Security audits (full) | `security-audits/YYYY-MM-DD-analyst-report.md` |
| API security | `security-audits/api/YYYY-MM-DD-bagheera.md` |
| Web security | `security-audits/web/YYYY-MM-DD-<target>.md` |
| Network audits | `security-audits/network/YYYY-MM-DD-<target>.md` |
| Threat intelligence | `security-audits/threat-intel/YYYY-MM-DD-<subject>.md` |
| Cloud audits | `security-audits/cloud/YYYY-MM-DD-<project>.md` |
| Identity audits | `security-audits/identity/YYYY-MM-DD-<project>.md` |
| Script raw output | `backend/outputs/YYYY-MM-DD-<script>-<target>.json` |
