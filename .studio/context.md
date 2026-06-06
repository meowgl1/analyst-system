---
project: analyst
type: security-analysis
---

# Analyst-system — Project Context

## Identity

Personal system for **security review** and **software requirements validation**.

- **What it does**: hosts specialised agents for on-demand audits of (a) the operating system, (b) new dependencies/skills before installing them, (c) software projects to verify spec coherence, (d) live security testing of mowgli.studio services.
- **What it does NOT do**: no automated destructive actions, no outreach, no runtime services.
- **Core principle**: Read-only by default. Evidence-first. Human-approves-remediation.

## Architecture

```
Analyst-system/
├── .studio/              # Studio structure (context, agents, librarian)
├── .agents/skills/       # 754 cybersecurity skills (source of truth, never move)
├── app/                  # Next.js 15 — report viewer UI (read-only dashboard)
├── backend/              # Python security scripts (stdlib only)
├── forensic-reports/     # Mac triage outputs (gitignored)
├── dependency-audits/    # Dependency audit outputs (gitignored)
├── requirements-reviews/ # Project review outputs (versioned)
├── security-audits/      # Security test outputs
└── .specify/             # Speckit constitution
```

## Non-negotiable rules

1. **Read-only by default** — no `rm`, no mutating `sudo`, no `kill -9`. Propose, don't execute.
2. **Evidence-first** — every finding cites command + output or `file:line`. No claims without proof.
3. **Severity ranking** — Critical / High / Medium / Low on every report.
4. **Persistent output** — reports in their respective output folders, never printed and lost.
5. **Speckit authority** — for requirements review, use `speckit-analyze`, `speckit-clarify`, `speckit-checklist`.

## Targets

| Target | URL |
|---|---|
| API | bagheera.mowgli.studio |
| Web (portfolio) | mowgli.studio |
| Web (app) | baloo.mowgli.studio |

## Constraints

- Python scripts: stdlib only — no `pip install`
- All security testing is unauthenticated unless `BAGHEERA_API_KEY` is set
- Frontend runs on port 3001 (`npm run dev` / `npm run build && npm start`)
- `skills-lock.json` tracks `.agents/skills/` — never move those directories
