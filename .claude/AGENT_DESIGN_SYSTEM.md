# Agent Design System

> Thomas's personal guidelines for instantiating Claude Code agents.
> Abstracted from patterns applied across projects (e.g. Jungle), not tied to any single use case.

---

## When to create an agent (vs skill, vs inline command)

| Form | When to use |
|---|---|
| **Inline (no agent)** | One-shot task, clear context, < 3 steps. Do it yourself. |
| **Skill** | Repeatable, deterministic, reusable procedure (e.g. "write a safe migration", "render an email"). No decision-making autonomy. |
| **Agent** | A role with autonomy: takes a vague task in a domain, explores, decides how to proceed, produces structured output. E.g. "audit the security of X", "find new lead channels". |

**Rule**: if I'll use this pattern ≥3 times in the future → worth writing it out.

---

## The 10 principles

### 1. Single Responsibility per agent
One agent = one clear domain. If the description contains "and also…" → split into two agents.

### 2. Department pattern for cross-domain tasks
When a task requires ≥3 distinct sub-domains → create an **orchestrator** that launches specialists **in parallel** and synthesizes their results.

Real examples (Jungle):
- *Quality Department*: `platform-orchestrator` → security, code-quality, architecture, test, db.
- *Investigation Department*: `outreach-strategist` → copywriting, deliverability, personalization, timing.

If the orchestrator adds no synthesis value → it's not needed. Don't orchestrate for the sake of orchestrating.

### 3. Model selection by task shape
| Model | When |
|---|---|
| **Sonnet 4.6** | Default for agents. Reasoning, design, synthesis, writing. |
| **Haiku 4.5** | High-throughput mechanical work: lint, naming review, file-by-file scanning. |
| **Opus** | Avoid unless the task is truly critical (high cost + latency). |

Specify the model in the agent frontmatter; don't defer to the default if the choice is informed.

### 4. Separation of layers (analysis vs execution)
**Never mix an agent that analyses with one that performs destructive actions.**
- Analyse → propose → the human (or a separate agent with different tools) executes.
- Example: `forensic-analyst` produces a report — it never uninstalls anything.
- Example from Jungle: the AI qualifier **does not import** `lib/gmail/send.ts`.

### 5. Read-only by default
In the `tools:` frontmatter of an audit/analysis agent → only `Read, Grep, Glob, Bash(read-only commands)`. No `Write`, `Edit`, `Bash(rm/sudo)`. Restricting tools is the best way to guarantee safety, because the AI literally cannot do what it's not authorized to do.

### 6. Evidence-first output
Every finding must include:
- **Command executed** (for system agents) or **`file:line`** (for code agents)
- **Literal output** or relevant snippet
- **Inference** clearly separated from the evidence

Never "I noticed that…" without pointing to the data.

### 7. Mandatory severity ranking
Findings always ranked: **Critical / High / Medium / Low**. Even if there are only 2 findings. Ranking forces the agent to be actionable and lets me triage in 30 seconds.

### 8. Structured finding persistence
Output in versioned markdown: `<domain>/YYYY-MM-DD-<name>.md`. Never just in chat. This way I can compare reports over time (e.g. was the Mac worse last week?).

### 9. Template-driven instantiation
`_template.md` is the source of truth for frontmatter. New agent = `cp _template.md new.md` + fill in. No snowflakes.

### 10. Composition, not duplication
If two agents share 60% of their work → extract a **skill** that both use. E.g. two system-triage agents share read-only commands via a `mac-forensic-commands` skill.

---

## Anti-patterns to avoid

- ❌ **"Does everything" agent** ("project-manager" that handles anything): vague description, poor quality.
- ❌ **Unlimited tools by default** (`tools: *`) on audit agents: negates the read-only principle.
- ❌ **Orchestrator with 1–2 sub-agents**: redundant. Go inline.
- ❌ **Agent with no severity criteria**: its outputs can't be prioritised.
- ❌ **Output that only lives in chat**: it gets lost. Always write to a file.
- ❌ **AI mixed with destructive execution**: violates separation of layers.
- ❌ **Overwriting existing agents** to make room for new ones: every agent is an isolated module.

---

## Standard frontmatter

See `agents/_template.md`. Required fields:
- `name`, `description`, `model`, `tools` (explicit list), `when_to_use`, `severity_schema` (if it produces findings).

---

## Permission boundaries

`.claude/settings.json` defines the global Bash allowlist for the project. Individual agents can further restrict (never expand) via their `tools:` frontmatter.
