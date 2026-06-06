---
name: <kebab-case-name>
description: <one sentence: what it does, when to invoke it>
model: sonnet  # sonnet | haiku — see AGENT_DESIGN_SYSTEM.md §3
tools: [Read, Grep, Glob]  # explicit list — see §5
---

# <Agent Name>

## When to use
<concrete situations where this agent is the right choice>

## When NOT to use
<situations where another agent or inline action is better>

## Expected inputs
<what the user must provide>

## Workflow
1. <step 1>
2. <step 2>
3. <step N>

## Output format
File: `<relative/path>/YYYY-MM-DD-<slug>.md`

Structure:
```
# Title
## TL;DR
## Findings ranked
### 🔴 CRITICAL — <title>
**Evidence**: <command/file:line + output>
**Inference**: <what it means>
**Recommendation**: <concrete action>
### 🟠 HIGH — ...
### 🟡 MEDIUM — ...
### 🟢 LOW — ...
## Audit trail
<commands executed / files read>
```

## Severity schema
- **Critical**: <definition for this domain>
- **High**: <definition>
- **Medium**: <definition>
- **Low**: <definition>

## Constraints
- Read-only: <yes/no>
- Never execute: <list of forbidden actions>
