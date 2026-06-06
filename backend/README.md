# Backend

Space where agents develop operational scripts for the system.

## Structure

```
backend/
├── scripts/     # One-shot scripts (Python, JS, shell) produced by agents
├── tools/       # Reusable utilities callable from multiple scripts
└── outputs/     # Script run outputs (gitignored)
```

## Conventions

- Every script starts with a header comment: what it does, when to use it, expected output.
- Scripts don't perform destructive actions without an explicit `--confirm` flag.
- Output goes to `outputs/YYYY-MM-DD-<script-name>.<ext>` (gitignored).
- Agents that generate scripts here follow the pattern: discovery → proposal → Thomas approves → execution.

## Example scripts that will live here

- `mac-health-snapshot.py` — captures CPU/RAM/disk metrics as JSON
- `launch-agent-diff.sh` — diffs current LaunchAgents against a saved baseline
- `dep-hash-check.py` — verifies installed binary hashes against the official registry
