#!/usr/bin/env python3
"""
build-index.py — Cybersecurity Skill Librarian Index Builder

Parsa tutte le SKILL.md in .agents/skills/ ed estrae i metadati YAML
per costruire skills-index.json. Usa solo la stdlib Python 3.

Usage:
    python3 .studio/skills/librarian/scripts/build-index.py

Output:
    .studio/skills/librarian/skills-index.json
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


def find_project_root() -> Path:
    """Walk up from cwd until we find skills-lock.json (project root marker)."""
    cwd = Path.cwd()
    for parent in [cwd, *cwd.parents]:
        if (parent / "skills-lock.json").exists():
            return parent
    # Fallback: try the script's location (4 levels up from scripts/)
    script_dir = Path(__file__).parent
    return script_dir.parent.parent.parent.parent


def parse_frontmatter(content: str) -> dict:
    """
    Parse YAML frontmatter between --- delimiters.
    Handles: strings, lists (- item), multi-line strings (> or |).
    """
    lines = content.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}

    fm_lines = []
    i = 1
    while i < len(lines):
        if lines[i].strip() == "---":
            break
        fm_lines.append(lines[i])
        i += 1

    result = {}
    j = 0
    while j < len(fm_lines):
        line = fm_lines[j]

        # Skip blank lines
        if not line.strip():
            j += 1
            continue

        # Key: value
        m = re.match(r'^(\w[\w_-]*)\s*:\s*(.*)', line)
        if not m:
            j += 1
            continue

        key = m.group(1)
        value_str = m.group(2).strip()

        # Multi-line string (> or |)
        if value_str in ('>', '|'):
            j += 1
            parts = []
            while j < len(fm_lines) and (fm_lines[j].startswith('  ') or fm_lines[j].strip() == ''):
                parts.append(fm_lines[j].strip())
                j += 1
            result[key] = ' '.join(p for p in parts if p)
            continue

        # Inline string value
        if value_str and not value_str.startswith('-'):
            # Strip quotes
            if (value_str.startswith("'") and value_str.endswith("'")) or \
               (value_str.startswith('"') and value_str.endswith('"')):
                value_str = value_str[1:-1]
            result[key] = value_str
            j += 1
            continue

        # List (value_str is empty, next lines are - items)
        if not value_str:
            j += 1
            items = []
            while j < len(fm_lines) and re.match(r'^\s*-\s+', fm_lines[j]):
                item = re.sub(r'^\s*-\s+', '', fm_lines[j]).strip().strip("'\"")
                items.append(item)
                j += 1
            result[key] = items
            continue

        result[key] = value_str
        j += 1

    return result


def build_index(project_root: Path) -> dict:
    skills_dir = project_root / ".agents" / "skills"
    if not skills_dir.exists():
        print(f"ERROR: Skills directory not found: {skills_dir}", file=sys.stderr)
        sys.exit(1)

    skills = []
    subdomains: dict[str, int] = {}
    errors = []

    skill_dirs = sorted(skills_dir.iterdir())
    total = len([d for d in skill_dirs if d.is_dir()])
    print(f"Scanning {total} skill directories...")

    for skill_dir in skill_dirs:
        if not skill_dir.is_dir():
            continue

        skill_md = skill_dir / "SKILL.md"
        if not skill_md.exists():
            errors.append(f"Missing SKILL.md: {skill_dir.name}")
            continue

        try:
            content = skill_md.read_text(encoding="utf-8")
        except Exception as e:
            errors.append(f"Read error {skill_dir.name}: {e}")
            continue

        fm = parse_frontmatter(content)

        name = fm.get("name") or skill_dir.name
        description = fm.get("description", "")
        subdomain = fm.get("subdomain", "")
        tags = fm.get("tags", [])
        nist_csf = fm.get("nist_csf", [])

        # Normalize: ensure lists are actually lists
        if isinstance(tags, str):
            tags = [tags]
        if isinstance(nist_csf, str):
            nist_csf = [nist_csf]

        # Count subdomain
        if subdomain:
            subdomains[subdomain] = subdomains.get(subdomain, 0) + 1

        skills.append({
            "name": name,
            "description": description,
            "subdomain": subdomain,
            "tags": tags,
            "nist_csf": nist_csf,
            "path": f"library/{skill_dir.name}/SKILL.md",
        })

    # Sort subdomains by count descending
    subdomains_sorted = dict(sorted(subdomains.items(), key=lambda x: -x[1]))

    index = {
        "version": 1,
        "generated": datetime.now(timezone.utc).isoformat(),
        "total": len(skills),
        "subdomains": subdomains_sorted,
        "skills": skills,
    }

    if errors:
        print(f"\nWarnings ({len(errors)}):")
        for e in errors:
            print(f"  - {e}")

    return index


def main():
    project_root = find_project_root()
    print(f"Project root: {project_root}")

    index = build_index(project_root)

    output_path = project_root / ".studio" / "skills" / "librarian" / "skills-index.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2, ensure_ascii=False)

    print(f"\nIndex built:")
    print(f"  Total skills: {index['total']}")
    print(f"  Subdomains:   {len(index['subdomains'])}")
    print(f"  Output:       {output_path}")
    print(f"\nTop 5 subdomains:")
    for subdomain, count in list(index["subdomains"].items())[:5]:
        print(f"  {count:3d}  {subdomain}")


if __name__ == "__main__":
    main()
