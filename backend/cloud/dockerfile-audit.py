#!/usr/bin/env python3
# dockerfile-audit.py
# What: Static analysis of a Dockerfile for security best practices.
#       Checks: non-root user, no hardcoded secrets, pinned base images,
#       multi-stage builds, exposed sensitive ports, ADD vs COPY, etc.
# When to use: Before deploying any Docker-based service or reviewing container config.
# Expected output: JSON to backend/outputs/YYYY-MM-DD-dockerfile-audit-<slug>.json
#
# Usage: python3 dockerfile-audit.py <path-to-Dockerfile>
#   e.g. python3 dockerfile-audit.py /path/to/project/Dockerfile

import sys
import json
import os
import re
import datetime

# Ports that are sensitive if exposed
SENSITIVE_PORTS = {
    22: "SSH — should not be exposed from a container",
    3306: "MySQL — expose only via internal network",
    5432: "PostgreSQL — expose only via internal network",
    6379: "Redis — frequently exploited when exposed",
    27017: "MongoDB — frequently exploited when exposed",
    9200: "Elasticsearch — frequently exposed without auth",
}

# Patterns suggesting hardcoded secrets
SECRET_PATTERNS = [
    (r"(?i)ENV\s+\w*(password|secret|key|token|api_key|access_key|auth)\w*\s*=\s*\S+",
     "Hardcoded secret in ENV instruction"),
    (r"(?i)ARG\s+\w*(password|secret|key|token)\w*\s*=\s*\S+",
     "Hardcoded secret in ARG instruction"),
    (r"(?i)(curl|wget).+https?://[^\s]+\s*\|\s*(bash|sh)",
     "Piped curl/wget to shell — supply chain risk"),
    (r"(?i)RUN\s+.*\beval\b",
     "eval in RUN instruction"),
]


def parse_dockerfile(path: str) -> list[dict]:
    """Parse Dockerfile into instruction list."""
    instructions = []
    try:
        with open(path) as f:
            lines = f.readlines()
    except Exception as e:
        return []

    current = None
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            if current:
                current["raw"] += " " + stripped[:-1].strip()
            else:
                current = {"line": i, "raw": stripped[:-1].strip()}
        else:
            if current:
                current["raw"] += " " + stripped
                instructions.append(current)
                current = None
            else:
                instructions.append({"line": i, "raw": stripped})

    if current:
        instructions.append(current)

    # Parse instruction keyword
    for instr in instructions:
        parts = instr["raw"].split(None, 1)
        instr["keyword"] = parts[0].upper() if parts else ""
        instr["args"] = parts[1] if len(parts) > 1 else ""

    return instructions


def audit_dockerfile(path: str) -> dict:
    instructions = parse_dockerfile(path)
    findings = []
    info = {
        "base_images": [],
        "has_user_instruction": False,
        "is_multi_stage": False,
        "exposed_ports": [],
        "instruction_count": len(instructions),
    }

    if not instructions:
        return {"error": f"Could not parse {path}", "findings": []}

    from_count = 0
    run_as_root = True

    full_text = "\n".join(i["raw"] for i in instructions)

    for instr in instructions:
        kw = instr["keyword"]
        args = instr["args"]
        line = instr["line"]

        # FROM — base image
        if kw == "FROM":
            from_count += 1
            image = args.split()[0] if args.split() else ""
            info["base_images"].append(image)

            # Check for unpinned base images
            if ":" not in image or image.endswith(":latest"):
                findings.append({
                    "type": "UNPINNED_BASE_IMAGE",
                    "severity": "MEDIUM",
                    "line": line,
                    "value": image,
                    "description": f"Base image '{image}' is not pinned to a specific digest",
                    "guidance": "Use digest pinning: FROM image@sha256:abc... for reproducible builds",
                })

            # Check for root-based images
            if image in ("ubuntu", "debian", "centos", "fedora") and ":" not in image:
                findings.append({
                    "type": "HEAVYWEIGHT_BASE_IMAGE",
                    "severity": "LOW",
                    "line": line,
                    "value": image,
                    "description": f"Using heavyweight base '{image}' — consider distroless or alpine",
                    "guidance": "Use minimal base images to reduce attack surface",
                })

        # USER — sets running user
        elif kw == "USER":
            info["has_user_instruction"] = True
            if args.strip().lower() in ("root", "0"):
                findings.append({
                    "type": "USER_ROOT",
                    "severity": "HIGH",
                    "line": line,
                    "description": "Container explicitly runs as root",
                    "guidance": "Add: USER nonroot or create a dedicated non-root user",
                })
            else:
                run_as_root = False

        # EXPOSE
        elif kw == "EXPOSE":
            for port_str in re.findall(r"\d+", args):
                port = int(port_str)
                info["exposed_ports"].append(port)
                if port in SENSITIVE_PORTS:
                    findings.append({
                        "type": "SENSITIVE_PORT_EXPOSED",
                        "severity": "HIGH",
                        "line": line,
                        "port": port,
                        "description": f"Port {port} exposed: {SENSITIVE_PORTS[port]}",
                        "guidance": "Use internal Docker networks instead of exposing sensitive ports",
                    })

        # ADD vs COPY
        elif kw == "ADD":
            src = args.split()[0] if args.split() else ""
            if not src.startswith("http"):  # HTTP ADD is intentional (though also bad)
                findings.append({
                    "type": "ADD_INSTEAD_OF_COPY",
                    "severity": "LOW",
                    "line": line,
                    "description": "ADD used instead of COPY — ADD has implicit tar extraction and URL fetch",
                    "guidance": "Use COPY for local files unless you specifically need ADD's tar/URL behavior",
                })

    # Multi-stage build check
    if from_count > 1:
        info["is_multi_stage"] = True

    # No USER instruction
    if not info["has_user_instruction"]:
        findings.append({
            "type": "NO_USER_INSTRUCTION",
            "severity": "HIGH",
            "description": "No USER instruction — container will run as root by default",
            "guidance": "Add USER instruction: RUN addgroup -S app && adduser -S app -G app && USER app",
        })

    # Secret patterns
    for pattern, description in SECRET_PATTERNS:
        matches = re.findall(pattern, full_text)
        if matches:
            findings.append({
                "type": "POTENTIAL_SECRET",
                "severity": "CRITICAL",
                "description": description,
                "guidance": "Use --secret mounts or env vars at runtime — never hardcode secrets",
                "match_count": len(matches),
            })

    # Check for .dockerignore existence
    dockerignore = os.path.join(os.path.dirname(path), ".dockerignore")
    if not os.path.exists(dockerignore):
        findings.append({
            "type": "NO_DOCKERIGNORE",
            "severity": "MEDIUM",
            "description": "No .dockerignore file — .git, node_modules, .env may be included in build context",
            "guidance": "Create .dockerignore with: .git, node_modules, .env*, *.log, .DS_Store",
        })

    return {
        "path": path,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "info": info,
        "findings": findings,
        "summary": {
            "critical": len([f for f in findings if f["severity"] == "CRITICAL"]),
            "high": len([f for f in findings if f["severity"] == "HIGH"]),
            "medium": len([f for f in findings if f["severity"] == "MEDIUM"]),
            "low": len([f for f in findings if f["severity"] == "LOW"]),
        }
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 dockerfile-audit.py <Dockerfile-path>")
        sys.exit(1)

    path = sys.argv[1]
    if not os.path.exists(path):
        print(f"Error: {path} not found")
        sys.exit(1)

    result = audit_dockerfile(path)

    print(f"\n=== Dockerfile Audit: {path} ===\n")
    s = result["summary"]
    print(f"  Critical: {s['critical']} | High: {s['high']} | Medium: {s['medium']} | Low: {s['low']}")
    for f in result["findings"]:
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(f["severity"], "⚪")
        print(f"  {icon} [{f['severity']}] {f['type']}")

    slug = os.path.basename(os.path.dirname(os.path.abspath(path))) or "dockerfile"
    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    output_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{date_str}-dockerfile-audit-{slug}.json")

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n  Full output: {output_file}")


if __name__ == "__main__":
    main()
