#!/usr/bin/env python3
# connection-monitor.py
# What: Snapshot of all active network connections on the local machine.
#       Groups by process, resolves remote IPs via reverse DNS, flags unusual destinations.
# When to use: Forensic triage or network audit — detect unexpected outbound connections.
# Expected output: JSON to backend/outputs/YYYY-MM-DD-connection-monitor.json
#
# Usage: python3 connection-monitor.py [--resolve]
#   --resolve: attempt reverse DNS on each remote IP (slower)

import sys
import json
import subprocess
import socket
import datetime
import os

# IPs/ranges that are always suspicious on a personal Mac
SUSPICIOUS_RANGES = [
    # Private ranges that shouldn't be appearing as external
]

# Ports that suggest exfiltration/C2 when used by unexpected processes
C2_INDICATOR_PORTS = {4444, 1337, 31337, 6666, 6667, 5555, 9999, 12345, 8888}

# Processes expected to make network connections
EXPECTED_PROCESSES = {
    "Google Chrome", "firefox", "Safari", "com.apple", "mds", "cloudd",
    "Dropbox", "Slack", "Discord", "Spotify", "zoom.us", "Code Helper",
    "node", "python3", "git", "curl", "wget", "ssh", "npm",
}


def resolve_ip(ip: str, timeout: float = 1.5) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def get_connections(resolve: bool = False) -> list[dict]:
    """Parse lsof -i for established connections."""
    try:
        result = subprocess.run(
            ["lsof", "-i", "-P", "-n", "-sTCP:ESTABLISHED"],
            capture_output=True, text=True, timeout=15
        )
        lines = result.stdout.strip().splitlines()
    except Exception as e:
        return []

    connections = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue

        process = parts[0]
        pid = parts[1]
        user = parts[2]
        addr_field = parts[8]

        # Parse "local->remote" or "local:port->remote:port"
        if "->" in addr_field:
            local, remote = addr_field.split("->", 1)
            local_port = local.rsplit(":", 1)[-1] if ":" in local else ""
            remote_addr = remote.rsplit(":", 1)[0] if ":" in remote else remote
            remote_port_str = remote.rsplit(":", 1)[-1] if ":" in remote else ""
        else:
            continue

        try:
            remote_port = int(remote_port_str)
        except ValueError:
            remote_port = 0

        # Skip localhost
        if remote_addr in ("127.0.0.1", "::1", "localhost"):
            continue

        hostname = resolve_ip(remote_addr) if resolve else ""

        entry = {
            "process": process,
            "pid": pid,
            "user": user,
            "local_port": local_port,
            "remote_addr": remote_addr,
            "remote_port": remote_port,
            "hostname": hostname,
            "c2_port": remote_port in C2_INDICATOR_PORTS,
        }
        connections.append(entry)

    return connections


def analyze(resolve: bool = False) -> dict:
    print(f"\n=== Connection Monitor: localhost ===")
    print(f"  Capturing established connections...\n")

    connections = get_connections(resolve)
    findings = []

    # Group by process
    by_process: dict[str, list] = {}
    for conn in connections:
        proc = conn["process"]
        by_process.setdefault(proc, []).append(conn)

    # Print summary
    for proc, conns in sorted(by_process.items(), key=lambda x: -len(x[1])):
        remotes = ", ".join(set(
            c.get("hostname") or c["remote_addr"] for c in conns[:3]
        ))
        print(f"  {proc:<30s} {len(conns):2d} connections  → {remotes}")

    # Flag C2 ports
    c2_connections = [c for c in connections if c.get("c2_port")]
    for conn in c2_connections:
        findings.append({
            "type": "C2_INDICATOR_PORT",
            "severity": "HIGH",
            "process": conn["process"],
            "remote": f"{conn['remote_addr']}:{conn['remote_port']}",
            "description": f"{conn['process']} connected to port {conn['remote_port']} — common C2/malware indicator",
            "guidance": "Investigate this process and its remote endpoint immediately",
        })

    # Flag unknown processes with many connections
    for proc, conns in by_process.items():
        if len(conns) > 20 and proc not in EXPECTED_PROCESSES:
            findings.append({
                "type": "HIGH_CONNECTION_COUNT",
                "severity": "MEDIUM",
                "process": proc,
                "count": len(conns),
                "description": f"{proc} has {len(conns)} connections — unusual for an unknown process",
                "guidance": "Verify this process is expected and check for data exfiltration",
            })

    return {
        "target": "localhost",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "total_connections": len(connections),
        "unique_processes": len(by_process),
        "c2_port_connections": len(c2_connections),
        "findings": findings,
        "connections": connections,
        "by_process_summary": {
            proc: len(conns) for proc, conns in by_process.items()
        },
    }


def main():
    resolve = "--resolve" in sys.argv
    result = analyze(resolve)

    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    output_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{date_str}-connection-monitor.json")

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n--- Summary ---")
    print(f"  Total connections: {result['total_connections']}")
    print(f"  Unique processes:  {result['unique_processes']}")
    if result["c2_port_connections"]:
        print(f"  🔴 C2 port connections: {result['c2_port_connections']}")
    for f in result["findings"]:
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(f["severity"], "⚪")
        print(f"  {icon} [{f['severity']}] {f['type']}: {f['process']}")
    print(f"\n  Full output: {output_file}")


if __name__ == "__main__":
    main()
