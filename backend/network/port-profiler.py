#!/usr/bin/env python3
# port-profiler.py
# What: Profiles listening ports on the local machine or a remote host.
#       Local mode: uses lsof to get process-bound ports with owner info.
#       Remote mode: probes a defined set of common ports via socket connect (no nmap).
# When to use: Network audit — identify unexpected services, verify firewall posture.
# Expected output: JSON to backend/outputs/YYYY-MM-DD-port-profiler-<host>.json
#
# Usage:
#   python3 port-profiler.py               # local machine
#   python3 port-profiler.py <hostname>    # remote host (passive probe)

import sys
import json
import subprocess
import socket
import datetime
import os

# Common ports to probe on remote hosts
REMOTE_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    8888: "HTTP-dev",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

SUSPICIOUS_LOCAL_PORTS = {4444, 1337, 31337, 6666, 6667, 5555, 9999, 12345}

RISK_BY_SERVICE = {
    "FTP": ("HIGH", "FTP transmits credentials in plaintext"),
    "Telnet": ("CRITICAL", "Telnet is unencrypted — replace with SSH"),
    "SMB": ("HIGH", "SMB exposed externally — common ransomware vector"),
    "RDP": ("HIGH", "RDP exposed — common brute-force target"),
    "Redis": ("HIGH", "Redis often has no auth by default"),
    "Elasticsearch": ("HIGH", "Elasticsearch often has no auth by default"),
    "MongoDB": ("HIGH", "MongoDB often has no auth by default"),
    "VNC": ("HIGH", "VNC exposed — weak auth common"),
}


def scan_local() -> dict:
    """Use lsof to list listening ports on the local machine."""
    try:
        result = subprocess.run(
            ["lsof", "-iTCP", "-sTCP:LISTEN", "-P", "-n"],
            capture_output=True, text=True, timeout=15
        )
        lines = result.stdout.strip().splitlines()
        ports = []
        seen = set()

        for line in lines[1:]:  # skip header
            parts = line.split()
            if len(parts) < 9:
                continue
            process = parts[0]
            pid = parts[1]
            user = parts[2]
            addr = parts[8]

            # Parse address like *:8080 or 127.0.0.1:3000
            if ":" in addr:
                port_str = addr.rsplit(":", 1)[-1]
                bind_addr = addr.rsplit(":", 1)[0]
                try:
                    port = int(port_str)
                except ValueError:
                    continue
            else:
                continue

            key = (port, process)
            if key in seen:
                continue
            seen.add(key)

            entry = {
                "port": port,
                "process": process,
                "pid": pid,
                "user": user,
                "bind_address": bind_addr,
                "external": bind_addr in ("*", "0.0.0.0", "::"),
            }

            if port in SUSPICIOUS_LOCAL_PORTS:
                entry["suspicious"] = True
                entry["note"] = "Port commonly used by malware/C2 frameworks"

            ports.append(entry)

        return {"mode": "local", "ports": ports}

    except Exception as e:
        return {"mode": "local", "error": str(e), "ports": []}


def probe_remote(host: str) -> dict:
    """Socket-connect probe on common ports."""
    open_ports = []
    print(f"  Probing {len(REMOTE_PORTS)} common ports on {host}...")

    for port, service in REMOTE_PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                open_ports.append({"port": port, "service": service, "state": "open"})
                print(f"    ✅ {port:5d}/{service}")
        except Exception:
            pass

    return {"mode": "remote", "host": host, "open_ports": open_ports}


def analyze(target: str | None) -> dict:
    findings = []

    if target is None:
        print(f"\n=== Port Profiler: localhost ===\n")
        scan = scan_local()
        ports = scan.get("ports", [])

        external_ports = [p for p in ports if p.get("external")]
        suspicious = [p for p in ports if p.get("suspicious")]

        for p in suspicious:
            findings.append({
                "type": "SUSPICIOUS_PORT",
                "severity": "HIGH",
                "port": p["port"],
                "process": p["process"],
                "description": f"Port {p['port']} ({p['process']}) is commonly used by malware/C2",
                "guidance": "Investigate this process — verify it is expected",
            })

        print(f"\n  Listening ports: {len(ports)}")
        print(f"  External (0.0.0.0/*): {len(external_ports)}")
        for p in external_ports[:10]:
            flag = "⚠️ " if p.get("suspicious") else "  "
            print(f"  {flag}{p['port']:5d} {p['process']:<20s} [{p['user']}] {p['bind_address']}")

        result = {
            "target": "localhost",
            "mode": "local",
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "total_listening": len(ports),
            "external_ports": len(external_ports),
            "suspicious_ports": len(suspicious),
            "ports": ports,
            "findings": findings,
        }

    else:
        print(f"\n=== Port Profiler: {target} ===\n")
        scan = probe_remote(target)
        open_ports = scan.get("open_ports", [])

        for p in open_ports:
            service = p["service"]
            if service in RISK_BY_SERVICE:
                severity, desc = RISK_BY_SERVICE[service]
                findings.append({
                    "type": f"RISKY_SERVICE_{service.upper().replace('-', '_')}",
                    "severity": severity,
                    "port": p["port"],
                    "service": service,
                    "description": f"Port {p['port']} ({service}) is open: {desc}",
                    "guidance": f"Restrict access to {service} — firewall or disable if unused",
                })

        print(f"\n  Open ports: {len(open_ports)}")
        s = {
            "critical": len([f for f in findings if f["severity"] == "CRITICAL"]),
            "high": len([f for f in findings if f["severity"] == "HIGH"]),
        }
        print(f"  Risky services: {s['critical']} critical, {s['high']} high")

        result = {
            "target": target,
            "mode": "remote",
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "open_ports": open_ports,
            "findings": findings,
        }

    return result


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else None
    slug = target if target else "localhost"
    result = analyze(target)

    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    output_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{date_str}-port-profiler-{slug}.json")

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n  Full output: {output_file}")


if __name__ == "__main__":
    main()
