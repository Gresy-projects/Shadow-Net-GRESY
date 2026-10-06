#!/usr/bin/env python3
"""
generate_labels.py — Parses attack_log.txt and outputs labels.csv.
Part of ShadowNet Block 3: Capture & Labeling Pipeline.
"""

import sys
import os
import csv

DEFAULT_LOG = "/logs/attack_log.txt"
DEFAULT_OUT = "/logs/labels.csv"

# Fallback relative paths if running outside Docker container
HOST_FALLBACK_LOG = "logs/attack_log.txt"
HOST_FALLBACK_OUT = "logs/labels.csv"

# Metadata enrichment mapping for attack classes
ATTACK_METADATA = {
    "nmap_scan": {
        "category": "Reconnaissance",
        "target_port": "1-1000",
        "protocol": "TCP"
    },
    "hydra_bruteforce": {
        "category": "Credential_Access",
        "target_port": "80",
        "protocol": "TCP/HTTP"
    },
    "sqlmap_sqli": {
        "category": "Exploitation",
        "target_port": "80",
        "protocol": "TCP/HTTP"
    }
}

def resolve_path(cli_path, default_path, fallback_path):
    if cli_path:
        return cli_path
    if os.path.exists(default_path):
        return default_path
    if os.path.exists(fallback_path):
        return fallback_path
    return default_path

def parse_logs(log_path, out_path, attacker_ip="10.10.0.20", target_ip="10.10.0.10"):
    if not os.path.exists(log_path):
        print(f"[!] Error: Log file {log_path} not found.")
        sys.exit(1)

    attacks = []
    current_attack = None

    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 3:
                continue

            action, attack_name, timestamp = parts[0], parts[1], parts[2]

            if action == "START":
                current_attack = {"name": attack_name, "start": timestamp, "end": None}
                attacks.append(current_attack)
            elif action == "END":
                if current_attack and current_attack["name"] == attack_name and current_attack["end"] is None:
                    current_attack["end"] = timestamp
                else:
                    for att in reversed(attacks):
                        if att["name"] == attack_name and att["end"] is None:
                            att["end"] = timestamp
                            break

    # Write output CSV
    fieldnames = [
        "attack_type",
        "category",
        "start_time",
        "end_time",
        "source_ip",
        "target_ip",
        "target_port",
        "protocol"
    ]

    out_dir = os.path.dirname(os.path.abspath(out_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(out_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for attack in attacks:
            meta = ATTACK_METADATA.get(attack["name"], {
                "category": "Unknown",
                "target_port": "any",
                "protocol": "IP"
            })
            writer.writerow({
                "attack_type": attack["name"],
                "category": meta["category"],
                "start_time": attack["start"],
                "end_time": attack["end"] or attack["start"],
                "source_ip": attacker_ip,
                "target_ip": target_ip,
                "target_port": meta["target_port"],
                "protocol": meta["protocol"]
            })

    print(f"[+] Ground-truth labels successfully generated: {out_path}")

if __name__ == "__main__":
    cli_log = sys.argv[1] if len(sys.argv) > 1 else None
    cli_out = sys.argv[2] if len(sys.argv) > 2 else None

    log_p = resolve_path(cli_log, DEFAULT_LOG, HOST_FALLBACK_LOG)
    out_p = resolve_path(cli_out, DEFAULT_OUT, HOST_FALLBACK_OUT)

    parse_logs(log_p, out_p)
