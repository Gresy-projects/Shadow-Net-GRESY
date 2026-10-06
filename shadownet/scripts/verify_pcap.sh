#!/usr/bin/env bash
set -euo pipefail

PCAP_FILE="${1:-/captures/session1.pcap}"

# Fallback to local path if default container path is missing
if [ ! -f "$PCAP_FILE" ] && [ -f "captures/session1.pcap" ]; then
    PCAP_FILE="captures/session1.pcap"
fi

echo "=== Verifying PCAP Capture: ${PCAP_FILE} ==="

if [ ! -f "$PCAP_FILE" ]; then
    echo "[!] Error: PCAP file '${PCAP_FILE}' does not exist!"
    exit 1
fi

FILE_SIZE=$(du -h "$PCAP_FILE" | awk '{print $1}')
echo "[+] File Size: ${FILE_SIZE}"

# 1. Inspect first 10 packets
echo ""
echo "--- Sample Packets (First 10) ---"
tcpdump -nn -r "$PCAP_FILE" -c 10

# 2. Count packets involving the target DVWA (10.10.0.10)
TOTAL_PACKETS=$(tcpdump -nn -r "$PCAP_FILE" 2>/dev/null | wc -l | awk '{print $1}')
DVWA_PACKETS=$(tcpdump -nn -r "$PCAP_FILE" "host 10.10.0.10" 2>/dev/null | wc -l | awk '{print $1}')
TOTAL_PACKETS=${TOTAL_PACKETS:-0}
DVWA_PACKETS=${DVWA_PACKETS:-0}

echo ""
echo "--- Traffic Summary ---"
echo "Total Captured Packets : ${TOTAL_PACKETS}"
echo "Packets Involving DVWA : ${DVWA_PACKETS}"

if [ "$DVWA_PACKETS" -gt 50 ]; then
    echo "[+] Verification SUCCESS: PCAP contains valid multi-attack traffic."
else
    echo "[!] WARNING: Abnormally low packet count (${DVWA_PACKETS}). Check if simulation executed properly."
fi
