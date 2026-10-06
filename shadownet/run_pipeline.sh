#!/usr/bin/env bash
set -euo pipefail

PCAP_PATH="${1:-/captures/session1.pcap}"
LOG_PATH="${2:-/logs/attack_log.txt}"
LABELS_PATH="${3:-/logs/labels.csv}"

echo "=========================================================="
echo "   ShadowNet: Automated Attack & Capture Pipeline         "
echo "=========================================================="

# 1. Clean previous run artifacts
echo "[*] Cleaning artifacts from previous runs..."
rm -f "$PCAP_PATH" "$LOG_PATH" "$LABELS_PATH"
mkdir -p "$(dirname "$PCAP_PATH")" "$(dirname "$LOG_PATH")" "$(dirname "$LABELS_PATH")"

# 2. Start tcpdump in background
echo "[1/4] Starting background tcpdump on eth0..."
TCPDUMP_LOG="$(dirname "$LOG_PATH")/tcpdump.log"
tcpdump -i eth0 -s 0 -n -U -w "$PCAP_PATH" > "$TCPDUMP_LOG" 2>&1 &
TCPDUMP_PID=$!
echo "[+] tcpdump running with PID: ${TCPDUMP_PID}"

# Trap termination signals to ensure tcpdump is cleanly killed if pipeline is cancelled
cleanup() {
    echo ""
    echo "[!] Caught interruption! Terminating tcpdump cleanly..."
    kill -2 "$TCPDUMP_PID" 2>/dev/null || true
    wait "$TCPDUMP_PID" 2>/dev/null || true
    exit 1
}
trap cleanup SIGINT SIGTERM

# Brief delay to ensure sniffer socket is bound
sleep 2

# Verify tcpdump didn't crash on startup
if ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then
    echo "[!] Error: tcpdump failed to start or exited prematurely!"
    if [ -f "$TCPDUMP_LOG" ]; then
        cat "$TCPDUMP_LOG"
    fi
    exit 1
fi

# 3. Execute Block 2 Attack Suite
echo "[2/4] Executing Attack Simulation Engine (Block 2)..."
if [ -f "/root/attacks/run_attacks.sh" ]; then
    bash /root/attacks/run_attacks.sh
elif [ -f "./attacker/run_attacks.sh" ]; then
    bash ./attacker/run_attacks.sh
else
    echo "[!] Error: run_attacks.sh not found!"
    kill -2 "$TCPDUMP_PID" 2>/dev/null || true
    exit 1
fi

# Brief delay to allow final TCP teardowns to complete
sleep 2

# 4. Gracefully terminate tcpdump
echo "[3/4] Stopping packet capture gracefully..."
kill -2 "$TCPDUMP_PID"
wait "$TCPDUMP_PID" 2>/dev/null || true
echo "[+] tcpdump terminated cleanly (buffers flushed)."

# 5. Generate Ground Truth Label CSV
echo "[4/4] Generating labels.csv from attack_log.txt..."
SCRIPT_DIR="/root/attacks/scripts"
if [ ! -d "$SCRIPT_DIR" ]; then
    SCRIPT_DIR="./scripts"
fi

python3 "$SCRIPT_DIR/generate_labels.py" "$LOG_PATH" "$LABELS_PATH"

# 6. Run PCAP Diagnostics
echo ""
bash "$SCRIPT_DIR/verify_pcap.sh" "$PCAP_PATH"

echo "=========================================================="
echo "   Pipeline Finished: PCAP and Labels Ready for ML        "
echo "=========================================================="
