#!/usr/bin/env bash
# ============================================================================
# BARON NEXUS — Kali Linux Local Network Security Agent Setup & Runner
# Supports rootless CAP_NET_RAW capability grant or standard TCP Connect mode
# ============================================================================
set -euo pipefail

echo "[*] Baron Nexus — Kali Linux Local Network Security Assessment Setup"
echo "[*] Checking required system packages (nmap, python3-venv, libpcap0.8)..."

if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -qq
  sudo apt-get install -y nmap python3 python3-venv python3-pip iproute2 net-tools libpcap0.8
fi

VENV_DIR="./.venv-kali-agent"
if [ ! -d "$VENV_DIR" ]; then
  echo "[*] Creating isolated Python virtual environment at $VENV_DIR..."
  python3 -m venv "$VENV_DIR"
fi

echo "[*] Installing Python dependencies from requirements.txt..."
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install -r requirements.txt

echo "[*] Optional: Granting CAP_NET_RAW to nmap binary for safe non-root SYN/ARP discovery..."
if command -v setcap >/dev/null 2>&1 && [ -x /usr/bin/nmap ]; then
  sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap || true
fi

echo "[+] Starting Baron Nexus FastAPI Local Network Security Engine on 127.0.0.1:8090..."
exec "$VENV_DIR/bin/uvicorn" main:app --host 127.0.0.1 --port 8090 --reload
