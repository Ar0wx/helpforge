#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-192.168.56.102}"

echo "[*] HelpForge manual-solve reference"
echo "[*] Target: ${TARGET}"
echo "[*] The full solution path is documented in the separate writeup ZIP."
echo "[*] Quick service check:"
echo "    curl -I http://${TARGET}/"
echo "    nmap -sV -p21,22,80,3306 ${TARGET}"
