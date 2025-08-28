#!/usr/bin/env bash
# wazuh-agent-uninstall.sh
# Cleanly stop, purge, and remove Wazuh agent on Ubuntu 20.04/22.04/24.04

set -Eeuo pipefail

log="/var/log/wazuh-agent-uninstall.log"
exec > >(tee -a "$log") 2>&1

echo "[+] Checking privileges..."
if [[ $EUID -ne 0 ]]; then
  echo "[!] Run as root (sudo)."
  exit 1
fi

echo "[+] Detecting Ubuntu..."
. /etc/os-release || { echo "[!] Not Ubuntu?"; exit 1; }

echo "[+] Stopping agent if present..."
systemctl stop wazuh-agent 2>/dev/null || true
systemctl disable wazuh-agent 2>/dev/null || true

echo "[+] Purging package..."
apt-get update -y
apt-get purge -y wazuh-agent || true
apt-get autoremove -y || true

echo "[+] Removing residual files (best effort)..."
rm -rf /var/ossec \
       /etc/ossec-init.conf \
       /var/log/wazuh-agent* \
       /etc/systemd/system/wazuh-agent.service \
       /var/run/wazuh \
       /var/lib/wazuh-agent 2>/dev/null || true

echo "[+] Reloading systemd..."
systemctl daemon-reload || true

echo "[+] Done. Log: $log"
