#!/usr/bin/env bash
# wazuh-stack-helper.sh
# One-stop installer / upgrader / uninstaller for Wazuh (single-node) on Ubuntu.
# - Installs latest 4.x Wazuh stack using the official Wazuh install script
# - Adds Wazuh apt repo for future upgrades
# - Can upgrade current stack to latest 4.x
# - Can uninstall & purge Wazuh components and configs (with optional backup)
#
# Notes:
# * Requires root
# * Supports Ubuntu 20.04/22.04/24.04
# * Logs to /var/log/wazuh-stack-helper.log
#
# v1.0

set -Eeuo pipefail

LOG_FILE="/var/log/wazuh-stack-helper.log"
exec > >(tee -a "$LOG_FILE") 2>&1

WAZUH_KEYRING="/etc/apt/keyrings/wazuh.gpg"
WAZUH_LIST="/etc/apt/sources.list.d/wazuh.list"
WAZUH_APT_LINE='deb [signed-by=/etc/apt/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main'
WAZUH_KEY_URL="https://packages.wazuh.com/key/GPG-KEY-WAZUH"
WAZUH_INSTALLER_URL="https://packages.wazuh.com/4.x/wazuh-install.sh"

#---- Helpers ---------------------------------------------------------------

err()  { echo -e "\n[!] ERROR: $*\n" >&2; }
ok()   { echo -e "[+] $*"; }
info() { echo -e "[-] $*"; }

on_error() {
  err "Script failed on line ${BASH_LINENO[0]} (command: ${BASH_COMMAND})"
  err "See log: $LOG_FILE"
}
trap on_error ERR

require_root() {
  if [[ $EUID -ne 0 ]]; then
    err "Please run as root (sudo)."
    exit 1
  fi
}

check_ubuntu() {
  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    case "${ID}-${VERSION_ID}" in
      ubuntu-20.04|ubuntu-22.04|ubuntu-24.04) ok "Detected $PRETTY_NAME";;
      ubuntu-*) info "Detected $PRETTY_NAME (untested but will try).";;
      *) err "This script targets Ubuntu 20.04/22.04/24.04."; exit 1;;
    esac
  else
    err "/etc/os-release not found. Are you on Ubuntu?"
    exit 1
  fi
}

apt_update_quiet() {
  info "Updating apt package lists..."
  apt-get update -y
}

ensure_prereqs() {
  ok "Installing prerequisites..."
  mkdir -p /etc/apt/keyrings
  apt-get update -y
  apt-get install -y --no-install-recommends \
    ca-certificates curl gnupg lsb-release apt-transport-https \
    jq unzip tar coreutils ufw
}

ensure_wazuh_repo() {
  if [[ ! -f "$WAZUH_KEYRING" ]]; then
    ok "Adding Wazuh GPG key..."
    curl -fsSL "$WAZUH_KEY_URL" | gpg --dearmor -o "$WAZUH_KEYRING"
    chmod 0644 "$WAZUH_KEYRING"
  else
    info "Wazuh keyring already present."
  fi

  if [[ ! -f "$WAZUH_LIST" ]] || ! grep -q "packages.wazuh.com/4.x/apt" "$WAZUH_LIST"; then
    ok "Adding Wazuh apt repository..."
    echo "$WAZUH_APT_LINE" > "$WAZUH_LIST"
    chmod 0644 "$WAZUH_LIST"
    apt_update_quiet
  else
    info "Wazuh apt repository already configured."
  fi
}

detect_installed() {
  local any=0
  dpkg -l | awk '/^ii/ && /(wazuh-(manager|indexer|dashboard))/ {print $2" "$3}' || true
  dpkg -l | grep -Eq '^ii\s+wazuh-manager' && any=1 || true
  dpkg -l | grep -Eq '^ii\s+wazuh-indexer' && any=1 || true
  dpkg -l | grep -Eq '^ii\s+wazuh-dashboard' && any=1 || true
  return $any
}

confirm() {
  local prompt="${1:-Are you sure?} [y/N]: "
  read -r -p "$prompt" ans || true
  [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]]
}

maybe_open_ufw_ports() {
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    echo
    info "UFW is active. Open common Wazuh ports?"
    echo "  - 1514/tcp (Agent/Events), 1514/udp (Syslog), 1515/tcp (Agent enrollment)"
    echo "  - 55000/tcp (Wazuh API), 5601/tcp (Dashboard)"
    if confirm "Open these UFW ports now?"; then
      ufw allow 1514/tcp || true
      ufw allow 1514/udp || true
      ufw allow 1515/tcp || true
      ufw allow 55000/tcp || true
      ufw allow 5601/tcp || true
      ok "UFW rules added."
    else
      info "Skipping UFW changes."
    fi
  fi
}

service_exists() {
  systemctl list-unit-files | grep -q "^$1\.service" || return 1
}

stop_wazuh_services() {
  info "Stopping Wazuh services (if running)..."
  for svc in wazuh-manager wazuh-indexer wazuh-dashboard; do
    if service_exists "$svc"; then
      systemctl stop "$svc" || true
      systemctl disable "$svc" || true
    fi
  done
}

#---- Actions ---------------------------------------------------------------

do_install() {
  ok "=== INSTALL: Wazuh single-node (latest 4.x) ==="
  ensure_prereqs
  ensure_wazuh_repo

  # Fetch official installer
  local installer="/tmp/wazuh-install.sh"
  ok "Downloading Wazuh official installer..."
  curl -fsSL "$WAZUH_INSTALLER_URL" -o "$installer"
  chmod +x "$installer"

  echo
  info "You can set a Dashboard admin password now (leave empty for auto/default)."
  read -r -s -p "Dashboard admin password (optional): " DASH_PW || true
  echo

  # Run the official all-in-one installer
  ok "Running Wazuh installer (this may take a while)..."
  if [[ -n "${DASH_PW:-}" ]]; then
    # Some installer revisions accept -p <password> for dashboard admin.
    # If not supported, it will ignore the flag and fall back to interactive/default.
    bash "$installer" -a -p "$DASH_PW"
  else
    bash "$installer" -a
  fi

  maybe_open_ufw_ports

  ok "Install complete."
  echo
  info "Useful bits:"
  echo "  - Dashboard:        http(s)://<this-host>:5601/   (or as printed by installer)"
  echo "  - Wazuh API port:   55000/tcp"
  echo "  - Credentials file: /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml (and/or installer output)"
  echo "  - Manager dir:      /var/ossec"
  echo "  - Indexer configs:  /etc/wazuh-indexer"
  echo
}

do_upgrade() {
  ok "=== UPGRADE: Wazuh to latest 4.x via apt ==="
  ensure_prereqs
  ensure_wazuh_repo

  if ! detect_installed; then
    err "No Wazuh packages appear installed. Choose Install instead."
    return 1
  fi

  info "Current Wazuh packages:"
  dpkg -l | awk '/^ii/ && /(wazuh-(manager|indexer|dashboard))/ {printf "  - %-20s %s\n",$2,$3}' || true
  echo

  if ! confirm "Proceed with apt upgrade of wazuh-* packages?"; then
    info "Upgrade cancelled."
    return 0
  fi

  apt_update_quiet
  # Only-upgrade avoids new installs if components are missing.
  ok "Upgrading wazuh packages..."
  apt-get install -y --only-upgrade wazuh-manager wazuh-indexer wazuh-dashboard || true

  # If any were not present, try full upgrade path
  info "Ensuring all core components are up-to-date..."
  apt-get install -y wazuh-manager wazuh-indexer wazuh-dashboard

  ok "Restarting services..."
  systemctl daemon-reload || true
  systemctl enable wazuh-indexer wazuh-manager wazuh-dashboard || true
  systemctl restart wazuh-indexer || true
  systemctl restart wazuh-manager || true
  systemctl restart wazuh-dashboard || true

  ok "Upgrade routine complete."
  systemctl --no-pager --full status wazuh-manager || true
}

do_uninstall() {
  ok "=== UNINSTALL: Purge Wazuh stack ==="

  # Offer backup
  echo
  info "You may want to back up configs/data before removal:"
  echo "  - /var/ossec"
  echo "  - /etc/wazuh-indexer  /var/lib/wazuh-indexer  /usr/share/wazuh-indexer"
  echo "  - /etc/wazuh-dashboard /usr/share/wazuh-dashboard"
  if confirm "Create a tar.gz backup in /root/wazuh-backup-$(date +%F).tgz first?"; then
    local bfile="/root/wazuh-backup-$(date +%F).tgz"
    tar -czf "$bfile" \
      /var/ossec \
      /etc/wazuh-indexer /var/lib/wazuh-indexer /usr/share/wazuh-indexer \
      /etc/wazuh-dashboard /usr/share/wazuh-dashboard \
      2>/dev/null || true
    ok "Backup (best-effort) at: $bfile"
  fi

  stop_wazuh_services

  ok "Purging packages..."
  apt-get purge -y wazuh-manager wazuh-indexer wazuh-dashboard || true
  apt-get autoremove -y || true

  ok "Removing residual files..."
  rm -rf /var/ossec \
         /etc/wazuh-indexer /var/lib/wazuh-indexer /usr/share/wazuh-indexer \
         /etc/wazuh-dashboard /usr/share/wazuh-dashboard \
         /var/log/wazuh* /var/lib/wazuh* /etc/systemd/system/wazuh* 2>/dev/null || true

  if [[ -f "$WAZUH_LIST" ]]; then
    if confirm "Remove the Wazuh apt repo and key as well?"; then
      rm -f "$WAZUH_LIST"
      rm -f "$WAZUH_KEYRING"
      apt_update_quiet
      ok "Repo and key removed."
    fi
  fi

  ok "Uninstall complete."
}

show_status() {
  ok "=== STATUS ==="
  echo "Date: $(date)"
  echo "Host: $(hostname -f 2>/dev/null || hostname)"
  echo
  info "Installed Wazuh packages:"
  dpkg -l | awk '/^ii/ && /(wazuh-(manager|indexer|dashboard))/ {printf "  - %-20s %s\n",$2,$3}' || echo "  (none)"
  echo
  info "Service states:"
  for svc in wazuh-indexer wazuh-manager wazuh-dashboard; do
    if service_exists "$svc"; then
      systemctl is-active --quiet "$svc" && st=active || st=inactive
      printf "  - %-16s %s\n" "$svc" "$st"
    fi
  done
  echo
  info "Repo presence:"
  [[ -f "$WAZUH_LIST" ]] && echo "  - $WAZUH_LIST exists" || echo "  - Wazuh apt repo not configured"
  [[ -f "$WAZUH_KEYRING" ]] && echo "  - $WAZUH_KEYRING exists" || echo "  - Wazuh GPG key not present"
  echo
}

menu() {
  echo
  echo "==================== Wazuh Stack Helper ===================="
  echo "1) Install latest Wazuh (single-node: Indexer + Manager + Dashboard)"
  echo "2) Upgrade Wazuh to latest 4.x (via apt)"
  echo "3) Uninstall / Purge Wazuh"
  echo "4) Status / Info"
  echo "5) Exit"
  echo "============================================================"
  read -r -p "Choose an option [1-5]: " choice || true
  case "${choice:-}" in
    1) do_install ;;
    2) do_upgrade ;;
    3) do_uninstall ;;
    4) show_status ;;
    5) exit 0 ;;
    *) echo "Invalid choice";;
  esac
}

#---- Main ------------------------------------------------------------------

require_root
check_ubuntu
ensure_prereqs

# Non-interactive flags (optional):
#   --install, --upgrade, --uninstall, --status
if [[ "${1:-}" == "--install" ]]; then
  do_install
  exit 0
elif [[ "${1:-}" == "--upgrade" ]]; then
  do_upgrade
  exit 0
elif [[ "${1:-}" == "--uninstall" ]]; then
  do_uninstall
  exit 0
elif [[ "${1:-}" == "--status" ]]; then
  show_status
  exit 0
fi

while true; do
  menu
  echo
  if ! confirm "Return to menu?"; then
    break
  fi
done

ok "Done. Log saved at: $LOG_FILE"
