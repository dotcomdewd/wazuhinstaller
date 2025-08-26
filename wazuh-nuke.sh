#!/usr/bin/env bash
# wazuh-nuke.sh — full uninstall of Wazuh + Filebeat leftovers, with optional clean reinstall
# OS: Ubuntu/Debian
# Usage:
#   sudo bash wazuh-nuke.sh
#   sudo bash wazuh-nuke.sh --no-backup
#   sudo bash wazuh-nuke.sh --reinstall               # clean reinstall after uninstall
#   sudo WAZUH_VERSION=4.9 bash wazuh-nuke.sh --reinstall
#   sudo bash wazuh-nuke.sh --reinstall --overwrite   # runs installer with --overwrite
#
# Notes:
# - Creates /root/wazuh-uninstall-backup-<ts>.tgz unless --no-backup is used.
# - Reinstall uses official all-in-one installer (manager+indexer+dashboard).

set -euo pipefail

NO_BACKUP=0
DO_REINSTALL=0
OVERWRITE=0
WAZUH_VERSION="${WAZUH_VERSION:-4.9}" # path segment on packages.wazuh.com (e.g., 4.9 or 4.x)

msg(){ echo -e "\033[1;32m[+] $*\033[0m"; }
warn(){ echo -e "\033[1;33m[!] $*\033[0m"; }
err(){ echo -e "\033[1;31m[!] $*\033[0m" >&2; }

require_root(){ [[ $EUID -eq 0 ]] || { err "Run as root (sudo)."; exit 1; }; }

for a in "$@"; do
  case "$a" in
    --no-backup) NO_BACKUP=1;;
    --reinstall) DO_REINSTALL=1;;
    --overwrite) OVERWRITE=1;;
    *) err "Unknown arg: $a"; exit 1;;
  esac
done

confirm(){
  read -r -p "This will COMPLETELY remove Wazuh & Filebeat data. Continue? [y/N] " ans
  [[ "${ans:-N}" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 1; }
}

stop_disable(){
  local svc
  for svc in wazuh-manager wazuh-indexer wazuh-dashboard wazuh-agent filebeat; do
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
    systemctl reset-failed "$svc" 2>/dev/null || true
  done
}

backup(){
  (( NO_BACKUP == 1 )) && { warn "Skipping backup (--no-backup)."; return; }
  local ts archive
  ts="$(date +%F-%H%M%S)"
  archive="/root/wazuh-uninstall-backup-${ts}.tgz"
  msg "Creating backup at $archive (may be large)…"
  tar czf "$archive" --ignore-failed-read \
    /var/ossec \
    /etc/wazuh* \
    /var/lib/wazuh* \
    /var/log/wazuh* \
    /usr/share/wazuh* \
    /etc/filebeat \
    /var/lib/filebeat \
    /var/log/filebeat \
    2>/dev/null || true
  echo "Backup (if any paths existed): $archive"
}

purge_packages(){
  msg "Fixing dpkg/apt state if wedged"
  dpkg --configure -a || true
  apt-get -f install -y || true

  msg "Purging Wazuh & Filebeat packages"
  # Try both normal purge and forced removal if half-installed
  DEBIAN_FRONTEND=noninteractive apt-get purge -y \
    wazuh-manager wazuh-indexer wazuh-dashboard wazuh-agent \
    wazuh-filebeat filebeat || true

  dpkg --remove --force-remove-reinstreq \
    wazuh-manager wazuh-indexer wazuh-dashboard wazuh-agent \
    wazuh-filebeat filebeat 2>/dev/null || true

  dpkg --purge \
    wazuh-manager wazuh-indexer wazuh-dashboard wazuh-agent \
    wazuh-filebeat filebeat 2>/dev/null || true
}

delete_units(){
  msg "Removing systemd unit files (if present) & reloading"
  rm -f /etc/systemd/system/{wazuh-manager,wazuh-indexer,wazuh-dashboard,wazuh-agent,filebeat}.service
  rm -f /lib/systemd/system/{wazuh-manager,wazuh-indexer,wazuh-dashboard,wazuh-agent,filebeat}.service
  systemctl daemon-reload
}

remove_repos_keys(){
  msg "Removing Wazuh apt repos & keys"
  rm -f /etc/apt/sources.list.d/wazuh*.list
  rm -f /usr/share/keyrings/wazuh*.gpg
  rm -f /etc/apt/trusted.gpg.d/wazuh*.gpg
  apt-get update -y || true
}

remove_users_groups(){
  msg "Deleting service users/groups (ignore if absent)"
  for u in ossec wazuh wazuh-indexer wazuh-dashboard filebeat; do
    getent passwd "$u" >/dev/null && userdel -f "$u" 2>/dev/null || true
    getent group  "$u" >/dev/null && groupdel "$u" 2>/dev/null || true
  done
}

wipe_files(){
  msg "Deleting residual directories"
  rm -rf \
    /var/ossec \
    /etc/wazuh-indexer /etc/wazuh-manager /etc/wazuh-dashboard \
    /var/lib/wazuh-indexer /var/lib/wazuh-manager /var/lib/wazuh-dashboard \
    /var/log/wazuh-indexer /var/log/wazuh-manager /var/log/wazuh-dashboard \
    /usr/share/wazuh-indexer /usr/share/wazuh-manager /usr/share/wazuh-dashboard \
    /usr/share/wazuh-alerts /usr/share/wazuh-api \
    /etc/filebeat /var/lib/filebeat /var/log/filebeat /usr/share/filebeat

  # Just in case other paths were used
  find / -xdev -type d -name "filebeat" 2>/dev/null | xargs -r rm -rf
}

apt_cleanup(){
  msg "Apt cleanup"
  apt-get autoremove -y || true
  apt-get autoclean -y || true
}

reinstall(){
  msg "Downloading Wazuh all-in-one installer (v${WAZUH_VERSION}.x)"
  cd /tmp
  curl -sSLO "https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh"
  chmod +x ./wazuh-install.sh

  msg "Running installer"
  if (( OVERWRITE == 1 )); then
    ./wazuh-install.sh -a --overwrite
  else
    ./wazuh-install.sh -a
  fi

  msg "Install finished. Dashboard and services should be up."
}

main(){
  require_root
  confirm

  stop_disable
  backup
  purge_packages
  delete_units
  remove_repos_keys
  remove_users_groups
  wipe_files
  apt_cleanup

  msg "Wazuh/Filebeat have been fully removed."
  if (( DO_REINSTALL == 1 )); then
    reinstall
  else
    echo
    echo "Next steps (manual reinstall):"
    echo "  cd /tmp && curl -sSLO https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh && chmod +x wazuh-install.sh && sudo ./wazuh-install.sh -a"
    echo "  (Add --overwrite if the installer detects remnants.)"
  fi
}

main
