#!/usr/bin/env bash
# Created By: Thomas Fosbenner (dotcomdewd@me.com)
# Wazuh SIEM all-in-one install + syslog + agent enrollment
# OS: Ubuntu/Debian (20.04/22.04/24.04 or recent Debian)
# Usage (defaults): sudo bash setup-wazuh.sh
# Customize:
#   SYSLOG_PORT=514 SYSLOG_PROTO=udp SYSLOG_CIDRS="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16" \
#   AGENT_PORT=1514 AUTHD_PORT=1515 DASHBOARD_PORT=5601 WAZUH_VERSION=4.9 sudo -E bash setup-wazuh.sh

set -euo pipefail

# -------- Config (overridable via env) --------
WAZUH_VERSION="${WAZUH_VERSION:-4.9}"     # major.minor that matches packages.wazuh.com path
SYSLOG_PORT="${SYSLOG_PORT:-514}"
SYSLOG_PROTO="${SYSLOG_PROTO:-udp}"       # udp|tcp
SYSLOG_CIDRS="${SYSLOG_CIDRS:-10.0.0.0/8,172.16.0.0/12,192.168.0.0/16}"

AGENT_PORT="${AGENT_PORT:-1514}"          # agent data (secure)
AUTHD_PORT="${AUTHD_PORT:-1515}"          # agent enrollment (authd)
API_PORT="${API_PORT:-55000}"             # Wazuh API (local)
DASHBOARD_PORT="${DASHBOARD_PORT:-5601}"  # Wazuh Dashboard

OSSEC_CONF="/var/ossec/etc/ossec.conf"

# -------- Helpers --------
msg(){ echo -e "\n\033[1;32m[+] $*\033[0m"; }
warn(){ echo -e "\n\033[1;33m[!] $*\033[0m"; }
err(){ echo -e "\n\033[1;31m[!] $*\033[0m" >&2; }

require_root(){
  if [[ $EUID -ne 0 ]]; then err "Run as root (sudo)."; exit 1; fi
}

detect_os(){
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS="$ID"
    VER="$VERSION_ID"
  else
    err "Cannot detect OS."
    exit 1
  fi
  case "$OS" in
    ubuntu|debian) : ;;
    *) err "Unsupported OS '$OS'. Use Ubuntu/Debian."; exit 1;;
  esac
}

port_in_use(){
  local proto="$1" port="$2"
  if command -v ss >/dev/null 2>&1; then
    if [[ "$proto" == "udp" ]]; then
      ss -lunp | awk '{print $5}' | grep -qE ":(^|)${port}$" || return 1
    else
      ss -lntp | awk '{print $4}' | grep -qE ":(^|)${port}$" || return 1
    fi
  else
    return 1
  fi
}

install_prereqs(){
  msg "Installing prerequisites"
  apt-get update -y
  apt-get install -y curl jq gnupg lsb-release xmlstarlet ufw
}

run_wazuh_official_installer(){
  msg "Fetching and running Wazuh official installer (all-in-one, v${WAZUH_VERSION}.x)"
  cd /tmp
  curl -sSLO "https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh"
  chmod +x ./wazuh-install.sh
  # -a => all-in-one (indexer + server + dashboard)
  ./wazuh-install.sh -a
}

backup_ossec_conf(){
  if [[ -f "$OSSEC_CONF" ]]; then
    cp -a "$OSSEC_CONF" "${OSSEC_CONF}.bak.$(date +%F_%H%M%S)"
  fi
}

xml_add_remote_secure_agent(){
  # Add/ensure <remote> for agent communications (secure over TCP)
  xmlstarlet ed -L \
    -d "/ossec_config/remote[connection='secure']" \
    -s "/ossec_config" -t elem -n "remoteTMP" -v "" \
    -s "/ossec_config/remoteTMP" -t elem -n "connection" -v "secure" \
    -s "/ossec_config/remoteTMP" -t elem -n "port" -v "${AGENT_PORT}" \
    -s "/ossec_config/remoteTMP" -t elem -n "protocol" -v "tcp" \
    -r "/ossec_config/remoteTMP" -v "remote" \
    "$OSSEC_CONF"
}

xml_add_remote_syslog(){
  # Add/ensure <remote> for syslog ingestion
  xmlstarlet ed -L \
    -d "/ossec_config/remote[connection='syslog']" \
    "$OSSEC_CONF"

  xmlstarlet ed -L \
    -s "/ossec_config" -t elem -n "remoteTMP2" -v "" \
    -s "/ossec_config/remoteTMP2" -t elem -n "connection" -v "syslog" \
    -s "/ossec_config/remoteTMP2" -t elem -n "port" -v "${SYSLOG_PORT}" \
    -s "/ossec_config/remoteTMP2" -t elem -n "protocol" -v "${SYSLOG_PROTO}" \
    -r "/ossec_config/remoteTMP2" -v "remote" \
    "$OSSEC_CONF"

  IFS=',' read -r -a CIDRS <<< "$SYSLOG_CIDRS"
  for c in "${CIDRS[@]}"; do
    xmlstarlet ed -L \
      -s "/ossec_config/remote[connection='syslog']" -t elem -n "allowed-ips" -v "${c// /}" \
      "$OSSEC_CONF"
  done
}

xml_enable_authd(){
  # Enable agent enrollment service
  if xmlstarlet sel -t -c "/ossec_config/auth" "$OSSEC_CONF" >/dev/null 2>&1; then
    xmlstarlet ed -L \
      -u "/ossec_config/auth/enabled" -v "yes" \
      -u "/ossec_config/auth/port" -v "${AUTHD_PORT}" \
      "$OSSEC_CONF" || true
  else
    xmlstarlet ed -L \
      -s "/ossec_config" -t elem -n "auth" -v "" \
      -s "/ossec_config/auth" -t elem -n "enabled" -v "yes" \
      -s "/ossec_config/auth" -t elem -n "port" -v "${AUTHD_PORT}" \
      -s "/ossec_config/auth" -t elem -n "use_source_ip" -v "yes" \
      -s "/ossec_config/auth" -t elem -n "force" -v "yes" \
      -s "/ossec_config/auth" -t elem -n "purge" -v "no" \
      "$OSSEC_CONF"
  fi
}

open_firewall(){
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    msg "Configuring UFW rules"
    ufw allow "${AGENT_PORT}/tcp"   || true   # Agent data (secure)
    ufw allow "${AUTHD_PORT}/tcp"   || true   # Agent enrollment
    ufw allow "${SYSLOG_PORT}/${SYSLOG_PROTO}" || true  # Syslog ingestion
    ufw allow "${DASHBOARD_PORT}/tcp" || true  # Dashboard (optional; you may restrict)
  else
    warn "UFW not active. Ensure the following ports are reachable as needed:
      - ${AGENT_PORT}/tcp (agents)
      - ${AUTHD_PORT}/tcp (agent enrollment)
      - ${SYSLOG_PORT}/${SYSLOG_PROTO} (syslog senders)
      - ${DASHBOARD_PORT}/tcp (dashboard - optional, can be local only)"
  fi
}

restart_wazuh(){
  msg "Restarting Wazuh manager"
  systemctl restart wazuh-manager
  sleep 3
  systemctl --no-pager --full status wazuh-manager || true
}

print_summary(){
  HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
  msg "Done!

Wazuh Dashboard:  http://${HOST_IP}:${DASHBOARD_PORT}
  (If remote access is not desired, restrict via firewall or bind locally.)

Agent enrollment (Linux example from an endpoint):
  # On the agent host
  curl -s https://packages.wazuh.com/${WAZUH_VERSION}/install.sh -o /tmp/wazuh-agent-install.sh
  sudo bash /tmp/wazuh-agent-install.sh --install-agent \
       --manager ${HOST_IP} --port ${AGENT_PORT} \
       --authd_server ${HOST_IP} --authd_port ${AUTHD_PORT}

Syslog senders (rsyslog example on a remote syslog server):
  # /etc/rsyslog.d/90-wazuh.conf
  *.*  @${HOST_IP}:${SYSLOG_PORT}   # UDP
  # or for TCP:  *.*  @@${HOST_IP}:${SYSLOG_PORT}
  systemctl restart rsyslog

If you previously saw 'Cannot find the ID of the agent' warnings,
that means the endpoint was talking like a Wazuh agent without being enrolled.
For pure syslog, make sure the device is sending plain syslog to ${SYSLOG_PROTO^^}/${SYSLOG_PORT};
for agents, enroll them (see above).

Config files backed up at: ${OSSEC_CONF}.bak.*
"
}

main(){
  require_root
  detect_os
  install_prereqs

  if port_in_use "$SYSLOG_PROTO" "$SYSLOG_PORT"; then
    warn "Something is already listening on ${SYSLOG_PROTO}/${SYSLOG_PORT}. If it's rsyslog,
         either disable its network input or change SYSLOG_PORT before rerunning."
  fi

  run_wazuh_official_installer

  if [[ ! -f "$OSSEC_CONF" ]]; then
    err "Wazuh manager config not found at $OSSEC_CONF. Aborting."
    exit 1
  fi

  backup_ossec_conf
  xml_add_remote_secure_agent
  xml_add_remote_syslog
  xml_enable_authd
  open_firewall
  restart_wazuh
  print_summary
}

main "$@"
