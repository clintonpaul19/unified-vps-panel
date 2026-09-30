#!/usr/bin/env bash
set -e
printf 'IP: '; curl -4fsS --max-time 3 https://api.ipify.org || true; echo
printf 'Hostname: '; hostname -f 2>/dev/null || hostname
if [ -f /etc/unified-vps/panel.env ]; then . /etc/unified-vps/panel.env; printf 'Domain: '; echo "${SERVER_DOMAIN:-not configured}"; fi
. /etc/os-release; echo "OS: $PRETTY_NAME"; uptime -p
for s in ssh nginx haproxy xray hysteria-server unified-vps-panel unified-vps-wstunnel-ssh unified-vps-ws-payload-ssh fail2ban; do state="$(systemctl is-active "$s" 2>/dev/null || true)"; [ -n "$state" ] || state=inactive; printf '%-32s %s\n' "$s" "$state"; done
