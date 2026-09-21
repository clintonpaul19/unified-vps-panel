#!/usr/bin/env bash
set -e
printf 'IP: '; curl -4fsS --max-time 3 https://api.ipify.org || true; echo
printf 'Hostname: '; hostname -f 2>/dev/null || hostname
if [ -f /etc/unified-vps/panel.env ]; then . /etc/unified-vps/panel.env; printf 'Domain: '; echo "${SERVER_DOMAIN:-not configured}"; fi
. /etc/os-release; echo "OS: $PRETTY_NAME"; uptime -p
for s in ssh xray hysteria-server nginx unified-vps-panel unified-vps-sslh-xray unified-vps-sslh-web unified-vps-sslh-ssh; do printf '%-28s %s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null || echo inactive)"; done
