#!/usr/bin/env bash
set -e
printf 'IP: '; curl -4fsS --max-time 3 https://api.ipify.org || true; echo
printf 'Hostname: '; hostname -f 2>/dev/null || hostname
. /etc/os-release; echo "OS: $PRETTY_NAME"; uptime -p
for s in ssh xray hysteria-server unified-vps-panel; do printf '%-22s %s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null || echo inactive)"; done
