#!/usr/bin/env bash
set -u
LOG=/var/log/unified-vps/watchdog.log
mkdir -p "$(dirname "$LOG")"
SERVICES=(ssh nginx haproxy xray hysteria-server unified-vps-panel unified-vps-wstunnel-ssh unified-vps-ws-payload-ssh fail2ban)
for svc in "${SERVICES[@]}"; do
  if systemctl is-enabled --quiet "$svc" 2>/dev/null || systemctl is-active --quiet "$svc" 2>/dev/null; then
    if ! systemctl is-active --quiet "$svc"; then
      printf '%s restarting %s\n' "$(date -Is)" "$svc" >>"$LOG"
      systemctl restart "$svc" >>"$LOG" 2>&1 || true
    fi
  fi
done
if [ -f "$LOG" ] && [ "$(stat -c%s "$LOG" 2>/dev/null || echo 0)" -gt 5242880 ]; then
  tail -n 1000 "$LOG" >"${LOG}.tmp" && mv "${LOG}.tmp" "$LOG"
fi
