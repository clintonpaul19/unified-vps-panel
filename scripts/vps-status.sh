#!/usr/bin/env bash
set -euo pipefail

echo "=== UNIFIED VPS TUNNELS ==="
if [ -f /etc/unified-vps/config.env ]; then . /etc/unified-vps/config.env; fi
printf 'Domain: %s\n' "${DOMAIN:-not configured}"
printf 'IP: '; curl -4fsS --max-time 3 https://api.ipify.org || true
echo
printf 'Hostname: '; hostname -f 2>/dev/null || hostname
. /etc/os-release
printf 'OS: %s\n' "$PRETTY_NAME"
printf 'Uptime: %s\n' "$(uptime -p)"

echo
echo "Services:"
for s in ssh nginx haproxy xray hysteria-server unified-vps-wstunnel-ssh unified-vps-ws-payload-ssh fail2ban; do
  state="$(systemctl is-active "$s" 2>/dev/null || true)"
  [ -n "$state" ] || state=inactive
  printf '%-34s %s\n' "$s" "$state"
done

echo
echo "Required TCP listeners:"
for p in 22 80 143 443 8080 8443 8880; do
  if ss -lntH "sport = :$p" 2>/dev/null | grep -q ":$p"; then
    printf 'TCP %-5s OPEN\n' "$p"
  else
    printf 'TCP %-5s MISSING\n' "$p"
  fi
done

if ss -lunH "sport = :53" 2>/dev/null | grep -q ':53'; then
  echo "UDP 53    OPEN"
else
  echo "UDP 53    MISSING"
fi

if ss -lntH "sport = :6080" 2>/dev/null | grep -q ':6080'; then
  echo "WARNING: obsolete panel port 6080 is still listening."
else
  echo "Web panel: REMOVED"
fi
