#!/usr/bin/env bash
set -euo pipefail
BASE=/etc/unified-vps
DOMAIN="$(sed -n 's/^DOMAIN=//p' "$BASE/config.env" 2>/dev/null | tail -n1 || true)"
echo "=== UNIFIED VPS TUNNELS ==="
echo "Domain: ${DOMAIN:-not configured}"
for s in ssh nginx haproxy xray hysteria-server unified-vps-wstunnel-ssh unified-vps-ws-payload-ssh fail2ban; do
  printf '%-34s %s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null || echo inactive)"
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
if ss -lunH "sport = :53" 2>/dev/null | grep -q ':53'; then echo "UDP 53    OPEN"; else echo "UDP 53    MISSING"; fi
