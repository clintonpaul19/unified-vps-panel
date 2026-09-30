#!/usr/bin/env bash
set -e
printf 'IP: '; curl -4fsS --max-time 3 https://api.ipify.org || true; echo
printf 'Hostname: '; hostname -f 2>/dev/null || hostname
if [ -f /etc/unified-vps/panel.env ]; then . /etc/unified-vps/panel.env; printf 'Domain: '; echo "${SERVER_DOMAIN:-not configured}"; fi
. /etc/os-release; echo "OS: $PRETTY_NAME"; uptime -p
for s in ssh nginx haproxy xray hysteria-server unified-vps-panel unified-vps-wstunnel-ssh unified-vps-ws-payload-ssh fail2ban; do state="$(systemctl is-active "$s" 2>/dev/null || true)"; [ -n "$state" ] || state=inactive; printf '%-32s %s\n' "$s" "$state"; done

echo
echo "Required listeners:"
for p in 22 80 143 443 8080 8443 8880 6080; do
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
