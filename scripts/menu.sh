#!/usr/bin/env bash
set -Eeuo pipefail
source /etc/unified-vps/panel.env
while true; do
 clear; echo '=== Unified VPS Panel ==='; /usr/local/bin/vps-status; echo
 echo "Domain: $SERVER_DOMAIN"; echo "Panel: https://$SERVER_DOMAIN/"; echo; echo '1) List users / copy connection URIs'; echo '2) Add user'; echo '3) Delete user'; echo '4) Panel credentials'; echo '5) Ookla Speedtest'; echo '6) Restart services'; echo '7) Exit'
 read -r -p 'Select: ' n
 case "$n" in
  1) curl -fsS -u "$ADMIN_USER:$ADMIN_PASSWORD" "http://127.0.0.1:${PANEL_PORT}/api/users" | python3 -m json.tool; read -r -p 'Enter...' _ ;;
  2) read -r -p 'Username: ' u; read -r -p 'Protocol (Hysteria/SSH/VMess/VLESS/Trojan): ' p; read -r -p 'Quota bytes (0 unlimited): ' q; read -r -p 'Days (0 unlimited): ' d; curl -fsS -u "$ADMIN_USER:$ADMIN_PASSWORD" -H 'Content-Type: application/json' -d "{\"username\":\"$u\",\"protocol\":\"$p\",\"quota_bytes\":$q,\"days\":$d}" "http://127.0.0.1:${PANEL_PORT}/api/users" | python3 -m json.tool; echo; echo 'The response contains generated credentials and copy-ready URIs for all supported ports.'; read -r -p 'Enter...' _ ;;
  3) read -r -p 'ID: ' id; curl -fsS -u "$ADMIN_USER:$ADMIN_PASSWORD" -H 'Content-Type: application/json' -d "{\"id\":$id}" "http://127.0.0.1:${PANEL_PORT}/api/users/delete" | python3 -m json.tool; read -r -p 'Enter...' _ ;;
  4) echo "Panel: https://$SERVER_DOMAIN/"; echo "Panel backend: 127.0.0.1:$PANEL_PORT"; echo "SSH ports: 80 443 143 8080 8443"; echo "Username: $ADMIN_USER"; echo "Password: $ADMIN_PASSWORD"; read -r -p 'Enter...' _ ;;
  5) if command -v speedtest >/dev/null 2>&1; then speedtest --accept-license --accept-gdpr || true; else echo 'Ookla Speedtest is not installed.'; fi; read -r -p 'Enter...' _ ;;
  6) systemctl restart ssh nginx xray hysteria-server unified-vps-panel unified-vps-sslh-xray unified-vps-sslh-web unified-vps-sslh-ssh; read -r -p 'Enter...' _ ;;
  7) exit 0 ;;
 esac
done
