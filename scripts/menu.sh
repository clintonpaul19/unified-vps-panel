#!/usr/bin/env bash
set -Eeuo pipefail
source /etc/unified-vps/panel.env
while true; do
 clear; echo '=== Unified VPS Panel ==='; /usr/local/bin/vps-status; echo
 echo '1) Users'; echo '2) Add user'; echo '3) Delete user'; echo '4) Credentials'; echo '5) Restart'; echo '6) Exit'
 read -r -p 'Select: ' n
 case "$n" in
 1) curl -fsS -u "$ADMIN_USER:$ADMIN_PASSWORD" "http://127.0.0.1:${PANEL_PORT}/api/users" | python3 -m json.tool; read -r -p 'Enter...' _;;
 2) read -r -p 'Username: ' u; read -r -p 'Protocol (Hysteria/VMess/VLESS/Trojan): ' p; read -r -p 'Quota bytes (0 unlimited): ' q; read -r -p 'Days (0 unlimited): ' d; /opt/unified-vps/manage-user.sh add "{\"username\":\"$u\",\"protocol\":\"$p\",\"quota_bytes\":$q,\"days\":$d}"; read -r -p 'Enter...' _;;
 3) read -r -p 'ID: ' id; /opt/unified-vps/manage-user.sh delete "$id"; read -r -p 'Enter...' _;;
 4) echo "Panel: http://$(curl -4fsS --max-time 3 https://api.ipify.org):$PANEL_PORT"; echo "User: $ADMIN_USER"; echo "Password: $ADMIN_PASSWORD"; read -r -p 'Enter...' _;;
 5) systemctl restart ssh xray hysteria-server unified-vps-panel; read -r -p 'Enter...' _;;
 6) exit 0;;
 esac
done
