#!/usr/bin/env bash
set -Eeuo pipefail
source /etc/unified-vps/panel.env
API="http://127.0.0.1:${PANEL_PORT}"
AUTH="-u ${ADMIN_USER}:${ADMIN_PASSWORD}"
pause(){ read -r -p 'Enter...' _; }
api_get(){ curl -fsS $AUTH "$API/api/users"; }
api_post(){ curl -fsS $AUTH -H 'Content-Type: application/json' -d "$1" "$API/api/users"; }

list_protocol(){
  local p="$1"
  echo "=== $p Accounts ==="
  api_get | python3 -c '
import json,sys
p=sys.argv[1]
rows=[x for x in json.load(sys.stdin) if x["protocol"]==p]
if not rows: print("No accounts."); raise SystemExit
for x in rows:
 print(f"ID: {x['id']}  User: {x['username']}  Enabled: {'Yes' if x['enabled'] else 'No'}  Used: {x['used_bytes']/(1024**3):.2f} GB  Quota: {'Unlimited' if not x['quota_bytes'] else f'{x['quota_bytes']/(1024**3):.2f} GB'}")
 print(f"Password/UUID: {x['secret']}")
 for port,uri in x.get("uris",{}).items(): print(f"  {port}: {uri}")
 print()
' "$p"
}

create_protocol(){
  local p="$1" u secret days quota json
  read -r -p "Username: " u
  [[ "$u" =~ ^[A-Za-z0-9_.-]{1,32}$ ]] || { echo "Invalid username."; pause; return; }
  if [[ "$p" == "SSH" ]]; then
    read -r -s -p "SSH Password: " secret; echo
    [[ -n "$secret" ]] || { echo "Password cannot be empty."; pause; return; }
  else secret=""; fi
  read -r -p "Duration (days, 0 = unlimited): " days
  read -r -p "Quota (GB, 0 = unlimited): " quota
  days=${days:-0}; quota=${quota:-0}
  if [[ "$p" == "SSH" ]]; then
    json="$(jq -n --arg u "$u" --arg p "$p" --arg s "$secret" --argjson d "$days" --argjson q "$quota" '{username:$u,protocol:$p,secret:$s,days:$d,quota_gb:$q}')"
  else
    json="$(jq -n --arg u "$u" --arg p "$p" --argjson d "$days" --argjson q "$quota" '{username:$u,protocol:$p,days:$d,quota_gb:$q}')"
  fi
  api_post "$json" | python3 -m json.tool
  pause
}

account_action(){
  local p="$1" action="$2" id days json
  read -r -p "Account ID: " id
  [[ "$id" =~ ^[0-9]+$ ]] || { echo "Invalid ID."; pause; return; }
  if [[ "$action" == "renew" ]]; then
    read -r -p "Renew for how many days? " days
    [[ "$days" =~ ^[1-9][0-9]*$ ]] || { echo "Invalid number of days."; pause; return; }
    json="$(jq -n --argjson id "$id" --arg action "$action" --argjson days "$days" '{id:$id,action:$action,days:$days}')"
  else
    json="$(jq -n --argjson id "$id" --arg action "$action" '{id:$id,action:$action}')"
  fi
  api_post "$json" | python3 -m json.tool
  pause
}

protocol_menu(){
  local p="$1" n
  while true; do
    clear
    echo "=== Unified VPS / $p ==="
    echo "1) List accounts"
    echo "2) Create account"
    echo "3) Delete account"
    echo "4) Renew account"
    echo "5) Enable account"
    echo "6) Disable account"
    echo "7) Back"
    read -r -p "Select: " n
    case "$n" in
      1) list_protocol "$p"; pause ;;
      2) create_protocol "$p" ;;
      3) read -r -p "Account ID: " id; [[ "$id" =~ ^[0-9]+$ ]] && api_post "$(jq -n --argjson id "$id" '{id:$id}')" | python3 -m json.tool || echo "Invalid ID."; pause ;;
      4) account_action "$p" renew ;;
      5) account_action "$p" enable ;;
      6) account_action "$p" disable ;;
      7) return ;;
    esac
  done
}

while true; do
  clear
  echo '=== Unified VPS Panel ==='
  /usr/local/bin/vps-status
  echo "Domain: $SERVER_DOMAIN"
  echo "Panel: https://$SERVER_DOMAIN/"
  echo
  echo "1) Hysteria"
  echo "2) SSH"
  echo "3) VMess"
  echo "4) VLESS"
  echo "5) Trojan"
  echo "6) Server information"
  echo "7) Panel credentials"
  echo "8) Ookla Speedtest"
  echo "9) Restart services"
  echo "10) Exit"
  read -r -p 'Select protocol: ' n
  case "$n" in
    1) protocol_menu Hysteria ;;
    2) protocol_menu SSH ;;
    3) protocol_menu VMess ;;
    4) protocol_menu VLESS ;;
    5) protocol_menu Trojan ;;
    6) /usr/local/bin/vps-status; pause ;;
    7) echo "Panel: https://$SERVER_DOMAIN/"; echo "Panel backend: 127.0.0.1:$PANEL_PORT"; echo "Direct SSH: 22"; echo "SSLH SSH ports: 80 443 143 8080 8443"; echo "Username: $ADMIN_USER"; echo "Password: $ADMIN_PASSWORD"; pause ;;
    8) speedtest --accept-license --accept-gdpr || true; pause ;;
    9) systemctl restart xray hysteria-server unified-vps-panel; echo "Backend services restarted."; pause ;;
    10) exit 0 ;;
  esac
done
