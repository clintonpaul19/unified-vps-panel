#!/usr/bin/env bash
set -Eeuo pipefail
source /etc/unified-vps/panel.env

API="http://127.0.0.1:${PANEL_PORT}"
AUTH="-u ${ADMIN_USER}:${ADMIN_PASSWORD}"
VERSION="v1.0.0"

pause(){ read -r -p 'Press Enter to continue...' _; }

isp_info(){
  curl -4fsS --max-time 4 https://ipinfo.io/org 2>/dev/null || echo "Unknown"
}

location_info(){
  curl -4fsS --max-time 4 https://ipinfo.io/city 2>/dev/null || echo "Unknown"
}

server_ip(){
  curl -4fsS --max-time 4 https://api.ipify.org 2>/dev/null || echo "Unknown"
}

api_get(){ curl -fsS $AUTH "$API/api/users"; }
api_post(){ curl -fsS $AUTH -H 'Content-Type: application/json' -d "$1" "$API/api/users"; }

status_word(){
  systemctl is-active "$1" 2>/dev/null || echo "OFF"
}

draw_header(){
  clear
  local ip host os cores ram load date_now time_now uptime domain isp location disk
  ip="$(server_ip)"
  host="$(hostname -f 2>/dev/null || hostname)"
  . /etc/os-release
  os="$PRETTY_NAME"
  cores="$(nproc)"
  ram="$(free -m | awk '/Mem:/ {print $3" / "$2" MB"}')"
  load="$(awk '{print $1", "$2", "$3}' /proc/loadavg)"
  date_now="$(date +%d-%m-%Y)"
  time_now="$(date +%H-%M-%S)"
  uptime="$(uptime -p | sed 's/^up //')"
  domain="${SERVER_DOMAIN:-not configured}"
  isp="$(isp_info)"
  location="$(location_info)"
  disk="$(df -h / | awk 'NR==2 {print $3" / "$2" ("$5")"}')"

  echo "╔══════════════════════════════════════════════════════════════════════════════╗"
  printf "║ %-76s ║\n" "UNIFIED VPS MANAGEMENT PANEL"
  printf "║ %-76s ║\n" "Fast • Secure • Reliable"
  echo "╠══════════════════════════════════════════════════════════════════════════════╣"
  printf "║ %-76s ║\n" "Welcome to Unified VPS Panel"
  echo "╠══════════════════════════════════════════════════════════════════════════════╣"
  printf "║ ● SYSTEM OS      = %-24s ● IP VPS       = %-26s ║\n" "$os" "$ip"
  printf "║ ● SYSTEM CORE    = %-24s ● DOMAIN       = %-26s ║\n" "$cores" "$domain"
  printf "║ ● SERVER RAM     = %-24s ● ISP          = %-26s ║\n" "$ram" "$isp"
  printf "║ ● LOAD/CPU       = %-24s ● LOCATION     = %-26s ║\n" "$load" "$location"
  printf "║ ● DATE            = %-24s ● VIRT TYPE    = %-26s ║\n" "$date_now" "$(systemd-detect-virt 2>/dev/null || echo Unknown)"
  printf "║ ● TIME            = %-24s ● DISK USAGE   = %-26s ║\n" "$time_now" "$disk"
  printf "║ ● UPTIME          = %-24s ● TCP PORTS    = %-26s ║\n" "$uptime" "22, 80, 143, 443, 8080, 8443"
  echo "╠══════════════════════════════════════════════════════════════════════════════╣"
  printf "║                         >>> SERVICE STATUS <<<                              ║\n"
  echo "╠══════════════════════════════════════════════════════════════════════════════╣"
  printf "║ SSH %-4s │ NGINX %-4s │ XRAY %-4s │ HYSTERIA %-4s │ PANEL %-4s │ SSLH %-4s ║\n"     "$(status_word ssh)" "$(status_word nginx)" "$(status_word xray)" "$(status_word hysteria-server)" "$(status_word unified-vps-panel)" "$(status_word unified-vps-sslh-xray)"
  echo "╚══════════════════════════════════════════════════════════════════════════════╝"
}

protocol_menu(){
  local p="$1" n id days quota secret json
  while true; do
    clear
    echo "=== UNIFIED VPS / $p ==="
    echo
    echo "[01] LIST ACCOUNTS"
    echo "[02] CREATE ACCOUNT"
    echo "[03] DELETE ACCOUNT"
    echo "[04] RENEW ACCOUNT"
    echo "[05] ENABLE ACCOUNT"
    echo "[06] DISABLE ACCOUNT"
    echo "[07] BACK"
    echo
    read -r -p "Select >>> " n
    case "$n" in
      1)
        api_get | python3 -c '
import json,sys
p=sys.argv[1]
rows=[x for x in json.load(sys.stdin) if x["protocol"]==p]
if not rows:
 print("No accounts.")
 raise SystemExit
for x in rows:
 used="{:.2f} GB".format(x["used_bytes"]/(1024**3))
 quota="Unlimited" if not x["quota_bytes"] else "{:.2f} GB".format(x["quota_bytes"]/(1024**3))
 enabled="Yes" if x["enabled"] else "No"
 print("ID: {}  User: {}  Enabled: {}  Used: {}  Quota: {}".format(x["id"],x["username"],enabled,used,quota))
 print("Password/UUID: {}".format(x["secret"]))
 if x["protocol"]=="SSH":
  print("Host: {}".format(x["host"]))
  print("Ports: 22, 80, 443, 143, 8080, 8443"))
 print()
' "$p"
        pause ;;
      2)
        read -r -p "Username: " id
        [[ "$id" =~ ^[A-Za-z0-9_.-]{1,32}$ ]] || { echo "Invalid username."; pause; continue; }
        secret=""
        if [[ "$p" == "SSH" ]]; then
          read -r -s -p "SSH Password: " secret; echo
          [[ -n "$secret" ]] || { echo "Password cannot be empty."; pause; continue; }
        fi
        read -r -p "Duration (days, 0 = unlimited): " days
        read -r -p "Quota (GB, 0 = unlimited): " quota
        days=${days:-0}; quota=${quota:-0}
        if [[ "$p" == "SSH" ]]; then
          json="$(jq -n --arg u "$id" --arg p "$p" --arg s "$secret" --argjson d "$days" --argjson q "$quota" '{username:$u,protocol:$p,secret:$s,days:$d,quota_gb:$q}')"
        else
          json="$(jq -n --arg u "$id" --arg p "$p" --argjson d "$days" --argjson q "$quota" '{username:$u,protocol:$p,days:$d,quota_gb:$q}')"
        fi
        api_post "$json" | python3 -m json.tool
        pause ;;
      3)
        read -r -p "Account ID: " id
        [[ "$id" =~ ^[0-9]+$ ]] || { echo "Invalid ID."; pause; continue; }
        api_post "$(jq -n --argjson id "$id" '{id:$id}')" | python3 -m json.tool
        pause ;;
      4)
        read -r -p "Account ID: " id
        read -r -p "Renew for how many days? " days
        json="$(jq -n --argjson id "$id" --arg action renew --argjson days "$days" '{id:$id,action:$action,days:$days}')"
        api_post "$json" | python3 -m json.tool
        pause ;;
      5|6)
        read -r -p "Account ID: " id
        if [[ "$n" == 5 ]]; then action=enable; else action=disable; fi
        api_post "$(jq -n --argjson id "$id" --arg action "$action" '{id:$id,action:$action}')" | python3 -m json.tool
        pause ;;
      7) return ;;
    esac
  done
}

user_management(){
  local n
  while true; do
    clear
    echo "╔══════════════════════════════════════════════╗"
    echo "║              USER MANAGEMENT                ║"
    echo "╠══════════════════════════════════════════════╣"
    echo "║ [01] HYSTERIA                               ║"
    echo "║ [02] SSH                                    ║"
    echo "║ [03] VMESS                                  ║"
    echo "║ [04] VLESS                                  ║"
    echo "║ [05] TROJAN                                 ║"
    echo "║ [06] ALL ACCOUNTS                           ║"
    echo "║ [07] BACK                                   ║"
    echo "╚══════════════════════════════════════════════╝"
    read -r -p "Select >>> " n
    case "$n" in
      1) protocol_menu Hysteria ;;
      2) protocol_menu SSH ;;
      3) protocol_menu VMess ;;
      4) protocol_menu VLESS ;;
      5) protocol_menu Trojan ;;
      6) api_get | python3 -m json.tool; pause ;;
      7) return ;;
    esac
  done
}

server_info(){
  draw_header
  echo
  echo "Detailed server information:"
  echo "IP       : $(server_ip)"
  echo "Hostname : $(hostname -f 2>/dev/null || hostname)"
  echo "Domain   : ${SERVER_DOMAIN:-not configured}"
  echo "ISP      : $(isp_info)"
  echo "Location : $(location_info)"
  echo "Kernel   : $(uname -r)"
  echo "Arch     : $(uname -m)"
  echo "Disk     : $(df -h / | awk 'NR==2 {print $3" / "$2" ("$5")"}')"
  echo "Memory   : $(free -h | awk '/Mem:/ {print $3" / "$2}')"
  echo "Uptime   : $(uptime -p)"
  pause
}

speedtest_menu(){
  if command -v speedtest >/dev/null 2>&1; then
    speedtest --accept-license --accept-gdpr || true
  else
    echo "Ookla Speedtest is not installed."
  fi
  pause
}

while true; do
  draw_header
  echo
  echo "        >>>>>>>>>>>>>>>>>  MAIN MENU  <<<<<<<<<<<<<<<<<"
  echo
  printf "%-38s %-38s %-38s
" "[01] SSH MENU" "[08] SERVER INFORMATION" "[15] RESTART SERVICES"
  printf "%-38s %-38s %-38s
" "[02] VLESS MENU" "[09] BACKUP / RESTORE" "[16] SPEEDTEST"
  printf "%-38s %-38s %-38s
" "[03] VMESS MENU" "[10] SERVER SETTINGS" "[17] VIEW CONNECTIONS"
  printf "%-38s %-38s %-38s
" "[04] TROJAN MENU" "[11] TOOLS & UTILITIES" "[18] SYSTEM RESOURCE"
  printf "%-38s %-38s %-38s
" "[05] HYSTERIA MENU" "[12] MONITORING" "[19] SECURITY"
  printf "%-38s %-38s %-38s
" "[06] USER MANAGEMENT" "[13] DOMAIN & NETWORK" "[20] UPDATE SCRIPT"
  printf "%-38s %-38s %-38s
" "[07] INSTALL EXTRA" "[14] LOGS & REPORTS" "[21] EXIT"
  echo
  echo "Script Version = $VERSION | Last Update = $(date +%d-%m-%Y)"
  echo
  read -r -p "Select an option [1 - 21] >>> " n
  case "$n" in
    1) protocol_menu SSH ;;
    2) protocol_menu VLESS ;;
    3) protocol_menu VMess ;;
    4) protocol_menu Trojan ;;
    5) protocol_menu Hysteria ;;
    6) user_management ;;
    7) echo "Install Extra module is ready for integration."; pause ;;
    8) server_info ;;
    9) echo "Backup / Restore module is ready for integration."; pause ;;
    10) echo "Server Settings module is ready for integration."; pause ;;
    11) echo "Tools & Utilities module is ready for integration."; pause ;;
    12) echo "Monitoring module is ready for integration."; pause ;;
    13) echo "Domain & Network module is ready for integration."; pause ;;
    14) echo "Logs & Reports module is ready for integration."; pause ;;
    15) systemctl restart xray hysteria-server unified-vps-panel; echo "Backend services restarted."; pause ;;
    16) speedtest_menu ;;
    17) api_get | python3 -m json.tool; pause ;;
    18) free -h; df -h; uptime; pause ;;
    19) echo "Security module is ready for integration."; pause ;;
    20) echo "Update the script from the official repository."; pause ;;
    21) exit 0 ;;
  esac
done
