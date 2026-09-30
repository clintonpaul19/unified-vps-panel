#!/usr/bin/env bash
set -Eeuo pipefail
source /etc/unified-vps/panel.env

API="http://127.0.0.1:${PANEL_PORT}"
AUTH="-u ${ADMIN_USER}:${ADMIN_PASSWORD}"
PANEL_VERSION="1.1.0"
REBOOT_CRON="/etc/cron.d/unified-vps-daily-reboot"

pause(){ read -r -p 'Press Enter to continue...' _; }

server_ip(){ curl -4fsS --max-time 4 https://api.ipify.org 2>/dev/null || echo "Unknown"; }
isp_info(){ curl -4fsS --max-time 4 https://ipinfo.io/org 2>/dev/null || echo "Unknown"; }
location_info(){ curl -4fsS --max-time 4 https://ipinfo.io/city 2>/dev/null || echo "Unknown"; }
status_word(){ systemctl is-active "$1" 2>/dev/null || echo "OFF"; }

ensure_daily_reboot(){
  mkdir -p /etc/cron.d
  cat >"$REBOOT_CRON" <<'EOF'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# Unified VPS: reboot once per day at 04:00 server local time.
0 4 * * * root /usr/sbin/reboot >/dev/null 2>&1
EOF
  chmod 644 "$REBOOT_CRON"
  systemctl enable --now cron >/dev/null 2>&1 || true
}

api_get(){ curl -fsS $AUTH "$API/api/users"; }
api_post(){ curl -fsS $AUTH -H 'Content-Type: application/json' -d "$1" "$API/api/users"; }
api_action(){ curl -fsS $AUTH -H 'Content-Type: application/json' -d "$1" "$API/api/users/action"; }
api_delete(){ curl -fsS $AUTH -H 'Content-Type: application/json' -d "$1" "$API/api/users/delete"; }

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
  time_now="$(date +%H:%M:%S)"
  uptime="$(uptime -p | sed 's/^up //')"
  domain="${SERVER_DOMAIN:-not configured}"
  isp="$(isp_info)"
  location="$(location_info)"
  disk="$(df -h / | awk 'NR==2 {print $3" / "$2" ("$5")"}')"

  echo "┌──────────────────────────────────────────────────────────────────────────────┐"
  printf "│ %-76s │\n" "UNIFIED VPS MANAGEMENT PANEL"
  printf "│ %-76s │\n" "Server control • Accounts • Network • Monitoring"
  echo "├──────────────────────────────────────────────────────────────────────────────┤"
  printf "│ OS      %-24s IP       %-28s │\n" "$os" "$ip"
  printf "│ DOMAIN  %-24s VIRT     %-28s │\n" "$domain" "$(systemd-detect-virt 2>/dev/null || echo Unknown)"
  printf "│ RAM     %-24s DISK     %-28s │\n" "$ram" "$disk"
  printf "│ LOAD    %-24s UPTIME   %-28s │\n" "$load" "$uptime"
  printf "│ LOCATION %-23s TIME     %-28s │\n" "$location" "$time_now"
  echo "├──────────────────────────────────────────────────────────────────────────────┤"
  printf "│ SSH %-8s NGINX %-8s HAProxy %-8s Xray %-8s Hysteria %-8s │\n" \
    "$(status_word ssh)" "$(status_word nginx)" "$(status_word haproxy)" "$(status_word xray)" "$(status_word hysteria-server)"
  printf "│ Panel %-7s Payload %-6s WS-Tunnel %-4s Daily reboot: %-23s │\n" \
    "$(status_word unified-vps-panel)" "$(status_word unified-vps-ws-payload-ssh)" "$(status_word unified-vps-wstunnel-ssh)" "04:00 local"
  echo "└──────────────────────────────────────────────────────────────────────────────┘"
}

print_protocol_accounts(){
  local p="$1"
  api_get | python3 -c '
import json,sys
p=sys.argv[1]
rows=[x for x in json.load(sys.stdin) if x["protocol"]==p]
if not rows:
 print("No accounts.")
 raise SystemExit
from datetime import datetime
for x in rows:
 used="{:.2f} GB".format(x["used_bytes"]/(1024**3))
 quota="Unlimited" if not x["quota_bytes"] else "{:.2f} GB".format(x["quota_bytes"]/(1024**3))
 enabled="Yes" if x["enabled"] else "No"
 exp="Unlimited" if not x["expiry"] else datetime.fromtimestamp(x["expiry"]).strftime("%Y-%m-%d")
 print("ID: {} | User: {} | Protocol: {} | Enabled: {}".format(x["id"],x["username"],x["protocol"],enabled))
 print("Used: {} | Quota: {} | Expiry: {}".format(used,quota,exp))
 print("Secret/Password: {}".format(x["secret"]))
 if x["protocol"]=="SSH":
  print("Host: {}".format(x["host"]))
  for k in ("WebSocket","WebSocket8080","WebSocket8880","WebSocketTLS","WebSocketTLS8443"):
   print("{}: {}".format(k,x["uris"].get(k,"")))
  print("Payload: GET {} HTTP/1.1 | Host: {} | Upgrade: websocket | Connection: Upgrade".format(x["uris"].get("Path","/ssh"),x["host"]))
 else:
  for port,uri in x["uris"].items():
   if str(port).isdigit():
    print("URI {}: {}".format(port,uri))
 print()
' "$p"
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
      1) print_protocol_accounts "$p"; pause ;;
      2)
        read -r -p "Username: " id
        [[ "$id" =~ ^[A-Za-z0-9_.-]{1,32}$ ]] || { echo "Invalid username."; pause; continue; }
        secret=""
        if [[ "$p" == "SSH" ]]; then
          read -r -s -p "SSH Password: " secret; echo
          [[ -n "$secret" ]] || { echo "Password cannot be empty."; pause; continue; }
        fi
        read -r -p "Duration (days, 0 = unlimited): " days
        days=${days:-0}
        if [[ "$p" == "SSH" ]]; then
          quota=0
          echo "SSH quota: unlimited (SSH per-user quota is not supported)."
        else
          read -r -p "Quota (GB, 0 = unlimited): " quota
          quota=${quota:-0}
        fi
        if [[ "$p" == "SSH" ]]; then
          json="$(jq -n --arg u "$id" --arg p "$p" --arg s "$secret" --argjson d "$days" --argjson q "$quota" '{username:$u,protocol:$p,secret:$s,days:$d,quota_gb:$q}')"
        else
          json="$(jq -n --arg u "$id" --arg p "$p" --argjson d "$days" --argjson q "$quota" '{username:$u,protocol:$p,days:$d,quota_gb:$q}')"
        fi
        if ! api_post "$json" | python3 -m json.tool; then
          echo "Account creation failed."
        fi
        pause ;;
      3)
        read -r -p "Account ID: " id
        [[ "$id" =~ ^[0-9]+$ ]] || { echo "Invalid ID."; pause; continue; }
        api_delete "$(jq -n --argjson id "$id" '{id:$id}')" | python3 -m json.tool
        pause ;;
      4)
        read -r -p "Account ID: " id
        [[ "$id" =~ ^[0-9]+$ ]] || { echo "Invalid ID."; pause; continue; }
        read -r -p "Renew for how many days? " days
        [[ "$days" =~ ^[0-9]+$ ]] || { echo "Invalid days."; pause; continue; }
        json="$(jq -n --argjson id "$id" --arg action renew --argjson days "$days" '{id:$id,action:$action,days:$days}')"
        api_action "$json" | python3 -m json.tool
        pause ;;
      5|6)
        read -r -p "Account ID: " id
        [[ "$id" =~ ^[0-9]+$ ]] || { echo "Invalid ID."; pause; continue; }
        if [[ "$n" == 5 ]]; then action=enable; else action=disable; fi
        api_action "$(jq -n --argjson id "$id" --arg action "$action" '{id:$id,action:$action}')" | python3 -m json.tool
        pause ;;
      7) return ;;
    esac
  done
}

all_accounts(){
  clear
  api_get | python3 -m json.tool
  pause
}

install_extra(){
  while true; do
    clear
    echo "=== INSTALL EXTRA TOOLS ==="
    echo "[01] htop"
    echo "[02] btop"
    echo "[03] ncdu"
    echo "[04] nload"
    echo "[05] curl/netcat/socat"
    echo "[06] Install all"
    echo "[07] Back"
    read -r -p "Select >>> " n
    case "$n" in
      1) apt-get update >/dev/null && apt-get install -y htop ;;
      2) apt-get update >/dev/null && apt-get install -y btop ;;
      3) apt-get update >/dev/null && apt-get install -y ncdu ;;
      4) apt-get update >/dev/null && apt-get install -y nload ;;
      5) apt-get update >/dev/null && apt-get install -y curl netcat-openbsd socat ;;
      6) apt-get update >/dev/null && apt-get install -y htop btop ncdu nload curl netcat-openbsd socat ;;
      7) return ;;
    esac
    [[ "$n" != "7" ]] && pause
  done
}

backup_restore(){
  local dir="/opt/unified-vps/backups" n f
  mkdir -p "$dir"
  while true; do
    clear
    echo "=== BACKUP / RESTORE ==="
    echo "[01] CREATE BACKUP"
    echo "[02] LIST BACKUPS"
    echo "[03] RESTORE LATEST BACKUP"
    echo "[04] BACK"
    read -r -p "Select >>> " n
    case "$n" in
      1)
        f="$dir/unified-vps-$(date +%Y%m%d-%H%M%S).tar.gz"
        tar -czf "$f" /etc/unified-vps /etc/hysteria /usr/local/etc/xray /etc/ssh/sshd_config.d /etc/haproxy/haproxy.cfg /opt/unified-vps/panel.py 2>/dev/null
        echo "Backup created: $f"
        pause ;;
      2)
        ls -lh "$dir" 2>/dev/null || true
        pause ;;
      3)
        f="$(ls -1t "$dir"/*.tar.gz 2>/dev/null | head -1 || true)"
        if [[ -z "$f" ]]; then echo "No backup found."; pause; continue; fi
        echo "Restore: $f"
        read -r -p "Type RESTORE to confirm: " n
        if [[ "$n" == "RESTORE" ]]; then
          tar -xzf "$f" -C /
          systemctl restart unified-vps-panel xray hysteria-server haproxy
          echo "Restore complete."
        else
          echo "Cancelled."
        fi
        pause ;;
      4) return ;;
    esac
  done
}

server_settings(){
  local n newpass confirm
  while true; do
    clear
    echo "=== SERVER SETTINGS ==="
    echo "[01] CHANGE PANEL ADMIN PASSWORD"
    echo "[02] VIEW PANEL SETTINGS"
    echo "[03] DAILY REBOOT STATUS"
    echo "[04] BACK"
    read -r -p "Select >>> " n
    case "$n" in
      1)
        read -r -s -p "New panel password: " newpass; echo
        read -r -s -p "Confirm password: " confirm; echo
        [[ -n "$newpass" && "$newpass" == "$confirm" ]] || { echo "Passwords do not match."; pause; continue; }
        python3 - "$newpass" <<'PY'
import sys
from pathlib import Path
p=Path("/etc/unified-vps/panel.env")
new=sys.argv[1]
lines=p.read_text().splitlines()
out=[]
for line in lines:
    if line.startswith("ADMIN_PASSWORD="):
        out.append("ADMIN_PASSWORD="+new)
    else:
        out.append(line)
p.write_text("\n".join(out)+"\n")
PY
        chmod 600 /etc/unified-vps/panel.env
        systemctl restart unified-vps-panel
        echo "Panel password changed."
        pause ;;
      2) sed -E 's/^ADMIN_PASSWORD=.*/ADMIN_PASSWORD=[REDACTED]/' /etc/unified-vps/panel.env; pause ;;
      3) grep -v '^SHELL=' "$REBOOT_CRON" 2>/dev/null || echo "Daily reboot is not configured."; pause ;;
      4) return ;;
    esac
  done
}

tools_menu(){
  local n host
  while true; do
    clear
    echo "=== TOOLS & UTILITIES ==="
    echo "[01] TEST DNS"
    echo "[02] PING DOMAIN"
    echo "[03] CHECK TCP PORT"
    echo "[04] SHOW LISTENING PORTS"
    echo "[05] CERTIFICATE EXPIRY"
    echo "[06] BACK"
    read -r -p "Select >>> " n
    case "$n" in
      1) host="${SERVER_DOMAIN:-}"; getent ahostsv4 "$host" || true; pause ;;
      2) host="${SERVER_DOMAIN:-}"; ping -c 4 -W 2 "$host" || true; pause ;;
      3) read -r -p "Port: " p; timeout 5 bash -c "</dev/tcp/127.0.0.1/$p" && echo "OPEN" || echo "CLOSED"; pause ;;
      4) ss -lntup; pause ;;
      5) openssl x509 -in /etc/unified-vps/xray.crt -noout -subject -issuer -dates 2>/dev/null || echo "Certificate unavailable."; pause ;;
      6) return ;;
    esac
  done
}

monitoring_menu(){
  local n svc
  while true; do
    clear
    echo "=== MONITORING ==="
    echo "[01] SERVICE STATUS"
    echo "[02] LIVE RESOURCE USAGE"
    echo "[03] VIEW SERVICE LOG"
    echo "[04] FAILED SERVICES"
    echo "[05] BACK"
    read -r -p "Select >>> " n
    case "$n" in
      1) systemctl --no-pager --type=service --state=running | grep -E 'ssh|nginx|haproxy|xray|hysteria|unified' || true; pause ;;
      2) free -h; df -h; uptime; ps -eo pid,comm,%cpu,%mem --sort=-%cpu | head -12; pause ;;
      3)
        read -r -p "Service (ssh/nginx/haproxy/xray/hysteria-server/unified-vps-panel): " svc
        journalctl -u "$svc" -n 120 --no-pager || true
        pause ;;
      4) systemctl --failed --no-pager || true; pause ;;
      5) return ;;
    esac
  done
}

domain_network(){
  local n domain
  domain="${SERVER_DOMAIN:-}"
  while true; do
    clear
    echo "=== DOMAIN & NETWORK ==="
    echo "Domain: $domain"
    echo "Public IPv4: $(server_ip)"
    echo "[01] DNS A RECORD"
    echo "[02] ROUTE / GATEWAY"
    echo "[03] CONNECTIONS"
    echo "[04] FIREWALL RULES"
    echo "[05] BACK"
    read -r -p "Select >>> " n
    case "$n" in
      1) getent ahostsv4 "$domain" | awk '{print $1}' | sort -u; pause ;;
      2) ip route; echo; ip route get 1.1.1.1 || true; pause ;;
      3) ss -tnup; pause ;;
      4) iptables -L INPUT -n -v --line-numbers; pause ;;
      5) return ;;
    esac
  done
}

logs_reports(){
  local n
  while true; do
    clear
    echo "=== LOGS & REPORTS ==="
    echo "[01] PANEL LOG"
    echo "[02] PROXY LOGS"
    echo "[03] SSH LOG"
    echo "[04] INSTALL FAILURE REPORTS"
    echo "[05] BACK"
    read -r -p "Select >>> " n
    case "$n" in
      1) journalctl -u unified-vps-panel -n 150 --no-pager; pause ;;
      2) journalctl -u haproxy -n 150 --no-pager; journalctl -u xray -n 100 --no-pager; journalctl -u hysteria-server -n 100 --no-pager; pause ;;
      3) journalctl -u ssh -n 150 --no-pager; pause ;;
      4) ls -lah /var/log/unified-vps/install-failure-* 2>/dev/null || echo "No install failure reports."; pause ;;
      5) return ;;
    esac
  done
}

view_connections(){
  clear
  echo "=== ACTIVE CONNECTIONS ==="
  echo
  ss -ntup
  echo
  echo "UDP listeners:"
  ss -unap
  pause
}

system_resource(){
  clear
  echo "=== SYSTEM RESOURCE ==="
  free -h
  echo
  df -h
  echo
  uptime
  echo
  echo "Top CPU:"
  ps -eo pid,comm,%cpu,%mem --sort=-%cpu | head -12
  echo
  echo "Top memory:"
  ps -eo pid,comm,%cpu,%mem --sort=-%mem | head -12
  pause
}

security_menu(){
  clear
  echo "=== SECURITY AUDIT ==="
  echo
  echo "-- SSH effective auth --"
  sshd -T | grep -E '^(port|listenaddress|addressfamily|passwordauthentication|kbdinteractiveauthentication|usepam|permitemptypasswords)'
  echo
  echo "-- Firewall --"
  iptables -L INPUT -n -v --line-numbers
  echo
  echo "-- TLS certificate --"
  openssl x509 -in /etc/unified-vps/xray.crt -noout -dates 2>/dev/null || true
  echo
  echo "-- Daily reboot --"
  grep -v '^SHELL=' "$REBOOT_CRON" 2>/dev/null || echo "Not configured"
  pause
}

restart_services(){
  echo "Restarting Unified VPS services..."
  systemctl restart ssh nginx haproxy unified-vps-panel xray hysteria-server unified-vps-wstunnel-ssh unified-vps-ws-payload-ssh
  echo
  systemctl is-active ssh nginx haproxy unified-vps-panel xray hysteria-server unified-vps-wstunnel-ssh unified-vps-ws-payload-ssh || true
  echo "Done."
  pause
}

speedtest_menu(){
  clear
  echo "=== OOKLA SPEEDTEST ==="
  if command -v speedtest >/dev/null 2>&1; then
    speedtest --accept-license --accept-gdpr || true
  else
    echo "Ookla Speedtest is not installed."
  fi
  pause
}

update_script(){
  local tmp_menu tmp_app tmp_haproxy tmp_payload
  tmp_menu="$(mktemp)"
  tmp_app="$(mktemp)"
  tmp_haproxy="$(mktemp)"
  tmp_payload="$(mktemp)"
  echo "Updating Unified VPS components..."
  if ! curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/scripts/menu.sh?$(date +%s)" -o "$tmp_menu" ||
     ! curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/panel/app.py?$(date +%s)" -o "$tmp_app" ||
     ! curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/config/haproxy.cfg?$(date +%s)" -o "$tmp_haproxy" ||
     ! curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/scripts/ws-payload-ssh.py?$(date +%s)" -o "$tmp_payload"; then
    rm -f "$tmp_menu" "$tmp_app" "$tmp_haproxy" "$tmp_payload"
    echo "Update download failed."
    pause
    return
  fi
  bash -n "$tmp_menu"
  python3 -m py_compile "$tmp_app"
  haproxy -c -f "$tmp_haproxy"
  install -m 0755 "$tmp_menu" /usr/local/bin/menu
  install -m 0644 "$tmp_app" /opt/unified-vps/panel.py
  install -m 0644 "$tmp_haproxy" /etc/haproxy/haproxy.cfg
  install -m 0755 "$tmp_payload" /opt/unified-vps/ws-payload-ssh.py
  rm -f "$tmp_menu" "$tmp_app" "$tmp_haproxy" "$tmp_payload"
  systemctl restart unified-vps-panel unified-vps-ws-payload-ssh haproxy
  ensure_daily_reboot
  echo "Update complete."
  pause
}

server_info(){
  draw_header
  echo
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
  echo "Daily reboot: 04:00 local"
  pause
}

ensure_daily_reboot

while true; do
  draw_header
  echo
  echo "============================ MAIN MENU ============================"
  echo "[01] SSH accounts"
  echo "[02] VLESS accounts"
  echo "[03] VMess accounts"
  echo "[04] Trojan accounts"
  echo "[05] Hysteria accounts"
  echo "[06] All accounts"
  echo "[07] Install extra tools"
  echo "[08] Server information"
  echo "[09] Backup / restore"
  echo "[10] Server settings"
  echo "[11] Tools & utilities"
  echo "[12] Monitoring"
  echo "[13] Domain & network"
  echo "[14] Logs & reports"
  echo "[15] Restart all services"
  echo "[16] Ookla speedtest"
  echo "[17] Active connections"
  echo "[18] System resources"
  echo "[19] Security audit"
  echo "[20] Update panel / proxy files"
  echo "[21] Exit"
  echo
  echo "Version = $PANEL_VERSION | Daily reboot = 04:00 local"
  echo
  read -r -p "Select an option [1-21] >>> " n
  case "$n" in
    1) protocol_menu SSH ;;
    2) protocol_menu VLESS ;;
    3) protocol_menu VMess ;;
    4) protocol_menu Trojan ;;
    5) protocol_menu Hysteria ;;
    6) all_accounts ;;
    7) install_extra ;;
    8) server_info ;;
    9) backup_restore ;;
    10) server_settings ;;
    11) tools_menu ;;
    12) monitoring_menu ;;
    13) domain_network ;;
    14) logs_reports ;;
    15) restart_services ;;
    16) speedtest_menu ;;
    17) view_connections ;;
    18) system_resource ;;
    19) security_menu ;;
    20) update_script ;;
    21) exit 0 ;;
    *) echo "Invalid option."; sleep 1 ;;
  esac
done
