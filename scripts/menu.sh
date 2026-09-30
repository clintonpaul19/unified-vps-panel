#!/usr/bin/env bash
set -Eeuo pipefail

PANEL_ENV="/etc/unified-vps/panel.env"
ADMIN_FILE="/etc/unified-vps/admin.json"
PANEL_PORT="$(sed -n 's/^PANEL_PORT=//p' "$PANEL_ENV" 2>/dev/null | tail -n1)"
SERVER_DOMAIN="$(sed -n 's/^SERVER_DOMAIN=//p' "$PANEL_ENV" 2>/dev/null | tail -n1)"
PANEL_PORT="${PANEL_PORT:-6080}"

ADMIN_USER=""
ADMIN_PASSWORD=""
if [[ -s "$ADMIN_FILE" ]] && command -v jq >/dev/null 2>&1; then
  ADMIN_USER="$(jq -r '.username // empty' "$ADMIN_FILE" 2>/dev/null || true)"
  ADMIN_PASSWORD="$(jq -r '.password // empty' "$ADMIN_FILE" 2>/dev/null || true)"
fi
if [[ -z "$ADMIN_USER" || -z "$ADMIN_PASSWORD" ]]; then
  ADMIN_USER="$(sed -n 's/^ADMIN_USER=//p' "$PANEL_ENV" 2>/dev/null | tail -n1)"
  ADMIN_PASSWORD="$(sed -n 's/^ADMIN_PASSWORD=//p' "$PANEL_ENV" 2>/dev/null | tail -n1)"
fi
if [[ "$ADMIN_USER" == "spiderman" && "$ADMIN_PASSWORD" == "spiderman" ]]; then
  rm -f "$ADMIN_FILE"
  sed -i -E '/^ADMIN_USER=/d;/^ADMIN_PASSWORD=/d' "$PANEL_ENV"
  ADMIN_USER=""; ADMIN_PASSWORD=""
fi
API="http://127.0.0.1:${PANEL_PORT}"
AUTH=(-u "${ADMIN_USER}:${ADMIN_PASSWORD}")
PANEL_VERSION="1.3.0"
REBOOT_CRON="/etc/cron.d/unified-vps-daily-reboot"

if [[ -z "$ADMIN_USER" || -z "$ADMIN_PASSWORD" ]]; then
  echo "Panel administrator credentials are not configured yet."
  echo "Open http://${SERVER_DOMAIN:-YOUR-DOMAIN}:${PANEL_PORT}/ in a browser"
  echo "and complete the first-run setup."
  exit 1
fi
AUTH=(-u "${ADMIN_USER}:${ADMIN_PASSWORD}")
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

api_get(){ curl -fsS "${AUTH[@]}" "$API/api/users"; }
api_post(){ curl -fsS "${AUTH[@]}" -H 'Content-Type: application/json' -d "$1" "$API/api/users"; }
api_action(){ curl -fsS "${AUTH[@]}" -H 'Content-Type: application/json' -d "$1" "$API/api/users/action"; }
api_delete(){ curl -fsS "${AUTH[@]}" -H 'Content-Type: application/json' -d "$1" "$API/api/users/delete"; }

api_usage(){ curl -fsS "${AUTH[@]}" "$API/api/usage"; }

select_account_id(){
  local p="$1" action_name="$2" data choice list count
  data="$(api_get)"
  list="$(mktemp)"
  printf '%s\n' "$data" | python3 -c 'import json,sys; p=sys.argv[1]; [print(str(x["id"])+"|"+x["username"]+"|"+("enabled" if x["enabled"] else "disabled")) for x in json.load(sys.stdin) if x["protocol"]==p]' "$p" >"$list"
  count="$(wc -l <"$list")"
  if [[ "$count" -eq 0 ]]; then
    echo "No $p accounts exist."
    rm -f "$list"
    return 1
  fi
  echo >/dev/tty
  echo "Select account to $action_name:" >/dev/tty
  awk -F'|' '{printf "[%d] %s (%s)\n",NR,$2,$3}' "$list" >/dev/tty
  while true; do
    read -r -p "Account >>> " choice
    if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= count )); then
      awk -F'|' -v n="$choice" 'NR==n {print $1; exit}' "$list"
      rm -f "$list"
      return 0
    fi
    echo "Invalid selection." >/dev/tty
  done
}

show_usage_summary(){
  local data history
  data="$(api_usage 2>/dev/null || true)"
  if [[ -z "$data" ]]; then
    echo "Usage data unavailable."
    return
  fi
  python3 - "$data" <<'PY'
import json,sys
d=json.loads(sys.argv[1]); s=d.get("server",{})
def h(n):
    n=float(n or 0); u=["B","KB","MB","GB","TB","PB"]; i=0
    while n>=1024 and i<len(u)-1:
        n/=1024; i+=1
    return f"{n:.2f} {u[i]}"
print("=== DATA USAGE ===")
print("Server traffic today   :",h(s.get("daily_bytes",0)))
print("Server traffic all time:",h(s.get("all_time_bytes",0)))
print("Live accounting interval: ~15 seconds")
PY
  history="$(curl -fsS "${AUTH[@]}" "$API/api/usage-history" 2>/dev/null || true)"
  if [[ -n "$history" ]]; then
    echo
    echo "Last 7 daily totals:"
    python3 - "$history" <<'PY'
import json,sys
d=json.loads(sys.argv[1])
def h(n):
 n=float(n or 0);u=["B","KB","MB","GB","TB","PB"];i=0
 while n>=1024 and i<len(u)-1:n/=1024;i+=1
 return f"{n:.2f} {u[i]}"
for day,val in list(zip(d.get("days",[]),d.get("values",[])))[-7:]:
 print(f"  {day}: {h(val)}")
PY
  fi
}

apply_firewall(){
  command -v iptables >/dev/null 2>&1 || return 0
  local p
  insert_rule(){
    local chain="$1"; shift
    iptables -C "$chain" "$@" -j ACCEPT 2>/dev/null && return 0
    local pos
    pos="$(iptables -S "$chain" 2>/dev/null | awk -v chain="$chain" '$1=="-A" && $2==chain {n++; for(i=3;i<NF;i++) if($i=="-j" && ($(i+1)=="DROP" || $(i+1)=="REJECT")) {print n; exit}}' || true)"
    if [[ -n "$pos" ]]; then iptables -I "$chain" "$pos" "$@" -j ACCEPT; else iptables -A "$chain" "$@" -j ACCEPT; fi
  }
  for p in 22 80 143 443 8080 8443 8880 6080; do insert_rule INPUT -p tcp --dport "$p"; done
  insert_rule INPUT -p tcp --dport 53
  insert_rule INPUT -p udp --dport 53
  insert_rule INPUT -p udp --dport 443
  insert_rule INPUT -m conntrack --ctstate ESTABLISHED,RELATED
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    for p in 22 80 143 443 8080 8443 8880 6080 53; do ufw allow "$p/tcp" >/dev/null || true; done
    ufw allow 53/udp >/dev/null || true
    ufw allow 443/udp >/dev/null || true
  fi
  iptables-save >/etc/iptables/rules.v4 2>/dev/null || true
  systemctl enable --now netfilter-persistent.service >/dev/null 2>&1 || true
}

verify_listeners(){
  local p
  for p in 22 80 143 443 8080 8443 8880 6080; do
    ss -lntH "sport = :$p" 2>/dev/null | grep -q ":$p" || { echo "Missing TCP listener: $p"; return 1; }
  done
  ss -lunH "sport = :53" 2>/dev/null | grep -q ':53' || { echo "Missing UDP listener: 53"; return 1; }
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
 daily="{:.2f} GB".format(x.get("daily_used_bytes",0)/(1024**3))
 quota="Unlimited" if not x["quota_bytes"] else "{:.2f} GB".format(x["quota_bytes"]/(1024**3))
 enabled="Yes" if x["enabled"] else "No"
 exp="Unlimited" if not x["expiry"] else datetime.fromtimestamp(x["expiry"]).strftime("%Y-%m-%d")
 print("ID: {} | User: {} | Protocol: {} | Enabled: {}".format(x["id"],x["username"],x["protocol"],enabled))
 print("Data today: {} | All time: {} | Quota: {} | Expiry: {}".format(daily,used,quota,exp))
 if x["protocol"]=="SSH":
  print("NOTE: SSH per-user byte metering is unavailable; server totals below are interface-level.")
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
    echo "[07] DATA USAGE"
    echo "[08] BACK"
    echo
    read -r -p "Select >>> " n
    case "$n" in
      1) print_protocol_accounts "$p"; show_usage_summary; pause ;;
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
        if id="$(select_account_id "$p" "delete")"; then
          api_delete "$(jq -n --argjson id "$id" '{id:$id}')" | python3 -m json.tool
        fi
        pause ;;
      4)
        if id="$(select_account_id "$p" "renew")"; then
          read -r -p "Renew for how many days? " days
          [[ "$days" =~ ^[0-9]+$ && "$days" -gt 0 ]] || { echo "Invalid days."; pause; continue; }
          json="$(jq -n --argjson id "$id" --arg action renew --argjson days "$days" '{id:$id,action:$action,days:$days}')"
          api_action "$json" | python3 -m json.tool
        fi
        pause ;;
      5|6)
        if [[ "$n" == 5 ]]; then action=enable; action_name=enable; else action=disable; action_name=disable; fi
        if id="$(select_account_id "$p" "$action_name")"; then
          api_action "$(jq -n --argjson id "$id" --arg action "$action" '{id:$id,action:$action}')" | python3 -m json.tool
        fi
        pause ;;
      7) show_usage_summary; pause ;;
      8) return ;;
    esac
  done
}

all_accounts(){
  clear
  api_get | python3 -m json.tool
  echo
  show_usage_summary
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
  mkdir -p "$dir"; chmod 700 "$dir"
  while true; do
    clear
    echo "=== BACKUP / RESTORE ==="
    echo "[01] CREATE VERIFIED BACKUP"
    echo "[02] LIST BACKUPS"
    echo "[03] RESTORE LATEST BACKUP"
    echo "[04] BACK"
    echo
    systemctl --no-pager list-timers unified-vps-backup.timer 2>/dev/null || true
    read -r -p "Select >>> " n
    case "$n" in
      1) /usr/local/sbin/unified-vps-backup; pause ;;
      2) ls -lh "$dir"/unified-vps-*.tar.gz 2>/dev/null || echo "No backups."; pause ;;
      3)
        f="$(ls -1t "$dir"/unified-vps-*.tar.gz 2>/dev/null | head -1 || true)"
        if [[ -z "$f" ]]; then echo "No backup found."; pause; continue; fi
        tar -tzf "$f" >/dev/null || { echo "Backup archive is invalid."; pause; continue; }
        echo "Restore: $f"
        read -r -p "Type RESTORE to confirm: " n
        if [[ "$n" == "RESTORE" ]]; then
          tar -xzf "$f" -C /
          systemctl restart unified-vps-panel xray hysteria-server haproxy
          echo "Restore complete."
        else echo "Cancelled."; fi
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
    echo "[04] CERTIFICATE STATUS"
    echo "[05] FORCE CERTIFICATE RENEWAL"
    echo "[06] BACK"
    read -r -p "Select >>> " n
    case "$n" in
      1)
        read -r -s -p "New panel password: " newpass; echo
        read -r -s -p "Confirm password: " confirm; echo
        [[ -n "$newpass" && "$newpass" == "$confirm" ]] || { echo "Passwords do not match."; pause; continue; }
        NEWPASS="$newpass" ADMIN_USER="$ADMIN_USER" python3 - <<'PY'
import json, os, tempfile
from pathlib import Path
p=Path("/etc/unified-vps/admin.json")
data={"username":os.environ["ADMIN_USER"],"password":os.environ["NEWPASS"]}
p.parent.mkdir(parents=True,exist_ok=True)
fd,tmp=tempfile.mkstemp(prefix=".admin.",dir=str(p.parent))
try:
    with os.fdopen(fd,"w",encoding="utf-8") as f: json.dump(data,f,ensure_ascii=False); f.write("\n")
    os.chmod(tmp,0o600); os.replace(tmp,p)
finally:
    try: os.unlink(tmp)
    except FileNotFoundError: pass
PY
        ADMIN_PASSWORD="$newpass"
        AUTH=(-u "${ADMIN_USER}:${ADMIN_PASSWORD}")
        systemctl restart unified-vps-panel
        echo "Panel password changed."
        pause ;;
      2) echo "Admin username: $ADMIN_USER"; echo "Credentials file: $ADMIN_FILE (root-only)"; pause ;;
      3) grep -v '^SHELL=' "$REBOOT_CRON" 2>/dev/null || echo "Daily reboot is not configured."; pause ;;
      4) openssl x509 -in /etc/unified-vps/xray.crt -noout -subject -issuer -dates 2>/dev/null || echo "Certificate unavailable."; pause ;;
      5)
        if systemctl is-active --quiet haproxy 2>/dev/null; then
          /root/.acme.sh/acme.sh --renew -d "$SERVER_DOMAIN" --force --pre-hook "systemctl stop haproxy" --post-hook "systemctl start haproxy" || true
        else
          /root/.acme.sh/acme.sh --renew -d "$SERVER_DOMAIN" --force || true
        fi
        pause ;;
      6) return ;;
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
    echo "[05] WATCHDOG / TIMERS"
    echo "[06] BACK"
    read -r -p "Select >>> " n
    case "$n" in
      1) systemctl --no-pager --type=service --state=running | grep -E 'ssh|nginx|haproxy|xray|hysteria|unified' || true; pause ;;
      2) free -h; df -h; uptime; ps -eo pid,comm,%cpu,%mem --sort=-%cpu | head -12; pause ;;
      3)
        read -r -p "Service (ssh/nginx/haproxy/xray/hysteria-server/unified-vps-panel): " svc
        journalctl -u "$svc" -n 120 --no-pager || true
        pause ;;
      4) systemctl --failed --no-pager || true; pause ;;
      5) systemctl --no-pager list-timers unified-vps-watchdog.timer unified-vps-backup.timer 2>/dev/null || true; pause ;;
      6) return ;;
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
    echo "[04] ACTIVITY EVENTS"
    echo "[05] WATCHDOG LOG"
    echo "[06] FAIL2BAN LOG"
    echo "[07] INSTALL FAILURE REPORTS"
    echo "[08] BACK"
    read -r -p "Select >>> " n
    case "$n" in
      1) journalctl -u unified-vps-panel -n 150 --no-pager; pause ;;
      2) journalctl -u haproxy -n 150 --no-pager; journalctl -u xray -n 100 --no-pager; journalctl -u hysteria-server -n 100 --no-pager; pause ;;
      3) journalctl -u ssh -n 150 --no-pager; pause ;;
      4) sqlite3 /etc/unified-vps/panel.db 'select datetime(created_at,"unixepoch","localtime"),action,username,details from events order by id desc limit 100;' 2>/dev/null || true; pause ;;
      5) tail -n 200 /var/log/unified-vps/watchdog.log 2>/dev/null || echo "No watchdog events."; pause ;;
      6) journalctl -u fail2ban -n 150 --no-pager; pause ;;
      7) ls -lah /var/log/unified-vps/install-failure-* 2>/dev/null || echo "No install failure reports."; pause ;;
      8) return ;;
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
  local n
  while true; do
    clear
    echo "=== SECURITY CENTER ==="
    echo "[01] SSH / AUTH AUDIT"
    echo "[02] FIREWALL RULES"
    echo "[03] FAIL2BAN STATUS"
    echo "[04] TLS CERTIFICATE"
    echo "[05] DAILY REBOOT"
    echo "[06] BACK"
    read -r -p "Select >>> " n
    case "$n" in
      1) sshd -T | grep -E '^(port|listenaddress|addressfamily|passwordauthentication|kbdinteractiveauthentication|usepam|permitemptypasswords)'; pause ;;
      2) iptables -L INPUT -n -v --line-numbers; pause ;;
      3) systemctl --no-pager status fail2ban || true; echo; fail2ban-client status sshd 2>/dev/null || true; pause ;;
      4) openssl x509 -in /etc/unified-vps/xray.crt -noout -subject -issuer -dates 2>/dev/null || true; pause ;;
      5) grep -v '^SHELL=' "$REBOOT_CRON" 2>/dev/null || echo "Not configured"; pause ;;
      6) return ;;
    esac
  done
}

restart_services(){
  echo "Restarting Unified VPS services..."
  if ! systemctl restart ssh nginx haproxy unified-vps-panel xray hysteria-server unified-vps-wstunnel-ssh unified-vps-ws-payload-ssh; then
    echo "One or more services failed to restart."
  fi
  apply_firewall
  echo
  systemctl is-active ssh nginx haproxy unified-vps-panel xray hysteria-server unified-vps-wstunnel-ssh unified-vps-ws-payload-ssh || true
  echo
  verify_listeners || ss -lntup || true
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
  local tmp_menu tmp_app tmp_haproxy tmp_payload tmp_wstunnel_unit tmp_hysteria_unit tmp_cert_hook tmp_status tmp_watch tmp_watch_unit tmp_timer tmp_backup tmp_backup_unit tmp_backup_timer tmp_f2b
  tmp_menu="$(mktemp)"; tmp_app="$(mktemp)"; tmp_haproxy="$(mktemp)"; tmp_payload="$(mktemp)"; tmp_wstunnel_unit="$(mktemp)"; tmp_hysteria_unit="$(mktemp)"; tmp_cert_hook="$(mktemp)"; tmp_status="$(mktemp)"
  tmp_watch="$(mktemp)"; tmp_watch_unit="$(mktemp)"; tmp_timer="$(mktemp)"
  tmp_backup="$(mktemp)"; tmp_backup_unit="$(mktemp)"; tmp_backup_timer="$(mktemp)"; tmp_f2b="$(mktemp)"
  echo "Updating Unified VPS components..."
  apt-get update -qq
  apt-get install -y -qq fail2ban sqlite3 >/dev/null
  if ! curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/scripts/menu.sh?$(date +%s)" -o "$tmp_menu" ||
     ! curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/panel/app.py?$(date +%s)" -o "$tmp_app" ||
     ! curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/config/haproxy.cfg?$(date +%s)" -o "$tmp_haproxy" ||
     ! curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/scripts/ws-payload-ssh.py?$(date +%s)" -o "$tmp_payload" ||
     ! curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/systemd/unified-vps-wstunnel-ssh.service?$(date +%s)" -o "$tmp_wstunnel_unit" ||
     ! curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/systemd/hysteria-server.service?$(date +%s)" -o "$tmp_hysteria_unit" ||
     ! curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/scripts/unified-vps-cert-reload?$(date +%s)" -o "$tmp_cert_hook" ||
     ! curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/scripts/vps-status.sh?$(date +%s)" -o "$tmp_status" ||
     ! curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/scripts/unified-vps-watchdog.sh?$(date +%s)" -o "$tmp_watch" ||
     ! curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/systemd/unified-vps-watchdog.service?$(date +%s)" -o "$tmp_watch_unit" ||
     ! curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/systemd/unified-vps-watchdog.timer?$(date +%s)" -o "$tmp_timer" ||
     ! curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/scripts/unified-vps-backup.sh?$(date +%s)" -o "$tmp_backup" ||
     ! curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/systemd/unified-vps-backup.service?$(date +%s)" -o "$tmp_backup_unit" ||
     ! curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/systemd/unified-vps-backup.timer?$(date +%s)" -o "$tmp_backup_timer" ||
     ! curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/config/fail2ban-unified-vps.local?$(date +%s)" -o "$tmp_f2b"; then
    echo "Update download failed."; rm -f "$tmp_menu" "$tmp_app" "$tmp_haproxy" "$tmp_payload" "$tmp_watch" "$tmp_watch_unit" "$tmp_timer" "$tmp_backup" "$tmp_backup_unit" "$tmp_backup_timer" "$tmp_f2b"; pause; return
  fi
  if ! bash -n "$tmp_menu" || ! bash -n "$tmp_cert_hook" || ! bash -n "$tmp_status" || ! python3 -m py_compile "$tmp_app" || ! haproxy -c -f "$tmp_haproxy" || ! systemd-analyze verify "$tmp_wstunnel_unit" "$tmp_hysteria_unit"; then
    echo "Validation failed. Nothing was installed."; rm -f "$tmp_menu" "$tmp_app" "$tmp_haproxy" "$tmp_payload" "$tmp_watch" "$tmp_watch_unit" "$tmp_timer" "$tmp_backup" "$tmp_backup_unit" "$tmp_backup_timer" "$tmp_f2b"; pause; return
  fi
  install -m 0755 "$tmp_menu" /usr/local/bin/menu
  install -m 0644 "$tmp_app" /opt/unified-vps/panel.py
  install -m 0644 "$tmp_haproxy" /etc/haproxy/haproxy.cfg
  install -m 0755 "$tmp_payload" /opt/unified-vps/ws-payload-ssh.py
  install -m 0644 "$tmp_wstunnel_unit" /etc/systemd/system/unified-vps-wstunnel-ssh.service
  install -m 0644 "$tmp_hysteria_unit" /etc/systemd/system/hysteria-server.service
  install -m 0755 "$tmp_cert_hook" /usr/local/sbin/unified-vps-cert-reload
  install -m 0755 "$tmp_status" /usr/local/bin/vps-status
  install -m 0755 "$tmp_watch" /usr/local/sbin/unified-vps-watchdog
  install -m 0644 "$tmp_watch_unit" /etc/systemd/system/unified-vps-watchdog.service
  install -m 0644 "$tmp_timer" /etc/systemd/system/unified-vps-watchdog.timer
  install -m 0755 "$tmp_backup" /usr/local/sbin/unified-vps-backup
  install -m 0644 "$tmp_backup_unit" /etc/systemd/system/unified-vps-backup.service
  install -m 0644 "$tmp_backup_timer" /etc/systemd/system/unified-vps-backup.timer
  mkdir -p /etc/fail2ban/jail.d
  install -m 0644 "$tmp_f2b" /etc/fail2ban/jail.d/unified-vps.local
  rm -f "$tmp_menu" "$tmp_app" "$tmp_haproxy" "$tmp_payload" "$tmp_wstunnel_unit" "$tmp_hysteria_unit" "$tmp_cert_hook" "$tmp_status" "$tmp_watch" "$tmp_watch_unit" "$tmp_timer" "$tmp_backup" "$tmp_backup_unit" "$tmp_backup_timer" "$tmp_f2b"
  systemctl daemon-reload
  systemctl enable --now fail2ban unified-vps-watchdog.timer unified-vps-backup.timer
  systemctl restart unified-vps-panel unified-vps-wstunnel-ssh unified-vps-ws-payload-ssh hysteria-server haproxy
  if ! /usr/local/bin/menu --apply-firewall; then
    echo "Update finished, but one or more required listeners are missing."
    ss -lntup || true
  fi
  ensure_daily_reboot
  echo "Update complete. Watchdog, backups and Fail2Ban are active."
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

if [[ "${1:-}" == "--apply-firewall" ]]; then
  apply_firewall
  if ! verify_listeners; then
    ss -lntup || true
    exit 1
  fi
  exit 0
fi

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
