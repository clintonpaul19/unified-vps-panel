#!/usr/bin/env bash
set -Eeuo pipefail

BASE=/etc/unified-vps
STATE="$BASE/accounts.json"
ENV="$BASE/config.env"
XRAY_CFG=/usr/local/etc/xray/config.json
HY2_CFG=/etc/hysteria/config.yaml
CERT="$BASE/xray.crt"
KEY="$BASE/xray.key"
XRAY_CERT_DIR=/usr/local/etc/xray/certs

die(){ echo "ERROR: $*" >&2; exit 1; }
root_only(){ [[ $EUID -eq 0 ]] || die "Run as root."; }
load_config(){ DOMAIN="$(sed -n 's/^DOMAIN=//p' "$ENV" 2>/dev/null | tail -n1)"; }
init_store(){ mkdir -p "$BASE"; chmod 700 "$BASE"; [[ -f "$STATE" ]] || printf '%s\n' '{"accounts":[]}' >"$STATE"; chmod 600 "$STATE"; }
valid_user(){ [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$ ]]; }
now(){ date +%s; }

account_exists(){
  python3 - "$STATE" "$1" <<'PY'
import json,sys
d=json.load(open(sys.argv[1],encoding="utf-8"))
raise SystemExit(0 if any(x["username"]==sys.argv[2] for x in d["accounts"]) else 1)
PY
}
account_get(){
  python3 - "$STATE" "$1" <<'PY'
import json,sys
d=json.load(open(sys.argv[1],encoding="utf-8"))
for x in d["accounts"]:
    if x["username"]==sys.argv[2]:
        print(json.dumps(x,separators=(",",":"))); raise SystemExit(0)
raise SystemExit(1)
PY
state_change(){
  local mode="$1" user="$2" obj="$3" tmp
  tmp="$(mktemp "$BASE/state.XXXXXX")"
  python3 - "$STATE" "$tmp" "$mode" "$user" "$obj" <<'PY'
import json,os,sys
src,dst,mode,user,obj=sys.argv[1:6]
d=json.load(open(src,encoding="utf-8"))
if mode=="add": d["accounts"].append(json.loads(obj))
elif mode=="replace": d["accounts"]=[json.loads(obj) if x["username"]==user else x for x in d["accounts"]]
elif mode=="delete": d["accounts"]=[x for x in d["accounts"] if x["username"]!=user]
else: raise SystemExit("invalid operation")
with open(dst,"w",encoding="utf-8") as f: json.dump(d,f,indent=2); f.write("\n")
os.chmod(dst,0o600); os.replace(dst,src)
PY
}
active_json(){
  python3 - "$STATE" <<'PY'
import json,sys,time
d=json.load(open(sys.argv[1],encoding="utf-8")); n=int(time.time())
print(json.dumps([x for x in d["accounts"] if x.get("enabled",True) and (not x.get("expiry") or int(x["expiry"])>n)],separators=(",",":")))
PY
}
save_domain(){
  local d="$1" tmp
  [[ "$d" =~ ^[A-Za-z0-9.-]+$ ]] || die "Invalid domain."
  tmp="$(mktemp "$BASE/env.XXXXXX")"
  printf 'DOMAIN=%s\n' "$d" >"$tmp"; chmod 600 "$tmp"; mv -f "$tmp" "$ENV"
  DOMAIN="$d"
}
copy_certs(){
  [[ -s "$CERT" && -s "$KEY" ]] || die "TLS certificate files are missing."
  install -d -m 755 "$XRAY_CERT_DIR"
  install -o xray -g xray -m 0644 "$CERT" "$XRAY_CERT_DIR/xray.crt"
  install -o xray -g xray -m 0640 "$KEY" "$XRAY_CERT_DIR/xray.key"
  install -m 0644 "$CERT" /etc/hysteria/server.crt
  install -m 0640 "$KEY" /etc/hysteria/server.key
  chown hysteria:hysteria /etc/hysteria/server.crt /etc/hysteria/server.key 2>/dev/null || true
}
render(){
  load_config; init_store
  [[ -n "$DOMAIN" ]] || die "Configure the domain first."
  copy_certs
  python3 - "$XRAY_CFG" "$(active_json)" "$XRAY_CERT_DIR/xray.crt" "$XRAY_CERT_DIR/xray.key" <<'PY'
import json,os,sys
path,raw,cert,key=sys.argv[1:]
a=json.loads(raw)
v=[{"id":x["secret"],"email":x["username"],"encryption":"none"} for x in a if x["protocol"]=="VLESS"]
m=[{"id":x["secret"],"email":x["username"],"alterId":0} for x in a if x["protocol"]=="VMess"]
t=[{"password":x["secret"],"email":x["username"]} for x in a if x["protocol"]=="Trojan"]
cfg={"log":{"loglevel":"warning"},"inbounds":[
{"listen":"127.0.0.1","port":18443,"protocol":"trojan","tag":"trojan443","settings":{"clients":t,"fallbacks":[{"path":"/vless","dest":"127.0.0.1:18444","xver":0},{"path":"/vmess","dest":"127.0.0.1:18445","xver":0},{"path":"/ssh","dest":"127.0.0.1:18446","xver":0},{"dest":"127.0.0.1:18447","xver":0}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"alpn":["http/1.1"],"certificates":[{"certificateFile":cert,"keyFile":key}]}}},
{"listen":"127.0.0.1","port":18444,"protocol":"vless","tag":"vless443","settings":{"clients":v,"decryption":"none"},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"/vless"}}},
{"listen":"127.0.0.1","port":18445,"protocol":"vmess","tag":"vmess443","settings":{"clients":m},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"/vmess"}}}
],"outbounds":[{"protocol":"freedom","tag":"direct"}]}
tmp=path+".tmp"
with open(tmp,"w",encoding="utf-8") as f: json.dump(cfg,f,indent=2); f.write("\n")
os.chmod(tmp,0o640); os.replace(tmp,path)
PY
  chown root:xray "$XRAY_CFG" 2>/dev/null || true
  python3 - "$(active_json)" "$HY2_CFG" /etc/hysteria/server.crt /etc/hysteria/server.key <<'PY'
import json,os,sys
raw,path,cert,key=sys.argv[1:]
users={x["username"]:x["secret"] for x in json.loads(raw) if x["protocol"]=="Hysteria"}
lines=["listen: 0.0.0.0:53","tls:",f"  cert: {cert}",f"  key: {key}","auth:","  type: userpass","  userpass:"]
if users:
    for u,p in users.items(): lines.append(f"    {json.dumps(u)}: {json.dumps(p)}")
else:
    lines.append("    no-users: disabled")
lines.append("speedTest: true")
tmp=path+".tmp"
with open(tmp,"w",encoding="utf-8") as f: f.write("\n".join(lines)+"\n")
os.chmod(tmp,0o640); os.replace(tmp,path)
PY
  chown hysteria:hysteria "$HY2_CFG" 2>/dev/null || true
  xray -test -config "$XRAY_CFG"
  systemctl restart xray hysteria-server haproxy nginx unified-vps-wstunnel-ssh unified-vps-ws-payload-ssh
}
show_account(){
  load_config
  local u="$1"
  account_exists "$u" || { echo "Account not found."; return; }
  echo "=== ACCOUNT ==="
  account_get "$u" | python3 -m json.tool
  echo
  python3 - "$STATE" "$u" "$DOMAIN" <<'PY'
import base64,json,sys,urllib.parse
d=json.load(open(sys.argv[1],encoding="utf-8")); u=sys.argv[2]; host=sys.argv[3]
x=next(z for z in d["accounts"] if z["username"]==u); p,s=x["protocol"],x["secret"]
if p=="VLESS":
 print(f"VLESS 80 : vless://{s}@{host}:80?type=ws&security=none&path=%2Fvless#{u}")
 print(f"VLESS 443: vless://{s}@{host}:443?type=ws&security=tls&path=%2Fvless&sni={host}#{u}")
elif p=="VMess":
 for port,tls in ((80,False),(443,True)):
  o={"v":"2","ps":u,"add":host,"port":str(port),"id":s,"aid":"0","scy":"auto","net":"ws","type":"none","host":host,"path":"/vmess","tls":"tls" if tls else "none"}
  if tls:o["sni"]=host
  print(f"VMess {port}: vmess://"+base64.b64encode(json.dumps(o,separators=(",",":")).encode()).decode())
elif p=="Trojan":
 print(f"Trojan 443: trojan://{s}@{host}:443?sni={host}#{u}")
elif p=="Hysteria":
 print(f"Hysteria2 53: hysteria2://{urllib.parse.quote(u,safe='')}:{urllib.parse.quote(s,safe='')}@{host}:53/?sni={urllib.parse.quote(host,safe='')}#{u}")
elif p=="SSH":
 print(f"Host: {host}")
 print(f"Password: {s}")
 for scheme,port in (("ws",80),("ws",8080),("ws",8880),("wss",443),("wss",8443)):
  print(f"{scheme.upper()} {port}: {scheme}://{host}:{port}/ssh")
PY
}
create_account(){
  load_config; init_store
  [[ -n "$DOMAIN" ]] || { echo "Configure domain first."; return; }
  local u proto secret days expiry obj n
  read -r -p "Username: " u
  valid_user "$u" || { echo "Invalid username."; return; }
  account_exists "$u" && { echo "Username already exists."; return; }
  echo "1) SSH   2) VLESS   3) VMess   4) Trojan   5) Hysteria 2"
  read -r -p "Protocol >>> " n
  case "$n" in 1) proto=SSH;;2) proto=VLESS;;3) proto=VMess;;4) proto=Trojan;;5) proto=Hysteria;;*) echo "Invalid protocol."; return;; esac
  if [[ "$proto" == SSH ]]; then
    read -r -s -p "SSH password: " secret; echo
    [[ -n "$secret" && "$secret" != *$'\n'* && "$secret" != *$'\r'* ]] || { echo "Invalid password."; return; }
  elif [[ "$proto" == VLESS || "$proto" == VMess ]]; then
    secret="$(python3 -c 'import uuid;print(uuid.uuid4())')"
  else
    secret="$(python3 -c 'import secrets;print(secrets.token_urlsafe(18))')"
  fi
  read -r -p "Duration in days (0 = unlimited): " days
  [[ -n "$days" ]] || days=0
  [[ "$days" =~ ^[0-9]+$ && "$days" -le 36500 ]] || { echo "Invalid duration."; return; }
  expiry=0; (( days > 0 )) && expiry=$(( $(now) + days*86400 ))
  obj="$(python3 - "$u" "$proto" "$secret" "$expiry" <<'PY'
import json,sys,time
print(json.dumps({"username":sys.argv[1],"protocol":sys.argv[2],"secret":sys.argv[3],"expiry":int(sys.argv[4]),"enabled":True,"created_at":int(time.time())},separators=(",",":")))
PY
)"
  state_change add "$u" "$obj"
  if [[ "$proto" == SSH ]]; then
    useradd -m -s /bin/bash "$u"
    printf '%s:%s\n' "$u" "$secret" | chpasswd
    if (( expiry > 0 )); then chage -E "$(date -d "@$expiry" +%Y-%m-%d)" "$u"; else chage -E -1 "$u"; fi
  fi
  render
  echo
  show_account "$u"
}
list_accounts(){
  init_store
  python3 - "$STATE" <<'PY'
import json,sys,time
d=json.load(open(sys.argv[1],encoding="utf-8")); n=int(time.time())
if not d["accounts"]: print("No accounts."); raise SystemExit
for x in d["accounts"]:
 exp="Unlimited" if not x.get("expiry") else time.strftime("%Y-%m-%d",time.localtime(x["expiry"]))
 state="ENABLED" if x.get("enabled",True) and (not x.get("expiry") or int(x["expiry"])>n) else "DISABLED"
 print(f'{x["username"]:24} {x["protocol"]:10} {state:9} {exp}')
PY
}
toggle_account(){
  local u="$1" value="$2" obj exp proto
  account_exists "$u" || { echo "Account not found."; return; }
  obj="$(account_get "$u")"
  exp="$(echo "$obj"|python3 -c 'import json,sys;print(json.load(sys.stdin)["expiry"])')"
  [[ "$value" != true || "$exp" == 0 || "$exp" -gt "$(now)" ]] || { echo "Account expired; renew it first."; return; }
  obj="$(python3 - "$obj" "$value" <<'PY'
import json,sys
x=json.loads(sys.argv[1]); x["enabled"]=sys.argv[2]=="true"; print(json.dumps(x,separators=(",",":")))
PY
)"
  state_change replace "$u" "$obj"
  proto="$(echo "$obj"|python3 -c 'import json,sys;print(json.load(sys.stdin)["protocol"])')"
  if [[ "$proto" == SSH ]]; then
    if [[ "$value" == true ]]; then usermod -U "$u"; else usermod -L "$u"; pkill -TERM -u "$u" 2>/dev/null || true; fi
  fi
  render; echo "$u: $value"
}
renew_account(){
  local u="$1" days obj exp proto
  account_exists "$u" || { echo "Account not found."; return; }
  read -r -p "Renew for how many days: " days
  [[ "$days" =~ ^[0-9]+$ && "$days" -ge 1 && "$days" -le 36500 ]] || { echo "Invalid duration."; return; }
  obj="$(account_get "$u")"; exp=$(( $(now) + days*86400 ))
  obj="$(python3 - "$obj" "$exp" <<'PY'
import json,sys
x=json.loads(sys.argv[1]); x["expiry"]=int(sys.argv[2]); x["enabled"]=True; print(json.dumps(x,separators=(",",":")))
PY
)"
  state_change replace "$u" "$obj"
  proto="$(echo "$obj"|python3 -c 'import json,sys;print(json.load(sys.stdin)["protocol"])')"
  if [[ "$proto" == SSH ]]; then usermod -U "$u"; chage -E "$(date -d "@$exp" +%Y-%m-%d)" "$u"; fi
  render; echo "Renewed $u."
}
delete_account(){
  local u="$1" p
  account_exists "$u" || { echo "Account not found."; return; }
  p="$(account_get "$u"|python3 -c 'import json,sys;print(json.load(sys.stdin)["protocol"])')"
  read -r -p "Delete $u permanently? [y/N]: " a
  [[ "$a" =~ ^[Yy]$ ]] || return
  state_change delete "$u" '{}'
  if [[ "$p" == SSH ]]; then pkill -TERM -u "$u" 2>/dev/null || true; userdel -r "$u" 2>/dev/null || true; fi
  render; echo "Deleted $u."
}
status_menu(){
  load_config
  local domain=not-configured
  [[ -n "$DOMAIN" ]] && domain="$DOMAIN"
  echo "=== UNIFIED VPS TUNNELS ==="
  echo "Domain: $domain"
  for s in ssh nginx haproxy xray hysteria-server unified-vps-wstunnel-ssh unified-vps-ws-payload-ssh; do
    printf '%-34s %s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null || echo inactive)"
  done
  echo
  ss -lnt | grep -E ':(22|80|143|443|8080|8443|8880) ' || true
  ss -lun | grep ':53 ' || true
}
usage_menu(){
  local dev
  dev="$(ip route show default | awk '/default/{print $5;exit}')"
  [[ -n "$dev" ]] || { echo "No default interface."; return; }
  echo "RX: $(awk '{printf "%.2f GB",$1/1024/1024/1024}' "/sys/class/net/$dev/statistics/rx_bytes")"
  echo "TX: $(awk '{printf "%.2f GB",$1/1024/1024/1024}' "/sys/class/net/$dev/statistics/tx_bytes")"
}
menu(){
  while true; do
    clear; load_config
    local domain=not-configured
    [[ -n "$DOMAIN" ]] && domain="$DOMAIN"
    echo "=============================================="
    echo "            UNIFIED VPS TUNNELS"
    echo "=============================================="
    echo "Domain: $domain"
    echo
    echo "[1] Configure domain"
    echo "[2] Create tunnel account"
    echo "[3] List accounts"
    echo "[4] Show connection details"
    echo "[5] Enable account"
    echo "[6] Disable account"
    echo "[7] Renew account"
    echo "[8] Delete account"
    echo "[9] Tunnel/service status"
    echo "[10] Restart tunnel services"
    echo "[11] Data usage"
    echo "[12] Exit"
    echo
    read -r -p "Select >>> " n
    case "$n" in
      1) read -r -p "Domain: " d; save_domain "$d"; render; read -r -p "Press Enter..." ;;
      2) create_account; read -r -p "Press Enter..." ;;
      3) list_accounts; read -r -p "Press Enter..." ;;
      4) read -r -p "Username: " u; show_account "$u"; read -r -p "Press Enter..." ;;
      5) read -r -p "Username: " u; toggle_account "$u" true; read -r -p "Press Enter..." ;;
      6) read -r -p "Username: " u; toggle_account "$u" false; read -r -p "Press Enter..." ;;
      7) read -r -p "Username: " u; renew_account "$u"; read -r -p "Press Enter..." ;;
      8) read -r -p "Username: " u; delete_account "$u"; read -r -p "Press Enter..." ;;
      9) status_menu; read -r -p "Press Enter..." ;;
      10) render; echo "Tunnel services restarted."; read -r -p "Press Enter..." ;;
      11) usage_menu; read -r -p "Press Enter..." ;;
      12) clear; exit 0 ;;
      *) echo "Invalid option."; sleep 1 ;;
    esac
  done
}
arg=menu
[[ $# -gt 0 ]] && arg="$1"
case "$arg" in
  menu) root_only; init_store; menu ;;
  --render) root_only; load_config; init_store; render ;;
  *) echo "Usage: tunnel.sh [--render]"; exit 2 ;;
esac
