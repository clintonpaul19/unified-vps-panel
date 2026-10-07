#!/usr/bin/env bash
set -Eeuo pipefail

BASE=/etc/unified-vps
STATE="$BASE/accounts.json"
ENV="$BASE/config.env"
XRAY_CFG=/usr/local/etc/xray/config.json
HY2_CFG=/etc/hysteria/config.yaml
CERT="$BASE/xray.crt"
KEY="$BASE/xray.key"
XDIR=/usr/local/etc/xray/certs
LOCK="$BASE/menu.lock"
DOMAIN=""

[[ $EUID -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
mkdir -p "$BASE"
chmod 700 "$BASE"
touch "$LOCK"
chmod 600 "$LOCK"
exec 9>"$LOCK"
flock -x 9

load(){ DOMAIN="$(sed -n 's/^DOMAIN=//p' "$ENV" 2>/dev/null | tail -n1 || true)"; }
load
[[ -f "$STATE" ]] || printf '%s\n' '{"accounts":[]}' >"$STATE"
chmod 600 "$STATE"

die(){ echo "ERROR: $*" >&2; return 1; }
valid_user(){ [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$ ]]; }
now(){ date +%s; }

exists(){
  python3 - "$STATE" "$1" <<'PY'
import json,sys
d=json.load(open(sys.argv[1],encoding="utf-8"))
raise SystemExit(0 if any(x["username"]==sys.argv[2] for x in d["accounts"]) else 1)
PY
}
get(){
  python3 - "$STATE" "$1" <<'PY'
import json,sys
d=json.load(open(sys.argv[1],encoding="utf-8"))
for x in d["accounts"]:
    if x["username"]==sys.argv[2]:
        print(json.dumps(x,separators=(",",":"))); raise SystemExit
raise SystemExit(1)
PY
}
active(){
  python3 - "$STATE" <<'PY'
import json,sys,time
d=json.load(open(sys.argv[1],encoding="utf-8")); n=int(time.time())
print(json.dumps([x for x in d["accounts"] if x.get("enabled",True) and (not x.get("expiry") or int(x["expiry"])>n)],separators=(",",":")))
PY
}
state_add(){
  python3 - "$STATE" "$1" <<'PY'
import json,os,sys,tempfile
p,obj=sys.argv[1:3]; d=json.load(open(p,encoding="utf-8"))
if any(x["username"]==json.loads(obj)["username"] for x in d["accounts"]): raise SystemExit("account already exists")
d["accounts"].append(json.loads(obj))
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(p),prefix=".accounts.")
with os.fdopen(fd,"w") as f: json.dump(d,f,indent=2); f.write("\n")
os.chmod(tmp,0o600); os.replace(tmp,p)
PY
}
state_replace(){
  python3 - "$STATE" "$1" "$2" <<'PY'
import json,os,sys,tempfile
p,u,obj=sys.argv[1:4]; d=json.load(open(p,encoding="utf-8"))
d["accounts"]=[json.loads(obj) if x["username"]==u else x for x in d["accounts"]]
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(p),prefix=".accounts.")
with os.fdopen(fd,"w") as f: json.dump(d,f,indent=2); f.write("\n")
os.chmod(tmp,0o600); os.replace(tmp,p)
PY
}
state_delete(){
  python3 - "$STATE" "$1" <<'PY'
import json,os,sys,tempfile
p,u=sys.argv[1:3]; d=json.load(open(p,encoding="utf-8"))
d["accounts"]=[x for x in d["accounts"] if x["username"]!=u]
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(p),prefix=".accounts.")
with os.fdopen(fd,"w") as f: json.dump(d,f,indent=2); f.write("\n")
os.chmod(tmp,0o600); os.replace(tmp,p)
PY
}
set_domain(){
  local d="$1" tmp
  [[ "$d" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "Invalid domain."
  tmp="$(mktemp "$BASE/.env.XXXXXX")"
  printf 'DOMAIN=%s\n' "$d" >"$tmp"
  chmod 600 "$tmp"
  mv -f "$tmp" "$ENV"
  DOMAIN="$d"
}

copy_certs(){
  [[ -s "$CERT" && -s "$KEY" ]] || die "TLS certificate files are missing."
  install -d -m 755 "$XDIR"
  install -o xray -g xray -m 0644 "$CERT" "$XDIR/xray.crt"
  install -o xray -g xray -m 0640 "$KEY" "$XDIR/xray.key"
  install -o hysteria -g hysteria -m 0644 "$CERT" /etc/hysteria/server.crt
  install -o hysteria -g hysteria -m 0640 "$KEY" /etc/hysteria/server.key
}

render(){
  load
  [[ -n "$DOMAIN" ]] || die "Configure the domain first."
  copy_certs
  local raw="$(active)"
  python3 - "$XRAY_CFG" "$raw" "$XDIR/xray.crt" "$XDIR/xray.key" <<'PY'
import json,os,sys,tempfile
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
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(path),prefix=".xray.")
with os.fdopen(fd,"w") as f: json.dump(cfg,f,indent=2); f.write("\n")
os.chmod(tmp,0o640); os.chown(tmp,0,os.getgid()); os.replace(tmp,path)
PY
  chown root:xray "$XRAY_CFG" 2>/dev/null || true
  python3 - "$HY2_CFG" "$raw" /etc/hysteria/server.crt /etc/hysteria/server.key <<'PY'
import json,os,sys,tempfile
path,raw,cert,key=sys.argv[1:]
users={x["username"]:x["secret"] for x in json.loads(raw) if x["protocol"]=="Hysteria"}
lines=["listen: 0.0.0.0:53","tls:",f"  cert: {cert}",f"  key: {key}","auth:","  type: userpass","  userpass:"]
if users:
    for u,p in users.items(): lines.append(f"    {json.dumps(u)}: {json.dumps(p)}")
else:
    lines.append("    disabled: " + __import__("secrets").token_urlsafe(24))
lines.append("speedTest: true")
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(path),prefix=".hy2.")
with os.fdopen(fd,"w") as f: f.write("\n".join(lines)+"\n")
os.chmod(tmp,0o640); os.chown(tmp,0,os.getgid()); os.replace(tmp,path)
PY
  chown hysteria:hysteria "$HY2_CFG" 2>/dev/null || true
  xray -test -config "$XRAY_CFG" >/dev/null
  systemctl restart xray hysteria-server haproxy nginx unified-vps-wstunnel-ssh unified-vps-ws-payload-ssh
}

account_details(){
  load
  local u="$1"
  exists "$u" || { echo "Account not found."; return 1; }
  local raw
  raw="$(get "$u")"
  python3 - "$DOMAIN" "$raw" <<'PY'
import base64,json,sys,urllib.parse
host=sys.argv[1]; x=json.loads(sys.argv[2]); u=x["username"]; p=x["protocol"]; s=x["secret"]
print(f"User: {u}")
print(f"Protocol: {p}")
print("Enabled:" if x.get("enabled",True) else "Disabled:", x.get("enabled",True))
if x.get("expiry"): print("Expires:", __import__("datetime").datetime.fromtimestamp(x["expiry"]).strftime("%Y-%m-%d"))
if p=="SSH":
  print("Host:",host); print("Password:",s)
  for scheme,port in (("ws",80),("ws",8080),("ws",8880),("wss",443),("wss",8443)): print(f"{scheme.upper()} {port}: {scheme}://{host}:{port}/ssh")
elif p=="VLESS":
  print(f"VLESS 80: vless://{s}@{host}:80?type=ws&security=none&path=%2Fvless#{u}")
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
PY
}

create(){
  load
  [[ -n "$DOMAIN" ]] || { echo "Configure domain first."; return; }
  local u p n secret days expiry obj
  read -r -p "Username: " u
  valid_user "$u" || { echo "Invalid username."; return; }
  exists "$u" && { echo "Username already exists."; return; }
  echo "[1] SSH  [2] VLESS  [3] VMess  [4] Trojan  [5] Hysteria 2"
  read -r -p "Protocol >>> " n
  case "$n" in 1)p=SSH;;2)p=VLESS;;3)p=VMess;;4)p=Trojan;;5)p=Hysteria;;*) echo "Invalid protocol."; return;; esac
  if [[ "$p" == SSH ]]; then
    read -r -s -p "SSH password: " secret; echo
    [[ -n "$secret" && ${#secret} -le 128 ]] || { echo "Invalid password."; return; }
  elif [[ "$p" == VLESS || "$p" == VMess ]]; then
    secret="$(python3 -c 'import uuid;print(uuid.uuid4())')"
  else
    secret="$(python3 -c 'import secrets;print(secrets.token_urlsafe(18))')"
  fi
  read -r -p "Duration in days (0 = unlimited): " days
  [[ -n "$days" ]] || days=0
  [[ "$days" =~ ^[0-9]+$ && "$days" -le 36500 ]] || { echo "Invalid duration."; return; }
  expiry=0; ((days>0)) && expiry=$(( $(now) + days*86400 ))
  obj="$(python3 - "$u" "$p" "$secret" "$expiry" <<'PY'
import json,sys,time
print(json.dumps({"username":sys.argv[1],"protocol":sys.argv[2],"secret":sys.argv[3],"expiry":int(sys.argv[4]),"enabled":True,"created_at":int(time.time())},separators=(",",":")))
PY
)"
  state_add "$obj"
  if [[ "$p" == SSH ]]; then
    useradd -m -s /bin/bash "$u"
    printf '%s:%s\n' "$u" "$secret" | chpasswd
    if ((expiry>0)); then chage -E "$(date -d "@$expiry" +%Y-%m-%d)" "$u"; else chage -E -1 "$u"; fi
  fi
  render
  echo
  account_details "$u"
}

list_accounts(){
  python3 - "$STATE" <<'PY'
import json,sys,time
d=json.load(open(sys.argv[1],encoding="utf-8")); n=int(time.time())
print("=== ACCOUNTS ===")
if not d["accounts"]: print("No accounts."); raise SystemExit
for x in d["accounts"]:
  exp="Unlimited" if not x.get("expiry") else time.strftime("%Y-%m-%d",time.localtime(x["expiry"]))
  state="ENABLED" if x.get("enabled",True) and (not x.get("expiry") or int(x["expiry"])>n) else "DISABLED"
  print(f'{x["username"]:24} {x["protocol"]:10} {state:9} {exp}')
PY
}

toggle(){
  local u="$1" val="$2" obj exp p
  exists "$u" || { echo "Account not found."; return; }
  obj="$(get "$u")"; exp="$(echo "$obj"|python3 -c 'import json,sys;print(json.load(sys.stdin)["expiry"])')"
  [[ "$val" != true || "$exp" == 0 || "$exp" -gt "$(now)" ]] || { echo "Account expired; renew first."; return; }
  obj="$(python3 - "$obj" "$val" <<'PY'
import json,sys
x=json.loads(sys.argv[1]); x["enabled"]=sys.argv[2]=="true"; print(json.dumps(x,separators=(",",":")))
PY
)"
  state_replace "$u" "$obj"
  p="$(echo "$obj"|python3 -c 'import json,sys;print(json.load(sys.stdin)["protocol"])')"
  if [[ "$p" == SSH ]]; then
    if [[ "$val" == true ]]; then usermod -U "$u"; else usermod -L "$u"; pkill -TERM -u "$u" 2>/dev/null || true; fi
  fi
  render
  echo "$u: $val"
}

renew(){
  local u="$1" days obj exp p
  exists "$u" || { echo "Account not found."; return; }
  read -r -p "Renew for how many days: " days
  [[ "$days" =~ ^[0-9]+$ && "$days" -ge 1 && "$days" -le 36500 ]] || { echo "Invalid duration."; return; }
  exp=$(( $(now) + days*86400 )); obj="$(get "$u")"
  obj="$(python3 - "$obj" "$exp" <<'PY'
import json,sys
x=json.loads(sys.argv[1]); x["expiry"]=int(sys.argv[2]); x["enabled"]=True; print(json.dumps(x,separators=(",",":")))
PY
)"
  state_replace "$u" "$obj"
  p="$(echo "$obj"|python3 -c 'import json,sys;print(json.load(sys.stdin)["protocol"])')"
  if [[ "$p" == SSH ]]; then usermod -U "$u"; chage -E "$(date -d "@$exp" +%Y-%m-%d)" "$u"; fi
  render
  echo "Renewed $u."
}

delete_account(){
  local u="$1" p ans
  exists "$u" || { echo "Account not found."; return; }
  p="$(get "$u"|python3 -c 'import json,sys;print(json.load(sys.stdin)["protocol"])')"
  read -r -p "Delete $u permanently? [y/N]: " ans
  [[ "$ans" =~ ^[Yy]$ ]] || return
  state_delete "$u"
  if [[ "$p" == SSH ]]; then pkill -TERM -u "$u" 2>/dev/null || true; userdel -r "$u" 2>/dev/null || true; fi
  render
  echo "Deleted $u."
}

status(){
  load
  echo "=== UNIFIED VPS TUNNELS ==="
  echo "Domain: ${DOMAIN:-not configured}"
  for s in ssh nginx haproxy xray hysteria-server unified-vps-wstunnel-ssh unified-vps-ws-payload-ssh; do
    printf '%-34s %s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null || echo inactive)"
  done
  echo
  echo "TCP:"
  ss -lnt | grep -E ':(22|80|143|443|8080|8443|8880) ' || true
  echo "UDP:"
  ss -lun | grep ':53 ' || true
}

usage(){
  local dev
  dev="$(ip route show default | awk '/default/{print $5;exit}')"
  [[ -n "$dev" ]] || return
  echo "RX: $(awk '{printf "%.2f GB",$1/1024/1024/1024}' "/sys/class/net/$dev/statistics/rx_bytes")"
  echo "TX: $(awk '{printf "%.2f GB",$1/1024/1024/1024}' "/sys/class/net/$dev/statistics/tx_bytes")"
}

main_menu(){
  while true; do
    clear
    load
    echo "=============================================="
    echo "             UNIFIED VPS TUNNELS"
    echo "=============================================="
    echo "Domain: ${DOMAIN:-not configured}"
    echo
    echo "[1] Configure domain"
    echo "[2] Create account"
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
      1) read -r -p "Domain: " d; set_domain "$d"; render; read -r -p "Press Enter..." ;;
      2) create; read -r -p "Press Enter..." ;;
      3) list_accounts; read -r -p "Press Enter..." ;;
      4) read -r -p "Username: " u; account_details "$u"; read -r -p "Press Enter..." ;;
      5) read -r -p "Username: " u; toggle "$u" true; read -r -p "Press Enter..." ;;
      6) read -r -p "Username: " u; toggle "$u" false; read -r -p "Press Enter..." ;;
      7) read -r -p "Username: " u; renew "$u"; read -r -p "Press Enter..." ;;
      8) read -r -p "Username: " u; delete_account "$u"; read -r -p "Press Enter..." ;;
      9) status; read -r -p "Press Enter..." ;;
      10) render; echo "Tunnel services restarted."; read -r -p "Press Enter..." ;;
      11) usage; read -r -p "Press Enter..." ;;
      12) clear; exit 0 ;;
      *) echo "Invalid option."; sleep 1 ;;
    esac
  done
}

case "${1:-menu}" in
  menu) main_menu ;;
  --render) render ;;
  *) echo "Usage: menu [--render]"; exit 2 ;;
esac
