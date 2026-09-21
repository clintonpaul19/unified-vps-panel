#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root.'; exit 1; }
. /etc/os-release
case "$ID" in ubuntu|debian) ;; *) echo "Unsupported OS: $ID"; exit 1;; esac
case "$(dpkg --print-architecture)" in amd64|arm64) ;; *) echo 'Supported architectures: amd64, arm64'; exit 1;; esac
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl jq openssl iproute2 iptables iptables-persistent sqlite3 python3 openssh-server dnsutils lsof procps psmisc
mkdir -p /opt/unified-vps /etc/unified-vps /var/log/unified-vps
for p in 22 80 443 2087; do iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport "$p" -j ACCEPT; done
for p in 53 443; do iptables -C INPUT -p udp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p udp --dport "$p" -j ACCEPT; done
iptables -C INPUT -p udp --dport 7100:7300 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p udp --dport 7100:7300 -j ACCEPT
iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables-save >/etc/iptables/rules.v4
if command -v ip6tables >/dev/null 2>&1; then ip6tables-save >/etc/iptables/rules.v6 2>/dev/null || true; fi
if ! command -v hysteria >/dev/null 2>&1; then curl -fsSL https://get.hy2.sh/ | bash; fi
if ! command -v xray >/dev/null 2>&1; then bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install; fi
# Xray public port layout: VLESS on 80; VMess and Trojan share 443 via fallback.
mkdir -p /usr/local/etc/xray
if [ ! -f /etc/unified-vps/xray.crt ]; then
  openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
    -keyout /etc/unified-vps/xray.key \
    -out /etc/unified-vps/xray.crt \
    -subj "/CN=unified-vps" >/dev/null 2>&1
  chmod 600 /etc/unified-vps/xray.key
fi
if [ ! -f /usr/local/etc/xray/config.json ]; then
  curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/config/xray.json" \
    -o /usr/local/etc/xray/config.json
fi
if ! xray -test -config /usr/local/etc/xray/config.json >/tmp/unified-vps-xray-test.log 2>&1; then
  cat /tmp/unified-vps-xray-test.log >&2
  echo "Xray configuration test failed." >&2
  exit 1
fi

if [ ! -f /etc/unified-vps/panel.env ]; then printf 'ADMIN_USER=admin\nADMIN_PASSWORD=' > /etc/unified-vps/panel.env; openssl rand -base64 32 | tr -dc 'A-Za-z0-9' | head -c 24 >> /etc/unified-vps/panel.env; printf '\nPANEL_PORT=2087\n' >> /etc/unified-vps/panel.env; chmod 600 /etc/unified-vps/panel.env; fi
cat >/opt/unified-vps/panel.py <<'PY'
import os,sqlite3,base64,hmac
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
DB='/etc/unified-vps/panel.db'; PORT=int(os.environ.get('PANEL_PORT','2087'))
def db():
 c=sqlite3.connect(DB); c.execute('create table if not exists users(id integer primary key,username text unique,protocol text,secret text,quota_bytes integer default 0,used_bytes integer default 0,expiry integer default 0,enabled integer default 1,created_at integer)'); c.commit(); return c
def auth(h):
 v=h.get('Authorization','')
 if not v.startswith('Basic '): return False
 try: u,p=base64.b64decode(v[6:]).decode().split(':',1)
 except: return False
 return hmac.compare_digest(u,os.environ.get('ADMIN_USER','admin')) and hmac.compare_digest(p,os.environ.get('ADMIN_PASSWORD',''))
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  if not auth(self.headers): self.send_response(401); self.send_header('WWW-Authenticate','Basic realm="Unified VPS"'); self.end_headers(); return
  c=db(); rows=c.execute('select username,protocol,used_bytes,quota_bytes,enabled from users order by id desc').fetchall(); c.close()
  html='<h1>Unified VPS Panel</h1><p>Hysteria UDP 53 · SSH 22 · SSH WS 80 · SSH WSS 443 · VMess 10086 · VLESS 10087 · Trojan 10088 · BadVPN 7100-7300</p><table border=1 cellpadding=8><tr><th>User</th><th>Protocol</th><th>Used</th><th>Quota</th><th>Enabled</th></tr>'
  for r in rows: html += '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' % r
  html+='</table>'; b=('<meta name="viewport" content="width=device-width"><body style="font-family:system-ui;background:#111;color:#eee;padding:25px">'+html+'</body>').encode()
  self.send_response(200); self.send_header('Content-Type','text/html'); self.send_header('Content-Length',str(len(b))); self.end_headers(); self.wfile.write(b)
db().close(); ThreadingHTTPServer(('0.0.0.0',PORT),H).serve_forever()
PY
cat >/etc/systemd/system/unified-vps-panel.service <<'EOF'
[Unit]
Description=Unified VPS Panel
After=network-online.target
[Service]
EnvironmentFile=/etc/unified-vps/panel.env
ExecStart=/usr/bin/python3 /opt/unified-vps/panel.py
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
cat >/usr/local/bin/vps-status <<'EOF'
#!/usr/bin/env bash
echo -n 'IP: '; curl -4fsS --max-time 3 https://api.ipify.org || true; echo
echo -n 'Hostname: '; hostname -f 2>/dev/null || hostname
. /etc/os-release; echo "OS: $PRETTY_NAME"; uptime -p
for s in ssh hysteria-server xray unified-vps-panel; do echo "$s: $(systemctl is-active "$s" 2>/dev/null || echo inactive)"; done
EOF
chmod 755 /usr/local/bin/vps-status
cat >/usr/local/bin/menu <<'EOF'
#!/usr/bin/env bash
source /etc/unified-vps/panel.env
while true; do clear; vps-status; echo; echo '1) Users'; echo '2) Restart services'; echo '3) Panel credentials'; echo '4) Exit'; read -r -p 'Select: ' n; case "$n" in 1) sqlite3 -header -column /etc/unified-vps/panel.db 'select id,username,protocol,used_bytes,quota_bytes,enabled from users;'; read -r -p 'Enter...' _;; 2) systemctl restart ssh hysteria-server xray unified-vps-panel; read -r -p 'Enter...' _;; 3) echo "Panel: http://$(curl -4fsS --max-time 3 https://api.ipify.org):$PANEL_PORT"; echo "Username: $ADMIN_USER"; echo "Password: $ADMIN_PASSWORD"; read -r -p 'Enter...' _;; 4) exit;; esac; done
EOF
chmod 755 /usr/local/bin/menu
systemctl daemon-reload
systemctl enable --now ssh unified-vps-panel
systemctl enable --now xray

echo 'Unified VPS Panel installation complete.'
echo 'Xray: VLESS=TCP/80, VMess=WS/TLS/443, Trojan=TLS/443'
echo 'Panel credentials: /etc/unified-vps/panel.env'
echo 'Run: menu'
echo 'Run: vps-status'
