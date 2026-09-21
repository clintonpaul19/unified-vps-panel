#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root.'; exit 1; }
. /etc/os-release
case "$ID" in ubuntu|debian) ;; *) echo "Unsupported OS: $ID"; exit 1;; esac
case "$(dpkg --print-architecture)" in amd64|arm64) ;; *) echo 'Supported architectures: amd64, arm64'; exit 1;; esac
export DEBIAN_FRONTEND=noninteractive

echo "=== Unified VPS Panel ==="
if [ -r /dev/tty ]; then
  read -r -p "Domain pointing to this VPS: " DOMAIN < /dev/tty
else
  echo "Interactive terminal required for domain prompt."
  exit 1
fi
DOMAIN="${DOMAIN#http://}"; DOMAIN="${DOMAIN#https://}"; DOMAIN="${DOMAIN%%/*}"
[[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "Invalid domain."; exit 1; }
[[ "$DOMAIN" == *.* ]] || { echo "Enter a real domain/subdomain."; exit 1; }
ACME_EMAIL="acme-$(openssl rand -hex 8)@${DOMAIN}"
echo "Generated ACME email: $ACME_EMAIL"

apt-get update
apt-get install -y ca-certificates curl jq openssl iproute2 iptables iptables-persistent sqlite3 python3 openssh-server dnsutils lsof procps psmisc socat nginx sslh cron

mkdir -p /opt/unified-vps /etc/unified-vps /etc/hysteria /var/log/unified-vps /usr/local/etc/xray
# Open every Unified VPS port before ACME. Let's Encrypt HTTP-01 needs TCP/80
# reachable from the Internet, and the final services use the same firewall rules.
for p in 80 443 143 8080 8443; do
  iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null ||
    iptables -I INPUT 1 -p tcp --dport "$p" -j ACCEPT
done
for p in 53 443; do
  iptables -C INPUT -p udp --dport "$p" -j ACCEPT 2>/dev/null ||
    iptables -I INPUT 1 -p udp --dport "$p" -j ACCEPT
done
iptables -C INPUT -p tcp --dport 53 -j ACCEPT 2>/dev/null ||
  iptables -I INPUT 1 -p tcp --dport 53 -j ACCEPT
iptables -C INPUT -p udp --dport 7100:7300 -j ACCEPT 2>/dev/null ||
  iptables -I INPUT 1 -p udp --dport 7100:7300 -j ACCEPT
iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null ||
  iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Persist the complete IPv4 firewall before any certificate work starts.
iptables-save >/etc/iptables/rules.v4
command -v ip6tables-save >/dev/null 2>&1 && ip6tables-save >/etc/iptables/rules.v6 || true

if ! command -v hysteria >/dev/null 2>&1; then curl -fsSL https://get.hy2.sh/ | bash; fi
if ! command -v xray >/dev/null 2>&1; then bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install; fi
curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/config/xray.json" -o /usr/local/etc/xray/config.json

# Get a trusted Let's Encrypt certificate for the supplied domain.
# Standalone ACME needs TCP/80 temporarily free.
systemctl stop unified-vps-sslh-xray unified-vps-sslh-web unified-vps-sslh-ssh sslh xray nginx 2>/dev/null || true
curl -fsSL https://get.acme.sh | sh -s email="$ACME_EMAIL"
"$HOME/.acme.sh/acme.sh" --set-default-ca --server letsencrypt
"$HOME/.acme.sh/acme.sh" --issue --standalone -d "$DOMAIN"
"$HOME/.acme.sh/acme.sh" --install-cert -d "$DOMAIN" \
  --fullchain-file /etc/unified-vps/xray.crt \
  --key-file /etc/unified-vps/xray.key \
  --reloadcmd "systemctl restart xray hysteria-server 2>/dev/null || true"
chmod 600 /etc/unified-vps/xray.key
chmod 644 /etc/unified-vps/xray.crt

XRAY_USER="$(systemctl cat xray 2>/dev/null | awk -F= '/^User=/{print $2; exit}')"
XRAY_USER="${XRAY_USER:-nobody}"
if id "$XRAY_USER" >/dev/null 2>&1; then
  XRAY_GROUP="$(id -gn "$XRAY_USER")"
  chown "$XRAY_USER:$XRAY_GROUP" /etc/unified-vps/xray.key /etc/unified-vps/xray.crt
  chmod 640 /etc/unified-vps/xray.key
fi

xray -test -config /usr/local/etc/xray/config.json

if ! command -v speedtest >/dev/null 2>&1; then
  curl -fsSL https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash
  apt-get update
  apt-get install -y speedtest
fi

cp /etc/unified-vps/xray.crt /etc/hysteria/server.crt
cp /etc/unified-vps/xray.key /etc/hysteria/server.key
chmod 640 /etc/hysteria/server.key
HY2_STATS_SECRET="$(openssl rand -hex 24)"
cat >/etc/hysteria/config.yaml <<YAML
listen: :53
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
auth:
  type: http
  http:
    url: http://127.0.0.1:6080/hysteria-auth
speedTest: true
trafficStats:
  listen: 127.0.0.1:9999
  secret: ${HY2_STATS_SECRET}
YAML

# SSH is kept on loopback; SSLH exposes it on the requested public ports.
mkdir -p /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/99-unified-vps.conf <<'EOF'
Port 22
ListenAddress 127.0.0.1:22
PasswordAuthentication yes
PermitEmptyPasswords no
EOF
sshd -t

# NGINX is the plain HTTP service behind SSLH on TCP/8080.
mkdir -p /var/www/html
cat >/var/www/html/index.html <<'EOF'
<!doctype html><html><head><meta charset="utf-8"><title>Unified VPS</title></head><body><h1>Unified VPS</h1><p>Server is online.</p></body></html>
EOF
cat >/etc/nginx/sites-available/unified-vps-8080 <<'EOF'
server {
    listen 127.0.0.1:18080;
    listen [::1]:18080;
    server_name _;
    root /var/www/html;
    index index.html;
}
EOF
ln -sf /etc/nginx/sites-available/unified-vps-8080 /etc/nginx/sites-enabled/unified-vps-8080
rm -f /etc/nginx/sites-enabled/default
nginx -t

SSlh_BIN="$(command -v sslh)"
cat >/etc/systemd/system/unified-vps-sslh-xray.service <<EOF
[Unit]
Description=Unified VPS SSH and Xray TCP multiplexer
After=network-online.target ssh.service xray.service
Requires=ssh.service
Wants=network-online.target
[Service]
Type=simple
ExecStartPre=/usr/sbin/sshd -t
ExecStart=$SSlh_BIN --foreground --numeric --user sslh --listen 0.0.0.0:80 --listen 0.0.0.0:443 --tls 127.0.0.1:18443 --ssh 127.0.0.1:22 --on-timeout ssh --timeout 5
Restart=always
RestartSec=1
KillMode=process
[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/unified-vps-sslh-web.service <<EOF
[Unit]
Description=Unified VPS SSH and HTTP 8080 multiplexer
After=network-online.target ssh.service nginx.service
Requires=ssh.service
Wants=network-online.target
[Service]
Type=simple
ExecStartPre=/usr/sbin/sshd -t
ExecStart=$SSlh_BIN --foreground --numeric --user sslh --listen 0.0.0.0:8080 --http 127.0.0.1:18080 --ssh 127.0.0.1:22 --on-timeout ssh --timeout 5
Restart=always
RestartSec=1
KillMode=process
[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/unified-vps-sslh-ssh.service <<EOF
[Unit]
Description=Unified VPS SSH alternate ports
After=network-online.target ssh.service
Requires=ssh.service
Wants=network-online.target
[Service]
Type=simple
ExecStartPre=/usr/sbin/sshd -t
ExecStart=$SSlh_BIN --foreground --numeric --user sslh --listen 0.0.0.0:143 --listen 0.0.0.0:8443 --ssh 127.0.0.1:22 --on-timeout ssh --timeout 5
Restart=always
RestartSec=1
KillMode=process
[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/hysteria-server.service <<'EOF'
[Unit]
Description=Hysteria 2 Server
After=network-online.target unified-vps-panel.service
Requires=unified-vps-panel.service
Wants=network-online.target
[Service]
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.yaml
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF

printf 'ADMIN_USER=spiderman\nADMIN_PASSWORD=spiderman\nPANEL_PORT=6080\nSERVER_DOMAIN=%s\nACME_EMAIL=%s\n' "$DOMAIN" "$ACME_EMAIL" > /etc/unified-vps/panel.env
chmod 600 /etc/unified-vps/panel.env

curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/panel/app.py" -o /opt/unified-vps/panel.py
cat >/etc/systemd/system/unified-vps-panel.service <<'EOF'
[Unit]
Description=Unified VPS Panel
After=network-online.target
[Service]
EnvironmentFile=/etc/unified-vps/panel.env
WorkingDirectory=/opt/unified-vps
ExecStartPre=/usr/bin/python3 -m py_compile /opt/unified-vps/panel.py
ExecStart=/usr/bin/python3 /opt/unified-vps/panel.py
Restart=always
RestartSec=2
[Install]
WantedBy=multi-user.target
EOF

curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/scripts/menu.sh" -o /usr/local/bin/menu
curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/scripts/vps-status.sh" -o /usr/local/bin/vps-status 2>/dev/null || true
chmod 755 /usr/local/bin/menu /usr/local/bin/vps-status

systemctl daemon-reload
systemctl enable ssh nginx unified-vps-panel xray hysteria-server unified-vps-sslh-xray unified-vps-sslh-web unified-vps-sslh-ssh
systemctl start ssh nginx unified-vps-panel
sleep 1
systemctl start xray
systemctl start hysteria-server
systemctl start unified-vps-sslh-xray unified-vps-sslh-web unified-vps-sslh-ssh
sshd -t
xray -test -config /usr/local/etc/xray/config.json
nginx -t
systemctl is-active --quiet ssh nginx unified-vps-panel xray hysteria-server unified-vps-sslh-xray unified-vps-sslh-web unified-vps-sslh-ssh

echo
echo "=============================================="
echo " Unified VPS Panel installation complete"
echo "=============================================="
echo "Domain: $DOMAIN"
echo "Panel: https://$DOMAIN/"
echo "Panel backend: 127.0.0.1:6080"
echo "Panel username: spiderman"
echo "Panel password: spiderman"
echo "Generated ACME email: $ACME_EMAIL"
echo "VLESS: TLS/WS on TCP 80 and 443"
echo "VMess: TLS/WS on TCP 80 and 443"
echo "Trojan: TLS on TCP 80 and 443"
echo "Hysteria 2: UDP/53 using $DOMAIN"
echo "SSH transports: TCP 80, 443, 143, 8080, 8443 using $DOMAIN"
echo "HTTP service: NGINX on TCP/8080"
echo "Ookla Speedtest: speedtest"
echo "CLI menu: menu"
echo "Status: vps-status"
echo
if [ -t 0 ] && [ -t 1 ]; then
  read -r -p "Reboot now? [y/N]: " REBOOT_NOW < /dev/tty
  case "${REBOOT_NOW,,}" in
    y|yes) echo "Rebooting..."; sleep 2; reboot ;;
    *) echo "Installation finished without reboot." ;;
  esac
else
  echo "No interactive terminal detected; skipping reboot prompt."
fi
