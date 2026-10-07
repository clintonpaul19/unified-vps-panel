#!/usr/bin/env bash
set -Eeuo pipefail

REPO="clintonpaul19/unified-vps-panel"
BASE="/etc/unified-vps"

die(){ echo "ERROR: $*" >&2; exit 1; }
[[ ${EUID:-99} -eq 0 ]] || die "Run as root."

echo "=== Unified VPS Tunnels ==="
read -r -p "Domain pointing to this VPS: " DOMAIN
DOMAIN="$(printf '%s' "$DOMAIN" | sed -E 's#^https?://##; s#/.*$##')"
[[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "Invalid domain."

apt-get update
apt-get install -y ca-certificates curl openssl iproute2 iptables iptables-persistent python3 openssh-server dnsutils lsof procps psmisc nginx haproxy cron fail2ban jq

UVPS_SHA="$(curl -fsSL "https://api.github.com/repos/${REPO}/commits/main" | jq -r '.sha // empty')"
[[ "$UVPS_SHA" =~ ^[0-9a-fA-F]{40}$ ]] || die "Could not resolve repository revision."
RAW="https://raw.githubusercontent.com/${REPO}/${UVPS_SHA}"
echo "Pinned repository revision: $UVPS_SHA"

mkdir -p "$BASE" /opt/unified-vps /etc/hysteria /usr/local/etc/xray/certs
chmod 700 "$BASE"
printf 'DOMAIN=%s\n' "$DOMAIN" >"$BASE/config.env"
chmod 600 "$BASE/config.env"

# Remove the retired web panel completely.
systemctl disable --now unified-vps-panel.service 2>/dev/null || true
rm -f /etc/systemd/system/unified-vps-panel.service
rm -f /usr/local/bin/menu /usr/local/bin/tunnel /usr/local/sbin/manage-user /usr/local/bin/vps-status
rm -rf /opt/unified-vps/uvps_panel /opt/unified-vps/panel.py
rm -f "$BASE/admin.json" "$BASE/panel.db" "$BASE/panel.env"
for u in unified-vps-backup.service unified-vps-backup.timer unified-vps-watchdog.service unified-vps-watchdog.timer; do
  systemctl disable --now "$u" 2>/dev/null || true
  rm -f "/etc/systemd/system/$u"
done
rm -f /etc/systemd/system/multi-user.target.wants/unified-vps-panel.service
systemctl daemon-reload

# Tunnel firewall only. TCP 6080 is removed.
while iptables -D INPUT -p tcp --dport 6080 -j ACCEPT 2>/dev/null; do :; done
while iptables -D INPUT -p tcp --dport 53 -j ACCEPT 2>/dev/null; do :; done
for p in 22 80 143 443 8080 8443 8880; do
  iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport "$p" -j ACCEPT
done
iptables -C INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -C INPUT -p udp --dport 443 -j ACCEPT 2>/dev/null || iptables -A INPUT -p udp --dport 443 -j ACCEPT
iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables-save >/etc/iptables/rules.v4
systemctl enable --now netfilter-persistent.service >/dev/null 2>&1 || true

# SSH.
mkdir -p /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/99-unified-vps-tunnel.conf <<'EOF'
AddressFamily inet
Port 22
ListenAddress 0.0.0.0:22
PasswordAuthentication yes
KbdInteractiveAuthentication yes
UsePAM yes
PermitEmptyPasswords no
EOF
sshd -t
systemctl enable --now ssh

# Xray.
getent passwd xray >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin xray
if ! command -v xray >/dev/null 2>&1; then
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u xray
fi
mkdir -p /etc/systemd/system/xray.service.d
cat >/etc/systemd/system/xray.service.d/20-unified-vps-user.conf <<'EOF'
[Service]
User=xray
Group=xray
EOF
systemctl daemon-reload

# Hysteria 2.
if ! command -v hysteria >/dev/null 2>&1; then
  bash <(curl -fsSL https://get.hy2.sh/) --version v2.13.0
fi
getent passwd hysteria >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin hysteria

# SSH WebSocket transport.
WSTUNNEL_VERSION="10.6.2"
case "$(dpkg --print-architecture)" in
  amd64) WSTUNNEL_ARCH="amd64" ;;
  arm64) WSTUNNEL_ARCH="arm64" ;;
  *) die "Unsupported architecture." ;;
esac
WSTUNNEL_FILE="wstunnel_${WSTUNNEL_VERSION}_linux_${WSTUNNEL_ARCH}.tar.gz"
curl -fsSL "https://github.com/erebe/wstunnel/releases/download/v${WSTUNNEL_VERSION}/${WSTUNNEL_FILE}" -o "/tmp/${WSTUNNEL_FILE}"
tar -xzf "/tmp/${WSTUNNEL_FILE}" -C /tmp
install -m 0755 /tmp/wstunnel /usr/local/bin/wstunnel
rm -f "/tmp/${WSTUNNEL_FILE}" /tmp/wstunnel
curl -fsSL "${RAW}/scripts/ws-payload-ssh.py" -o /opt/unified-vps/ws-payload-ssh.py
chmod 755 /opt/unified-vps/ws-payload-ssh.py
curl -fsSL "${RAW}/systemd/unified-vps-wstunnel-ssh.service" -o /etc/systemd/system/unified-vps-wstunnel-ssh.service
curl -fsSL "${RAW}/systemd/unified-vps-ws-payload-ssh.service" -o /etc/systemd/system/unified-vps-ws-payload-ssh.service

# UDP/53 must belong to Hysteria.
for legacy in udp-custom udp-mini; do
  systemctl disable --now "$legacy.service" 2>/dev/null || true
done
systemctl disable --now systemd-resolved.service 2>/dev/null || true
if [[ -L /etc/resolv.conf ]] || grep -q '127\.0\.0\.53' /etc/resolv.conf 2>/dev/null; then
  rm -f /etc/resolv.conf
  printf '%s\n' 'nameserver 1.1.1.1' 'nameserver 8.8.8.8' >/etc/resolv.conf
  chmod 644 /etc/resolv.conf
fi

# TLS certificate reload hook.
cat >/usr/local/sbin/unified-vps-cert-reload <<'EOF'
#!/usr/bin/env bash
set -u
BASE=/etc/unified-vps
install -d -m 755 /usr/local/etc/xray/certs
install -o xray -g xray -m 0644 "$BASE/xray.crt" /usr/local/etc/xray/certs/xray.crt 2>/dev/null || true
install -o xray -g xray -m 0640 "$BASE/xray.key" /usr/local/etc/xray/certs/xray.key 2>/dev/null || true
install -o hysteria -g hysteria -m 0644 "$BASE/xray.crt" /etc/hysteria/server.crt 2>/dev/null || true
install -o hysteria -g hysteria -m 0640 "$BASE/xray.key" /etc/hysteria/server.key 2>/dev/null || true
systemctl try-restart xray.service 2>/dev/null || true
systemctl try-restart hysteria-server.service 2>/dev/null || true
EOF
chmod 755 /usr/local/sbin/unified-vps-cert-reload

if ! command -v acme.sh >/dev/null 2>&1; then
  curl -fsSL https://get.acme.sh | sh -s email="acme-$(openssl rand -hex 8)@${DOMAIN}"
fi
ACME="${HOME}/.acme.sh/acme.sh"
[[ -s "$ACME" ]] || die "acme.sh installation failed."

if [[ ! -s "$BASE/xray.crt" ]] || ! openssl x509 -in "$BASE/xray.crt" -noout -checkend 2592000 >/dev/null 2>&1 || ! openssl x509 -in "$BASE/xray.crt" -noout -checkhost "$DOMAIN" >/dev/null 2>&1; then
  "$ACME" --issue --standalone -d "$DOMAIN" --pre-hook "systemctl stop haproxy nginx" --post-hook "systemctl start nginx"
fi
"$ACME" --install-cert -d "$DOMAIN" --fullchain-file "$BASE/xray.crt" --key-file "$BASE/xray.key" --reloadcmd "/usr/local/sbin/unified-vps-cert-reload"
/usr/local/sbin/unified-vps-cert-reload

# Local fallback site only; never a management interface.
rm -f /etc/nginx/sites-enabled/* /etc/nginx/conf.d/* 2>/dev/null || true
mkdir -p /var/www/html
printf '%s\n' '<!doctype html><html><body><h1>Unified VPS</h1></body></html>' >/var/www/html/index.html
cat >/etc/nginx/nginx.conf <<'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
events { worker_connections 1024; }
http {
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  sendfile on;
  server { listen 127.0.0.1:18080; server_name _; root /var/www/html; location / { try_files $uri /index.html; } }
}
EOF
nginx -t

curl -fsSL "${RAW}/config/haproxy.cfg" -o /etc/haproxy/haproxy.cfg
haproxy -c -f /etc/haproxy/haproxy.cfg

# Terminal-only menu and status command.
curl -fsSL "${RAW}/scripts/menu.sh" -o /usr/local/bin/menu
curl -fsSL "${RAW}/scripts/vps-status.sh" -o /usr/local/bin/vps-status
chmod 755 /usr/local/bin/menu /usr/local/bin/vps-status
ln -sfn /usr/local/bin/menu /usr/local/bin/tunnel
if [[ ! -f "$BASE/accounts.json" ]]; then printf '%s\n' '{"accounts":[]}' >"$BASE/accounts.json"; fi
chmod 600 "$BASE/accounts.json"

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin /usr/local/bin/menu --render
systemctl daemon-reload
systemctl enable --now nginx haproxy unified-vps-wstunnel-ssh unified-vps-ws-payload-ssh hysteria-server
systemctl enable xray >/dev/null 2>&1 || true
systemctl restart xray hysteria-server

curl -fsSL "${RAW}/config/fail2ban-unified-vps.local" -o /etc/fail2ban/jail.d/unified-vps.conf
systemctl enable --now fail2ban
systemctl restart fail2ban

cat >/etc/cron.d/unified-vps-daily-reboot <<'EOF'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
0 4 * * * root /usr/sbin/reboot >/dev/null 2>&1
EOF
chmod 644 /etc/cron.d/unified-vps-daily-reboot

# Final validation.
sshd -t
xray -test -config /usr/local/etc/xray/config.json
nginx -t
haproxy -c -f /etc/haproxy/haproxy.cfg
for s in ssh nginx haproxy xray hysteria-server unified-vps-wstunnel-ssh unified-vps-ws-payload-ssh fail2ban; do
  systemctl is-active --quiet "$s" || { echo "FAILED: $s"; systemctl status "$s" --no-pager -l || true; exit 1; }
done
for p in 22 80 143 443 8080 8443 8880; do
  ss -lntH "sport = :$p" 2>/dev/null | grep -q ":$p" || die "Missing TCP $p"
done
ss -lunH "sport = :53" 2>/dev/null | grep -q ':53' || die "Missing UDP 53"

echo
echo "=============================================="
echo " Unified VPS Tunnels installed"
echo "=============================================="
echo "Domain: $DOMAIN"
echo "Run: menu"
echo "No web panel is installed."
