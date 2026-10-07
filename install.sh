#!/usr/bin/env bash
set -Eeuo pipefail

REPO=clintonpaul19/unified-vps-panel
BASE=/etc/unified-vps

[[ $EUID -eq 0 ]] || { echo "Run as root." >&2; exit 1; }

echo "=== Unified VPS Tunnels ==="
read -r -p "Domain pointing to this VPS: " DOMAIN
DOMAIN="$(printf '%s' "$DOMAIN" | sed -E 's#^https?://##; s#/.*$##')"
[[ "$DOMAIN" == *.* && "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "Invalid domain."; exit 1; }

apt-get update
apt-get install -y ca-certificates curl openssl iproute2 iptables iptables-persistent python3 openssh-server dnsutils lsof procps psmisc nginx haproxy cron fail2ban jq

mkdir -p "$BASE" /etc/hysteria /usr/local/etc/xray/certs /opt/unified-vps /etc/systemd/system
chmod 700 "$BASE"
printf 'DOMAIN=%s\n' "$DOMAIN" > "$BASE/config.env"
chmod 600 "$BASE/config.env"

# Remove all web-panel state and services from older Unified VPS releases.
systemctl disable --now unified-vps-panel.service 2>/dev/null || true
rm -f /etc/systemd/system/unified-vps-panel.service
rm -f /usr/local/sbin/manage-user /usr/local/bin/menu
rm -rf /opt/unified-vps/uvps_panel /opt/unified-vps/panel.py
rm -f "$BASE/admin.json" "$BASE/panel.db" "$BASE/panel.env"
rm -rf /opt/unified-vps/backups /var/log/unified-vps
for u in unified-vps-backup.service unified-vps-backup.timer unified-vps-watchdog.service unified-vps-watchdog.timer; do
  systemctl disable --now "$u" 2>/dev/null || true
  rm -f "/etc/systemd/system/$u"
done
rm -f /etc/systemd/system/multi-user.target.wants/unified-vps-panel.service
rm -f /etc/systemd/system/unified-vps-sslh-xray.service

# Remove the old panel port rule and keep only tunnel ports.
while iptables -D INPUT -p tcp --dport 6080 -j ACCEPT 2>/dev/null; do :; done
# UDP/53 is the only port 53 transport. Remove the legacy TCP/53 rule from
# older installations so it is not unnecessarily exposed.
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
if [[ -f /etc/systemd/system/xray.service ]]; then
  sed -i -E 's/^[[:space:]]*User=[^[:space:]]+$/User=xray/' /etc/systemd/system/xray.service
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

# WebSocket SSH helpers.
WSTUNNEL_VERSION=10.6.2
case "$(dpkg --print-architecture)" in
  amd64) WSTUNNEL_ARCH=amd64 ;;
  arm64) WSTUNNEL_ARCH=arm64 ;;
  *) echo "Unsupported architecture."; exit 1 ;;
esac
TARBALL="wstunnel_$WSTUNNEL_VERSION"_linux_"$WSTUNNEL_ARCH".tar.gz"
curl -fsSL "https://github.com/erebe/wstunnel/releases/download/v$WSTUNNEL_VERSION/$TARBALL" -o "/tmp/$TARBALL"
tar -xzf "/tmp/$TARBALL" -C /tmp
install -m 0755 /tmp/wstunnel /usr/local/bin/wstunnel
rm -f "/tmp/$TARBALL" /tmp/wstunnel

curl -fsSL "https://raw.githubusercontent.com/$REPO/main/scripts/ws-payload-ssh.py" -o /opt/unified-vps/ws-payload-ssh.py
chmod 755 /opt/unified-vps/ws-payload-ssh.py
curl -fsSL "https://raw.githubusercontent.com/$REPO/main/systemd/unified-vps-wstunnel-ssh.service" -o /etc/systemd/system/unified-vps-wstunnel-ssh.service
curl -fsSL "https://raw.githubusercontent.com/$REPO/main/systemd/unified-vps-ws-payload-ssh.service" -o /etc/systemd/system/unified-vps-ws-payload-ssh.service

# TLS certificate. Create the reload hook before registering the certificate.
cat >/usr/local/sbin/unified-vps-cert-reload <<'EOF'
#!/usr/bin/env bash
set -u
BASE=/etc/unified-vps
install -d -m 755 /usr/local/etc/xray/certs
install -o xray -g xray -m 0644 "$BASE/xray.crt" /usr/local/etc/xray/certs/xray.crt 2>/dev/null || true
install -o xray -g xray -m 0640 "$BASE/xray.key" /usr/local/etc/xray/certs/xray.key 2>/dev/null || true
install -o hysteria -g hysteria -m 0644 "$BASE/xray.crt" /etc/hysteria/server.crt 2>/dev/null || true
install -o hysteria -g hysteria -m 0640 "$BASE/xray.key" /etc/hysteria/server.key 2>/dev/null || true
systemctl try-restart xray hysteria-server 2>/dev/null || true
EOF
chmod 755 /usr/local/sbin/unified-vps-cert-reload

if ! command -v acme.sh >/dev/null 2>&1; then
  curl -fsSL https://get.acme.sh | sh -s email="acme-$(openssl rand -hex 8)@$DOMAIN"
fi
ACME="$HOME/.acme.sh/acme.sh"
[[ -x "$ACME" || -s "$ACME" ]] || { echo "acme.sh installation failed."; exit 1; }

CERT_REUSE=0
if [[ -s "$BASE/xray.crt" ]] && openssl x509 -in "$BASE/xray.crt" -noout -checkend 2592000 >/dev/null 2>&1    && openssl x509 -in "$BASE/xray.crt" -noout -checkhost "$DOMAIN" >/dev/null 2>&1; then
  CERT_REUSE=1
  echo "Existing TLS certificate is valid for at least 30 days; reusing it."
fi
if [[ "$CERT_REUSE" -ne 1 ]]; then
  "$ACME" --issue --standalone -d "$DOMAIN"     --pre-hook "systemctl stop haproxy nginx"     --post-hook "systemctl start nginx"
fi
"$ACME" --install-cert -d "$DOMAIN"   --fullchain-file "$BASE/xray.crt"   --key-file "$BASE/xray.key"   --reloadcmd "/usr/local/sbin/unified-vps-cert-reload"
/usr/local/sbin/unified-vps-cert-reload

# UDP/53 belongs to Hysteria 2. Prevent old UDP helpers or systemd-resolved
# from owning the port.
for legacy in udp-custom udp-mini; do
  if systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -qx "$legacy.service"; then
    systemctl disable --now "$legacy.service" 2>/dev/null || true
  fi
done
if systemctl is-enabled --quiet systemd-resolved 2>/dev/null || systemctl is-active --quiet systemd-resolved 2>/dev/null; then
  systemctl disable --now systemd-resolved.service 2>/dev/null || true
fi
if [[ -L /etc/resolv.conf ]] || grep -q '127\.0\.0\.53' /etc/resolv.conf 2>/dev/null; then
  rm -f /etc/resolv.conf
  printf '%s\n' 'nameserver 1.1.1.1' 'nameserver 8.8.8.8' > /etc/resolv.conf
  chmod 644 /etc/resolv.conf
fi

# Local HTTP fallback only.
rm -f /etc/nginx/sites-enabled/* /etc/nginx/conf.d/* 2>/dev/null || true
mkdir -p /var/www/html
printf '%s\n' '<!doctype html><html><body><h1>Unified VPS</h1><p>Online.</p></body></html>' >/var/www/html/index.html
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

curl -fsSL "https://raw.githubusercontent.com/$REPO/main/config/haproxy.cfg" -o /etc/haproxy/haproxy.cfg
haproxy -c -f /etc/haproxy/haproxy.cfg

# Install the one terminal tunnel manager.
curl -fsSL "https://raw.githubusercontent.com/$REPO/main/scripts/tunnel.sh" -o /usr/local/bin/tunnel
chmod 755 /usr/local/bin/tunnel
ln -sfn /usr/local/bin/tunnel /usr/local/bin/menu
if [[ ! -f "$BASE/accounts.json" ]]; then
  printf '%s\n' '{"accounts":[]}' > "$BASE/accounts.json"
fi
chmod 600 "$BASE/accounts.json"

# Render and start.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin /usr/local/bin/tunnel --render
systemctl daemon-reload
systemctl enable --now nginx haproxy unified-vps-wstunnel-ssh unified-vps-ws-payload-ssh
systemctl restart xray hysteria-server

curl -fsSL "https://raw.githubusercontent.com/$REPO/main/config/fail2ban-unified-vps.local" -o /etc/fail2ban/jail.d/unified-vps.conf
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
xray -test -config "$XRAY_CFG"
nginx -t
haproxy -c -f /etc/haproxy/haproxy.cfg
for s in ssh nginx haproxy xray hysteria-server unified-vps-wstunnel-ssh unified-vps-ws-payload-ssh fail2ban; do
  systemctl is-active --quiet "$s" || { echo "FAILED: $s"; systemctl status "$s" --no-pager -l || true; exit 1; }
done
for p in 22 80 143 443 8080 8443 8880; do ss -lntH "sport = :$p" 2>/dev/null | grep -q ":$p" || { echo "Missing TCP $p"; exit 1; }; done
ss -lunH "sport = :53" 2>/dev/null | grep -q ':53' || { echo "Missing UDP 53"; exit 1; }

echo
echo "=============================================="
echo " Unified VPS Tunnels installed"
echo "=============================================="
echo "Domain: $DOMAIN"
echo "Run: menu"
echo "No web panel is installed."
