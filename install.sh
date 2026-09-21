#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root.'; exit 1; }
. /etc/os-release
case "$ID" in ubuntu|debian) ;; *) echo "Unsupported OS: $ID"; exit 1;; esac
case "$(dpkg --print-architecture)" in amd64|arm64) ;; *) echo 'Supported architectures: amd64, arm64'; exit 1;; esac
export DEBIAN_FRONTEND=noninteractive

# IPv6 is intentionally disabled for this deployment.
cat >/etc/sysctl.d/99-unified-vps-disable-ipv6.conf <<'EOF'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
sysctl --system >/dev/null 2>&1 || true

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
apt-get install -y ca-certificates curl jq openssl iproute2 iptables iptables-persistent sqlite3 python3 openssh-server dnsutils lsof procps psmisc socat nginx haproxy cron

# HAProxy replaces SSLH as the public TCP/HTTP multiplexer.
# Remove any legacy SSLH instance so it cannot compete for ports 80/443/8443/143/8080.
systemctl disable --now sslh.service 2>/dev/null || true
apt-get purge -y sslh 2>/dev/null || true

systemctl disable --now sslh.service 2>/dev/null || true
systemctl stop nginx.service 2>/dev/null || true

# Stop any pre-existing Hysteria instance before ACME can invoke its reload hook.
# This is intentionally limited to the Hysteria service/process name.
for svc in hysteria-server hysteria; do
  systemctl stop "$svc.service" 2>/dev/null || true
  systemctl disable "$svc.service" 2>/dev/null || true
done
pkill -TERM -x hysteria 2>/dev/null || true
sleep 1


mkdir -p /opt/unified-vps /etc/unified-vps /etc/hysteria /var/log/unified-vps /usr/local/etc/xray
# Open the required ports without flushing or bypassing an existing firewall.
# Rules are inserted before the first terminal DROP/REJECT when one exists.
insert_firewall_rule() {
  local bin="$1"; shift
  local chain="$1"; shift
  local terminal_pos
  if "$bin" -C "$chain" "$@" -j ACCEPT 2>/dev/null; then
    return 0
  fi
  terminal_pos="$("$bin" -L "$chain" --line-numbers -n 2>/dev/null |
    awk '$1 ~ /^[0-9]+$/ && ($4=="DROP" || $4=="REJECT") {pos=$1} END {print pos}')"
  if [ -n "$terminal_pos" ]; then
    "$bin" -I "$chain" "$terminal_pos" "$@" -j ACCEPT
  else
    "$bin" -A "$chain" "$@" -j ACCEPT
  fi
}
for p in 80 443 143 8080 8443 8880; do
  insert_firewall_rule iptables INPUT -p tcp --dport "$p"
done
insert_firewall_rule iptables INPUT -p tcp --dport 22
insert_firewall_rule iptables INPUT -p tcp --dport 6080
for p in 53 443; do
  insert_firewall_rule iptables INPUT -p udp --dport "$p"
done
insert_firewall_rule iptables INPUT -p tcp --dport 53
insert_firewall_rule iptables INPUT -m conntrack --ctstate ESTABLISHED,RELATED

# IPv6 is disabled for this deployment; do not configure IPv6 firewall rules.

iptables-save >/etc/iptables/rules.v4

if ! command -v hysteria >/dev/null 2>&1; then curl -fsSL https://get.hy2.sh/ | bash; fi
# Xray's upstream installer starts the service immediately after installation.
# Seed a valid empty configuration first so a fresh install does not emit a
# misleading "Failed to enable and start the Xray service" warning.
mkdir -p /usr/local/etc/xray
if [ ! -s /usr/local/etc/xray/config.json ]; then
  printf '{}\n' >/usr/local/etc/xray/config.json
fi
if ! command -v xray >/dev/null 2>&1; then bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install; fi
curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/config/xray.json" -o /usr/local/etc/xray/config.json

# Install wstunnel for SSH-over-WebSocket. HAProxy handles cleartext WS on
# 80/8880, while Xray's TLS fallback handles WSS on 443/8443.
WSTUNNEL_VERSION="10.6.2"
case "$(dpkg --print-architecture)" in
  amd64) WSTUNNEL_ARCH="amd64" ;;
  arm64) WSTUNNEL_ARCH="arm64" ;;
  *) echo "Unsupported architecture for wstunnel."; exit 1 ;;
esac
WSTUNNEL_TARBALL="wstunnel_${WSTUNNEL_VERSION}_linux_${WSTUNNEL_ARCH}.tar.gz"
curl -fsSL "https://github.com/erebe/wstunnel/releases/download/v${WSTUNNEL_VERSION}/${WSTUNNEL_TARBALL}" -o /tmp/${WSTUNNEL_TARBALL}
tar -xzf /tmp/${WSTUNNEL_TARBALL} -C /tmp
install -m 0755 /tmp/wstunnel /usr/local/bin/wstunnel
rm -f /tmp/${WSTUNNEL_TARBALL} /tmp/wstunnel

tmp_xray=/usr/local/etc/xray/config.json.ws.tmp
jq '(.inbounds[] | select(.tag=="trojan443") | .settings.fallbacks) |= ([{"path":"/ssh","dest":"127.0.0.1:18446","xver":0}] + .)' /usr/local/etc/xray/config.json > "$tmp_xray"
mv "$tmp_xray" /usr/local/etc/xray/config.json

cat >/etc/systemd/system/unified-vps-wstunnel-ssh.service <<'EOF'
[Unit]
Description=Unified VPS SSH over WebSocket
After=network-online.target ssh.service
Requires=ssh.service
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/local/bin/wstunnel server --restrict-to 127.0.0.1:22 ws://127.0.0.1:18446
Restart=always
RestartSec=2
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now unified-vps-wstunnel-ssh.service

# Install the legacy payload bridge. It accepts both the minimal
# GET/Host/Upgrade payload used by tunnel clients and a normal HTTPS GET.
# Normal GET requests receive HTTP 200; WebSocket upgrades are proxied to SSH.
curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/scripts/ws-payload-ssh.py" -o /opt/unified-vps/ws-payload-ssh.py
chmod 755 /opt/unified-vps/ws-payload-ssh.py
curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/systemd/unified-vps-ws-payload-ssh.service" -o /etc/systemd/system/unified-vps-ws-payload-ssh.service
systemctl daemon-reload
systemctl enable --now unified-vps-ws-payload-ssh.service

# UDPGW is intentionally not installed. It can interfere with SSHWS throughput.



# Get a trusted Let's Encrypt certificate for the supplied domain.
# Standalone ACME needs TCP/80 temporarily free.
# Stop services that could rebind ports while the final configuration is built.
systemctl stop haproxy unified-vps-sslh-xray unified-vps-sslh-web unified-vps-sslh-ssh sslh xray nginx hysteria-server 2>/dev/null || true
systemctl mask hysteria-server.service 2>/dev/null || true
curl -fsSL https://get.acme.sh | sh -s email="$ACME_EMAIL"
"$HOME/.acme.sh/acme.sh" --set-default-ca --server letsencrypt

cat >/usr/local/sbin/unified-vps-cert-reload <<'EOF'
#!/usr/bin/env bash
set -u
systemctl try-restart xray.service 2>/dev/null || true
systemctl try-restart hysteria-server.service 2>/dev/null || true
EOF
chmod 755 /usr/local/sbin/unified-vps-cert-reload

# Issue the certificate. acme.sh may return a non-zero status when an existing
# certificate is still current; the mandatory install-cert step below verifies
# that a usable certificate is actually available.
"$HOME/.acme.sh/acme.sh" --issue --standalone -d "$DOMAIN" || true

"$HOME/.acme.sh/acme.sh" --install-cert -d "$DOMAIN" \
  --fullchain-file /etc/unified-vps/xray.crt \
  --key-file /etc/unified-vps/xray.key \
  --reloadcmd "/usr/local/sbin/unified-vps-cert-reload"
chmod 600 /etc/unified-vps/xray.key
chmod 644 /etc/unified-vps/xray.crt

# Do not restart Xray/Hysteria from acme.sh during first installation.
# Their final configurations are created below, after certificates are installed.
echo "Certificate installed successfully."

XRAY_USER="$(systemctl show xray.service -p User --value 2>/dev/null || true)"
XRAY_USER="${XRAY_USER:-nobody}"
if id "$XRAY_USER" >/dev/null 2>&1; then
  XRAY_GROUP="$(id -gn "$XRAY_USER" 2>/dev/null || true)"
  if [ -n "$XRAY_GROUP" ]; then
    chown "$XRAY_USER:$XRAY_GROUP" /etc/unified-vps/xray.key /etc/unified-vps/xray.crt 2>/dev/null || true
  fi
  chmod 640 /etc/unified-vps/xray.key 2>/dev/null || true
fi

echo "Testing Xray configuration..."
if ! xray -test -config /usr/local/etc/xray/config.json; then
  echo "ERROR: Xray configuration test failed."
  systemctl status xray --no-pager -l 2>/dev/null || true
  journalctl -u xray -n 50 --no-pager 2>/dev/null || true
  exit 1
fi

if ! command -v speedtest >/dev/null 2>&1; then
  curl -fsSL https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash
  apt-get update
  apt-get install -y speedtest
fi

# Hysteria owns UDP/53. Keep its service masked until all configuration
# is complete so ACME hooks or stale unit state cannot restart it early.
for legacy in udp-custom udp-mini; do
  if systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -qx "$legacy.service"; then
    systemctl disable --now "$legacy.service" 2>/dev/null || true
  fi
done
systemctl stop hysteria-server.service 2>/dev/null || true

# Do not let systemd-resolved occupy UDP/53. Keep outbound DNS working
# with static resolvers while Hysteria owns this port.
if systemctl is-enabled --quiet systemd-resolved 2>/dev/null || systemctl is-active --quiet systemd-resolved 2>/dev/null; then
  systemctl disable --now systemd-resolved.service 2>/dev/null || true
fi
if [ -L /etc/resolv.conf ] || grep -q '127\.0\.0\.53' /etc/resolv.conf 2>/dev/null; then
  rm -f /etc/resolv.conf
  cat >/etc/resolv.conf <<'EOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF
  chmod 644 /etc/resolv.conf
fi

cp /etc/unified-vps/xray.crt /etc/hysteria/server.crt
cp /etc/unified-vps/xray.key /etc/hysteria/server.key
chmod 640 /etc/hysteria/server.key
HY2_STATS_SECRET="$(openssl rand -hex 24)"
cat >/etc/hysteria/config.yaml <<YAML
listen: 0.0.0.0:53
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

# SSH is kept on loopback; HAProxy exposes it on the requested public ports.
mkdir -p /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/99-unified-vps.conf <<'EOF'
AddressFamily inet
Port 22
ListenAddress 0.0.0.0:22
PasswordAuthentication yes
PermitEmptyPasswords no
EOF
sshd -t
# Restart SSH so a pre-existing sshd listener cannot retain IPv6 or a
# previous ListenAddress after repeated installations.
systemctl restart ssh

# NGINX is the plain HTTP service behind HAProxy on TCP/8080.
# Rebuild the NGINX configuration from scratch so no legacy IPv6 listener
# can survive across repeated installations.
mkdir -p /var/www/html
cat >/var/www/html/index.html <<'EOF'
<!doctype html><html><head><meta charset="utf-8"><title>Unified VPS</title></head><body><h1>Unified VPS</h1><p>Server is online.</p></body></html>
EOF

rm -f /etc/nginx/sites-enabled/* /etc/nginx/conf.d/* 2>/dev/null || true
mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/conf.d
cat >/etc/nginx/nginx.conf <<'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    sendfile on;
    keepalive_timeout 65;

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    server {
        listen 127.0.0.1:18080;
        server_name _;
        return 301 https://$host$request_uri;
    }
}
EOF

nginx -t

# HAProxy is the public transport multiplexer. It preserves raw SSH,
# detects cleartext HTTP/WebSocket traffic on 80/8880, and sends TLS traffic
# on 443/8443 to Xray without terminating TLS itself.
curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/config/haproxy.cfg" -o /etc/haproxy/haproxy.cfg
haproxy -c -f /etc/haproxy/haproxy.cfg

chown hysteria:hysteria /etc/hysteria/server.crt /etc/hysteria/server.key
chmod 640 /etc/hysteria/server.crt /etc/hysteria/server.key

cat >/etc/systemd/system/hysteria-server.service <<'EOF'
[Unit]
Description=Hysteria 2 Server
After=network-online.target unified-vps-panel.service
Requires=unified-vps-panel.service
Wants=network-online.target
[Service]
User=hysteria
Group=hysteria
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.yaml
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF

printf 'ADMIN_USER=spiderman\nADMIN_PASSWORD=spiderman\nPANEL_PORT=6080\nSERVER_DOMAIN=%s\nACME_EMAIL=%s\nHY2_STATS_SECRET=%s\nSSH_WS_PATH=ssh\nSSH_WS_PORT=443\n' "$DOMAIN" "$ACME_EMAIL" "$HY2_STATS_SECRET" > /etc/unified-vps/panel.env
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
# Enabling units must not prevent installation from reaching the explicit
# startup/diagnostic checks below. Some systemd environments may report a
# stale/failed job while creating the enablement links.
systemctl enable ssh nginx haproxy unified-vps-panel xray hysteria-server || true
systemctl start ssh nginx
if ! systemctl start unified-vps-panel; then
  echo "ERROR: unified-vps-panel.service failed to start."
  systemctl status unified-vps-panel --no-pager -l || true
  echo "--- panel journal ---"
  journalctl -u unified-vps-panel -n 80 --no-pager || true
  echo "--- port 6080 ---"
  ss -ltnp 2>/dev/null | grep ':6080' || true
  exit 1
fi
sleep 1
systemctl start xray

# Release the temporary mask only after all certificate/configuration work is done.
systemctl unmask hysteria-server.service 2>/dev/null || true

# Check immediately before starting Hysteria so any late listener is identified.
if lsof -nP -iUDP:53 2>/dev/null | grep -q UDP; then
  echo "ERROR: UDP/53 is already in use:"
  lsof -nP -iUDP:53 2>/dev/null || true
  exit 1
fi
systemctl start hysteria-server
systemctl start haproxy
sshd -t
xray -test -config /usr/local/etc/xray/config.json
nginx -t
haproxy -c -f /etc/haproxy/haproxy.cfg
SERVICES=(ssh nginx haproxy unified-vps-panel xray hysteria-server)
FAILED=0
for s in "${SERVICES[@]}"; do
  if ! systemctl is-active --quiet "$s"; then
    echo "ERROR: service failed: $s"
    systemctl status "$s" --no-pager -l || true
    journalctl -u "$s" -n 40 --no-pager || true
    FAILED=1
  fi
done
if [ "$FAILED" -ne 0 ]; then
  echo "Installation aborted because one or more required services failed."
  exit 1
fi

echo "Core configuration checks passed."

echo
echo "=============================================="
echo " Unified VPS Panel installation complete"
echo "=============================================="
echo "Domain: $DOMAIN"
echo "Panel: http://$DOMAIN:6080/"
echo "Panel backend: 127.0.0.1:6080"
echo "Panel username: spiderman"
echo "Panel password: spiderman"
echo "Generated ACME email: $ACME_EMAIL"
echo "VLESS: TLS/WS on TCP 80 and 443"
echo "VMess: TLS/WS on TCP 80 and 443"
echo "Trojan: TLS on TCP 80 and 443"
echo "Hysteria 2: UDP/53 using $DOMAIN"
echo "SSH transports: WS 80/8880, WSS 443/8443, raw TCP 143/8080/8443 using $DOMAIN"
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
