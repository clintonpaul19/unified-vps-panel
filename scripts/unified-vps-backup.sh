#!/usr/bin/env bash
set -Eeuo pipefail
DEST=/opt/unified-vps/backups
STAMP="$(date +%Y%m%d-%H%M%S)"
TMP="$(mktemp -d)"
OUT="$DEST/unified-vps-$STAMP.tar.gz"
mkdir -p "$DEST"
chmod 700 "$DEST"
exec 9>/run/unified-vps-backup.lock
if ! flock -n 9; then
  echo "Another Unified VPS backup is already running." >&2
  exit 75
fi
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/etc/unified-vps" "$TMP/etc/hysteria" "$TMP/usr/local/etc/xray" "$TMP/etc/ssh" "$TMP/etc/haproxy" "$TMP/etc/nginx" "$TMP/var/www/html" "$TMP/etc/systemd/system" "$TMP/etc/fail2ban/jail.d" "$TMP/etc/cron.d" "$TMP/etc/iptables" "$TMP/opt/unified-vps" "$TMP/usr/local/sbin" "$TMP/usr/local/bin" "$TMP/root"
cp -a /etc/unified-vps/. "$TMP/etc/unified-vps/" 2>/dev/null || true
cp -a /etc/hysteria/. "$TMP/etc/hysteria/" 2>/dev/null || true
cp -a /usr/local/etc/xray/. "$TMP/usr/local/etc/xray/" 2>/dev/null || true
cp -a /etc/ssh/sshd_config.d "$TMP/etc/ssh/" 2>/dev/null || true
cp -a /etc/haproxy/haproxy.cfg "$TMP/etc/haproxy/" 2>/dev/null || true
cp -a /etc/nginx/nginx.conf "$TMP/etc/nginx/" 2>/dev/null || true
cp -a /var/www/html/index.html "$TMP/var/www/html/" 2>/dev/null || true
cp -a /etc/fail2ban/jail.d/unified-vps.local "$TMP/etc/fail2ban/jail.d/" 2>/dev/null || true
cp -a /etc/cron.d/unified-vps-daily-reboot "$TMP/etc/cron.d/" 2>/dev/null || true
cp -a /etc/iptables/rules.v4 "$TMP/etc/iptables/" 2>/dev/null || true
# Preserve acme.sh account/certificate state so restored VPS instances can
# continue automatic renewal instead of merely restoring the current cert.
cp -a /root/.acme.sh "$TMP/root/" 2>/dev/null || true
for unit in hysteria-server.service unified-vps-panel.service unified-vps-wstunnel-ssh.service unified-vps-ws-payload-ssh.service unified-vps-watchdog.service unified-vps-watchdog.timer unified-vps-backup.service unified-vps-backup.timer; do
  cp -a "/etc/systemd/system/$unit" "$TMP/etc/systemd/system/" 2>/dev/null || true
done
cp -a /usr/local/sbin/unified-vps-cert-reload "$TMP/usr/local/sbin/" 2>/dev/null || true
cp -a /usr/local/sbin/unified-vps-watchdog "$TMP/usr/local/sbin/" 2>/dev/null || true
cp -a /usr/local/sbin/unified-vps-backup "$TMP/usr/local/sbin/" 2>/dev/null || true
cp -a /usr/local/bin/menu "$TMP/usr/local/bin/" 2>/dev/null || true
cp -a /usr/local/bin/vps-status "$TMP/usr/local/bin/" 2>/dev/null || true
cp -a /usr/local/sbin/manage-user "$TMP/usr/local/sbin/" 2>/dev/null || true
cp -a /opt/unified-vps/panel.py "$TMP/opt/unified-vps/" 2>/dev/null || true
cp -a /opt/unified-vps/ws-payload-ssh.py "$TMP/opt/unified-vps/" 2>/dev/null || true

if command -v sqlite3 >/dev/null 2>&1 && [ -f /etc/unified-vps/panel.db ]; then
  sqlite3 /etc/unified-vps/panel.db ".backup '$TMP/etc/unified-vps/panel.db'"
fi

tar -C "$TMP" -czf "$OUT" .
chmod 600 "$OUT"
tar -tzf "$OUT" >/dev/null
ls -1t "$DEST"/unified-vps-*.tar.gz 2>/dev/null | tail -n +8 | xargs -r rm -f
printf '%s\n' "$OUT"
