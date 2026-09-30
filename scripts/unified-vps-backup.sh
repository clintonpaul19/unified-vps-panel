#!/usr/bin/env bash
set -Eeuo pipefail
DEST=/opt/unified-vps/backups
STAMP="$(date +%Y%m%d-%H%M%S)"
TMP="$(mktemp -d)"
OUT="$DEST/unified-vps-$STAMP.tar.gz"
mkdir -p "$DEST"
chmod 700 "$DEST"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/etc/unified-vps" "$TMP/etc/hysteria" "$TMP/usr/local/etc/xray" "$TMP/etc/ssh" "$TMP/etc/haproxy" "$TMP/opt/unified-vps"
cp -a /etc/unified-vps/. "$TMP/etc/unified-vps/" 2>/dev/null || true
cp -a /etc/hysteria/. "$TMP/etc/hysteria/" 2>/dev/null || true
cp -a /usr/local/etc/xray/. "$TMP/usr/local/etc/xray/" 2>/dev/null || true
cp -a /etc/ssh/sshd_config.d "$TMP/etc/ssh/" 2>/dev/null || true
cp -a /etc/haproxy/haproxy.cfg "$TMP/etc/haproxy/" 2>/dev/null || true
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
