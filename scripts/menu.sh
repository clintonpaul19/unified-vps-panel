
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
    echo "Update download failed."; rm -f "$tmp_menu" "$tmp_app" "$tmp_haproxy" "$tmp_payload" "$tmp_wstunnel_unit" "$tmp_hysteria_unit" "$tmp_cert_hook" "$tmp_status" "$tmp_watch" "$tmp_watch_unit" "$tmp_timer" "$tmp_backup" "$tmp_backup_unit" "$tmp_backup_timer" "$tmp_f2b"; pause; return
  fi
  if ! bash -n "$tmp_menu" || ! bash -n "$tmp_cert_hook" || ! bash -n "$tmp_status" || ! bash -n "$tmp_watch" || ! bash -n "$tmp_backup" || ! python3 -m py_compile "$tmp_app" "$tmp_payload" || ! haproxy -c -f "$tmp_haproxy" || ! systemd-analyze verify "$tmp_wstunnel_unit" "$tmp_hysteria_unit" "$tmp_watch_unit" "$tmp_timer" "$tmp_backup_unit" "$tmp_backup_timer"; then
    echo "Validation failed. Nothing was installed."; rm -f "$tmp_menu" "$tmp_app" "$tmp_haproxy" "$tmp_payload" "$tmp_wstunnel_unit" "$tmp_hysteria_unit" "$tmp_cert_hook" "$tmp_status" "$tmp_watch" "$tmp_watch_unit" "$tmp_timer" "$tmp_backup" "$tmp_backup_unit" "$tmp_backup_timer" "$tmp_f2b"; pause; return
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