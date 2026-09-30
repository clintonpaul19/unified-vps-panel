
chown hysteria:hysteria /etc/hysteria/server.crt /etc/hysteria/server.key
chmod 640 /etc/hysteria/server.crt /etc/hysteria/server.key

curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/systemd/hysteria-server.service" -o /etc/systemd/system/hysteria-server.service

printf '%s\n%s\nPANEL_PORT=6080\nSERVER_DOMAIN=%s\nACME_EMAIL=%s\nHY2_STATS_SECRET=%s\nSSH_WS_PATH=ssh\nSSH_WS_PORT=443\n' "$PANEL_ADMIN_USER" "$PANEL_ADMIN_PASSWORD" "$DOMAIN" "$ACME_EMAIL" "$HY2_STATS_SECRET" > /etc/unified-vps/panel.env
chmod 600 /etc/unified-vps/panel.env

curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/panel/app.py" -o /opt/unified-vps/panel.py
curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/systemd/unified-vps-panel.service" -o /etc/systemd/system/unified-vps-panel.service
curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/scripts/menu.sh" -o /usr/local/bin/menu
curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/scripts/vps-status.sh" -o /usr/local/bin/vps-status
curl -fsSL "https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/scripts/manage-user.sh" -o /usr/local/sbin/manage-user
chmod 755 /usr/local/bin/menu /usr/local/bin/vps-status /usr/local/sbin/manage-user

systemctl daemon-reload