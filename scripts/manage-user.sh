#!/usr/bin/env bash
set -Eeuo pipefail
source /etc/unified-vps/panel.env
case "${1:-}" in
 add) curl -fsS -u "$ADMIN_USER:$ADMIN_PASSWORD" -H 'Content-Type: application/json' -d "${2:?JSON required}" "http://127.0.0.1:${PANEL_PORT}/api/users";;
 delete) curl -fsS -u "$ADMIN_USER:$ADMIN_PASSWORD" -H 'Content-Type: application/json' -d "{\"id\":${2:?ID required}}" "http://127.0.0.1:${PANEL_PORT}/api/users/delete";;
 *) echo 'Usage: manage-user.sh add <json>|delete <id>'; exit 2;;
esac
