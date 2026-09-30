#!/usr/bin/env bash
set -Eeuo pipefail

PANEL_ENV="/etc/unified-vps/panel.env"
ADMIN_FILE="/etc/unified-vps/admin.json"
PANEL_PORT="$(sed -n 's/^PANEL_PORT=//p' "$PANEL_ENV" 2>/dev/null | tail -n1)"
PANEL_PORT="${PANEL_PORT:-6080}"

ADMIN_USER=""
ADMIN_PASSWORD=""
if [[ -s "$ADMIN_FILE" ]] && command -v jq >/dev/null 2>&1; then
  ADMIN_USER="$(jq -r '.username // empty' "$ADMIN_FILE" 2>/dev/null || true)"
  ADMIN_PASSWORD="$(jq -r '.password // empty' "$ADMIN_FILE" 2>/dev/null || true)"
fi
if [[ -z "$ADMIN_USER" || -z "$ADMIN_PASSWORD" ]]; then
  echo "Panel administrator is not configured. Complete first-run setup in the web panel." >&2
  exit 1
fi

API="http://127.0.0.1:${PANEL_PORT}"

case "${1:-}" in
  add)
    curl -fsS -u "${ADMIN_USER}:${ADMIN_PASSWORD}" \
      -H 'Content-Type: application/json' \
      -d "${2:?JSON required}" \
      "${API}/api/users"
    ;;
  delete)
    id="${2:?ID required}"
    [[ "$id" =~ ^[0-9]+$ ]] || { echo "ID must be numeric." >&2; exit 2; }
    curl -fsS -u "${ADMIN_USER}:${ADMIN_PASSWORD}" \
      -H 'Content-Type: application/json' \
      -d "$(jq -nc --argjson id "$id" '{id:$id}')" \
      "${API}/api/users/delete"
    ;;
  *)
    echo 'Usage: manage-user.sh add <json>|delete <id>'
    exit 2
    ;;
esac
