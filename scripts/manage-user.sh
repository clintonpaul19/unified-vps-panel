#!/usr/bin/env bash
set -Eeuo pipefail

PYTHONPATH="/opt/unified-vps" /usr/bin/python3 - "${1:-}" "${2:-}" <<'PY'
import json
import sys

from uvps_panel.accounts import apply_user_action, create_user

action = sys.argv[1]
value = sys.argv[2]

if action == "add":
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON: {exc}")
    if not isinstance(payload, dict):
        raise SystemExit("JSON payload must be an object.")
    result = create_user(payload)
    print(json.dumps(result, separators=(",", ":"), ensure_ascii=False))
elif action == "delete":
    try:
        user_id = int(value)
    except (TypeError, ValueError):
        raise SystemExit("ID must be numeric.")
    apply_user_action(user_id, "delete")
    print(json.dumps({"ok": True, "id": user_id}, separators=(",", ":")))
else:
    raise SystemExit("Usage: manage-user add <json>|delete <id>")
PY
