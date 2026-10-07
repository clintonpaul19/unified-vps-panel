from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class Cursor:
    kind: str
    timestamp: datetime
    item_id: str


class InvalidCursor(ValueError):
    pass


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    try:
        padding = "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode((value + padding).encode("ascii"))
    except Exception as exc:
        raise InvalidCursor("invalid cursor encoding") from exc


def _sign(payload: str, secret: str) -> str:
    return _b64encode(hmac.new(secret.encode("utf-8"), payload.encode("ascii"), hashlib.sha256).digest())


def encode_cursor(*, kind: str, timestamp: datetime, item_id: str, secret: str) -> str:
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    timestamp = timestamp.astimezone(timezone.utc)
    raw = json.dumps({"v": 1, "k": kind, "t": timestamp.isoformat(), "i": str(item_id)}, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload = _b64encode(raw)
    return f"{payload}.{_sign(payload, secret)}"


def decode_cursor(*, value: str, kind: str, secret: str) -> Cursor:
    if not value or "." not in value:
        raise InvalidCursor("invalid cursor")
    payload, signature = value.split(".", 1)
    if not hmac.compare_digest(signature, _sign(payload, secret)):
        raise InvalidCursor("invalid cursor signature")
    try:
        body = json.loads(_b64decode(payload).decode("utf-8"))
        if body.get("v") != 1 or body.get("k") != kind:
            raise InvalidCursor("cursor does not match this endpoint")
        timestamp = datetime.fromisoformat(str(body["t"]))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        item_id = str(body["i"])
        if not item_id:
            raise InvalidCursor("cursor item id is missing")
        return Cursor(kind=kind, timestamp=timestamp.astimezone(timezone.utc), item_id=item_id)
    except InvalidCursor:
        raise
    except Exception as exc:
        raise InvalidCursor("invalid cursor payload") from exc
