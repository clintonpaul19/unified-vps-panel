import hashlib
import secrets
from datetime import datetime, timezone

from argon2 import PasswordHasher
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .config import settings

_hasher = PasswordHasher()

def hash_password(password: str) -> str:
    return _hasher.hash(password)

def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except Exception:
        return False

def token_hash(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()

def new_node_token() -> str:
    return secrets.token_urlsafe(48)

def session_serializer() -> URLSafeTimedSerializer:
    if not settings.session_secret:
        raise RuntimeError("SESSION_SECRET must be configured")
    return URLSafeTimedSerializer(settings.session_secret, salt="unified-vps-session")

def make_session(user_id: str) -> str:
    return session_serializer().dumps({"uid": user_id, "iat": int(datetime.now(timezone.utc).timestamp())})

def read_session(value: str) -> str | None:
    try:
        data = session_serializer().loads(value, max_age=settings.session_ttl_seconds)
        return str(data["uid"])
    except (BadSignature, SignatureExpired, KeyError, TypeError, ValueError):
        return None
