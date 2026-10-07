import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time

from .config import ADMIN_FILE, BASE, LOGIN_FAILURES, LOGIN_LOCK, LOGIN_MAX_FAILURES, LOGIN_WINDOW, PANEL_ENV, SESSION_COOKIE, SESSION_TTL

ADMIN = os.environ.get("ADMIN_USER", "").strip()
PASSWORD_HASH = ""
_RETIRED_CREDENTIAL_DIGEST = "89b4cdab4d0d839fcf432ca76640ffe90da27a63b6f0ad7bbf1d644f5ccd91a9"
_SCRYPT_N = 32768
_SCRYPT_R = 8
_SCRYPT_P = 3
_SCRYPT_DKLEN = 32
_SCRYPT_MAXMEM = 128 * 1024 * 1024


def _valid_username(username: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,31}", username))


def _valid_password(password: str) -> bool:
    return 8 <= len(password) <= 128 and "\n" not in password and "\r" not in password


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
        maxmem=_SCRYPT_MAXMEM,
    )
    return "scrypt$1$32768$8$3$" + _b64(salt) + "$" + _b64(digest)


def _verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, version, n, r, p, salt_text, digest_text = encoded.split("$", 6)
        if algorithm != "scrypt" or version != "1":
            return False
        n_i, r_i, p_i = int(n), int(r), int(p)
        if (n_i, r_i, p_i) != (_SCRYPT_N, _SCRYPT_R, _SCRYPT_P):
            return False
        salt = _unb64(salt_text)
        expected = _unb64(digest_text)
        if len(expected) != _SCRYPT_DKLEN:
            return False
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n_i,
            r=r_i,
            p=p_i,
            dklen=len(expected),
            maxmem=_SCRYPT_MAXMEM,
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, UnicodeError):
        return False


def _write_credentials(username: str, password_hash: str) -> None:
    os.makedirs(BASE, exist_ok=True, mode=0o700)
    os.chmod(BASE, 0o700)
    tmp = ADMIN_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"username": username, "password_hash": password_hash}, f, ensure_ascii=False)
        f.write("\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, ADMIN_FILE)
    os.chmod(ADMIN_FILE, 0o600)


def _blank_legacy_environment() -> None:
    try:
        with open(PANEL_ENV, encoding="utf-8") as f:
            lines = f.read().splitlines()
        lines = [line for line in lines if not line.startswith("ADMIN_USER=") and not line.startswith("ADMIN_PASSWORD=")]
        lines += ["ADMIN_USER=", "ADMIN_PASSWORD="]
        tmp_env = PANEL_ENV + ".tmp"
        with open(tmp_env, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        os.chmod(tmp_env, 0o600)
        os.replace(tmp_env, PANEL_ENV)
    except OSError:
        pass


def _load_admin_credentials():
    global ADMIN, PASSWORD_HASH
    try:
        st = os.stat(ADMIN_FILE)
        if st.st_uid != 0:
            return
        os.chmod(ADMIN_FILE, 0o600)
        with open(ADMIN_FILE, encoding="utf-8") as f:
            data = json.load(f)

        user = str(data.get("username", "")).strip()
        encoded = str(data.get("password_hash", ""))
        if _valid_username(user) and encoded.startswith("scrypt$1$") and _verify_password("invalid", encoded) is False:
            try:
                # Keep the already-hardened hash format, but do not needlessly
                # rehash it during startup. The negative check only validates shape.
                algorithm, version, n, r, p, salt_text, digest_text = encoded.split("$", 6)
                _unb64(salt_text)
                digest = _unb64(digest_text)
                valid = algorithm == "scrypt" and version == "1" and (int(n), int(r), int(p)) == (_SCRYPT_N, _SCRYPT_R, _SCRYPT_P) and len(digest) == _SCRYPT_DKLEN
            except (ValueError, TypeError, UnicodeError):
                valid = False
            if valid:
                ADMIN, PASSWORD_HASH = user, encoded
                _blank_legacy_environment()
                return

        legacy_password = str(data.get("password", ""))
        if (
            _valid_username(user)
            and _valid_password(legacy_password)
            and hashlib.sha256(f"{user}:{legacy_password}".encode("utf-8")).hexdigest() != _RETIRED_CREDENTIAL_DIGEST
        ):
            encoded = _hash_password(legacy_password)
            _write_credentials(user, encoded)
            _blank_legacy_environment()
            ADMIN, PASSWORD_HASH = user, encoded
            return

        try:
            os.unlink(ADMIN_FILE)
        except OSError:
            pass
        _blank_legacy_environment()
    except Exception:
        pass


_load_admin_credentials()


def admin_configured() -> bool:
    return bool(ADMIN and PASSWORD_HASH)


def _session_cookie(username: str) -> str:
    issued = str(int(time.time()))
    payload = f"{username}|{issued}"
    sig = hmac.new(
        f"{ADMIN}\0{PASSWORD_HASH}".encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload}|{sig}"


def _session_valid(cookie: str) -> bool:
    if not admin_configured() or not cookie:
        return False
    try:
        username, issued_text, sig = cookie.split("|", 2)
        issued = int(issued_text)
        if username != ADMIN or issued < 0 or time.time() - issued > SESSION_TTL:
            return False
        expected = hmac.new(
            f"{ADMIN}\0{PASSWORD_HASH}".encode("utf-8"),
            f"{username}|{issued}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(sig, expected)
    except (TypeError, ValueError):
        return False


def verify_admin_credentials(username: str, password: str) -> bool:
    return bool(
        admin_configured()
        and hmac.compare_digest(username, ADMIN)
        and _verify_password(password, PASSWORD_HASH)
    )


def auth(headers, basic_allowed=False) -> bool:
    if not admin_configured():
        return False

    if basic_allowed:
        value = headers.get("Authorization", "")
        if value.startswith("Basic "):
            try:
                raw = base64.b64decode(value[6:], validate=True).decode("utf-8")
                username, password = raw.split(":", 1)
                if verify_admin_credentials(username, password):
                    return True
            except (ValueError, UnicodeError):
                pass

    for item in headers.get("Cookie", "").split(";"):
        item = item.strip()
        if item.startswith(SESSION_COOKIE + "="):
            return _session_valid(item.split("=", 1)[1])
    return False


def _save_admin_credentials(username: str, password: str) -> None:
    global ADMIN, PASSWORD_HASH
    encoded = _hash_password(password)
    _write_credentials(username, encoded)
    _blank_legacy_environment()
    ADMIN, PASSWORD_HASH = username, encoded
