from __future__ import annotations

import logging
import time
from uuid import uuid4

from .metrics import record_request

from .config import settings

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("uvps.api")


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach a correlation id and avoid high-volume success-log amplification."""

    async def dispatch(self, request: Request, call_next) -> Response:
        incoming = request.headers.get("X-Request-ID", "")
        request_id = incoming.strip()[:128] if incoming else ""
        if not request_id or any(ord(ch) < 32 for ch in request_id):
            request_id = str(uuid4())

        if (
            request.method not in {"GET", "HEAD", "OPTIONS", "TRACE"}
            and request.url.path.startswith("/v1/")
            and request.url.path not in {"/v1/auth/login", "/v1/auth/bootstrap"}
            and request.cookies.get("uvps_session")
            and not (request.headers.get("Authorization", "").startswith("Bearer "))
        ):
            csrf_cookie = request.cookies.get("uvps_csrf", "")
            csrf_header = request.headers.get("X-CSRF-Token", "")
            if not csrf_cookie or not csrf_header or len(csrf_cookie) > 256 or len(csrf_header) > 256:
                return Response('{"detail":"CSRF validation failed"}', status_code=403, media_type="application/json")
            import hmac
            if not hmac.compare_digest(csrf_cookie, csrf_header):
                return Response('{"detail":"CSRF validation failed"}', status_code=403, media_type="application/json")

        request.state.request_id = request_id
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            elapsed_ms = (time.perf_counter() - started) * 1000
            logger.exception(
                "request failed request_id=%s method=%s path=%s elapsed_ms=%.1f",
                request_id,
                request.method,
                request.url.path,
                elapsed_ms,
            )
            raise

        elapsed_ms = (time.perf_counter() - started) * 1000
        record_request(request.method, response.status_code, elapsed_ms / 1000.0)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "font-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        )
        response.headers["Cache-Control"] = "no-store"

        if response.status_code >= 500:
            logger.error(
                "request server_error request_id=%s method=%s path=%s status=%s elapsed_ms=%.1f",
                request_id,
                request.method,
                request.url.path,
                response.status_code,
                elapsed_ms,
            )
        elif response.status_code >= 400 or elapsed_ms >= 1000:
            logger.warning(
                "request notable request_id=%s method=%s path=%s status=%s elapsed_ms=%.1f",
                request_id,
                request.method,
                request.url.path,
                response.status_code,
                elapsed_ms,
            )
        else:
            logger.debug(
                "request request_id=%s method=%s path=%s status=%s elapsed_ms=%.1f",
                request_id,
                request.method,
                request.url.path,
                response.status_code,
                elapsed_ms,
            )
        return response
