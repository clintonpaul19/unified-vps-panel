from __future__ import annotations

import logging
import time
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("uvps.api")


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach a correlation id and emit safe request timing logs."""

    async def dispatch(self, request: Request, call_next) -> Response:
        incoming = request.headers.get("X-Request-ID", "")
        request_id = incoming.strip()[:128] if incoming else ""
        if not request_id or any(ord(ch) < 32 for ch in request_id):
            request_id = str(uuid4())
        request.state.request_id = request_id
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            elapsed_ms = (time.perf_counter() - started) * 1000
            logger.exception("request failed request_id=%s method=%s path=%s elapsed_ms=%.1f", request_id, request.method, request.url.path, elapsed_ms)
            raise
        elapsed_ms = (time.perf_counter() - started) * 1000
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        logger.info("request request_id=%s method=%s path=%s status=%s elapsed_ms=%.1f", request_id, request.method, request.url.path, response.status_code, elapsed_ms)
        return response
