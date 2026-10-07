from __future__ import annotations

import threading
import time
from collections import defaultdict


_started_at = time.monotonic()
_lock = threading.Lock()
_requests: defaultdict[tuple[str, str], int] = defaultdict(int)
_duration: defaultdict[tuple[str, str], float] = defaultdict(float)


def record_request(method: str, status: int, duration_seconds: float) -> None:
    key = (method.upper(), str(status))
    with _lock:
        _requests[key] += 1
        _duration[key] += max(duration_seconds, 0.0)


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def render() -> str:
    now = time.monotonic()
    lines = [
        "# HELP uvps_process_uptime_seconds Process uptime in seconds.",
        "# TYPE uvps_process_uptime_seconds gauge",
        f"uvps_process_uptime_seconds {now - _started_at:.3f}",
        "# HELP uvps_http_requests_total Total HTTP requests by method and status.",
        "# TYPE uvps_http_requests_total counter",
    ]
    with _lock:
        request_rows = sorted(_requests.items())
        duration_rows = sorted(_duration.items())
    for (method, status), count in request_rows:
        lines.append(
            f'uvps_http_requests_total{{method="{_escape(method)}",status="{_escape(status)}"}} {count}'
        )
    lines.extend([
        "# HELP uvps_http_request_duration_seconds_total Total request duration by method and status.",
        "# TYPE uvps_http_request_duration_seconds_total counter",
    ])
    for (method, status), seconds in duration_rows:
        lines.append(
            f'uvps_http_request_duration_seconds_total{{method="{_escape(method)}",status="{_escape(status)}"}} {seconds:.6f}'
        )
    return "\n".join(lines) + "\n"
