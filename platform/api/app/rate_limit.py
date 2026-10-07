from __future__ import annotations

import threading
import time


class SlidingWindowLimiter:
    """Small bounded fixed-window limiter for single-process protection.

    Distributed deployments should still enforce limits at the WAF/Redis layer.
    """

    def __init__(self, max_attempts: int, window_seconds: int, max_keys: int = 10000) -> None:
        self.max_attempts = max(1, max_attempts)
        self.window_seconds = max(1, window_seconds)
        self.max_keys = max(100, max_keys)
        self._lock = threading.Lock()
        self._state: dict[str, tuple[int, float]] = {}

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            count, started = self._state.get(key, (0, now))
            if now - started >= self.window_seconds:
                count, started = 0, now
            if count >= self.max_attempts:
                return False
            self._state[key] = (count + 1, started)
            self._prune(now)
            return True

    def reset(self, key: str) -> None:
        with self._lock:
            self._state.pop(key, None)

    def _prune(self, now: float) -> None:
        if len(self._state) <= self.max_keys:
            return
        stale = [
            key for key, (_count, started) in self._state.items()
            if now - started >= self.window_seconds
        ]
        for key in stale:
            self._state.pop(key, None)
        if len(self._state) <= self.max_keys:
            return
        oldest = sorted(self._state.items(), key=lambda item: item[1][1])[: max(1, len(self._state) - self.max_keys)]
        for key, _value in oldest:
            self._state.pop(key, None)


from .config import settings\n\nlogin_limiter = SlidingWindowLimiter(\n    max_attempts=settings.login_rate_limit_attempts,\n    window_seconds=settings.login_rate_limit_window_seconds,\n    max_keys=10000,\n)
