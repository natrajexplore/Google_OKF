"""Per-tenant request limits (apis/ingest_telemetry.md).

Fixed one-minute windows held in process memory, so limits apply per server instance.
Running several replicas needs a shared store such as Redis.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from uuid import UUID

# apis/ingest_telemetry.md. The business limit was confirmed on 2026-10-24.
DEFAULT_LIMITS = {"growth": 500, "business": 2000, "enterprise_plus": 5000}
WINDOW_SEC = 60


class RateLimiter:
    def __init__(self, limits: dict[str, int] | None = None, clock: Callable[[], float] = time.monotonic):
        self.limits = limits or DEFAULT_LIMITS
        self._clock = clock
        self._windows: dict[UUID, tuple[int, int]] = {}
        self._lock = threading.Lock()

    def check(self, tenant_id: UUID, plan_tier: str) -> int | None:
        """Count one request. Returns None if allowed, else seconds until the window resets."""
        now = self._clock()
        window = int(now // WINDOW_SEC)
        with self._lock:
            current, count = self._windows.get(tenant_id, (window, 0))
            if current != window:
                count = 0
            if count >= self.limits.get(plan_tier, min(self.limits.values())):
                return max(1, math.ceil((window + 1) * WINDOW_SEC - now))
            self._windows[tenant_id] = (window, count + 1)
            return None
