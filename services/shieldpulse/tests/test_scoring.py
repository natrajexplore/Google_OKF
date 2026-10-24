import time
import uuid

import pytest

from shieldpulse.ratelimit import RateLimiter
from shieldpulse.scoring import score_diff


@pytest.mark.parametrize(
    ("zone", "port", "action", "severity", "score", "triggers"),
    [
        ("UNTRUST-ISP1", "22/tcp", "ALLOW", "P1", 95, True),     # the runbook's P1 example
        ("untrust-isp2", "3389/TCP", "allow", "P1", 95, True),   # case-insensitive
        ("INTERNET", "443/tcp", "ALLOW", "P2", 60, False),
        ("TRUST-LAN", "22/tcp", "ALLOW", "P3", 25, False),
        ("UNTRUST-ISP1", "22/tcp", "DENY", "INFO", 5, False),
    ],
)
def test_score_diff(zone, port, action, severity, score, triggers):
    result = score_diff(zone, port, action)
    assert (result.severity, result.blast_radius_score, result.triggers_runbook) == (severity, score, triggers)


def test_rate_limiter_window_and_retry_after():
    now = [120.0]
    limiter = RateLimiter({"growth": 2}, clock=lambda: now[0])
    tenant, other = uuid.uuid4(), uuid.uuid4()
    assert limiter.check(tenant, "growth") is None
    assert limiter.check(tenant, "growth") is None
    now[0] = 150.0
    assert limiter.check(tenant, "growth") == 30          # blocked until the minute resets
    assert limiter.check(other, "growth") is None         # limits are per tenant
    now[0] = 180.0
    assert limiter.check(tenant, "growth") is None        # new window


def test_rate_limiter_unknown_tier_uses_strictest_limit():
    limiter = RateLimiter({"growth": 1, "enterprise_plus": 5}, clock=time.monotonic)
    tenant = uuid.uuid4()
    assert limiter.check(tenant, "mystery") is None
    assert limiter.check(tenant, "mystery") is not None
