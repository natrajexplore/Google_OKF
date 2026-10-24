"""Runbook building blocks (runbooks/critical_drift_remediation.md, Step 2).

Signed rollback payloads, signed approval tokens, and the device and notifier interfaces.
Real NETCONF/REST device clients, the last-known-good Git store, and Slack/PagerDuty
notifiers are not built yet. SimulatedDevice and RecordingNotifier stand in for them.
"""

from __future__ import annotations

import base64
import hmac
import json
import logging
import time
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Any, Protocol
from uuid import UUID

log = logging.getLogger(__name__)


def sign(key: bytes, payload: bytes) -> str:
    return hmac.new(key, payload, sha256).hexdigest()


@dataclass(frozen=True)
class RollbackRequest:
    tenant_id: str
    drift_id: str
    device_hostname: str
    vendor_type: str
    rule_name: str
    # DRAFT: no golden-state store exists yet; devices restore their last-known-good commit.
    target: str = "last_known_good"

    def payload(self) -> bytes:
        """Canonical JSON, so the signature is stable across processes."""
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()


class DeviceClient(Protocol):
    def dispatch_rollback(self, payload: bytes, signature: str) -> None: ...

    def rule_present(self, device_hostname: str, rule_name: str) -> bool: ...


class Notifier(Protocol):
    def request_approval(self, tenant_id: UUID, event: dict[str, Any], approval_url: str) -> None: ...


class SimulatedDevice:
    """DEV/TEST ONLY. Verifies rollback signatures and 'removes' the rule when one arrives.

    converges=False simulates a rollback that never takes effect; fail_dispatch=True
    simulates an unreachable device.
    """

    def __init__(self, dispatch_key: bytes, converges: bool = True, fail_dispatch: bool = False):
        self._key = dispatch_key
        self.converges = converges
        self.fail_dispatch = fail_dispatch
        self.dispatched: list[dict[str, Any]] = []
        self._removed: set[tuple[str, str]] = set()

    def dispatch_rollback(self, payload: bytes, signature: str) -> None:
        if self.fail_dispatch:
            raise ConnectionError("device unreachable")
        if not hmac.compare_digest(sign(self._key, payload), signature):
            raise PermissionError("rollback signature rejected")
        request = json.loads(payload)
        self.dispatched.append(request)
        if self.converges:
            self._removed.add((request["device_hostname"], request["rule_name"]))
        log.info("simulated rollback on %s: %s", request["device_hostname"], request["rule_name"])

    def rule_present(self, device_hostname: str, rule_name: str) -> bool:
        return (device_hostname, rule_name) not in self._removed


class RecordingNotifier:
    """DEV/TEST ONLY. Logs approval requests and keeps them for inspection."""

    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    def request_approval(self, tenant_id: UUID, event: dict[str, Any], approval_url: str) -> None:
        self.sent.append({"tenant_id": tenant_id, "event": event, "approval_url": approval_url})
        log.warning("approval needed for tenant %s, drift %s: %s", tenant_id, event["drift_id"], approval_url)


class InvalidToken(Exception):
    pass


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def make_approval_token(key: bytes, job_id: UUID, tenant_id: UUID, ttl_sec: int, now: float | None = None) -> str:
    """Signed, expiring token for the one-click approval link."""
    expires = int((now if now is not None else time.time()) + ttl_sec)
    body = f"{job_id}.{tenant_id}.{expires}".encode()
    return f"{_b64(body)}.{sign(key, body)}"


def verify_approval_token(key: bytes, token: str, now: float | None = None) -> tuple[UUID, UUID]:
    """Return (job_id, tenant_id), or raise InvalidToken if the token is tampered with or expired."""
    try:
        encoded, signature = token.rsplit(".", 1)
        body = _unb64(encoded)
    except ValueError:
        raise InvalidToken("malformed token") from None
    if not hmac.compare_digest(sign(key, body), signature):
        raise InvalidToken("bad signature")
    try:
        job_id, tenant_id, expires = body.decode().split(".")
        job, tenant, expiry = UUID(job_id), UUID(tenant_id), int(expires)
    except ValueError:
        raise InvalidToken("malformed token") from None
    if (now if now is not None else time.time()) > expiry:
        raise InvalidToken("expired")
    return job, tenant
