"""Constants and helpers shared by the ShieldPulse tests (importable via pytest pythonpath)."""

from __future__ import annotations

import hmac
import uuid
from hashlib import sha256

TENANT_A = uuid.UUID("aaaaaaaa-0000-0000-0000-000000000001")  # enterprise_plus
TENANT_B = uuid.UUID("bbbbbbbb-0000-0000-0000-000000000002")  # growth
SECRETS = {"arn:test:a": "secret-a", "arn:test:b": "secret-b"}
TENANT_SECRET = {TENANT_A: "secret-a", TENANT_B: "secret-b"}
APPROVAL_KEY = b"test-approval-key"
DISPATCH_KEY = b"test-dispatch-key"


def signed_headers(tenant_id: uuid.UUID, body: bytes, secret: str | None = None) -> dict[str, str]:
    secret = secret or TENANT_SECRET[tenant_id]
    return {
        "X-Tenant-ID": str(tenant_id),
        "X-ShieldPulse-Signature": hmac.new(secret.encode(), body, sha256).hexdigest(),
        "Content-Type": "application/json",
    }


# Dashboard users (one per test tenant). Hashed once per test run; scrypt is deliberately slow.
SESSION_KEY = b"test-session-key"
USER_A = {"email": "ops@a.example", "password": "pass-a", "name": "Ada Ops"}
USER_B = {"email": "soc@b.example", "password": "pass-b", "name": "Bo Soc"}
_HASHES: dict[str, str] = {}


def password_hash(user: dict) -> str:
    from shieldpulse.auth import hash_password

    if user["email"] not in _HASHES:
        _HASHES[user["email"]] = hash_password(user["password"])
    return _HASHES[user["email"]]

