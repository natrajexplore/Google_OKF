"""Dashboard authentication: scrypt password hashes, signed session cookies, CSRF tokens.

Standard library only. SSO can replace password login later; sessions and CSRF stay the same.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from uuid import UUID

SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_LEN = 2**14, 8, 1, 32
SESSION_TTL_SEC = 8 * 3600


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_LEN)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = _unb64(digest)
        actual = hashlib.scrypt(password.encode(), salt=_unb64(salt), n=int(n), r=int(r), p=int(p),
                                dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


# Verified against when the email is unknown, so both failure paths cost one scrypt.
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


@dataclass(frozen=True)
class Session:
    user_id: UUID
    tenant_id: UUID
    expires: int

    def csrf_token(self, key: bytes) -> str:
        """Bound to this session, so a token from one login is useless in another."""
        return hmac.new(key, f"csrf.{self.user_id}.{self.expires}".encode(), hashlib.sha256).hexdigest()


def make_session_cookie(key: bytes, user_id: UUID, tenant_id: UUID, now: float | None = None) -> str:
    expires = int((now if now is not None else time.time()) + SESSION_TTL_SEC)
    body = f"{user_id}.{tenant_id}.{expires}".encode()
    return f"{_b64(body)}.{hmac.new(key, body, hashlib.sha256).hexdigest()}"


def read_session_cookie(key: bytes, cookie: str | None, now: float | None = None) -> Session | None:
    if not cookie:
        return None
    try:
        encoded, signature = cookie.rsplit(".", 1)
        body = _unb64(encoded)
        if not hmac.compare_digest(hmac.new(key, body, hashlib.sha256).hexdigest(), signature):
            return None
        user_id, tenant_id, expires = body.decode().split(".")
        session = Session(UUID(user_id), UUID(tenant_id), int(expires))
    except ValueError:
        return None
    if (now if now is not None else time.time()) > session.expires:
        return None
    return session


def check_csrf(key: bytes, session: Session, token: str | None) -> bool:
    return bool(token) and hmac.compare_digest(session.csrf_token(key), token)
