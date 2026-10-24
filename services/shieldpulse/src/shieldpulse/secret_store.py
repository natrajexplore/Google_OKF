"""Webhook secret resolution by `tenants.webhook_secret_arn`.

Production resolves ARNs through KMS with per-tenant data keys
(policies/tenant_isolation_soc2.md, control 2). That integration is not built yet;
LocalSecretStore serves development and tests from a JSON file or dict.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol


class SecretStore(Protocol):
    def get(self, arn: str) -> bytes | None: ...


class LocalSecretStore:
    """DEV/TEST ONLY: ARN -> secret mapping held in memory."""

    def __init__(self, secrets: dict[str, str]):
        self._secrets = {arn: value.encode() for arn, value in secrets.items()}

    @classmethod
    def from_file(cls, path: str | Path) -> LocalSecretStore:
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def get(self, arn: str) -> bytes | None:
        return self._secrets.get(arn)
