"""Fixtures: a throwaway PostgreSQL database per test session, accessed as the app role.

Needs the dev Postgres (`docker compose up -d` in services/shieldpulse) or any server at
$SHIELDPULSE_TEST_ADMIN_URL. DB tests skip if it is unreachable, unless
SHIELDPULSE_REQUIRE_DB=1 (set in CI), which turns that into a failure.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.conninfo import make_conninfo
from support import SECRETS, TENANT_A, TENANT_B

from shieldpulse.app import create_app
from shieldpulse.db import Database
from shieldpulse.ratelimit import RateLimiter
from shieldpulse.secret_store import LocalSecretStore

DB_DIR = Path(__file__).resolve().parents[1] / "db"
ADMIN_URL = os.environ.get("SHIELDPULSE_TEST_ADMIN_URL", "postgresql://postgres:postgres@localhost:55432/postgres")


@pytest.fixture(scope="session")
def pg():
    """Yield (admin_url, app_url) for a fresh database with schema and app role."""
    try:
        admin = psycopg.connect(ADMIN_URL, autocommit=True, connect_timeout=3)
    except psycopg.OperationalError as exc:
        if os.environ.get("SHIELDPULSE_REQUIRE_DB") == "1":
            raise
        pytest.skip(f"PostgreSQL not reachable at {ADMIN_URL}: {exc}")

    name = f"shieldpulse_test_{uuid.uuid4().hex[:8]}"
    admin.execute(f'CREATE DATABASE "{name}"')
    admin_url = make_conninfo(ADMIN_URL, dbname=name)
    with psycopg.connect(admin_url, autocommit=True) as conn:
        conn.execute((DB_DIR / "schema.sql").read_text(encoding="utf-8"))
        conn.execute((DB_DIR / "dev_roles.sql").read_text(encoding="utf-8"))
    app_url = make_conninfo(admin_url, user="shieldpulse_app", password="shieldpulse_app_dev")
    try:
        yield admin_url, app_url
    finally:
        admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        admin.close()


@pytest.fixture
def admin_conn(pg):
    """Superuser connection (bypasses RLS) for arranging and inspecting data. Resets tables."""
    with psycopg.connect(pg[0], autocommit=True) as conn:
        conn.execute("TRUNCATE public.policy_drift_events, public.tenants")
        conn.execute(
            "INSERT INTO public.tenants (tenant_id, org_name, plan_tier, mrr_inr, sla_mttr_target_sec,"
            " webhook_secret_arn, status) VALUES"
            " (%s, 'Tenant A', 'enterprise_plus', 450000, 900, 'arn:test:a', 'ACTIVE'),"
            " (%s, 'Tenant B', 'growth', 60000, 3600, 'arn:test:b', 'ACTIVE')",
            [TENANT_A, TENANT_B],
        )
        yield conn


@pytest.fixture
def db(pg):
    database = Database(pg[1], max_size=2)
    yield database
    database.close()


@pytest.fixture
def make_client(pg, admin_conn):
    """Build a TestClient; pass a RateLimiter to override the default limits."""
    clients = []

    def _make(limiter: RateLimiter | None = None) -> TestClient:
        client = TestClient(create_app(Database(pg[1], max_size=2), LocalSecretStore(SECRETS), limiter))
        client.__enter__()
        clients.append(client)
        return client

    yield _make
    for client in clients:
        client.__exit__(None, None, None)

