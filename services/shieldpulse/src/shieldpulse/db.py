"""Tenant-scoped PostgreSQL access (policies/tenant_isolation_soc2.md, control 1)."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from uuid import UUID

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool


class Database:
    def __init__(self, url: str, min_size: int = 1, max_size: int = 10):
        self.pool = ConnectionPool(url, min_size=min_size, max_size=max_size, open=True,
                                   kwargs={"row_factory": dict_row})

    def close(self) -> None:
        self.pool.close()

    @contextmanager
    def tenant_tx(self, tenant_id: UUID) -> Iterator[psycopg.Connection]:
        """Check out a connection and open a transaction bound to one tenant.

        set_config(..., is_local => true) is the parameterized form of
        `SET LOCAL app.current_tenant_id = '<uuid>'`. It expires with the transaction,
        so a pooled connection never carries one tenant's context into the next checkout.
        """
        with self.pool.connection() as conn, conn.transaction():
            conn.execute("SELECT set_config('app.current_tenant_id', %s, true)", [str(tenant_id)])
            yield conn
