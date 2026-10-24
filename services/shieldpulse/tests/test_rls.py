"""Tenant isolation (policies/tenant_isolation_soc2.md), tested as the real app role."""

import psycopg
import pytest
from support import TENANT_A, TENANT_B


def seed_event(admin_conn, tenant_id):
    admin_conn.execute(
        "INSERT INTO public.policy_drift_events (tenant_id, device_hostname, vendor_type, severity,"
        " blast_radius_score, remediation_mode) VALUES (%s, 'fw', 'fortigate', 'P2', 60, 'AUTO')",
        [tenant_id],
    )


def test_app_role_cannot_bypass_rls(pg):
    with psycopg.connect(pg[1]) as conn:
        row = conn.execute(
            "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
        ).fetchone()
    assert row == (False, False), "isolation tests are meaningless if the app role bypasses RLS"


def test_tenant_sees_only_its_own_rows(db, admin_conn):
    seed_event(admin_conn, TENANT_A)
    seed_event(admin_conn, TENANT_B)
    with db.tenant_tx(TENANT_A) as conn:
        assert conn.execute("SELECT tenant_id FROM public.tenants").fetchall() == [{"tenant_id": TENANT_A}]
        events = conn.execute("SELECT tenant_id FROM public.policy_drift_events").fetchall()
        assert events == [{"tenant_id": TENANT_A}]
        # Even an explicit filter for the other tenant returns nothing.
        other = conn.execute("SELECT count(*) AS n FROM public.policy_drift_events WHERE tenant_id = %s",
                             [TENANT_B]).fetchone()
        assert other["n"] == 0


def test_no_tenant_context_sees_nothing(pg, admin_conn):
    seed_event(admin_conn, TENANT_A)
    with psycopg.connect(pg[1]) as conn:
        assert conn.execute("SELECT count(*) FROM public.tenants").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM public.policy_drift_events").fetchone()[0] == 0


def test_cannot_write_or_move_rows_into_another_tenant(db, admin_conn):
    with pytest.raises(psycopg.errors.InsufficientPrivilege, match="row-level security"):
        with db.tenant_tx(TENANT_A) as conn:
            conn.execute(
                "INSERT INTO public.policy_drift_events (tenant_id, device_hostname, vendor_type, severity,"
                " blast_radius_score, remediation_mode) VALUES (%s, 'fw', 'fortigate', 'P1', 95, 'AUTO')",
                [TENANT_B],
            )
    seed_event(admin_conn, TENANT_A)
    with pytest.raises(psycopg.errors.InsufficientPrivilege, match="row-level security"):
        with db.tenant_tx(TENANT_A) as conn:
            conn.execute("UPDATE public.policy_drift_events SET tenant_id = %s", [TENANT_B])


def test_tenant_context_does_not_leak_across_pooled_checkouts(db, admin_conn):
    with db.tenant_tx(TENANT_A) as conn:
        assert conn.execute("SELECT count(*) AS n FROM public.tenants").fetchone()["n"] == 1
    # max_size=2 pool: check out every connection to be sure the used one is among them.
    with db.pool.connection() as c1, db.pool.connection() as c2:
        for conn in (c1, c2):
            setting = conn.execute("SELECT current_setting('app.current_tenant_id', true) AS s").fetchone()["s"]
            assert setting in (None, "")
            assert conn.execute("SELECT count(*) AS n FROM public.tenants").fetchone()["n"] == 0
