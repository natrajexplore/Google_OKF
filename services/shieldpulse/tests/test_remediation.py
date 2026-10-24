"""Runbook execution: queueing, AUTO and MANUAL_APPROVAL paths, convergence, isolation."""

import json
import time
import uuid

import psycopg
import pytest
from support import APPROVAL_KEY, DISPATCH_KEY, TENANT_A, TENANT_B, signed_headers

from shieldpulse.remediation import (
    InvalidToken,
    RollbackRequest,
    SimulatedDevice,
    make_approval_token,
    sign,
    verify_approval_token,
)

PATH = "/v1/telemetry/drift-snapshot"
APPROVE = "/v1/remediation/approve"


def ingest(client, tenant_id, port="22/tcp", rule="ALLOW-WAN-SSH-TEMP"):
    body = json.dumps({
        "device_hostname": "chennai-dc-fw01.corp.internal", "vendor_type": "palo_alto_panos",
        "snapshot_timestamp": "2026-10-17T08:15:00Z",
        "diff_summary": {"rule_name": rule, "source_zone": "UNTRUST-ISP1", "destination_port": port, "action": "ALLOW"},
    }).encode()
    resp = client.post(PATH, content=body, headers=signed_headers(tenant_id, body))
    assert resp.status_code == 202, resp.text
    return resp.json()["drift_events"][0]


def set_mode(admin_conn, tenant_id, mode):
    admin_conn.execute("UPDATE public.tenants SET remediation_mode = %s WHERE tenant_id = %s", [mode, tenant_id])


def job_row(admin_conn, job_id):
    return admin_conn.execute(
        "SELECT state, attempts, sla_met, last_error FROM public.remediation_jobs WHERE job_id = %s", [job_id]
    ).fetchone()


def remediated_at(admin_conn, drift_id):
    return admin_conn.execute(
        "SELECT remediated_at FROM public.policy_drift_events WHERE drift_id = %s", [drift_id]
    ).fetchone()[0]


# --- queueing ---------------------------------------------------------------------------

def test_only_runbook_events_are_queued_with_rule_details(make_client, admin_conn):
    client = make_client()
    p1 = ingest(client, TENANT_A)
    p2 = ingest(client, TENANT_A, port="443/tcp")
    assert p1["triggers_runbook"] and p1["remediation_job_id"]
    assert not p2["triggers_runbook"] and p2["remediation_job_id"] is None
    assert job_row(admin_conn, p1["remediation_job_id"])[0] == "PENDING"
    rule, diff = admin_conn.execute(
        "SELECT rule_name, diff_summary FROM public.policy_drift_events WHERE drift_id = %s", [p1["drift_id"]]
    ).fetchone()
    assert rule == "ALLOW-WAN-SSH-TEMP" and diff["destination_port"] == "22/tcp"


def test_event_takes_tenant_remediation_mode(make_client, admin_conn):
    set_mode(admin_conn, TENANT_A, "AUTO")
    client = make_client()
    assert ingest(client, TENANT_A)["remediation_mode"] == "AUTO"
    assert ingest(client, TENANT_B)["remediation_mode"] == "MANUAL_APPROVAL"


# --- AUTO path ----------------------------------------------------------------------------

def test_auto_rollback_converges_and_closes_sla(make_client, make_worker, admin_conn):
    set_mode(admin_conn, TENANT_A, "AUTO")
    event = ingest(make_client(), TENANT_A)
    device = SimulatedDevice(DISPATCH_KEY)
    worker = make_worker(device)

    assert worker.run_once() == "DISPATCHED"
    [sent] = device.dispatched
    assert (sent["rule_name"], sent["device_hostname"], sent["target"]) == (
        "ALLOW-WAN-SSH-TEMP", "chennai-dc-fw01.corp.internal", "last_known_good")
    assert remediated_at(admin_conn, event["drift_id"]) is None

    assert worker.run_once() == "REMEDIATED"
    assert remediated_at(admin_conn, event["drift_id"]) is not None
    state, _, sla_met, last_error = job_row(admin_conn, event["remediation_job_id"])
    assert (state, sla_met, last_error) == ("REMEDIATED", True, None)
    assert worker.run_once() is None  # nothing left to do


def test_sla_miss_is_recorded(make_client, make_worker, admin_conn):
    set_mode(admin_conn, TENANT_A, "AUTO")
    event = ingest(make_client(), TENANT_A)
    admin_conn.execute("UPDATE public.tenants SET sla_mttr_target_sec = 0 WHERE tenant_id = %s", [TENANT_A])
    worker = make_worker()
    worker.run_once(), worker.run_once()
    assert job_row(admin_conn, event["remediation_job_id"])[:3] == ("REMEDIATED", 0, False)


def test_rollback_that_never_converges_fails_after_retries(make_client, make_worker, admin_conn):
    set_mode(admin_conn, TENANT_A, "AUTO")
    event = ingest(make_client(), TENANT_A)
    worker = make_worker(SimulatedDevice(DISPATCH_KEY, converges=False), max_attempts=3)
    states = [worker.run_once() for _ in range(4)]
    assert states == ["DISPATCHED", "DISPATCHED", "DISPATCHED", "FAILED"]
    state, attempts, _, last_error = job_row(admin_conn, event["remediation_job_id"])
    assert (state, attempts) == ("FAILED", 3) and "still present" in last_error
    assert remediated_at(admin_conn, event["drift_id"]) is None


def test_unreachable_device_retries_then_fails(make_client, make_worker, admin_conn):
    set_mode(admin_conn, TENANT_A, "AUTO")
    event = ingest(make_client(), TENANT_A)
    worker = make_worker(SimulatedDevice(DISPATCH_KEY, fail_dispatch=True), max_attempts=2)
    assert [worker.run_once(), worker.run_once()] == ["PENDING", "FAILED"]
    assert "ConnectionError" in job_row(admin_conn, event["remediation_job_id"])[3]


def test_device_rejects_wrongly_signed_rollback():
    device = SimulatedDevice(DISPATCH_KEY)
    payload = RollbackRequest("t", "d", "fw", "fortigate", "R1").payload()
    with pytest.raises(PermissionError):
        device.dispatch_rollback(payload, sign(b"wrong-key", payload))
    assert device.dispatched == []


def test_inactive_tenant_is_skipped_without_dispatch(make_client, make_worker, admin_conn):
    set_mode(admin_conn, TENANT_A, "AUTO")
    event = ingest(make_client(), TENANT_A)
    admin_conn.execute("UPDATE public.tenants SET status = 'PAST_DUE' WHERE tenant_id = %s", [TENANT_A])
    device = SimulatedDevice(DISPATCH_KEY)
    assert make_worker(device).run_once() == "SKIPPED"
    assert device.dispatched == []
    assert "PAST_DUE" in job_row(admin_conn, event["remediation_job_id"])[3]


# --- MANUAL_APPROVAL path -----------------------------------------------------------------

def approval_token(worker):
    [message] = worker.notifier.sent
    return message["approval_url"].split("token=", 1)[1]


def test_manual_approval_flow(make_client, make_worker, admin_conn):
    client = make_client()
    event = ingest(client, TENANT_A)  # Tenant A defaults to MANUAL_APPROVAL
    device = SimulatedDevice(DISPATCH_KEY)
    worker = make_worker(device)

    assert worker.run_once() == "AWAITING_APPROVAL"
    assert worker.run_once() is None and device.dispatched == []  # nothing happens without approval
    token = approval_token(worker)

    page = client.get(APPROVE, params={"token": token})
    assert page.status_code == 200 and "ALLOW-WAN-SSH-TEMP" in page.text and "UNTRUST-ISP1" in page.text
    assert job_row(admin_conn, event["remediation_job_id"])[0] == "AWAITING_APPROVAL"  # GET changes nothing

    resp = client.post(APPROVE, data={"token": token, "decision": "approve"})
    assert resp.status_code == 200 and "APPROVED" in resp.text
    assert client.post(APPROVE, data={"token": token, "decision": "approve"}).status_code == 409  # one decision only

    assert [worker.run_once(), worker.run_once()] == ["DISPATCHED", "REMEDIATED"]
    assert remediated_at(admin_conn, event["drift_id"]) is not None


def test_rejected_rollback_is_never_dispatched(make_client, make_worker, admin_conn):
    client = make_client()
    event = ingest(client, TENANT_A)
    device = SimulatedDevice(DISPATCH_KEY)
    worker = make_worker(device)
    worker.run_once()
    assert client.post(APPROVE, data={"token": approval_token(worker), "decision": "reject"}).status_code == 200
    assert worker.run_once() is None and device.dispatched == []
    assert job_row(admin_conn, event["remediation_job_id"])[0] == "REJECTED"
    assert client.get(APPROVE, params={"token": approval_token(worker)}).status_code == 409


def test_tenant_going_inactive_while_awaiting_approval_is_skipped(make_client, make_worker, admin_conn):
    client = make_client()
    ingest(client, TENANT_A)
    device = SimulatedDevice(DISPATCH_KEY)
    worker = make_worker(device)
    worker.run_once()
    client.post(APPROVE, data={"token": approval_token(worker), "decision": "approve"})
    admin_conn.execute("UPDATE public.tenants SET status = 'CHURNED' WHERE tenant_id = %s", [TENANT_A])
    assert worker.run_once() == "SKIPPED" and device.dispatched == []


def test_bad_tokens_are_rejected(make_client, make_worker):
    client = make_client()
    ingest(client, TENANT_A)
    worker = make_worker()
    worker.run_once()
    token = approval_token(worker)
    tampered = token[:-1] + ("0" if token[-1] != "0" else "1")
    expired = make_approval_token(APPROVAL_KEY, uuid.uuid4(), TENANT_A, ttl_sec=-1)
    forged = make_approval_token(b"attacker-key", uuid.uuid4(), TENANT_A, ttl_sec=3600)
    for bad in (tampered, expired, forged, "garbage"):
        assert client.get(APPROVE, params={"token": bad}).status_code == 403, bad
        assert client.post(APPROVE, data={"token": bad, "decision": "approve"}).status_code == 403, bad
    assert client.post(APPROVE, data={"token": token, "decision": "maybe"}).status_code == 400


def test_token_round_trip_and_expiry():
    job, tenant = uuid.uuid4(), uuid.uuid4()
    token = make_approval_token(APPROVAL_KEY, job, tenant, ttl_sec=60, now=1000)
    assert verify_approval_token(APPROVAL_KEY, token, now=1059) == (job, tenant)
    with pytest.raises(InvalidToken, match="expired"):
        verify_approval_token(APPROVAL_KEY, token, now=1061)


def test_token_for_one_tenant_cannot_reach_another_tenants_job(make_client, make_worker, admin_conn):
    """A validly signed token naming the wrong tenant finds nothing, because RLS scopes the lookup."""
    client = make_client()
    event = ingest(client, TENANT_B)
    job_id = uuid.UUID(event["remediation_job_id"])
    mismatched = make_approval_token(APPROVAL_KEY, job_id, TENANT_A, ttl_sec=3600)
    assert client.get(APPROVE, params={"token": mismatched}).status_code == 404


# --- worker isolation and concurrency ----------------------------------------------------

def test_worker_role_cannot_bypass_rls_on_tenant_data(pg, make_client, admin_conn):
    ingest(make_client(), TENANT_A)
    with psycopg.connect(pg[2]) as conn:
        assert conn.execute(
            "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user").fetchone() == (False, False)
        # Queue-wide visibility is deliberate...
        assert conn.execute("SELECT count(*) FROM public.remediation_jobs").fetchone()[0] == 1
        # ...but tenant data still requires a tenant context.
        assert conn.execute("SELECT count(*) FROM public.policy_drift_events").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM public.tenants").fetchone()[0] == 0


def test_api_role_sees_only_its_tenants_jobs(pg, make_client, admin_conn):
    client = make_client()
    ingest(client, TENANT_A)
    ingest(client, TENANT_B)
    with psycopg.connect(pg[1]) as conn, conn.transaction():
        assert conn.execute("SELECT count(*) FROM public.remediation_jobs").fetchone()[0] == 0
        conn.execute("SELECT set_config('app.current_tenant_id', %s, true)", [str(TENANT_A)])
        assert conn.execute("SELECT tenant_id FROM public.remediation_jobs").fetchall() == [(TENANT_A,)]


def test_concurrent_workers_never_claim_the_same_job(pg, make_client, admin_conn):
    ingest(make_client(), TENANT_A)
    with psycopg.connect(pg[2]) as first, psycopg.connect(pg[2]) as second:
        claim = ("SELECT job_id FROM public.remediation_jobs WHERE state = 'PENDING'"
                 " FOR UPDATE SKIP LOCKED LIMIT 1")
        assert first.execute(claim).fetchone() is not None   # holds the row lock (open transaction)
        start = time.monotonic()
        assert second.execute(claim).fetchone() is None      # skips it instead of waiting
        assert time.monotonic() - start < 2
