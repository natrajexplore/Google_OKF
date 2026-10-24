import json
import uuid

from support import TENANT_A, TENANT_B, signed_headers

from shieldpulse.ratelimit import RateLimiter

PATH = "/v1/telemetry/drift-snapshot"


def payload(**diff) -> bytes:
    body = {
        "device_hostname": "chennai-dc-fw01.corp.internal",
        "vendor_type": "palo_alto_panos",
        "snapshot_timestamp": "2026-10-17T08:15:00Z",
        "diff_summary": {"rule_name": "ALLOW-WAN-SSH-TEMP", "source_zone": "UNTRUST-ISP1",
                         "destination_port": "22/tcp", "action": "ALLOW", **diff},
    }
    return json.dumps(body).encode()


def test_p1_drift_is_recorded(make_client, admin_conn):
    body = payload()
    resp = make_client().post(PATH, content=body, headers=signed_headers(TENANT_A, body))
    assert resp.status_code == 202, resp.text
    [event] = resp.json()["drift_events"]
    assert (event["severity"], event["blast_radius_score"], event["triggers_runbook"]) == ("P1", 95, True)
    row = admin_conn.execute(
        "SELECT tenant_id, device_hostname, severity, remediation_mode, remediated_at"
        " FROM public.policy_drift_events WHERE drift_id = %s", [event["drift_id"]]
    ).fetchone()
    assert row == (TENANT_A, "chennai-dc-fw01.corp.internal", "P1", "MANUAL_APPROVAL", None)


def test_snapshot_without_diff_records_nothing(make_client, admin_conn):
    body = json.dumps({"device_hostname": "fw01", "vendor_type": "fortigate",
                       "snapshot_timestamp": "2026-10-17T08:15:00Z"}).encode()
    resp = make_client().post(PATH, content=body, headers=signed_headers(TENANT_A, body))
    assert resp.status_code == 202
    assert resp.json() == {"accepted": True, "drift_events": []}
    assert admin_conn.execute("SELECT count(*) FROM public.policy_drift_events").fetchone()[0] == 0


def test_auth_failures_are_indistinguishable(make_client):
    client = make_client()
    body = payload()
    good = signed_headers(TENANT_A, body)
    cases = {
        "missing headers": {"Content-Type": "application/json"},
        "malformed tenant id": {**good, "X-Tenant-ID": "not-a-uuid"},
        "unknown tenant": signed_headers(uuid.uuid4(), body, secret="secret-a"),
        "wrong secret": signed_headers(TENANT_A, body, secret="secret-b"),
        "another tenant's id": {**good, "X-Tenant-ID": str(TENANT_B)},
    }
    for name, headers in cases.items():
        resp = client.post(PATH, content=body, headers=headers)
        assert (resp.status_code, resp.json()) == (401, {"detail": "Invalid tenant or signature"}), name


def test_signature_covers_raw_bytes(make_client):
    body = payload()
    reserialized = json.dumps(json.loads(body), indent=2).encode()  # same JSON, different bytes
    resp = make_client().post(PATH, content=reserialized, headers=signed_headers(TENANT_A, body))
    assert resp.status_code == 401


def test_invalid_payload_is_400_only_after_auth(make_client):
    client = make_client()
    for body in (b"{not json", payload().replace(b"palo_alto_panos", b"juniper")):
        assert client.post(PATH, content=body, headers=signed_headers(TENANT_A, body)).status_code == 400
        assert client.post(PATH, content=body, headers={"X-Tenant-ID": str(TENANT_A),
                                                         "X-ShieldPulse-Signature": "00"}).status_code == 401


def test_rate_limit_returns_429_with_retry_after(make_client):
    client = make_client(RateLimiter({"growth": 2, "business": 2, "enterprise_plus": 2}))
    body = payload(action="DENY")
    statuses = [client.post(PATH, content=body, headers=signed_headers(TENANT_A, body)).status_code
                for _ in range(3)]
    assert statuses == [202, 202, 429]
    blocked = client.post(PATH, content=body, headers=signed_headers(TENANT_A, body))
    assert 1 <= int(blocked.headers["Retry-After"]) <= 60
    # Tenant B has its own budget.
    assert client.post(PATH, content=body, headers=signed_headers(TENANT_B, body)).status_code == 202


def test_mttr_and_sla_breach(make_client, admin_conn):
    # Tenant A (target 900s): P1 fixed in 600s, P2 in 1800s -> mean 1200s, breached.
    # Excluded: a P3, an unresolved P1, and Tenant B's incident.
    admin_conn.execute(
        "INSERT INTO public.policy_drift_events"
        " (tenant_id, device_hostname, vendor_type, severity, blast_radius_score, remediation_mode,"
        "  detected_at, remediated_at) VALUES"
        " (%(a)s, 'fw1', 'fortigate', 'P1', 95, 'AUTO', now() - interval '2 hours', now() - interval '2 hours' + interval '600 seconds'),"
        " (%(a)s, 'fw1', 'fortigate', 'P2', 60, 'AUTO', now() - interval '1 hour', now() - interval '1 hour' + interval '1800 seconds'),"
        " (%(a)s, 'fw1', 'fortigate', 'P3', 25, 'AUTO', now() - interval '1 hour', now()),"
        " (%(a)s, 'fw1', 'fortigate', 'P1', 95, 'AUTO', now(), NULL),"
        " (%(b)s, 'fw2', 'aws_sg', 'P1', 95, 'AUTO', now() - interval '1 hour', now())",
        {"a": TENANT_A, "b": TENANT_B},
    )
    client = make_client()
    resp = client.get("/v1/metrics/mttr", headers=signed_headers(TENANT_A, b""))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["resolved_p1_p2_incidents"] == 2
    assert round(data["mttr_seconds"]) == 1200
    assert (data["sla_breached"], data["sla_credit_eligible"]) == (True, True)

    # Tenant B (growth, target 3600s): one 3600s incident -> not breached, never credit-eligible.
    data_b = client.get("/v1/metrics/mttr", headers=signed_headers(TENANT_B, b"")).json()
    assert data_b["resolved_p1_p2_incidents"] == 1
    assert (data_b["sla_breached"], data_b["sla_credit_eligible"]) == (False, False)
