"""Tenant dashboard: auth, sessions, CSRF, isolation, approvals, escaping, charts."""

import json
import re
from datetime import date

import psycopg
from support import TENANT_A, TENANT_B, USER_A, USER_B, signed_headers

from shieldpulse.auth import hash_password, make_session_cookie, read_session_cookie, verify_password
from shieldpulse.charts import format_duration, mttr_line_chart

WEBHOOK = "/v1/telemetry/drift-snapshot"


def ingest(client, tenant_id, rule="ALLOW-WAN-SSH-TEMP", port="22/tcp"):
    body = json.dumps({
        "device_hostname": "edge-fw01", "vendor_type": "fortigate", "snapshot_timestamp": "2026-10-24T08:00:00Z",
        "diff_summary": {"rule_name": rule, "source_zone": "UNTRUST-ISP1", "destination_port": port, "action": "ALLOW"},
    }).encode()
    resp = client.post(WEBHOOK, content=body, headers=signed_headers(tenant_id, body))
    assert resp.status_code == 202, resp.text
    return resp.json()["drift_events"][0]


def login(client, user):
    resp = client.post("/login", data={"email": user["email"], "password": user["password"], "next": "/app"})
    assert resp.status_code == 303, resp.text
    return resp


def csrf(page_html):
    return re.search(r'name="csrf" value="([0-9a-f]+)"', page_html).group(1)


# --- auth ---------------------------------------------------------------------------------

def test_pages_require_login_and_keep_destination(make_client):
    client = make_client()
    for path in ("/app", "/app/events?severity=P1", "/app/remediation", "/app/settings"):
        resp = client.get(path)
        assert resp.status_code == 303 and resp.headers["location"].startswith("/login?next=/app"), path
    assert client.get("/").headers["location"] == "/app"


def test_bad_credentials_get_one_generic_message(make_client):
    client = make_client()
    for email, password in ((USER_A["email"], "wrong"), ("nobody@a.example", USER_A["password"])):
        resp = client.post("/login", data={"email": email, "password": password})
        assert resp.status_code == 401
        assert "That email and password don" in resp.text
        assert "sp_session" not in resp.headers.get("set-cookie", "")


def test_login_sets_hardened_cookie_and_shows_tenant(make_client):
    client = make_client(secure_cookies=True)
    resp = login(client, USER_A)
    cookie = resp.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "secure" in cookie
    assert resp.headers["location"] == "/app"


def test_login_is_case_insensitive_on_email_and_lands_on_overview(make_client):
    client = make_client()
    client.post("/login", data={"email": USER_A["email"].upper(), "password": USER_A["password"]})
    page = client.get("/app")
    assert page.status_code == 200
    assert "Tenant A" in page.text and "Good to see you, Ada" in page.text
    assert "default-src 'self'" in page.headers["content-security-policy"]
    assert page.headers["cache-control"] == "no-store"


def test_next_cannot_redirect_off_site(make_client):
    client = make_client()
    for bad in ("//evil.example/app", "https://evil.example", "/login", "javascript:alert(1)"):
        resp = client.post("/login", data={"email": USER_A["email"], "password": USER_A["password"], "next": bad})
        assert resp.headers["location"] == "/app", bad


def test_tampered_or_expired_session_is_rejected(make_client):
    client = make_client()
    login(client, USER_A)
    good = client.cookies.get("sp_session")
    client.cookies.set("sp_session", good[:-1] + ("0" if good[-1] != "0" else "1"))
    assert client.get("/app").status_code == 303
    assert read_session_cookie(b"k", make_session_cookie(b"k", TENANT_A, TENANT_A, now=0), now=10) is not None
    assert read_session_cookie(b"k", make_session_cookie(b"k", TENANT_A, TENANT_A, now=0), now=10**9) is None


def test_login_is_rate_limited_per_email(make_client):
    client = make_client()
    statuses = [client.post("/login", data={"email": USER_B["email"], "password": "nope"}).status_code
                for _ in range(11)]
    assert statuses == [401] * 10 + [429]
    assert login(client, USER_A).status_code == 303  # other accounts are unaffected


def test_logout_requires_csrf_and_clears_session(make_client):
    client = make_client()
    login(client, USER_A)
    assert client.post("/logout", data={"csrf": "forged"}).status_code == 403
    token = csrf(client.get("/app").text)
    resp = client.post("/logout", data={"csrf": token})
    assert resp.status_code == 303 and 'sp_session=""' in resp.headers["set-cookie"]
    client.cookies.clear()
    assert client.get("/app").status_code == 303


def test_password_hashing():
    stored = hash_password("correct horse")
    assert stored.startswith("scrypt$16384$8$1$")
    assert verify_password("correct horse", stored) and not verify_password("Correct horse", stored)
    assert not verify_password("x", "not-a-hash") and not verify_password("x", "bcrypt$1$2$3$4$5")


# --- isolation ----------------------------------------------------------------------------

def test_dashboard_shows_only_own_tenant(make_client):
    client = make_client()
    mine = ingest(client, TENANT_A, rule="A-RULE")
    theirs = ingest(client, TENANT_B, rule="B-RULE")
    login(client, USER_A)
    listing = client.get("/app/events").text
    assert "A-RULE" in listing and "B-RULE" not in listing
    assert client.get(f"/app/events/{mine['drift_id']}").status_code == 200
    other = client.get(f"/app/events/{theirs['drift_id']}")
    assert other.status_code == 404 and "B-RULE" not in other.text
    assert client.get("/app/events/not-a-uuid").status_code == 404


def test_app_role_cannot_list_users_without_tenant_context(pg, admin_conn):
    with psycopg.connect(pg[1]) as conn:
        assert conn.execute("SELECT count(*) FROM public.tenant_users").fetchone()[0] == 0
        # The login function sees exactly the one matching row, nothing else.
        rows = conn.execute("SELECT tenant_id FROM public.dashboard_login_lookup(%s)", [USER_B["email"]]).fetchall()
        assert rows == [(TENANT_B,)]


def test_filters(make_client):
    client = make_client()
    ingest(client, TENANT_A, rule="P1-RULE")
    ingest(client, TENANT_A, rule="P2-RULE", port="443/tcp")
    login(client, USER_A)
    p1 = client.get("/app/events", params={"severity": "P1"}).text
    assert "P1-RULE" in p1 and "P2-RULE" not in p1
    assert "Nothing matches" in client.get("/app/events", params={"status": "remediated"}).text
    assert client.get("/app/events", params={"severity": "bogus"}).status_code == 200  # ignored, not an error


# --- approvals ----------------------------------------------------------------------------

def test_approve_from_dashboard_records_who(make_client, make_worker, admin_conn):
    client = make_client()
    event = ingest(client, TENANT_A)            # Tenant A defaults to MANUAL_APPROVAL
    make_worker().run_once()                    # PENDING -> AWAITING_APPROVAL
    login(client, USER_A)
    page = client.get("/app/remediation")
    assert "Awaiting your approval" in page.text and "ALLOW-WAN-SSH-TEMP" in page.text
    job_id = event["remediation_job_id"]

    forged = client.post(f"/app/remediation/{job_id}/decide", data={"csrf": "bad", "decision": "approve"})
    assert forged.status_code == 403
    assert admin_conn.execute("SELECT state FROM public.remediation_jobs WHERE job_id = %s",
                              [job_id]).fetchone()[0] == "AWAITING_APPROVAL"

    token = csrf(page.text)
    resp = client.post(f"/app/remediation/{job_id}/decide", data={"csrf": token, "decision": "approve"})
    assert resp.headers["location"] == "/app/remediation?done=approved"
    state, decided_by, via = admin_conn.execute(
        "SELECT j.state, u.email, j.decided_via FROM public.remediation_jobs j"
        " JOIN public.tenant_users u ON u.user_id = j.decided_by WHERE j.job_id = %s", [job_id]).fetchone()
    assert (state, decided_by, via) == ("APPROVED", USER_A["email"], "dashboard")

    again = client.post(f"/app/remediation/{job_id}/decide", data={"csrf": token, "decision": "reject"})
    assert again.headers["location"] == "/app/remediation?done=stale"
    detail = client.get(f"/app/events/{event['drift_id']}").text
    assert "Approved by Ada Ops" in detail


def test_cannot_decide_another_tenants_job(make_client, make_worker, admin_conn):
    client = make_client()
    theirs = ingest(client, TENANT_B)
    make_worker().run_once()
    login(client, USER_A)
    token = csrf(client.get("/app").text)
    resp = client.post(f"/app/remediation/{theirs['remediation_job_id']}/decide",
                       data={"csrf": token, "decision": "approve"})
    assert resp.headers["location"] == "/app/remediation?done=stale"  # RLS: the UPDATE matched nothing
    assert admin_conn.execute("SELECT state FROM public.remediation_jobs WHERE job_id = %s",
                              [theirs["remediation_job_id"]]).fetchone()[0] == "AWAITING_APPROVAL"


def test_link_approval_is_recorded_as_link(make_client, make_worker, admin_conn):
    client = make_client()
    event = ingest(client, TENANT_A)
    worker = make_worker()
    worker.run_once()
    token = worker.notifier.sent[0]["approval_url"].split("token=", 1)[1]
    client.post("/v1/remediation/approve", data={"token": token, "decision": "approve"})
    assert admin_conn.execute("SELECT decided_via, decided_by FROM public.remediation_jobs WHERE job_id = %s",
                              [event["remediation_job_id"]]).fetchone() == ("link", None)


# --- rendering ----------------------------------------------------------------------------

def test_untrusted_device_data_is_escaped(make_client):
    client = make_client()
    event = ingest(client, TENANT_A, rule="<script>alert(1)</script>")
    login(client, USER_A)
    for path in ("/app", "/app/events", f"/app/events/{event['drift_id']}"):
        html = client.get(path).text
        assert "<script>alert(1)</script>" not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html, path


def test_every_page_renders(make_client, make_worker):
    client = make_client()
    event = ingest(client, TENANT_A)
    make_worker().run_once()
    login(client, USER_A)
    for path in ("/app", "/app/events", f"/app/events/{event['drift_id']}", "/app/remediation", "/app/settings"):
        resp = client.get(path)
        assert resp.status_code == 200 and "ShieldPulse" in resp.text, path
    assert 'aria-label="1 awaiting approval"' in client.get("/app").text
    assert client.get("/static/app.css").status_code == 200


def test_format_duration():
    assert [format_duration(v) for v in (None, 42, 60, 125, 3600, 5430)] == ["—", "42s", "1m", "2m 05s", "1h 00m", "1h 30m"]


def test_chart_gaps_target_and_escaping():
    points = [{"day": date(2026, 10, d), "mttr_seconds": v, "incidents": 1 if v else 0}
              for d, v in ((1, 300.0), (2, 1200.0), (3, None), (4, 600.0))]
    svg = mttr_line_chart(points, 900)
    assert svg.count("<polyline") == 1          # days 1-2 form a line; day 4 is alone after the gap
    assert svg.count("<circle") == 3 and svg.count("is-over") == 1
    assert "SLA target 15m" in svg and 'role="img"' in svg
    empty = mttr_line_chart([{"day": date(2026, 10, 1), "mttr_seconds": None, "incidents": 0}], 900)
    assert "No resolved P1/P2 incidents" in empty


def test_axis_uses_round_steps():
    from shieldpulse.charts import nice_top

    assert nice_top(3600) == 7200    # 1h target -> 4 x 30m, headroom above the target line
    assert nice_top(800) == 1200     # -> 4 x 5m
    assert nice_top(50) == 240       # -> 4 x 1m
    svg = mttr_line_chart([{"day": date(2026, 10, 1), "mttr_seconds": 500.0, "incidents": 1}], 900)
    assert all(label in svg for label in (">5m<", ">10m<", ">15m<", ">20m<"))
