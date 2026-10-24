"""Tenant dashboard: server-rendered pages on the API's own port.

Every page reads inside the signed-in user's tenant context (Database.tenant_tx), so RLS
scopes all data exactly as it does for the webhook. Mutations require a session-bound CSRF
token; cookies are HttpOnly and SameSite=Strict.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from shieldpulse.auth import (
    DUMMY_HASH,
    SESSION_TTL_SEC,
    Session,
    check_csrf,
    make_session_cookie,
    read_session_cookie,
    verify_password,
)
from shieldpulse.charts import format_duration, mttr_line_chart
from shieldpulse.db import Database
from shieldpulse.metrics import daily_mttr, mttr_summary, overview_counts
from shieldpulse.ratelimit import RateLimiter

HERE = Path(__file__).parent
COOKIE = "sp_session"
SEVERITIES = ("P1", "P2", "P3", "INFO")
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                               "form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "Cache-Control": "no-store",
}

def when(value: datetime | None) -> str:
    """Absolute UTC time; static/app.js adds a relative "5 min ago" label in the browser."""
    if value is None:
        return "—"
    value = value.astimezone(timezone.utc)
    return f"{value:%b} {value.day}, {value:%H:%M} UTC"


def iso(value: datetime | None) -> str:
    return value.astimezone(timezone.utc).isoformat() if value else ""


templates = Jinja2Templates(directory=HERE / "templates")
templates.env.filters.update(duration=format_duration, when=when, iso=iso)


class LoginRequired(Exception):
    def __init__(self, next_path: str):
        self.next_path = next_path


def safe_next(path: str | None) -> str:
    """Only same-site dashboard paths; blocks open redirects such as //evil.example."""
    if path and path.startswith("/app") and not path.startswith("//"):
        return path
    return "/app"


def form(body: bytes) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(body.decode("utf-8", "replace")).items()}


def add_dashboard(app: FastAPI, db: Database, session_key: bytes, secure_cookies: bool = True,
                  login_limiter: RateLimiter | None = None) -> None:
    login_limiter = login_limiter or RateLimiter({"login": 10})  # attempts per email per minute
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    @app.exception_handler(LoginRequired)
    async def _to_login(_: Request, exc: LoginRequired) -> RedirectResponse:
        return RedirectResponse(f"/login?next={quote(exc.next_path)}", status_code=303)

    def current_user(request: Request) -> tuple[Session, dict[str, Any]]:
        session = read_session_cookie(session_key, request.cookies.get(COOKIE))
        if session is not None:
            with db.tenant_tx(session.tenant_id) as conn:
                user = conn.execute(
                    "SELECT u.user_id, u.display_name, u.email, t.tenant_id, t.org_name, t.plan_tier, t.status,"
                    "       t.remediation_mode, t.sla_mttr_target_sec,"
                    "       (SELECT COUNT(*) FROM public.remediation_jobs WHERE state = 'AWAITING_APPROVAL')"
                    "         AS awaiting_count"
                    " FROM public.tenant_users u JOIN public.tenants t USING (tenant_id)"
                    " WHERE u.user_id = %s", [session.user_id],
                ).fetchone()
            if user is not None:
                return session, user
        raise LoginRequired(request.url.path + (f"?{request.url.query}" if request.url.query else ""))

    def render(request: Request, name: str, context: dict[str, Any], status_code: int = 200,
               auth: tuple[Session, dict[str, Any]] | None = None) -> HTMLResponse:
        if auth is not None:
            session, user = auth
            context = {**context, "user": user, "csrf": session.csrf_token(session_key)}
        response = templates.TemplateResponse(request, name, {"path": request.url.path, **context},
                                              status_code=status_code)
        response.headers.update(SECURITY_HEADERS)
        return response

    def denied(request: Request, auth, message: str, status_code: int) -> HTMLResponse:
        return render(request, "message.html", {"title": "Not available", "message": message},
                      status_code, auth)

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse("/app", status_code=303)

    # --- auth --------------------------------------------------------------------------

    # The demo-account hint only shows in local dev (insecure cookies), never in production.
    demo_hint = not secure_cookies

    @app.get("/login", response_class=HTMLResponse, include_in_schema=False)
    def login_page(request: Request, next: str | None = None):
        return render(request, "login.html", {"next": safe_next(next), "error": None, "demo_hint": demo_hint})

    @app.post("/login", response_class=HTMLResponse, include_in_schema=False)
    async def login(request: Request):
        fields = form(await request.body())
        email = fields.get("email", "").strip()
        password = fields.get("password", "")
        next_path = safe_next(fields.get("next"))
        if login_limiter.check(uuid.uuid5(uuid.NAMESPACE_URL, email.lower()), "login") is not None:
            return render(request, "login.html", {"next": next_path, "error": "Too many attempts. Wait a minute "
                                                  "and try again.", "email": email, "demo_hint": demo_hint}, 429)
        with db.pool.connection() as conn:
            row = conn.execute("SELECT * FROM public.dashboard_login_lookup(%s)", [email]).fetchone()
        # Unknown emails still pay for one scrypt, so timing does not reveal which emails exist.
        valid = verify_password(password, row["password_hash"] if row else DUMMY_HASH) and row is not None
        if not valid:
            return render(request, "login.html", {"next": next_path, "error": "That email and password don't "
                                                  "match an account.", "email": email, "demo_hint": demo_hint}, 401)
        response = RedirectResponse(next_path, status_code=303)
        response.set_cookie(COOKIE, make_session_cookie(session_key, row["user_id"], row["tenant_id"]),
                            max_age=SESSION_TTL_SEC, httponly=True, samesite="strict", secure=secure_cookies,
                            path="/")
        return response

    @app.post("/logout", include_in_schema=False)
    async def logout(request: Request):
        session, _ = current_user(request)
        if not check_csrf(session_key, session, form(await request.body()).get("csrf")):
            return Response("Invalid form token", status_code=403)
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(COOKIE, path="/")
        return response

    # --- pages -------------------------------------------------------------------------

    @app.get("/app", response_class=HTMLResponse, include_in_schema=False)
    def overview(request: Request):
        auth = current_user(request)
        session, user = auth
        with db.tenant_tx(session.tenant_id) as conn:
            counts = overview_counts(conn)
            summary = mttr_summary(conn, user["plan_tier"], user["sla_mttr_target_sec"])
            series = daily_mttr(conn, 30)
            recent = conn.execute(
                "SELECT e.drift_id, e.detected_at, e.device_hostname, e.severity, e.blast_radius_score,"
                "       e.rule_name, e.remediated_at, j.state AS job_state"
                " FROM public.policy_drift_events e"
                " LEFT JOIN public.remediation_jobs j USING (drift_id, detected_at)"
                " ORDER BY e.detected_at DESC LIMIT 6",
            ).fetchall()
        return render(request, "overview.html", {
            "counts": counts, "summary": summary, "recent": recent,
            "chart": mttr_line_chart(series, user["sla_mttr_target_sec"]),
        }, auth=auth)

    @app.get("/app/events", response_class=HTMLResponse, include_in_schema=False)
    def events(request: Request, severity: str = "all", status: str = "all"):
        auth = current_user(request)
        severity = severity if severity in SEVERITIES else "all"
        status = status if status in ("open", "remediated") else "all"
        where, params = [], {}
        if severity != "all":
            where.append("e.severity = %(severity)s")
            params["severity"] = severity
        if status == "open":
            where.append("e.remediated_at IS NULL")
        elif status == "remediated":
            where.append("e.remediated_at IS NOT NULL")
        with db.tenant_tx(auth[0].tenant_id) as conn:
            rows = conn.execute(
                "SELECT e.drift_id, e.detected_at, e.device_hostname, e.vendor_type, e.severity,"
                "       e.blast_radius_score, e.rule_name, e.remediated_at, j.state AS job_state"
                " FROM public.policy_drift_events e"
                " LEFT JOIN public.remediation_jobs j USING (drift_id, detected_at)"
                + (" WHERE " + " AND ".join(where) if where else "")
                + " ORDER BY e.detected_at DESC LIMIT 100",
                params,
            ).fetchall()
        return render(request, "events.html", {"rows": rows, "severity": severity, "status": status,
                                               "severities": SEVERITIES}, auth=auth)

    @app.get("/app/events/{drift_id}", response_class=HTMLResponse, include_in_schema=False)
    def event_detail(request: Request, drift_id: str):
        auth = current_user(request)
        try:
            drift_uuid = uuid.UUID(drift_id)
        except ValueError:
            return denied(request, auth, "That drift event doesn't exist.", 404)
        with db.tenant_tx(auth[0].tenant_id) as conn:
            event = conn.execute(
                "SELECT * FROM public.policy_drift_events WHERE drift_id = %s LIMIT 1", [drift_uuid]
            ).fetchone()
            job = event and conn.execute(
                "SELECT j.*, u.display_name AS decided_by_name FROM public.remediation_jobs j"
                " LEFT JOIN public.tenant_users u ON u.user_id = j.decided_by"
                " WHERE j.drift_id = %s AND j.detected_at = %s",
                [event["drift_id"], event["detected_at"]],
            ).fetchone()
        if event is None:  # also the answer for another tenant's event: RLS hides it
            return denied(request, auth, "That drift event doesn't exist.", 404)
        return render(request, "event_detail.html", {"event": event, "job": job,
                                                     "timeline": timeline(event, job)}, auth=auth)

    @app.get("/app/remediation", response_class=HTMLResponse, include_in_schema=False)
    def remediation(request: Request, done: str | None = None):
        auth = current_user(request)
        with db.tenant_tx(auth[0].tenant_id) as conn:
            jobs = conn.execute(
                "SELECT j.job_id, j.state, j.attempts, j.sla_met, j.last_error, j.created_at, j.updated_at,"
                "       j.decided_at, j.decided_via, u.display_name AS decided_by_name,"
                "       e.drift_id, e.device_hostname, e.vendor_type, e.severity, e.blast_radius_score,"
                "       e.rule_name, e.diff_summary, e.detected_at"
                " FROM public.remediation_jobs j"
                " JOIN public.policy_drift_events e USING (drift_id, detected_at)"
                " LEFT JOIN public.tenant_users u ON u.user_id = j.decided_by"
                " ORDER BY (j.state = 'AWAITING_APPROVAL') DESC, j.created_at DESC LIMIT 50",
            ).fetchall()
        return render(request, "remediation.html", {
            "awaiting": [j for j in jobs if j["state"] == "AWAITING_APPROVAL"],
            "history": [j for j in jobs if j["state"] != "AWAITING_APPROVAL"],
            "done": done if done in ("approved", "rejected", "stale") else None,
        }, auth=auth)

    @app.post("/app/remediation/{job_id}/decide", include_in_schema=False)
    async def decide(request: Request, job_id: str):
        auth = current_user(request)
        session, user = auth
        fields = form(await request.body())
        if not check_csrf(session_key, session, fields.get("csrf")):
            return denied(request, auth, "This form expired. Reload the page and try again.", 403)
        decision = fields.get("decision")
        try:
            job_uuid = uuid.UUID(job_id)
        except ValueError:
            job_uuid = None
        if decision not in ("approve", "reject") or job_uuid is None:
            return denied(request, auth, "That decision isn't valid.", 400)
        with db.tenant_tx(session.tenant_id) as conn:
            updated = conn.execute(
                "UPDATE public.remediation_jobs SET state = %s, updated_at = now(), run_after = now(),"
                " decided_by = %s, decided_at = now(), decided_via = 'dashboard'"
                " WHERE job_id = %s AND state = 'AWAITING_APPROVAL' RETURNING job_id",
                ["APPROVED" if decision == "approve" else "REJECTED", user["user_id"], job_uuid],
            ).fetchone()
        outcome = ("approved" if decision == "approve" else "rejected") if updated else "stale"
        return RedirectResponse(f"/app/remediation?done={outcome}", status_code=303)

    @app.get("/app/settings", response_class=HTMLResponse, include_in_schema=False)
    def settings(request: Request):
        auth = current_user(request)
        return render(request, "settings.html", {}, auth=auth)


def timeline(event: dict[str, Any], job: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Steps reconstructed from recorded timestamps; steps without a recorded time show none."""
    steps = [{"label": "Drift detected", "at": event["detected_at"], "state": "done",
              "detail": f"Signed snapshot from {event['device_hostname']} scored {event['severity']} "
                        f"(blast radius {event['blast_radius_score']})."}]
    if job is None:
        steps.append({"label": "No runbook needed", "at": None, "state": "done",
                      "detail": "Below the P1 / blast-radius 80 threshold, so no automated remediation."})
        return steps
    steps.append({"label": "Queued for remediation", "at": job["created_at"], "state": "done",
                  "detail": f"Runbook job created ({event['remediation_mode'].replace('_', ' ').lower()})."})
    state = job["state"]
    if event["remediation_mode"] == "MANUAL_APPROVAL":
        if job["decided_at"]:
            who = job["decided_by_name"] or "a link holder"
            verb = "Rejected" if state == "REJECTED" else "Approved"
            steps.append({"label": f"{verb} by {who}", "at": job["decided_at"],
                          "state": "failed" if state == "REJECTED" else "done",
                          "detail": f"Decided via {job['decided_via'] or 'dashboard'}."})
        elif state == "AWAITING_APPROVAL":
            steps.append({"label": "Awaiting approval", "at": None, "state": "current",
                          "detail": "A signed approval link was sent. You can also decide on the Remediation page."})
    if state in ("DISPATCHED", "REMEDIATED", "FAILED"):
        steps.append({"label": "Rollback dispatched", "at": None, "state": "done" if state != "DISPATCHED" else "current",
                      "detail": "Signed rollback to the last-known-good configuration."})
    if state == "REMEDIATED":
        sla = "within" if job["sla_met"] else "outside"
        steps.append({"label": "Remediated", "at": event["remediated_at"], "state": "done",
                      "detail": f"Rule confirmed removed, {sla} the SLA target."})
    elif state in ("FAILED", "SKIPPED"):
        steps.append({"label": state.title(), "at": job["updated_at"], "state": "failed",
                      "detail": job["last_error"] or ""})
    return steps
