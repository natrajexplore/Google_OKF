"""ShieldPulse ingestion API (Phase 1).

Implements apis/ingest_telemetry.md. Checks run in this order: tenant lookup, HMAC over
the raw bytes, rate limit, then payload parsing, so unauthenticated input is never parsed.
"""

from __future__ import annotations

import hmac
import os
import re
from contextlib import asynccontextmanager
from hashlib import sha256
from html import escape
from typing import Any, Literal
from urllib.parse import parse_qs
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from psycopg.types.json import Jsonb
from pydantic import AwareDatetime, BaseModel, Field, ValidationError

from shieldpulse.db import Database
from shieldpulse.ratelimit import RateLimiter
from shieldpulse.remediation import InvalidToken, verify_approval_token
from shieldpulse.scoring import score_diff
from shieldpulse.secret_store import LocalSecretStore, SecretStore

# Unknown tenants and bad signatures share one response so tenant existence never leaks.
UNAUTHORIZED = HTTPException(status_code=401, detail="Invalid tenant or signature")
MONTH_RE = re.compile(r"\d{4}-(0[1-9]|1[0-2])")
SLA_CREDIT_PERCENT = 5  # metrics/net_revenue_retention.md


class DiffSummary(BaseModel):
    rule_name: str
    source_zone: str
    destination_port: str
    action: str


class Snapshot(BaseModel):
    device_hostname: str = Field(min_length=1, max_length=128)
    vendor_type: Literal["palo_alto_panos", "cisco_sdwan", "fortigate", "aws_sg"]
    snapshot_timestamp: AwareDatetime
    # Optional: periodic state snapshots may report no change.
    diff_summary: DiffSummary | None = None


class Tenant(BaseModel):
    tenant_id: UUID
    plan_tier: str
    status: str
    sla_mttr_target_sec: int
    remediation_mode: str


async def raw_body(request: Request) -> bytes:
    return await request.body()


def page(title: str, body: str, status_code: int = 200) -> HTMLResponse:
    return HTMLResponse(
        f"<!doctype html><html><head><meta charset='utf-8'><title>{escape(title)}</title></head>"
        f"<body style='font-family:system-ui;max-width:40rem;margin:2rem auto'><h1>{escape(title)}</h1>"
        f"{body}</body></html>",
        status_code=status_code,
    )


def create_app(
    db: Database,
    secrets: SecretStore,
    limiter: RateLimiter | None = None,
    approval_key: bytes | None = None,
) -> FastAPI:
    """Approval endpoints are only mounted when approval_key is given."""
    limiter = limiter or RateLimiter()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        db.close()

    app = FastAPI(title="ShieldPulse Control Plane", version="0.1.0", lifespan=lifespan)

    def authenticate(
        body: bytes = Depends(raw_body),
        x_tenant_id: str | None = Header(default=None),
        x_shieldpulse_signature: str | None = Header(default=None),
    ) -> Tenant:
        if not x_tenant_id or not x_shieldpulse_signature:
            raise UNAUTHORIZED
        try:
            tenant_id = UUID(x_tenant_id)
        except ValueError:
            raise UNAUTHORIZED from None
        with db.tenant_tx(tenant_id) as conn:
            row = conn.execute(
                "SELECT tenant_id, plan_tier, status, sla_mttr_target_sec, remediation_mode, webhook_secret_arn"
                " FROM public.tenants WHERE tenant_id = %s",
                [tenant_id],
            ).fetchone()
        secret = secrets.get(row["webhook_secret_arn"]) if row else None
        if secret is None:
            raise UNAUTHORIZED
        expected = hmac.new(secret, body, sha256).hexdigest()
        if not hmac.compare_digest(expected, x_shieldpulse_signature.strip().lower()):
            raise UNAUTHORIZED
        tenant = Tenant(**row)
        if (retry_after := limiter.check(tenant.tenant_id, tenant.plan_tier)) is not None:
            raise HTTPException(status_code=429, detail="Rate limit exceeded",
                                headers={"Retry-After": str(retry_after)})
        return tenant

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/telemetry/drift-snapshot", status_code=202)
    def ingest_drift_snapshot(tenant: Tenant = Depends(authenticate), body: bytes = Depends(raw_body)):
        try:
            snapshot = Snapshot.model_validate_json(body)
        except ValidationError as exc:
            errors = [{"loc": e["loc"], "msg": e["msg"]} for e in exc.errors()]
            return JSONResponse(status_code=400, content={"detail": "Invalid payload", "errors": errors})

        events: list[dict[str, Any]] = []
        if snapshot.diff_summary is not None:
            diff = snapshot.diff_summary
            score = score_diff(diff.source_zone, diff.destination_port, diff.action)
            job_id = None
            with db.tenant_tx(tenant.tenant_id) as conn:
                row = conn.execute(
                    "INSERT INTO public.policy_drift_events"
                    " (tenant_id, device_hostname, vendor_type, severity, blast_radius_score, remediation_mode,"
                    "  rule_name, diff_summary)"
                    " VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING drift_id, detected_at",
                    [tenant.tenant_id, snapshot.device_hostname, snapshot.vendor_type,
                     score.severity, score.blast_radius_score, tenant.remediation_mode,
                     diff.rule_name, Jsonb(diff.model_dump())],
                ).fetchone()
                # Queued in the same transaction, so a runbook-worthy event is never left without a job.
                if score.triggers_runbook:
                    job_id = conn.execute(
                        "INSERT INTO public.remediation_jobs (tenant_id, drift_id, detected_at)"
                        " VALUES (%s, %s, %s) RETURNING job_id",
                        [tenant.tenant_id, row["drift_id"], row["detected_at"]],
                    ).fetchone()["job_id"]
            events.append({
                "drift_id": str(row["drift_id"]),
                "detected_at": row["detected_at"].isoformat(),
                "severity": score.severity,
                "blast_radius_score": score.blast_radius_score,
                "remediation_mode": tenant.remediation_mode,
                "triggers_runbook": score.triggers_runbook,
                "remediation_job_id": str(job_id) if job_id else None,
            })
        return {"accepted": True, "drift_events": events}

    # DRAFT endpoint: not in the bundle. Exposes metrics/mean_time_to_remediate.md to the
    # tenant itself, authenticated like the webhook (HMAC over the empty body).
    @app.get("/v1/metrics/mttr")
    def get_mttr(month: str | None = None, tenant: Tenant = Depends(authenticate)) -> dict[str, Any]:
        """Trailing 30-day MTTR for dashboards, plus the calendar-month MTTR that governs SLA credits.

        month: billing month as YYYY-MM (UTC, by detected_at). Defaults to the current month.
        """
        if month is not None and not MONTH_RE.fullmatch(month):
            raise HTTPException(status_code=400, detail="month must be YYYY-MM")
        with db.tenant_tx(tenant.tenant_id) as conn:
            row = conn.execute(
                "WITH resolved AS ("
                "  SELECT detected_at AT TIME ZONE 'UTC' AS detected_utc, detected_at,"
                "         EXTRACT(EPOCH FROM (remediated_at - detected_at)) AS secs"
                "  FROM public.policy_drift_events"
                "  WHERE severity IN ('P1', 'P2') AND remediated_at IS NOT NULL"
                "), billing AS ("
                "  SELECT COALESCE(%(month)s::date, date_trunc('month', now() AT TIME ZONE 'UTC')::date) AS start"
                ")"
                " SELECT"
                "  (SELECT AVG(secs)::float FROM resolved"
                "    WHERE detected_at >= CURRENT_DATE - INTERVAL '30 days') AS trailing_mttr,"
                "  (SELECT COUNT(*) FROM resolved"
                "    WHERE detected_at >= CURRENT_DATE - INTERVAL '30 days') AS trailing_count,"
                "  (SELECT AVG(secs)::float FROM resolved, billing"
                "    WHERE detected_utc >= start AND detected_utc < start + INTERVAL '1 month') AS month_mttr,"
                "  (SELECT COUNT(*) FROM resolved, billing"
                "    WHERE detected_utc >= start AND detected_utc < start + INTERVAL '1 month') AS month_count,"
                "  (SELECT to_char(start, 'YYYY-MM') FROM billing) AS month",
                {"month": f"{month}-01" if month else None},
            ).fetchone()
        target = tenant.sla_mttr_target_sec
        trailing, monthly = row["trailing_mttr"], row["month_mttr"]
        # Confirmed 2026-10-24: a breach is the calendar month's average above target, and earns
        # at most one 5% credit, for enterprise_plus only (metrics/net_revenue_retention.md).
        breached = monthly is not None and monthly > target
        credit_eligible = breached and tenant.plan_tier == "enterprise_plus"
        return {
            "tenant_id": str(tenant.tenant_id),
            "sla_mttr_target_sec": target,
            "trailing_30_days": {
                "mttr_seconds": trailing,
                "resolved_p1_p2_incidents": row["trailing_count"],
                "above_target": trailing is not None and trailing > target,
            },
            "billing_month": {
                "month": row["month"],
                "mttr_seconds": monthly,
                "resolved_p1_p2_incidents": row["month_count"],
                "sla_breached": breached,
                "sla_credit_eligible": credit_eligible,
                "credit_percent": SLA_CREDIT_PERCENT if credit_eligible else 0,
            },
        }

    if approval_key is not None:
        add_approval_routes(app, db, approval_key)
    return app


def add_approval_routes(app: FastAPI, db: Database, approval_key: bytes) -> None:
    """Runbook Step 2 (MANUAL_APPROVAL): the one-click signed approval link.

    GET only shows a confirmation page. Email and chat link scanners prefetch URLs, so a GET
    that approved would trigger rollbacks nobody chose. The decision is a POST.
    DRAFT: the token is a bearer credential; approver identity (SSO) is not captured yet.
    """
    path = "/v1/remediation/approve"

    def load(token: str) -> tuple[dict, dict] | HTMLResponse:
        try:
            job_id, tenant_id = verify_approval_token(approval_key, token)
        except InvalidToken as exc:
            return page("Link not valid", f"<p>This approval link is {escape(str(exc))}.</p>", 403)
        with db.tenant_tx(tenant_id) as conn:
            job = conn.execute(
                "SELECT job_id, tenant_id, state, drift_id, detected_at FROM public.remediation_jobs"
                " WHERE job_id = %s", [job_id],
            ).fetchone()
            event = job and conn.execute(
                "SELECT device_hostname, vendor_type, severity, blast_radius_score, rule_name, diff_summary"
                " FROM public.policy_drift_events WHERE drift_id = %s AND detected_at = %s",
                [job["drift_id"], job["detected_at"]],
            ).fetchone()
        if not job or not event:
            return page("Link not valid", "<p>This remediation no longer exists.</p>", 404)
        return job, event

    @app.get(path, response_class=HTMLResponse)
    def approval_page(token: str):
        loaded = load(token)
        if isinstance(loaded, HTMLResponse):
            return loaded
        job, event = loaded
        if job["state"] != "AWAITING_APPROVAL":
            return page("Already decided", f"<p>This remediation is <b>{escape(job['state'])}</b>.</p>", 409)
        diff = event["diff_summary"] or {}
        rows = "".join(
            f"<tr><th align='left'>{escape(k)}</th><td>{escape(str(v))}</td></tr>"
            for k, v in [("Device", event["device_hostname"]), ("Vendor", event["vendor_type"]),
                         ("Severity", event["severity"]), ("Blast radius", event["blast_radius_score"]),
                         ("Rule", event["rule_name"]), ("Source zone", diff.get("source_zone")),
                         ("Destination port", diff.get("destination_port")), ("Action", diff.get("action"))]
        )
        form = (
            f"<form method='post' action='{path}'><input type='hidden' name='token' value='{escape(token)}'>"
            "<button name='decision' value='approve'>Approve rollback</button> "
            "<button name='decision' value='reject'>Reject</button></form>"
        )
        return page("Approve rollback?", f"<table>{rows}</table><p>Roll back to the last-known-good state?</p>{form}")

    @app.post(path, response_class=HTMLResponse)
    def decide(body: bytes = Depends(raw_body)):
        fields = parse_qs(body.decode("utf-8", "replace"))
        token = (fields.get("token") or [""])[0]
        decision = (fields.get("decision") or [""])[0]
        if decision not in ("approve", "reject"):
            return page("Invalid request", "<p>Choose approve or reject.</p>", 400)
        loaded = load(token)
        if isinstance(loaded, HTMLResponse):
            return loaded
        job, _ = loaded
        new_state = "APPROVED" if decision == "approve" else "REJECTED"
        with db.tenant_tx(job["tenant_id"]) as conn:
            updated = conn.execute(
                "UPDATE public.remediation_jobs SET state = %s, updated_at = now(), run_after = now()"
                " WHERE job_id = %s AND state = 'AWAITING_APPROVAL' RETURNING job_id",
                [new_state, job["job_id"]],
            ).fetchone()
        if updated is None:
            return page("Already decided", "<p>This remediation was already decided.</p>", 409)
        return page("Rollback approved" if new_state == "APPROVED" else "Rollback rejected",
                    f"<p>Remediation is now <b>{new_state}</b>.</p>")


def create_app_from_env() -> FastAPI:
    """Entry point for `uvicorn --factory shieldpulse.app:create_app_from_env`."""
    db = Database(os.environ["SHIELDPULSE_DATABASE_URL"])
    secrets = LocalSecretStore.from_file(os.environ["SHIELDPULSE_LOCAL_SECRETS"])
    approval_key = os.environ.get("SHIELDPULSE_APPROVAL_KEY")
    return create_app(db, secrets, approval_key=approval_key.encode() if approval_key else None)
