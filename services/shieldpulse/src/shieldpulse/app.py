"""ShieldPulse ingestion API (Phase 1).

Implements apis/ingest_telemetry.md. Checks run in this order: tenant lookup, HMAC over
the raw bytes, rate limit, then payload parsing, so unauthenticated input is never parsed.
"""

from __future__ import annotations

import hmac
import os
from contextlib import asynccontextmanager
from hashlib import sha256
from typing import Any, Literal
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import AwareDatetime, BaseModel, Field, ValidationError

from shieldpulse.db import Database
from shieldpulse.ratelimit import RateLimiter
from shieldpulse.scoring import score_diff
from shieldpulse.secret_store import LocalSecretStore, SecretStore

# Unknown tenants and bad signatures share one response so tenant existence never leaks.
UNAUTHORIZED = HTTPException(status_code=401, detail="Invalid tenant or signature")


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


async def raw_body(request: Request) -> bytes:
    return await request.body()


def create_app(db: Database, secrets: SecretStore, limiter: RateLimiter | None = None) -> FastAPI:
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
                "SELECT tenant_id, plan_tier, status, sla_mttr_target_sec, webhook_secret_arn"
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
            with db.tenant_tx(tenant.tenant_id) as conn:
                row = conn.execute(
                    "INSERT INTO public.policy_drift_events"
                    " (tenant_id, device_hostname, vendor_type, severity, blast_radius_score, remediation_mode)"
                    " VALUES (%s, %s, %s, %s, %s, %s) RETURNING drift_id, detected_at",
                    [tenant.tenant_id, snapshot.device_hostname, snapshot.vendor_type,
                     score.severity, score.blast_radius_score, score.remediation_mode],
                ).fetchone()
            events.append({
                "drift_id": str(row["drift_id"]),
                "detected_at": row["detected_at"].isoformat(),
                "severity": score.severity,
                "blast_radius_score": score.blast_radius_score,
                "remediation_mode": score.remediation_mode,
                "triggers_runbook": score.triggers_runbook,
            })
        return {"accepted": True, "drift_events": events}

    # DRAFT endpoint: not in the bundle. Exposes metrics/mean_time_to_remediate.md to the
    # tenant itself, authenticated like the webhook (HMAC over the empty body).
    @app.get("/v1/metrics/mttr")
    def get_mttr(tenant: Tenant = Depends(authenticate)) -> dict[str, Any]:
        with db.tenant_tx(tenant.tenant_id) as conn:
            row = conn.execute(
                "SELECT AVG(EXTRACT(EPOCH FROM (remediated_at - detected_at)))::float AS mttr_seconds,"
                "       COUNT(*) AS incidents"
                " FROM public.policy_drift_events"
                " WHERE severity IN ('P1', 'P2')"
                "   AND remediated_at IS NOT NULL"
                "   AND detected_at >= CURRENT_DATE - INTERVAL '30 days'",
            ).fetchone()
        mttr = row["mttr_seconds"]
        breached = mttr is not None and mttr > tenant.sla_mttr_target_sec
        return {
            "tenant_id": str(tenant.tenant_id),
            "window": "trailing_30_days",
            "resolved_p1_p2_incidents": row["incidents"],
            "mttr_seconds": mttr,
            "sla_mttr_target_sec": tenant.sla_mttr_target_sec,
            "sla_breached": breached,
            # Credits apply to enterprise_plus only (metrics/net_revenue_retention.md).
            "sla_credit_eligible": breached and tenant.plan_tier == "enterprise_plus",
        }

    return app


def create_app_from_env() -> FastAPI:
    """Entry point for `uvicorn --factory shieldpulse.app:create_app_from_env`."""
    db = Database(os.environ["SHIELDPULSE_DATABASE_URL"])
    secrets = LocalSecretStore.from_file(os.environ["SHIELDPULSE_LOCAL_SECRETS"])
    return create_app(db, secrets)
