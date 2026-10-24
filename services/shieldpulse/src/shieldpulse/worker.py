"""Remediation worker: runs runbooks/critical_drift_remediation.md for queued jobs.

Job states:
    PENDING ──AUTO──────────────► DISPATCHED ──rule gone──► REMEDIATED
       │                           ▲      └──still present × N──► FAILED
       └──MANUAL──► AWAITING_APPROVAL ──approve──► APPROVED ──┘
                                     └──reject───► REJECTED
    tenant not ACTIVE ──► SKIPPED

Each job is claimed with FOR UPDATE SKIP LOCKED, so several workers can run in parallel.
The claim reads only the queue. All event and tenant data is then read inside that job's
tenant context (policies/tenant_isolation_soc2.md, control 3).
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import psycopg

from shieldpulse.db import Database
from shieldpulse.remediation import (
    DeviceClient,
    Notifier,
    RecordingNotifier,
    RollbackRequest,
    SimulatedDevice,
    make_approval_token,
    sign,
)

log = logging.getLogger(__name__)

RUNNABLE_STATES = ("PENDING", "APPROVED", "DISPATCHED")


class Worker:
    def __init__(
        self,
        db: Database,
        device: DeviceClient,
        notifier: Notifier,
        dispatch_key: bytes,
        approval_key: bytes,
        approval_base_url: str,
        convergence_delay_sec: int = 60,  # runbook Step 3: poll 60 seconds after dispatch
        max_attempts: int = 3,            # retry budget for dispatch and convergence (confirmed 2026-10-24)
        approval_ttl_sec: int = 3600,     # approval link lifetime (confirmed 2026-10-24)
    ):
        self.db = db
        self.device = device
        self.notifier = notifier
        self.dispatch_key = dispatch_key
        self.approval_key = approval_key
        self.approval_base_url = approval_base_url.rstrip("/")
        self.convergence_delay_sec = convergence_delay_sec
        self.max_attempts = max_attempts
        self.approval_ttl_sec = approval_ttl_sec

    def run_once(self) -> str | None:
        """Process one due job. Returns its new state, or None if no job was due."""
        with self.db.pool.connection() as conn, conn.transaction():
            job = conn.execute(
                "SELECT job_id, tenant_id, drift_id, detected_at, state, attempts"
                " FROM public.remediation_jobs"
                " WHERE state = ANY(%s) AND run_after <= now()"
                " ORDER BY run_after LIMIT 1 FOR UPDATE SKIP LOCKED",
                [list(RUNNABLE_STATES)],
            ).fetchone()
            if job is None:
                return None
            conn.execute("SELECT set_config('app.current_tenant_id', %s, true)", [str(job["tenant_id"])])
            tenant = conn.execute(
                "SELECT status, sla_mttr_target_sec FROM public.tenants WHERE tenant_id = %s",
                [job["tenant_id"]],
            ).fetchone()
            event = conn.execute(
                "SELECT drift_id, device_hostname, vendor_type, severity, blast_radius_score,"
                " remediation_mode, rule_name, detected_at"
                " FROM public.policy_drift_events WHERE drift_id = %s AND detected_at = %s",
                [job["drift_id"], job["detected_at"]],
            ).fetchone()
            try:
                return self._step(conn, job, tenant, event)
            except psycopg.Error:
                raise  # the transaction is aborted; the job stays as it was and is retried
            except Exception as exc:  # device or notifier failure
                return self._retry_or_fail(conn, job, f"{type(exc).__name__}: {exc}")

    def run_forever(self, idle_sleep_sec: float = 1.0) -> None:
        while True:
            if self.run_once() is None:
                time.sleep(idle_sleep_sec)

    def _step(self, conn: psycopg.Connection, job: dict[str, Any], tenant: dict | None, event: dict | None) -> str:
        if tenant is None or event is None:
            return self._set(conn, job, "FAILED", last_error="tenant or drift event not found")

        if job["state"] in ("PENDING", "APPROVED"):
            # Step 1: telemetry integrity. Events are only created after the ingestion HMAC
            # check passes. Tenant status is re-checked here, including after an approval wait.
            if tenant["status"] != "ACTIVE":
                return self._set(conn, job, "SKIPPED", last_error=f"tenant status is {tenant['status']}")
            # Step 2: AUTO dispatches now. MANUAL waits for a signed approval.
            if job["state"] == "PENDING" and event["remediation_mode"] == "MANUAL_APPROVAL":
                return self._request_approval(conn, job, event)
            return self._dispatch(conn, job, event)

        # DISPATCHED. Step 3: verify convergence, then close the SLA timer.
        if self.device.rule_present(event["device_hostname"], event["rule_name"]):
            return self._retry_or_fail(conn, job, "unauthorized rule still present after rollback")
        row = conn.execute(
            "UPDATE public.policy_drift_events SET remediated_at = now()"
            " WHERE drift_id = %s AND detected_at = %s AND remediated_at IS NULL"
            " RETURNING EXTRACT(EPOCH FROM (remediated_at - detected_at))::float AS elapsed",
            [event["drift_id"], event["detected_at"]],
        ).fetchone()
        sla_met = row is not None and row["elapsed"] <= tenant["sla_mttr_target_sec"]
        return self._set(conn, job, "REMEDIATED", sla_met=sla_met, last_error=None)

    def _request_approval(self, conn: psycopg.Connection, job: dict, event: dict) -> str:
        token = make_approval_token(self.approval_key, job["job_id"], job["tenant_id"], self.approval_ttl_sec)
        url = f"{self.approval_base_url}/v1/remediation/approve?token={token}"
        self.notifier.request_approval(job["tenant_id"], {**event, "drift_id": str(event["drift_id"])}, url)
        return self._set(conn, job, "AWAITING_APPROVAL", last_error=None)

    def _dispatch(self, conn: psycopg.Connection, job: dict, event: dict) -> str:
        if not event["rule_name"]:
            # Without the rule name, convergence cannot be verified, so do not roll back blind.
            return self._set(conn, job, "FAILED", last_error="event has no rule_name; cannot verify convergence")
        request = RollbackRequest(
            tenant_id=str(job["tenant_id"]), drift_id=str(event["drift_id"]),
            device_hostname=event["device_hostname"], vendor_type=event["vendor_type"],
            rule_name=event["rule_name"],
        )
        payload = request.payload()
        self.device.dispatch_rollback(payload, sign(self.dispatch_key, payload))
        return self._set(conn, job, "DISPATCHED", attempts=0, last_error=None,
                         delay_sec=self.convergence_delay_sec)

    def _retry_or_fail(self, conn: psycopg.Connection, job: dict, error: str) -> str:
        attempts = job["attempts"] + 1
        if attempts >= self.max_attempts:
            return self._set(conn, job, "FAILED", attempts=attempts, last_error=error)
        log.warning("job %s attempt %d failed: %s", job["job_id"], attempts, error)
        return self._set(conn, job, job["state"], attempts=attempts, last_error=error,
                         delay_sec=self.convergence_delay_sec)

    def _set(self, conn: psycopg.Connection, job: dict, state: str, delay_sec: int = 0, **fields: Any) -> str:
        assignments = ", ".join(f"{name} = %({name})s" for name in fields)
        conn.execute(
            "UPDATE public.remediation_jobs SET state = %(state)s, updated_at = now(),"
            " run_after = now() + make_interval(secs => %(delay)s)"
            + (f", {assignments}" if assignments else "")
            + " WHERE job_id = %(job_id)s",
            {"state": state, "delay": delay_sec, "job_id": job["job_id"], **fields},
        )
        log.info("job %s: %s -> %s", job["job_id"], job["state"], state)
        return state


def main() -> None:
    """Dev entry point: `python -m shieldpulse.worker`, with a simulated device and a log notifier."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    dispatch_key = os.environ["SHIELDPULSE_DISPATCH_KEY"].encode()
    worker = Worker(
        db=Database(os.environ["SHIELDPULSE_WORKER_DATABASE_URL"]),
        device=SimulatedDevice(dispatch_key),
        notifier=RecordingNotifier(),
        dispatch_key=dispatch_key,
        approval_key=os.environ["SHIELDPULSE_APPROVAL_KEY"].encode(),
        approval_base_url=os.environ.get("SHIELDPULSE_PUBLIC_BASE_URL", "http://localhost:8000"),
        convergence_delay_sec=int(os.environ.get("SHIELDPULSE_CONVERGENCE_DELAY_SEC", "60")),
    )
    log.info("remediation worker started")
    worker.run_forever()


if __name__ == "__main__":
    main()
