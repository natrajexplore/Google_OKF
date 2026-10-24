"""Tenant metrics shared by the API and the dashboard (metrics/mean_time_to_remediate.md).

Every function takes a connection already bound to one tenant (Database.tenant_tx), so RLS
scopes all rows. None of them filter by tenant_id themselves.
"""

from __future__ import annotations

import re
from typing import Any

import psycopg

MONTH_RE = re.compile(r"\d{4}-(0[1-9]|1[0-2])")
SLA_CREDIT_PERCENT = 5  # metrics/net_revenue_retention.md


def mttr_summary(conn: psycopg.Connection, plan_tier: str, target_sec: int, month: str | None = None) -> dict[str, Any]:
    """Trailing 30-day MTTR (dashboards) plus the calendar-month MTTR that governs SLA credits.

    month: billing month as YYYY-MM (UTC, by detected_at). Defaults to the current month.
    """
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
    trailing, monthly = row["trailing_mttr"], row["month_mttr"]
    # Confirmed 2026-10-24: a breach is the calendar month's average above target, and earns
    # at most one 5% credit, for enterprise_plus only.
    breached = monthly is not None and monthly > target_sec
    credit_eligible = breached and plan_tier == "enterprise_plus"
    return {
        "sla_mttr_target_sec": target_sec,
        "trailing_30_days": {
            "mttr_seconds": trailing,
            "resolved_p1_p2_incidents": row["trailing_count"],
            "above_target": trailing is not None and trailing > target_sec,
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


def daily_mttr(conn: psycopg.Connection, days: int = 30) -> list[dict[str, Any]]:
    """One point per UTC day for the last `days` days; mttr_seconds is None on days without incidents."""
    return conn.execute(
        "SELECT d::date AS day, AVG(EXTRACT(EPOCH FROM (e.remediated_at - e.detected_at)))::float AS mttr_seconds,"
        "       COUNT(e.drift_id) AS incidents"
        " FROM generate_series((now() AT TIME ZONE 'UTC')::date - (%(days)s - 1), (now() AT TIME ZONE 'UTC')::date,"
        "                      INTERVAL '1 day') AS d"
        " LEFT JOIN public.policy_drift_events e"
        "   ON (e.detected_at AT TIME ZONE 'UTC')::date = d::date"
        "  AND e.severity IN ('P1', 'P2') AND e.remediated_at IS NOT NULL"
        " GROUP BY d ORDER BY d",
        {"days": days},
    ).fetchall()


def overview_counts(conn: psycopg.Connection) -> dict[str, int]:
    return conn.execute(
        "SELECT"
        "  (SELECT COUNT(*) FROM public.policy_drift_events WHERE remediated_at IS NULL) AS open_events,"
        "  (SELECT COUNT(*) FROM public.policy_drift_events WHERE remediated_at IS NULL AND severity = 'P1') AS open_p1,"
        "  (SELECT COUNT(*) FROM public.policy_drift_events"
        "    WHERE detected_at >= now() - INTERVAL '7 days') AS events_7d,"
        "  (SELECT COUNT(*) FROM public.remediation_jobs WHERE state = 'AWAITING_APPROVAL') AS awaiting_approval,"
        "  (SELECT COUNT(*) FROM public.remediation_jobs WHERE state IN ('PENDING', 'APPROVED', 'DISPATCHED')) AS in_flight,"
        "  (SELECT COUNT(*) FROM public.remediation_jobs WHERE state = 'FAILED') AS failed",
    ).fetchone()
