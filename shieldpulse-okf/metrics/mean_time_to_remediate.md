---
type: metric
title: "Mean Time to Remediate (MTTR)"
description: "Average elapsed time in seconds between detecting a P1/P2 policy drift event and restoring the compliant golden configuration."
resource: "bigquery://shieldpulse-analytics.ops_mart.vw_tenant_mttr"
owners: ["secops-eng@shieldpulse.io"]
tags: ["metric", "sla", "operations", "security"]
timestamp: "2026-10-17T08:55:00Z"
---

# Metric: Mean Time to Remediate (MTTR)

Primary product efficacy KPI delivered to enterprise CISOs and network engineering leads.

## SQL Definition

```sql
SELECT
  t.tenant_id,
  t.org_name,
  t.plan_tier,
  AVG(EXTRACT(EPOCH FROM (e.remediated_at - e.detected_at))) AS mttr_seconds
FROM public.policy_drift_events e
JOIN public.tenants t ON e.tenant_id = t.tenant_id
WHERE e.severity IN ('P1', 'P2')
  AND e.remediated_at IS NOT NULL
  AND e.detected_at >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY 1, 2, 3;
```

## Calculation Rules
These rules are read directly from the SQL definition above:
* **Scope:** only `P1` and `P2` events in [policy_drift_events](../tables/policy_drift_events.md). `P3` and `INFO` are excluded.
* **Resolved only:** events with `remediated_at IS NULL` are excluded, so an open incident does not affect MTTR until it is closed.
* **Window:** trailing 30 days by `detected_at`, grouped per tenant from [tenants](../tables/tenants.md).
* **Clock:** starts at `detected_at` (ingestion via the [Telemetry Ingestion Webhook](../apis/ingest_telemetry.md)) and stops at `remediated_at`, which is set in Step 3 of the [Critical Drift Remediation Runbook](../runbooks/critical_drift_remediation.md).

## SLA Thresholds & Consequences
* **Benchmark:** each tenant's `sla_mttr_target_sec` in [tenants](../tables/tenants.md). The default is `900` seconds (15 minutes) for `enterprise_plus`.
* **Financial impact:** for `enterprise_plus` tenants, a **calendar month** whose average P1/P2 MTTR exceeds the target triggers one automated credit of 5% of that month's invoice. The credit reduces [Net Revenue Retention (NRR)](./net_revenue_retention.md).
* **Two windows:** the trailing 30-day view above is for dashboards; SLA credits always use the calendar month.
* **Operational guardrail:** the runbook requires on-call to confirm that elapsed time stays below `sla_mttr_target_sec` when closing each P1.

## SLA Credit Query

> **Confirmed rules (2026-10-24).** Credits are computed per calendar month (UTC, by `detected_at`) from the month's average P1/P2 MTTR, with at most one credit per tenant per month. The query runs against the PostgreSQL source tables, because the bundle does not specify how `tenants` reaches BigQuery.

```sql
WITH monthly AS (
  SELECT
    e.tenant_id,
    date_trunc('month', e.detected_at AT TIME ZONE 'UTC') AS billing_month,
    AVG(EXTRACT(EPOCH FROM (e.remediated_at - e.detected_at))) AS mttr_seconds
  FROM public.policy_drift_events e
  WHERE e.severity IN ('P1', 'P2')
    AND e.remediated_at IS NOT NULL
  GROUP BY 1, 2
)
SELECT
  t.tenant_id,
  t.org_name,
  m.billing_month,
  m.mttr_seconds,
  t.sla_mttr_target_sec,
  m.mttr_seconds > t.sla_mttr_target_sec AS sla_breached   -- one 5% credit when true
FROM monthly m
JOIN public.tenants t ON t.tenant_id = m.tenant_id
WHERE t.plan_tier = 'enterprise_plus';
```

## Resolved Decisions
* **2026-10-24: SLA window.** Credits use the calendar billing month, not the trailing 30 days. The 30-day view remains for dashboards.
* **2026-10-24: Breach basis.** A breach is the month's *average* MTTR exceeding `sla_mttr_target_sec`, not individual incidents. This allows at most one 5% credit per tenant per month.
