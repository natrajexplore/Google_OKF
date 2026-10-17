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
* **Financial impact:** for `enterprise_plus` tenants, an MTTR above target triggers an automated credit of 5% of the monthly invoice. The credit reduces [Net Revenue Retention (NRR)](./net_revenue_retention.md).
* **Operational guardrail:** the runbook requires on-call to confirm that elapsed time stays below `sla_mttr_target_sec` when closing each P1.

## SLA Breach Query

> **Draft section.** This query is derived from the definitions above, not taken from the original specification. It runs against the PostgreSQL source tables, because the bundle does not specify how `tenants` reaches BigQuery.

```sql
WITH mttr AS (
  SELECT
    e.tenant_id,
    AVG(EXTRACT(EPOCH FROM (e.remediated_at - e.detected_at))) AS mttr_seconds
  FROM public.policy_drift_events e
  WHERE e.severity IN ('P1', 'P2')
    AND e.remediated_at IS NOT NULL
    AND e.detected_at >= CURRENT_DATE - INTERVAL '30 days'
  GROUP BY e.tenant_id
)
SELECT
  t.tenant_id,
  t.org_name,
  m.mttr_seconds,
  t.sla_mttr_target_sec,
  m.mttr_seconds > t.sla_mttr_target_sec AS sla_breached
FROM mttr m
JOIN public.tenants t ON t.tenant_id = m.tenant_id
WHERE t.plan_tier = 'enterprise_plus'
  AND t.status = 'ACTIVE';
```

## Open Questions
* The [NRR](./net_revenue_retention.md) credit rule refers to a **monthly** MTTR, but this view uses a **trailing 30-day** window. Which window governs SLA credits?
* Is a breach judged on the average MTTR, or per incident? "Each breach deducts 5%" could mean either.
