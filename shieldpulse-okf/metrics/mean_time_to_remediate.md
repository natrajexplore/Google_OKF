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
