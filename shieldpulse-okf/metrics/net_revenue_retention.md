---
type: metric
title: "Net Revenue Retention (NRR)"
description: "Percentage of recurring revenue retained from existing enterprise tenants over a trailing 12-month cohort, net of churn and SLA penalty credits."
resource: "bigquery://shieldpulse-analytics.finance_mart.vw_nrr_monthly"
owners: ["revops@shieldpulse.io", "founders@shieldpulse.io"]
tags: ["metric", "kpi", "finance", "saas"]
timestamp: "2026-10-17T08:50:00Z"
---

# Metric: Net Revenue Retention (NRR)

Measures the compounding growth health of ShieldPulse across our existing enterprise customer base.

## Formula

$$\text{NRR} = \frac{\text{Starting MRR} + \text{Expansion MRR} - \text{Contraction MRR} - \text{Churned MRR} - \text{SLA Penalty Credits}}{\text{Starting MRR}} \times 100$$

## Source Data & Lineage
* **Base Revenue:** Aggregated from `mrr_inr` and `status` in [tenants](../tables/tenants.md).
* **SLA Penalty Credits:** Calculated when a tenant on the `enterprise_plus` tier experiences a monthly [Mean Time to Remediate (MTTR)](./mean_time_to_remediate.md) exceeding their contracted `sla_mttr_target_sec` in [tenants](../tables/tenants.md). Each breach deducts 5% of monthly invoice value as an automated credit.

## Target Benchmarks
* **Healthy MicroSaaS Threshold:** Greater than 115% annualized.
* **Alert Trigger:** If trailing 30-day projected NRR drops below 105%, review P1 SLA breaches in [policy_drift_events](../tables/policy_drift_events.md).
