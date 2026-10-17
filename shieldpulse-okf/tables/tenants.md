---
type: table
title: "tenants"
description: "Master registry of enterprise customer organizations, subscription tiers, MRR, and SLA targets."
resource: "postgresql://prod-db.shieldpulse.internal:5432/core/public.tenants"
owners: ["data-eng@shieldpulse.io", "revops@shieldpulse.io"]
tags: ["database", "postgresql", "billing", "core", "multi-tenancy"]
timestamp: "2026-10-17T08:35:00Z"
---

# Table: `public.tenants`

Stores one row per subscribed enterprise organization. Every operational table in the platform joins back to `tenants.tenant_id` to enforce the [Tenant Data Isolation Policy](../policies/tenant_isolation_soc2.md).

## Schema

| Column | Type | Nullable | Description |
|---|---|---|---|
| `tenant_id` | `UUID` | No | Primary key. Immutable organization identifier. |
| `org_name` | `VARCHAR(120)` | No | Legal enterprise customer name. |
| `plan_tier` | `VARCHAR(32)` | No | Subscription tier: `growth`, `business`, or `enterprise_plus`. |
| `mrr_inr` | `NUMERIC(12,2)` | No | Contracted Monthly Recurring Revenue in INR. |
| `sla_mttr_target_sec` | `INTEGER` | No | Maximum contracted drift remediation window in seconds (default `900` for `enterprise_plus`). |
| `webhook_secret_arn` | `TEXT` | No | KMS ARN storing the tenant's HMAC secret for [Telemetry Ingestion Webhook](../apis/ingest_telemetry.md). |
| `status` | `VARCHAR(20)` | No | Account lifecycle state: `ACTIVE`, `PAST_DUE`, `CHURNED`. |
| `created_at` | `TIMESTAMPTZ` | No | Account provisioning timestamp (UTC). |

## Relationships & Joins
* **Downstream Drift Telemetry:** Joined one-to-many with [policy_drift_events](./policy_drift_events.md) on `tenants.tenant_id = policy_drift_events.tenant_id`.
* **Financial Metrics:** Feeds directly into [Net Revenue Retention (NRR)](../metrics/net_revenue_retention.md) via `mrr_inr` and `status`.
* **Operational SLAs:** `sla_mttr_target_sec` serves as the threshold benchmark for [Mean Time to Remediate (MTTR)](../metrics/mean_time_to_remediate.md).
