---
type: table
title: "remediation_jobs"
description: "Work queue and audit trail for the P1 remediation runbook: one row per drift event that triggers it, tracked from queueing to resolution."
resource: "postgresql://prod-db.shieldpulse.internal:5432/core/public.remediation_jobs"
owners: ["secops-eng@shieldpulse.io", "platform-eng@shieldpulse.io"]
tags: ["database", "postgresql", "remediation", "queue", "audit", "draft"]
timestamp: "2026-10-24T09:50:00Z"
status: "draft"
---

# Table: `public.remediation_jobs`

> **Draft (2026-10-24).** Introduced by the reference service to run the [Critical Drift Remediation Runbook](../runbooks/critical_drift_remediation.md). The `resource` host follows the convention of the other tables. Confirm before treating it as canonical.

One row is created, in the same transaction as the event, for every [policy_drift_events](./policy_drift_events.md) row with `severity = 'P1'` or `blast_radius_score >= 80`. Remediation workers claim rows with `FOR UPDATE SKIP LOCKED`, so several can run in parallel.

## Schema

| Column | Type | Nullable | Description |
|---|---|---|---|
| `job_id` | `UUID` | No | Primary key. |
| `tenant_id` | `UUID` | No | Foreign key referencing [tenants](./tenants.md). |
| `drift_id`, `detected_at` | `UUID`, `TIMESTAMPTZ` | No | Composite foreign key to [policy_drift_events](./policy_drift_events.md). Unique: one job per event. |
| `state` | `VARCHAR(24)` | No | `PENDING`, `AWAITING_APPROVAL`, `APPROVED`, `DISPATCHED`, `REMEDIATED`, `REJECTED`, `SKIPPED`, `FAILED`. |
| `attempts` | `INTEGER` | No | Failed dispatch or convergence checks in the current state. |
| `run_after` | `TIMESTAMPTZ` | No | Earliest time a worker may act next (e.g. 60s after dispatch). |
| `sla_met` | `BOOLEAN` | Yes | Set on `REMEDIATED`: elapsed time was within `sla_mttr_target_sec`. |
| `last_error` | `TEXT` | Yes | Reason for the latest retry, skip, or failure. |
| `decided_by` | `UUID` | Yes | **Draft (2026-10-24).** The [tenant_users](./tenant_users.md) member who approved or rejected; `NULL` for automatic runs and signed-link decisions. |
| `decided_at` | `TIMESTAMPTZ` | Yes | **Draft (2026-10-24).** When the approval decision was made. |
| `decided_via` | `VARCHAR(16)` | Yes | **Draft (2026-10-24).** `dashboard` (signed-in user) or `link` (signed approval link). |
| `created_at`, `updated_at` | `TIMESTAMPTZ` | No | Audit timestamps. |

## State Machine

* `PENDING` → `SKIPPED` when the tenant `status` is not `ACTIVE` (runbook Step 1).
* `PENDING` → `DISPATCHED` when `remediation_mode = 'AUTO'`, or → `AWAITING_APPROVAL` when it is `MANUAL_APPROVAL` (Step 2).
* `AWAITING_APPROVAL` → `APPROVED` or `REJECTED` through the signed approval link.
* `APPROVED` → `DISPATCHED`, after re-checking that the tenant is `ACTIVE`.
* `DISPATCHED` → `REMEDIATED` once the rule is confirmed removed, which sets `remediated_at` and feeds [MTTR](../metrics/mean_time_to_remediate.md) (Step 3). Otherwise it stays `DISPATCHED` and retries, then becomes `FAILED`.

## Access & Isolation
Per the [Tenant Data Isolation Policy](../policies/tenant_isolation_soc2.md), `FORCE ROW LEVEL SECURITY` applies:
* **API role:** sees only the current tenant's jobs.
* **Worker role:** a queue-wide policy lets it claim any tenant's job. It then reads [tenants](./tenants.md) and [policy_drift_events](./policy_drift_events.md) only within that job's `tenant_id` context.
