# Knowledge Bundle Change Log

Chronological audit trail of schema, metric, and operational updates across the ShieldPulse OKF bundle.

## 2026-10-24
* **Tenant Dashboard (Draft):** Added [tenant_users.md](./tables/tenant_users.md) and the `decided_by`, `decided_at` and `decided_via` columns on [remediation_jobs.md](./tables/remediation_jobs.md), so dashboard approvals record who decided. [control_plane.md](./architecture/control_plane.md) narrows its approver-identity open question to SSO.
* **Confirmed Draft Decisions:**
  * SLA credits use the calendar billing month, with a breach being the month's average MTTR above target (at most one 5% credit per month); see [mean_time_to_remediate.md](./metrics/mean_time_to_remediate.md) and [net_revenue_retention.md](./metrics/net_revenue_retention.md).
  * `business` tier rate limit is 2,000/min, and the webhook response codes are canonical ([ingest_telemetry.md](./apis/ingest_telemetry.md)).
  * Scoring rules, the job queue, a 3-attempt retry budget and 1-hour approval links are adopted, and [control_plane.md](./architecture/control_plane.md) now points to the reference implementation, with its remaining open questions narrowed.
* **Remediation Schema (Draft):** Added `remediation_mode` to [tenants.md](./tables/tenants.md), added `rule_name` and `diff_summary` to [policy_drift_events.md](./tables/policy_drift_events.md), and introduced [remediation_jobs.md](./tables/remediation_jobs.md) as the [runbook](./runbooks/critical_drift_remediation.md) work queue and audit trail. These are additive, nullable or defaulted columns, with no breaking change to existing queries.

## 2026-10-17
* **Enriched Truncated Concepts:** Completed [ingest_telemetry.md](./apis/ingest_telemetry.md) (request fields, processing, draft responses and security notes) and [mean_time_to_remediate.md](./metrics/mean_time_to_remediate.md) (calculation rules, SLA thresholds, draft breach query, open questions). Inferred content is marked **Draft section**.
* **Drafted Control Plane Architecture:** Reconstructed [control_plane.md](./architecture/control_plane.md) from existing concepts (status `draft`, open questions listed). Bundle files relocated under the bundle root and `runbook/` renamed to `runbooks/` to match [index.md](./index.md).
* **Added SLA Credit Adjustment to NRR:** Updated [net_revenue_retention.md](./metrics/net_revenue_retention.md) to subtract automated SLA penalty credits triggered when [mean_time_to_remediate.md](./metrics/mean_time_to_remediate.md) exceeds 15 minutes for `enterprise_plus` tier customers in [tenants.md](./tables/tenants.md).
* **Updated P1 Runbook for Auto-Rollback:** Modified [critical_drift_remediation.md](./runbooks/critical_drift_remediation.md) to require HMAC signature verification from [ingest_telemetry.md](./apis/ingest_telemetry.md) before dispatching an automated webhook rollback.

## 2026-10-02
* **Schema Migration on Drift Events:** Added `remediation_mode` (`AUTO` vs `MANUAL_APPROVAL`) and `blast_radius_score` columns to [policy_drift_events.md](./tables/policy_drift_events.md).

## 2026-09-15
* **Initial Bundle Release:** Published OKF v0.2 baseline covering [control_plane.md](./architecture/control_plane.md), core tables, and [tenant_isolation_soc2.md](./policies/tenant_isolation_soc2.md).
