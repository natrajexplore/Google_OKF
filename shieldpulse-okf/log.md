# Knowledge Bundle Change Log

Chronological audit trail of schema, metric, and operational updates across the ShieldPulse OKF bundle.

## 2026-10-17
* **Drafted Control Plane Architecture:** Reconstructed [control_plane.md](./architecture/control_plane.md) from existing concepts (status `draft`, open questions listed). Bundle files relocated under the bundle root and `runbook/` renamed to `runbooks/` to match [index.md](./index.md).
* **Added SLA Credit Adjustment to NRR:** Updated [net_revenue_retention.md](./metrics/net_revenue_retention.md) to subtract automated SLA penalty credits triggered when [mean_time_to_remediate.md](./metrics/mean_time_to_remediate.md) exceeds 15 minutes for `enterprise_plus` tier customers in [tenants.md](./tables/tenants.md).
* **Updated P1 Runbook for Auto-Rollback:** Modified [critical_drift_remediation.md](./runbooks/critical_drift_remediation.md) to require HMAC signature verification from [ingest_telemetry.md](./apis/ingest_telemetry.md) before dispatching an automated webhook rollback.

## 2026-10-02
* **Schema Migration on Drift Events:** Added `remediation_mode` (`AUTO` vs `MANUAL_APPROVAL`) and `blast_radius_score` columns to [policy_drift_events.md](./tables/policy_drift_events.md).

## 2026-09-15
* **Initial Bundle Release:** Published OKF v0.2 baseline covering [control_plane.md](./architecture/control_plane.md), core tables, and [tenant_isolation_soc2.md](./policies/tenant_isolation_soc2.md).
