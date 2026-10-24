---
type: architecture
title: "ShieldPulse Control Plane"
description: "Multi-tenant FastAPI ingestion pipeline, drift evaluation engine, and agentic remediation workflow for firewall, SD-WAN, and cloud security group drift."
resource: "https://github.com/natrajexplore/Google_OKF/tree/main/services/shieldpulse"
owners: ["platform-eng@shieldpulse.io", "secops-eng@shieldpulse.io"]
tags: ["architecture", "multi-tenancy", "ingestion", "remediation", "draft"]
timestamp: "2026-10-24T10:00:00Z"
status: "draft"
---

# Architecture: ShieldPulse Control Plane

> **Draft.** Reconstructed from the other concept files in this bundle. Every statement below cites its source concept. Decisions confirmed on 2026-10-24 are listed under [Resolved Questions](#resolved-questions). What remains unspecified is listed under [Open Questions](#open-questions) rather than assumed. The `resource` link points to the reference implementation.

The Control Plane receives configuration telemetry from customer network appliances, detects and scores policy drift, and drives remediation back to the golden configuration, all under strict per-tenant isolation.

## Request Flow

```
Customer appliance / CI pipeline
        │  POST /v1/telemetry/drift-snapshot
        ▼
[1] Ingestion API (FastAPI) ── HMAC + tenant auth, rate limit per plan_tier
        ▼
[2] Drift Evaluation Engine ── severity + blast_radius_score
        ▼
    public.policy_drift_events (PostgreSQL, RLS)
        │  severity = 'P1' OR blast_radius_score >= 80
        ▼
[3] Remediation Workflow ──┬── AUTO: signed REST/NETCONF rollback
                           └── MANUAL_APPROVAL: Slack/PagerDuty approval link
        ▼
[4] Convergence check ── set remediated_at ── MTTR / NRR (BigQuery)
```

## Components

### 1. Ingestion API
* Exposes the [Telemetry Ingestion Webhook](../apis/ingest_telemetry.md) `POST /v1/telemetry/drift-snapshot`, built on FastAPI ([index](../index.md)).
* Authenticates every request with `X-Tenant-ID` (must match `tenant_id` in [tenants](../tables/tenants.md)) and `X-ShieldPulse-Signature`, an HMAC-SHA256 of the raw body using the secret referenced by `webhook_secret_arn`.
* Enforces per-tier rate limits: 500 req/min for `growth`, 2,000 req/min for `business`, and 5,000 req/min for `enterprise_plus`.
* Accepts snapshots from `palo_alto_panos`, `cisco_sdwan`, `fortigate`, and `aws_sg` appliances ([policy_drift_events](../tables/policy_drift_events.md)).

### 2. Drift Evaluation Engine
* Compares incoming snapshots and diffs against the tenant's golden state and writes one row per discrepancy to [policy_drift_events](../tables/policy_drift_events.md).
* Assigns `severity` (`P1`, `P2`, `P3`, `INFO`) and a `blast_radius_score` (0–100) based on exposed subnets and ports, using the rules under [Resolved Questions](#resolved-questions).
* Copies the tenant's `remediation_mode` (`AUTO` or `MANUAL_APPROVAL`, from [tenants](../tables/tenants.md)) onto each event.

### 3. Agentic Remediation Workflow
* Any event with `severity = 'P1'` or `blast_radius_score >= 80` triggers the [Critical Drift Remediation Runbook](../runbooks/critical_drift_remediation.md).
* Re-verifies HMAC integrity and confirms that the tenant `status` is `ACTIVE` before acting ([log](../log.md), 2026-10-17).
* **`AUTO`:** dispatches a signed REST/NETCONF rollback restoring the last-known-good Git commit state on `device_hostname`.
* **`MANUAL_APPROVAL`:** sends an interactive Slack/PagerDuty alert to the tenant's SOC webhook with a one-click signed approval link.
* AI agents may read this OKF bundle, but every runtime MCP tool call must be parameterized with the authenticated `tenant_id` ([Tenant Data Isolation Policy](../policies/tenant_isolation_soc2.md)).

### 4. Convergence & SLA Closure
* Polls the appliance 60 seconds after rollback dispatch. Once the unauthorized rule is gone, sets `remediated_at = NOW()`.
* `remediated_at - detected_at` feeds [MTTR](../metrics/mean_time_to_remediate.md), which is benchmarked against `sla_mttr_target_sec` (default `900` for `enterprise_plus`).
* `enterprise_plus` MTTR breaches generate a 5% invoice credit that reduces [NRR](../metrics/net_revenue_retention.md).

## Data Stores

| Store | Location | Contents |
|---|---|---|
| Operational DB | `postgresql://prod-db.shieldpulse.internal:5432/core` | [tenants](../tables/tenants.md), [policy_drift_events](../tables/policy_drift_events.md) (partitioned monthly by `detected_at`) |
| Analytics | `bigquery://shieldpulse-analytics` | `ops_mart.vw_tenant_mttr`, `finance_mart.vw_nrr_monthly` |
| Secrets | KMS | Per-tenant HMAC secrets (`webhook_secret_arn`) and device credentials |

## Tenant Isolation
These controls come from the [Tenant Data Isolation Policy](../policies/tenant_isolation_soc2.md):
* `FORCE ROW LEVEL SECURITY` on all tenant tables. Every pool checkout runs `SET LOCAL app.current_tenant_id = '<uuid>'` before any query.
* Envelope encryption with a distinct KMS data key per `tenant_id`.
* Agent and MCP runtime calls are scoped to the authenticated `tenant_id`.

## Resolved Questions
These were adopted from the reference implementation (Phases 1–2) and confirmed on 2026-10-24:
* **Ingestion and evaluation** run synchronously in the webhook request. Runbook work is queue-backed: [remediation_jobs](../tables/remediation_jobs.md) in PostgreSQL, claimed by workers with `FOR UPDATE SKIP LOCKED`. The table doubles as the remediation audit trail.
* **Scoring rules:**
  * an `ALLOW` from an untrusted zone (`UNTRUST`, `INTERNET`, `WAN`, `0.0.0.0/0`) to `22/tcp` or `3389/tcp` is `P1`, score 95
  * any other untrusted `ALLOW` is `P2`, score 60
  * a trusted `ALLOW` is `P3`, score 25
  * anything else is `INFO`, score 5
* **Remediation runtime:**
  * A worker process runs the runbook steps, with up to 3 failed dispatch or convergence attempts before `FAILED`.
  * Manual approvals use a signed link valid for 1 hour. It opens a confirmation page, and the decision is a POST.
  * The worker's database role sees the whole queue, but reads tenant data only within each job's `tenant_id` context.
* **Webhook responses** (`202`, `400`, `401`, `429`) are canonical; see [ingest_telemetry](../apis/ingest_telemetry.md).

## Open Questions
Still unspecified. Confirm these before treating this document as canonical:
* How golden state is stored and versioned. The runbook mentions only a "last-known-good Git commit", and the reference implementation simulates device rollback.
* How data moves from PostgreSQL to BigQuery (ETL/CDC tooling and freshness).
* How the Control Plane reaches customer appliances (NETCONF/REST clients, credentials), and which notifier (Slack/PagerDuty) carries approval links.
* SSO for approvals. Dashboard approvals now record the signed-in [tenant_users](../tables/tenant_users.md) member, but sign-in is by password, and signed-link approvals remain anonymous bearer decisions.
* The deployment topology: region(s), runtime, and scaling of API and worker processes.
