---
type: runbook
title: "P1 Critical Security Drift Remediation Playbook"
description: "Standard operating procedure for automated and human-in-the-loop rollback of high-blast-radius firewall and WAN policy drift."
resource: "https://ops.shieldpulse.io/runbooks/p1-drift"
owners: ["secops-eng@shieldpulse.io", "oncall@shieldpulse.io"]
tags: ["runbook", "incident-response", "p1", "automation"]
timestamp: "2026-10-17T09:05:00Z"
---

# Runbook: P1 Critical Security Drift Remediation

Triggered automatically when a new row in [policy_drift_events](../tables/policy_drift_events.md) has `severity = 'P1'` or `blast_radius_score >= 80` (for example, `0.0.0.0/0` ingress opened on management ports `22/tcp` or `3389/tcp`, or an unauthorized BGP/IPsec tunnel peer modification).

## Execution Steps

### Step 1: Verify Telemetry Integrity
Confirm that the triggering payload from [Telemetry Ingestion Webhook](../apis/ingest_telemetry.md) passed HMAC verification and that the tenant `status` in [tenants](../tables/tenants.md) is `ACTIVE`.

### Step 2: Check Tenant Remediation Mode
Inspect `remediation_mode` on the event in [policy_drift_events](../tables/policy_drift_events.md):
* **If `AUTO`:** The [Control Plane](../architecture/control_plane.md) immediately dispatches a signed REST/NETCONF rollback payload to restore the last-known-good Git commit state on `device_hostname`.
* **If `MANUAL_APPROVAL`:** Dispatch an interactive Slack/PagerDuty alert to the tenant's SOC webhook with a one-click signed approval link.

### Step 3: Verify Convergence & Close SLA Timer
1. Poll the appliance state 60 seconds after rollback dispatch.
2. Once the unauthorized rule is confirmed removed, update `remediated_at = NOW()` in [policy_drift_events](../tables/policy_drift_events.md).
3. Verify that the total elapsed duration remains below `sla_mttr_target_sec` to protect [Mean Time to Remediate (MTTR)](../metrics/mean_time_to_remediate.md) and [Net Revenue Retention (NRR)](../metrics/net_revenue_retention.md).

