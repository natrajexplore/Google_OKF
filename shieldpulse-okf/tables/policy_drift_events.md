---
type: table
title: "policy_drift_events"
description: "Append-only operational table recording unauthorized network and firewall configuration drift events across tenants."
resource: "postgresql://prod-db.shieldpulse.internal:5432/core/public.policy_drift_events"
owners: ["secops-eng@shieldpulse.io"]
tags: ["database", "postgresql", "security", "drift", "telemetry"]
timestamp: "2026-10-17T08:40:00Z"
---

# Table: `public.policy_drift_events`

Captures every configuration discrepancy identified by the [Control Plane](../architecture/control_plane.md) when a payload arrives at the [Telemetry Ingestion Webhook](../apis/ingest_telemetry.md). Partitioned monthly by `detected_at`.

## Schema

| Column | Type | Nullable | Description |
|---|---|---|---|
| `drift_id` | `UUID` | No | Primary key for the drift incident. |
| `tenant_id` | `UUID` | No | Foreign key referencing [tenants](./tenants.md) (`tenant_id`). |
| `device_hostname` | `VARCHAR(128)` | No | Identifier of the affected firewall, router, or cloud gateway. |
| `vendor_type` | `VARCHAR(40)` | No | Appliance family (`palo_alto_panos`, `cisco_sdwan`, `fortigate`, `aws_sg`). |
| `severity` | `VARCHAR(10)` | No | Incident criticality: `P1`, `P2`, `P3`, `INFO`. |
| `blast_radius_score` | `SMALLINT` | No | Computed risk score from `0` to `100` based on exposed subnets and ports. |
| `remediation_mode` | `VARCHAR(20)` | No | Execution path: `AUTO` or `MANUAL_APPROVAL`. |
| `detected_at` | `TIMESTAMPTZ` | No | UTC timestamp when drift was ingested. |
| `remediated_at` | `TIMESTAMPTZ` | Yes | UTC timestamp when golden state was restored (`NULL` if unresolved). |

## Relationships & Joins
* **Tenant Ownership:** Joins many-to-one with [tenants](./tenants.md) on `tenant_id`.
* **SLA Calculation:** The delta between `remediated_at` and `detected_at` powers [Mean Time to Remediate (MTTR)](../metrics/mean_time_to_remediate.md).
* **Incident Response:** Any row inserted with `severity = 'P1'` or `blast_radius_score >= 80` triggers the [Critical Drift Remediation Runbook](../runbooks/critical_drift_remediation.md).

