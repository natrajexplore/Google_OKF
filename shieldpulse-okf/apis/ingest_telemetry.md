---
type: api
title: "POST /v1/telemetry/drift-snapshot"
description: "High-throughput webhook endpoint that ingests configuration state snapshots from enterprise network appliances."
resource: "https://api.shieldpulse.io/v1/telemetry/drift-snapshot"
owners: ["platform-eng@shieldpulse.io"]
tags: ["api", "webhook", "rest", "ingestion"]
timestamp: "2026-10-17T08:45:00Z"
---

# API: Telemetry Ingestion Webhook

Receives real-time configuration diffs or periodic state snapshots from customer edge collectors and CI/CD pipelines, routing them into the [Control Plane](../architecture/control_plane.md).

## Endpoint Specification
* **Method & Path:** `POST /v1/telemetry/drift-snapshot`
* **Authentication:** Requires headers `X-Tenant-ID` (matching `tenant_id` in [tenants](../tables/tenants.md)) and `X-ShieldPulse-Signature` (HMAC-SHA256 hex digest of the raw body signed with the secret at `webhook_secret_arn`).
* **Rate Limit:** 500 requests/minute for `growth`, 2,000 requests/minute for `business` (confirmed 2026-10-24), 5,000 requests/minute for `enterprise_plus`.

## Request Payload Example

```json
{
  "device_hostname": "chennai-dc-fw01.corp.internal",
  "vendor_type": "palo_alto_panos",
  "snapshot_timestamp": "2026-10-17T08:15:00Z",
  "diff_summary": {
    "rule_name": "ALLOW-WAN-SSH-TEMP",
    "source_zone": "UNTRUST-ISP1",
    "destination_port": "22/tcp",
    "action": "ALLOW"
  }
}
```

## Request Fields

| Field | Type | Description |
|---|---|---|
| `device_hostname` | string | Appliance identifier; stored as `device_hostname` (`VARCHAR(128)`) in [policy_drift_events](../tables/policy_drift_events.md). |
| `vendor_type` | string | One of `palo_alto_panos`, `cisco_sdwan`, `fortigate`, `aws_sg`. |
| `snapshot_timestamp` | string (ISO-8601, UTC) | When the appliance captured the configuration state. |
| `diff_summary` | object | Rule-level change: `rule_name`, `source_zone`, `destination_port`, `action`. |

## Processing
1. Headers are authenticated against [tenants](../tables/tenants.md). The HMAC is computed over the **raw** request body with the tenant secret at `webhook_secret_arn`, which is encrypted with a per-tenant KMS key under the [Tenant Data Isolation Policy](../policies/tenant_isolation_soc2.md).
2. The [Control Plane](../architecture/control_plane.md) evaluates the snapshot. Each detected discrepancy becomes a row in [policy_drift_events](../tables/policy_drift_events.md), timestamped by `detected_at` at ingestion.
3. Rows with `severity = 'P1'` or `blast_radius_score >= 80` trigger the [Critical Drift Remediation Runbook](../runbooks/critical_drift_remediation.md), which re-checks this endpoint's HMAC verification before any automated rollback.

## Responses

> **Confirmed 2026-10-24.** Originally inferred from the authentication and rate-limit rules above, and now canonical.

| Status | Meaning |
|---|---|
| `202 Accepted` | Snapshot authenticated and accepted for asynchronous drift evaluation. |
| `400 Bad Request` | Malformed JSON, missing required fields, or unsupported `vendor_type`. |
| `401 Unauthorized` | Missing `X-Tenant-ID`, unknown tenant, or invalid `X-ShieldPulse-Signature`. Unknown tenants are reported the same way as bad signatures, so the response does not reveal whether a tenant exists. |
| `429 Too Many Requests` | Tier rate limit exceeded. Clients should honor `Retry-After`. |

## Security Notes

> **Draft section.** These are implementation recommendations, not sourced requirements.

* Compare signatures in constant time, for example with `hmac.compare_digest`.
* Verify against the exact bytes received, before any JSON parsing or re-serialization.
