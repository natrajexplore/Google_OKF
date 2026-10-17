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
* **Rate Limit:** 500 requests/minute for `growth`, 5,000 requests/minute for `enterprise_plus`.

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
