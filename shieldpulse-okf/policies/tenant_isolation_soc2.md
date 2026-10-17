---
type: policy
title: "Multi-Tenant Data Isolation & SOC2 Governance"
description: "Mandatory architectural and database controls preventing cross-tenant data leakage across API, storage, and AI agent layers."
resource: "https://trust.shieldpulse.io/policies/soc2-tenant-isolation"
owners: ["security@shieldpulse.io"]
tags: ["policy", "soc2", "security", "rls", "governance"]
timestamp: "2026-10-17T09:00:00Z"
---

# Policy: Multi-Tenant Data Isolation & SOC2 Governance

Because ShieldPulse processes sensitive enterprise firewall rules and network topologies in the [Control Plane](../architecture/control_plane.md), strict logical and cryptographic isolation is mandatory.

## Mandatory Controls

1. **PostgreSQL Row-Level Security (RLS):** Both [tenants](../tables/tenants.md) and [policy_drift_events](../tables/policy_drift_events.md) enforce `FORCE ROW LEVEL SECURITY`. Every database connection pool checkout must execute `SET LOCAL app.current_tenant_id = '<uuid>'` before running queries.
2. **Per-Tenant Envelope Encryption:** Webhook signing secrets (`webhook_secret_arn` in [tenants](../tables/tenants.md)) and device credentials are encrypted using distinct KMS data keys scoped to each `tenant_id`.
3. **AI Agent Context Scoping:** When an autonomous agent executes the [Critical Drift Remediation Runbook](../runbooks/critical_drift_remediation.md), it may read this global OKF structural bundle, but runtime tool calls (MCP queries) must be strictly parameterized with the authenticated `tenant_id`.

