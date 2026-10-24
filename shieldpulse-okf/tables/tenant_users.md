---
type: table
title: "tenant_users"
description: "People who sign in to the tenant dashboard, scoped to one tenant each; used to attribute remediation approvals."
resource: "postgresql://prod-db.shieldpulse.internal:5432/core/public.tenant_users"
owners: ["platform-eng@shieldpulse.io", "security@shieldpulse.io"]
tags: ["database", "postgresql", "auth", "dashboard", "draft"]
timestamp: "2026-10-24T12:00:00Z"
status: "draft"
---

# Table: `public.tenant_users`

> **Draft (2026-10-24).** Introduced by the reference service's tenant dashboard. Password login is an interim step; SSO is expected to replace it.

Each row is one dashboard user belonging to exactly one tenant in [tenants](./tenants.md). Users approve or reject rollbacks for their own tenant. Their identity is recorded on [remediation_jobs](./remediation_jobs.md) as `decided_by`.

## Schema

| Column | Type | Nullable | Description |
|---|---|---|---|
| `user_id` | `UUID` | No | Primary key. |
| `tenant_id` | `UUID` | No | Foreign key referencing [tenants](./tenants.md). |
| `email` | `TEXT` | No | Sign-in email, unique case-insensitively. |
| `display_name` | `VARCHAR(120)` | No | Name shown in the dashboard and audit trail. |
| `password_hash` | `TEXT` | No | scrypt hash (`scrypt$N$r$p$salt$hash`); never stored or logged in plain text. |
| `created_at` | `TIMESTAMPTZ` | No | Provisioning timestamp (UTC). |

## Access & Isolation
Per the [Tenant Data Isolation Policy](../policies/tenant_isolation_soc2.md):
* `FORCE ROW LEVEL SECURITY` limits every reader to the current `tenant_id` context.
* Sign-in happens before the tenant is known, so the narrow function `dashboard_login_lookup(email)` returns only the single matching row. It runs as a dedicated `NOLOGIN` role whose policy is the only cross-tenant read path.
