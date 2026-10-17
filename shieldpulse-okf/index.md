---
okf_version: "0.2"
title: "ShieldPulse Enterprise MicroSaaS Knowledge Bundle"
description: "Canonical knowledge graph for ShieldPulse's multi-tenant security policy drift platform, covering schemas, APIs, SaaS metrics, compliance policies, and on-call runbooks."
entries:
  - architecture/control_plane.md
  - tables/tenants.md
  - tables/policy_drift_events.md
  - apis/ingest_telemetry.md
  - metrics/net_revenue_retention.md
  - metrics/mean_time_to_remediate.md
  - policies/tenant_isolation_soc2.md
  - runbooks/critical_drift_remediation.md
---

# ShieldPulse Knowledge Graph Index

Welcome to the canonical OKF bundle for **ShieldPulse**, an enterprise B2B MicroSaaS that detects, scores, and remediates unauthorized firewall, SD-WAN, and cloud security group drift in real time.

## How Agents Should Traverse This Bundle
1. Start here to identify the domain relevant to the user or system query.
2. Follow the Markdown links below to inspect specific schemas, formulas, or operational procedures.
3. Check [log.md](./log.md) before executing schema-dependent queries to verify recent breaking changes.

## Domain Directory

### System Architecture
* [Control Plane Architecture](./architecture/control_plane.md) — Multi-tenant FastAPI ingestion pipeline, drift evaluation engine, and agentic remediation workflow.

### Data Model (PostgreSQL & BigQuery)
* [tenants](./tables/tenants.md) — Enterprise customer accounts, ARR tiers, SLA thresholds, and subscription states.
* [policy_drift_events](./tables/policy_drift_events.md) — Time-series records of detected security rule deviations and remediation status.

### APIs & Integrations
* [Telemetry Ingestion Webhook](./apis/ingest_telemetry.md) — Authenticated REST endpoint receiving configuration snapshots from customer appliances.

### Business & Operational Metrics
* [Net Revenue Retention (NRR)](./metrics/net_revenue_retention.md) — Core financial health metric adjusted for SLA breach credits.
* [Mean Time to Remediate (MTTR)](./metrics/mean_time_to_remediate.md) — Core product value metric measuring drift detection-to-resolution speed.

### Governance & Operations
* [Tenant Data Isolation Policy](./policies/tenant_isolation_soc2.md) — SOC2 Type II Row-Level Security (RLS) and cryptographic boundary rules.
* [Critical Drift Remediation Runbook](./runbooks/critical_drift_remediation.md) — Step-by-step P1 response for zero-day port exposures and broken tunnel policies.
