# Google OKF — ShieldPulse Knowledge Bundle & MCP Server

[![CI](https://github.com/natrajexplore/Google_OKF/actions/workflows/ci.yml/badge.svg)](https://github.com/natrajexplore/Google_OKF/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)
[![MCP SDK 2.x](https://img.shields.io/badge/MCP%20SDK-2.x-6E56CF.svg)](https://modelcontextprotocol.io)
[![OKF v0.2](https://img.shields.io/badge/OKF-v0.2-2EA44F.svg)](shieldpulse-okf/index.md)

**Domain knowledge that AI agents can navigate, validate, and trust.**

This repository packages the operating knowledge of **ShieldPulse**, a multi-tenant B2B MicroSaaS that detects, scores, and remediates unauthorized firewall, SD-WAN, and cloud security-group drift. The knowledge is a version-controlled OKF bundle and is served to AI agents through a **read-only Model Context Protocol (MCP) server**.

## Contents

- [Why This Exists](#why-this-exists)
- [Key Features](#key-features)
- [The Knowledge Bundle](#the-knowledge-bundle)
- [Quick Start](#quick-start)
- [MCP Server](#mcp-server)
- [Contributing](#contributing)
- [Troubleshooting](#troubleshooting)
- [Project Layout](#project-layout) · [Roadmap](#roadmap) · [License](#license)

## Why This Exists

Agents answering questions about a production SaaS (for example, *"Which tenants breached their remediation SLA, and what does that cost us in NRR?"*) need more than raw schemas. They need to know how tables, APIs, metrics, policies, and runbooks relate, and which facts changed recently. Wikis and tribal knowledge don't provide that in a form an agent can traverse. This project does:

1. **Knowledge as code.** Each concept is a Markdown file with typed frontmatter, reviewed in pull requests and recorded in a change log.
2. **Validated in CI.** Every push and pull request runs a conformance check that catches missing types, broken links, and malformed content, plus the test suite.
3. **Served to agents safely.** The MCP server is read-only and confined to the bundle, and it carries no tenant data.

## Key Features

- **8 linked concepts** across architecture, data model, APIs, metrics, governance, and operations
- **Graph traversal** with outgoing links and backlinks, so agents can follow a question across domains
- **Change awareness:** `recent_changes` exposes `log.md`, so agents can check for breaking schema changes before relying on a schema
- **Transparent provenance:** inferred content is labeled **Draft**, and unresolved points are listed as Open Questions
- **Portable:** works with Claude Code, Claude Desktop, or any MCP client over stdio

## At a Glance

The repo contains three parts:

| Part | Path | Purpose |
|---|---|---|
| Knowledge bundle | [`shieldpulse-okf/`](shieldpulse-okf/index.md) | OKF v0.2 concept files covering schemas, APIs, metrics, policies, and runbooks |
| Validator | [`validate-okf.sh`](validate-okf.sh) | CI-ready conformance check for frontmatter, code fences, and links |
| MCP server | [`src/google_okf/`](src/google_okf/) | Six read-only tools for agents to traverse the bundle |
| Service (Phase 1) | [`services/shieldpulse/`](services/shieldpulse/README.md) | FastAPI webhook with HMAC auth, drift scoring, and PostgreSQL row-level security |

---

## The Knowledge Bundle

An OKF bundle is a directory of Markdown files. Each file is one **concept**: YAML frontmatter that describes it, followed by a Markdown body that links to related concepts with relative links. Two filenames are reserved:

* **`index.md`** is the entry point. Its frontmatter lists every concept (`entries`), and its body tells agents how to traverse the bundle.
* **`log.md`** is a chronological change log. Agents should check it before relying on a schema.

### Concept Map

| Domain | Concept | Type | What it defines |
|---|---|---|---|
| Architecture | [Control Plane](shieldpulse-okf/architecture/control_plane.md) | `architecture` | Ingestion → drift evaluation → remediation pipeline *(draft)* |
| Data model | [tenants](shieldpulse-okf/tables/tenants.md) | `table` | Customers, plan tiers, MRR, SLA targets, webhook secrets |
| Data model | [policy_drift_events](shieldpulse-okf/tables/policy_drift_events.md) | `table` | Drift incidents, severity, blast radius, remediation timestamps |
| APIs | [Telemetry Ingestion Webhook](shieldpulse-okf/apis/ingest_telemetry.md) | `api` | `POST /v1/telemetry/drift-snapshot`, HMAC-authenticated |
| Metrics | [Net Revenue Retention](shieldpulse-okf/metrics/net_revenue_retention.md) | `metric` | NRR net of churn and SLA penalty credits |
| Metrics | [Mean Time to Remediate](shieldpulse-okf/metrics/mean_time_to_remediate.md) | `metric` | P1/P2 detection-to-resolution time vs. SLA |
| Governance | [Tenant Isolation (SOC2)](shieldpulse-okf/policies/tenant_isolation_soc2.md) | `policy` | Row-level security, per-tenant KMS keys, agent context scoping |
| Operations | [Critical Drift Remediation](shieldpulse-okf/runbooks/critical_drift_remediation.md) | `runbook` | P1 auto-rollback and human-in-the-loop playbook |

### How the Concepts Relate

```mermaid
flowchart LR
    API["ingest_telemetry<br/>(api)"] -->|routes snapshots to| CP["control_plane<br/>(architecture)"]
    CP -->|writes| PDE["policy_drift_events<br/>(table)"]
    TEN["tenants<br/>(table)"] -->|1 : many| PDE
    TEN -->|webhook_secret_arn| API
    PDE -->|"P1 or blast_radius ≥ 80"| RB["critical_drift_remediation<br/>(runbook)"]
    RB -->|sets remediated_at| PDE
    PDE -->|detected → remediated| MTTR["mean_time_to_remediate<br/>(metric)"]
    TEN -->|sla_mttr_target_sec| MTTR
    MTTR -->|SLA breach credits| NRR["net_revenue_retention<br/>(metric)"]
    TEN -->|mrr_inr, status| NRR
    POL["tenant_isolation_soc2<br/>(policy)"] -.->|RLS + KMS| TEN
    POL -.->|RLS| PDE
    POL -.->|tenant-scoped tool calls| RB
```

This diagram shows the main relationships only. The bundle has more than 40 cross-links; use the `get_links` MCP tool to see all of them.

### Frontmatter Conventions

```yaml
---
type: table                  # required: architecture | table | api | metric | policy | runbook
title: "tenants"
description: "One-line summary used by agents to decide relevance."
resource: "postgresql://…"   # where the real thing lives
owners: ["data-eng@shieldpulse.io"]
tags: ["database", "billing"]
timestamp: "2026-10-17T08:35:00Z"
---
```

When you change a concept, add a dated entry to [`log.md`](shieldpulse-okf/log.md).

### Draft Content

Some content was reconstructed or inferred, because the original files were empty or cut off. It is marked in place, and you should confirm it before treating it as canonical:

* [`control_plane.md`](shieldpulse-okf/architecture/control_plane.md) has `status: "draft"`. It was reconstructed from the other concepts, and its open questions are listed at the end. Its `resource` URL is a placeholder.
* [`ingest_telemetry.md`](shieldpulse-okf/apis/ingest_telemetry.md): the **Responses** and **Security Notes** sections are drafts.
* [`mean_time_to_remediate.md`](shieldpulse-okf/metrics/mean_time_to_remediate.md): the **SLA Breach Query** is a draft. **Open Questions** flags a conflict between a monthly and a trailing 30-day SLA window.

---

## Quick Start

Requirements: Python ≥ 3.11 and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/natrajexplore/Google_OKF.git
cd Google_OKF
uv sync --all-packages       # install the MCP server, the ShieldPulse service, and dev tools

bash validate-okf.sh         # validate the bundle
uv run pytest -q             # run the tests
```

### Validate the Bundle

```bash
bash validate-okf.sh [BUNDLE_DIR]   # default: ./shieldpulse-okf
```

| Check | Fails when |
|---|---|
| Root entry point | `index.md` is missing |
| Concept typing | A concept file (anything except `index.md`/`log.md`) has no `type:` in its frontmatter |
| Code fences | A file has an unclosed code block |
| Links | A relative link points to a file that does not exist (`#anchors` are stripped; `https:`/`mailto:` links are skipped) |

The script exits `1` on any failure. [CI](.github/workflows/ci.yml) runs it, and then `pytest`, on Ubuntu and Windows for every push to `main` and every pull request. `.gitattributes` pins `*.sh` to LF line endings so the script runs on Windows checkouts too.

---

## MCP Server

The server exposes the bundle to agents through six **read-only** tools. It re-reads the bundle on every call, so edits are visible without a restart. Paths are confined to the bundle directory.

| Tool | Arguments | Returns |
|---|---|---|
| `get_index` | — | Bundle title, description, `okf_version`, index entries with summaries, and the traversal guide |
| `list_concepts` | `type?` | Path, type, title, and description for each concept, optionally filtered by type (e.g. `metric`) |
| `read_concept` | `path` | Full frontmatter and Markdown body |
| `get_links` | `path` | Outgoing links and backlinks |
| `search` | `query`, `limit?` | Keyword matches (every term must match); title, description, and tag hits rank higher |
| `recent_changes` | `since?` (`YYYY-MM-DD`) | `log.md` entries, newest first |

Recommended agent flow, which the server also sends as its instructions: **`get_index` → `read_concept` / `get_links` → `recent_changes` before relying on a schema.**

```mermaid
sequenceDiagram
    participant U as User
    participant A as AI Agent
    participant S as okf-bundle MCP server
    participant B as shieldpulse-okf/
    U->>A: "How is an MTTR SLA breach priced?"
    A->>S: get_index()
    S->>B: read index.md
    S-->>A: domain map + traversal guide
    A->>S: read_concept("metrics/mean_time_to_remediate.md")
    S-->>A: SQL definition, SLA rules
    A->>S: get_links(...) → read_concept("metrics/net_revenue_retention.md")
    S-->>A: 5% credit rule, NRR formula
    A->>S: recent_changes(since="2026-10-01")
    S-->>A: SLA credit adjustment added 2026-10-17
    A-->>U: Grounded answer citing bundle paths
```

### Run It

```bash
uv run google-okf [BUNDLE_DIR]      # stdio transport
```

The server looks for the bundle in this order: the CLI argument, then `$OKF_BUNDLE_DIR`, then `./shieldpulse-okf`.

### Add to Claude Code

```bash
claude mcp add okf-bundle -- uv run --directory /path/to/Google_OKF google-okf /path/to/Google_OKF/shieldpulse-okf
claude mcp get okf-bundle           # should report: ✔ Connected
```

The tools then appear as `mcp__okf-bundle__*`. To use the server in Claude Desktop or another MCP client, register the same `uv run …` command as a stdio server.

### Example

Asking *"Which concepts depend on the tenants table?"* leads an agent to call `get_links`:

```json
{
  "path": "tables/tenants.md",
  "outgoing": ["policies/tenant_isolation_soc2.md", "apis/ingest_telemetry.md", "tables/policy_drift_events.md",
               "metrics/net_revenue_retention.md", "metrics/mean_time_to_remediate.md"],
  "backlinks": ["apis/ingest_telemetry.md", "architecture/control_plane.md", "metrics/mean_time_to_remediate.md",
                "metrics/net_revenue_retention.md", "policies/tenant_isolation_soc2.md",
                "runbooks/critical_drift_remediation.md", "tables/policy_drift_events.md"]
}
```

### Security Model

The bundle contains **structural knowledge only**: no tenant data, credentials, or live connections. This follows the bundle's own [isolation policy](shieldpulse-okf/policies/tenant_isolation_soc2.md): agents may read the bundle freely, but any live query they build from it must be scoped to the authenticated `tenant_id`. Every tool is annotated `readOnlyHint`. Unknown or out-of-bundle paths (for example `../pyproject.toml`) return a tool error.

> Built on the MCP Python SDK **2.x** (`mcp.server.mcpserver.MCPServer`). In 2.x, the 1.x `FastMCP` class was renamed, so most older online examples won't match this code.

---

## Project Layout

```
.
├── shieldpulse-okf/            # the OKF knowledge bundle
│   ├── index.md                #   entry point (reserved)
│   ├── log.md                  #   change log (reserved)
│   ├── architecture/  apis/  metrics/  policies/  runbooks/  tables/
├── src/google_okf/
│   ├── __init__.py             # main(): runs the MCP server over stdio
│   ├── bundle.py               # loader: frontmatter, links, backlinks, search, log
│   └── server.py               # MCP tool definitions
├── tests/test_bundle.py        # loader, server, and real-bundle integrity tests
├── services/shieldpulse/       # Phase 1 service (uv workspace member), with its own README
│   ├── db/                     #   schema.sql (RLS), dev role and seed scripts
│   ├── src/shieldpulse/        #   app, db, scoring, rate limiting, secret store
│   ├── tests/                  #   unit, ingestion, and RLS isolation tests
│   └── docker-compose.yml      #   local PostgreSQL 17
├── validate-okf.sh             # bundle conformance check
└── pyproject.toml
```

## Contributing

Changes to the bundle follow the same review process as code changes.

**To add or update a concept:**

1. Create or edit a file in the matching domain folder, e.g. `shieldpulse-okf/tables/<name>.md`, with the [frontmatter](#frontmatter-conventions) filled in. `type` is required.
2. Link it to related concepts with **relative** Markdown links, e.g. `[tenants](../tables/tenants.md)`.
3. For a new concept, add its path to `entries` in `index.md` and to the matching section of the index body.
4. Add a dated entry to `log.md` describing the change. Call out breaking schema changes explicitly.
5. Label anything inferred rather than sourced as `> **Draft section.**`.

**Before opening a pull request:**

```bash
bash validate-okf.sh   # must print [PASS]
uv run pytest -q       # includes a real-bundle check that every index entry exists and every link resolves
```

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'mcp.server.fastmcp'` | Code written for MCP SDK 1.x | Use `from mcp.server.mcpserver import MCPServer` (this project targets 2.x) |
| `validate-okf.sh: $'\r': command not found` | Script checked out with CRLF line endings | Fresh clones are fixed by `.gitattributes`; for an older checkout, run `sed -i 's/\r$//' validate-okf.sh` |
| `No OKF bundle at '…' (index.md not found)` | Server started from the wrong directory | Pass the bundle path explicitly: `uv run google-okf /path/to/shieldpulse-okf` |
| MCP tools missing in Claude Code | Server added after the session started | Run `/mcp` to reconnect, or start a new session |
| `Unknown concept '…'` tool error | Path not relative to the bundle root | Use paths exactly as `list_concepts` returns them, e.g. `tables/tenants.md` |

## Roadmap

- [ ] Resolve the open questions in `control_plane.md` and `mean_time_to_remediate.md`, and replace the draft sections with sourced content
- [x] Add a CI workflow that runs `validate-okf.sh` and `pytest` on every push
- [x] ShieldPulse service, Phase 1: ingestion webhook, drift scoring, RLS tenant isolation, MTTR ([details](services/shieldpulse/README.md))
- [ ] Service Phase 2: remediation runbook (AUTO rollback, approval links, convergence, `remediated_at`)
- [ ] Service Phase 3: NRR (needs MRR history) and BigQuery analytics

## License

[MIT](LICENSE) © 2026 Nataraj Angappan
