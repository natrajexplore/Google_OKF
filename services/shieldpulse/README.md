# ShieldPulse Service — Phase 1

A reference implementation of the ingestion side of the [ShieldPulse Control Plane](../../shieldpulse-okf/architecture/control_plane.md): an HMAC-authenticated FastAPI webhook that scores configuration drift and records it in PostgreSQL. **Row-level security** enforces tenant isolation.

| Phase | Scope | Status |
|---|---|---|
| **1** | Ingestion webhook, drift scoring, tenant isolation, MTTR | ✅ This package |
| 2 | Remediation runbook: AUTO rollback, approval links, convergence check, `remediated_at` | Planned |
| 3 | NRR (needs MRR history in the schema) and BigQuery analytics | Planned |

## What's Implemented — and Where It Comes From

Every behavior traces to a bundle concept. Where the bundle is silent, the code is marked **DRAFT** and kept behind a small interface so it can be replaced.

| Behavior | Code | Source |
|---|---|---|
| `tenants` and `policy_drift_events` schema, monthly partitioning by `detected_at` | [`db/schema.sql`](db/schema.sql) | [tenants](../../shieldpulse-okf/tables/tenants.md), [policy_drift_events](../../shieldpulse-okf/tables/policy_drift_events.md) |
| `FORCE ROW LEVEL SECURITY`, with `app.current_tenant_id` set on every checkout | [`db/schema.sql`](db/schema.sql), [`db.py`](src/shieldpulse/db.py) | [isolation policy](../../shieldpulse-okf/policies/tenant_isolation_soc2.md) |
| `X-Tenant-ID` plus HMAC-SHA256 over the raw body, compared in constant time | [`app.py`](src/shieldpulse/app.py) | [ingest_telemetry](../../shieldpulse-okf/apis/ingest_telemetry.md) |
| Rate limits: 500/min for `growth`, 5,000/min for `enterprise_plus` | [`ratelimit.py`](src/shieldpulse/ratelimit.py) | ingest_telemetry |
| Runbook trigger: `P1` or `blast_radius_score >= 80` | [`scoring.py`](src/shieldpulse/scoring.py) | [runbook](../../shieldpulse-okf/runbooks/critical_drift_remediation.md) |
| MTTR: P1/P2, resolved, trailing 30 days; credits apply to `enterprise_plus` only | [`app.py`](src/shieldpulse/app.py) | [MTTR](../../shieldpulse-okf/metrics/mean_time_to_remediate.md), [NRR](../../shieldpulse-okf/metrics/net_revenue_retention.md) |
| **DRAFT:** response codes 202 / 400 / 401 / 429 | `app.py` | Draft section of ingest_telemetry |
| **DRAFT:** severity and score rules (below) | `scoring.py` | Inferred from the runbook's P1 example |
| **DRAFT:** `remediation_mode` always `MANUAL_APPROVAL` | `scoring.py` | `tenants` has no remediation-preference column |
| **DRAFT:** `business` tier limited to 500/min | `ratelimit.py` | Not specified in the bundle |
| **DRAFT:** `GET /v1/metrics/mttr` endpoint | `app.py` | Not in the bundle |
| **DRAFT:** local JSON secret store in place of KMS | [`secret_store.py`](src/shieldpulse/secret_store.py) | KMS integration not built yet |

### Draft Scoring Rules

The bundle has no golden-state store yet, so every reported `diff_summary` is treated as drift.

| Rule change | Severity | Score | Triggers runbook |
|---|---|---|---|
| `ALLOW` from an untrusted zone (`UNTRUST`, `INTERNET`, `WAN`, `0.0.0.0/0`) to `22/tcp` or `3389/tcp` | P1 | 95 | Yes |
| `ALLOW` from an untrusted zone to any other port | P2 | 60 | No |
| `ALLOW` from a trusted zone | P3 | 25 | No |
| Anything other than `ALLOW` | INFO | 5 | No |

## Run It Locally

Requirements: Docker, plus `uv sync --all-packages` from the repo root.

```bash
cd services/shieldpulse
docker compose up -d --wait        # Postgres on :55432 with the schema, app role, and two demo tenants

SHIELDPULSE_DATABASE_URL="postgresql://shieldpulse_app:shieldpulse_app_dev@localhost:55432/shieldpulse" \
SHIELDPULSE_LOCAL_SECRETS="dev/local-secrets.json" \
uv run uvicorn --factory shieldpulse.app:create_app_from_env --port 8000
```

Interactive API docs are served at <http://localhost:8000/docs>.

### Send a Signed Snapshot

```bash
BODY='{"device_hostname":"chennai-dc-fw01.corp.internal","vendor_type":"palo_alto_panos","snapshot_timestamp":"2026-10-17T08:15:00Z","diff_summary":{"rule_name":"ALLOW-WAN-SSH-TEMP","source_zone":"UNTRUST-ISP1","destination_port":"22/tcp","action":"ALLOW"}}'
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "dev-acme-webhook-secret" | sed 's/^.*= //')

curl -X POST http://localhost:8000/v1/telemetry/drift-snapshot \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: 11111111-1111-1111-1111-111111111111" \
  -H "X-ShieldPulse-Signature: $SIG" \
  --data-binary "$BODY"
```

```json
{"accepted": true, "drift_events": [{"drift_id": "…", "detected_at": "…", "severity": "P1",
  "blast_radius_score": 95, "remediation_mode": "MANUAL_APPROVAL", "triggers_runbook": true}]}
```

Sign the **exact bytes** you send. Re-serializing the JSON (for example, pretty-printing it) changes the bytes, and the request is rejected with `401`.

| Demo tenant | `X-Tenant-ID` | Tier | Secret |
|---|---|---|---|
| Acme Networks | `11111111-1111-1111-1111-111111111111` | `enterprise_plus` | `dev-acme-webhook-secret` |
| Globex Retail | `22222222-2222-2222-2222-222222222222` | `growth` | `dev-globex-webhook-secret` |

## API

| Method & path | Auth | Responses |
|---|---|---|
| `POST /v1/telemetry/drift-snapshot` | `X-Tenant-ID` + `X-ShieldPulse-Signature` | `202` with recorded events · `400` invalid payload · `401` unknown tenant or bad signature (deliberately indistinguishable) · `429` with `Retry-After` |
| `GET /v1/metrics/mttr` *(draft)* | Same headers, signature over the empty body | Trailing 30-day MTTR, `sla_breached`, `sla_credit_eligible` |
| `GET /healthz` | None | `{"status": "ok"}` |

Checks run in this order: **tenant lookup → signature → rate limit → payload parsing**. Unauthenticated input is never parsed.

## Tenant Isolation Design

- **The app connects as `shieldpulse_app`, which is neither superuser nor `BYPASSRLS`.** Superusers bypass RLS even when it is FORCEd, so this role separation is what makes the policy meaningful. A test fails if the app role ever gains those privileges.
- **Every transaction sets its tenant first,** using `set_config('app.current_tenant_id', …, true)`, the parameterized form of `SET LOCAL`. The setting expires at commit, so a pooled connection can't carry one tenant's context into the next checkout. A test covers this.
- **The tenant lookup itself is RLS-scoped:** the server sets the context to the claimed `X-Tenant-ID` before reading `tenants`.
- **Grants are on the partitioned parent table only,** so every read and write goes through its policy.

## Testing

```bash
docker compose up -d --wait                         # from services/shieldpulse
uv run pytest -v services/shieldpulse/tests         # from the repo root
```

Each test session creates a throwaway database (`shieldpulse_test_<random>`), applies the schema and app role, and drops it afterwards. The tests cover:

- **Scoring and rate limiting:** unit tests, no database needed
- **Ingestion:** the happy path, auth failures, raw-byte signatures, `400` only after successful auth, `429` per tenant, and the MTTR maths
- **RLS:** each tenant sees only its own rows, no context means no rows, cross-tenant writes and moves are rejected, and no context leaks between pooled connections

Without a reachable database, the database tests **skip**. CI sets `SHIELDPULSE_REQUIRE_DB=1` so they **fail** instead. Set `SHIELDPULSE_TEST_ADMIN_URL` to use a server other than `localhost:55432`.

## Known Limitations

- **The primary key is `(drift_id, detected_at)`, not `drift_id` alone.** PostgreSQL requires the partition key in the primary key. Only a `DEFAULT` partition exists; create monthly partitions with ops tooling such as pg_partman.
- **Rate limits are per process,** held in memory. Multiple replicas need a shared store such as Redis.
- **Unauthenticated traffic is not rate limited,** because limits are keyed by authenticated tenant. Edge protection (WAF or API gateway) is expected in front of the service.
- **`tenants.status` is not enforced at ingestion.** The runbook checks for `ACTIVE` before remediation, which is Phase 2.
- **Dev credentials** (`postgres` / `shieldpulse_app_dev`, the demo secrets) are for local use only.
