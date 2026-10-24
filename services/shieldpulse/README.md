# ShieldPulse Service

A reference implementation of the [ShieldPulse Control Plane](../../shieldpulse-okf/architecture/control_plane.md). An HMAC-authenticated FastAPI webhook scores configuration drift and records it in PostgreSQL, and a remediation worker runs the [P1 runbook](../../shieldpulse-okf/runbooks/critical_drift_remediation.md). **Row-level security** enforces tenant isolation throughout.

| Phase | Scope | Status |
|---|---|---|
| **1** | Ingestion webhook, drift scoring, tenant isolation, MTTR | ✅ Done |
| **2** | Remediation runbook: AUTO rollback, signed approval links, convergence check, `remediated_at` | ✅ Done |
| 3 | NRR (needs MRR history in the schema) and BigQuery analytics | Planned |

## What's Implemented — and Where It Comes From

Every behavior traces to a bundle concept. Where the bundle was silent, the code was marked **DRAFT**. Decisions confirmed on 2026-10-24 are marked **Confirmed**, and the rest remain DRAFT behind small interfaces so they can be replaced.

| Behavior | Code | Source |
|---|---|---|
| `tenants` and `policy_drift_events` schema, monthly partitioning by `detected_at` | [`db/schema.sql`](db/schema.sql) | [tenants](../../shieldpulse-okf/tables/tenants.md), [policy_drift_events](../../shieldpulse-okf/tables/policy_drift_events.md) |
| `FORCE ROW LEVEL SECURITY`, with `app.current_tenant_id` set on every checkout | [`db/schema.sql`](db/schema.sql), [`db.py`](src/shieldpulse/db.py) | [isolation policy](../../shieldpulse-okf/policies/tenant_isolation_soc2.md) |
| `X-Tenant-ID` plus HMAC-SHA256 over the raw body, compared in constant time | [`app.py`](src/shieldpulse/app.py) | [ingest_telemetry](../../shieldpulse-okf/apis/ingest_telemetry.md) |
| Rate limits: 500/min for `growth`, 5,000/min for `enterprise_plus` | [`ratelimit.py`](src/shieldpulse/ratelimit.py) | ingest_telemetry |
| Runbook trigger: `P1` or `blast_radius_score >= 80` | [`scoring.py`](src/shieldpulse/scoring.py) | [runbook](../../shieldpulse-okf/runbooks/critical_drift_remediation.md) |
| MTTR: P1/P2, resolved, trailing 30 days; credits apply to `enterprise_plus` only | [`app.py`](src/shieldpulse/app.py) | [MTTR](../../shieldpulse-okf/metrics/mean_time_to_remediate.md), [NRR](../../shieldpulse-okf/metrics/net_revenue_retention.md) |
| **Confirmed:** response codes 202 / 400 / 401 / 429 | `app.py` | ingest_telemetry (confirmed 2026-10-24) |
| **Confirmed:** severity and score rules (below) | `scoring.py` | control_plane, Resolved Questions (2026-10-24) |
| Runbook: tenant must be `ACTIVE`; AUTO dispatches a signed rollback; MANUAL sends a signed approval link; poll 60s after dispatch; set `remediated_at`; check the SLA | [`worker.py`](src/shieldpulse/worker.py), [`remediation.py`](src/shieldpulse/remediation.py) | runbook |
| **DRAFT:** `tenants.remediation_mode` (default `MANUAL_APPROVAL`), `policy_drift_events.rule_name` and `diff_summary`, and the `remediation_jobs` queue | `db/schema.sql` | Recorded in the bundle as draft schema changes ([log](../../shieldpulse-okf/log.md), 2026-10-24) |
| **Confirmed:** 3-attempt retry budget; 1-hour approval link lifetime | `worker.py` | control_plane, Resolved Questions (2026-10-24) |
| **DRAFT:** simulated device and logging notifier in place of NETCONF/REST and Slack/PagerDuty | `remediation.py` | No device or notifier integration yet |
| **Confirmed:** `business` tier limited to 2,000/min | `ratelimit.py` | ingest_telemetry (confirmed 2026-10-24) |
| **Confirmed:** SLA credits use the calendar month's average MTTR, with at most one 5% credit per month | `app.py` | MTTR and NRR concepts (confirmed 2026-10-24) |
| **DRAFT:** `GET /v1/metrics/mttr` endpoint | `app.py` | Not in the bundle |
| **DRAFT:** local JSON secret store in place of KMS | [`secret_store.py`](src/shieldpulse/secret_store.py) | KMS integration not built yet |

### Scoring Rules (Confirmed)

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

Start the remediation worker in a second terminal. It connects as its own database role:

```bash
SHIELDPULSE_WORKER_DATABASE_URL="postgresql://shieldpulse_worker:shieldpulse_worker_dev@localhost:55432/shieldpulse" \
SHIELDPULSE_DISPATCH_KEY="dev-dispatch-key" \
SHIELDPULSE_APPROVAL_KEY="dev-approval-key" \
SHIELDPULSE_PUBLIC_BASE_URL="http://localhost:8000" \
uv run python -m shieldpulse.worker          # add SHIELDPULSE_CONVERGENCE_DELAY_SEC=3 for faster demos
```

Also set `SHIELDPULSE_APPROVAL_KEY` (the same value) on the API server; without it, the approval endpoints are not mounted.

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

| Demo tenant | `X-Tenant-ID` | Tier, mode | Secret |
|---|---|---|---|
| Acme Networks | `11111111-1111-1111-1111-111111111111` | `enterprise_plus`, **AUTO** | `dev-acme-webhook-secret` |
| Globex Retail | `22222222-2222-2222-2222-222222222222` | `growth`, **MANUAL_APPROVAL** | `dev-globex-webhook-secret` |

## API

| Method & path | Auth | Responses |
|---|---|---|
| `POST /v1/telemetry/drift-snapshot` | `X-Tenant-ID` + `X-ShieldPulse-Signature` | `202` with recorded events · `400` invalid payload · `401` unknown tenant or bad signature (deliberately indistinguishable) · `429` with `Retry-After` |
| `GET /v1/metrics/mttr[?month=YYYY-MM]` *(draft endpoint)* | Same headers, signature over the empty body | `trailing_30_days` (dashboard view) and `billing_month` (the month's average, `sla_breached`, `sla_credit_eligible`, `credit_percent`); `400` for a bad `month` |
| `GET /v1/remediation/approve?token=…` | Signed approval token | Confirmation page only; never changes state · `403` bad or expired token · `409` already decided |
| `POST /v1/remediation/approve` | Token and `decision=approve\|reject` (form) | Approves or rejects, exactly once |
| `GET /healthz` | None | `{"status": "ok"}` |

Checks run in this order: **tenant lookup → signature → rate limit → payload parsing**. Unauthenticated input is never parsed.

## Remediation Runbook (Phase 2)

Every event that triggers the runbook gets a `remediation_jobs` row, written in the same transaction as the event, so a P1 is never left without a job. The worker then runs the [runbook](../../shieldpulse-okf/runbooks/critical_drift_remediation.md):

```mermaid
stateDiagram-v2
    [*] --> PENDING
    PENDING --> SKIPPED: tenant not ACTIVE
    PENDING --> DISPATCHED: AUTO, signed rollback sent
    PENDING --> AWAITING_APPROVAL: MANUAL, approval link sent
    AWAITING_APPROVAL --> APPROVED: POST approve
    AWAITING_APPROVAL --> REJECTED: POST reject
    APPROVED --> SKIPPED: tenant no longer ACTIVE
    APPROVED --> DISPATCHED: signed rollback sent
    DISPATCHED --> REMEDIATED: rule gone, remediated_at set
    DISPATCHED --> FAILED: still present after retries
    REMEDIATED --> [*]
```

- **Claiming jobs:** workers claim with `FOR UPDATE SKIP LOCKED`, so several can run in parallel without double-processing a job.
- **Isolation:** the claim reads only the queue. Event and tenant data are read within the job's tenant context. Only the worker role has queue-wide visibility.
- **Signed rollbacks:** each rollback payload is canonical JSON signed with HMAC-SHA256 (`SHIELDPULSE_DISPATCH_KEY`). The simulated device rejects bad signatures.
- **No blind rollbacks:** an event without a `rule_name` is never rolled back, because its convergence could not be verified.
- **Safe approval links:** the link opens a confirmation page, and the approval happens on POST. Email and chat link scanners prefetch URLs, so a one-click GET could approve rollbacks nobody chose.
- **SLA tracking:** `sla_met` on the job records whether `remediated_at - detected_at` stayed within `sla_mttr_target_sec`.

## Tenant Dashboard

A browser UI served by the API itself on **port 8000**: no separate frontend, build step or Node toolchain.

![Dashboard overview, light mode](../../docs/screenshots/dashboard-overview-light.png)
![Remediation page, dark mode](../../docs/screenshots/dashboard-remediation-dark.png)

| Page | What it shows |
|---|---|
| `/app` Overview | Open drift, approvals waiting, 30-day MTTR against target, this month's SLA status, daily MTTR chart, recent drift |
| `/app/events` | All drift events with severity and status filters; each opens a detail page with what changed and a timeline |
| `/app/remediation` | Rollbacks awaiting approval (approve or reject), and history showing **who** decided, how, and whether the SLA was met |
| `/app/settings` | Workspace and account details (read-only) |

### Run it

Start the API as above, with two more variables:

```bash
SHIELDPULSE_SESSION_KEY="dev-session-key" \
SHIELDPULSE_INSECURE_COOKIES=1 \
...  uv run uvicorn --factory shieldpulse.app:create_app_from_env --port 8000
```

Open <http://localhost:8000> and sign in with a demo account (shown on the login page in local dev):

| Account | Password | Tenant |
|---|---|---|
| `secops@acme.example` | `acme-demo-2026` | Acme Networks, automatic rollback |
| `soc@globex.example` | `globex-demo-2026` | Globex Retail, manual approval |

For a 30-day trend in the chart, load the optional demo history:

```bash
docker compose exec -T postgres psql -U postgres -d shieldpulse -f - < dev/demo_history.sql
```

`SHIELDPULSE_INSECURE_COOKIES=1` is for plain-HTTP localhost only. Browsers drop `Secure` cookies over HTTP, and the setting also shows the demo-account hint. Never set it in production.

### Design

- **Tone:** a warm, calm look inspired by the tone of Claude's website, which was studied with REA's browser capture. It is an original palette (parchment, warm ink, terracotta accent) with system serif headings and system sans-serif body text. No third-party logos, fonts or copy are used, and no external requests are made.
- **Themes:** light and dark follow the OS setting, and the moon button switches between them. The choice is remembered and applied before first paint, so there is no flash.
- **Rendering:** charts are inline SVG rendered on the server, so they need no chart library and change color with the theme. Each point has a hover tooltip, and there are gaps on days without incidents.
- **Responsive and accessible:** a sidebar on desktop and a top bar on phones; motion respects `prefers-reduced-motion`; landmarks, ARIA labels and visible focus rings throughout.

### Security

- **Sign-in:** passwords are scrypt-hashed. Unknown emails take the same time to fail as wrong passwords and get the same generic error. Sign-in is rate-limited to 10 attempts per email per minute.
- **Sessions:** HMAC-signed, expire after 8 hours, and use `HttpOnly`, `SameSite=Strict` and `Secure` cookies.
- **Forms:** every POST requires a CSRF token bound to the session.
- **Isolation:** every page reads inside the user's tenant context, so RLS isolates the UI exactly as it does the webhook. Another tenant's event returns 404, and deciding another tenant's job changes nothing.
- **Headers:** a strict Content-Security-Policy (`'self'` only, no inline scripts or styles), `no-store` caching, `frame-ancestors 'none'`, and `nosniff`.
- **Untrusted data:** device-reported values such as rule names are HTML-escaped everywhere. A test checks this with a `<script>` payload.

## Tenant Isolation Design

- **The API connects as `shieldpulse_app` and the worker as `shieldpulse_worker`.** These are login users in the group roles `shieldpulse_api_role` and `shieldpulse_worker_role`, which `schema.sql` creates and grants to. None of them is superuser or `BYPASSRLS`. Superusers bypass RLS even when it is FORCEd, so this role separation is what makes the policy meaningful. Tests fail if either role ever gains those privileges.
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
- **Ingestion:** the happy path, auth failures, raw-byte signatures, `400` only after successful auth, `429` per tenant, trailing 30-day MTTR, and calendar-month credits (month boundaries, and month average versus single slow incident)
- **Dashboard:** sign-in failures, hardened cookies, open-redirect protection, tampered and expired sessions, rate limiting, CSRF on every POST, tenant isolation in the UI, approver identity, HTML escaping, and chart rendering
- **RLS:** each tenant sees only its own rows, no context means no rows, cross-tenant writes and moves are rejected, and no context leaks between pooled connections
- **Runbook:** both the AUTO and MANUAL paths end to end; SLA miss; a rollback that never converges; an unreachable device; inactive tenants (including one that goes inactive while awaiting approval); tampered, expired, forged and cross-tenant approval tokens; GET never changing state; and concurrent workers never claiming the same job

Without a reachable database, the database tests **skip**. CI sets `SHIELDPULSE_REQUIRE_DB=1` so they **fail** instead. Set `SHIELDPULSE_TEST_ADMIN_URL` to use a server other than `localhost:55432`.

## Known Limitations

- **The primary key is `(drift_id, detected_at)`, not `drift_id` alone.** PostgreSQL requires the partition key in the primary key. Only a `DEFAULT` partition exists; create monthly partitions with ops tooling such as pg_partman.
- **Rate limits are per process,** held in memory. Multiple replicas need a shared store such as Redis.
- **Unauthenticated traffic is not rate limited,** because limits are keyed by authenticated tenant. Edge protection (WAF or API gateway) is expected in front of the service.
- **`tenants.status` is not enforced at ingestion.** Events from inactive tenants are recorded, and the worker skips their remediation.
- **The approval link is a bearer credential.** Anyone holding it can decide, and approver identity is not captured. Add SSO before production use.
- **No real device integration or golden-state store yet.** The rollback target is `last_known_good`, which the device is trusted to resolve.
- **There are no migrations.** Schema changes are applied by recreating the database (`docker compose down -v`). Adopt a migration tool before any shared environment.
- **Dev credentials** (`postgres` / `shieldpulse_app_dev`, the demo secrets) are for local use only.
