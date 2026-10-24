-- ShieldPulse core schema.
-- Sources: shieldpulse-okf/tables/tenants.md, tables/policy_drift_events.md,
--          policies/tenant_isolation_soc2.md
-- Run as the schema owner. The application connects as a separate, non-superuser
-- role (see dev_roles.sql): superusers bypass RLS even when it is FORCEd.

CREATE TABLE public.tenants (
    tenant_id           UUID          PRIMARY KEY,
    org_name            VARCHAR(120)  NOT NULL,
    plan_tier           VARCHAR(32)   NOT NULL CHECK (plan_tier IN ('growth', 'business', 'enterprise_plus')),
    mrr_inr             NUMERIC(12,2) NOT NULL,
    sla_mttr_target_sec INTEGER       NOT NULL,
    webhook_secret_arn  TEXT          NOT NULL,
    status              VARCHAR(20)   NOT NULL CHECK (status IN ('ACTIVE', 'PAST_DUE', 'CHURNED')),
    created_at          TIMESTAMPTZ   NOT NULL DEFAULT now(),
    -- DRAFT (Phase 2): tenant opt-in to automated rollback; copied onto each drift event.
    remediation_mode    VARCHAR(20)   NOT NULL DEFAULT 'MANUAL_APPROVAL'
                                      CHECK (remediation_mode IN ('AUTO', 'MANUAL_APPROVAL'))
);

-- Partitioned monthly by detected_at (per the table concept). PostgreSQL requires the
-- partition key in the primary key, so the PK is (drift_id, detected_at) rather than
-- drift_id alone. Creating each month's partition is left to ops tooling (e.g. pg_partman);
-- the DEFAULT partition catches rows until then.
CREATE TABLE public.policy_drift_events (
    drift_id           UUID         NOT NULL DEFAULT gen_random_uuid(),
    tenant_id          UUID         NOT NULL REFERENCES public.tenants (tenant_id),
    device_hostname    VARCHAR(128) NOT NULL,
    vendor_type        VARCHAR(40)  NOT NULL CHECK (vendor_type IN ('palo_alto_panos', 'cisco_sdwan', 'fortigate', 'aws_sg')),
    severity           VARCHAR(10)  NOT NULL CHECK (severity IN ('P1', 'P2', 'P3', 'INFO')),
    blast_radius_score SMALLINT     NOT NULL CHECK (blast_radius_score BETWEEN 0 AND 100),
    remediation_mode   VARCHAR(20)  NOT NULL CHECK (remediation_mode IN ('AUTO', 'MANUAL_APPROVAL')),
    detected_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    remediated_at      TIMESTAMPTZ,
    -- DRAFT (Phase 2): the changed rule, needed to verify convergence after rollback.
    rule_name          VARCHAR(128),
    diff_summary       JSONB,
    PRIMARY KEY (drift_id, detected_at)
) PARTITION BY RANGE (detected_at);

CREATE TABLE public.policy_drift_events_default PARTITION OF public.policy_drift_events DEFAULT;

CREATE INDEX ON public.policy_drift_events (tenant_id, detected_at);

-- Tenant isolation: every pool checkout sets app.current_tenant_id (transaction-local).
-- NULLIF guards the empty string the setting holds once a previous transaction ended.
ALTER TABLE public.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.tenants
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE public.policy_drift_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.policy_drift_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.policy_drift_events
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

-- DRAFT (Phase 2): runbook work queue (runbooks/critical_drift_remediation.md).
-- One row per event that triggers the runbook; it also serves as the remediation audit trail.
CREATE TABLE public.remediation_jobs (
    job_id        UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID        NOT NULL REFERENCES public.tenants (tenant_id),
    drift_id      UUID        NOT NULL,
    detected_at   TIMESTAMPTZ NOT NULL,
    state         VARCHAR(24) NOT NULL DEFAULT 'PENDING' CHECK (state IN (
                      'PENDING', 'AWAITING_APPROVAL', 'APPROVED', 'DISPATCHED',
                      'REMEDIATED', 'REJECTED', 'SKIPPED', 'FAILED')),
    attempts      INTEGER     NOT NULL DEFAULT 0,
    run_after     TIMESTAMPTZ NOT NULL DEFAULT now(),
    sla_met       BOOLEAN,
    last_error    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (drift_id, detected_at) REFERENCES public.policy_drift_events (drift_id, detected_at),
    UNIQUE (drift_id, detected_at)
);

CREATE INDEX ON public.remediation_jobs (state, run_after);

-- Tenants (the API) see only their own jobs. The worker role must claim jobs across all
-- tenants, so it gets a queue-wide policy here. It is still restricted to one tenant's rows
-- on tenants and policy_drift_events, which carry the sensitive data.
ALTER TABLE public.remediation_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.remediation_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.remediation_jobs
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

-- Access roles. Group roles without login hold every grant; deployments create login
-- users and grant them membership (dev_roles.sql does this for local runs). Neither group is
-- superuser or BYPASSRLS, so every query by their members is subject to the policies above.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'shieldpulse_api_role') THEN
        CREATE ROLE shieldpulse_api_role NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'shieldpulse_worker_role') THEN
        CREATE ROLE shieldpulse_worker_role NOLOGIN;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO shieldpulse_api_role, shieldpulse_worker_role;
GRANT SELECT ON public.tenants TO shieldpulse_api_role, shieldpulse_worker_role;
-- Grants are on the partitioned parent only, so all access goes through its RLS policy.
GRANT SELECT, INSERT, UPDATE ON public.policy_drift_events TO shieldpulse_api_role;
GRANT SELECT, UPDATE ON public.policy_drift_events TO shieldpulse_worker_role;
GRANT SELECT, INSERT, UPDATE ON public.remediation_jobs TO shieldpulse_api_role;
GRANT SELECT, UPDATE ON public.remediation_jobs TO shieldpulse_worker_role;

CREATE POLICY worker_queue ON public.remediation_jobs TO shieldpulse_worker_role
    USING (true) WITH CHECK (true);
