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

-- DRAFT (dashboard): tenant UI users. Password hashes are scrypt (see shieldpulse/auth.py).
CREATE TABLE public.tenant_users (
    user_id       UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID         NOT NULL REFERENCES public.tenants (tenant_id),
    email         TEXT         NOT NULL,
    display_name  VARCHAR(120) NOT NULL,
    password_hash TEXT         NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX tenant_users_email_key ON public.tenant_users (lower(email));

ALTER TABLE public.tenant_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_users FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.tenant_users
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

-- Approver identity for MANUAL_APPROVAL decisions (closes part of the approver-identity gap).
ALTER TABLE public.remediation_jobs
    ADD COLUMN decided_by  UUID REFERENCES public.tenant_users (user_id),
    ADD COLUMN decided_at  TIMESTAMPTZ,
    ADD COLUMN decided_via VARCHAR(16) CHECK (decided_via IN ('dashboard', 'link'));

-- Login happens before the tenant is known, so RLS would hide every user row. This narrow
-- function returns the single row matching one email. It runs as a dedicated NOLOGIN role,
-- the only role whose policy sees users across tenants.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'shieldpulse_login_role') THEN
        CREATE ROLE shieldpulse_login_role NOLOGIN;
    END IF;
END
$$;
GRANT USAGE ON SCHEMA public TO shieldpulse_login_role;
GRANT SELECT ON public.tenant_users TO shieldpulse_login_role;
CREATE POLICY login_lookup ON public.tenant_users FOR SELECT TO shieldpulse_login_role USING (true);

CREATE FUNCTION public.dashboard_login_lookup(p_email TEXT)
RETURNS TABLE (user_id UUID, tenant_id UUID, display_name VARCHAR, password_hash TEXT)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT u.user_id, u.tenant_id, u.display_name, u.password_hash
    FROM public.tenant_users u
    WHERE lower(u.email) = lower(p_email)
$$;
ALTER FUNCTION public.dashboard_login_lookup(TEXT) OWNER TO shieldpulse_login_role;
REVOKE ALL ON FUNCTION public.dashboard_login_lookup(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.dashboard_login_lookup(TEXT) TO shieldpulse_api_role;

GRANT SELECT ON public.tenant_users TO shieldpulse_api_role;
