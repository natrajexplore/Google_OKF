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
    created_at          TIMESTAMPTZ   NOT NULL DEFAULT now()
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
