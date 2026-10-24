-- DEV/TEST ONLY. Creates the non-superuser application role and its grants.
-- Production roles and credentials belong in your secrets/IaC tooling, not this file.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'shieldpulse_app') THEN
        CREATE ROLE shieldpulse_app LOGIN PASSWORD 'shieldpulse_app_dev' NOSUPERUSER NOBYPASSRLS;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO shieldpulse_app;
GRANT SELECT ON public.tenants TO shieldpulse_app;
-- Grants are on the partitioned parent only, so all access goes through its RLS policy.
GRANT SELECT, INSERT, UPDATE ON public.policy_drift_events TO shieldpulse_app;
