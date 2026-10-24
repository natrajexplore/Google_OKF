-- DEV/TEST ONLY. Login users for local runs, as members of the group roles in schema.sql.
-- Production users and credentials belong in your secrets/IaC tooling, not this file.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'shieldpulse_app') THEN
        CREATE ROLE shieldpulse_app LOGIN PASSWORD 'shieldpulse_app_dev' NOSUPERUSER NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'shieldpulse_worker') THEN
        CREATE ROLE shieldpulse_worker LOGIN PASSWORD 'shieldpulse_worker_dev' NOSUPERUSER NOBYPASSRLS;
    END IF;
END
$$;

GRANT shieldpulse_api_role TO shieldpulse_app;
GRANT shieldpulse_worker_role TO shieldpulse_worker;
