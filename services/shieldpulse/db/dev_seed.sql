-- DEV ONLY. Two demo tenants for local runs; their secrets are in dev/local-secrets.json.
-- Acme opts into AUTO rollback; Globex keeps the default MANUAL_APPROVAL.
-- Each insert sets its tenant first. A superuser bypasses RLS anyway, but a non-superuser
-- owner is bound by FORCE ROW LEVEL SECURITY and would otherwise be rejected.
BEGIN;
SELECT set_config('app.current_tenant_id', '11111111-1111-1111-1111-111111111111', true);
INSERT INTO public.tenants (tenant_id, org_name, plan_tier, mrr_inr, sla_mttr_target_sec, webhook_secret_arn, status, remediation_mode)
VALUES ('11111111-1111-1111-1111-111111111111', 'Acme Networks', 'enterprise_plus', 450000.00, 900,
        'arn:aws:kms:ap-south-1:000000000000:key/dev-acme', 'ACTIVE', 'AUTO');
COMMIT;

BEGIN;
SELECT set_config('app.current_tenant_id', '22222222-2222-2222-2222-222222222222', true);
INSERT INTO public.tenants (tenant_id, org_name, plan_tier, mrr_inr, sla_mttr_target_sec, webhook_secret_arn, status)
VALUES ('22222222-2222-2222-2222-222222222222', 'Globex Retail', 'growth', 60000.00, 3600,
        'arn:aws:kms:ap-south-1:000000000000:key/dev-globex', 'ACTIVE');
COMMIT;

-- Dashboard users (DEV ONLY). Passwords: secops@acme.example / acme-demo-2026,
-- soc@globex.example / globex-demo-2026. Hashes come from shieldpulse.auth.hash_password.
BEGIN;
SELECT set_config('app.current_tenant_id', '11111111-1111-1111-1111-111111111111', true);
INSERT INTO public.tenant_users (tenant_id, email, display_name, password_hash)
VALUES ('11111111-1111-1111-1111-111111111111', 'secops@acme.example', 'Acme SecOps', 'scrypt$16384$8$1$f4ZUvJWKQ422UwyXk3gbAQ$oARi2hMJ8rSDDulMnd4ESvD6oK18lW2z8MGjbwEP8i0');
COMMIT;
BEGIN;
SELECT set_config('app.current_tenant_id', '22222222-2222-2222-2222-222222222222', true);
INSERT INTO public.tenant_users (tenant_id, email, display_name, password_hash)
VALUES ('22222222-2222-2222-2222-222222222222', 'soc@globex.example', 'Globex SOC', 'scrypt$16384$8$1$cp8_9ZZwgviUOt3YbFIXoQ$fYWBaavNHlE1RhrmiP8ev42_AhJYl97a4E6A2nDCD8A');
COMMIT;
