-- DEV ONLY. Two demo tenants for local runs; their secrets are in dev/local-secrets.json.
-- Each insert sets its tenant first. A superuser bypasses RLS anyway, but a non-superuser
-- owner is bound by FORCE ROW LEVEL SECURITY and would otherwise be rejected.
BEGIN;
SELECT set_config('app.current_tenant_id', '11111111-1111-1111-1111-111111111111', true);
INSERT INTO public.tenants (tenant_id, org_name, plan_tier, mrr_inr, sla_mttr_target_sec, webhook_secret_arn, status)
VALUES ('11111111-1111-1111-1111-111111111111', 'Acme Networks', 'enterprise_plus', 450000.00, 900,
        'arn:aws:kms:ap-south-1:000000000000:key/dev-acme', 'ACTIVE');
COMMIT;

BEGIN;
SELECT set_config('app.current_tenant_id', '22222222-2222-2222-2222-222222222222', true);
INSERT INTO public.tenants (tenant_id, org_name, plan_tier, mrr_inr, sla_mttr_target_sec, webhook_secret_arn, status)
VALUES ('22222222-2222-2222-2222-222222222222', 'Globex Retail', 'growth', 60000.00, 3600,
        'arn:aws:kms:ap-south-1:000000000000:key/dev-globex', 'ACTIVE');
COMMIT;
