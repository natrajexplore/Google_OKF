-- DEV ONLY. Optional 30-day history for the demo tenants so the dashboard has a trend to show.
-- Run as the postgres superuser (bypasses RLS):
--   docker compose exec -T postgres psql -U postgres -d shieldpulse -f - < dev/demo_history.sql
-- Deterministic: the same rows every time (derived from hashtext, no random()).

WITH days AS (
    SELECT t.tenant_id, t.org_name, t.remediation_mode, t.sla_mttr_target_sec, d,
           abs(hashtext(t.org_name || d::text)) AS h
    FROM public.tenants t, generate_series(1, 29) AS d
), picked AS (
    SELECT *,
           date_trunc('day', now()) - make_interval(days => d) + make_interval(hours => 6 + h % 12) AS ts,
           CASE WHEN h % 3 = 0 THEN 'P1' WHEN h % 3 = 1 THEN 'P2' ELSE 'P3' END AS sev
    FROM days
    WHERE h % 4 <> 0                                    -- some days have no incidents
)
INSERT INTO public.policy_drift_events
    (tenant_id, device_hostname, vendor_type, severity, blast_radius_score, remediation_mode,
     detected_at, remediated_at, rule_name, diff_summary)
SELECT tenant_id,
       lower(split_part(org_name, ' ', 1)) || '-fw0' || (1 + h % 3),
       (ARRAY['palo_alto_panos', 'fortigate', 'cisco_sdwan', 'aws_sg'])[1 + h % 4],
       sev,
       CASE sev WHEN 'P1' THEN 95 WHEN 'P2' THEN 60 ELSE 25 END,
       remediation_mode,
       ts,
       ts + make_interval(secs => CASE sev WHEN 'P3' THEN 7200 ELSE 240 + (h % 1100) END),
       (ARRAY['ALLOW-WAN-SSH', 'TEMP-RDP-VENDOR', 'ANY-ANY-DEBUG', 'OPEN-SNMP-MGMT'])[1 + h % 4] || '-' || d,
       jsonb_build_object(
           'rule_name', (ARRAY['ALLOW-WAN-SSH', 'TEMP-RDP-VENDOR', 'ANY-ANY-DEBUG', 'OPEN-SNMP-MGMT'])[1 + h % 4] || '-' || d,
           'source_zone', CASE WHEN sev = 'P3' THEN 'TRUST-LAN' ELSE 'UNTRUST-ISP1' END,
           'destination_port', CASE sev WHEN 'P1' THEN '22/tcp' WHEN 'P2' THEN '443/tcp' ELSE '8080/tcp' END,
           'action', 'ALLOW')
FROM picked;

-- Completed runbook jobs for the historical P1s, so the Remediation history has entries.
INSERT INTO public.remediation_jobs
    (tenant_id, drift_id, detected_at, state, sla_met, created_at, updated_at, decided_by, decided_at, decided_via)
SELECT e.tenant_id, e.drift_id, e.detected_at, 'REMEDIATED',
       EXTRACT(EPOCH FROM (e.remediated_at - e.detected_at)) <= t.sla_mttr_target_sec,
       e.detected_at, e.remediated_at,
       CASE WHEN e.remediation_mode = 'MANUAL_APPROVAL' THEN u.user_id END,
       CASE WHEN e.remediation_mode = 'MANUAL_APPROVAL' THEN e.detected_at + INTERVAL '2 minutes' END,
       CASE WHEN e.remediation_mode = 'MANUAL_APPROVAL' THEN 'dashboard' END
FROM public.policy_drift_events e
JOIN public.tenants t USING (tenant_id)
LEFT JOIN LATERAL (SELECT user_id FROM public.tenant_users WHERE tenant_id = e.tenant_id LIMIT 1) u ON true
WHERE e.severity = 'P1' AND e.detected_at < date_trunc('day', now())
  AND NOT EXISTS (SELECT 1 FROM public.remediation_jobs j WHERE j.drift_id = e.drift_id);
