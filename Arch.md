shieldpulse-okf/
├── index.md                                  # Reserved: Root entry point & progressive disclosure map
├── log.md                                    # Reserved: Chronological audit trail of knowledge updates
├── architecture/
│   └── control_plane.md                      # Concept: MicroSaaS multi-tenant system architecture
├── tables/
│   ├── tenants.md                            # Concept: Enterprise customer & subscription master table
│   └── policy_drift_events.md                # Concept: Security configuration drift & audit log table
├── apis/
│   └── ingest_telemetry.md                   # Concept: Webhook API for firewall & gateway state ingestion
├── metrics/
│   ├── net_revenue_retention.md              # Concept: SaaS NRR & SLA penalty exposure formula
│   └── mean_time_to_remediate.md             # Concept: Operational MTTR compliance metric
├── policies/
│   └── tenant_isolation_soc2.md              # Concept: Multi-tenant RLS & encryption governance policy
└── runbooks/
    └── critical_drift_remediation.md         # Concept: P1 automated + human-in-the-loop incident playbook