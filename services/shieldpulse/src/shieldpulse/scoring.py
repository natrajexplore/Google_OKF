"""Drift severity and blast-radius scoring.

DRAFT: the bundle defines the outputs (severity P1/P2/P3/INFO, blast_radius_score 0-100,
runbook trigger at P1 or score >= 80) but not the formula, and it has no golden-state
store yet, so every reported diff is treated as drift. These rules are a placeholder,
derived from the runbook's P1 example: 0.0.0.0/0 ingress on 22/tcp or 3389/tcp.
"""

from __future__ import annotations

from dataclasses import dataclass

MANAGEMENT_PORTS = frozenset({"22/tcp", "3389/tcp"})
UNTRUSTED_ZONE_MARKERS = ("UNTRUST", "INTERNET", "WAN", "0.0.0.0/0")
RUNBOOK_SCORE_THRESHOLD = 80


@dataclass(frozen=True)
class Score:
    severity: str
    blast_radius_score: int
    # DRAFT: tenants has no remediation preference column, so everything defaults to the
    # human-in-the-loop path until that is specified.
    remediation_mode: str = "MANUAL_APPROVAL"

    @property
    def triggers_runbook(self) -> bool:
        """runbooks/critical_drift_remediation.md trigger condition (sourced)."""
        return self.severity == "P1" or self.blast_radius_score >= RUNBOOK_SCORE_THRESHOLD


def is_untrusted(zone: str) -> bool:
    zone = zone.upper()
    return any(marker in zone for marker in UNTRUSTED_ZONE_MARKERS)


def score_diff(source_zone: str, destination_port: str, action: str) -> Score:
    if action.upper() != "ALLOW":
        return Score("INFO", 5)
    if is_untrusted(source_zone):
        if destination_port.lower() in MANAGEMENT_PORTS:
            return Score("P1", 95)
        return Score("P2", 60)
    return Score("P3", 25)
