"""Drift severity and blast-radius scoring.

The rules below were derived from the runbook's P1 example (0.0.0.0/0 ingress on 22/tcp or
3389/tcp) and confirmed on 2026-10-24 (architecture/control_plane.md, Resolved Questions).
There is still no golden-state store, so every reported diff is treated as drift.
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
