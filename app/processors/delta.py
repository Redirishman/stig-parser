"""Baseline-vs-current comparison of two actionable finding sets.

Pure and I/O-free. Consumes two ``list[Finding]`` (each the output of the
existing parse pipeline) and classifies every finding as New, Resolved, or
Persisting. Identity is keyed on ``(server, vuln_id)`` — ``vuln_id`` is stable
across DISA benchmark revisions, where ``rule_id`` is not.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.parsers.base import Finding

_NEW = "New"
_RESOLVED = "Resolved"
_PERSISTING = "Persisting"


@dataclass
class DeltaFinding:
    """A finding tagged with its cross-run delta status."""
    stig_title: str
    vuln_id: str
    rule_id: str
    severity: str
    server: str
    ip_address: str
    check_text: str
    fix_text: str
    delta_status: str      # "New" | "Resolved" | "Persisting"
    baseline_status: str   # "" for New
    current_status: str    # "" for Resolved


@dataclass
class DeltaResult:
    """Full delta between a baseline and a current scan set."""
    findings: list[DeltaFinding] = field(default_factory=list)
    common_hosts: set[str] = field(default_factory=set)
    only_baseline_hosts: set[str] = field(default_factory=set)
    only_current_hosts: set[str] = field(default_factory=set)


def _tag(
    f: Finding, delta_status: str, baseline_status: str, current_status: str
) -> DeltaFinding:
    return DeltaFinding(
        stig_title=f.stig_title,
        vuln_id=f.vuln_id,
        rule_id=f.rule_id,
        severity=f.severity,
        server=f.server,
        ip_address=f.ip_address,
        check_text=f.check_text,
        fix_text=f.fix_text,
        delta_status=delta_status,
        baseline_status=baseline_status,
        current_status=current_status,
    )


def compute_delta(
    baseline: list[Finding], current: list[Finding]
) -> DeltaResult:
    """Compare two actionable finding sets and classify each finding.

    Classification is keyed on ``(server, vuln_id)``. This step assumes both
    hosts overlap; coverage scoping (unscanned / new hosts) is layered on in a
    later step.
    """
    b_index = {(f.server, f.vuln_id): f for f in baseline}
    c_index = {(f.server, f.vuln_id): f for f in current}

    result = DeltaResult()
    for key in set(b_index) | set(c_index):
        b = b_index.get(key)
        c = c_index.get(key)
        if b and c:
            result.findings.append(_tag(c, _PERSISTING, b.status, c.status))
        elif c is not None:
            result.findings.append(_tag(c, _NEW, "", c.status))
        else:
            result.findings.append(_tag(b, _RESOLVED, b.status, ""))

    result.findings.sort(key=lambda f: (f.server, f.vuln_id, f.delta_status))
    return result
