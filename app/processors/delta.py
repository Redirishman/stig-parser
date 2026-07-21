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

    Classification is keyed on ``(server, vuln_id)`` and scoped to host
    coverage: comparison only happens for hosts present in both runs.
    Hosts present only in the baseline were not re-scanned, so their
    findings cannot be inferred as resolved and are excluded entirely.
    Hosts present only in the current run are wholly new, so every finding
    on them is New.
    """
    b_index = {(f.server, f.vuln_id): f for f in baseline}
    c_index = {(f.server, f.vuln_id): f for f in current}

    baseline_hosts = {f.server for f in baseline}
    current_hosts = {f.server for f in current}
    common = baseline_hosts & current_hosts

    result = DeltaResult(
        common_hosts=common,
        only_baseline_hosts=baseline_hosts - current_hosts,
        only_current_hosts=current_hosts - baseline_hosts,
    )

    for key in set(b_index) | set(c_index):
        server, _vuln = key
        b = b_index.get(key)
        c = c_index.get(key)

        if server in result.only_current_hosts:
            # Whole host is new — every finding on it is New.
            result.findings.append(_tag(c, _NEW, "", c.status))
            continue
        if server in result.only_baseline_hosts:
            # Host was not re-scanned — cannot infer remediation. Exclude.
            continue

        # server in common
        if b and c:
            result.findings.append(_tag(c, _PERSISTING, b.status, c.status))
        elif c is not None:
            result.findings.append(_tag(c, _NEW, "", c.status))
        else:
            result.findings.append(_tag(b, _RESOLVED, b.status, ""))

    result.findings.sort(key=lambda f: (f.server, f.vuln_id, f.delta_status))
    return result
