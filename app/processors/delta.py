"""Baseline-vs-current comparison of two actionable finding sets.

Pure and I/O-free. Consumes two ``list[Finding]`` (each the output of the
existing parse pipeline) and classifies every finding as New, Resolved, or
Persisting. Identity is keyed on ``(server, vuln_id or rule_id)`` —
``vuln_id`` is stable across DISA benchmark revisions, where ``rule_id`` is
not, but ``vuln_id`` is blank for unmatched/non-DISA findings and ``rule_id``
is used as a fallback in that case (see ``_finding_key``). Hostnames are
matched case/whitespace-insensitively (see ``_host_key``).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from app.parsers.base import Finding

log = logging.getLogger(__name__)

# Public source of truth for delta status literals — import this rather than
# hardcoding "New" / "Resolved" / "Persisting" elsewhere (e.g. the exporter).
DELTA_STATUSES = ("New", "Resolved", "Persisting")
_NEW, _RESOLVED, _PERSISTING = DELTA_STATUSES


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
    """Delta between a baseline and a current scan set, scoped to hosts
    present in both runs (see ``compute_delta``)."""
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


def _host_key(server: str) -> str:
    """Normalize a hostname for matching.

    Hostname casing/whitespace varies by scanner and source field (FQDN vs
    ``path.stem`` fallback, etc. — see nessus_parser.py, xccdf_parser.py,
    cklb_parser.py). Without normalization the same physical host can be
    treated as two, producing false New/"not re-scanned" results.
    """
    return server.strip().casefold()


def _finding_key(f: Finding) -> tuple[str, str]:
    """Identity key for a finding: (normalized host, vuln_id-or-rule_id).

    vuln_id is blank when a rule could not be matched to a benchmark
    (matcher.py) or the source carries no V-ID (Nessus non-DISA audits,
    CKLB findings without group_id). Falling back to rule_id keeps those
    findings distinct instead of collapsing them onto a single dict key;
    rule_id is revision-unstable, but a collapsed key silently loses
    findings entirely, which is worse.
    """
    return (_host_key(f.server), f.vuln_id or f.rule_id)


def _index(findings: list[Finding], label: str) -> dict[tuple[str, str], Finding]:
    """Build a lookup keyed by ``_finding_key``, warning on residual duplicates."""
    out: dict[tuple[str, str], Finding] = {}
    for f in findings:
        k = _finding_key(f)
        if k in out:
            log.warning(
                "%s: duplicate finding for %s / %s — keeping the first; "
                "the scan set may contain overlapping result files.",
                label,
                f.server,
                f.vuln_id or f.rule_id,
            )
            continue
        out[k] = f
    return out


def compute_delta(
    baseline: list[Finding], current: list[Finding]
) -> DeltaResult:
    """Compare two actionable finding sets and classify each finding.

    Classification is keyed on ``(host, vuln_id or rule_id)`` (see
    ``_finding_key``) and scoped to host coverage: comparison only happens
    for hosts present in both runs. Hosts present only in the baseline were
    not re-scanned, so their findings cannot be inferred as resolved and are
    excluded entirely. Hosts present only in the current run are wholly new,
    so every finding on them is New. Host matching is case/whitespace
    insensitive (see ``_host_key``); the host sets on ``DeltaResult`` and
    each finding's ``server`` field keep the original, un-normalized spelling.
    """
    b_index = _index(baseline, "baseline")
    c_index = _index(current, "current")

    # Representative raw hostname per normalized host key (first-seen wins,
    # baseline checked before current) so DeltaResult's host sets stay
    # human-readable while matching stays case/whitespace-insensitive.
    raw_host: dict[str, str] = {}
    baseline_host_keys: set[str] = set()
    current_host_keys: set[str] = set()
    for f in baseline:
        hk = _host_key(f.server)
        baseline_host_keys.add(hk)
        raw_host.setdefault(hk, f.server)
    for f in current:
        hk = _host_key(f.server)
        current_host_keys.add(hk)
        raw_host.setdefault(hk, f.server)

    only_baseline_keys = baseline_host_keys - current_host_keys
    only_current_keys = current_host_keys - baseline_host_keys

    result = DeltaResult(
        common_hosts={raw_host[hk] for hk in baseline_host_keys & current_host_keys},
        only_baseline_hosts={raw_host[hk] for hk in only_baseline_keys},
        only_current_hosts={raw_host[hk] for hk in only_current_keys},
    )

    for key in set(b_index) | set(c_index):
        host_key = key[0]
        b = b_index.get(key)
        c = c_index.get(key)

        if host_key in only_current_keys:
            # Whole host is new — every finding on it is New.
            assert c is not None, "only_current_keys implies c_index has this key"
            result.findings.append(_tag(c, _NEW, "", c.status))
            continue
        if host_key in only_baseline_keys:
            # Host was not re-scanned — cannot infer remediation. Exclude.
            continue

        # host in common
        if b is not None and c is not None:
            result.findings.append(_tag(c, _PERSISTING, b.status, c.status))
        elif c is not None:
            result.findings.append(_tag(c, _NEW, "", c.status))
        else:
            assert b is not None, "key came from b_index or c_index; c was None"
            result.findings.append(_tag(b, _RESOLVED, b.status, ""))

    result.findings.sort(key=lambda f: (f.server, f.vuln_id, f.delta_status))
    return result
