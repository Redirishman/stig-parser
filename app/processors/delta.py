"""Baseline-vs-current comparison of two actionable finding sets.

Pure and I/O-free. Consumes two ``list[Finding]`` (each the output of the
existing parse pipeline) and classifies every finding as New, Resolved, or
Persisting. Identity is a two-pass match (see ``_match_two_pass``): findings
are matched on ``vuln_id`` where both sides have one, then leftovers are
matched on ``rule_id``. ``vuln_id`` is stable across DISA benchmark
revisions where ``rule_id`` is not, but ``vuln_id`` is blank whenever a rule
couldn't be matched to a benchmark, or the source carries no V-ID at all —
and one run can have broader benchmark coverage than the other (e.g.
``--benchmarks`` supplied for only one side), so a single-key scheme keyed
on "vuln_id-or-rule_id" is not reliable. Hostnames are matched
case/whitespace-insensitively (see ``_host_key``).
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from app.parsers.base import Finding

log = logging.getLogger(__name__)

# Public source of truth for delta status literals — import this rather than
# hardcoding "New" / "Resolved" / "Persisting" elsewhere (e.g. the exporter).
_NEW = "New"
_RESOLVED = "Resolved"
_PERSISTING = "Persisting"
DELTA_STATUSES = (_NEW, _RESOLVED, _PERSISTING)


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
    # User-visible warnings (duplicate findings, unreliable coverage, etc.)
    # -- mirrors ParseResult.warnings (app/core/pipeline.py) so callers can
    # drain both the same way.
    warnings: list[str] = field(default_factory=list)


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
    """Fallback single-key identity: (normalized host, vuln_id-or-rule_id).

    Used only for de-duplicating findings *within* a single run (e.g. two
    result files that overlap). Not used to match a finding *across* runs
    — see ``_match_two_pass`` for that, since vuln_id-or-rule_id is not a
    reliable cross-run key when the two runs have different benchmark
    coverage.
    """
    return (_host_key(f.server), f.vuln_id or f.rule_id)


def _vuln_key(f: Finding) -> tuple[str, str] | None:
    """Cross-run match key: (normalized host, vuln_id). None if vuln_id is blank."""
    if not f.vuln_id:
        return None
    return (_host_key(f.server), f.vuln_id)


def _rule_key(f: Finding) -> tuple[str, str]:
    """Cross-run match key: (normalized host, rule_id). Always defined."""
    return (_host_key(f.server), f.rule_id)


def _build_index(
    findings: list[Finding],
    key_fn: Callable[[Finding], tuple[str, str] | None],
    label: str,
    warnings: list[str],
) -> tuple[dict[tuple[str, str], int], set[int]]:
    """Map key -> index into ``findings``, keeping the first occurrence.

    Entries for which ``key_fn`` returns ``None`` are left unindexed (e.g.
    so a later matching pass can consider them). Colliding keys are
    dropped after the first and reported via both ``log.warning`` and
    ``warnings`` — most likely caused by overlapping/duplicate result
    files in one scan set.

    Returns ``(index, dropped_positions)``: ``dropped_positions`` are the
    indices of colliding entries that were NOT kept in ``index`` and
    should be excluded from any later matching pass too (they were
    reported, not silently retried).
    """
    index: dict[tuple[str, str], int] = {}
    dropped: set[int] = set()
    for i, f in enumerate(findings):
        k = key_fn(f)
        if k is None:
            continue
        if k in index:
            msg = (
                f"{label}: duplicate finding for {f.server} / "
                f"{f.vuln_id or f.rule_id} — keeping the first; the scan "
                "set may contain overlapping result files."
            )
            log.warning(msg)
            warnings.append(msg)
            dropped.add(i)
            continue
        index[k] = i
    return index, dropped


def _match_two_pass(
    base_common: list[Finding],
    curr_common: list[Finding],
    warnings: list[str],
) -> tuple[list[tuple[Finding, Finding]], list[Finding], list[Finding]]:
    """Two-pass identity match for findings on hosts present in both runs.

    Pass 1 matches on ``(host, vuln_id)`` wherever ``vuln_id`` is non-blank
    on both sides. Pass 2 matches whatever's left — blank ``vuln_id`` on
    either side, or a ``vuln_id`` with no vuln-keyed counterpart — on
    ``(host, rule_id)``.

    This tolerates the same finding being keyed on ``vuln_id`` in one run
    and ``rule_id`` in the other, e.g. because ``--benchmarks`` was
    supplied for only one of the two runs. A single-key scheme
    (``vuln_id or rule_id``) fails that case: the finding gets a different
    key in each run and looks like it Resolved in baseline and is brand
    New in current, when it never actually changed.

    Returns ``(persisting_pairs, resolved_baseline_only, new_current_only)``.
    """
    b_vuln_idx, b_vuln_dropped = _build_index(base_common, _vuln_key, "baseline", warnings)
    c_vuln_idx, c_vuln_dropped = _build_index(curr_common, _vuln_key, "current", warnings)

    pairs: list[tuple[Finding, Finding]] = []
    matched_b = set(b_vuln_dropped)
    matched_c = set(c_vuln_dropped)
    for k in set(b_vuln_idx) & set(c_vuln_idx):
        bi, ci = b_vuln_idx[k], c_vuln_idx[k]
        pairs.append((base_common[bi], curr_common[ci]))
        matched_b.add(bi)
        matched_c.add(ci)

    leftover_base = [f for i, f in enumerate(base_common) if i not in matched_b]
    leftover_curr = [f for i, f in enumerate(curr_common) if i not in matched_c]

    b_rule_idx, b_rule_dropped = _build_index(leftover_base, _rule_key, "baseline", warnings)
    c_rule_idx, c_rule_dropped = _build_index(leftover_curr, _rule_key, "current", warnings)

    matched_b2 = set(b_rule_dropped)
    matched_c2 = set(c_rule_dropped)
    for k in set(b_rule_idx) & set(c_rule_idx):
        bi, ci = b_rule_idx[k], c_rule_idx[k]
        pairs.append((leftover_base[bi], leftover_curr[ci]))
        matched_b2.add(bi)
        matched_c2.add(ci)

    resolved = [f for i, f in enumerate(leftover_base) if i not in matched_b2]
    new = [f for i, f in enumerate(leftover_curr) if i not in matched_c2]

    return pairs, resolved, new


def _blank_vuln_rate(findings: list[Finding]) -> float:
    if not findings:
        return 0.0
    blank = sum(1 for f in findings if not f.vuln_id)
    return blank / len(findings)


def compute_delta(
    baseline: list[Finding], current: list[Finding]
) -> DeltaResult:
    """Compare two actionable finding sets and classify each finding.

    Scoped to host coverage: comparison only happens for hosts present in
    both runs. Hosts present only in the baseline were not re-scanned, so
    their findings cannot be inferred as resolved and are excluded
    entirely. Hosts present only in the current run are wholly new, so
    every finding on them is New. Host matching is case/whitespace
    insensitive (see ``_host_key``); the host sets on ``DeltaResult`` and
    each finding's ``server`` field keep the original, un-normalized
    spelling.

    Within a common host, findings are matched cross-run via
    ``_match_two_pass`` (vuln_id first, rule_id for the leftovers) rather
    than a single combined key — see that function's docstring for why.
    """
    warnings: list[str] = []

    # --- host coverage ---------------------------------------------------
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

    common_keys = baseline_host_keys & current_host_keys
    only_baseline_keys = baseline_host_keys - current_host_keys
    only_current_keys = current_host_keys - baseline_host_keys

    result = DeltaResult(
        common_hosts={raw_host[hk] for hk in common_keys},
        only_baseline_hosts={raw_host[hk] for hk in only_baseline_keys},
        only_current_hosts={raw_host[hk] for hk in only_current_keys},
        warnings=warnings,
    )

    # --- hosts only in the current run: everything on them is New --------
    # (Baseline-only-host findings are simply excluded — never re-scanned.)
    new_host_findings = [f for f in current if _host_key(f.server) in only_current_keys]
    _, new_host_dropped = _build_index(
        new_host_findings, _finding_key, "current", warnings
    )
    for i, f in enumerate(new_host_findings):
        if i in new_host_dropped:
            continue
        result.findings.append(_tag(f, _NEW, "", f.status))

    # --- hosts in both runs: two-pass identity match ----------------------
    base_common = [f for f in baseline if _host_key(f.server) in common_keys]
    curr_common = [f for f in current if _host_key(f.server) in common_keys]

    pairs, resolved, new_common = _match_two_pass(base_common, curr_common, warnings)

    for b, c in pairs:
        result.findings.append(_tag(c, _PERSISTING, b.status, c.status))
    for f in resolved:
        result.findings.append(_tag(f, _RESOLVED, f.status, ""))
    for f in new_common:
        result.findings.append(_tag(f, _NEW, "", f.status))

    # If matching still left residual Resolved/New on common hosts *and*
    # the two runs have different Vuln-ID coverage, that residual is
    # probably an artifact of asymmetric benchmark matching rather than a
    # genuine change — flag it so Resolved counts aren't taken at face
    # value.
    if (resolved or new_common) and base_common and curr_common:
        b_rate = _blank_vuln_rate(base_common)
        c_rate = _blank_vuln_rate(curr_common)
        if b_rate != c_rate:
            msg = (
                "Baseline and current scans have different Vuln-ID coverage "
                f"on hosts common to both runs ({b_rate:.0%} vs {c_rate:.0%} "
                "of findings missing a Vuln-ID) — this usually means "
                "--benchmarks was supplied for only one run. Resolved/New "
                "counts on those hosts may be unreliable."
            )
            log.warning(msg)
            warnings.append(msg)

    result.findings.sort(
        key=lambda f: (f.server, f.vuln_id, f.rule_id, f.delta_status)
    )
    return result
