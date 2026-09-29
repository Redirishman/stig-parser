"""Baseline-vs-current comparison of two actionable finding sets.

Pure and I/O-free. Consumes two ``list[Finding]`` (each the output of the
existing parse pipeline) plus each run's *coverage* — the set of
``(server, stig_title)`` pairs the run actually scanned — and classifies
every finding as New, Resolved, Persisting, Not re-scanned, or Newly scanned.

Coverage is passed in, never derived from the finding lists: a finding list
is actionable-only, so a host or STIG with nothing left open is invisible in
it, and a STIG that was not re-scanned looks identical to one that was fully
remediated. ``parse_stage`` builds coverage from every parsed row before the
actionable filter, plus one pair per XCCDF scan file (see
``app.processors.matcher.scan_coverage``).

Identity within a common host is a two-pass match (see ``_match_two_pass``):
findings are matched on ``vuln_id`` where both sides have one, then leftovers
are matched on the ``rule_id`` stem. ``vuln_id`` is stable across DISA
benchmark revisions where ``rule_id`` is not, but ``vuln_id`` is blank
whenever a rule couldn't be matched to a benchmark, or the source carries no
V-ID at all — and one run can have broader benchmark coverage than the other
(e.g. ``--benchmarks`` supplied for only one side), so a single-key scheme
keyed on "vuln_id-or-rule_id" is not reliable. Hostnames are matched
case/whitespace-insensitively (``_host_key``); STIG titles are matched on an
edition-neutral key (``_stig_key``).
"""
from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from app.parsers.base import Finding

log = logging.getLogger(__name__)

# Public source of truth for delta status literals — import this rather than
# hardcoding the strings elsewhere (e.g. the exporter).
_NEW = "New"
_RESOLVED = "Resolved"
_PERSISTING = "Persisting"
_NOT_RESCANNED = "Not re-scanned"
_NEWLY_SCANNED = "Newly scanned"
DELTA_STATUSES = (_NEW, _RESOLVED, _PERSISTING, _NOT_RESCANNED, _NEWLY_SCANNED)

# A coverage entry: (server, stig_title) exactly as the scanner spelled them.
Pair = tuple[str, str]

# Longest pair list embedded in a single warning. The full list is on the
# workbook's Coverage block; the warning only has to name the problem.
_MAX_PAIRS_IN_WARNING = 20


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
    delta_status: str      # one of DELTA_STATUSES
    baseline_status: str   # "" for New / Newly scanned
    current_status: str    # "" for Resolved / Not re-scanned


@dataclass
class DeltaResult:
    """Delta between a baseline and a current scan set.

    Host sets and pair sets are derived from the two *coverage* inputs of
    ``compute_delta`` (never from the findings) and keep the first-seen raw
    spelling; membership is decided on the normalised keys.
    """
    findings: list[DeltaFinding] = field(default_factory=list)
    common_hosts: set[str] = field(default_factory=set)
    only_baseline_hosts: set[str] = field(default_factory=set)
    only_current_hosts: set[str] = field(default_factory=set)
    # (host, STIG) pairs scanned in the baseline but absent from the current
    # coverage, and vice versa. Findings on these pairs are tagged
    # "Not re-scanned" / "Newly scanned" and are never Resolved / New.
    not_rescanned_pairs: set[Pair] = field(default_factory=set)
    newly_scanned_pairs: set[Pair] = field(default_factory=set)
    # User-visible warnings (duplicate findings, coverage gaps, unreliable
    # Vuln-ID coverage, etc.) -- mirrors ParseResult.warnings
    # (app/core/pipeline.py) so callers can drain both the same way.
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


# Product-neutral phrases and tokens dropped from a STIG title before it is
# used as a coverage key, so the SCAP and Manual editions of one STIG — and
# successive revisions of one Nessus .audit — share a key.
_STIG_PHRASES = ("security technical implementation guide",)
_STIG_TOKENS = frozenset({"stig", "scap", "benchmark", "manual", "disa"})
_AUDIT_SUFFIX = ".audit"   # Nessus .audit filename; "audit" as a word is kept
_VERSION_TOKEN = re.compile(r"^v\d+r\d+$")
_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def _stig_key(stig_title: str) -> str:
    """Edition-neutral key for a STIG title.

    ``"Microsoft Windows 11 STIG SCAP Benchmark"`` and
    ``"Microsoft Windows 11 Security Technical Implementation Guide"`` both
    reduce to ``"microsoft windows 11"``; ``"DISA_STIG_MS_Windows_11_v2r8.audit"``
    and its ``v2r9`` successor both reduce to ``"ms windows 11"``.

    Whitespace is collapsed before the phrase match; only whole neutral
    tokens are dropped (``"Postgres STIGs"``, ``"Oracle Audit Vault"`` keep
    theirs). A non-blank title that normalises to nothing (``"STIG"``) keeps
    its collapsed, casefolded form: the blank key is reserved for a scan
    that matched no benchmark, which fails closed (R2-9).
    """
    text = " ".join(stig_title.split()).casefold()
    if not text:
        return ""
    normalised = text.removesuffix(_AUDIT_SUFFIX)
    for phrase in _STIG_PHRASES:
        normalised = normalised.replace(phrase, " ")
    tokens = [
        t for t in _NON_ALNUM.split(normalised)
        if t and t not in _STIG_TOKENS and not _VERSION_TOKEN.match(t)
    ]
    return " ".join(tokens) or text


_XCCDF_RULE_PREFIX = re.compile(r"^xccdf_[^_]+_rule_")
_RULE_REVISION_SUFFIX = re.compile(r"r\d+_rule$")


def _rule_stem(rule_id: str) -> str:
    """Rule ID with the XCCDF namespace prefix and ``rNNNNNN`` revision removed.

    ``xccdf_mil.disa.stig_rule_SV-254239r945408_rule`` -> ``SV-254239``, as
    does ``SV-254239r945411_rule``: the same rule across benchmark revisions.
    """
    stem = _XCCDF_RULE_PREFIX.sub("", rule_id.strip())
    return _RULE_REVISION_SUFFIX.sub("", stem)


def _pair_key(server: str, stig_title: str) -> tuple[str, str]:
    """Normalised coverage key: (host key, STIG key)."""
    return (_host_key(server), _stig_key(stig_title))


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


def _rule_key(f: Finding) -> tuple[str, str] | None:
    """Cross-run match key: (normalized host, rule stem). None if the stem is blank.

    A blank stem carries no identity — whether the rule ID is empty or is
    nothing but the XCCDF prefix and revision (``r1_rule``): two findings
    that both lack one must never be paired up as the same finding.
    """
    stem = _rule_stem(f.rule_id)
    if not stem:
        return None
    return (_host_key(f.server), stem)


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


def _dedupe(findings: list[Finding], label: str, warnings: list[str]) -> list[Finding]:
    """Drop within-run duplicates (first occurrence wins, collision warned)."""
    _, dropped = _build_index(findings, _finding_key, label, warnings)
    return [f for i, f in enumerate(findings) if i not in dropped]


def _match_two_pass(
    base_common: list[Finding],
    curr_common: list[Finding],
    warnings: list[str],
) -> tuple[list[tuple[Finding, Finding]], list[Finding], list[Finding]]:
    """Two-pass identity match for findings on hosts present in both runs.

    Pass 1 matches on ``(host, vuln_id)`` wherever ``vuln_id`` is non-blank
    on both sides. Pass 2 matches whatever's left — blank ``vuln_id`` on
    either side, or a ``vuln_id`` with no vuln-keyed counterpart — on
    ``(host, rule stem)``; a blank ``rule_id`` is never matched.

    This tolerates the same finding being keyed on ``vuln_id`` in one run
    and ``rule_id`` in the other, e.g. because ``--benchmarks`` was
    supplied for only one of the two runs. A single-key scheme
    (``vuln_id or rule_id``) fails that case: the finding gets a different
    key in each run and looks like it Resolved in baseline and is brand
    New in current, when it never actually changed.

    Returns ``(persisting_pairs, leftover_baseline, leftover_current)``.
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

    unmatched_base = [f for i, f in enumerate(leftover_base) if i not in matched_b2]
    unmatched_curr = [f for i, f in enumerate(leftover_curr) if i not in matched_c2]

    return pairs, unmatched_base, unmatched_curr


def _blank_vuln_rate(findings: list[Finding]) -> float:
    if not findings:
        return 0.0
    blank = sum(1 for f in findings if not f.vuln_id)
    return blank / len(findings)


def _index_coverage(
    coverage: Iterable[Pair], raw_host: dict[str, str]
) -> dict[tuple[str, str], Pair]:
    """Map normalised pair key -> first-seen raw pair; record raw hostnames."""
    indexed: dict[tuple[str, str], Pair] = {}
    for server, stig_title in coverage:
        pk = _pair_key(server, stig_title)
        indexed.setdefault(pk, (server, stig_title))
        raw_host.setdefault(pk[0], server)
    return indexed


def _format_pairs(pairs: set[Pair]) -> str:
    """Render pairs as ``HOST / STIG`` for a warning, capped for readability."""
    ordered = sorted(pairs, key=lambda p: (_host_key(p[0]), _stig_key(p[1]), p))
    shown = [f"{s} / {t or '(no STIG title)'}" for s, t in ordered[:_MAX_PAIRS_IN_WARNING]]
    extra = len(ordered) - len(shown)
    if extra > 0:
        shown.append(f"(+{extra} more — see the Coverage block)")
    return "; ".join(shown)


def compute_delta(
    baseline: list[Finding],
    current: list[Finding],
    *,
    baseline_coverage: set[Pair],
    current_coverage: set[Pair],
) -> DeltaResult:
    """Compare two actionable finding sets and classify each finding.

    ``baseline_coverage`` / ``current_coverage`` are the ``(server,
    stig_title)`` pairs each run actually scanned (``ParseResult.coverage``).
    They decide what a finding's absence means:

    - host only in the current coverage: every finding **Newly scanned**;
      host only in the baseline coverage: every finding **Not re-scanned**.
      Neither is ever New or Resolved.
    - hosts in both: findings are matched via ``_match_two_pass``; matched
      pairs are **Persisting**. A leftover baseline finding is **Resolved**
      only if its (host, STIG) pair is in the current coverage, otherwise
      **Not re-scanned**. A leftover current finding is **New** only if its
      pair is in the baseline coverage, otherwise **Newly scanned**.
    - a blank STIG title (scan matched no benchmark) can never verify a
      re-scan: leftovers on such a pair are always **Not re-scanned** /
      **Newly scanned**, whichever side the pair is on.

    Host matching is case/whitespace insensitive (``_host_key``) and STIG
    matching is edition-neutral (``_stig_key``); the host and pair sets on
    ``DeltaResult`` keep the original spellings. Every coverage gap is
    appended to ``DeltaResult.warnings`` so it reaches the workbook, not
    only the CLI log.
    """
    warnings: list[str] = []

    # --- coverage --------------------------------------------------------
    raw_host: dict[str, str] = {}
    base_pairs = _index_coverage(baseline_coverage, raw_host)
    curr_pairs = _index_coverage(current_coverage, raw_host)
    base_host_keys = {hk for hk, _ in base_pairs}
    curr_host_keys = {hk for hk, _ in curr_pairs}
    common_keys = base_host_keys & curr_host_keys

    result = DeltaResult(
        common_hosts={raw_host[hk] for hk in common_keys},
        only_baseline_hosts={raw_host[hk] for hk in base_host_keys - curr_host_keys},
        only_current_hosts={raw_host[hk] for hk in curr_host_keys - base_host_keys},
        not_rescanned_pairs={base_pairs[pk] for pk in base_pairs.keys() - curr_pairs.keys()},
        newly_scanned_pairs={curr_pairs[pk] for pk in curr_pairs.keys() - base_pairs.keys()},
        warnings=warnings,
    )

    # --- hosts not in both coverages: nothing to compare against ---------
    base_common = [f for f in baseline if _host_key(f.server) in common_keys]
    curr_common = [f for f in current if _host_key(f.server) in common_keys]
    base_uncovered = [f for f in baseline if _host_key(f.server) not in common_keys]
    curr_uncovered = [f for f in current if _host_key(f.server) not in common_keys]

    for f in _dedupe(base_uncovered, "baseline", warnings):
        result.findings.append(_tag(f, _NOT_RESCANNED, f.status, ""))
    for f in _dedupe(curr_uncovered, "current", warnings):
        result.findings.append(_tag(f, _NEWLY_SCANNED, "", f.status))

    # --- hosts in both runs: two-pass identity match ----------------------
    pairs, leftover_base, leftover_curr = _match_two_pass(
        base_common, curr_common, warnings
    )

    for b, c in pairs:
        result.findings.append(_tag(c, _PERSISTING, b.status, c.status))

    # A blank STIG key means the scan matched no benchmark, so a finding on
    # it cannot be shown to have been re-scanned: it fails closed as Not
    # re-scanned / Newly scanned even when the blank pair is on both sides
    # (R2-9). Matched pairs above are unaffected.
    resolved: list[Finding] = []
    for f in leftover_base:
        pk = _pair_key(f.server, f.stig_title)
        if pk[1] and pk in curr_pairs:
            resolved.append(f)
            result.findings.append(_tag(f, _RESOLVED, f.status, ""))
        else:
            result.findings.append(_tag(f, _NOT_RESCANNED, f.status, ""))

    new_common: list[Finding] = []
    for f in leftover_curr:
        pk = _pair_key(f.server, f.stig_title)
        if pk[1] and pk in base_pairs:
            new_common.append(f)
            result.findings.append(_tag(f, _NEW, "", f.status))
        else:
            result.findings.append(_tag(f, _NEWLY_SCANNED, "", f.status))

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

    # --- coverage warnings: these must reach the workbook, not just the log
    if not common_keys:
        msg = (
            "No hosts appear in BOTH scan sets — check that hostnames match. "
            "All baseline hosts are 'Not re-scanned' and all current hosts "
            "are 'Newly scanned'; nothing was compared."
        )
        log.warning(msg)
        warnings.append(msg)
    if result.not_rescanned_pairs:
        n = len(result.not_rescanned_pairs)
        msg = (
            f"{n} baseline host/STIG pair(s) were not re-scanned in the "
            "current set — their findings are tagged 'Not re-scanned', never "
            "Resolved, since resolution cannot be inferred for a scan nobody "
            f"re-ran: {_format_pairs(result.not_rescanned_pairs)}"
        )
        log.warning(msg)
        warnings.append(msg)
    if result.newly_scanned_pairs:
        n = len(result.newly_scanned_pairs)
        msg = (
            f"{n} current host/STIG pair(s) have no baseline scan — their "
            "findings are tagged 'Newly scanned', never New, since there is "
            f"nothing to compare them against: {_format_pairs(result.newly_scanned_pairs)}"
        )
        log.warning(msg)
        warnings.append(msg)
    # A scan that could not be matched to a benchmark has no STIG title, so
    # every such STIG on a host shares one coverage pair and a STIG not
    # re-scanned there cannot be told apart from one fully remediated. The
    # findings fail closed (above); the operator is told why and how to fix it.
    # Taken from the raw coverage inputs, not the indexed first-seen pairs:
    # a titled spelling can share a key with a blank one (every token
    # product-neutral) and would otherwise hide it depending on set order.
    blank_title_hosts = sorted(
        {raw_host[_host_key(server)]
         for server, title in (*baseline_coverage, *current_coverage)
         if not title.strip()},
        key=_host_key,
    )
    if blank_title_hosts:
        n = len(blank_title_hosts)
        msg = (
            f"{n} host(s) have scans with no STIG title (the scan could not be "
            "matched to a benchmark), so their findings cannot be verified as "
            "re-scanned and are tagged Not re-scanned / Newly scanned; supply "
            "--benchmarks for both sets: " + ", ".join(blank_title_hosts)
        )
        log.warning(msg)
        warnings.append(msg)

    result.findings.sort(
        key=lambda f: (_host_key(f.server), f.vuln_id, f.rule_id, f.delta_status)
    )
    return result
