"""Cross-reference XCCDF scan results against STIG benchmark definitions."""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path

from app.parsers.base import Benchmark, Finding, ScanResult
from app.reference.normalize import (
    MAX_FILE_NAME_CHARS,
    MAX_SHOWN_CHARS,
    clip,
    escape_controls,
    fold,
    is_disa_stem,
    norm_benchmark_id,
    rule_stem,
    safe_name,
    strip_group_prefix,
    strip_rule_prefix,
)

log = logging.getLogger(__name__)

_STATUS_MAP = {
    "fail": "Open",
    "notchecked": "Not Reviewed",
    "notselected": "Not Reviewed",
    "error": "Error",
    "unknown": "Unknown",
}


@dataclass
class MatchIssue:
    """A matching problem, reported as data so the pipeline can decide whether
    it still matters after reference enrichment has run."""
    kind: str                 # "no-benchmark" | "rules-not-found"
    source_file: str
    benchmark_id: str
    # The actionable findings the issue affects. The rows themselves, not their
    # keys: two results files can report the same host and rule.
    findings: list[Finding] = field(default_factory=list, repr=False)


def _id_key(benchmark_id: str) -> str:
    """The comparison form of a benchmark ID: XCCDF prefix stripped, case folded.

    ``xccdf_mil.disa.stig_benchmark_X`` and ``X`` are one benchmark. An ID
    whose prefix is not the standard shape is compared whole. Blank stays blank.
    """
    return fold(norm_benchmark_id(benchmark_id))


def _scan_key(scan: ScanResult) -> str:
    """What the scan says it was run against: its benchmark ID or, when it gives
    none, the file name of its benchmark href without the extension (handles
    path-style hrefs like ``./path/xccdf_mil.disa.stig_benchmark_X.xml``).
    """
    key = _id_key(scan.benchmark_id)
    if key or not scan.benchmark_href:
        return key
    # Path.stem is applied only to the href: benchmark IDs contain dots that it
    # would take for file extensions.
    return _id_key(Path(scan.benchmark_href).stem)


def rule_key(finding: Finding) -> str:
    """Which rule a row reports, however its file spells it: the DISA stem when the
    rule ID has one (prefix and revision are spelling), else the rule ID, else the V-ID."""
    stem = rule_stem(finding.rule_id)
    if is_disa_stem(stem):
        return fold(stem)
    return fold(strip_rule_prefix(finding.rule_id)) or fold(strip_group_prefix(finding.vuln_id))


def results_fingerprint(findings: list[Finding]) -> str | None:
    """SHA-256 over what one results file reported, given its actionable rows:
    host name, IP address and the sorted set of (rule key, status); None when
    there are no rows.

    Two files with one fingerprint are one scan supplied twice: SCC writes
    XCCDF results and an ARF report of every run, Evaluate-STIG an XCCDF file
    and a checklist, and a checklist saved again differs only in formatting.
    Byte comparison cannot see any of that. The host and address are taken per
    row, so a file reporting several hosts (.nessus) is fingerprinted whole.
    Fields are length-prefixed so where one ends and the next begins cannot be
    forged.
    """
    if not findings:
        return None
    digest = hashlib.sha256()
    for row in sorted({(f.server, f.ip_address, rule_key(f), f.status) for f in findings}):
        for value in row:
            data = value.encode("utf-8", "surrogatepass")
            digest.update(len(data).to_bytes(8, "big"))
            digest.update(data)
    return digest.hexdigest()


def _index_by_id(benchmarks: list[Benchmark]) -> dict[str, Benchmark]:
    """Benchmarks by ID key, the first of each ID winning. A blank ID is not indexed."""
    index: dict[str, Benchmark] = {}
    for benchmark in benchmarks:
        key = _id_key(benchmark.benchmark_id)
        if key:
            index.setdefault(key, benchmark)
    return index


def _resolve(
    scan: ScanResult, references: dict[str, Benchmark]
) -> tuple[Benchmark | None, Benchmark | None]:
    """The two benchmarks a scan is read against: ``(own, named)``.

    ``own`` is the benchmark embedded in the scan's own results file: the one
    that was scanned, and the only source of rule data and of the scanned
    release. A file that embeds exactly one benchmark was scanned against it,
    whatever the scan calls it. Of several, it is the one with the scan's
    benchmark ID; none of them otherwise.

    ``named`` is ``own``, or failing that the operator-supplied reference with
    the scan's benchmark ID (*references*, from :func:`_index_by_id`); it
    supplies the STIG title only.

    IDs are compared for equality, never as substrings: ``STIG`` is part of
    every DISA benchmark ID, and a scan named after the wrong STIG is a report
    that states something untrue. A blank ID matches nothing.
    """
    key = _scan_key(scan)
    embedded = scan.embedded_benchmarks
    if len(embedded) == 1:
        own = embedded[0]
    else:
        own = _index_by_id(embedded).get(key) if key else None
    named = own or (references.get(key) if key else None)
    return own, named


def match_results_by_scan(
    scan_results: list[ScanResult],
    benchmarks: list[Benchmark],
    issues: list[MatchIssue] | None = None,
) -> list[list[Finding]]:
    """Merge scan results with benchmark data into findings: one list per scan,
    in the order of *scan_results*.

    Only actionable statuses (fail, notchecked, notselected, error, unknown)
    are included in output — all others are discarded here.

    Each scan is read against the benchmark embedded in its own results file
    (``ScanResult.embedded_benchmarks``): V-ID, severity, check text, fix
    text, STIG ID and the scanned release come from it and from nowhere else.
    *benchmarks* are the operator-supplied references and give a scan with no
    embedded benchmark its STIG title only, and only the one with the scan's
    benchmark ID (see :func:`_resolve`). Whatever else a reference can add
    is added by reference enrichment, which records where it came from; text
    taken from a reference here would be reported as the scanner's.

    Matching problems are appended to *issues* (when given) rather than only
    logged: the caller reports the ones that enrichment could not repair.
    """
    references = _index_by_id(benchmarks)
    return [_match_scan(scan, references, issues) for scan in scan_results]


def _match_scan(
    scan: ScanResult, references: dict[str, Benchmark], issues: list[MatchIssue] | None
) -> list[Finding]:
    own, named = _resolve(scan, references)
    stig_title = named.title if named else ""
    scan_release = own.release if own else ""
    actionable: list[Finding] = []
    unmatched: list[Finding] = []

    for rr in scan.rule_results:
        display_status = _STATUS_MAP.get(rr.status)
        if display_status is None:
            # Discard: pass, notapplicable, informational, fixed, etc.
            continue

        rule_def = own.rules.get(rr.rule_id) if own else None
        finding = Finding(
            stig_title=stig_title,
            vuln_id=rule_def.vuln_id if rule_def else "",
            rule_id=rr.rule_id,
            # Blank, never "Unknown", when the scan's own benchmark does not
            # describe the rule: blank is what enrichment fills.
            severity=rule_def.severity if rule_def else "",
            status=display_status,
            server=scan.hostname,
            ip_address=scan.ip_address,
            check_text=rule_def.check_text if rule_def else "",
            fix_text=rule_def.fix_text if rule_def else "",
            stig_id=rule_def.stig_id if rule_def else "",
            scan_release=scan_release,
        )
        actionable.append(finding)
        if rule_def is None and own is not None:
            unmatched.append(finding)

    if named is None and actionable:
        log.debug(
            "%s: no benchmark matched (href=%r, id=%r)",
            safe_name(scan.source_file),
            clip(scan.benchmark_href, MAX_SHOWN_CHARS),
            clip(scan.benchmark_id, MAX_SHOWN_CHARS),
        )
        if issues is not None:
            issues.append(MatchIssue("no-benchmark", scan.source_file, scan.benchmark_id, list(actionable)))
    elif unmatched:
        log.debug(
            "%s: %d rule(s) not found in benchmark %r",
            safe_name(scan.source_file),
            len(unmatched),
            clip(own.benchmark_id, MAX_SHOWN_CHARS),
        )
        if issues is not None:
            issues.append(MatchIssue("rules-not-found", scan.source_file, own.benchmark_id, unmatched))
    return actionable


def unresolved_issue_warnings(
    issues: list[MatchIssue],
    findings: list[Finding],
    *,
    references_supplied: bool,
) -> list[str]:
    """Operator warnings for matching problems that enrichment did not repair.

    Called after enrichment, with the findings that reach the report: an
    affected finding that was dropped on the way is not counted.
    ``rules-not-found`` is skipped when the operator supplied references,
    because the enrichment report then names the same rules per STIG.
    """
    reported = {id(f) for f in findings}
    out: list[str] = []
    for issue in issues:
        affected = [f for f in issue.findings if id(f) in reported]
        # The file's display name is already escaped and bounded: escaped again it would show
        # one file under two names. escape_controls changes nothing in one, and still keeps
        # a raw name from forging a line. The benchmark ID comes from an upload.
        name = escape_controls(clip(issue.source_file, MAX_FILE_NAME_CHARS))
        if issue.kind == "no-benchmark":
            untitled = [f for f in affected if not f.stig_title]
            if not untitled:
                continue
            bare = sum(1 for f in untitled if not (f.severity or f.check_text or f.fix_text))
            if bare == len(untitled):
                lacking = "have no STIG title, severity, or check/fix text"
            else:
                # Enrichment filled some of them from a reference that has no title.
                lacking = f"have no STIG title ({bare} of them also have no severity or check/fix text)"
            out.append(
                f"{name}: no matching STIG benchmark — {len(untitled)} finding(s) {lacking}. "
                "Add the STIG as a reference."
            )
        elif issue.kind == "rules-not-found" and not references_supplied:
            blank = [f for f in affected if not f.check_text and not f.fix_text]
            if blank:
                out.append(
                    f"{name}: {len(blank)} rule(s) not found in benchmark "
                    f"'{safe_name(issue.benchmark_id)}' — check/fix text blank"
                )
    return out


def scan_coverage_pairs(
    scan_results: list[ScanResult],
    benchmarks: list[Benchmark],
) -> list[tuple[str, str] | None]:
    """One ``(hostname, STIG title)`` pair per XCCDF scan file, in order: None for a
    scan with no rule results, and a blank title for one no benchmark names.

    A pair is emitted regardless of the scan's results: a scan where every rule
    passed still says which host and STIG it covered. The delta report needs
    that to tell "fully remediated" apart from "not re-scanned" — the actionable
    finding list alone cannot (see spec Revision 2, R2-1).

    A scan with **no** rule results at all is not a scan (a benchmark handed in
    as results, or a run that never produced results): counting it would let
    every baseline finding on that host/STIG be reported Resolved (R2-9).
    ``parse_stage`` warns about each such file.

    The title is resolved through ``_resolve`` exactly as
    :func:`match_results_by_scan` does (the scan's own embedded benchmark, else
    the reference of the same ID), so a pair always matches the
    ``(server, stig_title)`` of any finding produced from the same scan.
    """
    references = _index_by_id(benchmarks)
    pairs: list[tuple[str, str] | None] = []
    for scan in scan_results:
        if not scan.rule_results:
            pairs.append(None)
            continue
        _own, named = _resolve(scan, references)
        pairs.append((scan.hostname, named.title if named else ""))
    return pairs
