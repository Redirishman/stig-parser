"""Shared parse→export pipeline used by the CLI, the Flask app, and the
async stage entrypoints. Single source of truth for the processing steps.

This module is AWS-agnostic and must not import boto3.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping

from app.core.inputs import ClassifiedInputs, classify_inputs
from app.exporters.excel_exporter import ExcelExporter
from app.parsers.base import Benchmark, Finding, ScanResult
from app.parsers.benchmark_parser import BenchmarkParser, load_xml
from app.parsers.cklb_parser import CKLBParser
from app.parsers.nessus_parser import NessusComplianceParser
from app.parsers.xccdf_parser import XCCDFResultsParser
from app.processors.delta import DeltaResult
from app.processors.filter import filter_findings
from app.processors.matcher import (
    MatchIssue,
    match_results_by_scan,
    results_fingerprint,
    scan_coverage_pairs,
    unresolved_issue_warnings,
)
from app.reference.cklb_loader import load_cklb_reference
from app.reference.enrich import EnrichmentReport, enrich_findings
from app.reference.library import ReferenceLibrary
from app.reference.normalize import (
    MAX_SHOWN_CHARS,
    clip,
    fold,
    is_disa_stem,
    is_vuln_id,
    norm_stig_id,
    product_key,
    rule_stem,
    safe_name,
    strip_group_prefix,
    strip_rule_prefix,
)


class PipelineError(Exception):
    """Raised when the pipeline cannot produce actionable findings.

    The message is user-safe and intended for display in the UI / CLI.
    ``warnings`` carries the per-file warnings :func:`parse_stage` had
    collected before it gave up — they are the diagnosis ("x.cklb: 0 rule
    results"), so a caller logs them ahead of the error instead of losing
    them with the ``ParseResult`` that was never built.
    """

    def __init__(self, message: str, warnings: list[str] | None = None) -> None:
        super().__init__(message)
        self.warnings: list[str] = list(warnings or [])


@dataclass
class ParseResult:
    """Output of :func:`parse_stage`."""
    findings: list[Finding]
    warnings: list[str]
    source_file_count: int
    # Every (server, stig_title) pair the scan set covered, built BEFORE the
    # actionable filter and including scans with nothing left open. The
    # delta report uses it to tell "fully remediated" from "not re-scanned".
    coverage: set[tuple[str, str]]
    # What reference enrichment filled, drifted, and could not find.
    enrichment: EnrichmentReport = field(default_factory=EnrichmentReport)


_UNTITLED_STIG = "(untitled STIG)"
_MAX_FILES_NAMED = 5        # files named in one line; the count stays exact
_MAX_HOSTS_NAMED = 5        # hosts given a line of their own; the rest are counted


@dataclass
class _ResultsFile:
    """One parsed results file: its rows, and what else it can give the run."""
    name: str                   # display name
    order: int                  # where it came in the order the operator supplied files
    rows: list[Finding] = field(default_factory=list)   # XCCDF: the matched findings
    scan: ScanResult | None = None      # XCCDF results only
    checklist: Path | None = None       # a results checklist, whose STIG text the library takes too
    nessus: bool = False                # a .nessus scan
    as_reference: bool = False          # XCCDF results that came in the reference slot
    ignored_values: int = 0             # a results checklist: values the parser ignored as not text

    def text_count(self) -> int:
        """Report rows with check text plus report rows with fix text, before enrichment."""
        return sum(bool(f.check_text) + bool(f.fix_text) for f in filter_findings(self.rows))


def _title_signature(rows: list[Finding]) -> frozenset[tuple[str, frozenset[str]]]:
    """The products a file titles its rows with: (folded host, product keys) for every titled host."""
    titles: dict[str, set[str]] = {}
    for f in rows:
        if f.stig_title.strip():
            titles.setdefault(fold(f.server), set()).add(product_key(f.stig_title))
    return frozenset((host, frozenset(keys)) for host, keys in titles.items())


def _one_per_scan(files: list[_ResultsFile], warnings: list[str]) -> list[_ResultsFile]:
    """*files* less every second copy of one scan, in their order; each copy dropped is named.

    One scan supplied twice (SCC's XCCDF results and ARF report, Evaluate-STIG's
    XCCDF and checklist, a checklist saved twice) would double every finding.
    Two files are copies of one scan only when all of these hold:
    - they have one fingerprint (see :func:`results_fingerprint`). A file with
      no actionable rows has none and is never merged;
    - both are .nessus scans or neither is: a Nessus scan and another scanner's
      that agree row for row are two scans (the fingerprint sees actionable
      rows only, so a host of the .nessus file that passed everything is
      invisible to it);
    - where both title a host's rows, the titles name one product (see
      :func:`product_key`). An untitled copy, such as a bare TestResult,
      joins the first copy of its scan.
    Of the copies, the one whose rows carry the most text is read, the first
    supplied on a tie. Files that are not copies are all read; when they
    report the same rules, :func:`_rules_in_several_files` says so.
    """
    group_of: dict[int, int] = {}                               # id(file) -> its copy group
    first_group: dict[tuple[str, bool], int] = {}               # (fingerprint, .nessus?) -> its first group
    titled_group: dict[tuple[str, bool, frozenset], int] = {}   # ... and its titles -> their group
    unclaimed: dict[tuple[str, bool], int] = {}                 # a group of untitled copies no title has joined
    best: dict[int, _ResultsFile] = {}                          # group -> the copy that is read
    text: dict[int, int] = {}
    numbers = itertools.count()
    ordered = sorted(files, key=lambda f: f.order)
    for rf in ordered:
        actionable = filter_findings(rf.rows)
        fingerprint = results_fingerprint(actionable)
        if fingerprint is None:
            continue
        scan = (fingerprint, rf.nessus)
        titles = _title_signature(actionable)
        if titles:
            group = titled_group.get((*scan, titles))
            if group is None:
                group = unclaimed.pop(scan, None)
                if group is None:
                    group = next(numbers)
                    first_group.setdefault(scan, group)
                titled_group[(*scan, titles)] = group
        else:
            group = first_group.get(scan)
            if group is None:
                group = first_group[scan] = unclaimed[scan] = next(numbers)
        group_of[id(rf)] = group
        text[id(rf)] = rf.text_count()
        held = best.get(group)
        if held is None or text[id(rf)] > text[id(held)]:
            best[group] = rf
    for rf in ordered:
        group = group_of.get(id(rf))
        if group is not None and best[group] is not rf:
            warnings.append(
                f"{rf.name}: same host and results as {best[group].name} — its rows are not repeated"
            )
    return [rf for rf in files if id(rf) not in group_of or best[group_of[id(rf)]] is rf]


def _rule_names(f: Finding) -> tuple[list[tuple[str, str]], bool, str]:
    """``(ids, identified, STIG ID)``: the IDs that name a row's rule, each with its kind
    (the DISA stem, the V-ID, the folded rule ID), whether one of them is a DISA stem or
    a V-ID, and its folded STIG ID. Scanners key one rule differently: a .nessus item
    may carry only the STIG ID and V-ID, and then puts the STIG ID where the rule ID
    goes; that is the STIG ID, not a rule ID. A STIG ID is kept apart because DISA
    reuses one across STIGs (router and switch NDM share CISC-ND-000010)."""
    ids = []
    stem = rule_stem(f.rule_id)
    if is_disa_stem(stem):
        ids.append(("stem", fold(stem)))
    if is_vuln_id(f.vuln_id):
        ids.append(("vuln", fold(strip_group_prefix(f.vuln_id))))
    identified = bool(ids)
    stig_id = norm_stig_id(f.stig_id)
    rule_id = fold(strip_rule_prefix(f.rule_id))
    if rule_id and norm_stig_id(f.rule_id) != stig_id:
        ids.append(("rule", rule_id))
    return ids, identified, stig_id


class _Rules:
    """Union-find over the IDs rows name rules by: two IDs one row carries name one rule."""

    def __init__(self) -> None:
        self._parent: dict[tuple[str, str], tuple[str, str]] = {}

    def find(self, key: tuple[str, str]) -> tuple[str, str]:
        root = key
        while (parent := self._parent.setdefault(root, root)) != root:
            root = parent
        while key != root:      # path compression
            self._parent[key], key = root, self._parent[key]
        return root

    def join(self, keys: list[tuple[str, str]]) -> tuple[str, str]:
        root = self.find(keys[0])
        for key in keys[1:]:
            other = self.find(key)
            if other != root:
                self._parent[other] = root
        return root


def _group_rules(rows: list[tuple[Finding, _ResultsFile]]) -> tuple[_Rules, list[tuple[tuple[str, str], _ResultsFile]]]:
    """Group one host's rows by the rule they report: ``(groups, [(a key of the row's
    group, the row's file)])``; a row that cannot be attributed to a rule is left out.

    Rows with a DISA stem or a V-ID join through those and their rule IDs, never
    through a STIG ID alone. A row with neither joins through its STIG ID only when
    it names one group among those rows, or none (it then joins the other rows known
    only by that STIG ID); a STIG ID that names several groups attributes nothing.
    """
    rules = _Rules()
    grouped: list[tuple[tuple[str, str], _ResultsFile]] = []
    stig_ids: list[tuple[tuple[str, str], str]] = []    # (an identified row's key, its STIG ID)
    unidentified: list[tuple[list[tuple[str, str]], str, _ResultsFile]] = []
    for f, rf in rows:
        ids, identified, stig_id = _rule_names(f)
        if not identified:
            unidentified.append((ids, stig_id, rf))
            continue
        grouped.append((rules.join(ids), rf))
        if stig_id:
            stig_ids.append((ids[0], stig_id))
    owners: dict[str, set[tuple[str, str]]] = {}        # STIG ID -> the identified groups with it
    for key, stig_id in stig_ids:
        owners.setdefault(stig_id, set()).add(rules.find(key))
    for ids, stig_id, rf in unidentified:
        keys = list(ids)
        if stig_id:
            named = owners.get(stig_id)
            if named is None:
                keys.append(("stig", stig_id))
            elif len(named) == 1:
                keys.append(next(iter(named)))
        if keys:
            grouped.append((rules.join(keys), rf))
    return rules, grouped


def _rules_in_several_files(findings: list[Finding], files: list[_ResultsFile]) -> list[str]:
    """One line per host some of whose rules have report rows from more than one results file.

    Such files are not copies of one scan, so each one's rows are in the
    report and the totals count those rules once per file. Called after
    enrichment, so IDs it filled count. Hosts are compared by their folded
    name, not with their STIG title: a scan and a checklist of one STIG title
    it differently, and a reference can title one of them. Rows name one rule
    when they share one of its IDs, however each scanner keys it (see
    :func:`_group_rules`). Files covering different rules of one host count
    nothing twice and get no line. At most five hosts are named.
    """
    file_of = {id(row): rf for rf in files for row in rf.rows}
    # folded host -> (the host as first seen, [(row, row's file)])
    hosts: dict[str, tuple[str, list[tuple[Finding, _ResultsFile]]]] = {}
    for f in findings:
        rf = file_of.get(id(f))
        if rf is not None:
            hosts.setdefault(fold(f.server), (f.server, []))[1].append((f, rf))
    out: list[str] = []
    for host, rows in hosts.values():
        rules, grouped = _group_rules(rows)
        reporting: dict[tuple[str, str], dict[int, _ResultsFile]] = {}
        for key, rf in grouped:
            reporting.setdefault(rules.find(key), {})[id(rf)] = rf
        shared = [by_file for by_file in reporting.values() if len(by_file) > 1]
        if not shared:
            continue
        involved = {id(rf): rf for by_file in shared for rf in by_file.values()}
        names = [rf.name for rf in sorted(involved.values(), key=lambda rf: rf.order)]
        shown = ", ".join(names[:_MAX_FILES_NAMED]) + (" …" if len(names) > _MAX_FILES_NAMED else "")
        out.append(
            f"{safe_name(host, MAX_SHOWN_CHARS)}: {len(shared)} rule(s) appear in more than one of {len(names)} "
            f"files ({shown}) — each file's rows are in the report, so totals count those rules more than once"
        )
    if len(out) > _MAX_HOSTS_NAMED:
        more = len(out) - _MAX_HOSTS_NAMED
        out = out[:_MAX_HOSTS_NAMED] + [f"… and {more} more host(s) with rules reported by more than one file"]
    return out


def _not_read(what: str, name: str, why: str) -> str:
    """The warning for a file no parser could read: what it was read as, its
    name and why, so every surface (web, API, CLI) shows the reason."""
    return f"Could not parse {what}: {name} — {why}" if why else f"Could not parse {what}: {name}"


def _malformed_line(name: str, count: int) -> str:
    """What the operator reads about checklist entries left out for their shape."""
    entries = "entry was" if count == 1 else "entries were"
    return f"{name}: {count} malformed checklist {entries} skipped"


def _can_name_a_scan(benchmark: Benchmark) -> bool:
    """True when an operator-supplied reference may give a scan its STIG title.

    It needs a benchmark ID, which is what the matcher compares, and a title:
    one with no title names nothing and would stand in the way of a later
    reference with the same ID.
    """
    return bool(benchmark.benchmark_id.strip() and benchmark.title.strip())


@dataclass
class _Run:
    """What one parse_stage call carries from step to step."""
    cancel_check: Callable[[], None] | None = None
    progress_cb: Callable[[str], None] | None = None
    warnings: list[str] = field(default_factory=list)

    def check(self) -> None:
        """Give the caller its chance to cancel; what it raises ends the run."""
        if self.cancel_check is not None:
            self.cancel_check()

    def progress(self, message: str) -> None:
        if self.progress_cb is not None:
            self.progress_cb(message)


# Why a self-contained results file can parse cleanly yet hold zero rows.
_ZERO_ROW_HINT = {
    ".cklb": "the checklist has no rules",
    ".nessus": "no Policy Compliance items (a vulnerability scan is not a compliance scan)",
}


def _load_reference_benchmarks(
    run: _Run, inputs: ClassifiedInputs, library: ReferenceLibrary, parser: BenchmarkParser
) -> list[Benchmark]:
    """Load every operator-supplied benchmark into *library*; the ones that may name a scan."""
    naming: list[Benchmark] = []
    for path in inputs.reference_xml:
        run.check()
        name = inputs.name_of(path)
        try:
            parsed, why = parser.read_all(path, name=name)
        except OSError:
            # Readable when it was classified, not now. One file never stops the run.
            run.warnings.append(f"Could not read file: {name}")
            continue
        if not parsed:
            run.warnings.append(_not_read("benchmark", name, why))
        usable = [bm for bm in parsed if bm.rules]
        if parsed and not usable:
            run.warnings.append(f"{name}: reference contains 0 rules — ignored")
        elif len(usable) < len(parsed):
            # One line per file, however many empty benchmarks it holds.
            run.warnings.append(
                f"{name}: {len(parsed) - len(usable)} of {len(parsed)} benchmarks "
                "in the file contain 0 rules — ignored"
            )
        for bm in usable:
            if _can_name_a_scan(bm):
                # A reference names a scan and gives it nothing else (see _match): keep
                # its title, not its rules, which the library already holds.
                naming.append(Benchmark(bm.benchmark_id, bm.title, release=bm.release))
            library.add_benchmark(bm, name, embedded=False)
    return naming


def _load_reference_checklists(run: _Run, inputs: ClassifiedInputs, library: ReferenceLibrary) -> list[Benchmark]:
    """Load every operator-supplied checklist into *library*; a title-only benchmark per STIG."""
    naming: list[Benchmark] = []
    for path in inputs.reference_cklb:
        run.check()
        name = inputs.name_of(path)
        checklist = load_cklb_reference(path, embedded=False, name=name, max_rules=library.rules_left)
        if not checklist.readable:
            run.warnings.append(_not_read("reference checklist", name, checklist.problem))
            continue
        if checklist.ignored_values:
            run.warnings.append(
                f"{name}: {checklist.ignored_values} non-text value(s) in the "
                "checklist were ignored"
            )
        if checklist.malformed_entries:
            run.warnings.append(_malformed_line(name, checklist.malformed_entries))
        if checklist.rules_not_built:
            library.not_loaded(name)        # the run holds no more rules: said once, by the library
        if checklist.rule_count == 0:
            # Not added: an empty checklist is not a supplied reference.
            if not checklist.rules_not_built:
                run.warnings.append(f"{name}: reference checklist contains 0 rules — ignored")
            continue
        for source, rules in checklist.stigs:
            if rules and not any(r.check_text for r in rules):
                # Which STIG, when the file holds more than one.
                stig = ""
                if len(checklist.stigs) > 1:
                    stig = f"{clip(source.title or source.benchmark_id, MAX_SHOWN_CHARS) or _UNTITLED_STIG}: "
                run.warnings.append(f"{name}: {stig}0 of {len(rules)} rules carry check text")
            library.add_rules(source, rules)
            # A checklist names its STIG as a benchmark does: a scan that carries
            # no benchmark gets the title from here, so every one of its findings
            # (and its coverage pair) is titled, not only those enrichment fills.
            # Title only: no rules, so the matcher can take nothing else from it.
            named = Benchmark(source.benchmark_id, source.title, release=source.release)
            if _can_name_a_scan(named):
                naming.append(named)
    return naming


def _parse_xccdf(
    run: _Run, inputs: ClassifiedInputs, path: Path, name: str,
    results_parser: XCCDFResultsParser, benchmark_parser: BenchmarkParser,
) -> _ResultsFile | None:
    """One XCCDF results file, with the benchmarks embedded in it; None (said so) when unreadable.

    The file is parsed once: the results parser, its scanner detection and the
    benchmark parser read the same tree, which is freed when this returns.
    """
    try:
        tree, why = load_xml(path)
        sr = None
        if tree is not None:
            sr, why = results_parser.read(path, name=name, tree=tree)
        embedded = benchmark_parser.read_all(path, name=name, tree=tree)[0] if sr else []
    except OSError:
        run.warnings.append(f"Could not read file: {name}")
        return None
    finally:
        tree = None     # the parsed document is the largest thing a file costs: let it go now
    if not sr:
        run.warnings.append(_not_read("results file", name, why))
        return None
    # The benchmark embedded in this results file (SCC) is ALWAYS used —
    # supplying a reference must never discard what the scan itself
    # carried. It is attached to the scan parsed from this same path, in
    # this same pass: two uploads can hold one file name, and the library
    # may answer add_benchmark with an identical copy from an earlier
    # file, so neither a name nor the returned source identifies it.
    sr.embedded_benchmarks.extend(bm for bm in embedded if bm.rules)
    return _ResultsFile(
        name, inputs.supply_order.get(path, 0), scan=sr, as_reference=path in inputs.results_from_references,
    )


def _parse_self_contained(run: _Run, inputs: ClassifiedInputs, path: Path, name: str) -> _ResultsFile | None:
    """One results checklist or .nessus scan; None (said so) when unreadable."""
    suffix = path.suffix.lower()
    try:
        if suffix == ".cklb":
            checklist, why = CKLBParser().read(path, name=name)
            parsed = None if checklist is None else checklist.findings
        else:
            checklist = None
            parsed, why = NessusComplianceParser().read(path, name=name)
    except OSError:
        run.warnings.append(f"Could not read file: {name}")
        return None
    if parsed is None:
        run.warnings.append(_not_read("results file", name, why))
        return None
    if not parsed:
        # Zero rows contribute no coverage pair (built from rows, below): like
        # a zero-rule-result XCCDF file this is not a scan, and the operator
        # must be told which file, by name.
        run.warnings.append(f"{name}: 0 rule results — not counted as a scan; {_ZERO_ROW_HINT[suffix]}")
    if checklist is not None:
        if checklist.skipped_rules:
            run.warnings.append(f"{name}: {checklist.skipped_rules} rule(s) have no status and were skipped")
        if checklist.malformed_entries:
            run.warnings.append(_malformed_line(name, checklist.malformed_entries))
    return _ResultsFile(
        name, inputs.supply_order.get(path, 0), rows=list(parsed),
        checklist=path if suffix == ".cklb" else None, nessus=suffix == ".nessus",
        ignored_values=checklist.ignored_values if checklist is not None else 0,
    )


def _parse_results(run: _Run, inputs: ClassifiedInputs, benchmark_parser: BenchmarkParser) -> list[_ResultsFile]:
    """Every results file, XCCDF first, each announced through the progress callback."""
    # Per-file progress over the results files — the dominant, multi-minute
    # phase. References parse fast and aren't counted here.
    total = len(inputs.xccdf_results) + len(inputs.self_contained)
    results_parser = XCCDFResultsParser()
    files: list[_ResultsFile] = []
    for done, path in enumerate((*inputs.xccdf_results, *inputs.self_contained), start=1):
        run.check()
        name = inputs.name_of(path)
        run.progress(f"Parsing {name} ({done} of {total})…")
        if done <= len(inputs.xccdf_results):
            parsed = _parse_xccdf(run, inputs, path, name, results_parser, benchmark_parser)
        else:
            parsed = _parse_self_contained(run, inputs, path, name)
        if parsed is not None:
            files.append(parsed)
    return files


def _match(files: list[_ResultsFile], naming: list[Benchmark], issues: list[MatchIssue]) -> None:
    """Give each XCCDF results file its findings: its scan read against its own benchmark."""
    xccdf = [(rf, scan) for rf in files if (scan := rf.scan) is not None]
    rows_by_scan = match_results_by_scan([scan for _, scan in xccdf], naming, issues)
    for (rf, _), rows in zip(xccdf, rows_by_scan):
        rf.rows = rows


def _ignored_line(name: str, by_parser: int, by_loader: int) -> str | None:
    """The one line about values a results checklist held where text belongs.

    The parser and the reference loader each read the file and may each skip a
    value the other never looks at, so the two counts can differ; then the larger
    is a floor, not the total.
    """
    most = max(by_parser, by_loader)
    if not most:
        return None
    at_least = "" if by_parser == by_loader else "at least "
    return f"{name}: {at_least}{most} non-text value(s) in the checklist were ignored"


def _feed_library(
    run: _Run, library: ReferenceLibrary, kept: list[_ResultsFile], files: list[_ResultsFile],
) -> None:
    """Put the STIG text the results files carry into the library as embedded content.

    The scan's own benchmark, or a results checklist's full STIG text, which can
    also fill blanks on findings that came from another scanner. Every kept
    file's first; then each copy that is not read, whose text may fill a blank
    the kept copy left. Where a copy's text is the kept file's, the library
    holds it under the kept file's name, so Text Source names the copy only
    when its own text was used.
    """
    kept_ids = {id(rf) for rf in kept}
    for rf in kept + [rf for rf in files if id(rf) not in kept_ids]:
        for bm in rf.scan.embedded_benchmarks if rf.scan is not None else ():
            library.add_benchmark(bm, rf.name, embedded=True)
        if rf.checklist is not None:
            reference = load_cklb_reference(rf.checklist, embedded=True, name=rf.name, max_rules=library.rules_left)
            line = _ignored_line(rf.name, rf.ignored_values, reference.ignored_values)
            if line:
                run.warnings.append(line)
            for source, rules in reference.stigs:
                library.add_rules(source, rules)
            if reference.rules_not_built:
                library.not_loaded(rf.name)


def _require_results(run: _Run, inputs: ClassifiedInputs, kept: list[_ResultsFile]) -> None:
    """Raise PipelineError, with the warnings so far, when no results file could be read."""
    if kept:
        return
    if (inputs.reference_xml or inputs.reference_cklb) and not (inputs.xccdf_results or inputs.self_contained):
        raise PipelineError(
            "No rule results were found: the file(s) supplied are STIG "
            "references (benchmarks or checklists used as references), not "
            "scan results. Add the scan results to report on.",
            run.warnings,
        )
    raise PipelineError("No valid results files could be parsed.", run.warnings)


def _require_findings(
    run: _Run, findings: list[Finding], total_files: int, total_rules: int, *, allow_empty: bool,
) -> None:
    """Raise PipelineError, with the warnings so far, when the results files hold no
    rule result at all, or (unless *allow_empty*) no actionable one."""
    if total_rules == 0:
        # Well-formed files with no rule results at all are a wrong input,
        # never a clean scan — allow_empty does not apply.
        raise PipelineError(
            f"No rule results were found in any of the {total_files} results "
            f"file(s). The files may not be scan results (XCCDF, CKLB, or "
            f".nessus), or may use an unrecognised structure. Check the "
            f"warnings for details.",
            run.warnings,
        )
    if not findings and not allow_empty:
        raise PipelineError(
            f"Parsed {total_rules} rule result(s) across {total_files} "
            f"file(s), but none had an actionable status (Open / Not Reviewed "
            f"/ Error / Unknown). Either every rule passed, or the results "
            f"were not matched to the supplied STIG benchmarks. Check the "
            f"warnings.",
            run.warnings,
        )


def _scan_coverage(files: list[_ResultsFile], pairs: list[tuple[str, str] | None]) -> set[tuple[str, str]]:
    """Each XCCDF scan's coverage pair (``matcher.scan_coverage_pairs``, one per file of
    *files*), once enrichment has filled titles.

    A scan no benchmark names has a blank title, and a blank pair can never show a
    re-scan: the delta report fails closed on it. When enrichment titled every
    actionable row of such a scan, the scan covers those titles instead. With any
    row still untitled, or no actionable row to tell by, the blank pair stays.
    """
    coverage: set[tuple[str, str]] = set()
    for rf, pair in zip(files, pairs, strict=True):
        if pair is None:
            continue
        rows = filter_findings(rf.rows)
        if pair[1].strip() or not rows or not all(f.stig_title.strip() for f in rows):
            coverage.add(pair)
        else:
            coverage |= {(f.server, f.stig_title) for f in rows}
    return coverage


def _report(
    run: _Run, kept: list[_ResultsFile], naming: list[Benchmark], library: ReferenceLibrary,
    issues: list[MatchIssue], *, allow_empty: bool,
) -> ParseResult:
    """Coverage, the actionable findings filled from the library, and every warning about them."""
    scan_files = [rf for rf in kept if rf.scan is not None]
    scan_results = [scan for rf in scan_files if (scan := rf.scan) is not None]
    sc_files = [rf for rf in kept if rf.scan is None]
    sc_findings = [row for rf in sc_files for row in rf.rows]
    # Coverage comes from every parsed row (self-contained formats emit all
    # statuses) plus one pair per XCCDF scan file — taken from the scan, not
    # its actionable rows, so a clean scan still records what it covered.
    coverage = {(f.server, f.stig_title) for f in sc_findings}
    scan_pairs = scan_coverage_pairs(scan_results, naming)
    # A file with no rule results has no pair (it is not a scan and must
    # never count as a re-scan); say so per file, in words that fit the slot it came in.
    for rf in scan_files:
        sr = rf.scan
        if sr is None or sr.rule_results:
            continue
        if rf.as_reference:
            run.warnings.append(
                f"{sr.source_file}: supplied as a STIG reference, but it holds a TestResult, so it was "
                "read as scan results — 0 rule results, not counted as a scan"
            )
        else:
            run.warnings.append(
                f"{sr.source_file}: 0 rule results — not counted as a scan; "
                "if this file is a benchmark, pass it as a reference"
            )

    findings = [row for rf in kept if rf.scan is not None for row in rf.rows]
    findings.extend(sc_findings)
    findings = filter_findings(findings)

    total_files = len(scan_results) + len(sc_files)
    total_rules = sum(len(s.rule_results) for s in scan_results) + len(sc_findings)
    _require_findings(run, findings, total_files, total_rules, allow_empty=allow_empty)

    # Fill blanks from the library (actionable findings only, so every count
    # is a report row), then report what could not be filled.
    enrichment = enrich_findings(findings, library)
    run.warnings.extend(
        unresolved_issue_warnings(issues, findings, references_supplied=library.has_standalone)
    )
    run.warnings.extend(enrichment.warnings())
    # Files that are not one scan twice, yet report the same rules of one host (two
    # runs, or a scan and a checklist that disagree): every row stays, the operator is told.
    run.warnings.extend(_rules_in_several_files(findings, kept))
    coverage |= _scan_coverage(scan_files, scan_pairs)
    # A title filled by enrichment must stay inside the coverage set, or the
    # delta report would treat the finding's own scan as not covering it.
    coverage |= {(f.server, f.stig_title) for f in findings}

    return ParseResult(
        findings=findings,
        warnings=run.warnings,
        source_file_count=total_files,
        coverage=coverage,
        enrichment=enrichment,
    )


def parse_stage(
    results_paths: list[Path],
    reference_paths: list[Path],
    extract_dir: Path,
    *,
    cancel_check: Callable[[], None] | None = None,
    allow_empty: bool = False,
    progress_cb: Callable[[str], None] | None = None,
    display_names: Mapping[Path, str] | None = None,
) -> ParseResult:
    """Parse results and references, match, filter to actionable findings,
    then fill blanks from the reference library.

    ``reference_paths`` are operator-supplied STIG references (Manual STIG
    XML, DISA ZIP, SCAP benchmark, or CKLB); files are routed by content, so a
    reference among the results still works.

    ``cancel_check`` is an optional zero-arg callable invoked between units of
    work; it may raise to abort (the Flask worker uses this for cancellation).
    ``progress_cb`` is an optional callable given a user-safe status string
    before each results file is parsed (the Flask worker surfaces these as
    activity-log lines so a long parse never looks frozen).
    Raises :class:`PipelineError` (user-safe message) when no actionable
    findings can be produced.

    ``allow_empty`` relaxes ONLY the zero-actionable-findings case: a scan set
    where every rule passed returns an empty ``ParseResult`` instead of
    raising. Delta runs need this — a fully remediated scan set is a
    legitimate (and desirable) input, not a failure. A results set where
    nothing could be parsed at all, or that parsed but contains zero rule
    results, still raises regardless.

    ``display_names`` maps a supplied path to the name the operator gave the
    file when it was saved under another (see :func:`classify_inputs`).
    """
    run = _Run(cancel_check, progress_cb)
    run.check()
    inputs = classify_inputs(
        results_paths, reference_paths, extract_dir, cancel_check=run.check, display_names=display_names,
    )
    run.warnings.extend(inputs.warnings)

    # Every benchmark and checklist the run sees goes into the reference
    # library, which fills blanks after matching and records where each value
    # came from. The matcher itself takes rule data only from the benchmark
    # embedded in a scan's own results file; an operator-supplied reference
    # gives it the STIG title and nothing else (naming), or its text would be
    # reported as the scanner's.
    library = ReferenceLibrary()
    benchmark_parser = BenchmarkParser()
    naming = _load_reference_benchmarks(run, inputs, library, benchmark_parser)
    naming += _load_reference_checklists(run, inputs, library)

    results_files = _parse_results(run, inputs, benchmark_parser)
    issues: list[MatchIssue] = []
    _match(results_files, naming, issues)
    # One scan supplied twice is read once; issues raised for a copy that is not
    # read affect no reported row, so unresolved_issue_warnings says nothing of them.
    kept = _one_per_scan(results_files, run.warnings)
    _feed_library(run, library, kept, results_files)
    # What the library could not index. Added before any error below, so the
    # diagnosis rides on the exception too.
    run.warnings.extend(library.warnings)
    _require_results(run, inputs, kept)

    run.check()
    return _report(run, kept, naming, library, issues, allow_empty=allow_empty)


def compute_summary(findings: list[Finding], source_file_count: int) -> dict[str, int]:
    """Build the summary dict shown in the UI after a successful run."""
    severity_counts = {"CAT I": 0, "CAT II": 0, "CAT III": 0}
    for f in findings:
        if f.severity in severity_counts:
            severity_counts[f.severity] += 1
    return {
        "files": source_file_count,
        "hosts": len({f.server for f in findings if f.server}),
        "findings": len(findings),
        "cat1": severity_counts["CAT I"],
        "cat2": severity_counts["CAT II"],
        "cat3": severity_counts["CAT III"],
    }


def export_stage(
    findings: list[Finding],
    output_path: Path,
    *,
    enrichment: EnrichmentReport | None = None,
    warnings: list[str] | None = None,
) -> None:
    """Write findings to an Excel workbook at ``output_path``.

    *enrichment* (``ParseResult.enrichment``) adds the Summary sheet's
    Reference sources table when the operator supplied a reference;
    *warnings* (``ParseResult.warnings``) are listed on the Summary sheet.
    """
    ExcelExporter().export(findings, output_path, enrichment=enrichment, warnings=warnings)


def default_output_name() -> str:
    """Timestamped default output filename."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"stig_findings_{ts}.xlsx"


def export_delta_stage(delta: DeltaResult, output_path: Path) -> None:
    """Write a delta result to an Excel workbook at ``output_path``."""
    ExcelExporter().export_delta(delta, output_path)


def default_delta_output_name() -> str:
    """Timestamped default delta output filename."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"stig_delta_{ts}.xlsx"
