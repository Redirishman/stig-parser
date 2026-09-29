"""Shared parse→export pipeline used by the CLI, the Flask app, and the
async stage entrypoints. Single source of truth for the processing steps.

This module is AWS-agnostic and must not import boto3.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from app.exporters.excel_exporter import ExcelExporter
from app.parsers.base import Finding
from app.parsers.benchmark_parser import BenchmarkParser
from app.parsers.cklb_parser import CKLBParser
from app.parsers.nessus_parser import NessusComplianceParser
from app.parsers.xccdf_parser import XCCDFResultsParser
from app.processors.delta import DeltaResult
from app.processors.filter import filter_findings
from app.processors.matcher import match_results_to_benchmarks, scan_coverage
from app.utils.zip_extract import expand_benchmark_paths


class PipelineError(Exception):
    """Raised when the pipeline cannot produce actionable findings.

    The message is user-safe and intended for display in the UI / CLI.
    """


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


def parse_stage(
    results_paths: list[Path],
    benchmark_paths: list[Path],
    extract_dir: Path,
    *,
    cancel_check: Callable[[], None] | None = None,
    allow_empty: bool = False,
) -> ParseResult:
    """Parse results + benchmarks, match, and filter to actionable findings.

    ``cancel_check`` is an optional zero-arg callable invoked between units of
    work; it may raise to abort (the Flask worker uses this for cancellation).
    Raises :class:`PipelineError` (user-safe message) when no actionable
    findings can be produced.

    ``allow_empty`` relaxes ONLY the zero-actionable-findings case: a scan set
    where every rule passed returns an empty ``ParseResult`` instead of
    raising. Delta runs need this — a fully remediated scan set is a
    legitimate (and desirable) input, not a failure. A results set where
    nothing could be parsed at all, or that parsed but contains zero rule
    results, still raises regardless.
    """

    def _check() -> None:
        if cancel_check is not None:
            cancel_check()

    warnings: list[str] = []

    # Self-contained formats take a separate parse path with no benchmark
    # matching: CKLB checklists (Evaluate-STIG / STIG Viewer 3, JSON) and
    # .nessus compliance scans (Tenable XML). Everything else goes through
    # the XCCDF pipeline.
    _SELF_CONTAINED = {".cklb": CKLBParser, ".nessus": NessusComplianceParser}
    sc_paths = [p for p in results_paths if p.suffix.lower() in _SELF_CONTAINED]
    xccdf_paths = [p for p in results_paths if p.suffix.lower() not in _SELF_CONTAINED]

    # When no benchmark files were supplied, SCC result files embed the full
    # benchmark definitions — use the XCCDF results files for both sides.
    # (CKLB files are JSON; feeding them to the benchmark parser would only
    # produce noise warnings.)
    if not benchmark_paths:
        benchmark_paths = list(xccdf_paths)

    _check()
    benchmark_paths, zip_warnings = expand_benchmark_paths(benchmark_paths, extract_dir)
    warnings.extend(zip_warnings)

    benchmark_parser = BenchmarkParser()
    benchmarks = []
    for path in benchmark_paths:
        _check()
        bm = benchmark_parser.parse(path)
        if bm:
            benchmarks.append(bm)
        else:
            warnings.append(f"Could not parse benchmark: {path.name}")

    results_parser = XCCDFResultsParser()
    scan_results = []
    for path in xccdf_paths:
        _check()
        sr = results_parser.parse(path)
        if sr:
            scan_results.append(sr)
        else:
            warnings.append(f"Could not parse results file: {path.name}")

    sc_findings: list[Finding] = []
    sc_file_count = 0
    for path in sc_paths:
        _check()
        parsed = _SELF_CONTAINED[path.suffix.lower()]().parse(path)
        if parsed is None:
            warnings.append(f"Could not parse results file: {path.name}")
        else:
            sc_file_count += 1
            sc_findings.extend(parsed)

    if not scan_results and sc_file_count == 0:
        raise PipelineError("No valid results files could be parsed.")

    _check()
    # Coverage comes from every parsed row (self-contained formats emit all
    # statuses) plus one pair per XCCDF scan file — captured BEFORE the
    # actionable filter so a clean scan still records what it covered.
    coverage = {(f.server, f.stig_title) for f in sc_findings}
    coverage |= scan_coverage(scan_results, benchmarks)
    # scan_coverage skips a file with no rule results (it is not a scan and
    # must never count as a re-scan); say so per file, so a benchmark that
    # was handed in as results is caught rather than silently ignored.
    for sr in scan_results:
        if not sr.rule_results:
            warnings.append(
                f"{sr.source_file}: 0 rule results — not counted as a scan; "
                "if this file is a benchmark, pass it with --benchmarks"
            )

    findings = match_results_to_benchmarks(scan_results, benchmarks)
    findings.extend(sc_findings)
    findings = filter_findings(findings)

    total_files = len(scan_results) + sc_file_count
    total_rules = sum(len(s.rule_results) for s in scan_results) + len(sc_findings)
    if total_rules == 0:
        # Well-formed files with no rule results at all are a wrong input
        # (e.g. a benchmark handed in as results), never a clean scan —
        # allow_empty does not apply.
        raise PipelineError(
            f"No rule results were found in any of the {total_files} results "
            f"file(s). The files may not be scan results (XCCDF, CKLB, or "
            f".nessus), or may use an unrecognised structure. Check the "
            f"warnings for details."
        )
    if not findings and not allow_empty:
        raise PipelineError(
            f"Parsed {total_rules} rule result(s) across {total_files} "
            f"file(s), but none had an actionable status (Open / Not Reviewed "
            f"/ Error / Unknown). Either every rule passed, or the results "
            f"were not matched to the supplied STIG benchmarks. Check the "
            f"warnings."
        )

    return ParseResult(
        findings=findings,
        warnings=warnings,
        source_file_count=total_files,
        coverage=coverage,
    )


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


def export_stage(findings: list[Finding], output_path: Path) -> None:
    """Write findings to an Excel workbook at ``output_path``."""
    ExcelExporter().export(findings, output_path)


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
