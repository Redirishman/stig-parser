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
from app.processors.filter import filter_findings
from app.processors.matcher import match_results_to_benchmarks
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


def parse_stage(
    results_paths: list[Path],
    benchmark_paths: list[Path],
    extract_dir: Path,
    *,
    cancel_check: Callable[[], None] | None = None,
    progress_cb: Callable[[str], None] | None = None,
) -> ParseResult:
    """Parse results + benchmarks, match, and filter to actionable findings.

    ``cancel_check`` is an optional zero-arg callable invoked between units of
    work; it may raise to abort (the Flask worker uses this for cancellation).
    ``progress_cb`` is an optional callable given a user-safe status string
    before each results file is parsed (the Flask worker surfaces these as
    activity-log lines so a long parse never looks frozen).
    Raises :class:`PipelineError` (user-safe message) when no actionable
    findings can be produced.
    """

    def _check() -> None:
        if cancel_check is not None:
            cancel_check()

    def _progress(msg: str) -> None:
        if progress_cb is not None:
            progress_cb(msg)

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

    # Per-file progress over the results files — the dominant, multi-minute
    # phase. Benchmarks parse fast and aren't counted here.
    total_results = len(xccdf_paths) + len(sc_paths)
    done = 0

    results_parser = XCCDFResultsParser()
    scan_results = []
    for path in xccdf_paths:
        _check()
        done += 1
        _progress(f"Parsing {path.name} ({done} of {total_results})…")
        sr = results_parser.parse(path)
        if sr:
            scan_results.append(sr)
        else:
            warnings.append(f"Could not parse results file: {path.name}")

    sc_findings: list[Finding] = []
    sc_file_count = 0
    for path in sc_paths:
        _check()
        done += 1
        _progress(f"Parsing {path.name} ({done} of {total_results})…")
        parsed = _SELF_CONTAINED[path.suffix.lower()]().parse(path)
        if parsed is None:
            warnings.append(f"Could not parse results file: {path.name}")
        else:
            sc_file_count += 1
            sc_findings.extend(parsed)

    if not scan_results and sc_file_count == 0:
        raise PipelineError("No valid results files could be parsed.")

    _check()
    findings = match_results_to_benchmarks(scan_results, benchmarks)
    findings.extend(sc_findings)
    findings = filter_findings(findings)

    if not findings:
        total_rules = sum(len(s.rule_results) for s in scan_results)
        total_rules += len(sc_findings)
        if total_rules == 0:
            msg = (
                f"No rule results were found in any of the "
                f"{len(scan_results) + sc_file_count} results file(s). The "
                f"files may not be scan results (XCCDF, CKLB, or .nessus), "
                f"or may use an unrecognised structure. Check the warnings "
                f"for details."
            )
        else:
            msg = (
                f"Parsed {total_rules} rule result(s) across "
                f"{len(scan_results) + sc_file_count} file(s), but none had "
                f"an actionable status (Open / Not Reviewed / Error / "
                f"Unknown). Either every rule passed, or the results were "
                f"not matched to the supplied STIG benchmarks. Check the "
                f"warnings."
            )
        raise PipelineError(msg)

    return ParseResult(
        findings=findings,
        warnings=warnings,
        source_file_count=len(scan_results) + sc_file_count,
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
