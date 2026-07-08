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
) -> ParseResult:
    """Parse results + benchmarks, match, and filter to actionable findings.

    ``cancel_check`` is an optional zero-arg callable invoked between units of
    work; it may raise to abort (the Flask worker uses this for cancellation).
    Raises :class:`PipelineError` (user-safe message) when no actionable
    findings can be produced.
    """

    def _check() -> None:
        if cancel_check is not None:
            cancel_check()

    warnings: list[str] = []

    # When no benchmark files were supplied, SCC result files embed the full
    # benchmark definitions — use the results files for both sides.
    if not benchmark_paths:
        benchmark_paths = list(results_paths)

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
    for path in results_paths:
        _check()
        sr = results_parser.parse(path)
        if sr:
            scan_results.append(sr)
        else:
            warnings.append(f"Could not parse results file: {path.name}")

    if not scan_results:
        raise PipelineError("No valid results files could be parsed.")

    _check()
    findings = match_results_to_benchmarks(scan_results, benchmarks)
    findings = filter_findings(findings)

    if not findings:
        total_rules = sum(len(s.rule_results) for s in scan_results)
        if total_rules == 0:
            msg = (
                f"No <rule-result> elements were found in any of the "
                f"{len(scan_results)} results file(s). The files may not be "
                f"XCCDF scan results, or may use an unrecognised structure. "
                f"Check the warnings for details."
            )
        else:
            msg = (
                f"Parsed {total_rules} rule-result(s) across "
                f"{len(scan_results)} file(s), but none had an actionable "
                f"status (Open / Not Reviewed / Error / Unknown). Either "
                f"every rule passed, or the results were not matched to the "
                f"supplied STIG benchmarks. Check the warnings."
            )
        raise PipelineError(msg)

    return ParseResult(
        findings=findings,
        warnings=warnings,
        source_file_count=len(scan_results),
    )


def compute_summary(findings: list[Finding], source_file_count: int) -> dict:
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
