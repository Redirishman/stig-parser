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

    # CKLB checklists (Evaluate-STIG / STIG Viewer 3) are JSON and
    # self-contained — they take a separate parse path with no benchmark
    # matching. Everything else goes through the XCCDF pipeline.
    cklb_paths = [p for p in results_paths if p.suffix.lower() == ".cklb"]
    xccdf_paths = [p for p in results_paths if p.suffix.lower() != ".cklb"]

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

    cklb_parser = CKLBParser()
    cklb_findings: list[Finding] = []
    cklb_file_count = 0
    for path in cklb_paths:
        _check()
        parsed = cklb_parser.parse(path)
        if parsed is None:
            warnings.append(f"Could not parse checklist: {path.name}")
        else:
            cklb_file_count += 1
            cklb_findings.extend(parsed)

    if not scan_results and cklb_file_count == 0:
        raise PipelineError("No valid results files could be parsed.")

    _check()
    findings = match_results_to_benchmarks(scan_results, benchmarks)
    findings.extend(cklb_findings)
    findings = filter_findings(findings)

    if not findings:
        total_rules = sum(len(s.rule_results) for s in scan_results)
        total_rules += len(cklb_findings)
        if total_rules == 0:
            msg = (
                f"No rule results were found in any of the "
                f"{len(scan_results) + cklb_file_count} results file(s). The "
                f"files may not be XCCDF scan results or CKLB checklists, or "
                f"may use an unrecognised structure. Check the warnings for "
                f"details."
            )
        else:
            msg = (
                f"Parsed {total_rules} rule result(s) across "
                f"{len(scan_results) + cklb_file_count} file(s), but none had "
                f"an actionable status (Open / Not Reviewed / Error / "
                f"Unknown). Either every rule passed, or the results were "
                f"not matched to the supplied STIG benchmarks. Check the "
                f"warnings."
            )
        raise PipelineError(msg)

    return ParseResult(
        findings=findings,
        warnings=warnings,
        source_file_count=len(scan_results) + cklb_file_count,
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
