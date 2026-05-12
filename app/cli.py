"""CLI entry point for STIG Compliance Parser."""
from __future__ import annotations

import argparse
import glob as glob_module
import logging
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from app.exporters.excel_exporter import ExcelExporter
from app.parsers.benchmark_parser import BenchmarkParser
from app.parsers.xccdf_parser import XCCDFResultsParser
from app.processors.filter import filter_findings
from app.processors.matcher import match_results_to_benchmarks
from app.utils.zip_extract import expand_benchmark_paths


def _resolve_paths(args: list[str], extensions: tuple[str, ...] = (".xml",)) -> list[Path]:
    """Expand directories and glob patterns into a flat list of Paths.

    Directories are scanned for files matching *extensions* (case-insensitive).
    Globs and explicit file paths pass through unchanged.
    """
    paths: list[Path] = []
    for arg in args:
        p = Path(arg)
        if p.is_dir():
            for ext in extensions:
                paths.extend(sorted(p.glob(f"*{ext}")))
        elif "*" in arg or "?" in arg or "[" in arg:
            matched = [Path(m) for m in glob_module.glob(arg, recursive=True)]
            paths.extend(sorted(matched))
        else:
            paths.append(p)
    return paths


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="stig-parser",
        description=(
            "Parse XCCDF compliance scan results and STIG benchmark definitions, "
            "then generate a consolidated Excel findings report."
        ),
    )
    p.add_argument(
        "--results",
        nargs="+",
        required=True,
        metavar="PATH",
        help="XCCDF results files or directory (supports globs).",
    )
    p.add_argument(
        "--benchmarks",
        nargs="+",
        required=True,
        metavar="PATH",
        help="STIG benchmark XML files or directory (supports globs).",
    )
    p.add_argument(
        "--output",
        metavar="FILE",
        default=None,
        help="Output Excel file path (default: stig_findings_<timestamp>.xlsx).",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Enable detailed logging output.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s  %(name)s  %(message)s",
        stream=sys.stderr,
    )
    log = logging.getLogger("app.cli")

    # Resolve file paths (results: .xml only, benchmarks: .xml or .zip)
    results_paths = _resolve_paths(args.results)
    benchmark_paths = _resolve_paths(args.benchmarks, extensions=(".xml", ".zip"))

    if not results_paths:
        log.error("No results files found for: %s", args.results)
        return 1
    if not benchmark_paths:
        log.error("No benchmark files found for: %s", args.benchmarks)
        return 1

    log.info("Results files:   %d", len(results_paths))
    log.info("Benchmark files: %d", len(benchmark_paths))

    # Expand any DISA STIG zip benchmarks into a managed temp dir
    extract_dir = Path(tempfile.mkdtemp(prefix="stig_zip_"))
    benchmark_paths, zip_warnings = expand_benchmark_paths(benchmark_paths, extract_dir)
    for w in zip_warnings:
        log.warning(w)
    if not benchmark_paths:
        log.error("No benchmark XCCDF files available after zip expansion. Aborting.")
        return 1

    # Parse benchmarks
    benchmark_parser = BenchmarkParser()
    benchmarks = []
    for path in benchmark_paths:
        log.info("Parsing benchmark: %s", path.name)
        bm = benchmark_parser.parse(path)
        if bm:
            benchmarks.append(bm)
        else:
            log.warning("Skipping unparseable benchmark: %s", path.name)

    # Parse results
    results_parser = XCCDFResultsParser()
    scan_results = []
    for i, path in enumerate(results_paths, start=1):
        log.info("Parsing results file %d/%d: %s", i, len(results_paths), path.name)
        sr = results_parser.parse(path)
        if sr:
            scan_results.append(sr)
        else:
            log.warning("Skipping unparseable results file: %s", path.name)

    if not scan_results:
        log.error("No valid results files could be parsed. Aborting.")
        return 1

    # Match and filter
    log.info("Matching results to benchmarks…")
    findings = match_results_to_benchmarks(scan_results, benchmarks)

    log.info("Filtering to actionable findings…")
    findings = filter_findings(findings)

    if not findings:
        log.error("No actionable findings after filtering. Nothing to export.")
        return 1

    log.info("Actionable findings: %d", len(findings))

    # Output path
    if args.output:
        output_path = Path(args.output)
    else:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = Path(f"stig_findings_{ts}.xlsx")

    # Export
    log.info("Exporting to %s…", output_path)
    try:
        ExcelExporter().export(findings, output_path)
    except Exception as exc:
        log.error("Export failed: %s", exc)
        return 1

    print(f"Report written: {output_path.resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
