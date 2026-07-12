"""CLI entry point for STIG Compliance Parser."""
from __future__ import annotations

import argparse
import glob as glob_module
import logging
import shutil
import sys
import tempfile
from pathlib import Path

from app.core.pipeline import (
    PipelineError,
    default_output_name,
    export_stage,
    parse_stage,
)


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
        help=(
            "XCCDF results files (.xml) and/or Evaluate-STIG / STIG Viewer 3 "
            "checklists (.cklb), or a directory (supports globs)."
        ),
    )
    p.add_argument(
        "--benchmarks",
        nargs="*",
        required=False,
        default=None,
        metavar="PATH",
        help=(
            "STIG benchmark XML/ZIP files or directory (supports globs). "
            "Optional for SCC — result files already embed benchmark definitions."
        ),
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

    # Resolve file paths (results: .xml/.cklb/.nessus, benchmarks: .xml/.zip)
    results_paths = _resolve_paths(args.results, extensions=(".xml", ".cklb", ".nessus"))
    benchmark_paths = (
        _resolve_paths(args.benchmarks, extensions=(".xml", ".zip"))
        if args.benchmarks
        else []
    )

    if not results_paths:
        log.error("No results files found for: %s", args.results)
        return 1

    # When no benchmark files are supplied the pipeline reuses the XCCDF
    # results as benchmark sources (SCC self-contained format); CKLB
    # checklists never need benchmarks.
    if not benchmark_paths:
        log.info(
            "No --benchmarks supplied — XCCDF results will be used as their "
            "own benchmark source (SCC self-contained format)."
        )

    log.info("Results files:   %d", len(results_paths))
    log.info("Benchmark files: %d", len(benchmark_paths))

    extract_dir = Path(tempfile.mkdtemp(prefix="stig_zip_"))
    try:
        try:
            result = parse_stage(results_paths, benchmark_paths, extract_dir)
        except PipelineError as exc:
            log.error("%s", exc)
            return 1

        for w in result.warnings:
            log.warning(w)

        log.info("Actionable findings: %d", len(result.findings))

        if args.output:
            output_path = Path(args.output)
        else:
            output_path = Path(default_output_name())

        log.info("Exporting to %s…", output_path)
        try:
            export_stage(result.findings, output_path)
        except Exception as exc:
            log.error("Export failed: %s", exc)
            return 1

        print(f"Report written: {output_path.resolve()}")
        return 0
    finally:
        shutil.rmtree(extract_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
