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
    default_delta_output_name,
    default_output_name,
    export_delta_stage,
    export_stage,
    parse_stage,
)
from app.processors.delta import compute_delta


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


_SUBCOMMANDS = ("report", "delta")


def _add_common_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--output",
        metavar="FILE",
        default=None,
        help="Output Excel file path (default: a timestamped name in the CWD).",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Enable detailed logging output.",
    )


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="stig-parser",
        description=(
            "Parse XCCDF compliance scan results and STIG benchmark "
            "definitions into a consolidated Excel findings report, or diff "
            "two scan sets (delta)."
        ),
    )
    sub = p.add_subparsers(dest="command")

    rp = sub.add_parser("report", help="Single-run findings report.")
    rp.add_argument(
        "--results",
        nargs="+",
        required=True,
        metavar="PATH",
        help=(
            "XCCDF results files (.xml) and/or Evaluate-STIG / STIG Viewer 3 "
            "checklists (.cklb) / .nessus, or a directory (supports globs)."
        ),
    )
    rp.add_argument(
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
    _add_common_flags(rp)

    dp = sub.add_parser(
        "delta", help="Diff a baseline scan set against a current one."
    )
    dp.add_argument(
        "--baseline",
        nargs="+",
        required=True,
        metavar="PATH",
        help="Baseline (older) scan results — same formats as report --results.",
    )
    dp.add_argument(
        "--current",
        nargs="+",
        required=True,
        metavar="PATH",
        help="Current (newer) scan results — same formats as report --results.",
    )
    dp.add_argument(
        "--benchmarks",
        nargs="*",
        required=False,
        default=None,
        metavar="PATH",
        help="STIG benchmark XML/ZIP applied to BOTH sets (optional for SCC).",
    )
    _add_common_flags(dp)

    return p


def _normalize_argv(argv: list[str]) -> list[str]:
    """Inject an implicit ``report`` subcommand for back-compat.

    Historically the CLI was invoked as ``stig-parser --results ...`` with no
    subcommand. If the first token is not a known subcommand (and not a bare
    ``-h``/``--help``), prepend ``report`` so old invocations keep working.
    An empty argv is normalized too, so a bare ``stig-parser`` still fails
    with the historical "--results is required" usage error rather than
    falling through with ``command=None``.
    """
    if argv and (argv[0] in _SUBCOMMANDS or argv[0] in ("-h", "--help")):
        return argv
    return ["report", *argv]


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    raw = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(_normalize_argv(raw))

    level = logging.DEBUG if getattr(args, "verbose", False) else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s  %(name)s  %(message)s",
        stream=sys.stderr,
    )

    if args.command == "delta":
        return _run_delta(args)
    return _run_report(args)


def _run_report(args: argparse.Namespace) -> int:
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


def _run_delta(args: argparse.Namespace) -> int:
    log = logging.getLogger("app.cli")

    baseline_paths = _resolve_paths(args.baseline, extensions=(".xml", ".cklb", ".nessus"))
    current_paths = _resolve_paths(args.current, extensions=(".xml", ".cklb", ".nessus"))
    benchmark_paths = (
        _resolve_paths(args.benchmarks, extensions=(".xml", ".zip"))
        if args.benchmarks
        else []
    )

    if not baseline_paths:
        log.error("No baseline results files found for: %s", args.baseline)
        return 1
    if not current_paths:
        log.error("No current results files found for: %s", args.current)
        return 1

    # Explicit (non-glob, non-directory) paths pass through _resolve_paths
    # unchecked; a typo'd filename would otherwise surface as an XML parser
    # traceback rather than a usage error.
    missing = [p for p in (*baseline_paths, *current_paths, *benchmark_paths) if not p.is_file()]
    if missing:
        log.error(
            "Input file(s) not found: %s", ", ".join(str(p) for p in missing)
        )
        return 1

    log.info(
        "Baseline files: %d  Current files: %d  Benchmark files: %d",
        len(baseline_paths),
        len(current_paths),
        len(benchmark_paths),
    )

    extract_dir = Path(tempfile.mkdtemp(prefix="stig_zip_"))
    try:
        try:
            base_res = parse_stage(baseline_paths, benchmark_paths, extract_dir)
            curr_res = parse_stage(current_paths, benchmark_paths, extract_dir)
        except PipelineError as exc:
            log.error("%s", exc)
            return 1

        for w in (*base_res.warnings, *curr_res.warnings):
            log.warning(w)

        delta = compute_delta(base_res.findings, curr_res.findings)

        # Surface delta-specific warnings (duplicate findings, asymmetric
        # benchmark coverage) the same way parse warnings are surfaced.
        for w in delta.warnings:
            log.warning(w)

        if not delta.common_hosts:
            log.warning(
                "No hosts appear in BOTH scan sets — check that hostnames "
                "match. All baseline hosts are 'not re-scanned' and all "
                "current hosts are 'new'."
            )

        output_path = (
            Path(args.output) if args.output else Path(default_delta_output_name())
        )
        log.info("Exporting delta to %s…", output_path)
        try:
            export_delta_stage(delta, output_path)
        except ValueError as exc:
            log.error("Export failed: %s", exc)
            return 1

        print(f"Delta report written: {output_path.resolve()}")
        return 0
    finally:
        shutil.rmtree(extract_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
