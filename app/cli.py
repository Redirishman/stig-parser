"""CLI entry point for STIG Compliance Parser."""
from __future__ import annotations

import argparse
import glob as glob_module
import logging
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path

from app.core.pipeline import (
    PipelineError,
    default_delta_output_name,
    default_output_name,
    export_delta_stage,
    export_stage,
    parse_stage,
)
from app.processors.delta import DELTA_STATUSES, compute_delta

# Accepted input extensions, shared by both subcommands so a newly supported
# format only has to be added in one place.
_RESULT_EXTS = (".xml", ".cklb", ".nessus")
_BENCHMARK_EXTS = (".xml", ".zip")


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
# Options whose values may themselves be paths named like a subcommand.
# A one-value option consumes exactly the next token; a multi-value option
# (nargs "+" / "*") consumes every following token up to the next flag.
_ONE_VALUE_OPTS = ("--output",)
_MULTI_VALUE_OPTS = ("--results", "--benchmarks", "--baseline", "--current")


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

    Exits 2 if a subcommand appears somewhere other than first (e.g.
    ``stig-parser --verbose delta ...``) — silently treating that as a
    ``report`` run produces a baffling "--results is required" error about a
    flag the user never typed.
    """
    if argv and (argv[0] in _SUBCOMMANDS or argv[0] in ("-h", "--help")):
        return argv

    misplaced = _misplaced_subcommand(argv)
    if misplaced:
        print(
            f"stig-parser: error: '{misplaced}' must be the first argument: "
            f"stig-parser {misplaced} [options]",
            file=sys.stderr,
        )
        raise SystemExit(2)

    return ["report", *argv]


def _misplaced_subcommand(argv: list[str]) -> str | None:
    """Return a subcommand name typed after another argument, if any.

    The values of a value-taking option are skipped rather than ending the
    scan: a file or directory named ``report`` or ``delta`` is a legal
    ``--results`` value, but ``--output x.xlsx delta ...`` is a misplaced
    subcommand and must not be silently run as ``report``.
    """
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok in _ONE_VALUE_OPTS:
            i += 2
        elif tok in _MULTI_VALUE_OPTS:
            i += 1
            while i < len(argv) and not argv[i].startswith("-"):
                i += 1
        elif tok in _SUBCOMMANDS:
            return tok
        else:
            i += 1
    return None


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    raw = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(_normalize_argv(raw))

    level = logging.DEBUG if args.verbose else logging.INFO
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
    results_paths = _resolve_paths(args.results, extensions=_RESULT_EXTS)
    benchmark_paths = (
        _resolve_paths(args.benchmarks, extensions=_BENCHMARK_EXTS)
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
            # The per-file warnings collected before the failure are the
            # diagnosis; show them ahead of the error.
            for w in exc.warnings:
                log.warning(w)
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

    baseline_paths = _resolve_paths(args.baseline, extensions=_RESULT_EXTS)
    current_paths = _resolve_paths(args.current, extensions=_RESULT_EXTS)
    benchmark_paths = (
        _resolve_paths(args.benchmarks, extensions=_BENCHMARK_EXTS)
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
        # Per-side extraction dirs: sharing one would expand every benchmark
        # ZIP twice (DISA STIG library ZIPs are large). allow_empty lets a
        # fully remediated scan set through — zero actionable findings is a
        # legitimate delta input, not a failure.
        # On failure the per-file warnings parse_stage collected first are
        # the diagnosis: log them, with their side, ahead of the error.
        try:
            base_res = parse_stage(
                baseline_paths, benchmark_paths, extract_dir / "baseline",
                allow_empty=True,
            )
        except PipelineError as exc:
            for w in exc.warnings:
                log.warning("Baseline scan set: %s", w)
            log.error("Baseline scan set: %s", exc)
            return 1
        try:
            curr_res = parse_stage(
                current_paths, benchmark_paths, extract_dir / "current",
                allow_empty=True,
            )
        except PipelineError as exc:
            for w in exc.warnings:
                log.warning("Current scan set: %s", w)
            log.error("Current scan set: %s", exc)
            return 1

        # Parse-stage warnings (unparseable files, files with no rule
        # results) are prefixed with their side so the reader knows which
        # scan set they describe; they are echoed here and, below, added to
        # the delta warnings so the workbook carries them too. A message
        # identical on both sides (a benchmark or ZIP problem, raised once
        # per parse_stage call) is not side-specific: it is kept once under
        # "Both scan sets:" rather than twice with different prefixes.
        shared = dict.fromkeys(w for w in base_res.warnings if w in set(curr_res.warnings))
        parse_warnings = [
            *(f"Both scan sets: {w}" for w in shared),
            *(f"Baseline scan set: {w}" for w in base_res.warnings if w not in shared),
            *(f"Current scan set: {w}" for w in curr_res.warnings if w not in shared),
        ]
        for w in parse_warnings:
            log.warning(w)

        # Coverage (which host/STIG pairs each set actually scanned) comes
        # from the scans, not the finding lists: a clean scan still counts
        # as re-scanned, and a STIG left out of the current set is reported
        # as not re-scanned rather than resolved.
        delta = compute_delta(
            base_res.findings,
            curr_res.findings,
            baseline_coverage=base_res.coverage,
            current_coverage=curr_res.coverage,
        )

        # Every delta warning — duplicate findings, asymmetric benchmark
        # coverage, hosts/STIGs not re-scanned or newly scanned, no host
        # overlap — is already logged by compute_delta under its own logger
        # and lives on delta.warnings so the workbook carries it too; it is
        # not echoed again here. The parse-stage warnings are prepended so
        # the workbook's Warnings block is complete.
        delta.warnings[:0] = parse_warnings

        counts = Counter(f.delta_status for f in delta.findings)
        log.info(
            "Delta: %s across %d common host(s)",
            ", ".join(f"{counts[s]} {s.lower()}" for s in DELTA_STATUSES),
            len(delta.common_hosts),
        )

        output_path = (
            Path(args.output) if args.output else Path(default_delta_output_name())
        )
        log.info("Exporting delta to %s…", output_path)
        try:
            export_delta_stage(delta, output_path)
        except Exception as exc:
            log.error("Export failed: %s", exc)
            return 1

        print(f"Delta report written: {output_path.resolve()}")
        return 0
    finally:
        shutil.rmtree(extract_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
