"""CLI entry point for STIG Compliance Parser."""
from __future__ import annotations

import argparse
import contextlib
import glob as glob_module
import logging
import os
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import TextIO

from app.core.pipeline import (
    PipelineError,
    default_delta_output_name,
    default_output_name,
    export_delta_stage,
    export_stage,
    parse_stage,
)
from app.processors.delta import DELTA_STATUSES, compute_delta
from app.reference.normalize import MAX_SHOWN_CHARS, escape_controls, safe_name

# Accepted input extensions, shared by both subcommands so a newly supported
# format only has to be added in one place. A ZIP is read as a folder in
# either slot (each member routed as if supplied loose).
_RESULT_EXTS = (".xml", ".cklb", ".nessus", ".zip")
_REFERENCE_EXTS = (".xml", ".zip", ".cklb")
_MAX_UNREADABLE_NAMED = 5   # unreadable directories named one by one; the rest are counted
_MAX_STIG_LINES = 50        # per-STIG summary lines; the rest are counted


def _file_or_link(path: Path) -> bool:
    """A file, or a link that is not to a directory. A dangling link is kept on
    purpose: the run then reads it, fails, and names it ("Could not read file")
    like any other unreadable file, instead of it vanishing here."""
    return path.is_file() or (path.is_symlink() and not path.is_dir())


def _directory_key(root: str, info: os.stat_result) -> tuple[object, ...]:
    """What identifies a directory for the walk: its device and inode, or, on a
    file system that reports no inode numbers (st_ino 0: some network shares,
    FUSE), its fully resolved path, so loops still end there."""
    if info.st_ino:
        return (info.st_dev, info.st_ino)
    return ("path", os.path.normcase(os.path.realpath(root)))


def _files_in(directory: Path, wanted: set[str], *, recursive: bool, unreadable: list[str]) -> list[Path]:
    """The files in *directory* whose lower-cased suffix is in *wanted*, sorted.

    With *recursive*, every subdirectory too, and a symlinked one is followed
    on purpose (a STIG folder kept elsewhere); each directory is read once
    (:func:`_directory_key`), so a second link to a folder adds nothing and a
    link loop ends. Within a directory, real subdirectories are walked before
    links, then by name, so which way into a folder names its files does not
    depend on listing order. A directory that cannot be listed is added to
    *unreadable*: it is reported, never skipped in silence. A dangling link
    is kept (:func:`_file_or_link`).
    """
    if not recursive:
        try:
            with os.scandir(directory) as entries:
                found = [Path(entry.path) for entry in entries]
        except OSError:
            unreadable.append(str(directory))
            return []
        return sorted(e for e in found if e.suffix.lower() in wanted and _file_or_link(e))

    def listing_failed(exc: OSError) -> None:
        unreadable.append(exc.filename if isinstance(exc.filename, str) else str(directory))

    visited: set[tuple[object, ...]] = set()
    found = []
    for root, dirs, files in os.walk(directory, onerror=listing_failed, followlinks=True):
        try:
            key = _directory_key(root, os.stat(root))
        except OSError:
            unreadable.append(root)
            dirs[:] = []
            continue
        if key in visited:
            dirs[:] = []        # reached again through a link: already read
            continue
        visited.add(key)
        dirs.sort(key=lambda name: (os.path.islink(os.path.join(root, name)), name))
        found.extend(Path(root, name) for name in files if Path(name).suffix.lower() in wanted)
    return sorted(e for e in found if _file_or_link(e))


def _resolve_paths(
    args: list[str], extensions: tuple[str, ...] = (".xml",), *, recursive: bool = False
) -> list[Path]:
    """Expand directories and glob patterns into a flat list of Paths.

    Directories are scanned for files whose suffix is one of *extensions* in
    any letter case (a pattern match would be case-sensitive on Linux), in
    sorted order, including every subdirectory when *recursive* (a folder of
    STIG references works as a library; see :func:`_files_in`). Each
    directory that could not be read gets a warning. Globs and explicit file
    paths pass through unchanged.
    """
    wanted = {ext.lower() for ext in extensions}
    paths: list[Path] = []
    unreadable: list[str] = []
    for arg in args:
        p = Path(arg)
        if p.is_dir():
            paths.extend(_files_in(p, wanted, recursive=recursive, unreadable=unreadable))
        elif "*" in arg or "?" in arg or "[" in arg:
            matched = [Path(m) for m in glob_module.glob(arg, recursive=True)]
            paths.extend(sorted(matched))
        else:
            paths.append(p)
    log = logging.getLogger("app.cli")
    for name in unreadable[:_MAX_UNREADABLE_NAMED]:
        log.warning("could not read directory %s", escape_controls(name))
    if len(unreadable) > _MAX_UNREADABLE_NAMED:
        log.warning("… and %d more directories could not be read", len(unreadable) - _MAX_UNREADABLE_NAMED)
    return paths


_SUBCOMMANDS = ("report", "delta")
# Options whose values may themselves be paths named like a subcommand.
# A one-value option consumes exactly the next token; a multi-value option
# (nargs "+" / "*") consumes every following token up to the next flag.
_ONE_VALUE_OPTS = ("--output",)
_MULTI_VALUE_OPTS = ("--results", "--references", "--benchmarks", "--baseline", "--current")


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
            "checklists (.cklb) / .nessus, ZIPs of them, or a directory (not "
            "scanned recursively; supports globs)."
        ),
    )
    rp.add_argument(
        "--references", "--benchmarks",
        dest="references",
        nargs="*",
        required=False,
        default=None,
        metavar="PATH",
        help=(
            "STIG references that fill blank check/fix text: Manual STIG XML, "
            "DISA STIG ZIP, SCAP benchmark, or .cklb checklist; a directory is "
            "scanned recursively, so one folder of STIGs works as a library. "
            "SCC results carry fix text only — add the Manual STIG for check "
            "text. (--benchmarks is accepted as an alias.)"
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
        "--references", "--benchmarks",
        dest="references",
        nargs="*",
        required=False,
        default=None,
        metavar="PATH",
        help="STIG references applied to BOTH sets (see report --references).",
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


def _utf8(stream: TextIO) -> TextIO:
    """*stream* (the log's), writing UTF-8; a character it cannot write becomes an escape.

    Redirected on Windows, stderr is in the ANSI code page (cp1252), so the
    em-dashes, ellipses and non-ASCII names in log lines came out garbled. A
    stream that cannot be reconfigured is left as it is.
    """
    if hasattr(stream, "reconfigure"):
        with contextlib.suppress(OSError, ValueError):
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
    return stream


def main(argv: list[str] | None = None) -> int:
    stream = _utf8(sys.stderr)      # first: usage errors are printed there too
    _utf8(sys.stdout)               # --help and the report path are printed there
    parser = _build_parser()
    raw = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(_normalize_argv(raw))

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s  %(name)s  %(message)s",
        stream=stream,
    )

    if args.command == "delta":
        return _run_delta(args)
    return _run_report(args)


def _run_report(args: argparse.Namespace) -> int:
    log = logging.getLogger("app.cli")

    # Resolve file paths. A reference directory is scanned recursively (a
    # folder of STIGs is a library); a results directory is not.
    results_paths = _resolve_paths(args.results, extensions=_RESULT_EXTS)
    reference_paths = (
        _resolve_paths(args.references, extensions=_REFERENCE_EXTS, recursive=True)
        if args.references
        else []
    )

    if not results_paths:
        log.error("No results files found for: %s", args.results)
        return 1

    log.info("Results files:   %d", len(results_paths))
    log.info("Reference files: %d", len(reference_paths))

    extract_dir = Path(tempfile.mkdtemp(prefix="stig_zip_"))
    try:
        try:
            result = parse_stage(results_paths, reference_paths, extract_dir)
        except PipelineError as exc:
            # The per-file warnings collected before the failure are the
            # diagnosis; show them ahead of the error.
            for w in exc.warnings:
                log.warning("%s", escape_controls(w))
            log.error("%s", escape_controls(str(exc)))
            return 1

        for w in result.warnings:
            log.warning("%s", escape_controls(w))

        log.info("Actionable findings: %d", len(result.findings))
        # What enrichment did, per STIG. A finding matched but refused (several
        # matches, or its STIG ID under another STIG's title) is counted apart
        # from one no reference holds. The title comes from an upload.
        stigs = list(result.enrichment.stigs.items())
        for title, counts in stigs[:_MAX_STIG_LINES]:
            log.info(
                "%s — check text filled: %d, fix text filled: %d, severity filled: %d, from a "
                "different release: %d, not in a supplied reference: %d, several matches: %d, "
                "other STIG title: %d",
                safe_name(title, MAX_SHOWN_CHARS), counts.filled_check, counts.filled_fix,
                counts.filled_severity, counts.drifted, counts.unmatched, counts.ambiguous,
                counts.product_refused,
            )
        if len(stigs) > _MAX_STIG_LINES:
            log.info("… and %d more STIG(s)", len(stigs) - _MAX_STIG_LINES)

        if args.output:
            output_path = Path(args.output)
        else:
            output_path = Path(default_output_name())

        log.info("Exporting to %s…", output_path)
        try:
            export_stage(result.findings, output_path, enrichment=result.enrichment, warnings=result.warnings)
        except Exception as exc:
            log.error("Export failed: %s", escape_controls(str(exc)))
            return 1

        print(f"Report written: {output_path.resolve()}")
        return 0
    finally:
        shutil.rmtree(extract_dir, ignore_errors=True)


def _run_delta(args: argparse.Namespace) -> int:
    log = logging.getLogger("app.cli")

    baseline_paths = _resolve_paths(args.baseline, extensions=_RESULT_EXTS)
    current_paths = _resolve_paths(args.current, extensions=_RESULT_EXTS)
    reference_paths = (
        _resolve_paths(args.references, extensions=_REFERENCE_EXTS, recursive=True)
        if args.references
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
    missing = [p for p in (*baseline_paths, *current_paths, *reference_paths) if not p.is_file()]
    if missing:
        log.error(
            "Input file(s) not found: %s", ", ".join(str(p) for p in missing)
        )
        return 1

    log.info(
        "Baseline files: %d  Current files: %d  Reference files: %d",
        len(baseline_paths),
        len(current_paths),
        len(reference_paths),
    )

    extract_dir = Path(tempfile.mkdtemp(prefix="stig_zip_"))
    try:
        # Per-side extraction dirs: sharing one would expand every benchmark
        # ZIP twice (DISA STIG library ZIPs are large). Both sides take the
        # same references, so a rule is filled and titled alike in each.
        # allow_empty lets a fully remediated scan set through — zero
        # actionable findings is a legitimate delta input, not a failure.
        # On failure the per-file warnings parse_stage collected first are
        # the diagnosis: log them, with their side, ahead of the error.
        try:
            base_res = parse_stage(
                baseline_paths, reference_paths, extract_dir / "baseline",
                allow_empty=True,
            )
        except PipelineError as exc:
            for w in exc.warnings:
                log.warning("Baseline scan set: %s", escape_controls(w))
            log.error("Baseline scan set: %s", escape_controls(str(exc)))
            return 1
        try:
            curr_res = parse_stage(
                current_paths, reference_paths, extract_dir / "current",
                allow_empty=True,
            )
        except PipelineError as exc:
            for w in exc.warnings:
                log.warning("Current scan set: %s", escape_controls(w))
            log.error("Current scan set: %s", escape_controls(str(exc)))
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
            log.warning("%s", escape_controls(w))

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
            log.error("Export failed: %s", escape_controls(str(exc)))
            return 1

        print(f"Delta report written: {output_path.resolve()}")
        return 0
    finally:
        shutil.rmtree(extract_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
