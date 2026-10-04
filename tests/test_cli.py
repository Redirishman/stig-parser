"""Tests for app.cli — argument parsing, path resolution, and end-to-end runs."""
from __future__ import annotations

import logging
import re
from pathlib import Path

import pytest
from openpyxl import load_workbook

from app.cli import _build_parser, _normalize_argv, _resolve_paths, main

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

class TestArgumentParsing:
    def test_results_is_required(self):
        parser = _build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(_normalize_argv([]))

    # --benchmarks is the alias of --references; both land in args.references.
    def test_benchmarks_is_optional(self):
        parser = _build_parser()
        # No --benchmarks flag at all — must not raise
        args = parser.parse_args(_normalize_argv(["--results", "a.xml"]))
        assert args.references is None

    def test_benchmarks_accepts_empty_list(self):
        parser = _build_parser()
        args = parser.parse_args(
            _normalize_argv(["--results", "a.xml", "--benchmarks"])
        )
        assert args.references == []

    def test_benchmarks_accepts_multiple_paths(self):
        parser = _build_parser()
        args = parser.parse_args(
            _normalize_argv(
                ["--results", "a.xml", "b.xml", "--benchmarks", "x.xml", "y.zip"]
            )
        )
        assert args.results == ["a.xml", "b.xml"]
        assert args.references == ["x.xml", "y.zip"]

    def test_references_accepts_multiple_paths(self):
        parser = _build_parser()
        args = parser.parse_args(
            _normalize_argv(["--results", "a.xml", "--references", "x.xml", "lib/", "c.cklb"])
        )
        assert args.references == ["x.xml", "lib/", "c.cklb"]

    def test_a_references_path_named_like_a_subcommand_is_not_rejected(self):
        # --references is multi-value: the scan for a misplaced subcommand skips its paths.
        assert _normalize_argv(["--results", "a.xml", "--references", "delta"]) == [
            "report", "--results", "a.xml", "--references", "delta",
        ]

    def test_output_flag_parsed(self):
        parser = _build_parser()
        args = parser.parse_args(
            _normalize_argv(["--results", "a.xml", "--output", "out.xlsx"])
        )
        assert args.output == "out.xlsx"

    def test_verbose_flag_parsed(self):
        parser = _build_parser()
        args = parser.parse_args(_normalize_argv(["--results", "a.xml", "--verbose"]))
        assert args.verbose is True

    def test_verbose_default_false(self):
        parser = _build_parser()
        args = parser.parse_args(_normalize_argv(["--results", "a.xml"]))
        assert args.verbose is False


class TestDeltaArgs:
    def test_delta_subcommand_parses(self):
        parser = _build_parser()
        args = parser.parse_args(
            ["delta", "--baseline", "a.xml", "--current", "b.xml"]
        )
        assert args.command == "delta"
        assert args.baseline == ["a.xml"]
        assert args.current == ["b.xml"]

    def test_delta_accepts_benchmarks_and_output(self):
        parser = _build_parser()
        args = parser.parse_args([
            "delta", "--baseline", "a.xml", "--current", "b.xml",
            "--benchmarks", "x.xml", "--output", "d.xlsx",
        ])
        assert args.references == ["x.xml"]
        assert args.output == "d.xlsx"

    def test_report_subcommand_parses(self):
        parser = _build_parser()
        args = parser.parse_args(["report", "--results", "a.xml"])
        assert args.command == "report"
        assert args.results == ["a.xml"]

    def test_bare_results_still_works(self):
        # Back-compat: no subcommand + --results routes to report
        args = _normalize_argv(["--results", "a.xml"])
        assert args[0] == "report"

    def test_subcommand_after_a_flag_is_rejected(self, capsys):
        # Without the guard this becomes an implicit `report` run and errors
        # about --results, a flag the user never typed.
        with pytest.raises(SystemExit) as exc:
            _normalize_argv(["--verbose", "delta", "--baseline", "a.xml"])
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "'delta' must be the first argument" in err

    def test_path_named_like_a_subcommand_is_not_rejected(self):
        # Scanning stops at the first value-taking option, so a directory
        # called "delta" is still a legal --results value.
        assert _normalize_argv(["--results", "delta"]) == ["report", "--results", "delta"]

    def test_subcommand_after_a_one_value_flag_is_rejected(self, capsys):
        # --output takes exactly one value; the scan resumes after it.
        with pytest.raises(SystemExit) as exc:
            _normalize_argv(["--output", "x.xlsx", "delta", "--baseline", "a.xml"])
        assert exc.value.code == 2
        assert "'delta' must be the first argument" in capsys.readouterr().err

    def test_subcommand_after_a_multi_value_flag_is_rejected(self, capsys):
        # --results consumes every following non-flag token as a path; the
        # next flag ends that run, so a subcommand after it is misplaced.
        with pytest.raises(SystemExit) as exc:
            _normalize_argv(["--results", "a.xml", "b.xml", "--verbose", "delta"])
        assert exc.value.code == 2
        assert "'delta' must be the first argument" in capsys.readouterr().err

    def test_every_value_of_a_multi_value_flag_is_skipped(self):
        argv = ["--results", "delta", "report", "--output", "delta"]
        assert _normalize_argv(argv) == ["report", *argv]

    def test_delta_requires_baseline_and_current(self):
        parser = _build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["delta", "--baseline", "a.xml"])


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

def _deny_listing(monkeypatch, denied: set[str]) -> None:
    """Make listing any directory whose name is in *denied* raise PermissionError, as a folder
    without read access does (no real ACLs: the test must run anywhere)."""
    import os
    real = os.scandir

    def scandir(path="."):
        if Path(path).name in denied:
            raise PermissionError(13, "Permission denied", os.fspath(path))
        return real(path)

    monkeypatch.setattr(os, "scandir", scandir)


def _symlink_dir(link: Path, target: Path) -> None:
    import os
    try:
        os.symlink(target, link, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlinks cannot be created here: {exc}")


class TestDirectoryWalk:
    """A reference library is walked in full: an unreadable folder is reported, a symlinked
    folder is followed (once), a link loop ends."""

    def _library(self, tmp_path: Path) -> Path:
        lib = tmp_path / "lib"
        for name in ("a/one.xml", "b/two.xml", "b/deeper/three.cklb"):
            (lib / name).parent.mkdir(parents=True, exist_ok=True)
            (lib / name).write_text("<x/>")
        return lib

    def test_an_unreadable_folder_is_reported_not_skipped(self, tmp_path, monkeypatch, caplog):
        from app.cli import _REFERENCE_EXTS
        lib = self._library(tmp_path)
        _deny_listing(monkeypatch, {"b"})
        with caplog.at_level(logging.WARNING, logger="app.cli"):
            paths = _resolve_paths([str(lib)], extensions=_REFERENCE_EXTS, recursive=True)
        assert [p.name for p in paths] == ["one.xml"]
        assert [r.getMessage() for r in caplog.records if r.name == "app.cli"] == [
            f"could not read directory {lib / 'b'}"]

    def test_an_unreadable_results_folder_is_reported_too(self, tmp_path, monkeypatch, caplog):
        from app.cli import _RESULT_EXTS
        results = tmp_path / "results"
        results.mkdir()
        (results / "scan.xml").write_text("<x/>")
        _deny_listing(monkeypatch, {"results"})
        with caplog.at_level(logging.WARNING, logger="app.cli"):
            assert _resolve_paths([str(results)], extensions=_RESULT_EXTS) == []
        assert [r.getMessage() for r in caplog.records if r.name == "app.cli"] == [
            f"could not read directory {results}"]

    def test_unreadable_folders_are_named_five_at_most(self, tmp_path, monkeypatch, caplog):
        from app.cli import _REFERENCE_EXTS
        lib = tmp_path / "lib"
        for i in range(8):
            (lib / f"d{i}").mkdir(parents=True)
        _deny_listing(monkeypatch, {f"d{i}" for i in range(8)})
        with caplog.at_level(logging.WARNING, logger="app.cli"):
            _resolve_paths([str(lib)], extensions=_REFERENCE_EXTS, recursive=True)
        messages = [r.getMessage() for r in caplog.records if r.name == "app.cli"]
        assert len(messages) == 6 and messages[-1] == "… and 3 more directories could not be read"

    def test_a_symlinked_folder_is_followed_once(self, tmp_path):
        from app.cli import _REFERENCE_EXTS
        lib = self._library(tmp_path)
        outside = tmp_path / "elsewhere"
        outside.mkdir()
        (outside / "four.xml").write_text("<x/>")
        _symlink_dir(lib / "linked", outside)            # a STIG folder kept elsewhere
        _symlink_dir(lib / "a_again", lib / "a")          # a second way into one folder
        paths = _resolve_paths([str(lib)], extensions=_REFERENCE_EXTS, recursive=True)
        assert sorted(p.name for p in paths) == ["four.xml", "one.xml", "three.cklb", "two.xml"]

    def test_a_link_loop_ends(self, tmp_path):
        from app.cli import _REFERENCE_EXTS
        lib = self._library(tmp_path)
        _symlink_dir(lib / "b" / "deeper" / "up", lib)   # points back at the top
        paths = _resolve_paths([str(lib)], extensions=_REFERENCE_EXTS, recursive=True)
        assert sorted(p.name for p in paths) == ["one.xml", "three.cklb", "two.xml"]

    def test_a_folder_that_lists_but_cannot_be_stat_ed_is_reported(self, tmp_path, monkeypatch, caplog):
        import os
        from app.cli import _REFERENCE_EXTS
        lib = self._library(tmp_path)
        real = os.stat

        def stat(path, *args, **kwargs):
            if Path(path).name == "b":
                raise PermissionError(13, "Permission denied", os.fspath(path))
            return real(path, *args, **kwargs)

        monkeypatch.setattr(os, "stat", stat)
        with caplog.at_level(logging.WARNING, logger="app.cli"):
            paths = _resolve_paths([str(lib)], extensions=_REFERENCE_EXTS, recursive=True)
        assert [p.name for p in paths] == ["one.xml"]
        assert [r.getMessage() for r in caplog.records if r.name == "app.cli"] == [
            f"could not read directory {lib / 'b'}"]

    @pytest.mark.parametrize("with_loop", [False, True])
    def test_a_file_system_without_inode_numbers_is_walked_in_full(self, tmp_path, monkeypatch, with_loop):
        # Some network shares and FUSE file systems report st_ino 0 for every directory: read
        # by (device, inode), every directory after the first looked visited and was skipped.
        import os
        import stat as stat_module
        from app.cli import _REFERENCE_EXTS
        lib = self._library(tmp_path)
        if with_loop:
            _symlink_dir(lib / "b" / "deeper" / "up", lib)
        real = os.stat

        def stat(path, *args, **kwargs):
            r = real(path, *args, **kwargs)
            if not stat_module.S_ISDIR(r.st_mode):
                return r
            return os.stat_result((r.st_mode, 0, r.st_dev, r.st_nlink, r.st_uid, r.st_gid, r.st_size,
                                   r.st_atime, r.st_mtime, r.st_ctime))

        monkeypatch.setattr(os, "stat", stat)
        paths = _resolve_paths([str(lib)], extensions=_REFERENCE_EXTS, recursive=True)
        assert sorted(p.name for p in paths) == ["one.xml", "three.cklb", "two.xml"]

    def test_a_folder_reached_two_ways_is_named_by_its_real_path(self, tmp_path):
        # The first way into a directory wins; scandir order is arbitrary on Linux. Real
        # directories are walked before links, so the paths do not depend on that order.
        from app.cli import _REFERENCE_EXTS
        lib = tmp_path / "lib"
        (lib / "z_real").mkdir(parents=True)
        (lib / "z_real" / "x.xml").write_text("<x/>")
        _symlink_dir(lib / "a_link", lib / "z_real")       # sorts first by name
        paths = _resolve_paths([str(lib)], extensions=_REFERENCE_EXTS, recursive=True)
        assert [p.relative_to(lib).as_posix() for p in paths] == ["z_real/x.xml"]

    def test_a_dangling_link_is_kept_and_named_by_the_run(self, tmp_path, caplog):
        # Not dropped in silence: the run reads it, fails, and says so like any unreadable file.
        import os
        lib = tmp_path / "lib"
        lib.mkdir()
        try:
            os.symlink(tmp_path / "gone.xml", lib / "gone.xml")
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlinks cannot be created here: {exc}")
        from app.cli import _REFERENCE_EXTS
        assert _resolve_paths([str(lib)], extensions=_REFERENCE_EXTS, recursive=True) == [lib / "gone.xml"]
        caplog.set_level(logging.WARNING)
        assert main(["report", "--results", str(FIXTURES / "scc_embedded_results.xml"),
                     "--references", str(lib), "--output", str(tmp_path / "r.xlsx")]) == 0
        assert any(r.getMessage() == "Could not read file: gone.xml"
                   for r in caplog.records if r.name == "app.cli"), [r.getMessage() for r in caplog.records]


def test_the_per_stig_summary_is_capped_at_50_lines(tmp_path, caplog, monkeypatch):
    import app.cli as cli
    from app.core.pipeline import parse_stage as real_parse_stage
    from app.reference.enrich import StigCounts

    def parse_with_many_stigs(*args, **kwargs):
        result = real_parse_stage(*args, **kwargs)
        result.enrichment.stigs = {f"STIG {i:02d}": StigCounts() for i in range(53)}
        return result

    monkeypatch.setattr(cli, "parse_stage", parse_with_many_stigs)
    caplog.set_level(logging.INFO)
    assert main(["report", "--results", str(FIXTURES / "scc_embedded_results.xml"),
                 "--output", str(tmp_path / "r.xlsx")]) == 0
    lines = [r.getMessage() for r in caplog.records if r.name == "app.cli" and "check text filled" in r.getMessage()]
    assert len(lines) == 50 and lines[-1].startswith("STIG 49 — ")
    assert any(r.getMessage() == "… and 3 more STIG(s)" for r in caplog.records if r.name == "app.cli")


class TestResolvePaths:
    def test_a_directory_scan_matches_extensions_in_any_case_and_only_files(self, tmp_path):
        # Whatever the file system's case rules: .XML, .Cklb, .ZIP are found; a folder named
        # like a file is not a file; the order is the sorted paths, not one run per extension.
        from app.cli import _REFERENCE_EXTS, _RESULT_EXTS
        for name in ("d.xml", "a.XML", "c.ZIP", "b.Cklb", "e.txt", "sub/f.Xml"):
            (tmp_path / name).parent.mkdir(exist_ok=True)
            (tmp_path / name).write_text("<x/>")
        (tmp_path / "folder.xml").mkdir()
        flat = _resolve_paths([str(tmp_path)], extensions=_RESULT_EXTS)
        assert [p.name for p in flat] == ["a.XML", "b.Cklb", "c.ZIP", "d.xml"]
        deep = _resolve_paths([str(tmp_path)], extensions=_REFERENCE_EXTS, recursive=True)
        assert [p.relative_to(tmp_path).as_posix() for p in deep] == [
            "a.XML", "b.Cklb", "c.ZIP", "d.xml", "sub/f.Xml"]

    def test_directory_resolves_to_xml_files(self, tmp_path):
        (tmp_path / "a.xml").write_text("<a/>")
        (tmp_path / "b.xml").write_text("<b/>")
        (tmp_path / "skip.txt").write_text("not xml")
        paths = _resolve_paths([str(tmp_path)])
        names = sorted(p.name for p in paths)
        assert names == ["a.xml", "b.xml"]

    def test_directory_with_zip_extension_filter(self, tmp_path):
        (tmp_path / "a.xml").write_text("<a/>")
        (tmp_path / "b.zip").write_bytes(b"PK\x03\x04")
        paths = _resolve_paths([str(tmp_path)], extensions=(".xml", ".zip"))
        names = sorted(p.name for p in paths)
        assert names == ["a.xml", "b.zip"]

    def test_explicit_file_passes_through(self, tmp_path):
        f = tmp_path / "single.xml"
        f.write_text("<x/>")
        paths = _resolve_paths([str(f)])
        assert paths == [f]

    def test_glob_pattern_expanded(self, tmp_path):
        (tmp_path / "scan1.xml").write_text("<x/>")
        (tmp_path / "scan2.xml").write_text("<x/>")
        (tmp_path / "other.xml").write_text("<x/>")
        paths = _resolve_paths([str(tmp_path / "scan*.xml")])
        names = sorted(p.name for p in paths)
        assert names == ["scan1.xml", "scan2.xml"]


# ---------------------------------------------------------------------------
# End-to-end main() invocations
# ---------------------------------------------------------------------------

class TestMainSeparateBenchmarks:
    """Traditional flow: --results + --benchmarks both supplied."""

    def test_separate_benchmark_produces_workbook(self, tmp_path):
        out = tmp_path / "out.xlsx"
        rc = main([
            "--results", str(FIXTURES / "scc_results.xml"),
            "--benchmarks", str(FIXTURES / "sample_benchmark.xml"),
            "--output", str(out),
        ])
        assert rc == 0
        assert out.exists()
        wb = load_workbook(str(out))
        assert {"Findings", "Summary"} <= set(wb.sheetnames)
        # Findings sheet has data rows beyond the header
        assert wb["Findings"].max_row >= 2


class TestMainOptionalBenchmarks:
    """SCC self-contained flow: --benchmarks omitted, results used for both sides."""

    def test_no_benchmarks_flag_uses_results_files(self, tmp_path, caplog):
        out = tmp_path / "out.xlsx"
        with caplog.at_level(logging.INFO, logger="app.cli"):
            rc = main([
                "--results", str(FIXTURES / "scc_results.xml"),
                "--output", str(out),
            ])
        assert rc == 0
        assert out.exists()
        # The run says it used no reference (the old "No --benchmarks
        # supplied" line no longer described what happens, and is gone).
        messages = [r.message for r in caplog.records if r.name == "app.cli"]
        assert "Reference files: 0" in messages, messages
        assert not any("No --benchmarks supplied" in m for m in messages)

    def test_empty_benchmarks_flag_also_uses_results_files(self, tmp_path):
        """`--benchmarks` with no values should behave like omitting the flag."""
        out = tmp_path / "out.xlsx"
        rc = main([
            "--results", str(FIXTURES / "scc_results.xml"),
            "--benchmarks",
            "--output", str(out),
        ])
        assert rc == 0
        assert out.exists()


class TestMainErrorCases:
    def test_empty_results_dir_exits_nonzero(self, tmp_path, caplog):
        """An empty directory has no .xml files → 'No results files found' → exit 1."""
        empty = tmp_path / "empty"
        empty.mkdir()
        out = tmp_path / "out.xlsx"
        with caplog.at_level(logging.ERROR, logger="app.cli"):
            rc = main([
                "--results", str(empty),
                "--benchmarks", str(FIXTURES / "sample_benchmark.xml"),
                "--output", str(out),
            ])
        assert rc == 1
        assert not out.exists()
        assert any(
            "No results files found" in r.message for r in caplog.records
        )


# ---------------------------------------------------------------------------
# Delta subcommand, end to end
# ---------------------------------------------------------------------------

def _variant(path: Path, dest: Path, replacements: dict[str, str]) -> Path:
    """Write a copy of the SCC fixture at *dest* with edits applied.

    Each key must appear exactly once in the source so a fixture change can
    never silently turn an edit into a no-op. (A "not unique" failure here
    almost always means the fixture was reformatted, not that the test is
    wrong — re-anchor the string against the current fixture text.)
    """
    text = path.read_text(encoding="utf-8")
    for old, new in replacements.items():
        assert text.count(old) == 1, f"{old!r} is not unique in {path.name}"
        text = text.replace(old, new)
    dest.write_text(text, encoding="utf-8")
    return dest


def _delta_rows(path: Path) -> dict[str, str]:
    """Map Rule ID -> Delta status from a delta workbook's Findings sheet.

    Asserts the mapping is lossless: two rows for one rule (e.g. the same
    unchanged finding emitted as both Resolved and New — the bug
    ``_match_two_pass`` exists to prevent) would otherwise collapse into one
    key and go unnoticed.
    """
    ws = load_workbook(path)["Findings"]
    rows = {
        ws.cell(row=r, column=4).value: ws.cell(row=r, column=1).value
        for r in range(2, ws.max_row + 1)
    }
    assert len(rows) == ws.max_row - 1, (
        f"{ws.max_row - 1} finding rows collapsed into {len(rows)} rule IDs "
        "— the sheet contains duplicate rows for a rule"
    )
    return rows


class TestDeltaEndToEnd:
    def test_delta_run_writes_workbook(self, tmp_path):
        # Same file as both baseline and current -> every finding Persisting.
        fixture = FIXTURES / "scc_results.xml"
        out = tmp_path / "delta.xlsx"
        rc = main([
            "delta",
            "--baseline", str(fixture),
            "--current", str(fixture),
            "--output", str(out),
        ])
        assert rc == 0
        assert out.exists()
        wb = load_workbook(out)
        assert "Findings" in wb.sheetnames and "Summary" in wb.sheetnames
        ws = wb["Findings"]
        tags = {ws.cell(row=r, column=1).value for r in range(2, ws.max_row + 1)}
        assert tags == {"Persisting"}

    def test_delta_tags_new_resolved_and_persisting(self, tmp_path):
        """A genuine change on one host produces all three delta statuses.

        SV-254239 goes fail -> pass (drops out of the current findings, so it
        is inferred Resolved); SV-254240 goes pass -> fail (New); the three
        remaining actionable rules are unchanged (Persisting).

        The benchmark is supplied so the STIG is titled: a scan that matched
        no benchmark fails closed (R2-9) and can never be Resolved or New.
        """
        baseline = FIXTURES / "scc_results.xml"
        # Anchor each edit to its rule-result element so the two status
        # swaps can't overlap.
        r239 = (
            'idref="xccdf_mil.disa.stig_rule_SV-254239r945408_rule" '
            'severity="high" time="2024-11-15T08:05:00">\n    <cdf:result>'
        )
        r240 = (
            'idref="xccdf_mil.disa.stig_rule_SV-254240r945411_rule" '
            'severity="medium" time="2024-11-15T08:05:30">\n    <cdf:result>'
        )
        current = _variant(
            baseline,
            tmp_path / "current.xml",
            {
                f"{r239}fail<": f"{r239}pass<",
                f"{r240}pass<": f"{r240}fail<",
            },
        )
        out = tmp_path / "delta.xlsx"
        rc = main([
            "delta",
            "--baseline", str(baseline),
            "--current", str(current),
            "--benchmarks", str(FIXTURES / "sample_benchmark.xml"),
            "--output", str(out),
        ])
        assert rc == 0
        rows = _delta_rows(out)
        assert rows == {
            "xccdf_mil.disa.stig_rule_SV-254239r945408_rule": "Resolved",
            "xccdf_mil.disa.stig_rule_SV-254240r945411_rule": "New",
            "xccdf_mil.disa.stig_rule_SV-254241r945414_rule": "Persisting",
            "xccdf_mil.disa.stig_rule_SV-254242r945417_rule": "Persisting",
            "xccdf_mil.disa.stig_rule_SV-254243r945420_rule": "Persisting",
            "xccdf_mil.disa.stig_rule_SV-254245r945426_rule": "Persisting",
        }

    def test_delta_with_benchmarks_flag(self, tmp_path):
        """--benchmarks applies to both scan sets and populates Vuln IDs."""
        fixture = FIXTURES / "scc_results.xml"
        out = tmp_path / "delta.xlsx"
        rc = main([
            "delta",
            "--baseline", str(fixture),
            "--current", str(fixture),
            "--benchmarks", str(FIXTURES / "sample_benchmark.xml"),
            "--output", str(out),
        ])
        assert rc == 0
        ws = load_workbook(out)["Findings"]
        vuln_ids = {ws.cell(row=r, column=3).value for r in range(2, ws.max_row + 1)}
        assert vuln_ids and all(v and v.startswith("V-") for v in vuln_ids)

    def test_delta_warnings_are_logged_exactly_once(self, tmp_path, caplog):
        """compute_delta's warnings must reach the operator via the CLI run's
        log - once. compute_delta logs each warning under its own logger;
        the CLI must not echo the same text a second time under "app.cli".

        The current set gains a rule that sample_benchmark.xml does not
        define, so its Vuln-ID coverage differs from the baseline's — the
        asymmetric-coverage warning compute_delta emits for exactly that case.
        """
        baseline = FIXTURES / "scc_results.xml"
        extra_rule = (
            '  <cdf:rule-result idref="xccdf_mil.disa.stig_rule_SV-999999r000001_rule"'
            ' severity="medium" time="2024-11-15T08:09:00">\n'
            "    <cdf:result>fail</cdf:result>\n"
            "  </cdf:rule-result>\n\n"
            '  <cdf:score system="urn:xccdf:scoring:default"'
        )
        current = _variant(
            baseline,
            tmp_path / "current.xml",
            {'  <cdf:score system="urn:xccdf:scoring:default"': extra_rule},
        )
        out = tmp_path / "delta.xlsx"
        with caplog.at_level(logging.WARNING):
            rc = main([
                "delta",
                "--baseline", str(baseline),
                "--current", str(current),
                "--benchmarks", str(FIXTURES / "sample_benchmark.xml"),
                "--output", str(out),
            ])
        assert rc == 0
        hits = [
            (r.name, r.message) for r in caplog.records
            if "have no V-ID, so they were matched by rule ID instead" in r.message
        ]
        assert len(hits) == 1, f"delta warning must be logged exactly once: {hits}"

    def test_parse_warning_shared_by_both_sides_is_logged_once(self, tmp_path, caplog):
        """A benchmark that fails to parse is reported by parse_stage once
        per side with an identical message. That is not side-specific, so the
        CLI keeps ONE copy, prefixed "Both scan sets:", in the log and on the
        workbook - never the same text twice under "Baseline scan set:" and
        "Current scan set:"."""
        good = FIXTURES / "scc_results.xml"
        bad_bench = tmp_path / "bad_bench.xml"
        bad_bench.write_text("<Benchmark><unclosed>", encoding="utf-8")
        out = tmp_path / "delta.xlsx"
        with caplog.at_level(logging.WARNING, logger="app.cli"):
            rc = main([
                "delta",
                "--baseline", str(good),
                "--current", str(good),
                "--benchmarks", str(bad_bench), str(FIXTURES / "sample_benchmark.xml"),
                "--output", str(out),
            ])
        assert rc == 0
        hits = [
            r.message for r in caplog.records
            if r.name == "app.cli" and "bad_bench.xml" in r.message
        ]
        assert len(hits) == 1, f"shared parse warning must be logged once: {hits}"
        assert hits[0].startswith("Both scan sets: "), hits
        listed = [w for w in _warning_rows(load_workbook(out)["Summary"]) if "bad_bench.xml" in w]
        assert len(listed) == 1 and listed[0].startswith("Both scan sets: "), listed

    def test_fully_remediated_current_scan_is_all_resolved(self, tmp_path, caplog):
        """A current scan with zero actionable findings must not abort, and
        every baseline finding on it must be Resolved.

        100% remediation is the operator's best possible outcome. The clean
        scan still records which host/STIG it covered (ParseResult.coverage),
        so compute_delta can tell "fully remediated" from "not re-scanned".
        The benchmark is supplied so the STIG is titled (R2-9).
        """
        baseline = FIXTURES / "scc_results.xml"
        clean = tmp_path / "clean.xml"
        clean.write_text(
            re.sub(
                r"<cdf:result>\w+</cdf:result>",
                "<cdf:result>pass</cdf:result>",
                baseline.read_text(encoding="utf-8"),
            ),
            encoding="utf-8",
        )
        out = tmp_path / "delta.xlsx"
        with caplog.at_level(logging.INFO, logger="app.cli"):
            rc = main([
                "delta",
                "--baseline", str(baseline),
                "--current", str(clean),
                "--benchmarks", str(FIXTURES / "sample_benchmark.xml"),
                "--output", str(out),
            ])
        assert rc == 0, "a fully remediated current scan must not fail the run"
        rows = _delta_rows(out)
        assert len(rows) == 5
        assert set(rows.values()) == {"Resolved"}
        assert any(
            "Delta: 0 new, 5 resolved, 0 persisting, 0 not re-scanned, "
            "0 newly scanned across 1 common host(s)" in r.message
            for r in caplog.records
        ), [r.message for r in caplog.records]

    def test_fully_clean_baseline_still_reports(self, tmp_path):
        """A baseline with zero actionable findings is legitimate too.

        (Clean baseline, findings appear later: every current finding is New.
        The benchmark is supplied so the STIG is titled, R2-9.)
        """
        current = FIXTURES / "scc_results.xml"
        clean = tmp_path / "clean.xml"
        clean.write_text(
            re.sub(
                r"<cdf:result>\w+</cdf:result>",
                "<cdf:result>pass</cdf:result>",
                current.read_text(encoding="utf-8"),
            ),
            encoding="utf-8",
        )
        out = tmp_path / "delta.xlsx"
        rc = main([
            "delta",
            "--baseline", str(clean),
            "--current", str(current),
            "--benchmarks", str(FIXTURES / "sample_benchmark.xml"),
            "--output", str(out),
        ])
        assert rc == 0
        assert set(_delta_rows(out).values()) == {"New"}

    def test_parse_failure_names_the_offending_scan_set(self, tmp_path, caplog):
        """The operator must not have to bisect to learn which side failed."""
        good = FIXTURES / "scc_results.xml"
        broken = tmp_path / "broken.xml"
        broken.write_text("<TestResult><unclosed>", encoding="utf-8")

        for bad_side, other, expected in (
            ("--baseline", "--current", "Baseline scan set"),
            ("--current", "--baseline", "Current scan set"),
        ):
            caplog.clear()
            with caplog.at_level(logging.ERROR, logger="app.cli"):
                rc = main([
                    "delta", bad_side, str(broken), other, str(good),
                    "--output", str(tmp_path / "delta.xlsx"),
                ])
            assert rc == 1
            assert any(expected in r.message for r in caplog.records), (
                f"{bad_side} failure not attributed to '{expected}': "
                f"{[r.message for r in caplog.records]}"
            )

    def test_partially_remediated_scan_tags_resolved(self, tmp_path, caplog):
        """Remediated findings on a still-reporting host are tagged Resolved.

        The benchmark is supplied so the STIG is titled (R2-9).
        """
        baseline = FIXTURES / "scc_results.xml"
        # Everything passes except SV-254239, so the host still appears in the
        # current run and its four other findings are inferred Resolved.
        text = re.sub(
            r"<cdf:result>\w+</cdf:result>",
            "<cdf:result>pass</cdf:result>",
            baseline.read_text(encoding="utf-8"),
        )
        keep = (
            'idref="xccdf_mil.disa.stig_rule_SV-254239r945408_rule" '
            'severity="high" time="2024-11-15T08:05:00">\n    <cdf:result>'
        )
        assert text.count(f"{keep}pass<") == 1
        current = tmp_path / "current.xml"
        current.write_text(text.replace(f"{keep}pass<", f"{keep}fail<"), encoding="utf-8")

        out = tmp_path / "delta.xlsx"
        with caplog.at_level(logging.INFO, logger="app.cli"):
            rc = main([
                "delta",
                "--baseline", str(baseline),
                "--current", str(current),
                "--benchmarks", str(FIXTURES / "sample_benchmark.xml"),
                "--output", str(out),
            ])
        assert rc == 0
        rows = _delta_rows(out)
        assert sorted(rows.values()) == ["Persisting", "Resolved", "Resolved", "Resolved", "Resolved"]
        assert rows["xccdf_mil.disa.stig_rule_SV-254239r945408_rule"] == "Persisting"
        # The console summary must match the workbook (headless/CI operators
        # only ever see this line).
        assert any(
            "Delta: 0 new, 4 resolved, 1 persisting, 0 not re-scanned, "
            "0 newly scanned across 1 common host(s)" in r.message
            for r in caplog.records
        ), [r.message for r in caplog.records]

    def test_parse_warnings_from_both_sides_are_logged(self, tmp_path, caplog):
        """parse_stage warnings from BOTH scan sets must reach the operator.

        Each set gets one unreadable XML file; the resulting warnings name
        the offending file, so a drain that lost either the baseline or the
        current half is detectable.
        """
        good = FIXTURES / "scc_results.xml"
        bad_baseline = tmp_path / "bad_baseline.xml"
        bad_current = tmp_path / "bad_current.xml"
        for p in (bad_baseline, bad_current):
            p.write_text("<TestResult><unclosed>", encoding="utf-8")

        out = tmp_path / "delta.xlsx"
        with caplog.at_level(logging.WARNING, logger="app.cli"):
            rc = main([
                "delta",
                "--baseline", str(good), str(bad_baseline),
                "--current", str(good), str(bad_current),
                "--output", str(out),
            ])
        assert rc == 0
        # Only records the CLI itself emitted — the parsers log their own
        # copies under different logger names.
        cli_warnings = [r.message for r in caplog.records if r.name == "app.cli"]
        assert any("bad_baseline.xml" in m for m in cli_warnings), (
            f"baseline parse warnings not surfaced by the CLI: {cli_warnings}"
        )
        assert any("bad_current.xml" in m for m in cli_warnings), (
            f"current parse warnings not surfaced by the CLI: {cli_warnings}"
        )

    def test_missing_baseline_file_returns_1(self, tmp_path, caplog):
        """A nonexistent --baseline path fails cleanly, without a traceback."""
        out = tmp_path / "delta.xlsx"
        with caplog.at_level(logging.ERROR, logger="app.cli"):
            rc = main([
                "delta",
                "--baseline", str(tmp_path / "nope.xml"),
                "--current", str(FIXTURES / "scc_results.xml"),
                "--output", str(out),
            ])
        assert rc == 1
        assert not out.exists()
        assert any(
            r.levelno >= logging.ERROR and "nope.xml" in r.message
            for r in caplog.records
        ), "the error must name the path that wasn't found"

    def test_unwritable_output_exits_cleanly(self, tmp_path, caplog):
        """Export failures (locked/unwritable file, missing dir) exit 1, not a
        traceback — an operator re-running with the workbook open in Excel
        hits this."""
        fixture = FIXTURES / "scc_results.xml"
        out = tmp_path / "no_such_dir" / "delta.xlsx"
        with caplog.at_level(logging.ERROR, logger="app.cli"):
            rc = main([
                "delta",
                "--baseline", str(fixture),
                "--current", str(fixture),
                "--output", str(out),
            ])
        assert rc == 1
        assert any("Export failed" in r.message for r in caplog.records)

    def test_default_output_name_is_a_delta_workbook(self, tmp_path, monkeypatch):
        """Without --output the file must be stig_delta_*, not stig_findings_*."""
        fixture = FIXTURES / "scc_results.xml"
        monkeypatch.chdir(tmp_path)
        rc = main([
            "delta", "--baseline", str(fixture), "--current", str(fixture),
        ])
        assert rc == 0
        written = [p.name for p in tmp_path.glob("*.xlsx")]
        assert len(written) == 1, written
        assert written[0].startswith("stig_delta_"), written

    def test_baseline_hosts_not_rescanned_are_reported(self, tmp_path, caplog):
        """Partial host coverage is warned about, not silently dropped."""
        baseline_a = FIXTURES / "scc_results.xml"
        baseline_b = _variant(
            baseline_a,
            tmp_path / "host02.xml",
            {"<cdf:target>WIN-SERVER-01</cdf:target>": "<cdf:target>WIN-SERVER-02</cdf:target>"},
        )
        out = tmp_path / "delta.xlsx"
        with caplog.at_level(logging.WARNING, logger="app.cli"):
            rc = main([
                "delta",
                "--baseline", str(baseline_a), str(baseline_b),
                "--current", str(baseline_a),
                "--output", str(out),
            ])
        assert rc == 0
        assert any(
            "not re-scanned" in r.message and "WIN-SERVER-02" in r.message
            for r in caplog.records
        ), "unscanned baseline hosts must be named"
        # ...and its findings stay on the report, tagged — never Resolved.
        ws = load_workbook(out)["Findings"]
        by_host: dict[str, set[str]] = {}
        for r in range(2, ws.max_row + 1):
            by_host.setdefault(ws.cell(row=r, column=8).value, set()).add(
                ws.cell(row=r, column=1).value
            )
        assert by_host == {
            "WIN-SERVER-01": {"Persisting"},
            "WIN-SERVER-02": {"Not re-scanned"},
        }

    def test_no_common_hosts_warns(self, tmp_path, caplog):
        """Disjoint hostnames make Resolved uninferable — the operator is told."""
        baseline = FIXTURES / "scc_results.xml"
        current = _variant(
            baseline,
            tmp_path / "current.xml",
            {"<cdf:target>WIN-SERVER-01</cdf:target>": "<cdf:target>WIN-SERVER-99</cdf:target>"},
        )
        out = tmp_path / "delta.xlsx"
        with caplog.at_level(logging.WARNING, logger="app.cli"):
            rc = main([
                "delta",
                "--baseline", str(baseline),
                "--current", str(current),
                "--output", str(out),
            ])
        assert rc == 0
        assert any(
            "No hosts appear in BOTH scan sets" in r.message for r in caplog.records
        )
        ws = load_workbook(out)["Findings"]
        tags = {ws.cell(row=r, column=1).value for r in range(2, ws.max_row + 1)}
        assert tags == {"Not re-scanned", "Newly scanned"}


def _second_stig(tmp_path: Path) -> tuple[Path, Path]:
    """A second STIG scanned on the same host: the Windows fixture pair
    (results + benchmark) re-identified as "Microsoft Edge" with its own
    benchmark id and rule/vuln IDs, so nothing collides with the original."""
    edits = {
        "V-2542": "V-9942",  # also rewrites SV-2542... rule IDs
        "MS_Windows_Server_2022_STIG": "MS_Edge_STIG",
        "Microsoft Windows Server 2022 Security Technical Implementation Guide":
            "Microsoft Edge Security Technical Implementation Guide",
    }
    out = []
    for src in (FIXTURES / "scc_results.xml", FIXTURES / "sample_benchmark.xml"):
        text = src.read_text(encoding="utf-8")
        for old, new in edits.items():
            text = text.replace(old, new)
        dest = tmp_path / f"edge_{src.name}"
        dest.write_text(text, encoding="utf-8")
        out.append(dest)
    return out[0], out[1]


def _pair_rows(summary_ws, label: str) -> list[tuple[str, str]]:
    """(host, STIG) rows listed under *label* in the Summary Coverage block."""
    r = next(
        i for i in range(1, summary_ws.max_row + 1)
        if summary_ws.cell(row=i, column=1).value == label
    )
    n = summary_ws.cell(row=r, column=2).value
    return [
        (summary_ws.cell(row=r + 1 + i, column=2).value,
         summary_ws.cell(row=r + 1 + i, column=3).value)
        for i in range(n)
    ]


class TestDeltaStigCoverageEndToEnd:
    """The live defect: one host, several STIGs, and a current set that
    omits one STIG scan. Its findings must be Not re-scanned, never Resolved
    — and the gap must be visible in the log AND on the workbook."""

    def test_stig_not_rescanned_is_never_resolved(self, tmp_path, caplog):
        win_results = FIXTURES / "scc_results.xml"
        win_bench = FIXTURES / "sample_benchmark.xml"
        edge_results, edge_bench = _second_stig(tmp_path)
        out = tmp_path / "delta.xlsx"
        with caplog.at_level(logging.WARNING, logger="app.cli"):
            rc = main([
                "delta",
                "--baseline", str(win_results), str(edge_results),
                "--current", str(win_results),
                "--benchmarks", str(win_bench), str(edge_bench),
                "--output", str(out),
            ])
        assert rc == 0
        rows = _delta_rows(out)
        edge = {k: v for k, v in rows.items() if "SV-9942" in k}
        win = {k: v for k, v in rows.items() if "SV-9942" not in k}
        assert len(edge) == 5 and set(edge.values()) == {"Not re-scanned"}
        assert len(win) == 5 and set(win.values()) == {"Persisting"}
        assert "Resolved" not in rows.values()
        assert any(
            "not re-scanned" in r.message.lower()
            and "WIN-SERVER-01" in r.message
            and "Microsoft Edge" in r.message
            for r in caplog.records
        ), [r.message for r in caplog.records]
        listed = _pair_rows(load_workbook(out)["Summary"], "Host / STIG pairs not re-scanned")
        assert len(listed) == 1
        assert listed[0][0] == "WIN-SERVER-01" and "Microsoft Edge" in listed[0][1]

    def test_newly_scanned_stig_is_never_new(self, tmp_path, caplog):
        win_results = FIXTURES / "scc_results.xml"
        win_bench = FIXTURES / "sample_benchmark.xml"
        edge_results, edge_bench = _second_stig(tmp_path)
        out = tmp_path / "delta.xlsx"
        with caplog.at_level(logging.WARNING, logger="app.cli"):
            rc = main([
                "delta",
                "--baseline", str(win_results),
                "--current", str(win_results), str(edge_results),
                "--benchmarks", str(win_bench), str(edge_bench),
                "--output", str(out),
            ])
        assert rc == 0
        rows = _delta_rows(out)
        edge = {k: v for k, v in rows.items() if "SV-9942" in k}
        win = {k: v for k, v in rows.items() if "SV-9942" not in k}
        assert len(edge) == 5 and set(edge.values()) == {"Newly scanned"}
        assert len(win) == 5 and set(win.values()) == {"Persisting"}
        assert "New" not in rows.values()
        assert any(
            "newly scanned" in r.message.lower()
            and "WIN-SERVER-01" in r.message
            and "Microsoft Edge" in r.message
            for r in caplog.records
        ), [r.message for r in caplog.records]
        listed = _pair_rows(load_workbook(out)["Summary"], "Host / STIG pairs newly scanned")
        assert len(listed) == 1
        assert listed[0][0] == "WIN-SERVER-01" and "Microsoft Edge" in listed[0][1]

    def test_coverage_warnings_reach_the_workbook(self, tmp_path):
        """The CLI log is gone by the time the workbook is read for
        accreditation; the coverage warning must be on the Summary sheet."""
        win_results = FIXTURES / "scc_results.xml"
        win_bench = FIXTURES / "sample_benchmark.xml"
        edge_results, edge_bench = _second_stig(tmp_path)
        out = tmp_path / "delta.xlsx"
        rc = main([
            "delta",
            "--baseline", str(win_results), str(edge_results),
            "--current", str(win_results),
            "--benchmarks", str(win_bench), str(edge_bench),
            "--output", str(out),
        ])
        assert rc == 0
        ws = load_workbook(out)["Summary"]
        text = " ".join(
            str(ws.cell(row=r, column=1).value)
            for r in range(1, ws.max_row + 1)
            if ws.cell(row=r, column=1).value is not None
        )
        assert "Warnings" in text
        assert "not re-scanned" in text and "Microsoft Edge" in text


def _strip_rule_results(src: Path, dest: Path) -> Path:
    """Copy *src* with every <cdf:rule-result> block removed."""
    text = src.read_text(encoding="utf-8")
    stripped = re.sub(
        r"<cdf:rule-result[ >].*?</cdf:rule-result>", "", text, flags=re.DOTALL
    )
    assert "<cdf:rule-result" not in stripped and "<cdf:target>" in stripped
    dest.write_text(stripped, encoding="utf-8")
    return dest


def _warning_rows(summary_ws) -> list[str]:
    """Every warning listed under the Summary sheet's Warnings heading."""
    heading = next(
        (i for i in range(1, summary_ws.max_row + 1)
         if summary_ws.cell(row=i, column=1).value == "Warnings"),
        None,
    )
    if heading is None:
        return []
    rows: list[str] = []
    r = heading + 1
    while summary_ws.cell(row=r, column=1).value not in (None, ""):
        rows.append(str(summary_ws.cell(row=r, column=1).value))
        r += 1
    return rows


class TestZeroRuleResultScanEndToEnd:
    """A current-set file with no <rule-result> at all (a benchmark handed
    in as results, or a scan that never ran) must not count as a re-scan:
    the baseline findings on that host/STIG are Not re-scanned, never
    Resolved, and the operator is told in the log AND on the workbook."""

    def test_empty_scan_file_never_resolves_baseline_findings(self, tmp_path, caplog):
        win_results = FIXTURES / "scc_results.xml"
        win_bench = FIXTURES / "sample_benchmark.xml"
        edge_results, edge_bench = _second_stig(tmp_path)
        empty = _strip_rule_results(win_results, tmp_path / "win_no_results.xml")
        out = tmp_path / "delta.xlsx"
        with caplog.at_level(logging.WARNING, logger="app.cli"):
            rc = main([
                "delta",
                "--baseline", str(win_results),
                "--current", str(empty), str(edge_results),
                "--benchmarks", str(win_bench), str(edge_bench),
                "--output", str(out),
            ])
        assert rc == 0
        rows = _delta_rows(out)
        win = {k: v for k, v in rows.items() if "SV-9942" not in k}
        assert len(win) == 5 and set(win.values()) == {"Not re-scanned"}, rows
        assert "Resolved" not in rows.values()
        expected = "win_no_results.xml: 0 rule results"
        assert any(
            expected in r.message and "pass it as a reference" in r.message
            for r in caplog.records if r.name == "app.cli"
        ), [r.message for r in caplog.records]
        listed = _warning_rows(load_workbook(out)["Summary"])
        assert any(expected in w and "pass it as a reference" in w for w in listed), listed


class TestUntitledScanFailsClosedEndToEnd:
    """Without --benchmarks the fixture scan matches no benchmark and has no
    STIG title, so a dropped finding cannot be shown re-scanned: it is Not
    re-scanned, never Resolved (R2-9), and the operator is told why in the
    log and on the workbook."""

    def test_dropped_finding_without_benchmarks_is_not_resolved(self, tmp_path, caplog):
        baseline = FIXTURES / "scc_results.xml"
        text = baseline.read_text(encoding="utf-8")
        # SV-254239 is the fixture's only "fail"; the other actionable rules
        # are notchecked/error/unknown. Remediating it drops it from current.
        assert text.count("<cdf:result>fail</cdf:result>") == 1
        current = tmp_path / "current.xml"
        current.write_text(
            text.replace("<cdf:result>fail</cdf:result>", "<cdf:result>pass</cdf:result>", 1),
            encoding="utf-8",
        )
        out = tmp_path / "delta.xlsx"
        with caplog.at_level(logging.WARNING, logger="app.cli"):
            rc = main([
                "delta",
                "--baseline", str(baseline),
                "--current", str(current),
                "--output", str(out),
            ])
        assert rc == 0
        rows = _delta_rows(out)
        assert rows["xccdf_mil.disa.stig_rule_SV-254239r945408_rule"] == "Not re-scanned"
        assert set(rows.values()) == {"Persisting", "Not re-scanned"}
        assert any(
            "cannot be verified as re-scanned" in r.message and "WIN-SERVER-01" in r.message
            for r in caplog.records
        ), [r.message for r in caplog.records]
        listed = _warning_rows(load_workbook(out)["Summary"])
        assert any("cannot be verified as re-scanned" in w for w in listed), listed


_EMPTY_CKLB = (
    '{"target_data": {"host_name": "HOST-C", "ip_address": "10.0.0.9"}, '
    '"stigs": [{"stig_name": "Win2022 STIG", "rules": []}]}'
)
_VULN_ONLY_NESSUS = (
    '<NessusClientData_v2><Report><ReportHost name="HOST-N">'
    '<HostProperties><tag name="host-ip">10.0.0.7</tag></HostProperties>'
    '<ReportItem port="443" severity="2" pluginID="12345" '
    'pluginName="Some CVE" pluginFamily="General"/>'
    "</ReportHost></Report></NessusClientData_v2>"
)


def _first_index(records, level: int, needle: str) -> int:
    """Index of the first app.cli record at *level* containing *needle*."""
    return next(
        i for i, r in enumerate(records)
        if r.name == "app.cli" and r.levelno == level and needle in r.message
    )


class TestParseFailureKeepsWarningsEndToEnd:
    """When parse_stage raises, the per-file warnings it collected first are
    the diagnosis ("empty.cklb: 0 rule results"). Both subcommands must log
    them BEFORE the error instead of dropping them with the failed
    ParseResult - otherwise the operator sees only "No rule results were
    found" and has to bisect."""

    def test_delta_logs_parse_warnings_before_the_error(self, tmp_path, caplog):
        good = FIXTURES / "scc_results.xml"
        empty = tmp_path / "empty.cklb"
        empty.write_text(_EMPTY_CKLB, encoding="utf-8")
        with caplog.at_level(logging.WARNING, logger="app.cli"):
            rc = main([
                "delta",
                "--baseline", str(good),
                "--current", str(empty),
                "--output", str(tmp_path / "delta.xlsx"),
            ])
        assert rc == 1
        messages = [r.message for r in caplog.records if r.name == "app.cli"]
        w = _first_index(caplog.records, logging.WARNING, "empty.cklb: 0 rule results")
        e = _first_index(caplog.records, logging.ERROR, "No rule results were found")
        assert caplog.records[w].message.startswith("Current scan set: "), messages
        assert caplog.records[e].message.startswith("Current scan set: "), messages
        assert w < e, messages

    def test_report_logs_parse_warnings_before_the_error(self, tmp_path, caplog):
        vuln_only = tmp_path / "vulnscan.nessus"
        vuln_only.write_text(_VULN_ONLY_NESSUS, encoding="utf-8")
        with caplog.at_level(logging.WARNING, logger="app.cli"):
            rc = main([
                "report",
                "--results", str(vuln_only),
                "--output", str(tmp_path / "report.xlsx"),
            ])
        assert rc == 1
        messages = [r.message for r in caplog.records if r.name == "app.cli"]
        w = _first_index(caplog.records, logging.WARNING, "vulnscan.nessus: 0 rule results")
        e = _first_index(caplog.records, logging.ERROR, "No rule results were found")
        assert w < e, messages


class TestReportBackCompatEndToEnd:
    def test_bare_results_produces_report(self, tmp_path):
        """The historical ``stig-parser --results ...`` form still runs."""
        out = tmp_path / "out.xlsx"
        rc = main(["--results", str(FIXTURES / "scc_results.xml"), "--output", str(out)])
        assert rc == 0
        assert out.exists()
        wb = load_workbook(out)
        assert {"Findings", "Summary"} <= set(wb.sheetnames)
        # Single-run report, not a delta: no Delta column.
        assert wb["Findings"].cell(row=1, column=1).value != "Delta"


# ---------------------------------------------------------------------------
# --references (alias --benchmarks)
# ---------------------------------------------------------------------------

_SUMMARY_LINE = (
    "Microsoft Windows 11 STIG SCAP Benchmark — check text filled: 2, fix text filled: 0, "
    "severity filled: 0, from a different release: 1, not in a supplied reference: 1, several matches: 0, "
    "other STIG title: 0"
)


class TestReferencesFlag:
    FIX = FIXTURES

    def _findings_sheet(self, path):
        return load_workbook(path)["Findings"]

    def _source_rows(self, path) -> list[str]:
        """File column of each row of the Summary sheet's Reference sources table."""
        rows = [[c.value for c in r] for r in load_workbook(path)["Summary"].iter_rows()]
        start = next(i for i, r in enumerate(rows) if r[0] == "Reference sources") + 2
        end = next(i for i in range(start, len(rows)) if rows[i][0] == "Not found in any supplied reference")
        return [r[0] for r in rows[start:end]]

    def test_references_flag_fills_check_text(self, tmp_path):
        out = tmp_path / "r.xlsx"
        rc = main(["report", "--results", str(self.FIX / "scc_embedded_results.xml"),
                   "--references", str(self.FIX / "manual_stig_win11.xml"), "--output", str(out)])
        assert rc == 0
        ws = self._findings_sheet(out)
        assert ws["H2"].value and ws["K2"].value.startswith("Check: manual_stig_win11.xml V2R9")

    def test_benchmarks_is_still_accepted_as_an_alias(self, tmp_path):
        out = tmp_path / "r.xlsx"
        rc = main(["--results", str(self.FIX / "scc_embedded_results.xml"),
                   "--benchmarks", str(self.FIX / "manual_stig_win11.xml"), "--output", str(out)])
        assert rc == 0 and self._findings_sheet(out)["H2"].value

    def test_reference_directory_is_scanned_recursively(self, tmp_path):
        import shutil
        lib = tmp_path / "stigs" / "windows"
        lib.mkdir(parents=True)
        shutil.copy(self.FIX / "manual_stig_win11.xml", lib / "manual_stig_win11.xml")
        out = tmp_path / "r.xlsx"
        rc = main(["report", "--results", str(self.FIX / "scc_embedded_results.xml"),
                   "--references", str(tmp_path / "stigs"), "--output", str(out)])
        assert rc == 0 and self._findings_sheet(out)["H2"].value

    def test_results_directory_is_not_scanned_recursively(self, tmp_path, caplog):
        import shutil
        nested = tmp_path / "results" / "older"
        nested.mkdir(parents=True)
        shutil.copy(self.FIX / "scc_embedded_results.xml", nested / "scan.xml")
        with caplog.at_level(logging.ERROR, logger="app.cli"):
            rc = main(["report", "--results", str(tmp_path / "results"),
                       "--output", str(tmp_path / "r.xlsx")])
        assert rc == 1
        assert any("No results files found" in r.message for r in caplog.records)

    def test_results_slot_takes_a_zip_from_a_directory(self, tmp_path):
        import zipfile
        scans = tmp_path / "scans"
        scans.mkdir()
        with zipfile.ZipFile(scans / "scans.zip", "w") as zf:
            zf.write(self.FIX / "scc_embedded_results.xml", "wkstn-01/results.xml")
        out = tmp_path / "r.xlsx"
        rc = main(["report", "--results", str(scans),
                   "--references", str(self.FIX / "manual_stig_win11.xml"), "--output", str(out)])
        assert rc == 0
        ws = self._findings_sheet(out)
        assert ws.max_row == 4 and ws["K2"].value.startswith("Check: manual_stig_win11.xml V2R9")

    def test_run_summary_reports_what_was_filled(self, tmp_path, caplog):
        caplog.set_level(logging.INFO)
        main(["report", "--results", str(self.FIX / "scc_embedded_results.xml"),
              "--references", str(self.FIX / "manual_stig_win11.xml"), "--output", str(tmp_path / "r.xlsx")])
        messages = [r.getMessage() for r in caplog.records if r.name == "app.cli"]
        assert any("check text filled: 2" in m for m in messages)
        assert _SUMMARY_LINE in messages, messages
        assert "Reference files: 1" in messages
        assert not any("--benchmarks" in m for m in messages), "the old fallback line is gone"

    def test_run_summary_escapes_the_stig_title(self, tmp_path, caplog):
        # A title comes from an upload: a newline in it must not forge a log line.
        scan = _variant(
            self.FIX / "scc_embedded_results.xml", tmp_path / "scan.xml",
            {"<cdf:title>Microsoft Windows 11 STIG SCAP Benchmark</cdf:title>":
             "<cdf:title>Win11&#10;ERROR forged line</cdf:title>"},
        )
        caplog.set_level(logging.INFO)
        rc = main(["report", "--results", str(scan),
                   "--references", str(self.FIX / "manual_stig_win11.xml"), "--output", str(tmp_path / "r.xlsx")])
        assert rc == 0
        line = next(r.getMessage() for r in caplog.records
                    if r.name == "app.cli" and "check text filled" in r.getMessage())
        assert line.startswith("Win11\\nERROR forged line — check text filled: 2"), line
        assert "\n" not in line

    def test_same_folder_as_results_and_references_reads_each_file_once(self, tmp_path, caplog):
        import shutil
        folder = tmp_path / "session"
        folder.mkdir()
        for name in ("scc_embedded_results.xml", "manual_stig_win11.xml"):
            shutil.copy(self.FIX / name, folder / name)
        out = tmp_path / "r.xlsx"
        caplog.set_level(logging.INFO)
        rc = main(["report", "--results", str(folder), "--references", str(folder), "--output", str(out)])
        assert rc == 0
        ws = self._findings_sheet(out)
        assert ws.max_row == 4, "three findings, not six"
        assert ws["K2"].value == "Check: manual_stig_win11.xml V2R9 | Fix: scanner"
        assert self._source_rows(out) == ["manual_stig_win11.xml", "scc_embedded_results.xml"]
        messages = [r.getMessage() for r in caplog.records if r.name == "app.cli"]
        assert messages.count(_SUMMARY_LINE) == 1, messages
        assert not any("identical to" in m or "same host and results as" in m for m in messages), messages

    def test_an_extracted_scap_bundle_in_a_reference_library_gives_one_support_line(self, tmp_path, caplog):
        # DISA's SCAP bundle unzipped into a library folder: the XCCDF is used (here it carries the
        # Manual STIG's text, so check text fills); OVAL, CPE and OCIL are named once, never as a
        # benchmark that could not be parsed.
        import shutil
        stem = "U_MS_Windows_11_V2R9_STIG_SCAP_1-3_Benchmark"
        bundle = tmp_path / "library" / "windows" / stem
        bundle.mkdir(parents=True)
        shutil.copy(self.FIX / "manual_stig_win11.xml", bundle / f"{stem}-xccdf.xml")
        oval = "<oval_definitions xmlns='http://oval.mitre.org/XMLSchema/oval-definitions-5'/>"
        for suffix, text in (("-oval.xml", oval), ("-cpe-oval.xml", oval.replace("/>", " id='cpe'/>")),
                             ("-cpe-dictionary.xml", "<cpe-list xmlns='http://cpe.mitre.org/dictionary/2.0'/>"),
                             ("-ocil.xml", "<ocil xmlns='http://scap.nist.gov/schema/ocil/2.0'/>")):
            (bundle / f"{stem}{suffix}").write_text(text, encoding="utf-8")
        out = tmp_path / "r.xlsx"
        caplog.set_level(logging.INFO)
        rc = main(["report", "--results", str(self.FIX / "scc_embedded_results.xml"),
                   "--references", str(tmp_path / "library"), "--output", str(out)])
        assert rc == 0
        assert self._findings_sheet(out)["K2"].value == f"Check: {stem}-xccdf.xml V2R9 | Fix: scanner"
        messages = [r.getMessage() for r in caplog.records if r.name == "app.cli"]
        assert not any("Could not parse" in m for m in messages), messages
        assert [m for m in messages if "SCAP support" in m] == [
            "4 SCAP support file(s) (OVAL, CPE, OCIL, stylesheets) were not used: "
            f"{stem}-cpe-dictionary.xml, {stem}-cpe-oval.xml, {stem}-ocil.xml, {stem}-oval.xml"]

    def test_delta_accepts_references(self, tmp_path, caplog):
        out = tmp_path / "d.xlsx"
        scc = str(self.FIX / "scc_embedded_results.xml")
        caplog.set_level(logging.INFO)
        rc = main(["delta", "--baseline", scc, "--current", scc,
                   "--references", str(self.FIX / "manual_stig_win11.xml"), "--output", str(out)])
        assert rc == 0
        ws = self._findings_sheet(out)
        headers = [c.value for c in ws[1]]
        assert "Text Source" in headers
        source = headers.index("Text Source") + 1
        assert {ws.cell(row=r, column=1).value for r in range(2, ws.max_row + 1)} == {"Persisting"}
        assert ws.cell(row=2, column=source).value == "Check: manual_stig_win11.xml V2R9 | Fix: scanner"
        assert any("Reference files: 1" in r.getMessage() for r in caplog.records if r.name == "app.cli")

    def test_delta_takes_the_benchmarks_alias_and_checks_its_paths(self, tmp_path, caplog):
        scc = str(self.FIX / "scc_embedded_results.xml")
        with caplog.at_level(logging.ERROR, logger="app.cli"):
            rc = main(["delta", "--baseline", scc, "--current", scc,
                       "--benchmarks", str(tmp_path / "missing.xml"), "--output", str(tmp_path / "d.xlsx")])
        assert rc == 1
        assert any("missing.xml" in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# What the CLI prints: one line per record, UTF-8
# ---------------------------------------------------------------------------

def _no_raw_break(messages: list[str]) -> bool:
    return not any("\n" in m or "\r" in m for m in messages)


class TestLogLinesCannotBeForged:
    """Warnings carry titles and host names from uploads. A line break in one must not
    start a line of its own in the CLI's output."""

    def _forging_reference(self, tmp_path: Path) -> Path:
        # The Server 2022 Manual STIG against the Windows 11 scan: the wrong-product warning
        # names the reference by its title.
        return _variant(
            FIXTURES / "manual_stig_server2022.xml", tmp_path / "ref.xml",
            {"<title>Microsoft Windows Server 2022 Security Technical Implementation Guide</title>":
             "<title>Server 2022&#10;ERROR  app.cli  forged&#13;line</title>"},
        )

    def test_report_warnings_are_one_line_each(self, tmp_path, caplog):
        caplog.set_level(logging.INFO)
        rc = main(["report", "--results", str(FIXTURES / "scc_embedded_results.xml"),
                   "--references", str(self._forging_reference(tmp_path)), "--output", str(tmp_path / "r.xlsx")])
        assert rc == 0
        warnings = [r.getMessage() for r in caplog.records if r.name == "app.cli" and r.levelno == logging.WARNING]
        assert _no_raw_break(warnings), warnings
        wrong = [w for w in warnings if "wrong product or STIG?" in w]
        assert len(wrong) == 1 and "(loaded: Server 2022\\nERROR  app.cli  forged\\rline V2R8)" in wrong[0], wrong

    def test_delta_warnings_are_one_line_each(self, tmp_path, caplog):
        caplog.set_level(logging.INFO)
        scc = str(FIXTURES / "scc_embedded_results.xml")
        rc = main(["delta", "--baseline", scc, "--current", scc,
                   "--references", str(self._forging_reference(tmp_path)), "--output", str(tmp_path / "d.xlsx")])
        assert rc == 0
        warnings = [r.getMessage() for r in caplog.records if r.name == "app.cli" and r.levelno == logging.WARNING]
        assert _no_raw_break(warnings), warnings
        assert [w for w in warnings if "wrong product" in w and w.startswith("Both scan sets: ")]

    @pytest.mark.parametrize("command", ["report", "delta"])
    def test_warnings_and_the_error_of_a_failed_run_are_one_line_each(self, tmp_path, caplog, monkeypatch, command):
        import app.cli as cli
        from app.core.pipeline import PipelineError

        def fail(*_args, **_kwargs):
            raise PipelineError("No rule results\nERROR forged", warnings=["a.xml: title\r\nWARNING forged"])

        monkeypatch.setattr(cli, "parse_stage", fail)
        scc = str(FIXTURES / "scc_embedded_results.xml")
        argv = (["report", "--results", scc] if command == "report"
                else ["delta", "--baseline", scc, "--current", scc]) + ["--output", str(tmp_path / "o.xlsx")]
        caplog.set_level(logging.INFO)
        assert main(argv) == 1
        printed = [r.getMessage() for r in caplog.records if r.name == "app.cli" and r.levelno >= logging.WARNING]
        assert _no_raw_break(printed), printed
        assert any(m.endswith("a.xml: title\\r\\nWARNING forged") for m in printed), printed
        assert any(m.endswith("No rule results\\nERROR forged") for m in printed), printed


def test_main_writes_its_log_as_utf8(tmp_path, monkeypatch):
    """Redirected on Windows, stderr would be cp1252 and an em-dash or ellipsis would
    arrive garbled; main makes it UTF-8 before it sets up logging."""
    import io
    import sys
    buffer = io.BytesIO()
    monkeypatch.setattr(sys, "stderr", io.TextIOWrapper(buffer, encoding="cp1252"))
    empty = tmp_path / "empty"
    empty.mkdir()
    assert main(["report", "--results", str(empty), "--output", str(tmp_path / "r.xlsx")]) == 1
    assert (sys.stderr.encoding, sys.stderr.errors) == ("utf-8", "backslashreplace")
    sys.stderr.write("— …")
    sys.stderr.flush()
    assert buffer.getvalue().endswith("— …".encode("utf-8"))


@pytest.mark.parametrize("command", ["report", "delta"])
def test_an_export_error_is_printed_on_one_line(tmp_path, caplog, monkeypatch, command):
    # The error can carry upload-derived text (openpyxl quotes the refused value); an escape
    # sequence or line break in it must not reach the terminal raw.
    import app.cli as cli

    def fail(*_args, **_kwargs):
        raise ValueError("value WIN\x1b[31m-01\nERROR  app.cli  forged cannot be used")

    monkeypatch.setattr(cli, "export_stage" if command == "report" else "export_delta_stage", fail)
    scc = str(FIXTURES / "scc_embedded_results.xml")
    argv = ["report", "--results", scc] if command == "report" else ["delta", "--baseline", scc, "--current", scc]
    caplog.set_level(logging.INFO)
    assert main([*argv, "--output", str(tmp_path / "o.xlsx")]) == 1
    errors = [r.getMessage() for r in caplog.records if r.name == "app.cli" and r.levelno == logging.ERROR]
    assert errors == ["Export failed: value WIN\\x1b[31m-01\\nERROR  app.cli  forged cannot be used"], errors


@pytest.mark.parametrize("target, title", [
    ("WIN-SERVER-01", "Windows Server 2022 STIG\u0007"),       # a BEL in the STIG title
    ("WIN\u001b[31m-01", "Windows Server 2022 STIG"),          # an escape sequence in the host name
])
def test_a_control_character_in_a_checklist_host_or_title_does_not_stop_the_export(tmp_path, target, title):
    import json
    doc = json.loads((FIXTURES / "evaluate_stig_checklist.cklb").read_text(encoding="utf-8-sig"))
    doc["target_data"]["host_name"] = target
    doc["stigs"][0]["display_name"] = title
    checklist = tmp_path / "checklist.cklb"
    checklist.write_text(json.dumps(doc), encoding="utf-8")
    out = tmp_path / "r.xlsx"
    assert main(["report", "--results", str(checklist), "--output", str(out)]) == 0
    findings = load_workbook(out)["Findings"]
    assert findings["F2"].value == target.replace("\u001b", "\ufffd")
    assert findings["A2"].value == title.replace("\u0007", "\ufffd")


def test_a_lone_surrogate_in_a_checklist_does_not_stop_the_export(tmp_path):
    import json
    doc = json.loads((FIXTURES / "evaluate_stig_checklist.cklb").read_text(encoding="utf-8-sig"))
    doc["stigs"][0]["rules"][0]["check_content"] = "before \ud800 after"
    checklist = tmp_path / "checklist.cklb"
    checklist.write_text(json.dumps(doc), encoding="utf-8")          # written as the escape \ud800
    out = tmp_path / "r.xlsx"
    assert main(["report", "--results", str(checklist), "--output", str(out)]) == 0
    assert "before \ufffd after" in [c.value for c in load_workbook(out)["Findings"]["H"]]


# --- each problem is printed once: a log line the run restates is not printed as well ---------------------

def _run_cli_on_broken_files(tmp_path, *extra: str) -> list[str]:
    """Run the CLI as the operator does, in its own process (inside pytest the root logger
    already has a handler, so the CLI's own would not be installed), over a good scan and
    one broken file of each kind; its stderr lines."""
    import subprocess
    import sys

    from tests.test_web import broken_uploads
    results, references = broken_uploads()
    folder = tmp_path / "in"
    folder.mkdir()
    for name, payload in (*results, *references):
        (folder / name).write_bytes(payload)
    argv = [sys.executable, "-m", "app.cli", "report",
            "--results", str(FIXTURES / "scc_embedded_results.xml"), *(str(folder / n) for n, _ in results),
            "--references", *(str(folder / n) for n, _ in references),
            "--output", str(tmp_path / "out.xlsx"), *extra]
    done = subprocess.run(argv, capture_output=True, cwd=Path(__file__).parent.parent, timeout=120)
    assert done.returncode == 0, done.stderr.decode("utf-8", "replace")
    return done.stderr.decode("utf-8").splitlines()


def test_the_cli_prints_each_problem_once_with_its_reason(tmp_path):
    from tests.test_web import expected_reasons
    lines = _run_cli_on_broken_files(tmp_path)
    for name, line in expected_reasons(tmp_path).items():
        assert [out for out in lines if name in out] == [f"WARNING  app.cli  {line}"], (name, lines)


# Every kind of problem (tests/problem_cases.py), the CLI run in this process: what it prints at
# WARNING is every WARNING record (the CLI's handler prints them all), here captured by caplog.
from tests.problem_cases import GOOD as CASE_GOOD, problem_cases  # noqa: E402

_CASES = problem_cases()


@pytest.mark.parametrize("case", _CASES, ids=[case.id for case in _CASES])
def test_the_cli_shows_each_problem_once(case, tmp_path, monkeypatch, caplog):
    import app.utils.zip_extract as zip_extract
    for name, value in case.patches.items():
        monkeypatch.setattr(zip_extract, name, value)
    folder = tmp_path / "in"
    folder.mkdir()
    results, references = [str(CASE_GOOD)], []
    for zone, name, payload in case.files:
        (folder / name).write_bytes(payload)
        (results if zone == "results" else references).append(str(folder / name))
    argv = ["report", "--results", *results, "--output", str(tmp_path / "out.xlsx")]
    if references:
        argv += ["--references", *references]
    with caplog.at_level(logging.WARNING):
        assert main(argv) == 0
    printed = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert [line for line in printed if case.subject in line] == case.shown


def test_the_report_workbook_carries_the_runs_warnings(tmp_path):
    from tests.test_excel_exporter import run_warning_rows
    broken = tmp_path / "broken.xml"
    broken.write_text("<TestResult><a></TestResult>", encoding="utf-8")
    out = tmp_path / "out.xlsx"
    assert main(["report", "--results", str(FIXTURES / "scc_embedded_results.xml"), str(broken),
                 "--output", str(out)]) == 0
    assert any(r.startswith("Could not parse results file: broken.xml — invalid XML") for r in run_warning_rows(out))


def test_help_is_printed_in_utf8_when_stdout_is_redirected():
    # Redirected on Windows, stdout is in the ANSI code page: an em-dash came out as a stray byte.
    import os
    import subprocess
    import sys
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONIOENCODING", "PYTHONUTF8")}
    done = subprocess.run([sys.executable, "-m", "app.cli", "report", "--help"], capture_output=True,
                          cwd=Path(__file__).parent.parent, env=env, timeout=60)
    assert done.returncode == 0
    assert "fix text only — add the Manual STIG" in done.stdout.decode("utf-8")
