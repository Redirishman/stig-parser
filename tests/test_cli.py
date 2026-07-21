"""Tests for app.cli — argument parsing, path resolution, and end-to-end runs."""
from __future__ import annotations

import logging
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

    def test_benchmarks_is_optional(self):
        parser = _build_parser()
        # No --benchmarks flag at all — must not raise
        args = parser.parse_args(_normalize_argv(["--results", "a.xml"]))
        assert args.benchmarks is None

    def test_benchmarks_accepts_empty_list(self):
        parser = _build_parser()
        args = parser.parse_args(
            _normalize_argv(["--results", "a.xml", "--benchmarks"])
        )
        assert args.benchmarks == []

    def test_benchmarks_accepts_multiple_paths(self):
        parser = _build_parser()
        args = parser.parse_args(
            _normalize_argv(
                ["--results", "a.xml", "b.xml", "--benchmarks", "x.xml", "y.zip"]
            )
        )
        assert args.results == ["a.xml", "b.xml"]
        assert args.benchmarks == ["x.xml", "y.zip"]

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
        assert args.benchmarks == ["x.xml"]
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

    def test_delta_requires_baseline_and_current(self):
        parser = _build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["delta", "--baseline", "a.xml"])


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

class TestResolvePaths:
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
        # The fallback message should appear in the log
        assert any(
            "No --benchmarks supplied" in r.message for r in caplog.records
        ), "expected fallback INFO message when --benchmarks omitted"

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
    never silently turn an edit into a no-op.
    """
    text = path.read_text(encoding="utf-8")
    for old, new in replacements.items():
        assert text.count(old) == 1, f"{old!r} is not unique in {path.name}"
        text = text.replace(old, new)
    dest.write_text(text, encoding="utf-8")
    return dest


def _delta_rows(path: Path) -> dict[str, str]:
    """Map Rule ID -> Delta status from a delta workbook's Findings sheet."""
    ws = load_workbook(path)["Findings"]
    return {
        ws.cell(row=r, column=4).value: ws.cell(row=r, column=1).value
        for r in range(2, ws.max_row + 1)
    }


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

    def test_delta_warnings_are_logged(self, tmp_path, caplog):
        """compute_delta's warnings must reach the operator via the CLI log.

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
        with caplog.at_level(logging.WARNING, logger="app.cli"):
            rc = main([
                "delta",
                "--baseline", str(baseline),
                "--current", str(current),
                "--benchmarks", str(FIXTURES / "sample_benchmark.xml"),
                "--output", str(out),
            ])
        assert rc == 0
        assert any(
            r.name == "app.cli" and "different Vuln-ID coverage" in r.message
            for r in caplog.records
        ), "delta warnings were not surfaced by the CLI"

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
        assert any(r.levelno >= logging.ERROR for r in caplog.records)

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
        assert tags == {"New"}


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
