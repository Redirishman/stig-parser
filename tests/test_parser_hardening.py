"""Hardening tests: fail-loud behaviour for structures the parsers used to
mishandle silently."""
from __future__ import annotations

from pathlib import Path

import pytest

from app.core.pipeline import PipelineError, parse_stage
from app.parsers.xccdf_parser import XCCDFResultsParser

FIXTURES = Path(__file__).parent / "fixtures"


class TestMultipleTestResults:
    """OpenSCAP remediation files carry two <TestResult> elements — the
    parser must report the LAST (post-remediation machine state)."""

    def test_uses_last_test_result(self):
        sr = XCCDFResultsParser().parse(FIXTURES / "openscap_remediation_results.xml")
        assert sr is not None
        statuses = {r.rule_id: r.status for r in sr.rule_results}
        # telnet rule was remediated: fail in the first TestResult, pass in
        # the second. Post-remediation state must win.
        assert statuses[
            "xccdf_org.ssgproject.content_rule_package_telnet_removed"
        ] == "pass"
        assert statuses[
            "xccdf_org.ssgproject.content_rule_service_sshd_enabled"
        ] == "fail"

    def test_warns_about_multiple_test_results(self, caplog):
        XCCDFResultsParser().parse(FIXTURES / "openscap_remediation_results.xml")
        assert any("2 <TestResult>" in r.message for r in caplog.records)


class TestLegacyCklRejection:
    """A legacy .ckl (STIG Viewer 2 XML) uploaded as .xml must be refused
    loudly, not parsed into an empty ScanResult."""

    def test_returns_none(self):
        assert XCCDFResultsParser().parse(FIXTURES / "legacy_checklist.ckl.xml") is None

    def test_warning_points_to_cklb(self, caplog):
        XCCDFResultsParser().parse(FIXTURES / "legacy_checklist.ckl.xml")
        assert any(".cklb" in r.message for r in caplog.records)


class TestPipelineWithCklb:
    def test_cklb_only_run_produces_findings(self, tmp_path):
        result = parse_stage(
            [FIXTURES / "evaluate_stig_checklist.cklb"],
            [],
            tmp_path / "extract",
        )
        assert result.source_file_count == 1
        assert {f.vuln_id for f in result.findings} == {
            "V-254239", "V-254241", "V-254242",
        }
        # Self-contained: check/fix text populated without any benchmark
        by_id = {f.vuln_id: f for f in result.findings}
        assert by_id["V-254239"].check_text
        assert by_id["V-254239"].fix_text
        # No noise warnings about benchmarks for a CKLB-only run
        assert not any("benchmark" in w.lower() for w in result.warnings)

    def test_mixed_xccdf_and_cklb_run(self, tmp_path):
        result = parse_stage(
            [
                FIXTURES / "scc_results.xml",
                FIXTURES / "evaluate_stig_checklist.cklb",
            ],
            [],
            tmp_path / "extract",
        )
        assert result.source_file_count == 2
        servers = {f.server for f in result.findings}
        assert "WIN-SERVER-01" in servers  # from the CKLB
        # XCCDF findings from the SCC fixture are present too
        assert len(result.findings) > 3

    def test_bad_cklb_alone_raises_pipeline_error(self, tmp_path):
        bad = tmp_path / "bad.cklb"
        bad.write_text("{not json", encoding="utf-8")
        with pytest.raises(PipelineError):
            parse_stage([bad], [], tmp_path / "extract")

    def test_bad_cklb_alongside_good_xccdf_is_warned_not_fatal(self, tmp_path):
        bad = tmp_path / "bad.cklb"
        bad.write_text("{not json", encoding="utf-8")
        result = parse_stage(
            [FIXTURES / "scc_results.xml", bad],
            [],
            tmp_path / "extract",
        )
        assert any("bad.cklb" in w for w in result.warnings)
        assert result.source_file_count == 1

    def test_summary_counts_cklb_severities(self, tmp_path):
        from app.core.pipeline import compute_summary

        result = parse_stage(
            [FIXTURES / "evaluate_stig_checklist.cklb"],
            [],
            tmp_path / "extract",
        )
        summary = compute_summary(result.findings, result.source_file_count)
        assert summary["cat1"] == 1   # V-254239 high
        assert summary["cat2"] == 2   # V-254241 medium + V-254242 override→medium
        assert summary["cat3"] == 0
        assert summary["hosts"] == 1
