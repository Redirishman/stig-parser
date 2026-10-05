"""Hardening tests: fail-loud behaviour for structures the parsers used to
mishandle silently."""
from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from app.core.pipeline import PipelineError, parse_stage
from app.parsers.xccdf_parser import XCCDFResultsParser

FIXTURES = Path(__file__).parent / "fixtures"


class TestMultipleTestResults:
    """OpenSCAP remediation files carry two <TestResult> elements — the
    parser must report the LAST (post-remediation machine state)."""

    def test_uses_last_test_result(self):
        sr = XCCDFResultsParser().read(FIXTURES / "openscap_remediation_results.xml")[0]
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
        XCCDFResultsParser().read(FIXTURES / "openscap_remediation_results.xml")[0]
        assert any("2 <TestResult>" in r.message for r in caplog.records)


class TestLegacyCklRejection:
    """A legacy .ckl (STIG Viewer 2 XML) uploaded as .xml must be refused
    loudly, not parsed into an empty ScanResult."""

    def test_returns_none(self):
        assert XCCDFResultsParser().read(FIXTURES / "legacy_checklist.ckl.xml")[0] is None

    def test_the_reason_points_to_cklb(self):
        scan, why = XCCDFResultsParser().read(FIXTURES / "legacy_checklist.ckl.xml")
        assert scan is None and ".cklb" in why


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


class TestPipelineWithNessus:
    def test_nessus_only_run_produces_findings(self, tmp_path):
        result = parse_stage(
            [FIXTURES / "nessus_compliance.nessus"],
            [],
            tmp_path / "extract",
        )
        assert result.source_file_count == 1
        # FAILED + WARNING + ERROR + FAILED-custom actionable; PASSED filtered
        assert len(result.findings) == 4
        by_id = {f.vuln_id: f for f in result.findings if f.vuln_id}
        assert by_id["V-204392"].severity == "CAT I"
        assert by_id["V-204392"].check_text  # self-contained, no benchmark
        assert not any("benchmark" in w.lower() for w in result.warnings)

    def test_all_three_formats_in_one_run(self, tmp_path):
        result = parse_stage(
            [
                FIXTURES / "scc_results.xml",
                FIXTURES / "evaluate_stig_checklist.cklb",
                FIXTURES / "nessus_compliance.nessus",
            ],
            [],
            tmp_path / "extract",
        )
        assert result.source_file_count == 3
        servers = {f.server for f in result.findings}
        assert "WIN-SERVER-01" in servers            # CKLB host
        assert "rhel7-lab-01.example.mil" in servers  # .nessus host



# --- per-row log lines are capped and escaped --------------------------------------------------------


def _warnings_from(caplog, logger: str) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == logger and r.levelno >= logging.WARNING]


def test_a_checklist_of_50000_rules_without_a_status_logs_five_warnings(tmp_path, caplog):
    from app.parsers.cklb_parser import CKLBParser
    rules = [{"group_id": f"V-{i}", "rule_id": f"SV-{i}r1_rule", "status": ""} for i in range(50_000)]
    path = tmp_path / "blank.cklb"
    path.write_text(json.dumps({"target_data": {"host_name": "H", "ip_address": "10.0.0.1"},
                                "stigs": [{"display_name": "X", "rules": rules}]}), encoding="utf-8")
    with caplog.at_level(logging.DEBUG, logger="app"):
        result = CKLBParser().read(path)[0]
    assert result.findings == [] and result.skipped_rules == 50_000     # the operator is told the count
    rows = [r for r in caplog.records if "has no status" in r.getMessage()]
    assert len(rows) == 50_000
    assert len([r for r in rows if r.levelno >= logging.WARNING]) == 5


def test_every_kind_of_checklist_row_line_counts_towards_the_five(tmp_path, caplog):
    from app.parsers.cklb_parser import CKLBParser
    rules = ([{"status": "open"}] * 3 + [{"group_id": "V-1", "status": ["open"]}] * 3
             + [{"group_id": "V-2", "status": "weird"}] * 3)
    stigs = [{"display_name": "X", "rules": rules}] + [{"display_name": "No rules"}] * 3
    path = tmp_path / "mixed.cklb"
    path.write_text(json.dumps({"target_data": {"host_name": "H", "ip_address": "10.0.0.1"}, "stigs": stigs}),
                    encoding="utf-8")
    with caplog.at_level(logging.DEBUG, logger="app"):
        CKLBParser().read(path)[0]
    per_row = ("no group_id/rule_id", "not text", "unrecognised status", "no rules list")
    lines = [r for r in caplog.records if any(p in r.getMessage() for p in per_row)]
    assert len(lines) == 12 and len([r for r in lines if r.levelno >= logging.WARNING]) == 5


def test_a_newline_in_a_checklist_id_or_status_cannot_start_a_log_line(tmp_path, caplog):
    from app.parsers.cklb_parser import CKLBParser
    path = tmp_path / "forged.cklb"
    path.write_text(json.dumps({"target_data": {"host_name": "H", "ip_address": "10.0.0.1"}, "stigs": [
        {"display_name": "X", "rules": [{"group_id": "V-1\nFORGED", "status": "odd\nFORGED"}]}]}), encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="app"):
        CKLBParser().read(path)[0]
    assert caplog.records and not any("\n" in r.getMessage() for r in caplog.records)


def test_xccdf_rule_results_without_a_result_log_five_escaped_warnings(tmp_path, caplog):
    results = "".join(f"<rule-result idref='SV-{i}r1_rule&#10;FORGED LINE'/>" for i in range(100))
    path = tmp_path / "no_results.xml"
    path.write_text(f"<TestResult><target>H</target>{results}"
                    "<rule-result idref='SV-0r1_rule'><result>fail</result></rule-result></TestResult>",
                    encoding="utf-8")
    with caplog.at_level(logging.DEBUG, logger="app"):
        scan = XCCDFResultsParser().read(path)[0]
    assert len(scan.rule_results) == 1
    rows = [r for r in caplog.records if "no <result>" in r.getMessage()]
    assert len(rows) == 100 and len([r for r in rows if r.levelno >= logging.WARNING]) == 5
    assert not any("\n" in r.getMessage() for r in caplog.records)


def test_nessus_items_with_an_unrecognised_result_log_five_escaped_warnings(tmp_path, caplog):
    from app.parsers.nessus_parser import NessusComplianceParser
    item = ("<ReportItem pluginName='x' pluginFamily='Policy Compliance'><cm:compliance-result>ODD&#10;FORGED"
            "</cm:compliance-result><cm:compliance-check-name>c{0}</cm:compliance-check-name></ReportItem>")
    path = tmp_path / "odd.nessus"
    path.write_text("<NessusClientData_v2><Report xmlns:cm='http://www.nessus.org/cm'><ReportHost name='h'>"
                    + "".join(item.format(i) for i in range(100)) + "</ReportHost></Report></NessusClientData_v2>",
                    encoding="utf-8")
    with caplog.at_level(logging.DEBUG, logger="app"):
        findings = NessusComplianceParser().read(path)[0]
    assert len(findings) == 100 and all(f.status == "Unknown" for f in findings)
    rows = [r for r in caplog.records if "unrecognised result" in r.getMessage()]
    assert len(rows) == 100 and len([r for r in rows if r.levelno >= logging.WARNING]) == 5
    assert not any("\n" in r.getMessage() for r in caplog.records)


def test_nessus_hosts_without_a_name_log_five_warnings(tmp_path, caplog):
    from app.parsers.nessus_parser import NessusComplianceParser
    host = ("<ReportHost><ReportItem pluginName='x' pluginFamily='Policy Compliance'>"
            "<cm:compliance-result>FAILED</cm:compliance-result>"
            "<cm:compliance-check-name>c{0}</cm:compliance-check-name></ReportItem></ReportHost>")
    path = tmp_path / "nameless.nessus"
    path.write_text("<NessusClientData_v2><Report xmlns:cm='http://www.nessus.org/cm'>"
                    + "".join(host.format(i) for i in range(100)) + "</Report></NessusClientData_v2>",
                    encoding="utf-8")
    with caplog.at_level(logging.DEBUG, logger="app"):
        findings = NessusComplianceParser().read(path)[0]
    assert len(findings) == 100 and {f.server for f in findings} == {"nameless"}
    rows = [r for r in caplog.records if "ReportHost with no name" in r.getMessage()]
    assert len(rows) == 100 and len([r for r in rows if r.levelno >= logging.WARNING]) == 5
