"""Tests for XCCDFResultsParser — all four scanner formats."""
from pathlib import Path

import pytest

from app.parsers.xccdf_parser import XCCDFResultsParser

FIXTURES = Path(__file__).parent / "fixtures"
PARSER = XCCDFResultsParser()


class TestSCCResults:
    def setup_method(self):
        self.result = PARSER.parse(FIXTURES / "scc_results.xml")

    def test_parses_successfully(self):
        assert self.result is not None

    def test_hostname(self):
        assert self.result.hostname == "WIN-SERVER-01"

    def test_ip_address(self):
        assert self.result.ip_address == "192.168.1.10"

    def test_benchmark_href(self):
        assert "Windows_Server_2022" in self.result.benchmark_href or \
               "MS_Windows_Server_2022" in self.result.benchmark_href

    def test_benchmark_id(self):
        assert "MS_Windows_Server_2022_STIG" in self.result.benchmark_id

    def test_scanner_detected(self):
        assert self.result.scanner == "SCC"

    def test_rule_results_count(self):
        # 7 rule-result elements in the fixture
        assert len(self.result.rule_results) == 7

    def test_fail_result(self):
        rr = next(r for r in self.result.rule_results if r.rule_id.endswith("SV-254239r945408_rule"))
        assert rr.status == "fail"

    def test_pass_result(self):
        rr = next(r for r in self.result.rule_results if r.rule_id.endswith("SV-254240r945411_rule"))
        assert rr.status == "pass"

    def test_notchecked_result(self):
        rr = next(r for r in self.result.rule_results if r.rule_id.endswith("SV-254241r945414_rule"))
        assert rr.status == "notchecked"

    def test_error_result(self):
        rr = next(r for r in self.result.rule_results if r.rule_id.endswith("SV-254242r945417_rule"))
        assert rr.status == "error"

    def test_unknown_result(self):
        rr = next(r for r in self.result.rule_results if r.rule_id.endswith("SV-254243r945420_rule"))
        assert rr.status == "unknown"

    def test_notselected_result(self):
        rr = next(r for r in self.result.rule_results if r.rule_id.endswith("SV-254245r945426_rule"))
        assert rr.status == "notselected"


class TestOpenSCAPResults:
    def setup_method(self):
        self.result = PARSER.parse(FIXTURES / "openscap_results.xml")

    def test_parses_successfully(self):
        assert self.result is not None

    def test_hostname(self):
        assert self.result.hostname == "rhel9-server-02"

    def test_ip_address(self):
        # First target-address is IPv4
        assert self.result.ip_address == "10.0.0.25"

    def test_scanner_detected(self):
        assert self.result.scanner == "OpenSCAP"

    def test_rule_count(self):
        assert len(self.result.rule_results) == 6

    def test_fail_result(self):
        rr = next(r for r in self.result.rule_results if r.rule_id.endswith("SV-257777r925318_rule"))
        assert rr.status == "fail"


class TestNessusResults:
    def setup_method(self):
        self.result = PARSER.parse(FIXTURES / "nessus_results.xml")

    def test_parses_successfully(self):
        assert self.result is not None

    def test_hostname(self):
        assert self.result.hostname == "WIN-SERVER-03"

    def test_ip_address(self):
        assert self.result.ip_address == "192.168.1.30"

    def test_scanner_detected(self):
        assert self.result.scanner == "Nessus"

    def test_rule_count(self):
        assert len(self.result.rule_results) == 4

    def test_fail_result(self):
        rr = next(r for r in self.result.rule_results if r.rule_id.endswith("SV-254239r945408_rule"))
        assert rr.status == "fail"


class TestEvaluateSTIGResults:
    def setup_method(self):
        self.result = PARSER.parse(FIXTURES / "evaluate_stig_results.xml")

    def test_parses_successfully(self):
        assert self.result is not None

    def test_hostname(self):
        assert self.result.hostname == "WIN-SERVER-04"

    def test_ip_address(self):
        assert self.result.ip_address == "192.168.1.40"

    def test_scanner_detected(self):
        assert self.result.scanner == "Evaluate-STIG"

    def test_rule_count(self):
        assert len(self.result.rule_results) == 4

    def test_fail_result(self):
        rr = next(r for r in self.result.rule_results if r.rule_id.endswith("SV-254239r945408_rule"))
        assert rr.status == "fail"


class TestEdgeCases:
    def test_invalid_xml_returns_none(self, tmp_path):
        bad = tmp_path / "bad.xml"
        bad.write_text("not xml at all <<<", encoding="utf-8")
        result = PARSER.parse(bad)
        assert result is None

    def test_missing_target_uses_filename(self, tmp_path):
        xml = tmp_path / "my-server.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            '<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2">'
            '<benchmark href="test.xml" id="test_benchmark"/>'
            '</TestResult>',
            encoding="utf-8",
        )
        result = PARSER.parse(xml)
        assert result is not None
        assert result.hostname == "my-server"

    def test_missing_ip_returns_na(self, tmp_path):
        xml = tmp_path / "noip.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            '<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2">'
            '<benchmark href="test.xml" id="test_benchmark"/>'
            '<target>SOME-HOST</target>'
            '</TestResult>',
            encoding="utf-8",
        )
        result = PARSER.parse(xml)
        assert result is not None
        assert result.ip_address == "N/A"
