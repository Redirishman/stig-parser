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
        """When no <target>, <target-facts>, or <title> exist, fall back to filename stem."""
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
        """When no <target-address> or <target-facts> IP exists, fall back to 'N/A'."""
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

    # ------------------------------------------------------------------
    # <target-facts> fallbacks
    # ------------------------------------------------------------------

    def test_target_facts_hostname_host_name_urn(self, tmp_path):
        """host_name URN in <target-facts> used when <target> is absent."""
        xml = tmp_path / "facts-host.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            '<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2">'
            '<benchmark href="test.xml" id="test_benchmark"/>'
            '<target-facts>'
            '<fact name="urn:scap:fact:asset:identifier:host_name">FACTS-HOST-01</fact>'
            '<fact name="urn:scap:fact:asset:identifier:ipv4">10.1.2.3</fact>'
            '</target-facts>'
            '</TestResult>',
            encoding="utf-8",
        )
        result = PARSER.parse(xml)
        assert result is not None
        assert result.hostname == "FACTS-HOST-01"

    def test_target_facts_hostname_fqdn_urn(self, tmp_path):
        """fqdn URN in <target-facts> used when host_name URN is absent."""
        xml = tmp_path / "facts-fqdn.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            '<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2">'
            '<benchmark href="test.xml" id="test_benchmark"/>'
            '<target-facts>'
            '<fact name="urn:scap:fact:asset:identifier:fqdn">server.example.com</fact>'
            '</target-facts>'
            '</TestResult>',
            encoding="utf-8",
        )
        result = PARSER.parse(xml)
        assert result is not None
        assert result.hostname == "server.example.com"

    def test_target_facts_ip_ipv4_urn(self, tmp_path):
        """ipv4 URN in <target-facts> used when <target-address> is absent."""
        xml = tmp_path / "facts-ip.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            '<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2">'
            '<benchmark href="test.xml" id="test_benchmark"/>'
            '<target>SOME-HOST</target>'
            '<target-facts>'
            '<fact name="urn:scap:fact:asset:identifier:ipv4">172.16.0.50</fact>'
            '</target-facts>'
            '</TestResult>',
            encoding="utf-8",
        )
        result = PARSER.parse(xml)
        assert result is not None
        assert result.ip_address == "172.16.0.50"

    def test_target_facts_prefers_ipv4_over_ipv6(self, tmp_path):
        """IPv4 URN is preferred over IPv6 when both are present in <target-facts>."""
        xml = tmp_path / "facts-dual-ip.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            '<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2">'
            '<benchmark href="test.xml" id="test_benchmark"/>'
            '<target>SOME-HOST</target>'
            '<target-facts>'
            '<fact name="urn:scap:fact:asset:identifier:ipv6">fe80::1</fact>'
            '<fact name="urn:scap:fact:asset:identifier:ipv4">192.168.10.5</fact>'
            '</target-facts>'
            '</TestResult>',
            encoding="utf-8",
        )
        result = PARSER.parse(xml)
        assert result is not None
        assert result.ip_address == "192.168.10.5"

    def test_target_takes_precedence_over_target_facts(self, tmp_path):
        """<target> beats <target-facts> when both are present."""
        xml = tmp_path / "both.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            '<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2">'
            '<benchmark href="test.xml" id="test_benchmark"/>'
            '<target>EXPLICIT-HOST</target>'
            '<target-facts>'
            '<fact name="urn:scap:fact:asset:identifier:host_name">FACTS-HOST</fact>'
            '</target-facts>'
            '</TestResult>',
            encoding="utf-8",
        )
        result = PARSER.parse(xml)
        assert result is not None
        assert result.hostname == "EXPLICIT-HOST"

    # ------------------------------------------------------------------
    # <title> fallback
    # ------------------------------------------------------------------

    def test_title_used_when_target_and_facts_absent(self, tmp_path):
        """<title> element used as hostname when <target> and <target-facts> are absent."""
        xml = tmp_path / "notarget.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            '<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2">'
            '<benchmark href="test.xml" id="test_benchmark"/>'
            '<title>SCC Results: WIN-TITLE-HOST</title>'
            '</TestResult>',
            encoding="utf-8",
        )
        result = PARSER.parse(xml)
        assert result is not None
        assert result.hostname == "SCC Results: WIN-TITLE-HOST"

    def test_filename_stem_is_last_resort(self, tmp_path):
        """Filename stem used only when <target>, <target-facts>, and <title> all absent."""
        xml = tmp_path / "last-resort.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            '<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2">'
            '<benchmark href="test.xml" id="test_benchmark"/>'
            '</TestResult>',
            encoding="utf-8",
        )
        result = PARSER.parse(xml)
        assert result is not None
        assert result.hostname == "last-resort"

    # ------------------------------------------------------------------
    # <TestResult> nested inside <Benchmark> (some SCC outputs)
    # ------------------------------------------------------------------

    def test_nested_test_result_extracts_hostname_ip_and_rules(self, tmp_path):
        """When <TestResult> is nested inside <Benchmark>, parser still finds host/IP/rules."""
        xml = tmp_path / "nested.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="bench_id">'
            '<TestResult id="result1">'
            '<benchmark href="benchmark.xml" id="benchmark_id"/>'
            '<target>NESTED-HOST</target>'
            '<target-address>10.20.30.40</target-address>'
            '<rule-result idref="SV-1_rule">'
            '<result>fail</result>'
            '</rule-result>'
            '<rule-result idref="SV-2_rule">'
            '<result>pass</result>'
            '</rule-result>'
            '<rule-result idref="SV-3_rule">'
            '<result>notchecked</result>'
            '</rule-result>'
            '</TestResult>'
            '</Benchmark>',
            encoding="utf-8",
        )
        result = PARSER.parse(xml)
        assert result is not None
        assert result.hostname == "NESTED-HOST"
        assert result.ip_address == "10.20.30.40"
        assert result.benchmark_id == "benchmark_id"
        assert len(result.rule_results) == 3
        statuses = {rr.rule_id: rr.status for rr in result.rule_results}
        assert statuses["SV-1_rule"] == "fail"
        assert statuses["SV-2_rule"] == "pass"
        assert statuses["SV-3_rule"] == "notchecked"

    def test_deeply_nested_test_result(self, tmp_path):
        """TestResult buried under multiple wrapper elements is still found."""
        xml = tmp_path / "deep.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">'
            '<Group id="wrapper">'
            '<TestResult id="result1">'
            '<target>DEEP-HOST</target>'
            '<rule-result idref="SV-X_rule">'
            '<result>fail</result>'
            '</rule-result>'
            '</TestResult>'
            '</Group>'
            '</Benchmark>',
            encoding="utf-8",
        )
        result = PARSER.parse(xml)
        assert result is not None
        assert result.hostname == "DEEP-HOST"
        assert len(result.rule_results) == 1

    def test_no_test_result_falls_back_safely(self, tmp_path):
        """File with no <TestResult> anywhere yields a parseable but empty ScanResult."""
        xml = tmp_path / "no-results.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="b"/>',
            encoding="utf-8",
        )
        result = PARSER.parse(xml)
        assert result is not None
        assert result.rule_results == []
