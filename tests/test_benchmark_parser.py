"""Tests for BenchmarkParser (XCCDF 1.1 STIG benchmark definitions)."""
from pathlib import Path

import pytest

from app.parsers.benchmark_parser import BenchmarkParser

FIXTURES = Path(__file__).parent / "fixtures"
PARSER = BenchmarkParser()


class TestSampleBenchmark:
    def setup_method(self):
        self.bm = PARSER.parse(FIXTURES / "sample_benchmark.xml")

    def test_parses_successfully(self):
        assert self.bm is not None

    def test_benchmark_id(self):
        assert "MS_Windows_Server_2022_STIG" in self.bm.benchmark_id

    def test_title(self):
        assert "Windows Server 2022" in self.bm.title

    def test_rule_count(self):
        assert len(self.bm.rules) == 7

    def test_cat_i_severity(self):
        rule = self.bm.rules.get("xccdf_mil.disa.stig_rule_SV-254239r945408_rule")
        assert rule is not None
        assert rule.severity == "CAT I"

    def test_cat_ii_severity(self):
        rule = self.bm.rules.get("xccdf_mil.disa.stig_rule_SV-254240r945411_rule")
        assert rule is not None
        assert rule.severity == "CAT II"

    def test_cat_iii_severity(self):
        rule = self.bm.rules.get("xccdf_mil.disa.stig_rule_SV-254242r945417_rule")
        assert rule is not None
        assert rule.severity == "CAT III"

    def test_vuln_id(self):
        rule = self.bm.rules.get("xccdf_mil.disa.stig_rule_SV-254239r945408_rule")
        assert rule.vuln_id == "V-254239"

    def test_check_text_nonempty(self):
        rule = self.bm.rules.get("xccdf_mil.disa.stig_rule_SV-254239r945408_rule")
        assert len(rule.check_text) > 10

    def test_fix_text_nonempty(self):
        rule = self.bm.rules.get("xccdf_mil.disa.stig_rule_SV-254239r945408_rule")
        assert len(rule.fix_text) > 10

    def test_check_text_content(self):
        rule = self.bm.rules.get("xccdf_mil.disa.stig_rule_SV-254239r945408_rule")
        assert "multifactor" in rule.check_text.lower()

    def test_fix_text_content(self):
        rule = self.bm.rules.get("xccdf_mil.disa.stig_rule_SV-254239r945408_rule")
        assert "multifactor" in rule.fix_text.lower() or "Configure" in rule.fix_text


class TestXCCDF12Benchmark:
    """BenchmarkParser must handle XCCDF 1.2 files (SCC result files with inline defs)."""

    def setup_method(self):
        xml = Path(__file__).parent / "_tmp_xccdf12_bench.xml"
        xml.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<cdf:Benchmark xmlns:cdf="http://checklists.nist.gov/xccdf/1.2"'
            '  id="xccdf_mil.disa.stig_benchmark_MS_Defender_Antivirus">'
            '<cdf:title>Microsoft Defender Antivirus STIG SCAP Benchmark</cdf:title>'
            '<cdf:Group id="xccdf_mil.disa.stig_group_V-213426">'
            '  <cdf:title>SRG-APP-000279</cdf:title>'
            '  <cdf:Rule id="xccdf_mil.disa.stig_rule_SV-213426r961197_rule"'
            '    weight="10.0" severity="high">'
            '    <cdf:version>WNDF-AV-000001</cdf:version>'
            '    <cdf:title>Defender AV must block PUA.</cdf:title>'
            '    <cdf:fixtext fixref="F-1">Set PUAProtection to Enabled and Block.</cdf:fixtext>'
            '    <cdf:fix id="F-1"/>'
            '  </cdf:Rule>'
            '</cdf:Group>'
            '<cdf:Group id="xccdf_mil.disa.stig_group_V-213427">'
            '  <cdf:Rule id="xccdf_mil.disa.stig_rule_SV-213427r961197_rule"'
            '    severity="medium">'
            '    <cdf:fixtext>Disable routine remediation policy.</cdf:fixtext>'
            '  </cdf:Rule>'
            '</cdf:Group>'
            '</cdf:Benchmark>',
            encoding="utf-8",
        )
        self.path = xml
        self.bm = PARSER.parse(xml)

    def teardown_method(self):
        self.path.unlink(missing_ok=True)

    def test_parses_successfully(self):
        assert self.bm is not None

    def test_benchmark_id(self):
        assert "MS_Defender_Antivirus" in self.bm.benchmark_id

    def test_title(self):
        assert "Defender Antivirus" in self.bm.title

    def test_rule_count(self):
        assert len(self.bm.rules) == 2

    def test_vuln_id_stripped_from_qualified_group_id(self):
        rule = self.bm.rules.get("xccdf_mil.disa.stig_rule_SV-213426r961197_rule")
        assert rule is not None
        assert rule.vuln_id == "V-213426"

    def test_severity_high(self):
        rule = self.bm.rules.get("xccdf_mil.disa.stig_rule_SV-213426r961197_rule")
        assert rule.severity == "CAT I"

    def test_severity_medium(self):
        rule = self.bm.rules.get("xccdf_mil.disa.stig_rule_SV-213427r961197_rule")
        assert rule.severity == "CAT II"

    def test_fix_text(self):
        rule = self.bm.rules.get("xccdf_mil.disa.stig_rule_SV-213426r961197_rule")
        assert "PUAProtection" in rule.fix_text


class TestEdgeCases:
    def test_invalid_xml_returns_none(self, tmp_path):
        bad = tmp_path / "bad.xml"
        bad.write_text("<broken", encoding="utf-8")
        result = PARSER.parse(bad)
        assert result is None

    def test_empty_benchmark_returns_object_with_no_rules(self, tmp_path):
        xml = tmp_path / "empty.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="empty_benchmark">'
            '<title>Empty Test</title>'
            '</Benchmark>',
            encoding="utf-8",
        )
        result = PARSER.parse(xml)
        assert result is not None
        assert result.benchmark_id == "empty_benchmark"
        assert result.title == "Empty Test"
        assert len(result.rules) == 0
