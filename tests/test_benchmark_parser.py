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
