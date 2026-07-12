"""Tests for app.parsers.nessus_parser — Tenable .nessus compliance scans."""
from __future__ import annotations

from pathlib import Path

import pytest

from app.parsers.nessus_parser import NessusComplianceParser
from app.processors.filter import filter_findings

FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE = FIXTURES / "nessus_compliance.nessus"


@pytest.fixture()
def parser() -> NessusComplianceParser:
    return NessusComplianceParser()


class TestFixtureParsing:
    def test_parses_fixture(self, parser):
        findings = parser.parse(FIXTURE)
        assert findings is not None
        # 5 compliance items; the Service Detection ReportItem is ignored
        assert len(findings) == 5

    def test_actionable_statuses(self, parser):
        actionable = filter_findings(parser.parse(FIXTURE))
        # FAILED + WARNING + ERROR + FAILED-custom; PASSED filtered out
        assert len(actionable) == 4

    def test_status_mapping(self, parser):
        by_id = {f.vuln_id: f for f in parser.parse(FIXTURE) if f.vuln_id}
        assert by_id["V-204392"].status == "Open"           # FAILED
        assert by_id["V-204393"].status == "Not A Finding"  # PASSED
        assert by_id["V-204394"].status == "Not Reviewed"   # WARNING
        assert by_id["V-204395"].status == "Error"          # ERROR

    def test_severity_from_cat_token(self, parser):
        by_id = {f.vuln_id: f for f in parser.parse(FIXTURE) if f.vuln_id}
        assert by_id["V-204392"].severity == "CAT I"
        assert by_id["V-204394"].severity == "CAT III"
        assert by_id["V-204395"].severity == "CAT II"

    def test_ids_from_reference_tokens(self, parser):
        by_id = {f.vuln_id: f for f in parser.parse(FIXTURE) if f.vuln_id}
        assert by_id["V-204392"].rule_id == "SV-204392r646841_rule"

    def test_item_without_disa_tokens_falls_back_to_check_name(self, parser):
        no_ref = [f for f in parser.parse(FIXTURE) if not f.vuln_id]
        assert len(no_ref) == 1
        f = no_ref[0]
        assert f.status == "Open"
        assert f.severity == "Unknown"  # no CAT token — do not guess
        assert "Custom site check" in f.rule_id

    def test_host_metadata_prefers_fqdn_over_ip_name(self, parser):
        f = parser.parse(FIXTURE)[0]
        assert f.server == "rhel7-lab-01.example.mil"
        assert f.ip_address == "192.168.77.10"

    def test_check_text_includes_info_and_actual_value(self, parser):
        by_id = {f.vuln_id: f for f in parser.parse(FIXTURE) if f.vuln_id}
        f = by_id["V-204392"]
        assert "Discretionary access control" in f.check_text
        assert "0644" in f.check_text  # scanner's actual observed value

    def test_fix_text_from_solution(self, parser):
        by_id = {f.vuln_id: f for f in parser.parse(FIXTURE) if f.vuln_id}
        assert "rpm --setperms" in by_id["V-204392"].fix_text

    def test_stig_title_from_benchmark_name(self, parser):
        by_id = {f.vuln_id: f for f in parser.parse(FIXTURE) if f.vuln_id}
        assert by_id["V-204392"].stig_title == "DISA STIG Red Hat Enterprise Linux 7"

    def test_title_falls_back_to_audit_file(self, parser):
        no_ref = [f for f in parser.parse(FIXTURE) if not f.vuln_id]
        assert no_ref[0].stig_title == "site_custom.audit"


class TestMalformedInput:
    def test_invalid_xml_returns_none(self, parser, tmp_path):
        bad = tmp_path / "bad.nessus"
        bad.write_text("<NessusClientData_v2><unclosed", encoding="utf-8")
        assert parser.parse(bad) is None

    def test_wrong_root_returns_none(self, parser, tmp_path, caplog):
        f = tmp_path / "notnessus.nessus"
        f.write_text("<SomethingElse/>", encoding="utf-8")
        assert parser.parse(f) is None
        assert any("NessusClientData" in r.message for r in caplog.records)

    def test_vuln_scan_without_compliance_items_warns(self, parser, tmp_path, caplog):
        f = tmp_path / "vulnscan.nessus"
        f.write_text(
            '<NessusClientData_v2><Report><ReportHost name="10.0.0.1">'
            '<HostProperties><tag name="host-ip">10.0.0.1</tag></HostProperties>'
            '<ReportItem port="443" severity="2" pluginID="12345" '
            'pluginName="Some CVE" pluginFamily="General"/>'
            "</ReportHost></Report></NessusClientData_v2>",
            encoding="utf-8",
        )
        findings = parser.parse(f)
        assert findings == []
        assert any("no Policy Compliance" in r.message for r in caplog.records)

    def test_unknown_compliance_result_maps_to_unknown(self, parser, tmp_path):
        f = tmp_path / "weird.nessus"
        f.write_text(
            '<NessusClientData_v2><Report xmlns:cm="http://www.nessus.org/cm">'
            '<ReportHost name="10.0.0.1">'
            '<HostProperties><tag name="host-ip">10.0.0.1</tag></HostProperties>'
            '<ReportItem port="0" severity="2" pluginID="21157" '
            'pluginName="Unix Compliance Checks" pluginFamily="Policy Compliance">'
            "<cm:compliance-check-name>X - check</cm:compliance-check-name>"
            "<cm:compliance-result>BANANA</cm:compliance-result>"
            "</ReportItem></ReportHost></Report></NessusClientData_v2>",
            encoding="utf-8",
        )
        findings = parser.parse(f)
        assert findings[0].status == "Unknown"

    def test_multi_host_report(self, parser, tmp_path):
        item = (
            '<ReportItem port="0" severity="2" pluginID="21157" '
            'pluginName="Unix Compliance Checks" pluginFamily="Policy Compliance">'
            "<cm:compliance-check-name>X - check</cm:compliance-check-name>"
            "<cm:compliance-result>FAILED</cm:compliance-result>"
            "<cm:compliance-reference>CAT|II,Vuln-ID|V-1</cm:compliance-reference>"
            "</ReportItem>"
        )
        f = tmp_path / "twohosts.nessus"
        f.write_text(
            '<NessusClientData_v2><Report xmlns:cm="http://www.nessus.org/cm">'
            f'<ReportHost name="10.0.0.1"><HostProperties>'
            f'<tag name="host-ip">10.0.0.1</tag></HostProperties>{item}</ReportHost>'
            f'<ReportHost name="10.0.0.2"><HostProperties>'
            f'<tag name="host-ip">10.0.0.2</tag></HostProperties>{item}</ReportHost>'
            "</Report></NessusClientData_v2>",
            encoding="utf-8",
        )
        findings = parser.parse(f)
        assert len(findings) == 2
        assert {x.server for x in findings} == {"10.0.0.1", "10.0.0.2"}
