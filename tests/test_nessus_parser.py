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
        findings = parser.read(FIXTURE)[0]
        assert findings is not None
        # 5 compliance items; the Service Detection ReportItem is ignored
        assert len(findings) == 5

    def test_actionable_statuses(self, parser):
        actionable = filter_findings(parser.read(FIXTURE)[0])
        # FAILED + WARNING + ERROR + FAILED-custom; PASSED filtered out
        assert len(actionable) == 4

    def test_status_mapping(self, parser):
        by_id = {f.vuln_id: f for f in parser.read(FIXTURE)[0] if f.vuln_id}
        assert by_id["V-204392"].status == "Open"           # FAILED
        assert by_id["V-204393"].status == "Not A Finding"  # PASSED
        assert by_id["V-204394"].status == "Not Reviewed"   # WARNING
        assert by_id["V-204395"].status == "Error"          # ERROR

    def test_severity_from_cat_token(self, parser):
        by_id = {f.vuln_id: f for f in parser.read(FIXTURE)[0] if f.vuln_id}
        assert by_id["V-204392"].severity == "CAT I"
        assert by_id["V-204394"].severity == "CAT III"
        assert by_id["V-204395"].severity == "CAT II"

    def test_ids_from_reference_tokens(self, parser):
        by_id = {f.vuln_id: f for f in parser.read(FIXTURE)[0] if f.vuln_id}
        assert by_id["V-204392"].rule_id == "SV-204392r646841_rule"

    def test_item_without_disa_tokens_falls_back_to_check_name(self, parser):
        no_ref = [f for f in parser.read(FIXTURE)[0] if not f.vuln_id]
        assert len(no_ref) == 1
        f = no_ref[0]
        assert f.status == "Open"
        assert f.severity == "Unknown"  # no CAT token — do not guess
        assert "Custom site check" in f.rule_id

    def test_host_metadata_prefers_fqdn_over_ip_name(self, parser):
        f = parser.read(FIXTURE)[0][0]
        assert f.server == "rhel7-lab-01.example.mil"
        assert f.ip_address == "192.168.77.10"

    def test_check_text_includes_info_and_actual_value(self, parser):
        by_id = {f.vuln_id: f for f in parser.read(FIXTURE)[0] if f.vuln_id}
        f = by_id["V-204392"]
        assert "Discretionary access control" in f.check_text
        assert "0644" in f.check_text  # scanner's actual observed value

    def test_fix_text_from_solution(self, parser):
        by_id = {f.vuln_id: f for f in parser.read(FIXTURE)[0] if f.vuln_id}
        assert "rpm --setperms" in by_id["V-204392"].fix_text

    def test_stig_title_from_benchmark_name(self, parser):
        by_id = {f.vuln_id: f for f in parser.read(FIXTURE)[0] if f.vuln_id}
        assert by_id["V-204392"].stig_title == "DISA STIG Red Hat Enterprise Linux 7"

    def test_title_falls_back_to_audit_file(self, parser):
        no_ref = [f for f in parser.read(FIXTURE)[0] if not f.vuln_id]
        assert no_ref[0].stig_title == "site_custom.audit"


class TestMalformedInput:
    def test_invalid_xml_returns_none(self, parser, tmp_path):
        bad = tmp_path / "bad.nessus"
        bad.write_text("<NessusClientData_v2><unclosed", encoding="utf-8")
        assert parser.read(bad)[0] is None

    def test_wrong_root_returns_none_and_says_why(self, parser, tmp_path):
        f = tmp_path / "notnessus.nessus"
        f.write_text("<SomethingElse/>", encoding="utf-8")
        findings, why = parser.read(f)
        assert findings is None and "NessusClientData" in why

    def test_vuln_scan_without_compliance_items_has_no_findings(self, parser, tmp_path):
        f = tmp_path / "vulnscan.nessus"
        f.write_text(
            '<NessusClientData_v2><Report><ReportHost name="10.0.0.1">'
            '<HostProperties><tag name="host-ip">10.0.0.1</tag></HostProperties>'
            '<ReportItem port="443" severity="2" pluginID="12345" '
            'pluginName="Some CVE" pluginFamily="General"/>'
            "</ReportHost></Report></NessusClientData_v2>",
            encoding="utf-8",
        )
        # Read, with nothing in it: the run says why (a vulnerability scan is not a compliance scan).
        assert parser.read(f) == ([], "")

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
        findings = parser.read(f)[0]
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
        findings = parser.read(f)[0]
        assert len(findings) == 2
        assert {x.server for x in findings} == {"10.0.0.1", "10.0.0.2"}


# --- the STIG ID token ------------------------------------------------------------------

def test_findings_carry_the_stig_id_token():
    from pathlib import Path
    from app.parsers.nessus_parser import NessusComplianceParser
    findings = NessusComplianceParser().read(Path(__file__).parent / "fixtures" / "nessus_compliance.nessus")[0]
    with_reference = [f for f in findings if f.vuln_id]
    assert with_reference, "fixture should contain DISA-referenced items"
    assert all(f.stig_id for f in with_reference)
    assert {f.vuln_id: f.stig_id for f in with_reference} == {
        "V-204392": "RHEL-07-010010", "V-204393": "RHEL-07-010020",
        "V-204394": "RHEL-07-010030", "V-204395": "RHEL-07-010040"}
    custom, = [f for f in findings if not f.vuln_id]
    assert custom.stig_id == ""                 # no STIG-ID token: a check name is never taken for one
    assert all(f.scan_release == "" for f in findings)   # the audit file's version is not a STIG release


def _one_item(tmp_path, reference):
    path = tmp_path / "one.nessus"
    path.write_text(
        '<NessusClientData_v2><Report xmlns:cm="http://www.nessus.org/cm">'
        '<ReportHost name="HOST-A"><HostProperties><tag name="host-ip">N/A</tag></HostProperties>'
        '<ReportItem port="0" severity="2" pluginID="21157" '
        'pluginName="Unix Compliance Checks" pluginFamily="Policy Compliance">'
        "<cm:compliance-check-name>X - check</cm:compliance-check-name>"
        "<cm:compliance-result>FAILED</cm:compliance-result>"
        f"<cm:compliance-reference>{reference}</cm:compliance-reference>"
        "<cm:compliance-benchmark-name>DISA STIG Product X</cm:compliance-benchmark-name>"
        "</ReportItem></ReportHost></Report></NessusClientData_v2>",
        encoding="utf-8",
    )
    return path


def test_a_stig_id_that_doubles_as_the_rule_id_is_also_the_stig_id(parser, tmp_path):
    finding, = parser.read(_one_item(tmp_path, "CAT|II,STIG-ID|rhel_07_010010"))[0]
    assert finding.rule_id == "rhel_07_010010"          # no Rule-ID token: the STIG ID stands in, as written
    assert finding.stig_id == "RHEL-07-010010"          # and is recorded as the STIG ID, normalised
    assert finding.stig_title == "DISA STIG Product X"


def test_the_stig_id_is_normalised_and_bounded(parser, tmp_path):
    finding, = parser.read(_one_item(tmp_path, "Rule-ID|SV-1r1_rule,STIG-ID|DISA-STIG-rhel_07_010010"))[0]
    assert (finding.rule_id, finding.stig_id) == ("SV-1r1_rule", "RHEL-07-010010")
    finding, = parser.read(_one_item(tmp_path, "Rule-ID|SV-1r1_rule,STIG-ID|" + "s" * 100_000))[0]
    assert len(finding.stig_id) <= 200
