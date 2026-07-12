"""Tests for app.parsers.cklb_parser — STIG Viewer 3 / Evaluate-STIG CKLB files."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.parsers.cklb_parser import CKLBParser

FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE = FIXTURES / "evaluate_stig_checklist.cklb"


@pytest.fixture()
def parser() -> CKLBParser:
    return CKLBParser()


class TestFixtureParsing:
    def test_parses_fixture(self, parser):
        findings = parser.parse(FIXTURE)
        assert findings is not None

    def test_only_actionable_statuses_survive_filtering_expectations(self, parser):
        """Parser returns ALL rules; filtering is the pipeline's job. But the
        statuses must be mapped so filter_findings keeps exactly the right ones."""
        from app.processors.filter import filter_findings

        findings = parser.parse(FIXTURE)
        actionable = filter_findings(findings)
        assert {f.vuln_id for f in actionable} == {"V-254239", "V-254241", "V-254242"}

    def test_status_mapping(self, parser):
        findings = {f.vuln_id: f for f in parser.parse(FIXTURE)}
        assert findings["V-254239"].status == "Open"
        assert findings["V-254240"].status == "Not A Finding"
        assert findings["V-254241"].status == "Not Reviewed"
        assert findings["V-254243"].status == "Not Applicable"

    def test_severity_mapping(self, parser):
        findings = {f.vuln_id: f for f in parser.parse(FIXTURE)}
        assert findings["V-254239"].severity == "CAT I"     # high
        assert findings["V-254241"].severity == "CAT II"    # medium

    def test_severity_override_wins(self, parser):
        findings = {f.vuln_id: f for f in parser.parse(FIXTURE)}
        # V-254242 is low (CAT III) but carries an ISSM override to medium
        assert findings["V-254242"].severity == "CAT II"

    def test_host_metadata(self, parser):
        f = parser.parse(FIXTURE)[0]
        assert f.server == "WIN-SERVER-01"
        assert f.ip_address == "192.168.1.10"

    def test_inline_check_and_fix_text(self, parser):
        findings = {f.vuln_id: f for f in parser.parse(FIXTURE)}
        f = findings["V-254239"]
        assert "administrative account" in f.check_text
        assert "separate account" in f.fix_text

    def test_stig_title_uses_display_name(self, parser):
        f = parser.parse(FIXTURE)[0]
        assert f.stig_title == "Microsoft Windows Server 2022 STIG"

    def test_rule_id_from_rule_id_src(self, parser):
        findings = {f.vuln_id: f for f in parser.parse(FIXTURE)}
        assert findings["V-254239"].rule_id == "SV-254239r958472_rule"


class TestMalformedInput:
    def test_invalid_json_returns_none(self, parser, tmp_path):
        bad = tmp_path / "broken.cklb"
        bad.write_text("{not json", encoding="utf-8")
        assert parser.parse(bad) is None

    def test_json_but_not_cklb_returns_none(self, parser, tmp_path):
        notcklb = tmp_path / "other.cklb"
        notcklb.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
        assert parser.parse(notcklb) is None

    def test_stigs_not_a_list_returns_none(self, parser, tmp_path):
        f = tmp_path / "weird.cklb"
        f.write_text(json.dumps({"stigs": "oops"}), encoding="utf-8")
        assert parser.parse(f) is None

    def test_empty_rules_returns_empty_list_with_warning(self, parser, tmp_path, caplog):
        f = tmp_path / "empty.cklb"
        f.write_text(
            json.dumps({"stigs": [{"stig_name": "X", "rules": []}], "target_data": {}}),
            encoding="utf-8",
        )
        result = parser.parse(f)
        assert result == []
        assert any("0 rules" in r.message for r in caplog.records)

    def test_rule_missing_status_skipped_with_warning(self, parser, tmp_path, caplog):
        doc = {
            "target_data": {"host_name": "H1", "ip_address": "1.2.3.4"},
            "stigs": [{
                "stig_name": "X",
                "rules": [
                    {"group_id": "V-1", "rule_id": "SV-1r1_rule", "severity": "high"},
                    {"group_id": "V-2", "rule_id": "SV-2r1_rule", "severity": "low",
                     "status": "open"},
                ],
            }],
        }
        f = tmp_path / "partial.cklb"
        f.write_text(json.dumps(doc), encoding="utf-8")
        findings = parser.parse(f)
        assert [x.vuln_id for x in findings] == ["V-2"]
        assert any("no status" in r.message.lower() for r in caplog.records)

    def test_unknown_status_maps_to_unknown(self, parser, tmp_path):
        """Fail loud, not silent: a status we don't recognise is kept as
        'Unknown' so it survives filtering and appears in the report."""
        doc = {
            "target_data": {"host_name": "H1", "ip_address": "1.2.3.4"},
            "stigs": [{
                "stig_name": "X",
                "rules": [{"group_id": "V-1", "rule_id": "SV-1r1_rule",
                           "severity": "medium", "status": "banana"}],
            }],
        }
        f = tmp_path / "weirdstatus.cklb"
        f.write_text(json.dumps(doc), encoding="utf-8")
        assert parser.parse(f)[0].status == "Unknown"

    def test_missing_hostname_falls_back_to_filename(self, parser, tmp_path, caplog):
        doc = {
            "target_data": {},
            "stigs": [{
                "stig_name": "X",
                "rules": [{"group_id": "V-1", "rule_id": "SV-1r1_rule",
                           "severity": "medium", "status": "open"}],
            }],
        }
        f = tmp_path / "no_host.cklb"
        f.write_text(json.dumps(doc), encoding="utf-8")
        findings = parser.parse(f)
        assert findings[0].server == "no_host"
        assert findings[0].ip_address == "N/A"


class TestMultiStig:
    def test_multiple_stigs_in_one_checklist(self, parser, tmp_path):
        doc = {
            "target_data": {"host_name": "H1", "ip_address": "1.2.3.4"},
            "stigs": [
                {"stig_name": "STIG A", "rules": [
                    {"group_id": "V-1", "rule_id": "SV-1r1_rule",
                     "severity": "high", "status": "open"}]},
                {"stig_name": "STIG B", "rules": [
                    {"group_id": "V-2", "rule_id": "SV-2r1_rule",
                     "severity": "low", "status": "open"}]},
            ],
        }
        f = tmp_path / "multi.cklb"
        f.write_text(json.dumps(doc), encoding="utf-8")
        findings = parser.parse(f)
        assert len(findings) == 2
        assert {x.stig_title for x in findings} == {"STIG A", "STIG B"}
