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
        findings = parser.read(FIXTURE)[0]
        assert findings is not None

    def test_only_actionable_statuses_survive_filtering_expectations(self, parser):
        """Parser returns ALL rules; filtering is the pipeline's job. But the
        statuses must be mapped so filter_findings keeps exactly the right ones."""
        from app.processors.filter import filter_findings

        findings = parser.read(FIXTURE)[0].findings
        actionable = filter_findings(findings)
        assert {f.vuln_id for f in actionable} == {"V-254239", "V-254241", "V-254242"}

    def test_status_mapping(self, parser):
        findings = {f.vuln_id: f for f in parser.read(FIXTURE)[0].findings}
        assert findings["V-254239"].status == "Open"
        assert findings["V-254240"].status == "Not A Finding"
        assert findings["V-254241"].status == "Not Reviewed"
        assert findings["V-254243"].status == "Not Applicable"

    def test_severity_mapping(self, parser):
        findings = {f.vuln_id: f for f in parser.read(FIXTURE)[0].findings}
        assert findings["V-254239"].severity == "CAT I"     # high
        assert findings["V-254241"].severity == "CAT II"    # medium

    def test_severity_override_wins(self, parser):
        findings = {f.vuln_id: f for f in parser.read(FIXTURE)[0].findings}
        # V-254242 is low (CAT III) but carries an ISSM override to medium
        assert findings["V-254242"].severity == "CAT II"

    def test_host_metadata(self, parser):
        f = parser.read(FIXTURE)[0].findings[0]
        assert f.server == "WIN-SERVER-01"
        assert f.ip_address == "192.168.1.10"

    def test_inline_check_and_fix_text(self, parser):
        findings = {f.vuln_id: f for f in parser.read(FIXTURE)[0].findings}
        f = findings["V-254239"]
        assert "administrative account" in f.check_text
        assert "separate account" in f.fix_text

    def test_stig_title_uses_display_name(self, parser):
        f = parser.read(FIXTURE)[0].findings[0]
        assert f.stig_title == "Microsoft Windows Server 2022 STIG"

    def test_rule_id_from_rule_id_src(self, parser):
        findings = {f.vuln_id: f for f in parser.read(FIXTURE)[0].findings}
        assert findings["V-254239"].rule_id == "SV-254239r958472_rule"


class TestMalformedInput:
    def test_invalid_json_returns_none(self, parser, tmp_path):
        bad = tmp_path / "broken.cklb"
        bad.write_text("{not json", encoding="utf-8")
        assert parser.read(bad)[0] is None

    def test_json_but_not_cklb_returns_none(self, parser, tmp_path):
        notcklb = tmp_path / "other.cklb"
        notcklb.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
        assert parser.read(notcklb)[0] is None

    def test_stigs_not_a_list_returns_none(self, parser, tmp_path):
        f = tmp_path / "weird.cklb"
        f.write_text(json.dumps({"stigs": "oops"}), encoding="utf-8")
        assert parser.read(f)[0] is None

    def test_empty_rules_returns_empty_list_and_a_zero_rule_count(self, parser, tmp_path):
        f = tmp_path / "empty.cklb"
        f.write_text(
            json.dumps({"stigs": [{"stig_name": "X", "rules": []}], "target_data": {}}),
            encoding="utf-8",
        )
        result = parser.read(f)[0]
        assert result.findings == [] and result.rule_count == 0     # the run names the file for it

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
        findings = parser.read(f)[0].findings
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
        assert parser.read(f)[0].findings[0].status == "Unknown"

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
        findings = parser.read(f)[0].findings
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
        findings = parser.read(f)[0].findings
        assert len(findings) == 2
        assert {x.stig_title for x in findings} == {"STIG A", "STIG B"}


# --- STIG ID and scanned release ------------------------------------------------------

def test_findings_carry_stig_id_and_release():
    from pathlib import Path
    from app.parsers.cklb_parser import CKLBParser
    findings = CKLBParser().read(Path(__file__).parent / "fixtures" / "evaluate_stig_checklist.cklb")[0].findings
    first = next(f for f in findings if f.vuln_id == "V-254239")
    assert first.stig_id == "WN22-00-000010"
    assert first.scan_release == "V1R4"
    assert {f.scan_release for f in findings} == {"V1R4"}
    assert all(f.stig_id.startswith("WN22-00-0000") for f in findings)


def _checklist(tmp_path, stig_fields, rule_fields):
    rule = {"group_id": "V-1", "rule_id": "SV-1r1_rule", "severity": "medium", "status": "open", **rule_fields}
    doc = {"target_data": {"host_name": "H1", "ip_address": "N/A"},
           "stigs": [{"stig_name": "X", "rules": [rule], **stig_fields}]}
    path = tmp_path / "list.cklb"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def test_the_stig_id_is_normalised_and_each_stig_keeps_its_own_release(parser, tmp_path):
    doc = {"target_data": {"host_name": "H1", "ip_address": "N/A"}, "stigs": [
        {"stig_name": "A", "version": "2", "release_info": "Release: 8 Benchmark Date: 01 Jan 2026", "rules": [
            {"group_id": "V-1", "rule_id": "SV-1r1_rule", "severity": "low", "status": "open",
             "rule_version": "wn11_00_000150"}]},
        {"stig_name": "B", "version": 1, "rules": [
            {"group_id": "V-2", "rule_id": "SV-2r1_rule", "severity": "low", "status": "open"}]},
    ]}
    path = tmp_path / "two.cklb"
    path.write_text(json.dumps(doc), encoding="utf-8")
    a, b = parser.read(path)[0].findings
    assert (a.stig_id, a.scan_release) == ("WN11-00-000150", "V2R8")
    assert (b.stig_id, b.scan_release) == ("", "V1")          # no rule_version, no release_info: nothing invented


@pytest.mark.parametrize("hostile", [{"a": ["x" * 100_000]}, ["WN22-00-000010"], 5, True])
def test_a_stig_id_or_release_that_is_not_text_is_left_blank(parser, tmp_path, hostile):
    path = _checklist(tmp_path, {"version": hostile if not isinstance(hostile, int) else [hostile],
                                 "release_info": hostile}, {"rule_version": hostile})
    finding, = parser.read(path)[0].findings
    assert (finding.stig_id, finding.scan_release) == ("", "")


def test_a_huge_stig_id_or_version_is_bounded(parser, tmp_path):
    path = _checklist(tmp_path, {"version": "v" * 1_000_000}, {"rule_version": "s" * 1_000_000})
    finding, = parser.read(path)[0].findings
    assert len(finding.stig_id) <= 200 and len(finding.scan_release) <= 40


# --- a hostile results checklist: never a crash, never text made from a non-string -------

NOT_TEXT = [{"a": 1}, ["x", "y"], True, 12345, 1.5]


class TestHostileJson:
    def test_an_integer_literal_past_the_digit_limit_is_an_unreadable_file(self, parser, tmp_path):
        path = tmp_path / "huge_int.cklb"
        path.write_text('{"stigs": [], "n": ' + "9" * 5000 + "}", encoding="utf-8")
        result, why = parser.read(path)
        assert result is None and why.startswith("not valid JSON")

    def test_a_nesting_bomb_is_an_unreadable_file(self, parser, tmp_path):
        path = tmp_path / "nested.cklb"
        path.write_text("[" * 200_000, encoding="utf-8")
        assert parser.read(path)[0] is None

    def test_bytes_that_are_not_utf8_are_an_unreadable_file(self, parser, tmp_path):
        path = tmp_path / "binary.cklb"
        path.write_bytes(b"\xff\xfe\x00\x80")
        assert parser.read(path)[0] is None

    def test_a_missing_file_is_an_unreadable_file(self, parser, tmp_path):
        assert parser.read(tmp_path / "gone.cklb")[0] is None

    def test_the_reason_a_file_was_not_read_is_returned_not_logged(self, parser, tmp_path, caplog):
        # The caller names the file (by its display name, bounded): the reason carries no name.
        path = tmp_path / ("n" * 150 + ".cklb")
        path.write_text("{not json", encoding="utf-8")
        result, why = parser.read(path)
        assert result is None and why.startswith("not valid JSON") and "n" * 20 not in why
        assert caplog.records == []

    @pytest.mark.parametrize("target", [["a"], "text", 7, True, {"host_name": {"a": 1}, "ip_address": ["x"]}])
    def test_target_data_of_the_wrong_shape_falls_back_like_missing_data(self, parser, tmp_path, target):
        doc = {"target_data": target, "stigs": [{"stig_name": "X", "rules": [
            {"group_id": "V-1", "rule_id": "SV-1r1_rule", "severity": "medium", "status": "open"}]}]}
        path = tmp_path / "odd_target.cklb"
        path.write_text(json.dumps(doc), encoding="utf-8")
        finding, = parser.read(path)[0].findings
        assert (finding.server, finding.ip_address) == ("odd_target", "N/A")

    def test_a_non_text_host_name_falls_back_to_the_fqdn(self, parser, tmp_path):
        doc = {"target_data": {"host_name": {"a": 1}, "fqdn": "host.example", "ip_address": 5},
               "stigs": [{"stig_name": "X", "rules": [
                   {"group_id": "V-1", "rule_id": "SV-1r1_rule", "severity": "medium", "status": "open"}]}]}
        path = tmp_path / "list.cklb"
        path.write_text(json.dumps(doc), encoding="utf-8")
        finding, = parser.read(path)[0].findings
        assert (finding.server, finding.ip_address) == ("host.example", "N/A")


def _one_rule(tmp_path, rule_fields, stig_fields=None):
    rule = {"group_id": "V-1", "rule_id": "SV-1r1_rule", "severity": "medium", "status": "open",
            "check_content": "check", "fix_text": "fix", **rule_fields}
    stig = {"stig_name": "X STIG", "rules": [rule], **(stig_fields or {})}
    path = tmp_path / "list.cklb"
    path.write_text(json.dumps({"target_data": {"host_name": "H1", "ip_address": "N/A"}, "stigs": [stig]}),
                    encoding="utf-8")
    return path


class TestTextComesFromStringsOnly:
    @pytest.mark.parametrize("bad", NOT_TEXT)
    def test_check_and_fix_text_that_are_not_text_are_blank(self, parser, tmp_path, bad):
        finding, = parser.read(_one_rule(tmp_path, {"check_content": bad, "fix_text": bad}))[0].findings
        assert (finding.check_text, finding.fix_text) == ("", "")       # never "{'a': 1}" or "True"

    @pytest.mark.parametrize("bad", NOT_TEXT)
    def test_a_title_that_is_not_text_falls_back_to_the_next_title_field(self, parser, tmp_path, bad):
        finding, = parser.read(_one_rule(tmp_path, {}, {"display_name": bad, "stig_name": "X STIG"}))[0].findings
        assert finding.stig_title == "X STIG"
        finding, = parser.read(_one_rule(tmp_path, {}, {"display_name": bad, "stig_name": bad, "stig_id": bad}))[0].findings
        assert finding.stig_title == "Unknown STIG"

    @pytest.mark.parametrize("bad", NOT_TEXT)
    def test_an_id_that_is_not_text_falls_back_to_the_next_id_field(self, parser, tmp_path, bad):
        finding, = parser.read(_one_rule(tmp_path, {
            "group_id": bad, "group_id_src": "V-9", "rule_id_src": bad, "rule_id": "SV-9r1_rule", "rule_version": bad}))[0].findings
        assert (finding.vuln_id, finding.rule_id, finding.stig_id) == ("V-9", "SV-9r1_rule", "")

    @pytest.mark.parametrize("bad", NOT_TEXT)
    def test_a_rule_with_no_text_id_at_all_is_skipped_not_invented(self, parser, tmp_path, bad, caplog):
        path = _one_rule(tmp_path, {"group_id": bad, "group_id_src": bad, "rule_id_src": bad, "rule_id": bad})
        assert parser.read(path)[0].findings == []
        assert any("no group_id/rule_id" in r.getMessage() for r in caplog.records)

    @pytest.mark.parametrize("bad", NOT_TEXT + [0, False, [], {}, ["open"], 1])
    def test_a_status_that_is_not_text_is_reported_as_unknown(self, parser, tmp_path, bad, caplog):
        # Fail closed: the rule has a status the parser cannot read, so the row is shown for
        # review. It is never dropped, and never read as the "open" inside ["open"].
        from app.processors.filter import filter_findings
        result = parser.read(_one_rule(tmp_path, {"status": bad}))[0]
        finding, = result.findings
        assert finding.status == "Unknown" and (finding.vuln_id, finding.rule_id) == ("V-1", "SV-1r1_rule")
        assert filter_findings([finding]) == [finding]
        assert any("status that is not text" in r.getMessage() for r in caplog.records)
        assert result.ignored_values == 1

    @pytest.mark.parametrize("blank", ["", "   ", None])
    def test_a_blank_or_missing_status_is_still_skipped_with_a_log_warning(self, parser, tmp_path, blank, caplog):
        result = parser.read(_one_rule(tmp_path, {"status": blank}))[0]
        assert result.findings == []
        assert any("no status" in r.getMessage().lower() for r in caplog.records)
        assert result.ignored_values == 0
        path = _one_rule(tmp_path, {})
        doc = json.loads(path.read_text(encoding="utf-8"))
        del doc["stigs"][0]["rules"][0]["status"]
        path.write_text(json.dumps(doc), encoding="utf-8")
        assert parser.read(path)[0].findings == []

    def test_a_rule_with_an_unreadable_status_and_no_usable_id_is_skipped(self, parser, tmp_path):
        path = _one_rule(tmp_path, {"status": ["open"], "group_id": 5, "rule_id": {"a": 1}})
        assert parser.read(path)[0].findings == []


class TestIgnoredValuesAreCounted:
    def test_every_non_text_value_the_parser_ignored_is_counted(self, parser, tmp_path):
        path = _one_rule(tmp_path, {"check_content": {"a": 1}, "fix_text": ["x"], "rule_version": 7, "severity": True},
                         {"display_name": {"x": 1}, "release_info": ["Release: 4"]})
        result = parser.read(path)[0]
        finding, = result.findings
        assert result.ignored_values == 6
        assert (finding.check_text, finding.fix_text, finding.stig_id, finding.severity) == ("", "", "", "Unknown")

    def test_a_clean_checklist_and_missing_values_count_nothing(self, parser):
        result = parser.read(FIXTURE)[0]
        assert result.findings and result.ignored_values == 0

    def test_an_integer_version_is_not_an_ignored_value(self, parser, tmp_path):
        result = parser.read(_one_rule(tmp_path, {}, {"version": 2, "release_info": "Release: 8"}))[0]
        finding, = result.findings
        assert finding.scan_release == "V2R8" and result.ignored_values == 0

    def test_each_file_has_its_own_count(self, parser, tmp_path):
        assert parser.read(_one_rule(tmp_path, {"check_content": {"a": 1}}))[0].ignored_values == 1
        assert parser.read(FIXTURE)[0].ignored_values == 0
        broken = tmp_path / "broken.cklb"
        broken.write_text("{not json", encoding="utf-8")
        assert parser.read(broken)[0] is None

    @pytest.mark.parametrize("bad", NOT_TEXT)
    def test_a_severity_that_is_not_text_is_unknown(self, parser, tmp_path, bad):
        finding, = parser.read(_one_rule(tmp_path, {"severity": bad}))[0].findings
        assert finding.severity == "Unknown"

    @pytest.mark.parametrize("overrides", [["x"], "text", 5, {"severity": ["x"]}, {"severity": {"severity": {"a": 1}}},
                                           {"severity": {"severity": 5, "value": ["high"]}}])
    def test_a_severity_override_of_the_wrong_shape_is_ignored(self, parser, tmp_path, overrides):
        finding, = parser.read(_one_rule(tmp_path, {"severity": "low", "overrides": overrides}))[0].findings
        assert finding.severity == "CAT III"

    def test_a_well_formed_override_still_wins(self, parser, tmp_path):
        finding, = parser.read(_one_rule(tmp_path, {"severity": "low", "overrides": {"severity": {"severity": "high"}}}))[0].findings
        assert finding.severity == "CAT I"

    def test_no_field_ever_holds_the_repr_of_a_json_value(self, parser, tmp_path):
        bad = {"a": 1}
        path = _one_rule(tmp_path, {"check_content": bad, "fix_text": bad, "rule_version": bad, "group_id_src": bad,
                                    "rule_id_src": bad, "severity": bad},
                         {"display_name": bad, "version": bad, "release_info": bad})
        finding, = parser.read(path)[0].findings
        assert not any("{" in value for value in vars(finding).values())


class TestSkippedRulesAreCounted:
    def _checklist(self, tmp_path, statuses):
        rules = [{"group_id": f"V-{n}", "rule_id": f"SV-{n}r1_rule", "severity": "medium", **status}
                 for n, status in enumerate(statuses, 1)]
        path = tmp_path / "list.cklb"
        path.write_text(json.dumps({"target_data": {"host_name": "H1", "ip_address": "N/A"},
                                    "stigs": [{"stig_name": "X", "rules": rules}]}), encoding="utf-8")
        return path

    def test_rules_with_a_blank_null_or_missing_status_are_counted(self, parser, tmp_path):
        path = self._checklist(tmp_path, [{"status": ""}, {"status": "   "}, {"status": None}, {},
                                          {"status": "open"}, {"status": ["open"]}])
        result = parser.read(path)[0]
        assert [(f.vuln_id, f.status) for f in result.findings] == [("V-5", "Open"), ("V-6", "Unknown")]
        assert result.skipped_rules == 4
        assert result.ignored_values == 1                # the list; a blank status is not a non-text value

    def test_a_clean_checklist_skips_nothing(self, parser):
        result = parser.read(FIXTURE)[0]
        assert result.findings and result.skipped_rules == 0

    def test_each_file_has_its_own_count(self, parser, tmp_path):
        assert parser.read(self._checklist(tmp_path, [{"status": ""}]))[0].skipped_rules == 1
        assert parser.read(FIXTURE)[0].skipped_rules == 0
        broken = tmp_path / "broken.cklb"
        broken.write_text("{not json", encoding="utf-8")
        assert parser.read(broken)[0] is None


def _malformed_checklist(tmp_path):
    """The fixture plus six entries of the wrong shape: three rules (two not objects, one with no
    usable ID) and three STIG entries (one not an object, two with no rules list)."""
    doc = json.loads(FIXTURE.read_text(encoding="utf-8-sig"))
    doc["stigs"][0]["rules"] += [["not", "a", "rule"], {"status": "open", "severity": "low"}, 7]
    doc["stigs"] += ["not a stig", {"display_name": "No rules", "rules": "nope"}, {"display_name": "Missing"}]
    path = tmp_path / "malformed.cklb"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


class TestMalformedEntriesAreCounted:
    def test_every_entry_dropped_for_its_shape_is_counted(self, parser, tmp_path):
        result = parser.read(_malformed_checklist(tmp_path))[0]
        assert len(result.findings) == 5            # every well-formed rule is still read
        assert result.malformed_entries == 6

    def test_a_clean_checklist_counts_nothing(self, parser):
        result = parser.read(FIXTURE)[0]
        assert result.findings and result.malformed_entries == 0

    def test_each_file_has_its_own_count(self, parser, tmp_path):
        assert parser.read(_malformed_checklist(tmp_path))[0].malformed_entries == 6
        assert parser.read(FIXTURE)[0].malformed_entries == 0
        broken = tmp_path / "broken.cklb"
        broken.write_text("{not json", encoding="utf-8")
        assert parser.read(broken)[0] is None
