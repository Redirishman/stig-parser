import json
import logging
from pathlib import Path

import pytest

from app.parsers.base import Finding
from app.reference.cklb_loader import load_cklb_reference
from app.reference.library import ReferenceLibrary


def _candidates(lib, finding):
    """The rules a lookup offers for *finding*, best first."""
    return [rule for rule, _ in lib.lookup(finding).matches]


FIX = Path(__file__).parent / "fixtures"


def test_loads_every_rule_with_text_and_ids():
    loaded = load_cklb_reference(FIX / "evaluate_stig_checklist.cklb", embedded=False)
    assert (loaded.readable, loaded.ignored_values, loaded.rule_count) == (True, 0, 5)
    assert len(loaded.stigs) == 1
    source, rules = loaded.stigs[0]
    assert (source.edition, source.embedded, source.release) == ("cklb", False, "V1R4")
    assert source.title == "Microsoft Windows Server 2022 STIG"
    assert source.rule_count == 5
    first = rules[0]
    assert (first.vuln_id, first.rule_id, first.rule_stem, first.revision) == (
        "V-254239", "SV-254239r958472_rule", "SV-254239", "r958472")
    assert first.stig_id == "WN22-00-000010"
    assert first.severity == "CAT I"
    assert first.check_text and first.fix_text


def _unreadable(loaded) -> bool:
    """Not a checklist at all: nothing loaded, and the result says so."""
    return (loaded.stigs, loaded.readable, loaded.rule_count) == ([], False, 0)


def test_invalid_or_non_cklb_json_returns_empty(tmp_path):
    bad = tmp_path / "bad.cklb"
    bad.write_text("{not json", encoding="utf-8")
    assert _unreadable(load_cklb_reference(bad, embedded=False))
    other = tmp_path / "other.cklb"
    other.write_text('{"hello": 1}', encoding="utf-8")
    assert _unreadable(load_cklb_reference(other, embedded=False))


def test_hostile_json_returns_empty_instead_of_raising(tmp_path):
    # Untrusted upload: a nesting bomb, an integer literal past int()'s digit
    # limit, and bytes that are not UTF-8 must all be treated as "not a CKLB".
    nested = tmp_path / "nested.cklb"
    nested.write_text("[" * 200000, encoding="utf-8")
    assert _unreadable(load_cklb_reference(nested, embedded=False))
    huge_int = tmp_path / "huge_int.cklb"
    huge_int.write_text('{"stigs": [], "n": ' + "9" * 5000 + "}", encoding="utf-8")
    assert _unreadable(load_cklb_reference(huge_int, embedded=False))
    binary = tmp_path / "binary.cklb"
    binary.write_bytes(b"\xff\xfe\x00\x80")
    assert _unreadable(load_cklb_reference(binary, embedded=False))


# --- identifiers and malformed entries ---------------------------------------

def _cklb(tmp_path, stigs):
    path = tmp_path / "list.cklb"
    path.write_text(json.dumps({"stigs": stigs}), encoding="utf-8")
    return path


def _rule(**overrides):
    rule = {"severity": "high", "rule_version": "WN22-00-000010", "check_content": "check", "fix_text": "fix"}
    rule.update(overrides)
    return rule


def test_xccdf_prefixes_are_stripped_from_group_and_rule_ids(tmp_path):
    path = _cklb(tmp_path, [{"stig_id": "X", "display_name": "X STIG", "version": 1, "rules": [
        _rule(group_id_src="xccdf_mil.disa.stig_group_V-254239",
              rule_id_src="xccdf_mil.disa.stig_rule_SV-254239r958472_rule"),
        _rule(group_id="xccdf_mil.disa.stig_group_V-254240", rule_id="xccdf_mil.disa.stig_rule_SV-254240r958473_rule"),
    ]}])
    (source, rules), = load_cklb_reference(path, embedded=False).stigs
    assert [(r.vuln_id, r.rule_id, r.rule_stem, r.revision) for r in rules] == [
        ("V-254239", "SV-254239r958472_rule", "SV-254239", "r958472"),
        ("V-254240", "SV-254240r958473_rule", "SV-254240", "r958473"),
    ]


def test_a_checklist_with_only_prefixed_group_ids_is_found_by_vuln_id(tmp_path):
    path = _cklb(tmp_path, [{"stig_id": "X", "display_name": "X STIG", "version": 1, "rules": [
        _rule(group_id_src="xccdf_mil.disa.stig_group_V-254239",
              rule_id_src="xccdf_mil.disa.stig_rule_SV-254239r958472_rule"),
    ]}])
    lib = ReferenceLibrary()
    for source, rules in load_cklb_reference(path, embedded=False).stigs:
        lib.add_rules(source, rules)
    hits = _candidates(lib, Finding("X STIG", "V-254239", "", "", "Open", "h", "i", "", ""))
    assert [h.check_text for h in hits] == ["check"]


def test_a_stig_entry_without_a_rules_list_is_counted_and_the_rest_still_load(tmp_path, caplog):
    path = _cklb(tmp_path, [
        {"stig_id": "BROKEN", "display_name": "Broken STIG", "version": 1},
        {"stig_id": "X", "display_name": "X STIG", "version": 1,
         "rules": [_rule(group_id="V-1", rule_id_src="SV-1r1_rule")]},
    ])
    with caplog.at_level(logging.WARNING, logger="app.reference.cklb_loader"):
        reference = load_cklb_reference(path, embedded=False)
    assert [source.title for source, _ in reference.stigs] == ["X STIG"]
    assert reference.malformed_entries == 1              # the caller reports it (one line per file)
    assert caplog.records == []                          # and nothing says it a second time


# --- text comes from strings only ----------------------------------------------


def _reference(tmp_path, stig, name="list.cklb"):
    path = tmp_path / name
    path.write_text(json.dumps({"stigs": [stig]}), encoding="utf-8")
    return load_cklb_reference(path, embedded=False)


def _load(tmp_path, stig, name="list.cklb"):
    return _reference(tmp_path, stig, name).stigs


@pytest.mark.parametrize("bad", [{"nested": "value"}, True, False, 12345, 1.5, ["a", "b"]])
def test_non_string_values_never_become_text(tmp_path, caplog, bad):
    stig = {"stig_id": "X", "display_name": "X STIG", "version": 1, "rules": [
        {"group_id": "V-1", "rule_id_src": "SV-1r1_rule", "rule_version": bad, "severity": bad,
         "check_content": bad, "fix_text": bad}]}
    with caplog.at_level(logging.WARNING, logger="app.reference.cklb_loader"):
        reference = _reference(tmp_path, stig)
    (source, rules), = reference.stigs
    rule, = rules
    assert (rule.check_text, rule.fix_text, rule.stig_id, rule.severity) == ("", "", "", "")
    assert (rule.vuln_id, rule.rule_id) == ("V-1", "SV-1r1_rule")        # still loaded, found by its IDs
    assert reference.ignored_values == 4 and caplog.records == []


def test_a_non_string_id_falls_back_to_the_next_id_field(tmp_path, caplog):
    stig = {"stig_id": "X", "display_name": "X STIG", "version": 1, "rules": [
        {"group_id": {"a": 1}, "group_id_src": "xccdf_mil.disa.stig_group_V-9",
         "rule_id_src": 12345, "rule_id": "SV-9r1_rule", "check_content": "check", "fix_text": "fix"}]}
    reference = _reference(tmp_path, stig)
    (source, rules), = reference.stigs
    assert [(r.vuln_id, r.rule_id, r.check_text) for r in rules] == [("V-9", "SV-9r1_rule", "check")]
    assert reference.ignored_values == 2


def test_a_non_string_title_falls_back_and_only_the_version_may_be_a_number(tmp_path, caplog):
    stig = {"stig_id": "MY_STIG", "display_name": {"x": 1}, "stig_name": True, "version": 3,
            "release_info": "Release: 2", "rules": []}
    reference = _reference(tmp_path, stig)
    (source, rules), = reference.stigs
    assert (source.title, source.release) == ("MY_STIG", "V3R2")          # an int version is accepted
    assert reference.ignored_values == 2                                   # the dict and the bool


@pytest.mark.parametrize("bad_version", [True, {"v": 1}, ["1"], 1.5])
def test_a_version_that_is_not_a_string_or_an_int_is_ignored(tmp_path, caplog, bad_version):
    stig = {"stig_id": "X", "display_name": "X STIG", "version": bad_version, "release_info": "Release: 2", "rules": []}
    reference = _reference(tmp_path, stig)
    (source, rules), = reference.stigs
    assert source.release == ""
    assert reference.ignored_values == 1


def test_one_warning_per_file_counts_every_ignored_value(tmp_path, caplog):
    rules = [{"group_id": f"V-{n}", "rule_id_src": f"SV-{n}r1_rule", "check_content": {"n": n}, "fix_text": [n]}
             for n in range(5)]
    stig = {"stig_id": "X", "display_name": "X STIG", "version": 1, "rules": rules}
    assert _reference(tmp_path, stig).ignored_values == 10


def test_a_clean_checklist_and_missing_values_do_not_warn(tmp_path, caplog):
    stig = {"stig_id": "X", "display_name": "X STIG", "version": 1, "rules": [
        {"group_id": "V-1", "rule_id_src": "SV-1r1_rule", "check_content": "check"}]}      # fix_text absent: normal
    reference = _reference(tmp_path, stig)
    (source, rules), = reference.stigs
    assert reference.ignored_values == 0
    assert rules[0].fix_text == ""


def test_the_operator_line_names_the_checklist_by_its_display_name(tmp_path):
    # The loader writes no line of its own; the run's names the file as the operator supplied it.
    from app.core.pipeline import parse_stage
    name = "n" * 150 + ".cklb"
    stig = {"stig_id": "X", "display_name": "X STIG", "version": 1, "rules": [
        {"group_id": "V-1", "rule_id_src": "SV-1r1_rule", "check_content": {"a": 1}}]}
    path = tmp_path / name
    path.write_text(json.dumps({"stigs": [stig]}), encoding="utf-8")
    result = parse_stage([Path(__file__).parent / "fixtures" / "scc_embedded_results.xml"], [path], tmp_path / "x")
    assert [w for w in result.warnings if "non-text" in w] == [f"{name}: 1 non-text value(s) in the checklist were ignored"]


# --- the result says what kind of file it was ------------------------------------------

def test_a_missing_file_is_unreadable(tmp_path):
    assert _unreadable(load_cklb_reference(tmp_path / "gone.cklb", embedded=False))


@pytest.mark.parametrize("stigs", [[], [{"stig_id": "X", "display_name": "X STIG", "version": 1, "rules": []}],
                                   [{"stig_id": "X", "display_name": "X STIG"}, "not an entry", 7]])
def test_a_readable_checklist_with_no_rules_is_not_the_same_as_an_unreadable_file(tmp_path, stigs):
    loaded = load_cklb_reference(_cklb(tmp_path, stigs), embedded=False)
    assert loaded.readable is True and loaded.rule_count == 0


def test_the_result_counts_the_rules_of_every_stig(tmp_path):
    path = _cklb(tmp_path, [
        {"stig_id": "A", "display_name": "A STIG", "version": 1,
         "rules": [_rule(group_id="V-1", rule_id_src="SV-1r1_rule"), _rule(group_id="V-2", rule_id_src="SV-2r1_rule")]},
        {"stig_id": "B", "display_name": "B STIG", "version": 1, "rules": [_rule(group_id="V-3", rule_id_src="SV-3r1_rule")]},
    ])
    loaded = load_cklb_reference(path, embedded=False)
    assert (loaded.readable, loaded.rule_count, len(loaded.stigs)) == (True, 3, 2)


def test_the_result_carries_the_number_of_ignored_values(tmp_path):
    rules = [{"group_id": f"V-{n}", "rule_id_src": f"SV-{n}r1_rule", "check_content": {"n": n}, "fix_text": [n]}
             for n in range(5)]
    path = _cklb(tmp_path, [{"stig_id": "X", "display_name": "X STIG", "version": 1, "rules": rules}])
    loaded = load_cklb_reference(path, embedded=False)
    assert (loaded.ignored_values, loaded.rule_count) == (10, 5)
    clean = _cklb(tmp_path, [{"stig_id": "X", "display_name": "X STIG", "version": 1,
                              "rules": [_rule(group_id="V-1", rule_id_src="SV-1r1_rule")]}])
    assert load_cklb_reference(clean, embedded=False).ignored_values == 0



def test_entries_dropped_for_their_shape_are_counted(tmp_path):
    path = _cklb(tmp_path, [
        {"stig_id": "X", "display_name": "X STIG", "version": 1,
         "rules": [_rule(group_id="V-1", rule_id_src="SV-1r1_rule"), "not a rule", 7]},
        "not a stig", {"stig_id": "B", "display_name": "No rules"}, {"stig_id": "C", "rules": {"a": 1}},
    ])
    loaded = load_cklb_reference(path, embedded=False)
    assert (loaded.rule_count, loaded.malformed_entries) == (1, 5)
    assert load_cklb_reference(FIX / "evaluate_stig_checklist.cklb", embedded=False).malformed_entries == 0


# --- the reference library is bounded ---------------------------------------------------------

def test_a_rule_entry_with_no_usable_identifier_is_dropped_and_counted(tmp_path):
    # Nothing could ever find it: no rule ID, no V-ID-shaped group ID, no STIG ID.
    path = _cklb(tmp_path, [{"stig_id": "X", "display_name": "X STIG", "version": 1, "rules": [
        {}, {"rule_id": "  "}, {"group_id": "accounts-session", "check_content": "c"},
        _rule(group_id="V-1", rule_id_src="SV-1r1_rule"), {"rule_version": "WN22-00-000020"},
    ]}])
    loaded = load_cklb_reference(path, embedded=False)
    (source, rules), = loaded.stigs
    assert [r.rule_id or r.stig_id for r in rules] == ["SV-1r1_rule", "WN22-00-000020"]
    assert (loaded.malformed_entries, loaded.rule_count, source.rule_count) == (3, 2, 2)


def test_no_more_rules_are_built_than_the_run_may_hold(tmp_path):
    path = _cklb(tmp_path, [
        {"stig_id": "X", "display_name": "X STIG", "version": 1,
         "rules": [_rule(group_id=f"V-{n}", rule_id_src=f"SV-{n}r1_rule") for n in range(3)]},
        {"stig_id": "Y", "display_name": "Y STIG", "version": 1,
         "rules": [_rule(group_id=f"V-{n}", rule_id_src=f"SV-{n}r1_rule") for n in range(10, 13)]},
    ])
    loaded = load_cklb_reference(path, embedded=False, max_rules=4)
    assert [len(rules) for _, rules in loaded.stigs] == [3, 1]
    assert [source.rule_count for source, _ in loaded.stigs] == [3, 1]
    assert loaded.rules_not_built == 2


def test_reference_rules_and_sources_have_no_instance_dict():
    (source, rules), = load_cklb_reference(FIX / "evaluate_stig_checklist.cklb", embedded=False).stigs
    assert not hasattr(source, "__dict__") and not hasattr(rules[0], "__dict__")
