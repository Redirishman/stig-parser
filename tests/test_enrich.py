import json
from pathlib import Path

import pytest

from app.parsers.base import Benchmark, BenchmarkRule, Finding
from app.parsers.benchmark_parser import BenchmarkParser
from app.reference.cklb_loader import load_cklb_reference
from app.reference.enrich import EnrichmentReport, enrich_findings, source_key
from app.reference.library import ReferenceLibrary


def _candidates(lib, finding):
    """The rules a lookup offers for *finding*, best first."""
    return [rule for rule, _ in lib.lookup(finding).matches]


FIX = Path(__file__).parent / "fixtures"
TITLE = "Microsoft Windows 11 STIG SCAP Benchmark"


def _scc_finding(num, revision, fix="scanner fix"):
    """A finding as the matcher produces it from the SCC fixture: fix text, no check text."""
    return Finding(TITLE, f"V-{num}", f"xccdf_mil.disa.stig_rule_SV-{num}{revision}_rule", "CAT II",
                   "Open", "WKSTN-01", "10.0.0.21", "", fix, scan_release="V2R8")


def _library(with_manual=True):
    lib = ReferenceLibrary()
    lib.add_benchmark(BenchmarkParser().read_all(FIX / "scc_embedded_results.xml")[0][0], "scc_embedded_results.xml", embedded=True)
    if with_manual:
        lib.add_benchmark(BenchmarkParser().read_all(FIX / "manual_stig_win11.xml")[0][0], "manual_stig_win11.xml", embedded=False)
    return lib


def test_fills_blank_check_text_and_never_overwrites_scanner_text():
    f = _scc_finding(253284, "r958928")
    enrich_findings([f], _library())
    assert f.check_text.startswith("Verify the registry value")
    assert f.fix_text == "scanner fix"                       # untouched
    assert f.stig_id == "WN11-00-000150"                     # blank on the finding, filled from a candidate
    assert f.text_source == "Check: manual_stig_win11.xml V2R9 | Fix: scanner"


def test_different_revision_is_filled_and_counted_as_drift():
    f = _scc_finding(253285, "r958930")
    report = enrich_findings([f], _library())
    assert f.check_text.startswith("Run Get-WindowsOptionalFeature")
    assert f.text_source == "Check: manual_stig_win11.xml V2R9, scanned V2R8 | Fix: scanner"
    assert report.stigs[TITLE].drifted == 1
    assert any("different release" in w and "V2R9" in w and "V2R8" in w for w in report.warnings())


def test_rule_missing_from_the_supplied_reference_is_reported():
    # Two findings so the STIG is only partly unmatched; a fully unmatched STIG
    # gets the "wrong product" wording instead (tested below).
    f = _scc_finding(253286, "r958932")
    report = enrich_findings([_scc_finding(253284, "r958928"), f], _library())
    assert f.check_text == ""
    assert f.text_source == "Check: not in supplied references | Fix: scanner"
    assert report.stigs[TITLE].unmatched == 1
    assert any("not found in any supplied reference" in w and "SV-253286" in w for w in report.warnings())


def test_no_reference_supplied_explains_the_blank_check_text_once():
    findings = [_scc_finding(253284, "r958928"), _scc_finding(253285, "r958930")]
    report = enrich_findings(findings, _library(with_manual=False))
    assert all(f.text_source == "Check: no reference supplied | Fix: scanner" for f in findings)
    warnings = report.warnings()
    assert len(warnings) == 1
    assert "Check text is blank for 2 finding(s)" in warnings[0] and "Manual STIG" in warnings[0]


def test_fully_blank_finding_is_filled_from_a_stem_match_then_re_resolved():
    # As produced when the scan matched no benchmark rule: only server and rule ID are known.
    f = Finding("", "", "xccdf_mil.disa.stig_rule_SV-253285r958930_rule", "", "Open", "h", "i", "", "")
    lib = ReferenceLibrary()
    lib.add_benchmark(BenchmarkParser().read_all(FIX / "manual_stig_win11.xml")[0][0], "manual_stig_win11.xml", embedded=False)
    enrich_findings([f], lib)
    assert (f.vuln_id, f.stig_id, f.severity) == ("V-253285", "WN11-00-000160", "CAT II")
    assert f.stig_title == "Microsoft Windows 11 Security Technical Implementation Guide"
    assert f.check_text and f.fix_text
    assert f.text_source == "Check and fix: manual_stig_win11.xml V2R9, revision differs from scan"


def test_cklb_reference_fills_a_finding_from_another_scanner():
    f = Finding("Nessus Compliance", "V-254239", "SV-254239r945408_rule", "CAT I", "Open", "h", "i", "", "")
    lib = ReferenceLibrary()
    for source, rules in load_cklb_reference(FIX / "evaluate_stig_checklist.cklb", embedded=False).stigs:
        lib.add_rules(source, rules)
    enrich_findings([f], lib)
    assert f.check_text and f.fix_text and f.stig_id == "WN22-00-000010"
    assert f.stig_title == "Nessus Compliance"               # non-blank title is never replaced


def test_wrong_product_reference_says_so():
    findings = [_scc_finding(253284, "r958928")]
    lib = ReferenceLibrary()
    lib.add_benchmark(BenchmarkParser().read_all(FIX / "scc_embedded_results.xml")[0][0], "scc_embedded_results.xml", embedded=True)
    lib.add_benchmark(BenchmarkParser().read_all(FIX / "manual_stig_server2022.xml")[0][0], "manual_stig_server2022.xml", embedded=False)
    warnings = enrich_findings(findings, lib).warnings()
    assert any("none of 1 finding(s) that need text matched a supplied reference" in w
               and "Microsoft Windows Server 2022 Security Technical Implementation Guide V2R8" in w for w in warnings)


def test_report_round_trips_through_json():
    report = enrich_findings([_scc_finding(253285, "r958930")], _library())
    again = EnrichmentReport.from_dict(report.to_dict())
    assert again.warnings() == report.warnings()
    assert [s.file_name for s in again.standalone_sources] == ["manual_stig_win11.xml"]
    assert again.source_counts["manual_stig_win11.xml|MS_Windows_11_STIG"]["filled_check"] == 1


def _win11_manual_library():
    lib = ReferenceLibrary()
    lib.add_benchmark(BenchmarkParser().read_all(FIX / "manual_stig_win11.xml")[0][0], "manual_stig_win11.xml", embedded=False)
    return lib


SERVER = "Microsoft Windows Server 2022 STIG"


def _server_finding(check, fix, rule_id="SV-254239r958472_rule", vuln_id="V-254239"):
    return Finding(SERVER, vuln_id, rule_id, "CAT I", "Open", "SRV-01", "10.0.0.5", check, fix, scan_release="V1R4")


def test_a_complete_finding_is_never_reported_as_unmatched():
    # Win11 reference supplied, but this Server 2022 finding already carries scanner
    # check AND fix text: it needs nothing, so a missing reference is not a problem.
    f = _server_finding("scanner check", "scanner fix")
    report = enrich_findings([f], _win11_manual_library())
    assert report.stigs[SERVER].needed == 0
    assert report.stigs[SERVER].unmatched == 0
    assert report.warnings() == []
    assert f.text_source == "Check and fix: scanner"


def test_only_findings_that_need_text_count_toward_wrong_product():
    complete = _server_finding("scanner check", "scanner fix")
    needy = _server_finding("", "scanner fix", rule_id="SV-254240r958473_rule", vuln_id="V-254240")
    report = enrich_findings([complete, needy], _win11_manual_library())
    counts = report.stigs[SERVER]
    assert (counts.findings, counts.needed, counts.unmatched) == (2, 1, 1)
    warnings = report.warnings()
    assert any("none of 1 finding(s) that need text matched a supplied reference" in w for w in warnings)
    assert not any("not found in any supplied reference" in w for w in warnings)


def test_a_partly_matched_stig_keeps_the_per_rule_wording():
    complete = _server_finding("scanner check", "scanner fix")
    needy_a = _server_finding("", "scanner fix", rule_id="SV-254240r958473_rule", vuln_id="V-254240")
    matched = _scc_finding(253284, "r958928")
    # Same STIG title so the counts land together: one matched (Win11 rule), one not.
    matched.stig_title = SERVER
    report = enrich_findings([complete, needy_a, matched], _win11_manual_library())
    counts = report.stigs[SERVER]
    assert (counts.needed, counts.unmatched) == (2, 1)
    assert any("1 rule(s) not found in any supplied reference: SV-254240" in w for w in report.warnings())


def test_needed_survives_the_json_round_trip():
    report = enrich_findings([_server_finding("", "scanner fix")], _win11_manual_library())
    assert report.stigs[SERVER].needed == 1
    again = EnrichmentReport.from_dict(report.to_dict())
    assert again.stigs[SERVER].needed == 1
    assert again.warnings() == report.warnings()


# --- no silent gap for findings with no text at all --------------------------

def _textless(title=SERVER, rule_id="SV-254239r958472_rule", vuln_id="V-254239"):
    return Finding(title, vuln_id, rule_id, "CAT I", "Open", "SRV-01", "10.0.0.5", "", "")


def test_titled_finding_with_no_text_and_no_reference_is_reported():
    f = _textless()
    report = enrich_findings([f], ReferenceLibrary())
    assert f.text_source == "Check and fix: no reference supplied"
    assert report.stigs[SERVER].blank_both == 1
    assert f"{SERVER}: 1 finding(s) have neither check nor fix text — add the STIG as a reference" \
        in report.warnings()


def test_blank_both_counts_per_stig_in_one_line():
    findings = [_textless(), _textless(rule_id="SV-254240r958473_rule", vuln_id="V-254240")]
    warnings = enrich_findings(findings, ReferenceLibrary()).warnings()
    assert [w for w in warnings if "neither check nor fix" in w] == [
        f"{SERVER}: 2 finding(s) have neither check nor fix text — add the STIG as a reference"]


def test_untitled_finding_with_no_text_is_not_counted_here():
    # The pipeline reports untitled findings per results file.
    report = enrich_findings([_textless(title="")], ReferenceLibrary())
    assert all(c.blank_both == 0 for c in report.stigs.values())
    assert not any("neither check nor fix" in w for w in report.warnings())


def test_fix_without_check_still_gets_only_the_blank_check_line():
    f = Finding(SERVER, "V-254239", "SV-254239r958472_rule", "CAT I", "Open", "h", "i", "", "scanner fix")
    report = enrich_findings([f], ReferenceLibrary())
    assert report.stigs[SERVER].blank_both == 0
    warnings = report.warnings()
    assert len(warnings) == 1 and warnings[0].startswith("Check text is blank for 1 finding(s)")


def test_a_finding_reported_as_unmatched_is_not_also_counted_as_blank_both():
    report = enrich_findings([_textless()], _win11_manual_library())
    counts = report.stigs[SERVER]
    assert (counts.unmatched, counts.blank_both) == (1, 0)
    assert not any("neither check nor fix" in w for w in report.warnings())


def test_blank_both_survives_the_json_round_trip():
    report = enrich_findings([_textless()], ReferenceLibrary())
    again = EnrichmentReport.from_dict(report.to_dict())
    assert again.stigs[SERVER].blank_both == 1
    assert again.warnings() == report.warnings()


# --- bounded report ----------------------------------------------------------

def test_unmatched_ids_are_capped_but_the_count_stays_exact():
    findings = [_textless(rule_id=f"SV-9{n:05d}r1_rule", vuln_id=f"V-9{n:05d}") for n in range(500)]
    matched = _scc_finding(253284, "r958928")
    matched.stig_title = SERVER                                # one finding the Win11 reference does answer
    report = enrich_findings(findings + [matched], _win11_manual_library())
    counts = report.stigs[SERVER]
    assert (counts.needed, counts.unmatched) == (501, 500)
    assert len(counts.unmatched_ids) == 50
    assert counts.unmatched_ids[0] == "SV-900000" and counts.unmatched_ids[-1] == "SV-900049"   # first 50, in order
    # the operator line still names five and says there are more
    line = next(w for w in report.warnings() if "rule(s) not found in any supplied reference" in w)
    assert line.startswith(f"{SERVER}: 500 finding(s) across 500 rule(s) not found in any supplied reference: SV-900000")
    assert counts.unmatched_rules == 500
    assert line.endswith("SV-900000, SV-900001, SV-900002, SV-900003, SV-900004…")


def test_the_capped_report_round_trips_through_json_unchanged():
    findings = [_textless(rule_id=f"SV-9{n:05d}r1_rule", vuln_id=f"V-9{n:05d}") for n in range(500)]
    findings.append(_server_finding("", "scanner fix"))        # a matched-by-nothing finding with a fix
    report = enrich_findings(findings, _win11_manual_library())
    wire = json.loads(json.dumps(report.to_dict()))
    again = EnrichmentReport.from_dict(wire)
    assert again.to_dict() == report.to_dict()
    assert again.warnings() == report.warnings()
    counts = again.stigs[SERVER]
    assert (counts.needed, counts.unmatched, counts.blank_both) == (501, 501, 0)
    assert counts.unmatched_rules == 501
    assert len(counts.unmatched_ids) == 50


def test_every_stig_counts_field_survives_the_round_trip():
    from dataclasses import fields

    from app.reference.enrich import StigCounts
    samples = {"list[str]": lambda n: [f"id{n}"], "str": lambda n: f"pair{n}", "bool": lambda n: True,
               "int": lambda n: n + 1}
    populated = StigCounts(**{f.name: samples[f.type](n) for n, f in enumerate(fields(StigCounts))})
    report = EnrichmentReport(stigs={"T": populated})
    assert EnrichmentReport.from_dict(json.loads(json.dumps(report.to_dict()))).stigs["T"] == populated


# --- never fill from the wrong rule ------------------------------------------

ROUTER = "Cisco IOS XE Router NDM STIG"
SWITCH = "Cisco IOS XE Switch NDM STIG"


def _ndm_stig(title, release, rule_id, vuln_id, check):
    bench = Benchmark("xccdf_mil.disa.stig_benchmark_X", title, release=release)
    bench.rules[rule_id] = BenchmarkRule(vuln_id, rule_id, "CAT II", check, f"{check} fix", stig_id="CISC-ND-000010")
    return bench


def _ndm_library(*names):
    sources = {
        "router": (_ndm_stig(ROUTER, "V2R1", "SV-1r1_rule", "V-1", "router check"), "router.xml"),
        "switch": (_ndm_stig(SWITCH, "V2R1", "SV-2r1_rule", "V-2", "switch check"), "switch.xml"),
    }
    lib = ReferenceLibrary()
    for name in names:
        bench, file_name = sources[name]
        lib.add_benchmark(bench, file_name, embedded=False)
    return lib


def _ndm_finding(title):
    """A finding that only knows its STIG title and STIG ID."""
    return Finding(title, "", "", "", "Open", "ROUTER-1", "10.0.0.9", "", "", stig_id="CISC-ND-000010")


def test_a_stig_id_shared_with_another_product_is_not_filled_from_it():
    f = _ndm_finding(ROUTER)
    report = enrich_findings([f], _ndm_library("switch"))
    assert f.check_text == "" and f.fix_text == ""
    assert f.text_source == "Check and fix: STIG ID found under a different STIG title, not filled"
    assert (report.stigs[ROUTER].product_refused, report.stigs[ROUTER].unmatched) == (1, 0)
    warnings = report.warnings()
    assert (f"{ROUTER}: 1 finding(s) carry a STIG ID found only under a different STIG title "
            f"({SWITCH}) and were not filled — if this is the right STIG, "
            "supply the scan's own benchmark or a checklist") in warnings
    assert not any("not found in any supplied reference" in w or "wrong product" in w for w in warnings)


def test_both_products_loaded_fills_from_the_matching_product_only():
    for order in (("router", "switch"), ("switch", "router")):
        f = _ndm_finding(ROUTER)
        enrich_findings([f], _ndm_library(*order))
        assert f.check_text == "router check", order
        assert f.fix_text == "router check fix", order
        assert f.text_source.endswith("router.xml V2R1, matched by STIG ID"), order


def test_untitled_finding_matching_two_products_by_stig_id_is_not_filled_and_reported():
    f = _ndm_finding("")
    report = enrich_findings([f], _ndm_library("router", "switch"))
    assert f.check_text == "" and f.fix_text == ""
    assert f.text_source == "Check and fix: STIG ID matches several STIGs, not filled"
    counts = report.stigs["(no STIG title)"]
    assert (counts.ambiguous, counts.unmatched) == (1, 0)
    assert ("(no STIG title): 1 finding(s) match more than one rule or STIG and were not filled "
            "— supply the scan's own benchmark or only the matching STIG") in report.warnings()
    # a hostile or odd report must not claim the rule is simply absent
    assert not any("not found in any supplied reference" in w for w in report.warnings())


def test_untitled_finding_matching_one_product_by_stig_id_is_filled_and_says_how():
    f = _ndm_finding("")
    report = enrich_findings([f], _ndm_library("router"))
    assert (f.check_text, f.stig_title) == ("router check", ROUTER)
    assert f.text_source == "Check and fix: router.xml V2R1, matched by STIG ID"
    assert report.stigs[ROUTER].ambiguous == 0                       # filled, so counted under its new title


def test_a_finding_never_receives_text_from_a_sibling_rule_of_its_group():
    bench = Benchmark("xccdf_mil.disa.stig_benchmark_X", "X STIG", release="V1R1")
    for rule_id, check in (("SV-10r1_rule", "text of SV-10"), ("SV-11r1_rule", "text of SV-11")):
        bench.rules[rule_id] = BenchmarkRule("V-1", rule_id, "CAT II", check, f"fix of {rule_id}", stig_id="X-1")
    lib = ReferenceLibrary()
    lib.add_benchmark(bench, "x.xml", embedded=False)
    for rule_id, expected in (("SV-10r1_rule", "text of SV-10"), ("SV-11r1_rule", "text of SV-11"), ("SV-12r1_rule", "")):
        f = Finding("X STIG", "V-1", rule_id, "CAT II", "Open", "h", "i", "", "")
        enrich_findings([f], lib)
        assert f.check_text == expected, rule_id


def _server_2022_library():
    lib = ReferenceLibrary()
    for source, rules in load_cklb_reference(FIX / "evaluate_stig_checklist.cklb", embedded=False).stigs:
        lib.add_rules(source, rules)
    return lib


def test_nessus_style_finding_whose_rule_id_is_its_stig_id_still_fills():
    for vuln_id, title in (("V-254239", "Nessus Compliance"),                         # reached by V-ID
                           ("", "Microsoft Windows Server 2022 STIG"),                 # STIG ID, same product
                           ("", "")):                                                  # STIG ID, one product loaded
        f = Finding(title, vuln_id, "WN22-00-000010", "CAT I", "Open", "h", "i", "", "", stig_id="WN22-00-000010")
        enrich_findings([f], _server_2022_library())
        assert f.check_text and f.fix_text, (vuln_id, title)
        assert f.vuln_id == "V-254239", (vuln_id, title)


def test_nessus_style_finding_titled_as_another_product_is_not_filled_by_stig_id_alone():
    f = Finding("Some Other Product STIG", "", "WN22-00-000010", "CAT I", "Open", "h", "i", "", "",
                stig_id="WN22-00-000010")
    enrich_findings([f], _server_2022_library())
    assert f.check_text == "" and f.vuln_id == ""


def test_ambiguous_survives_the_json_round_trip():
    report = enrich_findings([_ndm_finding("")], _ndm_library("router", "switch"))
    again = EnrichmentReport.from_dict(report.to_dict())
    assert again.stigs["(no STIG title)"].ambiguous == 1
    assert again.warnings() == report.warnings()


# --- counts and wording that tell the truth ----------------------------------

def test_unmatched_line_counts_findings_and_distinct_rules_and_names_each_rule_once():
    on_six_hosts = []
    for n in range(6):
        f = _scc_finding(253286, "r958932")
        f.server = f"WKSTN-{n:02d}"
        on_six_hosts.append(f)
    report = enrich_findings(on_six_hosts + [_scc_finding(253284, "r958928")], _library())
    counts = report.stigs[TITLE]
    assert (counts.unmatched, counts.unmatched_rules, counts.unmatched_ids) == (6, 1, ["SV-253286"])
    assert f"{TITLE}: 6 finding(s) across 1 rule(s) not found in any supplied reference: SV-253286" \
        in report.warnings()


def test_unmatched_ids_are_distinct_and_in_first_seen_order():
    ids = ["SV-9r1_rule", "SV-3r1_rule", "SV-9r1_rule", "SV-5r1_rule", "SV-3r1_rule"]
    findings = [_textless(rule_id=rule_id, vuln_id="") for rule_id in ids]
    findings.append(_server_finding("", "scanner fix"))
    matched = _scc_finding(253284, "r958928")
    matched.stig_title = SERVER                      # one finding the reference answers, so the STIG is only partly unmatched
    report = enrich_findings(findings + [matched], _win11_manual_library())
    counts = report.stigs[SERVER]
    assert counts.unmatched_ids == ["SV-9", "SV-3", "SV-5", "SV-254239"]
    assert (counts.unmatched, counts.unmatched_rules) == (6, 4)


def test_drift_line_counts_findings_and_names_the_releases():
    report = enrich_findings([_scc_finding(253285, "r958930")], _library())
    line = next(w for w in report.warnings() if "different release" in w)
    assert line.startswith(f"{TITLE}: 1 finding(s) took check/fix text from a different release (")
    assert "reference V2R9, scanned V2R8" in line


def _undated_reference(rule_id, check):
    bench = Benchmark("xccdf_mil.disa.stig_benchmark_X", "X STIG", release="")
    bench.rules[rule_id] = BenchmarkRule("V-1", rule_id, "CAT II", check, "fix", stig_id="X-1")
    lib = ReferenceLibrary()
    lib.add_benchmark(bench, "undated.xml", embedded=False)
    return lib


def test_drift_line_omits_the_parenthetical_when_no_release_is_known():
    f = Finding("X STIG", "V-1", "SV-1r1_rule", "CAT II", "Open", "h", "i", "", "")
    report = enrich_findings([f], _undated_reference("SV-1r2_rule", "check"))
    line = next(w for w in report.warnings() if "different release" in w)
    assert line == "X STIG: 1 finding(s) took check/fix text from a different release — see the Text Source column"
    assert "(reference" not in line


def test_unknown_or_blank_severity_is_filled_but_a_real_one_is_kept():
    lib = _win11_manual_library()
    for severity, expected in (("Unknown", "CAT I"), ("", "CAT I"), ("CAT III", "CAT III")):   # reference says CAT I
        f = _scc_finding(253284, "r958928")
        f.severity = severity
        report = enrich_findings([f], lib)
        assert f.severity == expected, severity
        assert report.stigs[TITLE].filled_severity == (0 if severity == "CAT III" else 1)
        counts = report.source_counts["manual_stig_win11.xml|MS_Windows_11_STIG"]
        assert counts["filled_severity"] == (0 if severity == "CAT III" else 1)   # per source too
    f = _scc_finding(253286, "r958932")                # not in the reference: nothing to fill it with
    f.severity = "Unknown"
    enrich_findings([f], lib)
    assert f.severity == "Unknown"


def test_source_key_names_the_file_and_the_benchmark():
    lib = _library()
    manual = next(s for s in lib.sources if s.file_name == "manual_stig_win11.xml")
    assert source_key(manual) == "manual_stig_win11.xml|MS_Windows_11_STIG"


def test_a_finding_filled_from_a_drifted_rule_is_one_drift_per_source_not_one_per_field():
    f = Finding(TITLE, "V-253285", "xccdf_mil.disa.stig_rule_SV-253285r958930_rule", "CAT II",
                "Open", "WKSTN-01", "10.0.0.21", "", "", scan_release="V2R8")   # check AND fix blank
    report = enrich_findings([f], _win11_manual_library())          # no embedded copy: the Manual STIG fills both
    entry = report.source_counts["manual_stig_win11.xml|MS_Windows_11_STIG"]
    assert (entry["filled_check"], entry["filled_fix"], entry["drifted"]) == (1, 1, 1)
    assert report.stigs[TITLE].drifted == 1


def _two_stig_cklb(tmp_path):
    def stig(stig_id, name, rule_id, vuln_id, check):
        return {"stig_id": stig_id, "display_name": name, "version": 1,
                "release_info": "Release: 2 Benchmark Date: x",
                "rules": [{"group_id": vuln_id, "rule_id_src": rule_id, "rule_version": f"{stig_id}-1",
                           "severity": "medium", "check_content": check, "fix_text": f"{check} fix"}]}
    path = tmp_path / "both.cklb"
    path.write_text(json.dumps({"stigs": [stig("A_STIG", "A STIG", "SV-1r1_rule", "V-1", "check a"),
                                          stig("B_STIG", "B STIG", "SV-2r1_rule", "V-2", "check b")]}),
                    encoding="utf-8")
    return path


def test_a_multi_stig_checklist_keeps_one_source_count_entry_per_stig(tmp_path):
    lib = ReferenceLibrary()
    for source, rules in load_cklb_reference(_two_stig_cklb(tmp_path), embedded=False).stigs:
        lib.add_rules(source, rules)
    findings = [Finding("A STIG", "V-1", "SV-1r1_rule", "CAT II", "Open", "h", "i", "", ""),
                Finding("B STIG", "V-2", "SV-2r1_rule", "CAT II", "Open", "h", "i", "", "")]
    report = enrich_findings(findings, lib)
    assert sorted(report.source_counts) == ["both.cklb|A_STIG", "both.cklb|B_STIG"]
    assert all(v["filled_check"] == 1 for v in report.source_counts.values())


def test_fix_text_blank_line_is_aggregated_like_the_check_text_one():
    findings = [
        Finding("A STIG", "V-1", "SV-1r1_rule", "CAT II", "Open", "h", "i", "scanner check", ""),
        Finding("A STIG", "V-2", "SV-2r1_rule", "CAT II", "Open", "h", "i", "scanner check", ""),
        Finding("B STIG", "V-3", "SV-3r1_rule", "CAT II", "Open", "h", "i", "scanner check", ""),
    ]
    report = enrich_findings(findings, ReferenceLibrary())
    assert "Fix text is blank for 3 finding(s) in 2 STIG(s): A STIG; B STIG." in report.warnings()
    assert report.stigs["A STIG"].blank_fix_with_check == 2
    assert not any(w.startswith("Check text is blank") for w in report.warnings())


def test_a_finding_with_both_texts_adds_no_blank_text_line():
    f = Finding("A STIG", "V-1", "SV-1r1_rule", "CAT II", "Open", "h", "i", "scanner check", "scanner fix")
    assert enrich_findings([f], ReferenceLibrary()).warnings() == []


def test_the_loaded_list_in_the_wrong_product_line_stops_at_five_sources():
    lib = ReferenceLibrary()
    for n in range(1, 8):
        bench = Benchmark("xccdf_mil.disa.stig_benchmark_X", f"Ref {n}", release="V1R1")
        bench.rules[f"SV-{n}r1_rule"] = BenchmarkRule(f"V-{n}", f"SV-{n}r1_rule", "CAT II", "c", "f", stig_id=f"R-{n}")
        lib.add_benchmark(bench, f"ref{n}.xml", embedded=False)
    f = Finding("Other STIG", "V-100", "SV-100r1_rule", "CAT II", "Open", "h", "i", "", "")
    line = next(w for w in enrich_findings([f], lib).warnings() if "wrong product" in w)
    assert "(loaded: Ref 1 V1R1; Ref 2 V1R1; Ref 3 V1R1; Ref 4 V1R1; Ref 5 V1R1…)" in line
    assert "Ref 6" not in line and "Ref 7" not in line


def test_from_dict_ignores_keys_it_does_not_know():
    report = enrich_findings([_scc_finding(253285, "r958930")], _library())
    wire = json.loads(json.dumps(report.to_dict()))
    wire["stigs"][TITLE]["a_future_counter"] = 7
    wire["sources"][0]["a_future_field"] = "x"
    wire["a_future_section"] = {}
    again = EnrichmentReport.from_dict(wire)
    assert again.to_dict() == report.to_dict()


def test_blank_fix_with_check_survives_the_json_round_trip():
    f = Finding("A STIG", "V-1", "SV-1r1_rule", "CAT II", "Open", "h", "i", "scanner check", "")
    again = EnrichmentReport.from_dict(enrich_findings([f], ReferenceLibrary()).to_dict())
    assert again.stigs["A STIG"].blank_fix_with_check == 1


# --- DISA stems only; a V-ID-only match on a multi-rule group is ambiguous ---

def test_a_scanner_that_names_rules_its_own_way_still_fills_by_vuln_id():
    f = Finding("", "V-254239", "xccdf_org.ssgproject.content_rule_accounts_tmout", "CAT I", "Open", "h", "i", "", "")
    enrich_findings([f], _server_2022_library())
    assert f.check_text and f.fix_text and f.stig_id == "WN22-00-000010"


def test_a_finding_for_another_disa_rule_never_takes_the_text_of_the_rule_with_its_vuln_id():
    f = Finding("", "V-254239", "SV-254241r1_rule", "CAT I", "Open", "h", "i", "", "")
    report = enrich_findings([f], _server_2022_library())
    assert f.check_text == "" and f.fix_text == ""
    assert report.stigs["(no STIG title)"].unmatched == 1


def _group_v1_library():
    bench = Benchmark("xccdf_mil.disa.stig_benchmark_X", "X STIG", release="V1R1")
    for rule_id, stig_id in (("SV-10r1_rule", "X-10"), ("SV-11r1_rule", "X-11")):
        bench.rules[rule_id] = BenchmarkRule("V-1", rule_id, "CAT II", f"text of {rule_id}", f"fix of {rule_id}",
                                             stig_id=stig_id)
    lib = ReferenceLibrary()
    lib.add_benchmark(bench, "x.xml", embedded=False)
    return lib


def test_a_vuln_id_that_names_several_rules_is_not_filled_and_is_reported():
    f = Finding("X STIG", "V-1", "", "CAT II", "Open", "h", "i", "", "")
    report = enrich_findings([f], _group_v1_library())
    assert f.check_text == "" and f.fix_text == ""
    assert f.text_source == "Check and fix: V-ID matches several rules, not filled"
    counts = report.stigs["X STIG"]
    assert (counts.ambiguous, counts.unmatched) == (1, 0)
    assert ("X STIG: 1 finding(s) match more than one rule or STIG and were not filled "
            "— supply the scan's own benchmark or only the matching STIG") in report.warnings()
    assert not any("not found in any supplied reference" in w for w in report.warnings())


def test_a_complete_finding_on_an_ambiguous_group_is_not_reported():
    f = Finding("X STIG", "V-1", "", "CAT II", "Open", "h", "i", "scanner check", "scanner fix")
    report = enrich_findings([f], _group_v1_library())
    assert report.stigs["X STIG"].ambiguous == 0
    assert report.warnings() == []


def test_one_rule_in_two_manual_releases_is_filled_from_the_best_ranked_one():
    lib = ReferenceLibrary()
    for release, revision, check, file_name in (("V1R1", "r1", "older text", "old.xml"),
                                                ("V1R2", "r2", "newer text", "new.xml")):
        bench = Benchmark("xccdf_mil.disa.stig_benchmark_X", "X STIG", release=release)
        rule_id = f"SV-254239{revision}_rule"
        bench.rules[rule_id] = BenchmarkRule("V-254239", rule_id, "CAT I", check, f"{check} fix", stig_id="X-1")
        lib.add_benchmark(bench, file_name, embedded=False)
    f = Finding("X STIG", "V-254239", "", "CAT I", "Open", "h", "i", "", "")
    report = enrich_findings([f], lib)
    assert (f.check_text, f.fix_text) == ("newer text", "newer text fix")
    assert report.stigs["X STIG"].ambiguous == 0
    assert f.text_source == "Check and fix: new.xml V1R2, matched by V-ID"


# --- only V-ID-shaped group IDs are a lookup key ------------------------------

SSG_TMOUT = "xccdf_org.ssgproject.content_rule_accounts_tmout"
SSG_SESSIONS = "xccdf_org.ssgproject.content_rule_accounts_max_concurrent_login_sessions"


def _ccs_benchmark(group):
    """ComplianceAsCode shape: one Group holds several Rules; one has severity and fix text, one has neither."""
    bench = Benchmark("xccdf_org.ssgproject.content_benchmark_RHEL-9", "Guide to the Secure Configuration of RHEL 9",
                      release="")
    bench.rules[SSG_TMOUT] = BenchmarkRule(group, SSG_TMOUT, "CAT I", "", "tmout fix text")
    bench.rules[SSG_SESSIONS] = BenchmarkRule(group, SSG_SESSIONS, "Unknown", "", "")
    return bench


def _sessions_finding(group):
    return Finding("Guide to the Secure Configuration of RHEL 9", group, SSG_SESSIONS, "Unknown", "Open",
                   "rhel9-01", "10.0.0.7", "", "")


def test_a_group_id_that_is_not_a_vuln_id_never_lends_a_sibling_rules_text():
    lib = ReferenceLibrary()
    lib.add_benchmark(_ccs_benchmark("accounts-session"), "scan.xml", embedded=True)
    f = _sessions_finding("accounts-session")
    report = enrich_findings([f], lib)
    assert f.severity == "Unknown"                        # as scanned: the sibling's CAT I is not lent
    assert f.fix_text == "" and f.check_text == ""
    assert "accounts_tmout" not in f.text_source
    assert report.stigs[f.stig_title].filled_severity == 0 and report.stigs[f.stig_title].filled_fix == 0


def test_siblings_under_a_vuln_id_shaped_group_with_non_disa_rule_ids_are_not_lent_either():
    lib = ReferenceLibrary()
    lib.add_benchmark(_ccs_benchmark("V-1"), "scan.xml", embedded=True)
    f = _sessions_finding("V-1")
    report = enrich_findings([f], lib)
    assert f.severity == "Unknown" and f.fix_text == ""
    # its own rule matched exactly, so it is not ambiguous: it is a finding whose rule has no text
    assert report.stigs[f.stig_title].ambiguous == 0
    assert "V-ID matches several rules" not in f.text_source and "accounts_tmout" not in f.text_source
    # the same group still serves the rule that has the text
    own = Finding(f.stig_title, "V-1", SSG_TMOUT, "", "Open", "h", "i", "", "")
    enrich_findings([own], lib)
    assert (own.severity, own.fix_text) == ("CAT I", "tmout fix text")


def test_a_non_vuln_group_id_on_the_finding_does_not_conflict_with_the_rules_vuln_id():
    lib = ReferenceLibrary()
    lib.add_benchmark(_stig_for_vuln_tests(), "x.xml", embedded=False)
    f = Finding("X STIG", "accounts-session", "SV-1r1_rule", "", "Open", "h", "i", "", "")
    assert [c.check_text for c in _candidates(lib, f)] == ["check"]


def _stig_for_vuln_tests():
    bench = Benchmark("xccdf_mil.disa.stig_benchmark_X", "X STIG", release="V1R1")
    bench.rules["SV-1r1_rule"] = BenchmarkRule("V-1", "SV-1r1_rule", "CAT II", "check", "fix", stig_id="X-1")
    return bench


def test_a_group_id_is_never_a_key():
    lib = ReferenceLibrary()
    lib.add_benchmark(_ccs_benchmark("accounts-session"), "scan.xml", embedded=True)
    finding = Finding("", "accounts-session", "", "", "Open", "h", "i", "", "")
    assert lib.lookup(finding).matches == [] and lib.lookup(finding).ambiguous is False


def test_one_disa_rule_and_one_ssg_rule_under_one_vuln_id_is_not_ambiguous():
    lib = ReferenceLibrary()
    embedded = Benchmark("xccdf_org.ssgproject.content_benchmark_RHEL-9", "RHEL 9 SSG", release="")
    embedded.rules[SSG_TMOUT] = BenchmarkRule("V-258068", SSG_TMOUT, "Unknown", "", "")
    lib.add_benchmark(embedded, "scan.xml", embedded=True)
    manual = Benchmark("xccdf_mil.disa.stig_benchmark_RHEL_9", "Red Hat Enterprise Linux 9 STIG", release="V2R4")
    manual.rules["SV-258068r1_rule"] = BenchmarkRule("V-258068", "SV-258068r1_rule", "CAT II", "manual check",
                                                     "manual fix", stig_id="RHEL-09-211010")
    lib.add_benchmark(manual, "manual.xml", embedded=False)
    f = Finding("RHEL 9 SSG", "V-258068", SSG_TMOUT, "", "Open", "h", "i", "", "")
    result = lib.lookup(f)
    assert result.ambiguous is False
    assert [(r.source.file_name, key) for r, key in result.matches] == [("scan.xml", "rule_id"), ("manual.xml", "vuln_id")]
    report = enrich_findings([f], lib)
    assert f.check_text == "manual check" and f.fix_text == "manual fix"
    assert f.text_source == "Check and fix: manual.xml V2R4, matched by V-ID"
    assert report.stigs[f.stig_title].ambiguous == 0


def test_two_non_disa_rules_under_one_vuln_id_are_ambiguous_without_a_rule_id():
    lib = ReferenceLibrary()
    lib.add_benchmark(_ccs_benchmark("V-1"), "scan.xml", embedded=False)
    result = lib.lookup(Finding("", "V-1", "", "", "Open", "h", "i", "", ""))
    assert result.matches == [] and (result.ambiguous, result.ambiguous_by) == (True, "vuln_id")


def test_the_same_non_disa_rule_loaded_twice_is_not_ambiguous():
    lib = ReferenceLibrary()
    for name in ("a.xml", "b.xml"):
        bench = Benchmark("xccdf_org.ssgproject.content_benchmark_RHEL-9", "RHEL 9 SSG", release="")
        bench.rules[SSG_TMOUT] = BenchmarkRule("V-1", SSG_TMOUT, "CAT I", "c", "f")
        lib.add_benchmark(bench, name, embedded=False)
    result = lib.lookup(Finding("", "V-1", "", "", "Open", "h", "i", "", ""))
    assert result.ambiguous is False and len(result.matches) == 2


# --- say so when a STIG ID is found only under a different product -----------

SERVER_MANUAL_TITLE = "Microsoft Windows Server 2022 Security Technical Implementation Guide"


def _server_manual_library():
    lib = ReferenceLibrary()
    lib.add_benchmark(BenchmarkParser().read_all(FIX / "manual_stig_server2022.xml")[0][0], "manual_stig_server2022.xml",
                      embedded=False)
    return lib


def test_a_stig_id_found_only_under_another_title_is_refused_in_words_that_are_true():
    title = "DISA Windows Server 2022 STIG v1r4"
    f = Finding(title, "", "", "", "Open", "SRV-01", "10.0.0.5", "", "", stig_id="WN22-00-000010")
    report = enrich_findings([f], _server_manual_library())
    assert f.check_text == "" and f.fix_text == ""
    counts = report.stigs[title]
    assert (counts.product_refused, counts.unmatched, counts.ambiguous) == (1, 0, 0)
    warnings = report.warnings()
    assert (f"{title}: 1 finding(s) carry a STIG ID found only under a different STIG title "
            f"({SERVER_MANUAL_TITLE}) and were not filled — if this is the right STIG, "
            "supply the scan's own benchmark or a checklist") in warnings
    assert not any("not found in any supplied reference" in w or "wrong product" in w for w in warnings)
    assert f.text_source == "Check and fix: STIG ID found under a different STIG title, not filled"


def test_a_scanner_audit_file_title_matches_the_manual_stig_it_names():
    lib = ReferenceLibrary()
    bench = Benchmark("xccdf_mil.disa.stig_benchmark_RHEL_7", "Red Hat Enterprise Linux 7 Security Technical Implementation Guide",
                      release="V3R4")
    bench.rules["SV-204392r1_rule"] = BenchmarkRule("V-204392", "SV-204392r1_rule", "CAT I", "rhel check", "rhel fix",
                                                    stig_id="RHEL-07-010010")
    lib.add_benchmark(bench, "rhel7.xml", embedded=False)
    f = Finding("DISA_STIG_Red_Hat_Enterprise_Linux_7_v3r4.audit", "", "", "", "Open", "h", "i", "", "",
                stig_id="RHEL-07-010010")
    report = enrich_findings([f], lib)
    assert (f.check_text, f.fix_text) == ("rhel check", "rhel fix")
    assert f.text_source.endswith(", matched by STIG ID")
    assert report.stigs["DISA_STIG_Red_Hat_Enterprise_Linux_7_v3r4.audit"].product_refused == 0


def test_a_refused_finding_that_another_key_answered_is_not_reported_as_refused():
    # Titled "DISA Windows Server 2022 STIG": the STIG ID is refused, but the V-ID reaches the rule.
    f = Finding("DISA Windows Server 2022 STIG v1r4", "V-254239", "", "", "Open", "h", "i", "", "",
                stig_id="WN22-00-000010")
    report = enrich_findings([f], _server_manual_library())
    assert f.check_text and f.fix_text
    assert report.stigs["DISA Windows Server 2022 STIG v1r4"].product_refused == 0


def test_product_refused_survives_the_json_round_trip():
    title = "DISA Windows Server 2022 STIG v1r4"
    f = Finding(title, "", "", "", "Open", "h", "i", "", "", stig_id="WN22-00-000010")
    report = enrich_findings([f], _server_manual_library())
    again = EnrichmentReport.from_dict(json.loads(json.dumps(report.to_dict())))
    assert again.stigs[title].product_refused == 1
    assert again.warnings() == report.warnings()


def test_the_refused_titles_in_the_warning_stop_at_five_and_say_so():
    lib = ReferenceLibrary()
    for n in range(1, 8):
        bench = Benchmark("xccdf_mil.disa.stig_benchmark_X", f"Product {n} STIG", release="V1R1")
        bench.rules[f"SV-{n}r1_rule"] = BenchmarkRule(f"V-{n}", f"SV-{n}r1_rule", "CAT II", "c", "f", stig_id="SHARED-1")
        lib.add_benchmark(bench, f"p{n}.xml", embedded=False)
    f = Finding("Another STIG", "", "", "", "Open", "h", "i", "", "", stig_id="SHARED-1")
    line = next(w for w in enrich_findings([f], lib).warnings() if "different STIG title" in w)
    assert "(Product 1 STIG; Product 2 STIG; Product 3 STIG; Product 4 STIG; Product 5 STIG…)" in line
    assert "Product 6" not in line


# --- embedded copies differing in text; payloads from older builds -------------

def test_the_embedded_copy_that_has_check_text_fills_the_finding_and_is_credited():
    lib = ReferenceLibrary()
    for file_name, check in (("a.xml", ""), ("b.xml", "check text from the second copy")):
        bench = Benchmark("xccdf_mil.disa.stig_benchmark_X", "X STIG", release="V1R1")
        bench.rules["SV-5r1_rule"] = BenchmarkRule("V-5", "SV-5r1_rule", "CAT II", check, "fix", stig_id="X-5")
        lib.add_benchmark(bench, file_name, embedded=True)
    f = Finding("X STIG", "V-5", "SV-5r1_rule", "CAT II", "Open", "h", "i", "", "scanner fix")
    report = enrich_findings([f], lib)
    assert f.check_text == "check text from the second copy" and f.fix_text == "scanner fix"
    assert f.text_source == "Check: b.xml V1R1 | Fix: scanner"
    assert report.source_counts["b.xml|X"]["filled_check"] == 1
    assert "a.xml|X" not in report.source_counts


def test_forty_truly_identical_embedded_copies_are_still_one_source():
    lib = ReferenceLibrary()
    for n in range(40):
        bench = Benchmark("xccdf_mil.disa.stig_benchmark_X", "X STIG", release="V1R1")
        bench.rules["SV-5r1_rule"] = BenchmarkRule("V-5", "SV-5r1_rule", "CAT II", "", "fix", stig_id="X-5")
        lib.add_benchmark(bench, f"host-{n:02d}.xml", embedded=True)
    assert len(lib.sources) == 1 and lib.warnings == []


def test_an_older_payload_without_rule_counts_prints_no_across_zero_clause():
    on_six_hosts = []
    for n in range(6):
        f = _scc_finding(253286, "r958932")
        f.server = f"WKSTN-{n:02d}"
        on_six_hosts.append(f)
    report = enrich_findings(on_six_hosts + [_scc_finding(253284, "r958928")], _library())
    wire = json.loads(json.dumps(report.to_dict()))
    del wire["stigs"][TITLE]["unmatched_rules"]                       # as written before the field existed
    line = next(w for w in EnrichmentReport.from_dict(wire).warnings() if "not found in any supplied reference" in w)
    assert line == f"{TITLE}: 6 finding(s) not found in any supplied reference: SV-253286"
    assert "across" not in line
    # a current payload still says it
    current = next(w for w in report.warnings() if "not found in any supplied reference" in w)
    assert current == f"{TITLE}: 6 finding(s) across 1 rule(s) not found in any supplied reference: SV-253286"


def test_an_older_payload_still_marks_a_long_id_list_as_cut():
    wire = {"stigs": {"T": {"findings": 9, "needed": 9, "unmatched": 7,
                            "unmatched_ids": [f"SV-{n}" for n in range(1, 8)]}}, "sources": [], "source_counts": {}}
    line = next(w for w in EnrichmentReport.from_dict(wire).warnings() if "not found" in w)
    assert line == "T: 7 finding(s) not found in any supplied reference: SV-1, SV-2, SV-3, SV-4, SV-5…"


# --- an exact rule match is never ambiguous; untitled refused reference; V-ID-only fills are labelled ---

def _two_rule_group(first_has_check):
    """Group V-1 with two non-DISA rules; the first has fix text only, the second has check text."""
    bench = Benchmark("xccdf_org.ssgproject.content_benchmark_X", "Guide X", release="V1R1")
    bench.rules["accounts_a"] = BenchmarkRule("V-1", "accounts_a", "CAT II", "check a" if first_has_check else "", "fix a")
    bench.rules["accounts_b"] = BenchmarkRule("V-1", "accounts_b", "CAT II", "check b", "fix b")
    lib = ReferenceLibrary()
    lib.add_benchmark(bench, "ref.xml", embedded=False)
    return lib


def test_a_finding_whose_own_rule_matched_exactly_is_never_ambiguous_but_the_sibling_is_still_dropped():
    lib = _two_rule_group(first_has_check=False)
    f = Finding("Guide X", "V-1", "accounts_a", "CAT II", "Open", "h", "i", "", "scanner fix")
    result = lib.lookup(f)
    assert [(r.rule_id, key) for r, key in result.matches] == [("accounts_a", "rule_id")]
    assert result.ambiguous is False and result.ambiguous_by == ""
    report = enrich_findings([f], lib)
    assert f.check_text == ""                                   # the sibling's check text is not lent
    counts = report.stigs["Guide X"]
    assert (counts.ambiguous, counts.blank_check_with_fix) == (0, 1)
    assert "V-ID matches several rules" not in f.text_source


def test_without_an_exact_rule_match_a_crowded_vuln_id_is_still_ambiguous():
    lib = _two_rule_group(first_has_check=False)
    result = lib.lookup(Finding("Guide X", "V-1", "", "CAT II", "Open", "h", "i", "", ""))
    assert result.matches == [] and (result.ambiguous, result.ambiguous_by) == (True, "vuln_id")


def test_an_exact_rule_match_is_not_ambiguous_by_stig_id_either():
    lib = ReferenceLibrary()
    for title, rule_id, vuln in (("Router STIG", "router_rule", "V-1"), ("Switch STIG", "switch_rule", "V-2"),
                                 ("Firewall STIG", "firewall_rule", "V-3")):
        bench = Benchmark("xccdf_org.ssgproject.content_benchmark_X", title, release="V1R1")
        bench.rules[rule_id] = BenchmarkRule(vuln, rule_id, "CAT II", "c", "f", stig_id="SHARED-1")
        lib.add_benchmark(bench, f"{rule_id}.xml", embedded=False)
    exact = lib.lookup(Finding("", "", "router_rule", "", "Open", "h", "i", "", "", stig_id="SHARED-1"))
    assert [r.rule_id for r, _ in exact.matches] == ["router_rule"] and exact.ambiguous is False
    stranger = lib.lookup(Finding("", "", "other_rule", "", "Open", "h", "i", "", "", stig_id="SHARED-1"))
    assert stranger.matches == [] and (stranger.ambiguous, stranger.ambiguous_by) == (True, "stig_id")


def test_a_refused_reference_with_no_title_is_named_as_untitled():
    bench = Benchmark("xccdf_mil.disa.stig_benchmark_X", "", release="V1R1")
    bench.rules["SV-1r1_rule"] = BenchmarkRule("V-1", "SV-1r1_rule", "CAT II", "c", "f", stig_id="X-1")
    lib = ReferenceLibrary()
    lib.add_benchmark(bench, "untitled.xml", embedded=False)
    f = Finding("Some STIG", "", "", "", "Open", "h", "i", "", "", stig_id="X-1")
    assert lib.lookup(f).refused_products == ("(untitled reference)",)
    warning = next(w for w in enrich_findings([f], lib).warnings() if "different STIG title" in w)
    assert "(untitled reference)" in warning and "()" not in warning


def _by_vuln_library():
    bench = Benchmark("xccdf_mil.disa.stig_benchmark_X", "X STIG", release="V1R1")
    bench.rules["SV-5r1_rule"] = BenchmarkRule("V-5", "SV-5r1_rule", "CAT II", "check", "fix", stig_id="X-5")
    lib = ReferenceLibrary()
    lib.add_benchmark(bench, "ref.xml", embedded=False)
    return lib


def test_a_fill_reached_only_by_the_vuln_id_says_so_after_the_release_wording():
    f = Finding("X STIG", "V-5", "", "CAT II", "Open", "h", "i", "", "")
    enrich_findings([f], _by_vuln_library())
    assert f.text_source == "Check and fix: ref.xml V1R1, matched by V-ID"
    drifted = Finding("X STIG", "V-5", "SV-9r1_rule", "CAT II", "Open", "h", "i", "", "", scan_release="V9R9")
    assert enrich_findings([drifted], _by_vuln_library()).stigs["X STIG"].filled_check == 0   # stem conflict
    scanned = Finding("X STIG", "V-5", "xccdf_org.x_rule_thing", "CAT II", "Open", "h", "i", "", "")
    enrich_findings([scanned], _by_vuln_library())
    assert scanned.text_source == "Check and fix: ref.xml V1R1, matched by V-ID"


def test_a_fill_reached_by_the_rule_id_or_stem_is_not_labelled_by_vuln_id():
    exact = Finding("X STIG", "V-5", "SV-5r1_rule", "CAT II", "Open", "h", "i", "", "")
    enrich_findings([exact], _by_vuln_library())
    assert exact.text_source == "Check and fix: ref.xml V1R1"
    stem = Finding("X STIG", "V-5", "SV-5r7_rule", "CAT II", "Open", "h", "i", "", "")
    enrich_findings([stem], _by_vuln_library())
    assert "matched by" not in stem.text_source


def test_a_scanner_supplied_text_never_gets_a_match_label():
    f = Finding("X STIG", "V-5", "", "CAT II", "Open", "h", "i", "scanner check", "scanner fix")
    enrich_findings([f], _by_vuln_library())
    assert f.text_source == "Check and fix: scanner"


# --- tolerant report loading --------------------------------------------------------

@pytest.mark.parametrize("payload", [None, [], "report", 5, True, {}, {"stigs": []}, {"stigs": "x", "sources": 3},
                                     {"stigs": None, "sources": None, "source_counts": None},
                                     {"source_counts": ["a"]}])
def test_a_payload_of_the_wrong_shape_loads_as_an_empty_report(payload):
    report = EnrichmentReport.from_dict(payload)
    assert (report.stigs, report.sources, report.source_counts) == ({}, [], {})
    assert report.warnings() == []


def test_non_dict_entries_are_skipped_and_the_rest_load():
    wire = {"stigs": {"A": {"findings": 2, "needed": 2, "unmatched": 2, "unmatched_ids": ["SV-1"]},
                      "B": "nope", "C": [1, 2], "D": None},
            "sources": ["x", None, 7, {"file_name": "ok.xml", "benchmark_id": "X", "title": "T", "release": "V1R1",
                                       "embedded": False, "edition": "manual", "rule_count": 3}],
            "source_counts": {"ok.xml|X": {"filled_check": 1}, "bad": "x", "worse": [1]}}
    report = EnrichmentReport.from_dict(wire)
    assert list(report.stigs) == ["A"]
    assert [s.file_name for s in report.sources] == ["ok.xml"]
    assert list(report.source_counts) == ["ok.xml|X"]
    assert report.warnings()          # still renders


def test_a_source_entry_with_missing_fields_loads_with_defaults():
    report = EnrichmentReport.from_dict({"sources": [{"file_name": "a.xml"}, {"title": "T", "future": 1}, {}]})
    assert [(s.file_name, s.title, s.release, s.embedded, s.rule_count) for s in report.sources] == [
        ("a.xml", "", "", False, 0), ("", "T", "", False, 0), ("", "", "", False, 0)]


def test_fields_of_the_wrong_type_fall_back_to_their_defaults_and_never_break_warnings():
    wire = {"stigs": {"T": {"findings": "many", "needed": None, "unmatched": 3.5, "unmatched_rules": True,
                            "unmatched_ids": "SV-1", "refused_titles": {"a": 1}, "refused_more": "yes",
                            "drift_pair": 5, "drifted": [1], "ambiguous": -4, "blank_both": {"a": 1},
                            "product_refused": "1", "blank_check_with_fix": None, "blank_fix_with_check": 2}},
            "sources": [{"file_name": 5, "title": ["x"], "embedded": "true", "rule_count": "9"}],
            "source_counts": {"k": {"filled_check": "x", "filled_fix": True, "drifted": 2}}}
    report = EnrichmentReport.from_dict(wire)
    counts = report.stigs["T"]
    assert (counts.findings, counts.needed, counts.unmatched, counts.unmatched_rules) == (0, 0, 0, 0)
    assert (counts.unmatched_ids, counts.refused_titles, counts.refused_more, counts.drift_pair) == ([], [], False, "")
    assert (counts.ambiguous, counts.blank_fix_with_check) == (0, 2)
    assert report.source_counts == {"k": {"drifted": 2}}
    assert report.sources[0].file_name == "" and report.sources[0].embedded is False
    report.warnings()                  # does not raise


def test_a_hostile_list_in_a_payload_is_capped_and_clipped():
    wire = {"stigs": {"T": {"unmatched": 9, "needed": 20, "unmatched_ids": [f"SV-{n}" + "x" * 1000 for n in range(5000)],
                            "refused_titles": ["R" * 1000] * 500}}}
    counts = EnrichmentReport.from_dict(wire).stigs["T"]
    assert len(counts.unmatched_ids) == 50 and all(len(i) <= 120 for i in counts.unmatched_ids)
    assert len(counts.refused_titles) <= 5 and all(len(t) <= 120 for t in counts.refused_titles)


# --- the titles named in an aggregated line are capped --------------------------------

def _fix_only(title, num=1):
    return Finding(title, f"V-{num}", f"SV-{num}r1_rule", "CAT II", "Open", "h", "i", "", "scanner fix")


def test_an_aggregated_line_names_at_most_five_titles_and_counts_the_rest():
    findings = [_fix_only(f"STIG {n}", n) for n in range(1, 9)]
    line, = enrich_findings(findings, ReferenceLibrary()).warnings()
    assert line.startswith(
        "Check text is blank for 8 finding(s) in 8 STIG(s): STIG 1; STIG 2; STIG 3; STIG 4; STIG 5 … and 3 more. ")
    assert "STIG 6" not in line
    check_only = [Finding(f"STIG {n}", f"V-{n}", f"SV-{n}r1_rule", "CAT II", "Open", "h", "i", "scanner check", "")
                  for n in range(1, 7)]
    line, = enrich_findings(check_only, ReferenceLibrary()).warnings()
    assert line == "Fix text is blank for 6 finding(s) in 6 STIG(s): STIG 1; STIG 2; STIG 3; STIG 4; STIG 5 … and 1 more."


def test_five_titles_are_all_named_with_no_remainder():
    line, = enrich_findings([_fix_only(f"STIG {n}", n) for n in range(1, 6)], ReferenceLibrary()).warnings()
    assert "STIG 1; STIG 2; STIG 3; STIG 4; STIG 5. SCC results" in line and "more" not in line


def test_twenty_thousand_titles_make_one_short_line():
    wire = {"stigs": {f"STIG {n} {'T' * 150}": {"findings": 1, "needed": 1, "blank_check_with_fix": 1}
                      for n in range(20_000)}}
    line, = EnrichmentReport.from_dict(wire).warnings()
    assert "in 20000 STIG(s)" in line and len(line) < 1200


def test_titles_that_read_the_same_once_clipped_are_named_once():
    # The report keys are clipped when written; a loaded payload's keys are not.
    wire = {"stigs": {"T" * 120 + suffix: {"findings": 1, "needed": 1, "blank_check_with_fix": 1}
                      for suffix in ("-a", "-b", "-c")}}
    wire["stigs"]["Other STIG"] = {"findings": 1, "needed": 1, "blank_check_with_fix": 1}
    line, = EnrichmentReport.from_dict(wire).warnings()
    assert line.count("T" * 120) == 1
    assert f"in 4 STIG(s): {'T' * 120}; Other STIG. SCC results" in line
