"""Text taken from uploads is bounded before it reaches a cell, a warning or the report.

Every string here is built in memory; nothing is read from a fixture file except
where the parser itself is the thing under test.
"""
import json

from app.parsers.base import Benchmark, BenchmarkRule, Finding
from app.parsers.benchmark_parser import BenchmarkParser
from app.reference.cklb_loader import load_cklb_reference
from app.reference.enrich import EnrichmentReport, enrich_findings
from app.reference.library import ReferenceLibrary
from app.reference.models import ReferenceRule, ReferenceSource
from app.reference.normalize import clip, release_label

FIVE_MB = 5_000_000
THREE_MB = 3_000_000


def _bench(title="X STIG", release="V1R1", benchmark_id="xccdf_mil.disa.stig_benchmark_X", revision="r2",
           stig_id="X-1"):
    bench = Benchmark(benchmark_id, title, release=release)
    rule_id = f"SV-1{revision}_rule"
    bench.rules[rule_id] = BenchmarkRule("V-1", rule_id, "CAT II", "check text", "fix text", stig_id=stig_id)
    return bench


def _finding(**overrides):
    f = Finding("X STIG", "V-1", "SV-1r1_rule", "CAT II", "Open", "host", "10.0.0.1", "", "")
    for name, value in overrides.items():
        setattr(f, name, value)
    return f


def _enrich(bench, finding, *, file_name="ref.xml"):
    lib = ReferenceLibrary()
    lib.add_benchmark(bench, file_name, embedded=False)
    return enrich_findings([finding], lib)


def _assert_bounded(report):
    assert report.warnings(), "the scenario is meant to produce warnings"
    assert all(len(w) < 2000 for w in report.warnings()), [len(w) for w in report.warnings()]
    assert len(json.dumps(report.to_dict())) < 20000


# --- normalize ------------------------------------------------------------------

def test_clip_returns_at_most_the_limit():
    assert clip("abcdef", 3) == "abc"
    assert clip("ab", 3) == "ab"
    assert clip(None, 3) == ""
    assert len(clip("x" * FIVE_MB, 120)) == 120


def test_an_unparseable_release_is_cut_to_forty_characters():
    assert len(release_label("x" * FIVE_MB)) == 40
    assert release_label("V2R8 something else") == "V2R8 something else"
    assert release_label("002.008") == "V2R8"


# --- parsers --------------------------------------------------------------------

def test_the_benchmark_parser_clips_release_title_and_benchmark_id(tmp_path):
    path = tmp_path / "huge.xml"
    path.write_text(
        f'<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="{"i" * THREE_MB}">'
        f"<title>{'t' * THREE_MB}</title><version>{'v' * FIVE_MB}</version>"
        '<Group id="V-1"><Rule id="SV-1r1_rule" severity="medium"><version>X-1</version><title>r</title>'
        "<fixtext>fix</fixtext><check><check-content>check</check-content></check></Rule></Group></Benchmark>",
        encoding="utf-8")
    bench = BenchmarkParser().read_all(path)[0][0]
    assert len(bench.release) <= 40
    assert len(bench.title) <= 200
    assert len(bench.benchmark_id) <= 200
    assert bench.rules  # the rules are untouched


def test_the_checklist_loader_clips_release_title_benchmark_id_and_ids(tmp_path):
    path = tmp_path / "huge.cklb"
    path.write_text(json.dumps({"stigs": [{
        "stig_id": "i" * THREE_MB, "display_name": "t" * THREE_MB, "version": "v" * FIVE_MB,
        "release_info": "Release: 1", "rules": [{
            "group_id": "V-" + "9" * THREE_MB, "rule_id_src": "SV-1r1_rule" + "z" * THREE_MB,
            "rule_version": "s" * THREE_MB, "severity": "high", "check_content": "check", "fix_text": "fix"}],
    }]}), encoding="utf-8")
    (source, rules), = load_cklb_reference(path, embedded=False).stigs
    assert len(source.release) <= 40 and len(source.title) <= 200 and len(source.benchmark_id) <= 200
    rule, = rules
    assert max(len(rule.vuln_id), len(rule.rule_id), len(rule.stig_id), len(rule.stig_title)) <= 200


# --- the cell, the warnings and the report ------------------------------------------

def test_a_huge_reference_release_cannot_bloat_the_text_source():
    f = _finding()
    report = _enrich(_bench(release="x" * FIVE_MB), f)           # revision r2 vs r1: the release is named
    assert len(f.text_source) < 300, len(f.text_source)
    _assert_bounded(report)


def test_a_huge_scan_release_cannot_bloat_the_text_source():
    f = _finding(scan_release="y" * FIVE_MB)
    report = _enrich(_bench(), f)
    assert len(f.text_source) < 300, len(f.text_source)
    _assert_bounded(report)


def test_a_huge_reference_title_cannot_bloat_a_warning_or_the_report():
    f = _finding(stig_title="")                                   # takes the reference's title
    report = _enrich(_bench(title="T" * THREE_MB), f)
    assert len(f.stig_title) <= 200
    _assert_bounded(report)


def test_a_huge_scanner_title_cannot_bloat_a_warning_or_the_report():
    f = _finding(stig_title="S" * THREE_MB)
    report = _enrich(_bench(), f)
    _assert_bounded(report)


def test_a_huge_reference_stig_id_cannot_land_in_a_finding():
    f = _finding(stig_id="")
    _enrich(_bench(stig_id="s" * THREE_MB), f)
    assert len(f.stig_id) <= 200


def test_a_huge_unmatched_rule_id_is_clipped_in_the_report():
    other = _finding(rule_id="SV-9r1_rule" + "z" * THREE_MB, vuln_id="V-9", stig_id="")
    matched = _finding()
    lib = ReferenceLibrary()
    lib.add_benchmark(_bench(revision="r1"), "ref.xml", embedded=False)
    report = enrich_findings([matched, other], lib)
    ids = report.stigs["X STIG"].unmatched_ids
    assert ids and all(len(i) <= 120 for i in ids)
    assert len(json.dumps(report.to_dict())) < 20000


def test_the_loaded_list_clips_each_reference_title():
    lib = ReferenceLibrary()
    for n in range(7):
        source = ReferenceSource(f"ref{n}.xml", "X", "T" * THREE_MB, "R" * THREE_MB, False, "manual", 1)
        rule = ReferenceRule(f"V-{n}", f"SV-{n}r1_rule", f"SV-{n}", "r1", f"X-{n}", "CAT II", "T", "c", "f", source)
        lib.add_rules(source, [rule])
    f = _finding(rule_id="SV-100r1_rule", vuln_id="V-100", stig_id="")
    report = enrich_findings([f], lib)
    _assert_bounded(report)


def test_a_huge_file_name_cannot_bloat_the_text_source():
    f = _finding()
    report = _enrich(_bench(), f, file_name="n" * THREE_MB + ".xml")
    assert len(f.text_source) < 300, len(f.text_source)
    assert report.warnings()


def test_a_report_payload_with_a_huge_title_still_warns_briefly():
    wire = {"stigs": {"T" * THREE_MB: {"findings": 2, "needed": 2, "unmatched": 1, "unmatched_ids": ["SV-1"],
                                       "refused_titles": ["R" * THREE_MB], "product_refused": 1, "drifted": 1,
                                       "blank_check_with_fix": 1, "blank_fix_with_check": 1, "ambiguous": 1,
                                       "blank_both": 1, "drift_pair": "p" * THREE_MB}},
            "sources": [], "source_counts": {}}
    warnings = EnrichmentReport.from_dict(wire).warnings()
    assert warnings and all(len(w) < 2000 for w in warnings), [len(w) for w in warnings]


def test_a_source_file_name_is_cut_to_255_characters():
    source = ReferenceSource("n" * THREE_MB + ".xml", "X", "T", "V1R1", False, "manual", 1)
    assert source.file_name == "…" + "n" * 250 + ".xml"     # cut from the left: the file name is kept
    assert ReferenceSource("ref.xml", "X", "T", "V1R1", False, "manual", 1).file_name == "ref.xml"
    lib = ReferenceLibrary()
    held = lib.add_benchmark(_bench(), "n" * THREE_MB + ".xml", embedded=False)
    assert len(held.file_name) == 255
    report = enrich_findings([_finding()], lib)
    assert len(json.dumps(report.to_dict())) < 20000
