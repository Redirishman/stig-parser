from pathlib import Path

from app.parsers.base import Benchmark, BenchmarkRule, Finding
from app.parsers.benchmark_parser import BenchmarkParser
from app.reference.library import ReferenceLibrary


def _candidates(lib, finding):
    """The rules a lookup offers for *finding*, best first."""
    return [rule for rule, _ in lib.lookup(finding).matches]


FIX = Path(__file__).parent / "fixtures"


def _finding(rule_id="", vuln_id="", stig_id=""):
    return Finding("", vuln_id, rule_id, "", "Open", "h", "i", "", "", stig_id=stig_id)


def _library():
    lib = ReferenceLibrary()
    scc = BenchmarkParser().read_all(FIX / "scc_embedded_results.xml")[0][0]
    manual = BenchmarkParser().read_all(FIX / "manual_stig_win11.xml")[0][0]
    lib.add_benchmark(scc, "scc_embedded_results.xml", embedded=True)
    lib.add_benchmark(manual, "manual_stig_win11.xml", embedded=False)
    return lib


def test_sources_record_edition_release_and_counts():
    lib = _library()
    by_file = {s.file_name: s for s in lib.sources}
    assert by_file["scc_embedded_results.xml"].edition == "scap"
    assert by_file["scc_embedded_results.xml"].embedded is True
    assert by_file["scc_embedded_results.xml"].rule_count == 4
    assert by_file["manual_stig_win11.xml"].edition == "manual"
    assert by_file["manual_stig_win11.xml"].release == "V2R9"
    assert by_file["manual_stig_win11.xml"].benchmark_id == "MS_Windows_11_STIG"
    assert lib.has_standalone is True


def test_long_form_rule_id_finds_the_short_form_manual_rule():
    cands = _candidates(_library(), _finding("xccdf_mil.disa.stig_rule_SV-253284r958928_rule"))
    assert [c.source.file_name for c in cands] == ["manual_stig_win11.xml", "scc_embedded_results.xml"]
    assert cands[0].check_text and not cands[1].check_text


def test_stem_match_across_revisions_prefers_the_same_revision():
    cands = _candidates(_library(), _finding("xccdf_mil.disa.stig_rule_SV-253285r958930_rule"))
    # exact-revision hit (the embedded SCAP rule) first, then the Manual rule of another revision
    assert [(c.source.file_name, c.revision) for c in cands] == [
        ("scc_embedded_results.xml", "r958930"),
        ("manual_stig_win11.xml", "r991589"),
    ]


def test_vuln_id_and_stig_id_lookups():
    lib = _library()
    assert _candidates(lib, _finding(vuln_id="V-253287"))[0].rule_stem == "SV-253287"
    assert _candidates(lib, _finding(stig_id="wn11_00_000175"))[0].vuln_id == "V-253287"


def test_no_keys_no_candidates():
    assert _candidates(_library(), _finding()) == []
    assert ReferenceLibrary().has_standalone is False


# --- release-aware ranking ---------------------------------------------------

def _release_benchmark(release, revision, check):
    bench = Benchmark("xccdf_mil.disa.stig_benchmark_X", "X STIG", release=release)
    rule_id = f"SV-1{revision}_rule"
    bench.rules[rule_id] = BenchmarkRule("V-1", rule_id, "CAT II", check, "fix", stig_id="X-1")
    return bench


def _two_release_library(older_first):
    older = (_release_benchmark("V2R8", "r2", "older"), "x_v2r8.xml")
    newer = (_release_benchmark("V2R10", "r4", "newer"), "x_v2r10.xml")
    lib = ReferenceLibrary()
    for bench, name in ([older, newer] if older_first else [newer, older]):
        lib.add_benchmark(bench, name, embedded=False)
    return lib


def _scanned(scan_release):
    return Finding("X STIG", "V-1", "SV-1r3_rule", "CAT II", "Open", "h", "i", "", "", scan_release=scan_release)


def test_without_a_scanned_release_the_newest_release_wins_in_either_load_order():
    for older_first in (True, False):
        cands = _candidates(_two_release_library(older_first), _scanned(""))
        assert [c.source.release for c in cands] == ["V2R10", "V2R8"], older_first


def test_the_scanned_release_wins_over_a_newer_one_in_either_load_order():
    for older_first in (True, False):
        cands = _candidates(_two_release_library(older_first), _scanned("V2R8"))
        assert [c.source.release for c in cands] == ["V2R8", "V2R10"], older_first


def test_same_revision_and_operator_supplied_still_outrank_release():
    lib = ReferenceLibrary()
    lib.add_benchmark(_release_benchmark("V2R10", "r4", "newer"), "x_v2r10.xml", embedded=False)
    lib.add_benchmark(_release_benchmark("V2R8", "r3", "same revision"), "x_v2r8.xml", embedded=False)
    lib.add_benchmark(_release_benchmark("V2R11", "r5", "embedded"), "scan.xml", embedded=True)
    cands = _candidates(lib, _scanned("V2R10"))
    assert [c.source.file_name for c in cands] == ["x_v2r8.xml", "x_v2r10.xml", "scan.xml"]


def test_an_unparseable_release_sorts_after_a_parseable_one():
    lib = ReferenceLibrary()
    lib.add_benchmark(_release_benchmark("draft", "r2", "unlabelled"), "a_draft.xml", embedded=False)
    lib.add_benchmark(_release_benchmark("V1R1", "r4", "labelled"), "b_v1r1.xml", embedded=False)
    assert [c.source.file_name for c in _candidates(lib, _scanned(""))] == ["b_v1r1.xml", "a_draft.xml"]


# --- bounded lookups ---------------------------------------------------------

def _crowded_benchmark(count, *, share_stem=True):
    bench = Benchmark("xccdf_mil.disa.stig_benchmark_X", "X STIG", release="V1R1")
    for i in range(count):
        rule_id = f"SV-1r{i}_rule" if share_stem else f"SV-{i}r1_rule"
        bench.rules[rule_id] = BenchmarkRule(f"V-{i}", rule_id, "CAT II", "c", "f", stig_id=f"X-{i}")
    return bench


def test_a_crowded_stem_is_bounded_and_warned_about_exactly_once():
    # A small input: with the cap removed this fails on the first assertion instead of grinding.
    lib = ReferenceLibrary()
    lib.add_benchmark(_crowded_benchmark(100), "big.xml", embedded=False)
    findings = [Finding("X", "", "SV-1r999999_rule", "", "Open", "h", "i", "", "") for _ in range(5)]
    results = [_candidates(lib, f) for f in findings]
    assert all(len(r) == 32 for r in results), [len(r) for r in results]
    assert lib.warnings == ["big.xml: more than 32 rules share one rule stem — extra rules ignored for lookup"]


def test_each_crowded_index_warns_once_per_source_file():
    lib = ReferenceLibrary()
    bench = Benchmark("xccdf_mil.disa.stig_benchmark_X", "X STIG", release="V1R1")
    for i in range(40):
        rule_id = f"SV-1r{i}_rule"
        bench.rules[rule_id] = BenchmarkRule("V-1", rule_id, "CAT II", "c", "f", stig_id="X-1")
    lib.add_benchmark(bench, "dup.xml", embedded=False)
    assert sorted(lib.warnings) == sorted(
        f"dup.xml: more than 32 rules share one {kind} — extra rules ignored for lookup"
        for kind in ("rule stem", "V-ID", "STIG ID"))


def test_thirty_two_rules_per_key_is_not_a_warning():
    lib = ReferenceLibrary()
    lib.add_benchmark(_crowded_benchmark(32), "ok.xml", embedded=False)
    assert lib.warnings == []
    # no V-ID on the finding: the 32 rules have 32 different V-IDs, and a V-ID that differs is a contradiction
    by_stem = Finding("X STIG", "", "SV-1r3_rule", "CAT II", "Open", "h", "i", "", "")
    assert len(_candidates(lib, by_stem)) == 32


def test_the_warning_escapes_and_truncates_the_untrusted_file_name():
    lib = ReferenceLibrary()
    hostile = "evil\nname\x1b[31m" + "x" * 300 + ".xml"
    lib.add_benchmark(_crowded_benchmark(40), hostile, embedded=False)
    assert lib.warnings
    for w in lib.warnings:
        assert "\n" not in w and "\x1b" not in w
        shown = w.split(": more than")[0]
        assert len(shown) <= 120 and shown.startswith("…") and shown.endswith("x.xml")


# --- never match the wrong rule ----------------------------------------------

ROUTER = "Cisco IOS XE Router NDM STIG"
SWITCH = "Cisco IOS XE Switch NDM Security Technical Implementation Guide"


def _stig(title, release, rules):
    """rules: (rule_id, vuln_id, stig_id, check_text) tuples."""
    bench = Benchmark("xccdf_mil.disa.stig_benchmark_X", title, release=release)
    for rule_id, vuln_id, stig_id, check in rules:
        bench.rules[rule_id] = BenchmarkRule(vuln_id, rule_id, "CAT II", check, "fix", stig_id=stig_id)
    return bench


def _ndm_library(*names):
    """Router and/or switch NDM references, in the order given. Both define CISC-ND-000010."""
    sources = {
        "router": (_stig(ROUTER, "V2R1", [("SV-1r1_rule", "V-1", "CISC-ND-000010", "router check")]), "router.xml"),
        "switch": (_stig(SWITCH, "V2R1", [("SV-2r1_rule", "V-2", "CISC-ND-000010", "switch check")]), "switch.xml"),
    }
    lib = ReferenceLibrary()
    for name in names:
        bench, file_name = sources[name]
        lib.add_benchmark(bench, file_name, embedded=False)
    return lib


def _by_stig_id(title="", stig_id="CISC-ND-000010", rule_id="", vuln_id=""):
    return Finding(title, vuln_id, rule_id, "", "Open", "h", "i", "", "", stig_id=stig_id)


def test_stig_id_match_needs_the_same_product_when_the_finding_is_titled():
    assert [c.source.file_name for c in _candidates(_ndm_library("switch"), _by_stig_id(ROUTER))] == []
    for order in (("router", "switch"), ("switch", "router")):
        cands = _candidates(_ndm_library(*order), _by_stig_id(ROUTER))
        assert [c.source.file_name for c in cands] == ["router.xml"], order


def test_product_match_ignores_stig_scap_benchmark_and_release_wording():
    lib = ReferenceLibrary()
    lib.add_benchmark(_stig("Microsoft Windows 11 Security Technical Implementation Guide", "V2R9",
                            [("SV-5r1_rule", "V-5", "WN11-00-000150", "check")]), "manual.xml", embedded=False)
    finding = _by_stig_id("Microsoft Windows 11 STIG SCAP Benchmark", stig_id="wn11_00_000150")
    assert [c.source.file_name for c in _candidates(lib, finding)] == ["manual.xml"]


def test_untitled_stig_id_match_is_ambiguous_across_products():
    lib = _ndm_library("router", "switch")
    result = lib.lookup(_by_stig_id(""))
    assert result.matches == [] and result.ambiguous is True
    assert _candidates(lib, _by_stig_id("")) == []
    assert lib.lookup(_by_stig_id("")).matches == []


def test_untitled_stig_id_match_is_accepted_when_one_product_answers():
    lib = _ndm_library("router")
    result = lib.lookup(_by_stig_id(""))
    assert [(r.source.file_name, key) for r, key in result.matches] == [("router.xml", "stig_id")]
    assert result.ambiguous is False
    # two releases of the same product are still one product
    lib.add_benchmark(_stig(ROUTER, "V2R2", [("SV-1r2_rule", "V-1", "CISC-ND-000010", "newer")]),
                      "router_r2.xml", embedded=False)
    again = lib.lookup(_by_stig_id(""))
    assert again.ambiguous is False
    assert [r.source.file_name for r, _ in again.matches] == ["router_r2.xml", "router.xml"]


def test_candidates_report_the_first_key_that_reached_each_rule():
    lib = ReferenceLibrary()
    lib.add_benchmark(_stig("X STIG", "V1R1", [("SV-1r1_rule", "V-1", "X-1", "check")]), "x.xml", embedded=False)
    def keys(finding):
        return [key for _, key in lib.lookup(finding).matches]
    assert keys(Finding("", "", "SV-1r1_rule", "", "Open", "h", "i", "", "")) == ["rule_id"]
    assert keys(Finding("", "", "SV-1r2_rule", "", "Open", "h", "i", "", "")) == ["stem"]
    assert keys(Finding("", "V-1", "", "", "Open", "h", "i", "", "")) == ["vuln_id"]
    assert keys(_by_stig_id("", stig_id="X-1")) == ["stig_id"]
    # all four keys name the same rule: it is reported once, under the strongest key
    full = Finding("X STIG", "V-1", "SV-1r1_rule", "", "Open", "h", "i", "", "", stig_id="X-1")
    assert keys(full) == ["rule_id"]
    assert _candidates(lib, full) == [r for r, _ in lib.lookup(full).matches]


def test_a_rule_with_a_different_stem_is_rejected_even_when_the_vuln_id_matches():
    # OpenSCAP shape: one Group (V-1) holds several Rules.
    lib = ReferenceLibrary()
    lib.add_benchmark(_stig("X STIG", "V1R1", [
        ("SV-10r1_rule", "V-1", "X-10", "text of SV-10"),
        ("SV-11r1_rule", "V-1", "X-11", "text of SV-11"),
    ]), "x.xml", embedded=False)
    finding = Finding("X STIG", "V-1", "SV-10r1_rule", "", "Open", "h", "i", "", "")
    assert [c.check_text for c in _candidates(lib, finding)] == ["text of SV-10"]
    other = Finding("X STIG", "V-1", "SV-12r1_rule", "", "Open", "h", "i", "", "")
    assert _candidates(lib, other) == []


def test_a_rule_with_a_different_vuln_id_is_rejected_even_when_the_stem_matches():
    lib = ReferenceLibrary()
    lib.add_benchmark(_stig("X STIG", "V1R1", [("SV-1r1_rule", "V-1", "X-1", "check")]), "x.xml", embedded=False)
    assert _candidates(lib, Finding("", "V-999", "SV-1r1_rule", "", "Open", "h", "i", "", "")) == []
    assert len(_candidates(lib, Finding("", "v-1 ", "SV-1r1_rule", "", "Open", "h", "i", "", ""))) == 1


def test_a_finding_whose_rule_id_is_its_stig_id_has_no_stem_to_conflict():
    # What the Nessus parser produces when the audit has no Rule-ID.
    lib = ReferenceLibrary()
    lib.add_benchmark(_stig("Microsoft Windows Server 2022 STIG", "V1R4",
                            [("SV-254239r958472_rule", "V-254239", "WN22-00-000010", "check")]),
                      "server.xml", embedded=False)
    nessus = Finding("Nessus Compliance", "V-254239", "WN22-00-000010", "", "Open", "h", "i", "", "",
                     stig_id="WN22-00-000010")
    assert [(r.source.file_name, key) for r, key in lib.lookup(nessus).matches] == [("server.xml", "vuln_id")]
    # without a V-ID it needs the STIG ID, and the product must agree
    titled = Finding("Microsoft Windows Server 2022 STIG", "", "WN22-00-000010", "", "Open", "h", "i", "", "",
                     stig_id="WN22-00-000010")
    assert [(r.source.file_name, key) for r, key in lib.lookup(titled).matches] == [("server.xml", "stig_id")]
    untitled = Finding("", "", "WN22-00-000010", "", "Open", "h", "i", "", "", stig_id="WN22-00-000010")
    assert [(r.source.file_name, key) for r, key in lib.lookup(untitled).matches] == [("server.xml", "stig_id")]


# --- embedded copies must not crowd out a reference --------------------------

def _scc_embedded_benchmark():
    return _stig("Windows 11 STIG", "V2R8", [
        ("SV-5r1_rule", "V-5", "WN11-00-000150", ""),
        ("SV-6r1_rule", "V-6", "WN11-00-000160", ""),
    ])


def _win11_reference():
    return _stig("Windows 11 Security Technical Implementation Guide", "V2R9", [
        ("SV-5r1_rule", "V-5", "WN11-00-000150", "manual check 5"),
        ("SV-6r1_rule", "V-6", "WN11-00-000160", "manual check 6"),
    ])


def test_identical_embedded_benchmarks_are_loaded_once():
    lib = ReferenceLibrary()
    first = lib.add_benchmark(_scc_embedded_benchmark(), "host-01.xml", embedded=True)
    for n in range(2, 41):
        again = lib.add_benchmark(_scc_embedded_benchmark(), f"host-{n:02d}.xml", embedded=True)
        assert again is first
    assert [s.file_name for s in lib.sources] == ["host-01.xml"]
    lib.add_benchmark(_win11_reference(), "manual.xml", embedded=False)
    finding = Finding("Windows 11 STIG", "V-5", "SV-5r1_rule", "CAT II", "Open", "h", "i", "", "")
    cands = _candidates(lib, finding)
    assert [c.source.file_name for c in cands] == ["manual.xml", "host-01.xml"]
    assert len([s for s in lib.sources if s.embedded]) == 1
    assert lib.warnings == []


def test_forty_identical_embedded_copies_do_not_push_out_a_later_reference():
    lib = ReferenceLibrary()
    for n in range(40):
        lib.add_benchmark(_scc_embedded_benchmark(), f"host-{n:02d}.xml", embedded=True)
    lib.add_benchmark(_win11_reference(), "manual.xml", embedded=False)
    finding = Finding("Windows 11 STIG", "V-5", "SV-5r1_rule", "CAT II", "Open", "h", "i", "", "")
    assert _candidates(lib, finding)[0].check_text == "manual check 5"
    assert len([s for s in lib.sources if s.embedded]) == 1
    assert lib.warnings == []


def test_embedded_copies_with_different_rules_or_release_are_kept():
    lib = ReferenceLibrary()
    lib.add_benchmark(_scc_embedded_benchmark(), "a.xml", embedded=True)
    other_release = _scc_embedded_benchmark()
    other_release.release = "V2R9"
    lib.add_benchmark(other_release, "b.xml", embedded=True)
    other_rules = _stig("Windows 11 STIG", "V2R8", [("SV-5r1_rule", "V-5", "WN11-00-000150", "")])
    lib.add_benchmark(other_rules, "c.xml", embedded=True)
    assert [s.file_name for s in lib.sources] == ["a.xml", "b.xml", "c.xml"]


def test_an_identical_operator_supplied_benchmark_is_never_dropped():
    lib = ReferenceLibrary()
    lib.add_benchmark(_scc_embedded_benchmark(), "a.xml", embedded=False)
    lib.add_benchmark(_scc_embedded_benchmark(), "b.xml", embedded=False)
    assert [s.file_name for s in lib.sources] == ["a.xml", "b.xml"]


def test_add_rules_dedupes_an_identical_embedded_source_too():
    from app.reference.models import ReferenceRule, ReferenceSource

    def source(name):
        return ReferenceSource(name, "MS_Windows_11_STIG", "T", "V1R1", True, "cklb", 1)

    def rules(src):
        return [ReferenceRule("V-1", "SV-1r1_rule", "SV-1", "r1", "X-1", "CAT II", "T", "c", "f", src)]

    lib = ReferenceLibrary()
    first = source("a.cklb")
    lib.add_rules(first, rules(first))
    second = source("b.cklb")
    assert lib.add_rules(second, rules(second)) is first
    assert [s.file_name for s in lib.sources] == ["a.cklb"]
    assert len(_candidates(lib, Finding("", "V-1", "", "", "Open", "h", "i", "", ""))) == 1


def test_supplied_and_embedded_rules_have_separate_caps():
    lib = ReferenceLibrary()
    for n in range(40):                 # 40 DIFFERENT embedded benchmarks that share one stem
        bench = _stig("Windows 11 STIG", f"V2R{n}", [("SV-1r1_rule", f"V-{n}", f"X-{n}", "")])
        lib.add_benchmark(bench, f"host-{n:02d}.xml", embedded=True)
    lib.add_benchmark(_stig("Windows 11 STIG", "V3R1", [("SV-1r1_rule", "V-1", "X-1", "operator text")]),
                      "manual.xml", embedded=False)
    finding = Finding("", "", "SV-1r1_rule", "", "Open", "h", "i", "", "")
    cands = _candidates(lib, finding)
    assert cands[0].source.file_name == "manual.xml" and cands[0].check_text == "operator text"
    assert len([c for c in cands if c.source.embedded]) == 32
    assert any("more than 32 rules share one rule stem" in w for w in lib.warnings)


def test_operator_supplied_rules_still_have_their_own_cap():
    lib = ReferenceLibrary()
    for n in range(40):
        bench = _stig("Windows 11 STIG", f"V2R{n}", [("SV-1r1_rule", f"V-{n}", f"X-{n}", "text")])
        lib.add_benchmark(bench, f"ref-{n:02d}.xml", embedded=False)
    cands = _candidates(lib, Finding("", "", "SV-1r1_rule", "", "Open", "h", "i", "", ""))
    assert len(cands) == 32
    assert any("more than 32 rules share one rule stem" in w for w in lib.warnings)


# --- the stem guard compares DISA stems only; a V-ID-only match on a group is ambiguous ----------

def _server_library():
    lib = ReferenceLibrary()
    lib.add_benchmark(_stig("Microsoft Windows Server 2022 STIG", "V1R4",
                            [("SV-254239r958472_rule", "V-254239", "WN22-00-000010", "server check")]),
                      "server.xml", embedded=False)
    return lib


def test_a_non_disa_rule_id_has_no_stem_to_conflict_with():
    ssg = Finding("", "V-254239", "xccdf_org.ssgproject.content_rule_accounts_tmout", "", "Open", "h", "i", "", "")
    cands = _server_library().lookup(ssg).matches
    assert [(r.check_text, key) for r, key in cands] == [("server check", "vuln_id")]
    scanner_name = Finding("", "V-254239", "Windows Server 2022: account lockout", "", "Open", "h", "i", "", "")
    assert len(_candidates(_server_library(), scanner_name)) == 1


def test_a_different_disa_stem_still_conflicts_with_the_rule():
    other = Finding("", "V-254239", "SV-254241r1_rule", "", "Open", "h", "i", "", "")
    assert _candidates(_server_library(), other) == []


def test_a_non_disa_stem_in_the_reference_is_not_compared_either():
    lib = ReferenceLibrary()
    lib.add_benchmark(_stig("X STIG", "V1R1", [("accounts_tmout", "V-1", "X-1", "ssg check")]),
                      "ssg.xml", embedded=False)
    finding = Finding("", "V-1", "SV-10r1_rule", "", "Open", "h", "i", "", "")
    assert [c.check_text for c in _candidates(lib, finding)] == ["ssg check"]


def _group_library(*rules):
    lib = ReferenceLibrary()
    lib.add_benchmark(_stig("X STIG", "V1R1", [(rule_id, "V-1", stig_id, text) for rule_id, stig_id, text in rules]),
                      "x.xml", embedded=False)
    return lib


def test_a_v_id_that_names_several_rules_is_ambiguous_without_a_rule_id():
    lib = _group_library(("SV-10r1_rule", "X-10", "text of SV-10"), ("SV-11r1_rule", "X-11", "text of SV-11"))
    for finding in (Finding("X STIG", "V-1", "", "", "Open", "h", "i", "", ""),
                    Finding("X STIG", "V-1", "xccdf_org.ssgproject.content_rule_accounts_tmout", "", "Open", "h", "i", "", "")):
        result = lib.lookup(finding)
        assert result.matches == [] and result.ambiguous is True and result.ambiguous_by == "vuln_id"
        assert _candidates(lib, finding) == []


def test_a_finding_with_a_disa_stem_picks_its_own_rule_from_the_group():
    lib = _group_library(("SV-10r1_rule", "X-10", "text of SV-10"), ("SV-11r1_rule", "X-11", "text of SV-11"))
    result = lib.lookup(Finding("X STIG", "V-1", "SV-11r9_rule", "", "Open", "h", "i", "", ""))
    assert [r.check_text for r, _ in result.matches] == ["text of SV-11"]
    assert result.ambiguous is False and result.ambiguous_by == ""


def test_one_rule_from_two_releases_is_not_ambiguous_and_the_best_ranked_comes_first():
    lib = ReferenceLibrary()
    lib.add_benchmark(_stig("X STIG", "V1R1", [("SV-254239r1_rule", "V-254239", "X-1", "older")]), "old.xml", embedded=False)
    lib.add_benchmark(_stig("X STIG", "V1R2", [("SV-254239r2_rule", "V-254239", "X-1", "newer")]), "new.xml", embedded=False)
    for scan_release, first in (("", "newer"), ("V1R1", "older")):
        finding = Finding("X STIG", "V-254239", "", "", "Open", "h", "i", "", "", scan_release=scan_release)
        result = lib.lookup(finding)
        assert result.ambiguous is False
        assert [r.check_text for r, _ in result.matches] == [first, "older" if first == "newer" else "newer"]


def test_group_candidates_are_dropped_even_when_the_rule_id_matched_another_rule():
    # The exact rule-ID hit is kept; the V-ID-only group members must not fill what it lacks.
    lib = _group_library(("SV-10r1_rule", "X-10", "text of SV-10"), ("SV-11r1_rule", "X-11", "text of SV-11"))
    lib.add_benchmark(_stig("Other", "V1R1", [("accounts_tmout", "V-1", "O-1", "ssg text")]), "ssg.xml", embedded=False)
    finding = Finding("", "V-1", "accounts_tmout", "", "Open", "h", "i", "", "")
    result = lib.lookup(finding)
    assert [(r.check_text, key) for r, key in result.matches] == [("ssg text", "rule_id")]
    assert result.ambiguous is False     # the exact hit stays and answers; the group members are simply dropped


def test_the_stig_id_ambiguity_names_its_cause():
    result = _ndm_library("router", "switch").lookup(_by_stig_id(""))
    assert (result.ambiguous, result.ambiguous_by) == (True, "stig_id")


def test_lookup_names_the_titles_a_stig_id_was_refused_under():
    only_switch = _ndm_library("switch").lookup(_by_stig_id(ROUTER))
    assert only_switch.matches == [] and only_switch.refused_products == (SWITCH,) and not only_switch.refused_more
    both = _ndm_library("router", "switch").lookup(_by_stig_id(ROUTER))
    assert [r.source.file_name for r, _ in both.matches] == ["router.xml"] and both.refused_products == (SWITCH,)
    untitled = _ndm_library("router", "switch").lookup(_by_stig_id(""))
    assert untitled.refused_products == () and untitled.ambiguous is True
    answered = _ndm_library("router").lookup(_by_stig_id(ROUTER))
    assert answered.refused_products == ()


def test_refused_titles_are_distinct_capped_at_five_and_clipped():
    lib = ReferenceLibrary()
    for n in range(1, 8):
        title = f"Product {n} STIG" + ("x" * 300 if n == 1 else "")
        lib.add_benchmark(_stig(title, "V1R1", [(f"SV-{n}r1_rule", f"V-{n}", "SHARED-1", "c")]), f"p{n}.xml", embedded=False)
    lib.add_benchmark(_stig("Product 2 STIG", "V1R2", [("SV-2r2_rule", "V-2", "SHARED-1", "c")]), "p2b.xml", embedded=False)
    result = lib.lookup(_by_stig_id("Other STIG", stig_id="SHARED-1"))
    assert len(result.refused_products) == 5 and result.refused_more is True
    assert len(set(result.refused_products)) == 5
    assert all(len(t) <= 120 for t in result.refused_products)


# --- embedded copies are identical only when their text is -------------------

def _embedded_copy(check="", fix="fix", severity="CAT II", order=("SV-5r1_rule", "SV-6r1_rule")):
    bench = Benchmark("xccdf_mil.disa.stig_benchmark_X", "Windows 11 STIG", release="V2R8")
    for rule_id in order:
        bench.rules[rule_id] = BenchmarkRule(f"V-{rule_id[3]}", rule_id, severity, check, fix, stig_id=f"X-{rule_id[3]}")
    return bench


def test_an_embedded_copy_with_the_same_ids_but_different_text_is_a_separate_source():
    lib = ReferenceLibrary()
    first = lib.add_benchmark(_embedded_copy(check=""), "a.xml", embedded=True)
    second = lib.add_benchmark(_embedded_copy(check="the check text"), "b.xml", embedded=True)
    assert second is not first
    assert [s.file_name for s in lib.sources] == ["a.xml", "b.xml"]


def test_a_difference_in_severity_or_fix_text_also_separates_embedded_copies():
    for kwargs in ({"severity": "CAT I"}, {"fix": "another fix"}):
        lib = ReferenceLibrary()
        lib.add_benchmark(_embedded_copy(), "a.xml", embedded=True)
        lib.add_benchmark(_embedded_copy(**kwargs), "b.xml", embedded=True)
        assert [s.file_name for s in lib.sources] == ["a.xml", "b.xml"], kwargs


def test_embedded_copies_with_identical_text_dedupe_whatever_the_rule_order():
    lib = ReferenceLibrary()
    first = lib.add_benchmark(_embedded_copy(check="c"), "a.xml", embedded=True)
    for n in range(40):
        order = ("SV-5r1_rule", "SV-6r1_rule") if n % 2 else ("SV-6r1_rule", "SV-5r1_rule")
        assert lib.add_benchmark(_embedded_copy(check="c", order=order), f"h{n}.xml", embedded=True) is first
    assert [s.file_name for s in lib.sources] == ["a.xml"]


def test_the_text_that_tells_copies_apart_is_not_confusable_by_where_a_field_ends():
    lib = ReferenceLibrary()
    one = Benchmark("xccdf_mil.disa.stig_benchmark_X", "T", release="V1R1")
    one.rules["SV-1r1_rule"] = BenchmarkRule("V-1", "SV-1r1_rule", "CAT II", "ab", "c")
    two = Benchmark("xccdf_mil.disa.stig_benchmark_X", "T", release="V1R1")
    two.rules["SV-1r1_rule"] = BenchmarkRule("V-1", "SV-1r1_rule", "CAT II", "a", "bc")
    lib.add_benchmark(one, "one.xml", embedded=True)
    lib.add_benchmark(two, "two.xml", embedded=True)
    assert [s.file_name for s in lib.sources] == ["one.xml", "two.xml"]


# --- ASCII-only folding of ID keys ------------------------------------------------------

SHARP_S = chr(0xDF)     # str.upper() turns it into "SS", which would collide with a real "SS"


def _ssg_library(rule_id):
    bench = Benchmark("xccdf_org.ssgproject.content_benchmark_X", "Guide X", release="V1R1")
    bench.rules[rule_id] = BenchmarkRule("", rule_id, "CAT II", "check", "fix")
    lib = ReferenceLibrary()
    lib.add_benchmark(bench, "ref.xml", embedded=False)
    return lib


def test_a_non_ascii_rule_id_never_collides_with_its_ascii_upper_case_form():
    lib = _ssg_library("accounts_ss")
    assert _candidates(lib, Finding("", "", f"accounts_{SHARP_S}", "", "Open", "h", "i", "", "")) == []
    assert len(_candidates(lib, Finding("", "", "ACCOUNTS_SS", "", "Open", "h", "i", "", ""))) == 1   # ASCII still folds


def test_a_non_ascii_rule_id_still_matches_itself_and_only_itself():
    lib = _ssg_library(f"accounts_{SHARP_S}")
    assert len(_candidates(lib, Finding("", "", f"accounts_{SHARP_S}", "", "Open", "h", "i", "", ""))) == 1
    assert _candidates(lib, Finding("", "", "accounts_ss", "", "Open", "h", "i", "", "")) == []


def test_two_rules_whose_ids_differ_only_by_a_non_ascii_letter_are_two_identities():
    bench = Benchmark("xccdf_org.ssgproject.content_benchmark_X", "Guide X", release="V1R1")
    for rule_id in ("rule_ss", f"rule_{SHARP_S}"):
        bench.rules[rule_id] = BenchmarkRule("V-1", rule_id, "CAT II", "c", "f")
    lib = ReferenceLibrary()
    lib.add_benchmark(bench, "ref.xml", embedded=False)
    result = lib.lookup(Finding("", "V-1", "", "", "Open", "h", "i", "", ""))
    assert result.matches == [] and (result.ambiguous, result.ambiguous_by) == (True, "vuln_id")



def test_a_long_file_name_in_a_library_warning_keeps_its_end():
    lib = ReferenceLibrary()
    name = "lib.zip/" + "folder/" * 30 + "big-xccdf.xml"
    lib.add_benchmark(_crowded_benchmark(40), name, embedded=False)
    assert lib.warnings == [
        "…" + name[-119:] + ": more than 32 rules share one rule stem — extra rules ignored for lookup"]


# --- the run holds a bounded number of rules ----------------------------------------------------

def _bench(bid: str, numbers: range) -> Benchmark:
    return Benchmark(bid, f"{bid} STIG", {f"SV-{n}r1_rule": BenchmarkRule(f"V-{n}", f"SV-{n}r1_rule", "CAT II", "c", "f")
                                         for n in numbers}, release="V1R1")


def test_rules_past_the_run_limit_are_not_held_and_the_first_file_is_named(monkeypatch):
    import app.reference.library as library_module
    monkeypatch.setattr(library_module, "MAX_RULES_PER_RUN", 3)
    lib = ReferenceLibrary()
    lib.add_benchmark(_bench("A", range(2)), "a.xml", embedded=False)
    lib.add_benchmark(_bench("B", range(10, 12)), "b.xml", embedded=False)
    lib.add_benchmark(_bench("C", range(20, 22)), "c.xml", embedded=False)
    assert lib.rules_left == 0
    assert [(s.file_name, s.rule_count) for s in lib.sources] == [("a.xml", 2), ("b.xml", 1)]
    assert [r.rule_id for r in _candidates(lib, _finding("SV-10r1_rule"))] == ["SV-10r1_rule"]
    assert _candidates(lib, _finding("SV-11r1_rule")) == [] and _candidates(lib, _finding("SV-20r1_rule")) == []
    assert lib.warnings == [
        "b.xml: the limit of 3 STIG reference rules for one run was reached — rules past it, in this file and "
        "any later reference, were not loaded; findings they would have filled read \"not in supplied references\""]


def test_a_file_whose_rules_were_not_built_is_named(monkeypatch):
    import app.reference.library as library_module
    monkeypatch.setattr(library_module, "MAX_RULES_PER_RUN", 3)
    lib = ReferenceLibrary()
    lib.not_loaded("list.cklb")
    lib.not_loaded("other.cklb")
    assert lib.rules_left == 0 and len(lib.warnings) == 1 and lib.warnings[0].startswith("list.cklb: the limit of 3")
