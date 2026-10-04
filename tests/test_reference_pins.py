"""Behaviour that only these tests pin: each one fails when the code it names is removed."""
from app.parsers.base import Benchmark, BenchmarkRule, Finding
from app.reference import normalize
from app.reference.enrich import enrich_findings
from app.reference.library import ReferenceLibrary
from app.reference.models import ReferenceSource, make_rule
from app.reference.normalize import product_key



def _candidates(lib, finding):
    """The rules a lookup offers for *finding*, best first."""
    return [rule for rule, _ in lib.lookup(finding).matches]

def _bench(title, release, rules, benchmark_id="xccdf_mil.disa.stig_benchmark_X"):
    """rules: (rule_id, vuln_id, stig_id, check_text, fix_text) tuples."""
    bench = Benchmark(benchmark_id, title, release=release)
    for rule_id, vuln_id, stig_id, check, fix in rules:
        bench.rules[rule_id] = BenchmarkRule(vuln_id, rule_id, "CAT II", check, fix, stig_id=stig_id)
    return bench


def _finding(**overrides):
    f = Finding("", "", "", "", "Open", "host", "10.0.0.1", "", "")
    for name, value in overrides.items():
        setattr(f, name, value)
    return f


# --- enrich: the second lookup ---------------------------------------------------------

def test_a_second_lookup_with_the_filled_identifiers_reaches_a_rule_the_first_could_not():
    lib = ReferenceLibrary()
    lib.add_benchmark(_bench("X STIG", "V1R1", [("SV-1r1_rule", "V-1", "X-1", "", "fix from the scan's benchmark")]),
                      "scan.xml", embedded=True)
    lib.add_benchmark(_bench("X Guide", "V1R1", [("accounts_tmout", "V-1", "", "check from the supplied reference", "f")],
                             benchmark_id="xccdf_org.ssgproject.content_benchmark_X"), "ref.xml", embedded=False)
    f = _finding(rule_id="SV-1r1_rule")            # only a rule ID: the V-ID is learned from the embedded rule
    enrich_findings([f], lib)
    assert f.vuln_id == "V-1"
    assert f.check_text == "check from the supplied reference"
    assert f.text_source.startswith("Check: ref.xml V1R1, matched by V-ID")


# --- library: ranking --------------------------------------------------------------------

def test_a_supplied_rule_outranks_an_embedded_one_even_when_the_embedded_one_is_newer_and_was_scanned():
    lib = ReferenceLibrary()
    rule = [("SV-1r1_rule", "V-1", "X-1", "c", "f")]
    lib.add_benchmark(_bench("X STIG", "V2R5", rule), "embedded.xml", embedded=True)      # loaded first, newest, scanned
    lib.add_benchmark(_bench("X STIG", "V1R1", rule), "supplied.xml", embedded=False)
    finding = _finding(rule_id="SV-1r1_rule", scan_release="V2R5")
    assert [r.source.file_name for r in _candidates(lib, finding)] == ["supplied.xml", "embedded.xml"]


def test_the_same_revision_ranks_first_when_either_side_has_no_rule_suffix():
    with_suffix = ReferenceLibrary()
    with_suffix.add_benchmark(_bench("X STIG", "V1R9", [("SV-1r2_rule", "", "", "c", "f")]), "newer.xml", embedded=False)
    with_suffix.add_benchmark(_bench("X STIG", "V1R1", [("SV-1r3_rule", "", "", "c", "f")]), "older.xml", embedded=False)
    # a checklist's rule_id has no "_rule": the finding must still find its own revision first
    assert _candidates(with_suffix, _finding(rule_id="SV-1r3"))[0].source.file_name == "older.xml"

    bare = ReferenceLibrary()
    bare.add_benchmark(_bench("X STIG", "V1R9", [("SV-1r2", "", "", "c", "f")]), "newer.xml", embedded=False)
    bare.add_benchmark(_bench("X STIG", "V1R1", [("SV-1r3", "", "", "c", "f")]), "older.xml", embedded=False)
    assert _candidates(bare, _finding(rule_id="SV-1r3_rule"))[0].source.file_name == "older.xml"


# --- library: severity ---------------------------------------------------------------------

def test_an_unknown_severity_is_stored_blank():
    lib = ReferenceLibrary()
    bench = _bench("X STIG", "V1R1", [("SV-1r1_rule", "V-1", "X-1", "c", "f")])
    bench.rules["SV-1r1_rule"].severity = "Unknown"
    lib.add_benchmark(bench, "ref.xml", embedded=False)
    assert _candidates(lib, _finding(rule_id="SV-1r1_rule"))[0].severity == ""
    source = ReferenceSource("a.xml", "X", "T", "V1R1", False, "manual", 1)
    kept = dict(vuln_id="V-1", rule_id="SV-1r1_rule", stig_id="X-1", stig_title="T", check_text="c", fix_text="f")
    assert make_rule(source, severity="Unknown", **kept).severity == ""
    assert make_rule(source, severity="CAT I", **kept).severity == "CAT I"


# --- enrich: refused titles, the standalone-candidate branch, the drift pair ----------------

def test_refused_titles_are_capped_across_findings_and_the_cut_is_reported():
    lib = ReferenceLibrary()
    for n in range(1, 7):                              # six products; P1-P3 share STIG ID S1, P4-P6 share S2
        lib.add_benchmark(_bench(f"Product {n} STIG", "V1R1", [(f"SV-{n}r1_rule", f"V-{n}", "S1" if n <= 3 else "S2", "c", "f")]),
                          f"p{n}.xml", embedded=False)
    first, second = _finding(stig_title="Other STIG", stig_id="S1"), _finding(stig_title="Other STIG", stig_id="S2")
    report = enrich_findings([first, second], lib)
    counts = report.stigs["Other STIG"]
    assert counts.product_refused == 2
    assert len(counts.refused_titles) == 5 and counts.refused_more is True        # three + three distinct titles
    assert any(w.endswith("scan's own benchmark or a checklist") and "…)" in w for w in report.warnings())


def test_a_refusal_is_not_counted_when_a_standalone_rule_answered_the_finding():
    lib = ReferenceLibrary()
    lib.add_benchmark(_bench("Alpha STIG", "V1R1", [("SV-1r1_rule", "V-1", "A-1", "", "")]), "alpha.xml", embedded=False)
    lib.add_benchmark(_bench("Beta STIG", "V1R1", [("SV-2r1_rule", "", "S-1", "", "beta fix")]), "beta.xml", embedded=False)
    f = _finding(stig_title="Alpha STIG", vuln_id="V-1", stig_id="S-1", check_text="scanner check")
    report = enrich_findings([f], lib)
    counts = report.stigs["Alpha STIG"]
    assert (counts.product_refused, counts.blank_fix_with_check) == (0, 1)          # the V-ID rule answered, with no fix
    assert f.fix_text == ""
    assert f.text_source == "Check: scanner | Fix: in alpha.xml V1R1, which has no fix text"   # the cell agrees


def test_the_most_common_drift_pair_is_the_one_reported_not_the_first_seen():
    lib = ReferenceLibrary()
    lib.add_benchmark(_bench("X STIG", "V1R2", [("SV-1r2_rule", "V-1", "X-1", "check", "fix")]), "ref.xml", embedded=False)
    findings = [_finding(stig_title="X STIG", vuln_id="V-1", rule_id="SV-1r1_rule", scan_release=release)
                for release in ("V1R0", "V1R1", "V1R1", "V1R1")]       # one odd pair first, then the common one
    report = enrich_findings(findings, lib)
    assert report.stigs["X STIG"].drifted == 4
    assert report.stigs["X STIG"].drift_pair == "reference V1R2, scanned V1R1"


# --- normalize: the product key cache -------------------------------------------------------

def test_the_product_key_cache_is_bounded():
    info = normalize._product_key.cache_info()
    assert info.maxsize is not None and info.maxsize <= 10_000
    for n in range(info.maxsize + 50):
        product_key(f"Distinct Product Title {n}")
    assert normalize._product_key.cache_info().currsize <= info.maxsize


# --- library: which ambiguity is named when both apply ------------------------------------

def test_a_finding_ambiguous_by_vuln_id_and_by_stig_id_is_reported_as_the_vuln_id_case():
    lib = ReferenceLibrary()
    lib.add_benchmark(_bench("Router STIG", "V1R1", [("SV-10r1_rule", "V-1", "R-10", "c", "f"),
                                                      ("SV-11r1_rule", "V-1", "R-11", "c", "f")]), "group.xml", embedded=False)
    for title, rule_id in (("Switch STIG", "SV-20r1_rule"), ("Firewall STIG", "SV-30r1_rule")):
        lib.add_benchmark(_bench(title, "V1R1", [(rule_id, "", "SHARED-1", "c", "f")]), f"{rule_id}.xml", embedded=False)
    by_vuln_only = lib.lookup(_finding(vuln_id="V-1"))
    by_stig_only = lib.lookup(_finding(stig_id="SHARED-1"))
    assert (by_vuln_only.ambiguous_by, by_stig_only.ambiguous_by) == ("vuln_id", "stig_id")   # each alone is ambiguous
    f = _finding(vuln_id="V-1", stig_id="SHARED-1")
    both = lib.lookup(f)
    assert both.matches == [] and (both.ambiguous, both.ambiguous_by) == (True, "vuln_id")
    report = enrich_findings([f], lib)
    assert f.text_source == "Check and fix: V-ID matches several rules, not filled"
    assert report.stigs["(no STIG title)"].ambiguous == 1


# --- models: the rule-side STIG ID is normalised ------------------------------------------

def test_make_rule_normalises_a_stig_id_written_the_scanner_way():
    source = ReferenceSource("a.xml", "X", "Windows 11 STIG", "V1R1", False, "manual", 1)
    rule = make_rule(source, vuln_id="V-1", rule_id="SV-1r1_rule", stig_id="disa_stig_wn11_00_000150",
                     severity="CAT II", stig_title="Windows 11 STIG", check_text="c", fix_text="f")
    assert normalize.norm_stig_id("disa_stig_wn11_00_000150") == "WN11-00-000150"
    assert rule.stig_id == "WN11-00-000150"
    lib = ReferenceLibrary()
    lib.add_rules(source, [rule])
    assert _candidates(lib, _finding(stig_id="WN11-00-000150")) == [rule]
