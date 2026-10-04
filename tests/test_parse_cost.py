"""What parsing a file would cost is measured from its bytes, before any parser reads it."""
import hashlib
import json
from pathlib import Path

import pytest

import app.utils.parse_cost as parse_cost
from app.core.inputs import classify_inputs
from app.utils.parse_cost import measure, start_tags, too_costly

FIX = Path(__file__).parent / "fixtures"


def _write(tmp_path: Path, name: str, data: bytes | str) -> Path:
    path = tmp_path / name
    path.write_bytes(data.encode() if isinstance(data, str) else data)
    return path


# Elements plus attributes: every '=' is charged (an attribute has one; one in text costs nothing to over-count).
@pytest.mark.parametrize("name,elements", [
    # elements + declaration and comment + '='
    ("scc_embedded_results.xml", 60 + 2 + 64), ("manual_stig_win11.xml", 35 + 2 + 34),
    ("nessus_compliance.nessus", 100 + 2 + 50),
])
def test_xml_elements_and_attributes_are_counted_and_the_file_is_hashed(name, elements):
    cost = measure(FIX / name, kind="xml")
    assert cost.elements == elements and not cost.crowded_tag
    assert cost.digest == hashlib.sha256((FIX / name).read_bytes()).hexdigest()


def test_end_tags_are_not_counted_and_every_other_construct_is(tmp_path):
    # Comments, CDATA and instructions are nodes the parser builds too.
    path = _write(tmp_path, "a.xml", '<?xml version="1.0"?><!DOCTYPE r><!-- c --><r><a/><b></b><![CDATA[x]]></r>')
    assert measure(path, kind="xml").elements == 7 + 1          # seven constructs, one '='


def test_counting_does_not_depend_on_where_the_chunks_fall(tmp_path, monkeypatch):
    data = "<r>" + "<a x='1'></a><b/>" * 5000 + "</r>"
    path = _write(tmp_path, "a.xml", data)
    whole = measure(path, kind="xml")
    for chunk in (1, 2, 3, 7, 64):
        monkeypatch.setattr(parse_cost, "_CHUNK", chunk)
        assert measure(path, kind="xml") == whole
    assert whole.elements == 1 + 2 * 5000 + 5000


def test_json_values_are_counted(tmp_path):
    path = _write(tmp_path, "c.cklb", json.dumps({"stigs": [{"rules": [{}, {}, {"a": [1, 2]}]}]}))
    # 5 objects, 3 arrays, 3 commas
    assert measure(path, kind="json").elements == 11
    assert measure(path, kind="").elements == 0         # hashed only


def test_a_crowded_start_tag_is_found_even_across_chunks(tmp_path, monkeypatch):
    monkeypatch.setattr(parse_cost, "MAX_TAG_ATTRIBUTES", 8)
    ok = _write(tmp_path, "ok.xml", "<r " + " ".join(f'a{i}="v"' for i in range(8)) + "/>")
    crowded = _write(tmp_path, "crowded.xml", "<r><e " + " ".join(f'a{i}="v"' for i in range(9)) + "/></r>")
    assert not measure(ok, kind="xml").crowded_tag
    assert measure(crowded, kind="xml").crowded_tag
    monkeypatch.setattr(parse_cost, "_CHUNK", 5)
    assert measure(crowded, kind="xml").crowded_tag
    assert not measure(ok, kind="xml").crowded_tag
    # '=' in text, a comment or an end tag is not an attribute
    text = _write(tmp_path, "text.xml", "<r>" + "=" * 50 + "<!-- " + "=" * 50 + " --></r>")
    assert not measure(text, kind="xml").crowded_tag


def test_too_costly_names_what_is_over_the_cap(monkeypatch):
    monkeypatch.setattr(parse_cost, "MAX_FILE_ELEMENTS", 10)
    assert too_costly(parse_cost.ParseCost("d", 10)) == ""
    assert too_costly(parse_cost.ParseCost("d", 11)) == "too many elements to parse safely — not read"
    assert too_costly(parse_cost.ParseCost("d", 1, True)) == (
        "an element has too many attributes to parse safely — not read")


def test_start_tags_are_found_with_any_prefix(tmp_path):
    path = _write(tmp_path, "s.xml", "<cdf:Benchmark>" + " " * 3000 + "<x:TestResult id='r'/></cdf:Benchmark>")
    assert start_tags(path, ("TestResult", "Benchmark")) == {"TestResult", "Benchmark"}
    assert start_tags(path, ("TestResult",)) == {"TestResult"}
    plain = _write(tmp_path, "p.xml", "<Benchmark><title>TestResult and &lt;TestResult&gt;</title></Benchmark>")
    assert start_tags(plain, ("TestResult",)) == set()
    assert start_tags(_write(tmp_path, "e.xml", ""), ("TestResult",)) == set()


@pytest.mark.parametrize("hidden", [
    "<!-- <TestResult> -->", "<![CDATA[<TestResult>]]>", "<?pi <TestResult/> ?>",
    "<!DOCTYPE b [<!ENTITY e '<TestResult>'>]>", "<!-- a > b <TestResult> -->",
])
def test_a_tag_in_a_comment_cdata_instruction_or_doctype_is_not_a_tag(tmp_path, hidden):
    path = _write(tmp_path, "h.xml", hidden + "<Benchmark><TestResultX/></Benchmark>")
    assert start_tags(path, ("TestResult", "Benchmark")) == {"Benchmark"}
    unterminated = _write(tmp_path, "u.xml", "<Benchmark><!-- <TestResult>")
    assert start_tags(unterminated, ("TestResult", "Benchmark")) == {"Benchmark"}


# --- classification refuses what would cost too much, and names it -----------------------------

def test_a_crowded_file_is_named_and_not_routed(tmp_path, monkeypatch):
    monkeypatch.setattr(parse_cost, "MAX_TAG_ATTRIBUTES", 8)
    crowded = _write(tmp_path, "crowded.xml", "<Benchmark " + " ".join(f'a{i}="v"' for i in range(9)) + "/>")
    c = classify_inputs([], [crowded], tmp_path / "x")
    assert c.reference_xml == []
    assert c.warnings == ["crowded.xml: an element has too many attributes to parse safely — not read"]


def test_a_checklist_with_too_many_values_is_named_and_not_routed(tmp_path, monkeypatch):
    monkeypatch.setattr(parse_cost, "MAX_FILE_ELEMENTS", 100)
    big = _write(tmp_path, "big.cklb", json.dumps({"stigs": [{"rules": [{} for _ in range(100)]}]}))
    for results, references in (([big], []), ([], [big])):
        c = classify_inputs(results, references, tmp_path / "x")
        assert (c.self_contained, c.reference_cklb) == ([], [])
        assert c.warnings == ["big.cklb: too many elements to parse safely — not read"]


def test_refusals_past_the_first_five_are_counted(tmp_path, monkeypatch):
    monkeypatch.setattr(parse_cost, "MAX_FILE_ELEMENTS", 2)
    files = [_write(tmp_path, f"f{n}.xml", f"<Benchmark n='{n}'><a/><b/></Benchmark>") for n in range(7)]
    c = classify_inputs([], files, tmp_path / "x")
    assert c.reference_xml == []
    assert c.warnings == [f"f{n}.xml: too many elements to parse safely — not read" for n in range(5)] + [
        "… and 2 more file(s) too costly to parse safely — not read"]


def test_once_the_run_budget_is_spent_no_later_file_is_read(tmp_path, monkeypatch):
    monkeypatch.setattr(parse_cost, "MAX_RUN_ELEMENTS", 140)    # 124, then 69 or 3 do not fit
    small = _write(tmp_path, "small.xml", "<Benchmark><a/></Benchmark>")     # 2 elements, would fit
    c = classify_inputs([FIX / "scc_embedded_results.xml"], [FIX / "manual_stig_win11.xml", small], tmp_path / "x")
    assert [p.name for p in c.xccdf_results] == ["scc_embedded_results.xml"] and c.reference_xml == []
    over = ("not read — the parse limit for one run was reached; any scan results or STIG references "
            "in it are missing from this report")
    assert c.warnings == [f"manual_stig_win11.xml: {over}", f"small.xml: {over}"]


def test_files_refused_in_an_archive_are_named_and_the_archive_is_not_called_empty(tmp_path, monkeypatch):
    import zipfile
    monkeypatch.setattr(parse_cost, "MAX_FILE_ELEMENTS", 2)
    z = tmp_path / "bundle.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for n in range(7):
            zf.writestr(f"f{n}.xml", f"<Benchmark n='{n}'><a/><b/></Benchmark>")
    c = classify_inputs([], [z], tmp_path / "x")
    assert c.reference_xml == []
    assert c.warnings == [f"f{n}.xml: too many elements to parse safely — not read" for n in range(5)] + [
        "… and 2 more file(s) too costly to parse safely — not read"]


def test_reference_content_has_its_own_budget(tmp_path, monkeypatch):
    size = (FIX / "manual_stig_win11.xml").stat().st_size
    monkeypatch.setattr(parse_cost, "MAX_RUN_REFERENCE_BYTES", size + 10)
    second = _write(tmp_path, "second.xml", "<Benchmark id='b'><Group id='V-1'/></Benchmark>")
    c = classify_inputs([FIX / "scc_embedded_results.xml"], [FIX / "manual_stig_win11.xml", second],
                        tmp_path / "x")
    assert [p.name for p in c.reference_xml] == ["manual_stig_win11.xml"]
    assert [p.name for p in c.xccdf_results] == ["scc_embedded_results.xml"]     # results are not charged
    assert c.warnings == ["second.xml: not read — the limit on STIG reference content for one run was reached; "
                          "any rules in it are missing from this report"]


# --- attributes are counted as libxml2 reads them -------------------------------------------------

def test_a_gt_inside_attribute_values_does_not_hide_a_crowded_tag(tmp_path, monkeypatch):
    # '>' is allowed in an attribute value: the tag does not end there.
    for quote in ('"', "'"):
        values = " ".join(f"a{i}={quote}>{quote}" for i in range(65))
        path = _write(tmp_path, "gt.xml", f"<TestResult><x {values}/></TestResult>")
        assert measure(path, kind="xml").crowded_tag, quote
    spaced = " ".join(f'a{i} =\n ">"' for i in range(65))          # whitespace around '=' too
    assert measure(_write(tmp_path, "sp.xml", f"<r><x {spaced}/></r>"), kind="xml").crowded_tag
    fine = " ".join(f'a{i}=">"' for i in range(64))
    assert not measure(_write(tmp_path, "ok.xml", f"<r><x {fine}/></r>"), kind="xml").crowded_tag


def test_a_crowded_tag_longer_than_a_chunk_is_found(tmp_path, monkeypatch):
    monkeypatch.setattr(parse_cost, "_CHUNK", 64)
    values = " ".join(f'attribute_number_{i}=">{"v" * 40}"' for i in range(80))
    assert measure(_write(tmp_path, "long.xml", f"<r>{'x' * 50}<x {values}/></r>"), kind="xml").crowded_tag


def test_attributes_are_charged_to_the_element_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(parse_cost, "MAX_FILE_ELEMENTS", 1000)
    unit = "<a " + " ".join(f'b{j}=""' for j in range(60)) + "/>"
    path = _write(tmp_path, "flat.xml", "<TestResult>" + unit * 20 + "</TestResult>")   # 21 elements, 1,200 attributes
    cost = measure(path, kind="xml")
    assert cost.elements == 21 + 1200 and not cost.crowded_tag
    assert too_costly(cost) == "too many elements to parse safely — not read"


@pytest.mark.parametrize("name", sorted(p.name for p in FIX.iterdir() if p.suffix in (".xml", ".nessus", ".cklb")))
def test_no_fixture_is_too_costly(name):
    cost = measure(FIX / name, kind="json" if name.endswith(".cklb") else "xml")
    assert too_costly(cost) == ""



def test_a_namespace_prefix_of_any_length_is_read(tmp_path):
    for length in (1, 99, 100, 150, 5000):
        prefix = "p" * length
        path = _write(tmp_path, "p.xml", f"<{prefix}:Benchmark><{prefix}:TestResult/></{prefix}:Benchmark>")
        assert start_tags(path, ("TestResult", "Benchmark")) == {"TestResult", "Benchmark"}, length
