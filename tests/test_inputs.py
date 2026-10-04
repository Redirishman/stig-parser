"""classify_inputs: uploads are routed by what they contain, not by the slot they came from."""
import io
import zipfile
from pathlib import Path

import pytest

import app.utils.zip_extract as zip_extract
from app.core.inputs import classify_inputs

FIX = Path(__file__).parent / "fixtures"


def _kind(tmp_path: Path, path: Path) -> str:
    """What classify_inputs takes *path* for: results and benchmarks are routed by what they
    contain, whichever slot they come in; anything else ("other") keeps its slot or is named."""
    import tempfile
    work = Path(tempfile.mkdtemp(dir=tmp_path))
    as_results = classify_inputs([path], [], work / "r")
    as_reference = classify_inputs([], [path], work / "f")
    if as_results.xccdf_results and as_reference.xccdf_results:
        return "results"
    if as_results.reference_xml and as_reference.reference_xml:
        return "benchmark"
    return "other"


def test_sniff_xml(tmp_path):
    assert _kind(tmp_path, FIX / "scc_embedded_results.xml") == "results"      # Benchmark root, TestResult nested
    assert _kind(tmp_path, FIX / "evaluate_stig_results.xml") == "results"
    assert _kind(tmp_path, FIX / "manual_stig_win11.xml") == "benchmark"
    assert _kind(tmp_path, FIX / "scap_datastream_win11.xml") == "benchmark"
    assert _kind(tmp_path, FIX / "legacy_checklist.ckl.xml") == "other"


def test_sniff_xml_invalid_is_routed_by_its_tags(tmp_path):
    # Nothing is parsed to classify: a file that is not well-formed goes where its
    # tags say, and the parser that reads it names it (see test_reference_pipeline).
    bad = tmp_path / "bad.xml"
    bad.write_text("<Benchmark", encoding="utf-8")
    assert _kind(tmp_path, bad) == "benchmark"
    bad.write_text("<root><a></root>", encoding="utf-8")
    assert _kind(tmp_path, bad) == "other"


def test_sniff_xml_missing_file_is_other(tmp_path):
    assert _kind(tmp_path, tmp_path / "gone.xml") == "other"


def test_sniff_xml_without_a_namespace(tmp_path):
    bare = tmp_path / "bare.xml"
    bare.write_text("<Benchmark id='x'><Group id='V-1'/></Benchmark>", encoding="utf-8")
    assert _kind(tmp_path, bare) == "benchmark"
    bare.write_text("<wrapper><Benchmark id='x'/><TestResult id='r'/></wrapper>", encoding="utf-8")
    assert _kind(tmp_path, bare) == "results"


def test_sniff_xml_keeps_the_parser_limits_on_an_upload(tmp_path):
    # The hardened parser refuses a document nested deeper than libxml2 allows. Classifying
    # it parses nothing, and the parser that reads it keeps that limit and names the file.
    from app.core.pipeline import parse_stage
    deep = tmp_path / "deep.xml"
    deep.write_text("<Benchmark>" + "<a>" * 300 + "<TestResult/>" + "</a>" * 300 + "</Benchmark>", encoding="utf-8")
    assert _kind(tmp_path, deep) == "results"
    result = parse_stage([FIX / "scc_embedded_results.xml", deep], [], tmp_path / "run")
    assert any(w.startswith("Could not parse results file: deep.xml — invalid XML") for w in result.warnings)


def test_sniff_xml_does_not_resolve_entities(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("<TestResult/>", encoding="utf-8")
    xxe = tmp_path / "xxe.xml"
    xxe.write_text(
        f'<!DOCTYPE Benchmark [<!ENTITY x SYSTEM "{secret.as_uri()}">]><Benchmark>&x;</Benchmark>',
        encoding="utf-8")
    assert _kind(tmp_path, xxe) == "benchmark"       # the external entity is never read, so no TestResult appears


def test_a_benchmark_in_the_results_list_is_routed_to_references(tmp_path):
    c = classify_inputs([FIX / "evaluate_stig_results.xml", FIX / "manual_stig_server2022.xml"], [], tmp_path)
    assert [p.name for p in c.xccdf_results] == ["evaluate_stig_results.xml"]
    assert [p.name for p in c.reference_xml] == ["manual_stig_server2022.xml"]


def test_results_in_the_reference_list_are_routed_to_results(tmp_path):
    c = classify_inputs([], [FIX / "scc_embedded_results.xml"], tmp_path)
    assert [p.name for p in c.xccdf_results] == ["scc_embedded_results.xml"]
    assert c.reference_xml == []


def test_cklb_is_results_unless_it_came_through_the_reference_list(tmp_path):
    cklb = FIX / "evaluate_stig_checklist.cklb"
    as_results = classify_inputs([cklb], [], tmp_path)
    assert as_results.self_contained == [cklb] and as_results.reference_cklb == []
    as_reference = classify_inputs([], [cklb], tmp_path)
    assert as_reference.self_contained == [] and as_reference.reference_cklb == [cklb]


def test_nessus_and_unrecognised_xml_keep_their_list(tmp_path):
    unknown = tmp_path / "unknown.xml"
    unknown.write_text("<report><row/></report>", encoding="utf-8")
    c = classify_inputs([FIX / "nessus_compliance.nessus", unknown], [], tmp_path)
    assert [p.name for p in c.self_contained] == ["nessus_compliance.nessus"]
    assert [p.name for p in c.xccdf_results] == ["unknown.xml"]   # the results parser reports it
    assert c.warnings == []


def test_unrecognised_xml_in_the_reference_list_stays_a_reference(tmp_path):
    # The benchmark parser reports it; it must not turn up as a results file.
    unknown = tmp_path / "unknown.xml"
    unknown.write_text("<report><row/></report>", encoding="utf-8")
    c = classify_inputs([], [unknown], tmp_path)
    assert [p.name for p in c.reference_xml] == ["unknown.xml"] and c.xccdf_results == []


# --- loose SCAP support files: recognised as in an archive, named once per run ---------------

SUPPORT = "SCAP support file(s) (OVAL, CPE, OCIL, stylesheets) were not used: "


def _support_files(directory: Path) -> list[Path]:
    """SCAP support content as DISA's bundles hold it, recognised by name and by document element."""
    directory.mkdir(parents=True, exist_ok=True)
    files = {
        "U_X_V1R1_STIG_SCAP_1-2_Benchmark-oval.xml": "<oval_definitions",     # by name: never read
        "definitions.xml": "<oval_definitions xmlns='http://oval.mitre.org/XMLSchema/oval-definitions-5'/>",
        "dictionary.xml": "<cpe-list xmlns='http://cpe.mitre.org/dictionary/2.0'/>",
        "questions.xml": "<ocil xmlns='http://scap.nist.gov/schema/ocil/2.0'/>",
        "transform.xml": "<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform'/>",
    }
    for name, text in files.items():
        (directory / name).write_text(text, encoding="utf-8")
    return [directory / name for name in files]


@pytest.mark.parametrize("slot", ["results", "reference"])
def test_loose_scap_support_files_are_named_in_one_line_and_not_routed(tmp_path, slot):
    support = _support_files(tmp_path / "bundle")
    paths = [FIX / "manual_stig_win11.xml", *support]
    c = classify_inputs(paths, [], tmp_path / "x") if slot == "results" else classify_inputs([], paths, tmp_path / "x")
    assert [p.name for p in c.reference_xml] == ["manual_stig_win11.xml"]
    assert (c.xccdf_results, c.self_contained, c.reference_cklb) == ([], [], [])
    assert c.warnings == [
        "5 " + SUPPORT + "U_X_V1R1_STIG_SCAP_1-2_Benchmark-oval.xml, definitions.xml, dictionary.xml, "
        "questions.xml, transform.xml"
    ]


def test_the_list_of_loose_scap_support_files_is_capped_and_covers_both_slots(tmp_path):
    support = []
    for n in range(1, 8):
        support.append(tmp_path / f"oval{n}.xml")
        support[-1].write_text(f"<oval_definitions n='{n}'/>", encoding="utf-8")
    c = classify_inputs(support[:4], support[4:], tmp_path / "x")
    assert c.warnings == ["7 " + SUPPORT + "oval1.xml, oval2.xml, oval3.xml, oval4.xml, oval5.xml …"]
    assert (c.xccdf_results, c.reference_xml) == ([], [])


def test_a_nessus_scan_in_the_reference_list_is_results(tmp_path):
    c = classify_inputs([], [FIX / "nessus_compliance.nessus"], tmp_path)
    assert [p.name for p in c.self_contained] == ["nessus_compliance.nessus"]
    assert c.reference_xml == [] and c.reference_cklb == []


def test_suffixes_are_matched_whatever_their_case(tmp_path):
    upper = tmp_path / "LIST.CKLB"
    upper.write_bytes((FIX / "evaluate_stig_checklist.cklb").read_bytes())
    assert classify_inputs([upper], [], tmp_path / "x").self_contained == [upper]
    assert classify_inputs([], [upper], tmp_path / "x").reference_cklb == [upper]


def test_reference_zip_is_expanded_and_typed(tmp_path):
    z = tmp_path / "U_MS_Windows_11_V2R9_STIG.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.write(FIX / "manual_stig_win11.xml", "U_MS_Windows_11_V2R9_Manual_STIG/U_MS_Windows_11_STIG_V2R9_Manual-xccdf.xml")
        zf.write(FIX / "scap_datastream_win11.xml", "U_MS_Windows_11_V2R8_STIG_SCAP_1-3_Benchmark.xml")
        zf.write(FIX / "evaluate_stig_checklist.cklb", "checklist.cklb")
        zf.writestr("readme.txt", "ignored")
    c = classify_inputs([], [z], tmp_path / "x")
    assert sorted(c.name_of(p) for p in c.reference_xml) == [
        "U_MS_Windows_11_STIG_V2R9_Manual-xccdf.xml", "U_MS_Windows_11_V2R8_STIG_SCAP_1-3_Benchmark.xml"]
    assert [c.name_of(p) for p in c.reference_cklb] == ["checklist.cklb"]
    assert c.warnings == []


def test_a_benchmark_in_a_zip_in_the_results_list_is_a_reference(tmp_path):
    z = tmp_path / "U_MS_Windows_11_V2R9_STIG.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.write(FIX / "manual_stig_win11.xml", "U_MS_Windows_11_STIG_V2R9_Manual-xccdf.xml")
    c = classify_inputs([FIX / "scc_embedded_results.xml", z], [], tmp_path / "x")
    assert [p.name for p in c.xccdf_results] == ["scc_embedded_results.xml"]
    assert [c.name_of(p) for p in c.reference_xml] == ["U_MS_Windows_11_STIG_V2R9_Manual-xccdf.xml"]
    assert c.warnings == []


# --- a ZIP is a folder: its members are routed like loose files in the same slot ----------

def _zip(path, members):
    """members: archive name -> fixture Path, or text."""
    with zipfile.ZipFile(path, "w") as zf:
        for name, content in members.items():
            if isinstance(content, Path):
                zf.write(content, name)
            else:
                zf.writestr(name, content)
    return path


def _names(c, paths):
    """Display names: an archive member is extracted under a generated file name."""
    return sorted(c.name_of(p) for p in paths)


def test_a_checklist_in_a_zip_in_the_results_list_is_results(tmp_path):
    z = _zip(tmp_path / "host_checklists.zip", {"WIN-SERVER-04.cklb": FIX / "evaluate_stig_checklist.cklb"})
    c = classify_inputs([FIX / "scc_embedded_results.xml", z], [], tmp_path / "x")
    assert _names(c, c.self_contained) == ["WIN-SERVER-04.cklb"] and c.reference_cklb == []
    assert c.warnings == []


def test_a_checklist_in_a_zip_in_the_reference_list_stays_a_reference(tmp_path):
    z = _zip(tmp_path / "references.zip", {"WIN-SERVER-04.cklb": FIX / "evaluate_stig_checklist.cklb"})
    c = classify_inputs([FIX / "scc_embedded_results.xml"], [z], tmp_path / "x")
    assert _names(c, c.reference_cklb) == ["WIN-SERVER-04.cklb"] and c.self_contained == []


@pytest.mark.parametrize("slot", ["results", "reference"])
def test_results_and_a_manual_stig_in_one_zip_are_both_used(tmp_path, slot):
    z = _zip(tmp_path / "scan_folder.zip", {
        "scans/WKSTN-01_SCC-5.14_XCCDF-Results_MS_Windows_11.xml": FIX / "scc_embedded_results.xml",
        "stig/U_MS_Windows_11_STIG_V2R9_Manual-xccdf.xml": FIX / "manual_stig_win11.xml",
        "scans/host.nessus": FIX / "nessus_compliance.nessus",
    })
    c = classify_inputs([z], [], tmp_path / "x") if slot == "results" else classify_inputs([], [z], tmp_path / "x")
    assert _names(c, c.xccdf_results) == ["WKSTN-01_SCC-5.14_XCCDF-Results_MS_Windows_11.xml"]
    assert _names(c, c.reference_xml) == ["U_MS_Windows_11_STIG_V2R9_Manual-xccdf.xml"]
    assert _names(c, c.self_contained) == ["host.nessus"]              # a .nessus scan is results in either slot
    assert c.warnings == []


def test_a_disa_style_zip_gives_its_manual_stig_and_no_warnings(tmp_path):
    z = _zip(tmp_path / "U_MS_Windows_11_V2R9_STIG.zip", {
        "U_MS_Windows_11_V2R9_Manual_STIG/U_MS_Windows_11_STIG_V2R9_Manual-xccdf.xml": FIX / "manual_stig_win11.xml",
        "U_MS_Windows_11_V2R9_Manual_STIG/STIG_unclass.xsl": "<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform'/>",
        "U_MS_Windows_11_V2R9_Manual_STIG/DoD-DISA-logos-as-JPEG.jpg": "not really an image",
        "U_MS_Windows_11_V2R9_Manual_STIG/logo.png": "not really an image",
        "U_MS_Windows_11_V2R9_Overview.pdf": "%PDF",
    })
    c = classify_inputs([], [z], tmp_path / "x")
    assert _names(c, c.reference_xml) == ["U_MS_Windows_11_STIG_V2R9_Manual-xccdf.xml"]
    assert (c.xccdf_results, c.self_contained, c.reference_cklb, c.warnings) == ([], [], [], [])


@pytest.mark.parametrize("slot", ["results", "reference"])
def test_a_zip_of_ancillary_files_only_gets_one_warning(tmp_path, slot):
    z = _zip(tmp_path / "leftovers.zip", {
        "U_X_V1R1_STIG_SCAP_1-2_Benchmark-oval.xml": "<oval_definitions/>",
        "definitions.xml": "<oval_definitions/>",
        "dictionary.xml": "<cpe-list/>",
        "STIG_unclass.xsl": "<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform'/>",
        "logo.png": "x", "Overview.pdf": "%PDF", "readme.txt": "text",
    })
    c = classify_inputs([z], [], tmp_path / "x") if slot == "results" else classify_inputs([], [z], tmp_path / "x")
    assert (c.xccdf_results, c.self_contained, c.reference_xml, c.reference_cklb) == ([], [], [], [])
    assert c.warnings == [
        "No scan results or STIG references found in leftovers.zip (expected XCCDF results, "
        "a benchmark *xccdf.xml or *_Benchmark.xml, .cklb or .nessus files inside the zip)"
    ]


def test_ancillary_members_beside_useful_ones_are_ignored_without_a_warning(tmp_path):
    z = _zip(tmp_path / "bundle.zip", {
        "U_MS_Windows_11_STIG_V2R9_Manual-xccdf.xml": FIX / "manual_stig_win11.xml",
        "U_MS_Windows_11_V2R8_STIG_SCAP_1-2_Benchmark-oval.xml": "<oval_definitions/>",
        "U_MS_Windows_11_V2R8_STIG_SCAP_1-2_Benchmark-cpe-oval.xml": "<oval_definitions/>",
        "U_MS_Windows_11_V2R8_STIG_SCAP_1-2_Benchmark-cpe-dictionary.xml": "<cpe-list/>",
        "U_MS_Windows_11_V2R8_STIG_SCAP_1-2_Benchmark-ocil.xml": "<ocil/>",
        "U_MS_Windows_11_V2R8_STIG_SCAP_1-2_Benchmark-xccdf.xml": FIX / "scap_datastream_win11.xml",
        "STIG_unclass.xsl": "<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform'/>",
        "DoD-DISA-logos-as-JPEG.jpg": "x", "U_MS_Windows_11_V2R9_Overview.pdf": "%PDF",
    })
    c = classify_inputs([], [z], tmp_path / "x")
    assert _names(c, c.reference_xml) == ["U_MS_Windows_11_STIG_V2R9_Manual-xccdf.xml",
                                          "U_MS_Windows_11_V2R8_STIG_SCAP_1-2_Benchmark-xccdf.xml"]
    assert c.warnings == [] and c.xccdf_results == []


# --- XML in an archive that is neither results nor a reference is named ----------------------

@pytest.mark.parametrize("slot", ["results", "reference"])
def test_unrecognised_xml_members_are_named_once_per_archive(tmp_path, slot):
    members = {"U_Manual-xccdf.xml": FIX / "manual_stig_win11.xml", "definitions.xml": "<oval_definitions/>"}
    members.update({f"report{n}.xml": f"<report n='{n}'/>" for n in range(1, 4)})
    z = _zip(tmp_path / "bundle.zip", members)
    c = classify_inputs([z], [], tmp_path / "x") if slot == "results" else classify_inputs([], [z], tmp_path / "x")
    assert _names(c, c.reference_xml) == ["U_Manual-xccdf.xml"] and c.xccdf_results == []
    assert c.warnings == ["bundle.zip: 3 XML file(s) were not recognised as scan results or STIG references: "
                          "report1.xml, report2.xml, report3.xml"]


def test_the_list_of_unrecognised_members_is_capped(tmp_path):
    z = _zip(tmp_path / "bundle.zip", {f"report{n}.xml": f"<report n='{n}'/>" for n in range(1, 9)})
    c = classify_inputs([z], [], tmp_path / "x")
    assert c.warnings == ["bundle.zip: 8 XML file(s) were not recognised as scan results or STIG references: "
                          "report1.xml, report2.xml, report3.xml, report4.xml, report5.xml …"]


# --- a legacy STIG Viewer .ckl is named as unsupported, loose or zipped ----------------------

CKL = "STIG Viewer .ckl checklists are not supported — save it as .cklb in STIG Viewer 3 and upload that"


@pytest.mark.parametrize("slot", ["results", "reference"])
def test_a_loose_legacy_checklist_is_named_as_unsupported_and_not_routed(tmp_path, slot):
    by_suffix = _copy(FIX / "legacy_checklist.ckl.xml", tmp_path / "OLD-HOST.ckl")
    upper = tmp_path / "OTHER.CKL"
    upper.write_text("not even XML", encoding="utf-8")
    paths = [FIX / "legacy_checklist.ckl.xml", by_suffix, upper, FIX / "scc_embedded_results.xml"]
    c = classify_inputs(paths, [], tmp_path / "x") if slot == "results" else classify_inputs([], paths, tmp_path / "x")
    assert c.warnings == [f"legacy_checklist.ckl.xml: {CKL}",
                          "OLD-HOST.ckl: identical to legacy_checklist.ckl.xml — read once",
                          f"OTHER.CKL: {CKL}"]
    assert _names(c, c.xccdf_results) == ["scc_embedded_results.xml"]
    assert (c.self_contained, c.reference_xml, c.reference_cklb) == ([], [], [])


@pytest.mark.parametrize("slot", ["results", "reference"])
def test_legacy_checklists_in_a_zip_are_named_as_unsupported(tmp_path, slot):
    z = _zip(tmp_path / "session.zip", {
        "scans/WKSTN-01_results.xml": FIX / "scc_embedded_results.xml",
        "checklists/legacy_checklist.ckl.xml": FIX / "legacy_checklist.ckl.xml",
        "checklists/OLD-HOST.ckl": FIX / "legacy_checklist.ckl.xml",
    })
    c = classify_inputs([z], [], tmp_path / "x") if slot == "results" else classify_inputs([], [z], tmp_path / "x")
    assert _names(c, c.xccdf_results) == ["WKSTN-01_results.xml"]
    assert c.warnings == [f"legacy_checklist.ckl.xml: {CKL}", f"OLD-HOST.ckl: {CKL}"]


def test_a_zip_of_legacy_checklists_only_is_not_also_called_empty_and_the_list_is_capped(tmp_path):
    z = _zip(tmp_path / "old.zip", {f"HOST-{n}.ckl": f"<CHECKLIST n='{n}'/>" for n in range(1, 9)})
    c = classify_inputs([z], [], tmp_path / "x")
    assert c.warnings == [f"HOST-{n}.ckl: {CKL}" for n in range(1, 6)] + [
        "old.zip: … and 3 more .ckl checklist(s) not supported"]


def test_sniff_xml_still_calls_a_legacy_checklist_other(tmp_path):
    assert _kind(tmp_path, FIX / "legacy_checklist.ckl.xml") == "other"
@pytest.mark.parametrize("slot,expected", [("results", "xccdf_results"), ("reference", "xccdf_results")])
def test_a_member_that_is_not_well_formed_is_routed_like_a_loose_file_so_it_is_reported(tmp_path, slot, expected):
    z = _zip(tmp_path / "scan.zip", {"broken.xml": "<TestResult><unclosed>"})
    c = classify_inputs([z], [], tmp_path / "x") if slot == "results" else classify_inputs([], [z], tmp_path / "x")
    assert _names(c, getattr(c, expected)) == ["broken.xml"] and c.warnings == []


def test_a_wrapper_zip_is_still_unwrapped(tmp_path):
    inner = _zip(tmp_path / "inner.zip", {"U_MS_Windows_11_STIG_V2R9_Manual-xccdf.xml": FIX / "manual_stig_win11.xml"})
    wrapper = tmp_path / "wrapper.zip"
    with zipfile.ZipFile(wrapper, "w") as zf:
        zf.write(inner, "U_MS_Windows_11_V2R9_STIG.zip")
    c = classify_inputs([], [wrapper], tmp_path / "x")
    assert _names(c, c.reference_xml) == ["U_MS_Windows_11_STIG_V2R9_Manual-xccdf.xml"] and c.warnings == []


def test_an_upper_case_zip_suffix_and_a_long_zip_name(tmp_path):
    z = _zip(tmp_path / "STIG.ZIP", {"Manual-xccdf.xml": FIX / "manual_stig_win11.xml"})
    c = classify_inputs([], [z], tmp_path / "x")
    assert _names(c, c.reference_xml) == ["Manual-xccdf.xml"]
    long_name = _zip(tmp_path / ("n" * 150 + ".zip"), {"readme.txt": "no xml"})
    warning, = classify_inputs([], [long_name], tmp_path / "y").warnings
    assert "n" * 150 + ".zip" in warning and len(warning) < 400      # shown whole: a file name is at most 255


def test_a_zip_that_is_not_a_zip_gets_the_warning(tmp_path):
    bad = tmp_path / "not-a-zip.zip"
    bad.write_bytes(b"this is not a zip file")
    c = classify_inputs([bad], [], tmp_path / "x")
    assert c.warnings == ["not-a-zip.zip: not a readable ZIP — not read"] and c.xccdf_results == []


def test_display_names_of_archive_members(tmp_path):
    z = _zip(tmp_path / "scans.zip", {"scans/rhel9_results_2026-01-15T10:00:00.xml": FIX / "openscap_results.xml",
                                      "refs/Manual-xccdf.xml": FIX / "manual_stig_win11.xml"})
    loose = FIX / "scc_embedded_results.xml"
    c = classify_inputs([loose, z], [], tmp_path / "x")
    assert [c.name_of(p) for p in c.xccdf_results] == ["scc_embedded_results.xml", "rhel9_results_2026-01-15T10:00:00.xml"]
    assert [c.name_of(p) for p in c.reference_xml] == ["Manual-xccdf.xml"]
    assert c.xccdf_results[1].name != "rhel9_results_2026-01-15T10:00:00.xml" and c.xccdf_results[1].is_file()
    assert c.warnings == []


def test_skipped_members_are_named_five_at_most_and_the_archive_is_not_called_empty(tmp_path):
    z = tmp_path / "damaged.zip"
    marker = b"MARKER-" + bytes(range(256))
    with zipfile.ZipFile(z, "w", zipfile.ZIP_STORED) as zf:
        for n in range(1, 8):
            zf.writestr(f"bad{n}.xml", b"<TestResult><!--" + marker + bytes([n]) * 8 + b"--></TestResult>")
    data = bytearray(z.read_bytes())
    at = data.find(marker)
    while at != -1:
        data[at + 20] ^= 0xFF
        at = data.find(marker, at + 1)
    z.write_bytes(bytes(data))
    c = classify_inputs([z], [], tmp_path / "x")
    assert c.warnings == [f"damaged.zip: could not read bad{n}.xml: Bad CRC-32 for file 'bad{n}.xml' — skipped"
                          for n in range(1, 6)] + [
        "damaged.zip: … and 2 more skipped"]
    assert c.xccdf_results == []


def test_a_flood_of_too_deep_zips_is_named_five_times_then_counted(tmp_path):
    def zipped(members: dict) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            for name, data in members.items():
                zf.writestr(name, data)
        return buffer.getvalue()

    flood = zipped({f"x{n:02d}.zip": b"" for n in range(1, 41)})       # at the depth limit: never opened
    z = _zip(tmp_path / "outer.zip", {"scan.xml": FIX / "scc_embedded_results.xml",
                                      "wrapped.zip": zipped({"inner.zip": flood})})
    c = classify_inputs([z], [], tmp_path / "x")
    assert c.warnings == [f"outer.zip: x{n:02d}.zip is nested more than 2 ZIPs deep — skipped" for n in range(1, 6)] + [
        "outer.zip: … and 35 more skipped"]
    assert _names(c, c.xccdf_results) == ["scan.xml"]


def test_zip_without_reference_content_warns(tmp_path):
    z = tmp_path / "empty.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("readme.txt", "nothing")
    c = classify_inputs([], [z], tmp_path / "x")
    assert len(c.warnings) == 1 and "empty.zip" in c.warnings[0]
    in_results = classify_inputs([z], [], tmp_path / "y")
    assert len(in_results.warnings) == 1 and "empty.zip" in in_results.warnings[0]
    assert in_results.xccdf_results == []


# --- a file supplied twice is read once ---------------------------------------------------

def _copy(source: Path, target: Path) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(source.read_bytes())
    return target


def test_the_same_path_in_both_slots_is_routed_once_without_a_warning(tmp_path):
    scc = FIX / "scc_embedded_results.xml"
    c = classify_inputs([scc], [scc], tmp_path / "x")
    assert c.xccdf_results == [scc] and c.reference_xml == [] and c.warnings == []
    nessus = FIX / "nessus_compliance.nessus"
    c = classify_inputs([nessus, nessus], [nessus], tmp_path / "x")
    assert c.self_contained == [nessus] and c.warnings == []


def test_the_same_path_spelled_two_ways_is_one_file(tmp_path):
    scc = _copy(FIX / "scc_embedded_results.xml", tmp_path / "scans" / "scc.xml")
    other_spelling = tmp_path / "scans" / ".." / "scans" / "scc.xml"
    c = classify_inputs([scc, other_spelling], [], tmp_path / "x")
    assert c.xccdf_results == [scc] and c.warnings == []


def test_identical_content_under_another_name_is_read_once_and_said_to_be(tmp_path):
    first = _copy(FIX / "scc_embedded_results.xml", tmp_path / "a" / "host.xml")
    second = _copy(FIX / "scc_embedded_results.xml", tmp_path / "b" / "host (copy).xml")
    c = classify_inputs([first, second], [], tmp_path / "x")
    assert c.xccdf_results == [first]
    assert c.warnings == ["host (copy).xml: identical to host.xml — read once"]


def test_the_first_occurrence_wins_and_the_results_slot_comes_first(tmp_path):
    as_reference = _copy(FIX / "evaluate_stig_checklist.cklb", tmp_path / "refs" / "reference.cklb")
    as_results = _copy(FIX / "evaluate_stig_checklist.cklb", tmp_path / "scans" / "host.cklb")
    c = classify_inputs([as_results], [as_reference], tmp_path / "x")
    assert c.self_contained == [as_results] and c.reference_cklb == []
    assert c.warnings == ["reference.cklb: identical to host.cklb — read once"]


def test_a_reference_supplied_twice_is_one_reference(tmp_path):
    manual = FIX / "manual_stig_win11.xml"
    copy = _copy(manual, tmp_path / "again.xml")
    c = classify_inputs([], [manual, manual, copy], tmp_path / "x")
    assert c.reference_xml == [manual]
    assert c.warnings == ["again.xml: identical to manual_stig_win11.xml — read once"]


def test_the_same_zip_twice_is_expanded_once(tmp_path):
    z = _zip(tmp_path / "stig.zip", {"Manual-xccdf.xml": FIX / "manual_stig_win11.xml"})
    c = classify_inputs([z], [z], tmp_path / "x")
    assert _names(c, c.reference_xml) == ["Manual-xccdf.xml"] and c.warnings == []
    copy = _copy(z, tmp_path / "copy.zip")
    c = classify_inputs([], [z, copy], tmp_path / "y")
    assert _names(c, c.reference_xml) == ["Manual-xccdf.xml"]
    assert c.warnings == ["copy.zip: identical to stig.zip — read once"]


def test_a_zip_member_identical_to_a_loose_file_is_read_once_and_the_zip_is_not_called_empty(tmp_path):
    z = _zip(tmp_path / "bundle.zip", {"U_Manual-xccdf.xml": FIX / "manual_stig_win11.xml"})
    c = classify_inputs([], [FIX / "manual_stig_win11.xml", z], tmp_path / "x")
    assert _names(c, c.reference_xml) == ["manual_stig_win11.xml"]
    assert c.warnings == ["U_Manual-xccdf.xml: identical to manual_stig_win11.xml — read once"]


def test_two_identical_members_of_one_zip_are_read_once(tmp_path):
    z = _zip(tmp_path / "bundle.zip", {"a/Manual-xccdf.xml": FIX / "manual_stig_win11.xml",
                                       "b/Manual-xccdf.xml": FIX / "manual_stig_win11.xml"})
    c = classify_inputs([], [z], tmp_path / "x")
    assert _names(c, c.reference_xml) == ["bundle.zip/a/Manual-xccdf.xml"]
    assert c.warnings == ["bundle.zip/b/Manual-xccdf.xml: identical to bundle.zip/a/Manual-xccdf.xml — read once"]


def test_different_files_of_the_same_size_are_both_read(tmp_path):
    one, two = tmp_path / "one.xml", tmp_path / "two.xml"
    one.write_text("<TestResult id='a'/>", encoding="utf-8")
    two.write_text("<TestResult id='b'/>", encoding="utf-8")
    c = classify_inputs([one, two], [], tmp_path / "x")
    assert c.xccdf_results == [one, two] and c.warnings == []


@pytest.mark.parametrize("slot", ["results", "reference"])
def test_a_file_that_cannot_be_read_is_named_and_left_out(tmp_path, slot):
    gone = tmp_path / "gone.xml"
    folder = tmp_path / "a_folder.cklb"
    folder.mkdir()
    paths = [gone, gone, folder, FIX / "scc_embedded_results.xml"]
    c = classify_inputs(paths, [], tmp_path / "x") if slot == "results" else classify_inputs([], paths, tmp_path / "x")
    assert c.warnings == ["Could not read file: gone.xml", "Could not read file: a_folder.cklb"]
    assert _names(c, c.xccdf_results) == ["scc_embedded_results.xml"]
    assert (c.self_contained, c.reference_xml, c.reference_cklb) == ([], [], [])


def test_the_names_in_the_duplicate_warning_are_escaped_and_bounded(tmp_path):
    first = _copy(FIX / "manual_stig_win11.xml", tmp_path / ("a" * 150 + ".xml"))
    second = _copy(FIX / "manual_stig_win11.xml", tmp_path / ("b" * 150 + ".xml"))
    warning, = classify_inputs([], [first, second], tmp_path / "x").warnings
    assert warning == f"{'b' * 150}.xml: identical to {'a' * 150}.xml — read once"
    line_break = _copy(FIX / "scc_embedded_results.xml", tmp_path / "ok.xml")
    c = classify_inputs([line_break], [], tmp_path / "y")
    assert c.name_of(Path("a\nb.xml")) == "a\\nb.xml"              # escaped: a name cannot forge a line


def test_two_identical_files_with_the_same_one_letter_name_are_still_one_file(tmp_path):
    # A one-character string is a shared object in CPython: the check must not rest on identity.
    first = _copy(FIX / "scc_embedded_results.xml", tmp_path / "1" / "a")
    second = _copy(FIX / "scc_embedded_results.xml", tmp_path / "2" / "a")
    c = classify_inputs([first, second], [], tmp_path / "x")
    assert c.xccdf_results == [first]
    assert c.warnings == ["a (2): identical to a — read once"]


# --- every display name is unique in the run and names something the operator supplied ------------

def _zero_results(path: Path, host: str) -> Path:
    path.write_text(f"<TestResult><target>{host}</target><target-address>10.0.0.9</target-address></TestResult>",
                    encoding="utf-8")
    return path


def test_a_loose_file_and_two_members_with_its_name_are_each_named_for_what_they_are(tmp_path):
    loose = _zero_results(tmp_path / "results.xml", "HOST-L")
    z = _zip(tmp_path / "more.zip", {"x/results.xml": FIX / "scc_embedded_results.xml",
                                     "y/results.xml": _zero_results(tmp_path / "y.xml", "HOST-Y")})
    c = classify_inputs([loose, z], [], tmp_path / "x")
    assert [c.name_of(p) for p in c.xccdf_results] == ["results.xml", "more.zip/x/results.xml", "more.zip/y/results.xml"]
    assert c.warnings == []


def test_a_member_named_like_a_loose_file_supplied_later_is_named_by_its_archive_too(tmp_path):
    z = _zip(tmp_path / "more.zip", {"x/results.xml": FIX / "scc_embedded_results.xml"})
    loose = _zero_results(tmp_path / "results.xml", "HOST-L")
    c = classify_inputs([z, loose], [], tmp_path / "x")
    assert [c.name_of(p) for p in c.xccdf_results] == ["more.zip/x/results.xml", "results.xml"]


def test_members_with_one_name_in_two_archives_are_named_by_their_archives(tmp_path):
    one = _zip(tmp_path / "one.zip", {"Manual-xccdf.xml": FIX / "manual_stig_win11.xml"})
    two = _zip(tmp_path / "two.zip", {"stig/Manual-xccdf.xml": FIX / "manual_stig_server2022.xml"})
    c = classify_inputs([], [one, two], tmp_path / "x")
    assert [c.name_of(p) for p in c.reference_xml] == ["one.zip/Manual-xccdf.xml", "two.zip/stig/Manual-xccdf.xml"]
    assert c.warnings == []


def test_a_member_of_a_nested_archive_is_named_by_the_archive_the_operator_supplied(tmp_path):
    inner = _zip(tmp_path / "inner.zip", {"Manual-xccdf.xml": FIX / "manual_stig_server2022.xml"})
    z = _zip(tmp_path / "outer.zip", {"Manual-xccdf.xml": FIX / "manual_stig_win11.xml", "wrap/inner.zip": inner})
    c = classify_inputs([], [z], tmp_path / "x")
    assert [c.name_of(p) for p in c.reference_xml] == [
        "outer.zip/Manual-xccdf.xml", "outer.zip/wrap/inner.zip/Manual-xccdf.xml"]


def test_a_long_qualified_name_is_cut_from_the_left_and_escaped(tmp_path):
    deep = "level/" * 60 + "line\nbreak/results.xml"
    z = _zip(tmp_path / "more.zip", {deep: FIX / "scc_embedded_results.xml", "results.xml": FIX / "openscap_results.xml"})
    c = classify_inputs([z], [], tmp_path / "x")
    names = [c.name_of(p) for p in c.xccdf_results]
    assert names[1] == "more.zip/results.xml"
    assert len(names[0]) == 255 and names[0].startswith("…") and names[0].endswith("/line\\nbreak/results.xml")


def test_names_still_equal_are_numbered(tmp_path):
    # An archive may list one path twice; two loose files may share a name.
    with zipfile.ZipFile(tmp_path / "twice.zip", "w") as zf:
        zf.write(FIX / "manual_stig_win11.xml", "Manual-xccdf.xml")
        with pytest.warns(UserWarning):     # zipfile: "Duplicate name"
            zf.write(FIX / "manual_stig_server2022.xml", "Manual-xccdf.xml")
    first = _copy(FIX / "scc_embedded_results.xml", tmp_path / "1" / "scan.xml")
    second = _copy(FIX / "openscap_results.xml", tmp_path / "2" / "scan.xml")
    c = classify_inputs([first, second], [tmp_path / "twice.zip"], tmp_path / "x")
    assert [c.name_of(p) for p in c.xccdf_results] == ["scan.xml", "scan.xml (2)"]
    assert [c.name_of(p) for p in c.reference_xml] == ["twice.zip/Manual-xccdf.xml", "twice.zip/Manual-xccdf.xml (2)"]



# --- an archive is bounded, and other archive formats inside one are named ----------------------

MISSING = "any scan results or STIG references among them are missing from this report"


def test_an_archive_over_the_member_limit_is_read_up_to_it_and_the_rest_is_counted(tmp_path, monkeypatch):
    monkeypatch.setattr(zip_extract, "_MAX_MEMBERS", 2)
    z = _zip(tmp_path / "big.zip", {"one.xml": FIX / "scc_embedded_results.xml", "two.xml": FIX / "openscap_results.xml",
                                    "three.xml": FIX / "evaluate_stig_results.xml",
                                    "four.cklb": FIX / "evaluate_stig_checklist.cklb"})
    c = classify_inputs([z], [], tmp_path / "x")
    assert _names(c, c.xccdf_results) == ["one.xml", "two.xml"] and c.self_contained == []
    assert c.warnings == [f"big.zip: member limit reached — 2 more file(s) not checked; {MISSING}"]


def test_an_archive_over_the_size_limit_is_read_up_to_it_and_the_rest_is_counted(tmp_path, monkeypatch):
    monkeypatch.setattr(zip_extract, "_MAX_ARCHIVE_BYTES", (FIX / "scc_embedded_results.xml").stat().st_size + 100)
    z = _zip(tmp_path / "big.zip", {"one.xml": FIX / "scc_embedded_results.xml",
                                    "two.xml": FIX / "manual_stig_win11.xml"})
    c = classify_inputs([z], [], tmp_path / "x")
    assert _names(c, c.xccdf_results) == ["one.xml"] and c.reference_xml == []
    assert c.warnings == [f"big.zip: size limit reached — 1 more file(s) not checked; {MISSING}"]


def test_archives_of_another_format_inside_a_zip_are_named_in_one_line(tmp_path):
    z = _zip(tmp_path / "mixed.zip", {"scan.xml": FIX / "scc_embedded_results.xml", "hostB.7z": "x",
                                      "hostC.TAR.GZ": "x", "hostD.rar": "x", "e.tar": "x", "f.tgz": "x", "g.bz2": "x",
                                      "notes.txt": "x"})
    c = classify_inputs([z], [], tmp_path / "x")
    assert _names(c, c.xccdf_results) == ["scan.xml"]
    assert c.warnings == [
        "mixed.zip: 6 archive(s) inside were not read (only ZIP is supported): hostB.7z, hostC.TAR.GZ, hostD.rar, "
        "e.tar, f.tgz …"]


def test_a_zip_holding_only_other_archives_is_named_for_them_not_called_empty(tmp_path):
    z = _zip(tmp_path / "wrapped.zip", {"scans.tar.gz": "x"})
    c = classify_inputs([z], [], tmp_path / "x")
    assert c.warnings == ["wrapped.zip: 1 archive(s) inside were not read (only ZIP is supported): scans.tar.gz"]



# --- one run is bounded too ---------------------------------------------------------------------

def _three_archives(tmp_path):
    scans = [FIX / "scc_embedded_results.xml", FIX / "openscap_results.xml", FIX / "evaluate_stig_results.xml",
             FIX / "openscap_remediation_results.xml", FIX / "nessus_results.xml"]
    return [_zip(tmp_path / "one.zip", {"s1.xml": scans[0], "s2.xml": scans[1]}),
            _zip(tmp_path / "two.zip", {"s3.xml": scans[2], "s4.xml": scans[3]}),
            _zip(tmp_path / "three.zip", {"s5.xml": scans[4]})]


def test_the_member_limit_of_one_run_stops_the_archive_that_reaches_it_and_skips_the_rest(tmp_path, monkeypatch):
    monkeypatch.setattr(zip_extract, "_MAX_RUN_MEMBERS", 3)
    c = classify_inputs(_three_archives(tmp_path), [], tmp_path / "x")
    assert _names(c, c.xccdf_results) == ["s1.xml", "s2.xml", "s3.xml"]
    assert c.warnings == [f"two.zip: member limit reached — 1 more file(s) not checked; {MISSING}",
                          "three.zip: not read — the limit for one run was reached"]


def test_the_size_limit_of_one_run_stops_the_archive_that_reaches_it_and_skips_the_rest(tmp_path, monkeypatch):
    first_two = sum((FIX / n).stat().st_size for n in ("scc_embedded_results.xml", "openscap_results.xml"))
    monkeypatch.setattr(zip_extract, "_MAX_RUN_BYTES", first_two + 10)
    c = classify_inputs(_three_archives(tmp_path), [], tmp_path / "x")
    assert _names(c, c.xccdf_results) == ["s1.xml", "s2.xml"]
    assert c.warnings == [f"two.zip: size limit reached — 2 more file(s) not checked; {MISSING}",
                          "three.zip: not read — the limit for one run was reached"]



def test_the_limit_line_says_what_may_be_missing_without_reading_the_rest(tmp_path, monkeypatch):
    # Six scans, then four OVAL results under names that do not say so. Three scans are read;
    # the other seven files are not opened to learn which of them were scans.
    monkeypatch.setattr(zip_extract, "_MAX_MEMBERS", 3)
    text = (FIX / "scc_embedded_results.xml").read_text(encoding="utf-8")
    with zipfile.ZipFile(tmp_path / "six_hosts.zip", "w") as zf:
        for i in range(6):
            zf.writestr(f"h{i}/WKSTN-{i}_XCCDF-Results.xml", text.replace("WKSTN-01", f"WKSTN-1{i}"))
        for i in range(4):
            zf.writestr(f"oval/WKSTN-{i}_OVAL-Results.xml",
                        '<?xml version="1.0"?><oval_results xmlns="http://oval.mitre.org/XMLSchema/oval-results-5"/>')
    c = classify_inputs([tmp_path / "six_hosts.zip"], [], tmp_path / "x")
    assert len(c.xccdf_results) == 3
    assert c.warnings == [f"six_hosts.zip: member limit reached — 7 more file(s) not checked; {MISSING}"]



# --- a file with no document element near its start is not parsed --------------------------------

_PADDING = {"whitespace": " " * (70 * 1024), "comments": "<!--x-->" * (9 * 1024), "PIs": "<?p x?>" * (10 * 1024)}


def _padded(kind: str) -> str:
    """Results whose document element comes only after 70 KiB of *kind* padding."""
    return ('<?xml version="1.0"?>\n' + _PADDING[kind]
            + "<TestResult><target>H</target><rule-result idref='SV-1r1_rule'><result>fail</result></rule-result>"
              "</TestResult>")


@pytest.fixture
def full_parses(monkeypatch):
    """The paths the full XML parse is asked to read."""
    from lxml import etree
    seen: list[Path] = []
    real = etree.parse

    def spy(source, *args, **kwargs):
        seen.append(Path(str(source)))
        return real(source, *args, **kwargs)

    monkeypatch.setattr(etree, "parse", spy)
    return seen


@pytest.mark.parametrize("kind", sorted(_PADDING))
def test_a_padded_member_is_named_for_what_it_lacks_and_not_parsed(tmp_path, kind, full_parses):
    z = _zip(tmp_path / "bundle.zip", {"padded.xml": _padded(kind), "scan.xml": FIX / "scc_embedded_results.xml"})
    c = classify_inputs([z], [], tmp_path / "x")
    assert _names(c, c.xccdf_results) == ["scan.xml"]
    assert c.warnings == ["bundle.zip: 1 file(s) have no XML element in their first 64 KiB — not read: padded.xml"]
    assert full_parses == []        # classifying parses nothing


@pytest.mark.parametrize("kind", sorted(_PADDING))
def test_a_padded_loose_file_is_named_for_what_it_lacks_and_not_parsed(tmp_path, kind, full_parses):
    padded = tmp_path / "padded.xml"
    padded.write_text(_padded(kind), encoding="utf-8")
    for slot in ("results", "references"):
        c = classify_inputs([padded], [], tmp_path / "x") if slot == "results" else classify_inputs([], [padded], tmp_path / "y")
        assert (c.xccdf_results, c.reference_xml) == ([], [])
        assert c.warnings == ["padded.xml: no XML element in its first 64 KiB — not read"]
    assert full_parses == []
    assert _kind(tmp_path, padded) == "other"


def test_files_that_start_with_a_declaration_and_a_short_comment_still_classify(tmp_path, full_parses):
    # Both fixtures open with an XML declaration and a comment before their document element.
    assert _kind(tmp_path, FIX / "scc_embedded_results.xml") == "results"
    assert _kind(tmp_path, FIX / "manual_stig_win11.xml") == "benchmark"
    z = _zip(tmp_path / "bundle.zip", {"scan.xml": FIX / "scc_embedded_results.xml",
                                       "Manual-xccdf.xml": FIX / "manual_stig_win11.xml"})
    c = classify_inputs([z], [], tmp_path / "x")
    assert (_names(c, c.xccdf_results), _names(c, c.reference_xml)) == (["scan.xml"], ["Manual-xccdf.xml"])
    assert c.warnings == []


def test_a_short_file_with_no_document_element_is_still_handed_to_its_parser(tmp_path):
    # Under 64 KiB, a file that is not XML is not "no root near the start": its parser names the error.
    broken = tmp_path / "broken.xml"
    broken.write_text("<!-- only a comment -->", encoding="utf-8")
    c = classify_inputs([broken], [], tmp_path / "x")
    assert c.xccdf_results == [broken] and c.warnings == []


# --- every member opened counts --------------------------------------------------------------------

def test_members_only_sniffed_count_against_the_member_limit(tmp_path, monkeypatch):
    # Ten OVAL results under names that do not say so, then a scan: each OVAL member is opened to read
    # its first tag, and that counts, though none is extracted.
    monkeypatch.setattr(zip_extract, "_MAX_MEMBERS", 5)
    oval = '<?xml version="1.0"?><oval_results xmlns="http://oval.mitre.org/XMLSchema/oval-results-5"/>'
    members = {f"WKSTN-{i}_OVAL-Results.xml": oval.replace("?>", f"?><!--{i}-->") for i in range(10)}
    members["scan.xml"] = FIX / "scc_embedded_results.xml"
    c = classify_inputs([_zip(tmp_path / "ovals.zip", members)], [], tmp_path / "x")
    assert c.xccdf_results == []
    assert c.warnings == [f"ovals.zip: member limit reached — 6 more file(s) not checked; {MISSING}"]



def test_members_with_no_xml_element_near_their_start_are_named_five_at_most(tmp_path):
    members = {f"padded_{i}.xml": _padded("comments").replace("<target>H<", f"<target>H{i}<") for i in range(7)}
    members["scan.xml"] = FIX / "scc_embedded_results.xml"
    c = classify_inputs([_zip(tmp_path / "bundle.zip", members)], [], tmp_path / "x")
    assert c.warnings == ["bundle.zip: 7 file(s) have no XML element in their first 64 KiB — not read: "
                          "padded_0.xml, padded_1.xml, padded_2.xml, padded_3.xml, padded_4.xml …"]



def test_an_archive_with_too_many_entries_is_named_and_not_read(tmp_path, monkeypatch):
    monkeypatch.setattr(zip_extract, "_MAX_ENTRIES", 3)
    z = _zip(tmp_path / "many.zip", {f"m{i}.xml": f"<m{i}/>" for i in range(5)})
    c = classify_inputs([z, FIX / "scc_embedded_results.xml"], [], tmp_path / "x")
    assert _names(c, c.xccdf_results) == ["scc_embedded_results.xml"]
    assert c.warnings == ["many.zip: more than 3 entries — not read"]



# --- classification polls for cancellation -----------------------------------------------------------

class _Cancelled(Exception):
    pass


def _cancel_on(call: int):
    calls = []

    def check() -> None:
        calls.append(1)
        if len(calls) >= call:
            raise _Cancelled
    return check, calls


def test_classification_polls_for_cancellation_per_loose_file(tmp_path):
    loose = [FIX / n for n in ("scc_embedded_results.xml", "openscap_results.xml", "evaluate_stig_results.xml")]
    check, calls = _cancel_on(2)
    with pytest.raises(_Cancelled):
        classify_inputs(loose, [], tmp_path / "x", cancel_check=check)
    assert len(calls) == 2


def test_classification_stops_inside_an_archive_when_cancelled(tmp_path):
    z = _zip(tmp_path / "many.zip", {f"m{i}.xml": f"<m{i}/>" for i in range(20)})
    check, calls = _cancel_on(5)
    with pytest.raises(_Cancelled):
        classify_inputs([z], [], tmp_path / "x", cancel_check=check)
    assert len(calls) == 5
    assert len(list((tmp_path / "x").iterdir())) < 20



def test_three_files_with_one_name_are_numbered_in_the_order_supplied(tmp_path):
    first = _copy(FIX / "scc_embedded_results.xml", tmp_path / "1" / "scan.xml")
    second = _copy(FIX / "openscap_results.xml", tmp_path / "2" / "scan.xml")
    third = _copy(FIX / "evaluate_stig_results.xml", tmp_path / "3" / "scan.xml")
    c = classify_inputs([first, second], [third], tmp_path / "x")
    assert [c.name_of(p) for p in (first, second, third)] == ["scan.xml", "scan.xml (2)", "scan.xml (3)"]


def test_a_supplied_name_holding_a_number_is_never_given_twice(tmp_path):
    # "scan.xml (2)" and "scan.xml (3)" are taken by the files supplied under those names:
    # the second "scan.xml" is numbered past both.
    taken_2 = _copy(FIX / "openscap_results.xml", tmp_path / "1" / "scan.xml (2)")
    taken_3 = _copy(FIX / "scc_results.xml", tmp_path / "2" / "scan.xml (3)")
    first = _copy(FIX / "scc_embedded_results.xml", tmp_path / "3" / "scan.xml")
    second = _copy(FIX / "evaluate_stig_results.xml", tmp_path / "4" / "scan.xml")
    c = classify_inputs([taken_2, taken_3, first, second], [], tmp_path / "x")
    assert [c.name_of(p) for p in (taken_2, taken_3, first, second)] == [
        "scan.xml (2)", "scan.xml (3)", "scan.xml", "scan.xml (4)"]


@pytest.mark.parametrize("root", ["stylesheet", "transform"])
def test_a_member_whose_root_is_an_xsl_stylesheet_is_neither_read_nor_named(tmp_path, root):
    z = _zip(tmp_path / "bundle.zip", {
        "report-style.xml": f"<xsl:{root} xmlns:xsl='http://www.w3.org/1999/XSL/Transform' version='1.0'/>",
        "scan.xml": FIX / "scc_embedded_results.xml"})
    c = classify_inputs([z], [], tmp_path / "x")
    assert _names(c, c.xccdf_results) == ["scan.xml"] and c.warnings == []
    assert len(list((tmp_path / "x").iterdir())) == 1        # only the scan was extracted


def test_a_member_recognised_as_ancillary_by_its_root_is_neither_read_nor_named(tmp_path):
    z = _zip(tmp_path / "bundle.zip", {"checks.xml": '<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/'
                                                     'oval-definitions-5"/>',
                                       "scan.xml": FIX / "scc_embedded_results.xml"})
    c = classify_inputs([z], [], tmp_path / "x")
    assert _names(c, c.xccdf_results) == ["scan.xml"] and c.warnings == []
    assert len(list((tmp_path / "x").iterdir())) == 1        # only the scan was extracted


# --- the names the operator gave uploads saved under other names --------------------------------------

def test_a_supplied_name_is_cleaned_before_it_names_the_file(tmp_path):
    saved = tmp_path / "upload.xml"
    saved.write_bytes(b"<a><b></a>")
    c = classify_inputs([saved], [], tmp_path / "x", display_names={saved: "résumé‮.xml"})
    assert c.name_of(saved) == "résumé.xml"          # NFC, the bidi control removed


def test_an_archive_is_named_by_its_supplied_name_in_its_lines_and_its_members(tmp_path):
    import zipfile
    saved = tmp_path / "upload.zip"
    with zipfile.ZipFile(saved, "w") as zf:
        zf.writestr("s/notes.xml", "<notes/>")
    loose = tmp_path / "notes.xml"
    loose.write_bytes(b"<other/>")
    c = classify_inputs([saved, loose], [], tmp_path / "x", display_names={saved: "архив.zip"})
    # The member's name is taken by the loose file, so it is qualified with the archive's supplied name.
    assert c.warnings == ["архив.zip: 1 XML file(s) were not recognised as scan results "
                          "or STIG references: архив.zip/s/notes.xml"]


def test_a_full_disk_is_reported_as_the_size_limit(tmp_path, monkeypatch):
    import errno

    def full(*args, **kwargs):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(zip_extract, "_bounded_extract", full)
    z = _zip(tmp_path / "scans.zip", {"a.xml": FIX / "scc_embedded_results.xml", "b.xml": FIX / "openscap_results.xml"})
    c = classify_inputs([z], [], tmp_path / "x")
    assert c.xccdf_results == []
    assert c.warnings == [f"scans.zip: size limit reached — 2 more file(s) not checked; {MISSING}"]


def test_identical_members_of_one_archive_are_summarised(tmp_path):
    z = _zip(tmp_path / "bundle.zip", {f"bad{n}.xml": "<r><a></r>" for n in range(300)})
    c = classify_inputs([z], [], tmp_path / "x")
    identical = [w for w in c.warnings if "identical to" in w]
    assert identical == [f"bad{n}.xml: identical to bad0.xml — read once" for n in range(1, 6)] + [
        "bundle.zip: … and 294 more identical to bad0.xml — read once"]
    assert len(c.warnings) == 7      # and the one line naming bad0.xml as not recognised



# --- a tag inside a comment, CDATA or a processing instruction is not a tag ---------------------------

_HIDDEN = {
    "comment": "<!-- <TestResult> -->",
    "cdata": "<![CDATA[ <TestResult> ]]>",
    "instruction": "<?note <TestResult> ?>",
    "long comment": "<!-- " + "x" * (1100 * 1024) + " <TestResult> -->",      # longer than any read
}


@pytest.mark.parametrize("hidden", sorted(_HIDDEN))
def test_a_benchmark_with_a_tag_inside_a_comment_cdata_or_instruction_stays_a_benchmark(tmp_path, hidden):
    text = (FIX / "manual_stig_win11.xml").read_text(encoding="utf-8")
    at = text.index("<Group")
    path = tmp_path / "manual.xml"
    path.write_text(text[:at] + _HIDDEN[hidden] + text[at:], encoding="utf-8")
    assert _kind(tmp_path, path) == "benchmark"



def test_results_under_a_long_namespace_prefix_are_recognised_in_a_zip(tmp_path):
    text = (FIX / "scc_embedded_results.xml").read_text(encoding="utf-8")
    assert "xmlns:cdf=" in text and "<cdf:TestResult" in text
    prefix = "p" * 150
    long_prefix = text.replace("xmlns:cdf=", f"xmlns:{prefix}=").replace("cdf:", f"{prefix}:")
    z = _zip(tmp_path / "scans.zip", {"scan.xml": long_prefix})
    c = classify_inputs([z], [], tmp_path / "x")
    assert _names(c, c.xccdf_results) == ["scan.xml"] and c.warnings == []
