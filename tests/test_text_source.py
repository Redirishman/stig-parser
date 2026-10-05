import pytest

from app.reference.models import ReferenceRule, ReferenceSource
from app.reference.text_source import Outcome, source_phrase, text_source_cell


def _rule(revision="r1", release="V2R9", file_name="manual.xml"):
    src = ReferenceSource(file_name, "X", "T", release, False, "manual", 1)
    return ReferenceRule("V-1", f"SV-1{revision}_rule", "SV-1", revision, "", "", "T", "c", "f", src)


def test_scanner_supplied_text():
    assert source_phrase(None, Outcome.SCANNER, finding_revision="r1", scan_release="V2R8") == "scanner"


def test_filled_from_the_same_revision():
    assert source_phrase(_rule("r1"), Outcome.FILLED, finding_revision="r1", scan_release="V2R8") == "manual.xml V2R9"


def test_filled_from_a_different_revision_names_the_scanned_release():
    assert source_phrase(_rule("r2"), Outcome.FILLED, finding_revision="r1",
                         scan_release="V2R8") == "manual.xml V2R9, scanned V2R8"


def test_different_revision_without_a_distinct_scanned_release():
    for scan_release in ("", "V2R9"):
        assert source_phrase(_rule("r2"), Outcome.FILLED, finding_revision="r1", scan_release=scan_release
                             ) == "manual.xml V2R9, revision differs from scan"


def test_finding_without_a_revision_is_not_called_drift():
    assert source_phrase(_rule("r2"), Outcome.FILLED, finding_revision="", scan_release="") == "manual.xml V2R9"


def test_nothing_filled():
    assert source_phrase(None, Outcome.NOT_IN_REFERENCES, finding_revision="r1", scan_release=""
                         ) == "not in supplied references"
    assert source_phrase(None, Outcome.NO_REFERENCE, finding_revision="r1", scan_release=""
                         ) == "no reference supplied"


def test_cell_text():
    assert text_source_cell("scanner", "scanner") == "Check and fix: scanner"
    assert text_source_cell("manual.xml V2R9", "scanner") == "Check: manual.xml V2R9 | Fix: scanner"


def test_stig_id_only_match_is_said_after_the_release_wording():
    assert source_phrase(_rule("r1"), Outcome.FILLED_BY_STIG_ID, finding_revision="", scan_release="V2R8"
                         ) == "manual.xml V2R9, matched by STIG ID"
    assert source_phrase(_rule("r2"), Outcome.FILLED_BY_STIG_ID, finding_revision="r1", scan_release="V2R8"
                         ) == "manual.xml V2R9, scanned V2R8, matched by STIG ID"
    assert source_phrase(_rule("r2"), Outcome.FILLED_BY_STIG_ID, finding_revision="r1", scan_release=""
                         ) == "manual.xml V2R9, revision differs from scan, matched by STIG ID"


def test_scanner_text_never_gets_a_match_suffix():
    assert source_phrase(None, Outcome.SCANNER, finding_revision="", scan_release="") == "scanner"


def test_ambiguous_stig_id_is_not_called_absent():
    assert source_phrase(None, Outcome.AMBIGUOUS_STIG_ID, finding_revision="", scan_release=""
                         ) == "STIG ID matches several STIGs, not filled"


def test_ambiguous_v_id_is_named_as_such():
    assert source_phrase(None, Outcome.AMBIGUOUS_VULN_ID, finding_revision="", scan_release=""
                         ) == "V-ID matches several rules, not filled"


def test_a_v_id_only_match_is_said_after_the_release_wording():
    assert source_phrase(_rule("r1"), Outcome.FILLED_BY_VULN_ID, finding_revision="", scan_release="V2R8"
                         ) == "manual.xml V2R9, matched by V-ID"
    assert source_phrase(_rule("r2"), Outcome.FILLED_BY_VULN_ID, finding_revision="r1", scan_release="V2R8"
                         ) == "manual.xml V2R9, scanned V2R8, matched by V-ID"


def test_a_refused_product_is_named_as_such():
    assert source_phrase(None, Outcome.PRODUCT_REFUSED, finding_revision="", scan_release=""
                         ) == "STIG ID found under a different STIG title, not filled"


@pytest.mark.parametrize("outcome", [Outcome.FILLED, Outcome.FILLED_BY_VULN_ID, Outcome.FILLED_BY_STIG_ID])
def test_a_filled_outcome_needs_the_rule_that_filled_it(outcome):
    with pytest.raises(ValueError):
        source_phrase(None, outcome, finding_revision="", scan_release="")


@pytest.mark.parametrize("outcome", [Outcome.BLANK_CHECK, Outcome.BLANK_FIX, Outcome.BLANK_BOTH])
def test_a_finding_level_outcome_is_not_a_field_phrase(outcome):
    with pytest.raises(ValueError):
        source_phrase(_rule(), outcome, finding_revision="", scan_release="")



def test_a_long_display_name_keeps_its_file_name():
    name = "lib.zip/STIG_Library_April_2026/Operating_Systems/Microsoft/Windows/Workstation_and_Server_Benchmarks_Manual_Editions/win11/manual-xccdf.xml"
    assert len(name) > 120
    phrase = source_phrase(_rule("r1", file_name=name), Outcome.FILLED, finding_revision="r1", scan_release="")
    assert phrase == "…" + name[-119:] + " V2R9"
    assert phrase.endswith("/win11/manual-xccdf.xml V2R9")


def test_a_supplied_rule_without_the_text_is_named_as_found():
    assert source_phrase(_rule("r2"), Outcome.IN_REFERENCE_NO_TEXT, finding_revision="r1", scan_release="V2R8"
                         ) == "in manual.xml V2R9, which has no check text"
    assert source_phrase(_rule("r1"), Outcome.IN_REFERENCE_NO_TEXT, finding_revision="r1", scan_release="",
                         field="fix") == "in manual.xml V2R9, which has no fix text"
    with pytest.raises(ValueError):
        source_phrase(None, Outcome.IN_REFERENCE_NO_TEXT, finding_revision="", scan_release="")
