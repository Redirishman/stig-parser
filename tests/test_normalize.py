# tests/test_normalize.py
import time

import pytest

from app.reference.normalize import (
    fold,
    is_disa_stem,
    is_vuln_id,
    norm_benchmark_id,
    norm_stig_id,
    product_key,
    release_key,
    release_label,
    rule_revision,
    rule_stem,
    strip_group_prefix,
    strip_rule_prefix,
)


@pytest.mark.parametrize("raw,expected", [
    ("xccdf_mil.disa.stig_rule_SV-254239r945408_rule", "SV-254239r945408_rule"),
    ("SV-254239r945408_rule", "SV-254239r945408_rule"),
    ("  SV-254239r945408_rule ", "SV-254239r945408_rule"),
    ("xccdf_org.ssgproject.content_rule_package_aide_installed", "package_aide_installed"),
    ("", ""),
])
def test_strip_rule_prefix(raw, expected):
    assert strip_rule_prefix(raw) == expected


@pytest.mark.parametrize("raw,stem,revision", [
    ("xccdf_mil.disa.stig_rule_SV-254239r945408_rule", "SV-254239", "r945408"),
    ("SV-254239r1153440_rule", "SV-254239", "r1153440"),
    ("SV-254239_rule", "SV-254239", ""),
    ("WN22-00-000010", "WN22-00-000010", ""),
    ("", "", ""),
    # STIG Viewer checklists carry rule_id without the _rule suffix.
    ("SV-254239r945408", "SV-254239", "r945408"),
    # Case-insensitive; revision is reported lower-case.
    ("xccdf_mil.disa.stig_rule_SV-254239R945408_RULE", "SV-254239", "r945408"),
    # A revision must follow a digit, so non-STIG ids are left alone.
    ("xccdf_org.ssgproject.content_rule_package_aide_installed", "package_aide_installed", ""),
])
def test_rule_stem_and_revision(raw, stem, revision):
    assert rule_stem(raw) == stem
    assert rule_revision(raw) == revision


@pytest.mark.parametrize("raw,expected", [
    ("xccdf_mil.disa.stig_group_V-254239", "V-254239"),
    ("V-254239", "V-254239"),
    ("", ""),
])
def test_strip_group_prefix(raw, expected):
    assert strip_group_prefix(raw) == expected


@pytest.mark.parametrize("raw,expected", [
    ("WN22-00-000010", "WN22-00-000010"),
    ("wn22_00_000030", "WN22-00-000030"),
    ("DISA-STIG-RHEL-09-651010", "RHEL-09-651010"),
    ("disa_stig_rhel_09_651010", "RHEL-09-651010"),
    ("WNFWA-000001", "WNFWA-000001"),
    ("  ", ""),
])
def test_norm_stig_id(raw, expected):
    assert norm_stig_id(raw) == expected


@pytest.mark.parametrize("raw,expected", [
    ("xccdf_mil.disa.stig_benchmark_MS_Windows_Server_2022_STIG", "MS_Windows_Server_2022_STIG"),
    ("MS_Windows_Server_2022_STIG", "MS_Windows_Server_2022_STIG"),
])
def test_norm_benchmark_id(raw, expected):
    assert norm_benchmark_id(raw) == expected


@pytest.mark.parametrize("version,info,expected", [
    ("2", "Release: 8 Benchmark Date: 01 Apr 2026", "V2R8"),      # Manual STIG
    ("002.008", "Benchmark Date: 01 Apr 2026", "V2R8"),           # SCAP benchmark
    ("1", "Release: 4 Benchmark Date: 24 Jul 2024", "V1R4"),      # CKLB (version is an int there)
    ("V1R4", "", "V1R4"),                                         # already a label
    ("3", "", "V3"),
    ("", "", ""),
])
def test_release_label(version, info, expected):
    assert release_label(version, info) == expected


@pytest.mark.parametrize("version,info", [
    ("\u00b2", ""),                      # superscript two: str.isdigit() is True, int() raises
    ("\u0663", "Release: 1"),            # Arabic-Indic three: same trap
    ("\u0660\u0660\u0662.\u0660\u0660\u0668", ""),  # non-ASCII digits in the SCAP shape
])
def test_release_label_leaves_non_ascii_digits_unchanged(version, info):
    assert release_label(version, info) == version


# --- hostile input: these values come from uploaded files -------------------

def test_release_label_scap_pattern_is_not_a_redos():
    hostile = "0" * 2000 + "." + "0" * 2000 + "x"
    start = time.perf_counter()
    result = release_label(hostile, "")
    elapsed = time.perf_counter() - start
    assert elapsed < 0.5
    assert result == hostile[:40]          # returned as it is, cut to the label bound


def test_release_label_oversized_plain_digits_never_raise_and_are_cut():
    # int() raises ValueError above 4300 digits; the label must never raise.
    huge = "9" * 5000
    assert release_label(huge, "") == huge[:40]


def test_release_label_oversized_release_number_is_ignored():
    # The version is valid; the absurd release number is dropped, not parsed.
    assert release_label("2", "Release: " + "9" * 5000) == "V2"


def test_release_label_digit_groups_are_bounded_at_nine():
    assert release_label("123456789", "") == "V123456789"
    assert release_label("1" * 10, "") == "1" * 10
    assert release_label("2", "Release: 123456789") == "V2R123456789"
    assert release_label("2", "Release: " + "1" * 10) == "V2"
    assert release_label("1" * 10 + ".1", "") == "1" * 10 + ".1"


def test_release_label_release_word_must_stand_alone():
    assert release_label("2", "Pre-Release: 4") == "V2"
    assert release_label("2", "Release: 4 Benchmark Date: 01 Apr 2026") == "V2R4"


def test_release_label_scap_leading_zeros_still_parse():
    assert release_label("002.008", "") == "V2R8"


def test_norm_stig_id_does_not_case_fold_non_ascii():
    # str.upper() maps U+00DF to "SS", which would collide two different IDs.
    assert norm_stig_id("WN22-\u00df") != norm_stig_id("WN22-SS")
    assert norm_stig_id("wn22_\u00df") == "wn22-\u00df"


# --- revision lookbehind and anchoring, pinned ------------------------------

def test_revision_requires_a_preceding_digit():
    assert rule_stem("foo_r2") == "foo_r2"
    assert rule_revision("foo_r2") == ""


def test_only_the_trailing_revision_is_split_off():
    assert rule_stem("SV-1r2r3_rule") == "SV-1r2"
    assert rule_revision("SV-1r2r3_rule") == "r3"


def test_different_stems_never_collide_on_revision_digits():
    assert rule_stem("SV-12r3_rule") != rule_stem("SV-1r23_rule")


# --- release ordering key ----------------------------------------------------

@pytest.mark.parametrize("label,expected", [
    ("V2R10", (2, 10)),
    ("V2R9", (2, 9)),
    ("V2R8", (2, 8)),
    ("V3", (3, 0)),
    ("V0R0", (0, 0)),
    ("v2r8", (2, 8)),
    ("V002R008", (2, 8)),
    ("", (-1, -1)),
    ("garbage", (-1, -1)),
    ("V2R", (-1, -1)),
    ("V2R8 extra", (-1, -1)),
    ("V²R1", (-1, -1)),                 # superscript two is not an ASCII digit
    ("V1234567890R1", (-1, -1)),                  # ten digits: past the nine-digit bound
    ("V1R" + "9" * 5000, (-1, -1)),               # never reaches int()
])
def test_release_key(label, expected):
    assert release_key(label) == expected


def test_release_key_orders_releases_numerically_not_textually():
    assert release_key("V2R10") > release_key("V2R9")
    assert release_key("V3") > release_key("V2R10")
    assert release_key("V2R1") > release_key("not a release")


# --- product key -------------------------------------------------------------

@pytest.mark.parametrize("title,expected", [
    ("Microsoft Windows 11 STIG SCAP Benchmark", "microsoft windows 11"),
    ("Microsoft Windows 11 Security Technical Implementation Guide", "microsoft windows 11"),
    ("Microsoft Windows Server 2022 STIG", "microsoft windows server 2022"),
    ("DISA_Microsoft_Windows_Server_2022_STIG_V1R4", "microsoft windows server 2022"),
    ("Cisco IOS XE Router NDM STIG", "cisco ios xe router ndm"),
    ("Cisco IOS XE Switch NDM Security Technical Implementation Guide", "cisco ios xe switch ndm"),
    ("Windows 11 Manual  Benchmark V2R9", "windows 11"),
    ("Security-Technical Implementation Guide: Foo (v1r2)", "foo"),
    ("  Foo   Bar  ", "foo bar"),
    ("DISA_STIG_Red_Hat_Enterprise_Linux_7_v3r4.audit", "red hat enterprise linux 7"),
    ("Red Hat Enterprise Linux 7 Security Technical Implementation Guide", "red hat enterprise linux 7"),
    ("STIG", "stig"),                                       # nothing left: the folded original
    ("  SCAP   Benchmark ", "scap benchmark"),
    ("", ""),
])
def test_product_key(title, expected):
    assert product_key(title) == expected


def test_product_key_keeps_distinct_products_distinct():
    assert product_key("Cisco IOS XE Router NDM STIG") != product_key("Cisco IOS XE Switch NDM STIG")
    assert product_key("Windows 10 STIG") != product_key("Windows 11 STIG")


def test_product_key_is_safe_on_hostile_titles():
    started = time.perf_counter()
    assert product_key("v" + "9" * 5000 + "r1") == "v" + "9" * 999           # read to 1,000 characters, no int()
    product_key("a " * 100000)
    product_key("security technical implementation guide " * 20000)
    assert time.perf_counter() - started < 2.0


# --- DISA-style rule stems ---------------------------------------------------

@pytest.mark.parametrize("stem,expected", [
    ("SV-254241", True), ("sv-1", True), ("SV-123456789012", True),
    ("SV-", False), ("SV-1234567890123", False), ("SV-12a", False), ("SV-²", False),
    ("WN22-00-000010", False), ("accounts_tmout", False), ("", False),
])
def test_is_disa_stem(stem, expected):
    assert is_disa_stem(stem) is expected



# --- V-ID-shaped group IDs ---------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    ("V-254239", True), ("v-1", True), (" V-1 ", True), ("V-123456789012", True),
    ("xccdf_mil.disa.stig_group_V-254239", True),
    ("V-", False), ("V-1234567890123", False), ("V-12a", False), ("V-1-2", False),
    ("accounts-session", False), ("xccdf_org.ssgproject.content_group_accounts-session", False),
    ("SV-1", False), ("", False),
])
def test_is_vuln_id(value, expected):
    assert is_vuln_id(value) is expected


def test_is_vuln_id_is_safe_on_hostile_values():
    started = time.perf_counter()
    assert is_vuln_id("V-" + "9" * 100000) is False
    assert is_vuln_id("xccdf_" + "a" * 100000) is False
    assert time.perf_counter() - started < 1.0


# --- ASCII-only folding of IDs ---------------------------------------------------

def test_fold_upper_cases_ascii_and_leaves_everything_else_alone():
    sharp_s = chr(0xDF)
    assert fold("sv-1r2_rule") == "SV-1R2_RULE"
    assert fold("") == ""
    assert fold(f"stra{sharp_s}e") == f"stra{sharp_s}e"            # "STRASSE" would collide with a real "strasse"
    assert fold("caf" + chr(0xE9)) == "caf" + chr(0xE9)


@pytest.mark.parametrize("value,expected", [
    ("  text \n", "text"), ("", ""), (None, ""), (True, ""), (0, ""), (12345, ""), (1.5, ""),
    ({"a": 1}, ""), (["a"], ""),
])
def test_json_text_takes_strings_only(value, expected):
    from app.reference.normalize import json_text
    assert json_text(value) == expected


def test_safe_name_takes_a_limit():
    from app.reference.normalize import safe_name
    assert safe_name("n" * 300) == "n" * 80                       # the default: a log line
    assert safe_name("n" * 300, 255) == "n" * 255
    assert safe_name("a\nb" * 100, 255) == ("a\\nb" * 100)[:255]   # still escaped, still bounded after escaping
    assert safe_name("ordinary_name.xml", 255) == "ordinary_name.xml"


def test_escape_controls_writes_c0_c1_and_del_as_escapes_and_nothing_else():
    from app.reference.normalize import escape_controls, safe_name
    assert escape_controls("a\nb\rc\td\x00e\x1bf\x7fg\x85h\x9fi") == (
        "a\\nb\\rc\\td\\x00e\\x1bf\\x7fg\\x85h\\x9fi")
    # Printable text is left alone: quotes, backslashes, non-ASCII, an em-dash.
    text = "C:\\scans\\x.xml — 'Windows' \"11\" ü …"
    assert escape_controls(text) == text
    # A name safe_name already escaped holds no control character: nothing is escaped twice.
    name = safe_name("bad\nname\x1b.xml")
    assert escape_controls(name) == name


def test_escape_controls_covers_line_separators_and_bidi_controls():
    # U+2028/U+2029 end a line for many viewers; the bidi controls can make a line read
    # differently from what it holds. Each is written as its escape too.
    from app.reference.normalize import escape_controls
    for ch in "\u2028\u2029\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069":
        assert escape_controls(f"a{ch}b") == f"a\\u{ord(ch):04x}b", hex(ord(ch))
    # Neighbouring characters that are not controls stay as they are.
    assert escape_controls("a\u200db‰c\u2065d\u206ae") == "a\u200db‰c\u2065d\u206ae"


# --- an error as the operator reads it ------------------------------------------------------------

def test_error_text_gives_an_xml_error_without_the_file_url(tmp_path):
    from lxml import etree

    from app.reference.normalize import error_text
    broken = tmp_path / "member_x1y2.xml"
    broken.write_text("<root><a></root>", encoding="utf-8")
    with pytest.raises(etree.XMLSyntaxError) as exc:
        etree.parse(str(broken), etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False))
    assert "file:/" in str(exc.value)                  # what lxml says, and why it is not used
    assert error_text(exc.value) == "Opening and ending tag mismatch: a line 1 and root, line 1, column 17"


def test_error_text_gives_an_os_error_without_its_path(tmp_path):
    from app.reference.normalize import error_text
    missing = tmp_path / "member_x1y2.cklb"
    with pytest.raises(OSError) as exc:
        missing.read_text(encoding="utf-8")
    assert error_text(exc.value) == exc.value.strerror
    assert error_text(OSError("built without an errno")) == "the file could not be read"


def test_error_text_adds_the_line_when_the_message_lacks_it():
    import json

    from app.reference.normalize import error_text
    with pytest.raises(ValueError) as exc:
        json.loads('{\n "a": }')
    assert error_text(exc.value) == str(exc.value)     # "...: line 2 column 7 (char 8)": said once
    syntax = SyntaxError("Bad thing")
    syntax.lineno, syntax.filename = 4, "/srv/jobs/abc/member_1.xml"
    assert error_text(syntax) == "Bad thing (line 4)"


def test_error_text_removes_a_file_name_the_exception_carries_and_is_bounded_and_escaped():
    from app.reference.normalize import error_text

    class Odd(Exception):
        filename = "/srv/jobs/abc/member_1.xml"

    assert error_text(Odd("cannot use /srv/jobs/abc/member_1.xml here")) == "cannot use … here"
    assert error_text(ValueError("x\n" * 200)) == ("x\\n" * 200)[:120]
    assert error_text(ValueError("")) == "ValueError"



def test_clip_left_keeps_the_end_of_a_long_value():
    from app.reference.normalize import clip_left
    assert clip_left("short.xml", 120) == "short.xml"
    assert clip_left("x" * 120, 120) == "x" * 120
    long = "lib.zip/" + "folder/" * 30 + "manual-xccdf.xml"
    assert clip_left(long, 120) == "…" + long[-119:] and len(clip_left(long, 120)) == 120
    assert clip_left("", 120) == "" and clip_left(None, 120) == ""



def test_shown_file_name_escapes_and_keeps_the_end():
    from app.reference.normalize import shown_file_name
    assert shown_file_name("a\nb\x1b.xml") == "a\\nb\\x1b.xml"
    long = "d/" * 100 + "line\nbreak.xml"
    shown = shown_file_name(long)
    assert len(shown) == 120 and shown.startswith("…") and shown.endswith("line\\nbreak.xml")
    assert shown_file_name("x" * 300 + ".cklb", 255) == "…" + "x" * 249 + ".cklb"
