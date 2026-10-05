"""Tests for the DISA STIG ZIP extraction utility."""
from __future__ import annotations

import io
import logging
import re
import struct
import zipfile
from pathlib import Path

import pytest

import app.utils.zip_extract as zip_extract
from app.utils.zip_extract import extract_from_zip

_FAKE_XCCDF = (
    '<?xml version="1.0"?>'
    '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="fake_stig">'
    '<title>Fake STIG</title>'
    '</Benchmark>'
)


def _make_zip(zip_path: Path, members: dict[str, bytes | str]) -> Path:
    """Build a zip at *zip_path* with the given filename → content mapping."""
    with zipfile.ZipFile(zip_path, "w") as zf:
        for name, content in members.items():
            if isinstance(content, str):
                content = content.encode("utf-8")
            zf.writestr(name, content)
    return zip_path


class TestExtractXccdfFromZip:
    def test_extracts_single_xccdf(self, tmp_path):
        zip_path = _make_zip(
            tmp_path / "stig.zip",
            {
                "U_MS_Windows_Server_2022_STIG_V2R8_Manual-xccdf.xml": _FAKE_XCCDF,
                "U_MS_Windows_Server_2022_STIG_V2R8_Overview.pdf": b"%PDF-1.4 fake",
            },
        )
        dest = tmp_path / "out"
        extracted = extract_from_zip(zip_path, dest).members
        assert len(extracted) == 1
        assert extracted[0].name.endswith("xccdf.xml")
        assert extracted[0].path.read_text(encoding="utf-8").startswith("<?xml")

    def test_strips_internal_folder_structure(self, tmp_path):
        zip_path = _make_zip(
            tmp_path / "stig.zip",
            {"some/nested/folder/U_RHEL_9_STIG_V1R1_Manual-xccdf.xml": _FAKE_XCCDF},
        )
        dest = tmp_path / "out"
        extracted = extract_from_zip(zip_path, dest).members
        assert len(extracted) == 1
        # Folder structure flattened — file lives directly in dest
        assert extracted[0].path.parent == dest
        assert extracted[0].name == "U_RHEL_9_STIG_V1R1_Manual-xccdf.xml"

    def test_returns_empty_when_no_xccdf(self, tmp_path):
        zip_path = _make_zip(
            tmp_path / "stig.zip",
            {"readme.txt": "no xccdf here", "Overview.pdf": b"%PDF"},
        )
        dest = tmp_path / "out"
        extracted = extract_from_zip(zip_path, dest).members
        assert extracted == []

    def test_unwraps_nested_zip(self, tmp_path):
        # Build the inner DISA-style zip first
        inner_zip = _make_zip(
            tmp_path / "inner.zip",
            {"U_MS_Windows_Server_2022_STIG_V2R8_Manual-xccdf.xml": _FAKE_XCCDF},
        )
        inner_bytes = inner_zip.read_bytes()
        inner_zip.unlink()

        # Wrapper zip contains the inner zip
        wrapper = _make_zip(
            tmp_path / "wrapper.zip",
            {"U_MS_Windows_Server_2022_V2R8_STIG.zip": inner_bytes},
        )
        dest = tmp_path / "out"
        extracted = extract_from_zip(wrapper, dest).members
        assert len(extracted) == 1
        assert extracted[0].name == "U_MS_Windows_Server_2022_STIG_V2R8_Manual-xccdf.xml"
        # Nested zip itself is cleaned up
        assert [p.suffix for p in dest.iterdir()] == [".xml"]

    def test_handles_filename_collisions(self, tmp_path):
        zip_path = _make_zip(
            tmp_path / "stig.zip",
            {
                "a/Manual-xccdf.xml": "<a/>",
                "b/Manual-xccdf.xml": "<b/>",
            },
        )
        dest = tmp_path / "out"
        extracted = extract_from_zip(zip_path, dest).members
        assert len(extracted) == 2
        # Both files exist under distinct generated names; each keeps its own name and path.
        assert len({m.path for m in extracted}) == 2 and all(m.path.is_file() for m in extracted)
        assert [(m.name, m.path_in_archive) for m in extracted] == [
            ("Manual-xccdf.xml", "a/Manual-xccdf.xml"), ("Manual-xccdf.xml", "b/Manual-xccdf.xml")]

    def test_invalid_zip_returns_empty(self, tmp_path):
        bad = tmp_path / "not-a-zip.zip"
        bad.write_bytes(b"this is not a zip file")
        dest = tmp_path / "out"
        extracted = extract_from_zip(bad, dest).members
        assert extracted == []

    def test_case_insensitive_xccdf_match(self, tmp_path):
        zip_path = _make_zip(
            tmp_path / "stig.zip",
            {"WEIRD_MIXED_CASE_XCCDF.XML": _FAKE_XCCDF},
        )
        dest = tmp_path / "out"
        extracted = extract_from_zip(zip_path, dest).members
        assert len(extracted) == 1


def test_extracts_scap_datastreams_and_checklists(tmp_path):
    import zipfile
    z = tmp_path / "bundle.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("U_X_V1R1_STIG_SCAP_1-3_Benchmark.xml", "<a/>")
        zf.writestr("U_X_STIG_V1R1_Manual-xccdf.xml", "<a/>")
        zf.writestr("list.cklb", "{}")
        zf.writestr("U_X_V1R1_STIG_SCAP_1-2_Benchmark-oval.xml", "<a/>")
        zf.writestr("U_X_V1R1_STIG_SCAP_1-2_Benchmark-cpe-dictionary.xml", "<a/>")
    names = sorted(p.name for p in extract_from_zip(z, tmp_path / "out").members)
    assert names == ["U_X_STIG_V1R1_Manual-xccdf.xml", "U_X_V1R1_STIG_SCAP_1-3_Benchmark.xml", "list.cklb"]


# --- a ZIP is a folder: every member that may be results or a reference comes out ---------

def test_extracts_results_xml_and_nessus_members_whatever_they_are_called(tmp_path):
    z = _make_zip(tmp_path / "scan_folder.zip", {
        "HOST-A_SCC_XCCDF-Results_Windows_11.xml": "<Benchmark><TestResult/></Benchmark>",
        "results/host-b.xml": "<TestResult/>",
        "scan.nessus": "<NessusClientData_v2/>",
        "WIN-SERVER-04.CKLB": "{}",
    })
    names = sorted(p.name for p in extract_from_zip(z, tmp_path / "out").members)
    assert names == ["HOST-A_SCC_XCCDF-Results_Windows_11.xml", "WIN-SERVER-04.CKLB", "host-b.xml", "scan.nessus"]


def test_ancillary_members_are_not_extracted(tmp_path):
    z = _make_zip(tmp_path / "stig.zip", {
        "U_X_STIG_V1R1_Manual-xccdf.xml": _FAKE_XCCDF,
        "U_X_V1R1_STIG_SCAP_1-2_Benchmark-oval.xml": "<oval_definitions/>",       # by name
        "U_X_V1R1_STIG_SCAP_1-2_Benchmark-cpe-oval.xml": "<oval_definitions/>",
        "U_X_V1R1_STIG_SCAP_1-2_Benchmark-cpe-dictionary.xml": "<cpe-list/>",
        "U_X_V1R1_STIG_SCAP_1-2_Benchmark-ocil.xml": "<ocil/>",
        "definitions.xml": '<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"/>',  # by root
        "dictionary.xml": '<cpe-list xmlns="http://cpe.mitre.org/dictionary/2.0"/>',
        "STIG_unclass.xsl": "<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform'/>",
        "DoD-DISA-logos-as-JPEG.jpg": b"\xff\xd8",
        "U_X_V1R1_Overview.pdf": b"%PDF",
        "readme.txt": "text",
    })
    out = tmp_path / "out"
    assert [p.name for p in extract_from_zip(z, out).members] == ["U_X_STIG_V1R1_Manual-xccdf.xml"]
    assert len(list(out.iterdir())) == 1                                             # nothing else was written


def test_an_ancillary_member_is_recognised_from_its_first_tag_alone(tmp_path):
    # The rest of the member is never read: here it is not even well-formed.
    big = "<oval_definitions>" + "<definition/>" * 20_000 + "<<<< not XML at all"
    z = _make_zip(tmp_path / "stig.zip", {"definitions.xml": big})
    out = tmp_path / "out"
    assert extract_from_zip(z, out).members == []
    assert list(out.iterdir()) == []


def test_a_member_that_is_not_well_formed_is_extracted_so_its_parser_can_say_so(tmp_path):
    z = _make_zip(tmp_path / "scan.zip", {"broken.xml": "<TestResult><unclosed>", "empty.xml": ""})
    assert sorted(p.name for p in extract_from_zip(z, tmp_path / "out").members) == ["broken.xml", "empty.xml"]


def test_the_root_check_does_not_resolve_entities(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("<oval_definitions/>", encoding="utf-8")
    xxe = f'<!DOCTYPE Benchmark [<!ENTITY x SYSTEM "{secret.as_uri()}">]><Benchmark>&x;</Benchmark>'
    z = _make_zip(tmp_path / "stig.zip", {"x-xccdf.xml": xxe})
    assert [p.name for p in extract_from_zip(z, tmp_path / "out").members] == ["x-xccdf.xml"]


# --- members are extracted under generated names; a bad member never stops the archive ------

_RESULTS = "<TestResult><rule-result idref='SV-1r1_rule'><result>fail</result></rule-result></TestResult>"


def _set_encrypted_flag(zip_path: Path) -> None:
    """Mark every member as encrypted (general-purpose flag bit 0), as a password-protected ZIP has."""
    data = bytearray(zip_path.read_bytes())
    for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        at = data.find(signature)
        while at != -1:
            data[at + flag_offset] |= 0x01
            at = data.find(signature, at + 4)
    zip_path.write_bytes(bytes(data))


def _corrupt_member(zip_path: Path, payload: bytes) -> None:
    """Flip one byte inside the stored bytes of the member that holds *payload*."""
    data = bytearray(zip_path.read_bytes())
    at = data.find(payload)
    assert at != -1
    data[at + len(payload) // 2] ^= 0xFF
    zip_path.write_bytes(bytes(data))


def test_a_member_is_extracted_under_a_generated_name_and_keeps_its_own_for_display(tmp_path):
    hostile = {
        "rhel9_results_2026-01-15T10:00:00.xml": _RESULTS,            # a colon: not a file name on Windows
        "folder/" + "n" * 296 + ".xml": _RESULTS,                      # longer than a path component may be
        "CON.xml": _RESULTS, "trailing dot..xml": _RESULTS, "a\\b\\back.xml": _RESULTS,
    }
    out = tmp_path / "out"
    extraction = extract_from_zip(_make_zip(tmp_path / "scans.zip", hostile), out)
    assert extraction.skipped == [] and extraction.unreadable == ""
    assert [m.name for m in extraction.members] == [
        "rhel9_results_2026-01-15T10:00:00.xml", "…" + "n" * 250 + ".xml", "CON.xml", "trailing dot..xml", "back.xml"]
    for member in extraction.members:
        assert member.path.parent == out and member.path.read_text(encoding="utf-8") == _RESULTS
        assert member.path.suffix == ".xml" and member.path.name != member.name
        assert ":" not in member.path.name and len(member.path.name) < 40


def test_a_display_name_is_escaped(tmp_path):
    extraction = extract_from_zip(_make_zip(tmp_path / "scans.zip", {"line\nbreak.xml": _RESULTS}), tmp_path / "out")
    assert [m.name for m in extraction.members] == ["line\\nbreak.xml"]


def test_a_member_keeps_its_base_name_and_its_path_inside_the_archive(tmp_path):
    # No name is invented here: the caller names members once it knows every name in the run.
    inner = _make_zip(tmp_path / "inner.zip", {"y\\Manual-xccdf.xml": "<c/>"})
    z = _make_zip(tmp_path / "one.zip", {"a/Manual-xccdf.xml": "<a/>", "b/Manual-xccdf.xml": "<b/>",
                                         "nested/inner.zip": inner.read_bytes()})
    extraction = extract_from_zip(z, tmp_path / "out")
    assert [(m.name, m.path_in_archive) for m in extraction.members] == [
        ("Manual-xccdf.xml", "a/Manual-xccdf.xml"), ("Manual-xccdf.xml", "b/Manual-xccdf.xml"),
        ("Manual-xccdf.xml", "nested/inner.zip/y/Manual-xccdf.xml")]


def test_the_path_inside_the_archive_keeps_only_what_a_display_name_can_show(tmp_path):
    deep = "d/" * 400 + "scan.xml"
    extraction = extract_from_zip(_make_zip(tmp_path / "one.zip", {deep: _RESULTS}), tmp_path / "out")
    member, = extraction.members
    assert member.path_in_archive == deep[-256:]


def test_a_password_protected_archive_is_not_read(tmp_path):
    z = _make_zip(tmp_path / "locked.zip", {"scan.xml": _RESULTS, "other.xml": _RESULTS})
    _set_encrypted_flag(z)
    out = tmp_path / "out"
    extraction = extract_from_zip(z, out)
    assert (extraction.members, extraction.skipped) == ([], [])
    assert extraction.unreadable == "password-protected — not read"
    assert list(out.iterdir()) == []


def test_a_file_that_is_not_a_zip_is_not_read(tmp_path):
    bad = tmp_path / "not-a-zip.zip"
    bad.write_bytes(b"this is not a zip file")
    extraction = extract_from_zip(bad, tmp_path / "out")
    assert (extraction.members, extraction.unreadable) == ([], "not a readable ZIP — not read")
    gone = extract_from_zip(tmp_path / "gone.zip", tmp_path / "out")
    assert (gone.members, gone.unreadable) == ([], "not a readable ZIP — not read")


@pytest.mark.parametrize("compression", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_a_member_with_a_bad_crc_is_skipped_and_the_rest_are_read(tmp_path, compression):
    z = tmp_path / "damaged.zip"
    marker = b"MARKER-" + bytes(range(256)) * 4
    with zipfile.ZipFile(z, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("good_before.xml", _RESULTS)
        zf.writestr("damaged.xml", b"<TestResult><!--" + marker + b"--></TestResult>", compress_type=zipfile.ZIP_STORED)
        zf.writestr("good_after.xml", _RESULTS, compress_type=compression)
    _corrupt_member(z, marker)
    out = tmp_path / "out"
    extraction = extract_from_zip(z, out)
    assert [m.name for m in extraction.members] == ["good_before.xml", "good_after.xml"]
    assert extraction.skipped == ["could not read damaged.xml: Bad CRC-32 for file 'damaged.xml' — skipped"]
    assert len(list(out.iterdir())) == 2                               # the partial file was removed


def test_a_member_whose_compressed_data_is_damaged_is_skipped(tmp_path):
    z = tmp_path / "damaged.zip"
    body = ("<TestResult>" + "<a>text</a>" * 5000 + "</TestResult>").encode()
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("good.xml", _RESULTS)
        zf.writestr("damaged.xml", body)
    data = bytearray(z.read_bytes())
    info = zipfile.ZipFile(z).getinfo("damaged.xml")
    start = info.header_offset + 30 + len("damaged.xml")
    for at in range(start + 5, start + info.compress_size - 5):
        data[at] ^= 0xFF
    z.write_bytes(bytes(data))
    out = tmp_path / "out"
    extraction = extract_from_zip(z, out)
    assert [m.name for m in extraction.members] == ["good.xml"]
    # The reason is zlib's own message, which names what it found; its wording varies by zlib version.
    assert len(extraction.skipped) == 1
    assert re.fullmatch(r"could not read damaged\.xml: Error -3 while decompressing data: .+ — skipped",
                        extraction.skipped[0]), extraction.skipped
    assert len(list(out.iterdir())) == 1


# --- what an archive skips is said ------------------------------------------------------------

def _nest(tmp_path: Path, levels: int, innermost: dict) -> bytes:
    """*innermost* wrapped in *levels* ZIPs, as bytes."""
    data = _make_zip(tmp_path / "level.zip", innermost).read_bytes()
    for _ in range(levels - 1):
        data = _make_zip(tmp_path / "level.zip", {"inner.zip": data}).read_bytes()
    return data


def test_a_zip_nested_within_the_limit_is_read(tmp_path):
    z = _make_zip(tmp_path / "outer.zip", {"wrapped.zip": _nest(tmp_path, 2, {"deep.xml": _RESULTS})})
    extraction = extract_from_zip(z, tmp_path / "out")
    assert [m.name for m in extraction.members] == ["deep.xml"] and extraction.skipped == []


def test_a_zip_nested_too_deep_is_named_and_not_opened(tmp_path):
    z = _make_zip(tmp_path / "outer.zip", {
        "good.xml": _RESULTS,
        "wrapped.zip": _nest(tmp_path, 3, {"too_deep.xml": _RESULTS}),
    })
    out = tmp_path / "out"
    extraction = extract_from_zip(z, out)
    assert [m.name for m in extraction.members] == ["good.xml"]
    assert extraction.skipped == ["inner.zip is nested more than 2 ZIPs deep — skipped"]
    assert [p.suffix for p in out.iterdir()] == [".xml"]


def test_a_flood_of_zips_nested_too_deep_is_counted_not_listed(tmp_path, caplog):
    # 40 ZIP names at the depth limit: never opened, each a WARNING line and a stored string
    # before; a 90,000-entry archive made 90,000 of each. The first 5 are listed, the rest counted.
    flood = {f"x{n:02d}.zip": b"" for n in range(1, 41)}
    z = _make_zip(tmp_path / "outer.zip", {"good.xml": _RESULTS, "wrapped.zip": _nest(tmp_path, 2, flood)})
    with caplog.at_level(logging.WARNING, logger="app.utils.zip_extract"):
        extraction = extract_from_zip(z, tmp_path / "out")
    assert [m.name for m in extraction.members] == ["good.xml"]
    assert extraction.skipped == [f"x{n:02d}.zip is nested more than 2 ZIPs deep — skipped" for n in range(1, 6)]
    assert extraction.skipped_more == 35
    assert caplog.records == []                 # the caller names them, from the Extraction


def test_the_real_entry_limits_guard_uploads(tmp_path):
    # Other tests lower the limits to build small archives; these archives meet the real ones.
    def archive(name: str, names) -> Path:
        path = tmp_path / name
        with zipfile.ZipFile(path, "w") as zf:
            for member in names:
                zf.writestr(member, b"")
        return path

    at_limit = archive("at.zip", (str(n) for n in range(100_000)))
    assert extract_from_zip(at_limit, tmp_path / "a").unreadable == ""
    over = archive("over.zip", (str(n) for n in range(100_001)))
    assert extract_from_zip(over, tmp_path / "b").unreadable == "more than 100,000 entries — not read"
    long_names = archive("long.zip", (f"{n:04d}" + "n" * 16_100 for n in range(1_000)))   # about 16.2 MB of entries
    assert extract_from_zip(long_names, tmp_path / "c").unreadable == "entry list over 16,000,000 bytes — not read"


def test_an_inner_zip_that_cannot_be_read_is_named(tmp_path):
    locked = _make_zip(tmp_path / "locked.zip", {"scan.xml": _RESULTS})
    _set_encrypted_flag(locked)
    z = _make_zip(tmp_path / "outer.zip", {
        "good.xml": _RESULTS,
        "broken.zip": b"this is not a zip file",
        "locked.zip": locked.read_bytes(),
    })
    out = tmp_path / "out"
    extraction = extract_from_zip(z, out)
    assert [m.name for m in extraction.members] == ["good.xml"]
    assert extraction.skipped == ["broken.zip is not a readable ZIP — skipped",
                                  "locked.zip is password-protected — skipped"]
    assert [p.suffix for p in out.iterdir()] == [".xml"]


def test_a_member_over_the_size_cap_is_named(tmp_path, monkeypatch):
    import app.utils.zip_extract as zip_extract
    monkeypatch.setattr(zip_extract, "_MAX_EXTRACTED_BYTES", 2048)
    z = _make_zip(tmp_path / "outer.zip", {
        "small.xml": _RESULTS,
        "huge.xml": "<TestResult>" + "<a/>" * 5000 + "</TestResult>",
        "huge_inner.zip": b"PK" + b"0" * 5000,
    })
    out = tmp_path / "out"
    extraction = extract_from_zip(z, out)
    assert [m.name for m in extraction.members] == ["small.xml"]
    assert extraction.skipped == ["huge.xml is larger than the 2048-byte limit — skipped",
                                  "huge_inner.zip is larger than the 2048-byte limit — skipped"]
    assert len(list(out.iterdir())) == 1


def test_the_size_limit_is_stated_in_megabytes_when_it_is_that_large():
    from app.utils.zip_extract import _size_limit
    assert _size_limit(500 * 1024 * 1024) == "500 MB" and _size_limit(2048) == "2048-byte"


def test_legacy_checklists_are_named_and_not_extracted(tmp_path):
    z = _make_zip(tmp_path / "session.zip", {
        "a/OLD-HOST.ckl": "<CHECKLIST/>", "b/renamed.xml": "<CHECKLIST><ASSET/></CHECKLIST>",
        "c/UPPER.CKL": "anything", "good.xml": _RESULTS,
    })
    out = tmp_path / "out"
    extraction = extract_from_zip(z, out)
    assert [m.name for m in extraction.members] == ["good.xml"]
    assert extraction.legacy_checklists == ["OLD-HOST.ckl", "renamed.xml", "UPPER.CKL"]
    assert extraction.skipped == [] and len(list(out.iterdir())) == 1


def test_an_ordinary_long_member_name_is_shown_whole(tmp_path):
    name = "WIN-SERVER-01_SCC-5.14.1_2026-01-15_100000_XCCDF-Results_MS_Windows_Server_2022_STIG-002.003.xml"
    assert len(name) > 80
    z = _make_zip(tmp_path / "session.zip", {name: _RESULTS, name.replace(".xml", ".zip"): b"not a zip"})
    extraction = extract_from_zip(z, tmp_path / "out")
    assert [m.name for m in extraction.members] == [name]
    assert extraction.skipped == [f"{name.replace('.xml', '.zip')} is not a readable ZIP — skipped"]


# --- an archive is bounded, nested archives included ---------------------------------------------


def test_extraction_stops_at_the_member_limit_and_counts_what_was_not_read(tmp_path, monkeypatch):
    monkeypatch.setattr(zip_extract, "_MAX_MEMBERS", 4)
    inner = _make_zip(tmp_path / "inner.zip", {"i1.xml": "<i1/>", "i2.xml": "<i2/>", "i3.cklb": "{}"})
    z = _make_zip(tmp_path / "outer.zip", {
        "a.xml": "<a/>", "b-oval.xml": "<oval_definitions/>", "b.xml": "<b/>", "nested/inner.zip": inner.read_bytes(),
        "c.cklb": "{}", "d.7z": "x", "OLD.ckl": "<CHECKLIST/>", "notes.pdf": "x",
    })
    out = tmp_path / "out"
    extraction = extract_from_zip(z, out)
    # a, b, the nested archive and i1 are four (an ancillary file is never extracted). Not read: i2 and
    # i3 inside, and after it c.cklb, d.7z and OLD.ckl (a PDF would not have been read anyway).
    assert [m.name for m in extraction.members] == ["a.xml", "b.xml", "i1.xml"]
    assert (extraction.limit, extraction.not_read) == ("member", 5)
    assert sorted(p.path for p in extraction.members) == sorted(out.iterdir())     # nothing else left on disk


def test_extraction_stops_at_the_size_limit_while_streaming_and_removes_the_partial_member(tmp_path, monkeypatch):
    # Checklists, which are not sniffed: what is charged is what is extracted.
    monkeypatch.setattr(zip_extract, "_MAX_ARCHIVE_BYTES", 1500)
    z = _make_zip(tmp_path / "big.zip", {"a.cklb": "{" + "x" * 1000 + "}", "b.cklb": "{" + "y" * 1000 + "}",
                                         "c.cklb": "{}"})
    out = tmp_path / "out"
    extraction = extract_from_zip(z, out)
    assert [m.name for m in extraction.members] == ["a.cklb"]
    assert (extraction.limit, extraction.not_read) == ("size", 2)     # b, cut off part way, and c
    assert list(out.iterdir()) == [extraction.members[0].path]


def test_a_nested_archive_spends_the_size_budget_of_the_archive_supplied(tmp_path, monkeypatch):
    inner = _make_zip(tmp_path / "inner.zip", {"b.xml": "<b>" + "y" * 1000 + "</b>"})
    z = _make_zip(tmp_path / "outer.zip", {"a.xml": "<a>" + "x" * 1000 + "</a>", "inner.zip": inner.read_bytes(),
                                           "c.xml": "<c/>"})
    # Room for a.xml and the nested archive itself, not for what is inside it.
    monkeypatch.setattr(zip_extract, "_MAX_ARCHIVE_BYTES", 1007 + inner.stat().st_size + 10)
    extraction = extract_from_zip(z, tmp_path / "out")
    assert [m.name for m in extraction.members] == ["a.xml"]
    assert (extraction.limit, extraction.not_read) == ("size", 2)


def test_an_archive_within_the_limits_is_read_whole(tmp_path):
    z = _make_zip(tmp_path / "small.zip", {f"m{i}.xml": f"<m{i}/>" for i in range(20)})
    extraction = extract_from_zip(z, tmp_path / "out")
    assert len(extraction.members) == 20 and (extraction.limit, extraction.not_read) == ("", 0)


def test_archives_of_another_format_are_listed_not_read(tmp_path):
    inner = _make_zip(tmp_path / "inner.zip", {"deep.XZ": "x"})
    z = _make_zip(tmp_path / "outer.zip", {
        "scan.xml": "<a/>", "hostB.7z": "x", "hostC.TAR.GZ": "x", "hostD.rar": "x", "e.tar": "x", "f.tgz": "x",
        "g.bz2": "x", "inner.zip": inner.read_bytes(), "h.txt": "x",
    })
    extraction = extract_from_zip(z, tmp_path / "out")
    assert extraction.other_archives == [
        "hostB.7z", "hostC.TAR.GZ", "hostD.rar", "e.tar", "f.tgz", "g.bz2", "deep.XZ"]
    assert [m.name for m in extraction.members] == ["scan.xml"]



# --- the sniff for ancillary XML is bounded and charged ---------------------------------------------

_OVAL_ROOT = '<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"/>'
_PADDING = {"whitespace": " " * (1024 * 1024), "comments": "<!--x-->" * (128 * 1024), "PIs": "<?p x?>" * (150 * 1024)}


def _padded(kind: str) -> str:
    """An OVAL document whose root comes only after about 1 MB of *kind* padding."""
    return '<?xml version="1.0"?>\n' + _PADDING[kind] + _OVAL_ROOT


@pytest.mark.parametrize("kind", sorted(_PADDING))
def test_the_sniff_stops_after_64_kib_without_a_start_tag_and_is_charged(tmp_path, kind):
    z = _make_zip(tmp_path / "padded.zip", {"checks.xml": _padded(kind), "oval.xml": _OVAL_ROOT})
    with zipfile.ZipFile(z) as zf:
        padded, plain = zf.infolist()
        budget = zip_extract.Budget(members=10, bytes=10 ** 9)
        assert zip_extract._member_kind(zf, padded, "checks.xml", (budget,)) == ("candidate", 64 * 1024)
        assert 10 ** 9 - budget.bytes == 64 * 1024
        budget = zip_extract.Budget(members=10, bytes=10 ** 9)
        assert zip_extract._member_kind(zf, plain, "oval.xml", (budget,)) == ("ancillary", len(_OVAL_ROOT))
        assert 10 ** 9 - budget.bytes == len(_OVAL_ROOT)


@pytest.mark.parametrize("kind", sorted(_PADDING))
def test_a_padded_member_is_extracted_and_charged_like_any_other(tmp_path, monkeypatch, kind):
    # 512 KiB for the archive: the sniff takes 64 KiB, extracting the padded member the rest, and the
    # scan after it is not read. Unbounded and uncharged, the sniff read all of it and the scan was read.
    monkeypatch.setattr(zip_extract, "_MAX_ARCHIVE_BYTES", 512 * 1024)
    z = _make_zip(tmp_path / "padded.zip", {"checks.xml": _padded(kind), "scan.xml": _RESULTS})
    out = tmp_path / "out"
    extraction = extract_from_zip(z, out)
    assert extraction.members == [] and (extraction.limit, extraction.not_read) == ("size", 2)
    assert list(out.iterdir()) == []


# --- one run has a budget of its own ----------------------------------------------------------------

def test_archives_of_one_run_share_its_budget(tmp_path):
    run = zip_extract.Budget(members=3, bytes=10 ** 9)
    first = extract_from_zip(_make_zip(tmp_path / "one.zip", {"a.xml": "<a/>", "b.xml": "<b/>"}), tmp_path / "out",
                             run=run)
    second = extract_from_zip(_make_zip(tmp_path / "two.zip", {"c.xml": "<c/>", "d.xml": "<d/>"}), tmp_path / "out",
                              run=run)
    assert [m.name for m in first.members] == ["a.xml", "b.xml"] and first.limit == ""
    assert [m.name for m in second.members] == ["c.xml"] and (second.limit, second.not_read) == ("member", 1)
    assert run.spent



def test_a_member_only_sniffed_counts_against_the_run_too(tmp_path):
    run = zip_extract.Budget(members=3, bytes=10 ** 9)
    ovals = {f"o{i}.xml": _OVAL_ROOT for i in range(5)}
    extraction = extract_from_zip(_make_zip(tmp_path / "ovals.zip", ovals), tmp_path / "out", run=run)
    assert extraction.members == [] and (extraction.limit, extraction.not_read) == ("member", 2)
    assert run.spent


def test_a_member_named_as_ancillary_is_not_opened_and_does_not_count(tmp_path, monkeypatch):
    monkeypatch.setattr(zip_extract, "_MAX_MEMBERS", 1)
    z = _make_zip(tmp_path / "bundle.zip", {f"U_X_{i}-oval.xml": _OVAL_ROOT for i in range(5)} | {"scan.xml": _RESULTS})
    extraction = extract_from_zip(z, tmp_path / "out")
    assert [m.name for m in extraction.members] == ["scan.xml"] and extraction.limit == ""



# --- a member may not be larger than a loose upload --------------------------------------------------

def test_a_member_a_loose_upload_of_its_size_could_not_be_is_not_read(tmp_path):
    # Just over the 200 MB a loose file may be: zeros, so the archive stays small.
    from app.core.uploads import reject_size
    size = 200 * 1024 * 1024 + 1
    z = tmp_path / "big.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("scan.xml", _RESULTS)
        with zf.open("big.cklb", "w") as member:
            block = bytes(1024 * 1024)
            for _ in range(200):
                member.write(block)
            member.write(b"{")
    assert reject_size("big.cklb", size) is not None          # the upload limit refuses it loose
    out = tmp_path / "out"
    extraction = extract_from_zip(z, out)
    assert [m.name for m in extraction.members] == ["scan.xml"]
    assert extraction.skipped == ["big.cklb is larger than the 200 MB limit — skipped"]
    assert sorted(out.iterdir()) == [extraction.members[0].path]


def test_a_member_over_the_loose_upload_cap_is_skipped_and_the_rest_read(tmp_path, monkeypatch):
    # The cap lowered to keep the test small: a member larger than one loose file may be is not read.
    monkeypatch.setattr(zip_extract, "_MAX_EXTRACTED_BYTES", 4096)
    flat = "<TestResult>" + "<a/>" * 2000 + "</TestResult>"
    z = _make_zip(tmp_path / "flat.zip", {"results.xml": flat, "scan.xml": _RESULTS})
    extraction = extract_from_zip(z, tmp_path / "out")
    assert [m.name for m in extraction.members] == ["scan.xml"]
    assert extraction.skipped == ["results.xml is larger than the 4096-byte limit — skipped"]



# --- no archive raises; an oversized central directory is refused ------------------------------------


def _zip_bytes(members: dict[str, str], method: int = zipfile.ZIP_STORED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as zf:
        for name, text in members.items():
            zf.writestr(name, text)
    return buf.getvalue()


def _corrupt_first_member(data: bytes, name: str) -> bytes:
    """*data* with 40 bytes of its first member's compressed stream flipped."""
    out = bytearray(data)
    start = 30 + len(name) + 40
    for i in range(start, start + 40):
        out[i] ^= 0x5A
    return bytes(out)


def _skipped_and_cleaned(tmp_path, data: bytes) -> list[str]:
    z = tmp_path / "damaged.zip"
    z.write_bytes(data)
    out = tmp_path / "out"
    extraction = extract_from_zip(z, out)
    assert [m.name for m in extraction.members] == ["scan.xml"]
    assert sorted(out.iterdir()) == [extraction.members[0].path]        # no partial file is left
    return extraction.skipped


def test_a_corrupt_lzma_member_is_skipped_and_named(tmp_path):
    data = _corrupt_first_member(_zip_bytes({"bad.xml": _RESULTS * 50, "scan.xml": _RESULTS}, zipfile.ZIP_LZMA),
                                 "bad.xml")
    assert _skipped_and_cleaned(tmp_path, data) == ["could not read bad.xml: Corrupt input data — skipped"]


def test_a_corrupt_zstandard_member_is_skipped_and_named(tmp_path):
    pytest.importorskip("compression.zstd")             # Python 3.14 and later
    data = _corrupt_first_member(
        _zip_bytes({"bad.xml": _RESULTS * 50, "scan.xml": _RESULTS}, zipfile.ZIP_ZSTANDARD), "bad.xml")
    skipped = _skipped_and_cleaned(tmp_path, data)
    assert len(skipped) == 1
    assert re.fullmatch(r"could not read bad\.xml: Unable to decompress Zstandard data: .+ — skipped", skipped[0])


def _with_central_entry(data: bytes, change) -> bytes:
    out = bytearray(data)
    change(out, out.find(b"PK\x01\x02"))
    return bytes(out)


def test_an_archive_that_needs_a_newer_zip_version_is_not_read(tmp_path):
    data = _with_central_entry(_zip_bytes({"scan.xml": _RESULTS}),
                               lambda out, cd: struct.pack_into("<H", out, cd + 6, 64))     # version needed: 6.4
    z = tmp_path / "v64.zip"
    z.write_bytes(data)
    assert extract_from_zip(z, tmp_path / "out").unreadable == "not a readable ZIP — not read"


def test_an_archive_whose_utf8_flagged_name_is_not_utf8_is_not_read(tmp_path):
    def change(out, cd):
        struct.pack_into("<H", out, cd + 8, struct.unpack_from("<H", out, cd + 8)[0] | 0x800)
        out[cd + 46:cd + 50] = b"\xff\xfe\xfd\xfc"
    z = tmp_path / "names.zip"
    z.write_bytes(_with_central_entry(_zip_bytes({"abcd.xml": _RESULTS}), change))
    assert extract_from_zip(z, tmp_path / "out").unreadable == "not a readable ZIP — not read"


def _as_zip64(data: bytes, classic: tuple[int, int] = (0xFFFF, 0xFFFFFFFF)) -> bytes:
    """*data* with its end of central directory written the ZIP64 way: the counts in a ZIP64 end
    record, the classic record holding *classic* (entries, directory size) in their place."""
    eocd = data.rfind(b"PK\x05\x06")
    _sig, _disk, _cd_disk, on_disk, total, cd_size, cd_offset, _comment = struct.unpack_from("<4s4H2LH", data, eocd)
    record = struct.pack("<4sQ2H2L4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, on_disk, total, cd_size, cd_offset)
    locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, eocd, 1)
    end = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, classic[0], classic[0], classic[1], 0xFFFFFFFF, 0)
    return data[:eocd] + record + locator + end


def _count_entries_built(monkeypatch) -> list[int]:
    """Every entry the ZIP reader builds from here on, counted: a refused archive builds none."""
    built: list[int] = []

    class Counted(zipfile.ZipInfo):
        __slots__ = ()

        def __init__(self, *args, **kwargs) -> None:
            built.append(1)
            super().__init__(*args, **kwargs)
    monkeypatch.setattr(zipfile, "ZipInfo", Counted)
    return built


def test_an_archive_with_too_many_entries_is_not_opened(tmp_path, monkeypatch):
    monkeypatch.setattr(zip_extract, "_MAX_ENTRIES", 3)
    members = {f"m{i}.xml": f"<m{i}/>" for i in range(5)}
    z = tmp_path / "many.zip"
    z.write_bytes(_zip_bytes(members))
    built = _count_entries_built(monkeypatch)
    extraction = extract_from_zip(z, tmp_path / "out")
    assert extraction.unreadable == "more than 3 entries — not read" and extraction.members == []
    assert built == []                                   # refused before the reader built a thing
    nested = _make_zip(tmp_path / "outer.zip", {"inner.zip": z.read_bytes(), "scan.xml": _RESULTS})
    extraction = extract_from_zip(nested, tmp_path / "out2")
    assert [m.name for m in extraction.members] == ["scan.xml"]
    assert extraction.skipped == ["inner.zip has more than 3 entries — skipped"]


def test_the_entry_count_of_a_zip64_archive_is_read_from_its_zip64_end_record(tmp_path, monkeypatch):
    z = tmp_path / "zip64.zip"
    z.write_bytes(_as_zip64(_zip_bytes({f"m{i}.xml": f"<m{i}/>" for i in range(5)})))
    with zipfile.ZipFile(z) as zf:
        assert len(zf.infolist()) == 5                  # a valid archive
    monkeypatch.setattr(zip_extract, "_MAX_ENTRIES", 4)
    assert extract_from_zip(z, tmp_path / "a").unreadable == "more than 4 entries — not read"
    monkeypatch.setattr(zip_extract, "_MAX_ENTRIES", 5)
    # The classic record says 0xFFFF; the archive holds five entries and is read.
    assert len(extract_from_zip(z, tmp_path / "b").members) == 5


def test_the_entry_list_size_of_a_zip64_archive_is_read_from_its_zip64_end_record(tmp_path, monkeypatch):
    z = tmp_path / "zip64.zip"
    z.write_bytes(_as_zip64(_zip_bytes({f"m{i}.xml": f"<m{i}/>" for i in range(5)})))     # 5 x 52 bytes
    monkeypatch.setattr(zip_extract, "_MAX_ENTRIES", 5)
    monkeypatch.setattr(zip_extract, "_DIRECTORY_BYTES_PER_ENTRY", 52)
    assert len(extract_from_zip(z, tmp_path / "a").members) == 5     # the classic record's 0xFFFFFFFF is not the size
    monkeypatch.setattr(zip_extract, "_DIRECTORY_BYTES_PER_ENTRY", 51)
    assert extract_from_zip(z, tmp_path / "b").unreadable == "entry list over 255 bytes — not read"


def test_a_malformed_end_record_is_left_to_the_zip_reader(tmp_path):
    z = tmp_path / "bad_end.zip"
    z.write_bytes(_zip_bytes({"scan.xml": _RESULTS})[:-5])       # the end record cut short
    assert extract_from_zip(z, tmp_path / "out").unreadable == "not a readable ZIP — not read"



# --- classification polls for cancellation; sniffed bytes are charged once; names keep their extension --

class _Cancelled(Exception):
    pass


def _cancel_on(call: int):
    calls = []

    def check() -> None:
        calls.append(1)
        if len(calls) >= call:
            raise _Cancelled
    return check, calls


def test_extraction_polls_for_cancellation_per_member_nested_archives_too(tmp_path):
    inner = _make_zip(tmp_path / "inner.zip", {f"i{i}.xml": f"<i{i}/>" for i in range(5)})
    z = _make_zip(tmp_path / "outer.zip", {"a.xml": "<a/>", "inner.zip": inner.read_bytes(),
                                           **{f"m{i}.xml": f"<m{i}/>" for i in range(5)}})
    check, calls = _cancel_on(4)
    out = tmp_path / "out"
    with pytest.raises(_Cancelled):
        extract_from_zip(z, out, cancel_check=check)
    # a.xml, the nested archive, i0: the fourth poll comes at i1, inside the nested archive.
    assert len(calls) == 4
    assert len([p for p in out.iterdir() if p.suffix == ".xml"]) == 2


def test_a_member_just_under_the_budget_is_not_refused_because_of_its_sniff(tmp_path, monkeypatch):
    member = "<a>" + "x" * 1000 + "</a>"
    monkeypatch.setattr(zip_extract, "_MAX_ARCHIVE_BYTES", len(member) + 10)
    extraction = extract_from_zip(_make_zip(tmp_path / "one.zip", {"a.xml": member}), tmp_path / "out")
    assert [m.name for m in extraction.members] == ["a.xml"] and extraction.limit == ""


def test_a_long_member_name_keeps_its_extension(tmp_path):
    extraction = extract_from_zip(_make_zip(tmp_path / "one.zip", {"n" * 300 + ".xml": _RESULTS}), tmp_path / "out")
    assert [m.name for m in extraction.members] == ["…" + "n" * 250 + ".xml"]



# --- pins for behaviour the mutation run found unpinned ------------------------------------------------

def test_a_nested_archive_spends_the_run_budget_too(tmp_path):
    inner = _make_zip(tmp_path / "inner.zip", {"b.xml": "<b>" + "y" * 1000 + "</b>"})
    z = _make_zip(tmp_path / "outer.zip", {"a.xml": "<a>" + "x" * 1000 + "</a>", "inner.zip": inner.read_bytes()})
    run = zip_extract.Budget(members=100, bytes=1007 + inner.stat().st_size + 10)
    extraction = extract_from_zip(z, tmp_path / "out", run=run)
    assert [m.name for m in extraction.members] == ["a.xml"] and extraction.limit == "size"
    assert run.spent


def test_a_sniff_that_spends_the_budget_stops_the_archive_even_on_an_ancillary_member(tmp_path, monkeypatch):
    # The sniff of a.xml reads all 1,000-odd bytes and finds OVAL: nothing is extracted, yet the budget
    # is spent, so b.xml is not even sniffed.
    monkeypatch.setattr(zip_extract, "_MAX_ARCHIVE_BYTES", 500)
    padded_oval = _OVAL_ROOT + "<!--" + "p" * 1000 + "-->"
    extraction = extract_from_zip(_make_zip(tmp_path / "ovals.zip", {"a.xml": padded_oval, "b.xml": _OVAL_ROOT}),
                                  tmp_path / "out")
    assert extraction.members == [] and (extraction.limit, extraction.not_read) == ("size", 2)


def test_a_limit_a_nested_archive_reaches_is_the_supplied_archives(tmp_path, monkeypatch, caplog):
    import logging
    monkeypatch.setattr(zip_extract, "_MAX_MEMBERS", 2)
    inner = _make_zip(tmp_path / "inner.zip", {"i1.xml": "<i1/>", "i2.xml": "<i2/>"})
    z = _make_zip(tmp_path / "outer.zip", {"inner.zip": inner.read_bytes(), "c.xml": "<c/>"})
    with caplog.at_level(logging.WARNING, logger="app"):
        extraction = extract_from_zip(z, tmp_path / "out")
    # The Extraction carries it once, for the caller to name under the archive supplied.
    assert (extraction.limit, extraction.not_read) == ("member", 2)
    assert caplog.records == []



def test_a_partial_file_is_removed_after_a_member_read_error(tmp_path):
    # A checklist is not sniffed: the damaged stream is met while the member is being written.
    data = _corrupt_first_member(_zip_bytes({"bad.cklb": '{"stigs": []}' * 2000, "scan.xml": _RESULTS},
                                            zipfile.ZIP_DEFLATED), "bad.cklb")
    assert _skipped_and_cleaned(tmp_path, data) == ["could not read bad.cklb: Bad CRC-32 for file 'bad.cklb' — skipped"]



def _with_entry_count(data: bytes, count: int) -> bytes:
    """*data* with its end record claiming *count* entries, whatever its central directory holds."""
    out = bytearray(data)
    eocd = out.rfind(b"PK\x05\x06")
    struct.pack_into("<2H", out, eocd + 8, count, count)
    return bytes(out)


def test_an_archive_whose_end_record_understates_its_entries_is_refused_by_its_directory_size(tmp_path, monkeypatch):
    # The ZIP reader builds an entry for every record in the central directory, whatever count the
    # end record gives: one that says 1 over 1,000 records must be refused by the directory's size.
    monkeypatch.setattr(zip_extract, "_MAX_ENTRIES", 100)          # a directory of at most 16,000 bytes
    z = tmp_path / "lying.zip"
    z.write_bytes(_with_entry_count(_zip_bytes({f"d/m{i:04d}.xml": "<a/>" for i in range(1000)}), 1))
    built = _count_entries_built(monkeypatch)
    extraction = extract_from_zip(z, tmp_path / "out")
    assert extraction.unreadable == "entry list over 16,000 bytes — not read" and extraction.members == []
    assert built == []                                   # refused before the reader built a thing


def test_a_nested_archive_with_an_oversized_entry_list_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(zip_extract, "_MAX_ENTRIES", 100)
    inner = _with_entry_count(_zip_bytes({f"m{i:04d}.xml": "<a/>" for i in range(1000)}), 1)
    z = _make_zip(tmp_path / "outer.zip", {"inner.zip": inner, "scan.xml": _RESULTS})
    extraction = extract_from_zip(z, tmp_path / "out")
    assert [m.name for m in extraction.members] == ["scan.xml"]
    assert extraction.skipped == ["inner.zip has an entry list over 16,000 bytes — skipped"]


def test_an_archive_whose_short_entries_fit_the_size_limit_is_refused_by_its_record_count(tmp_path, monkeypatch):
    # 200 records of 54 bytes fit 16,000 bytes; the end record says 1; the reader would build 200.
    monkeypatch.setattr(zip_extract, "_MAX_ENTRIES", 100)
    z = tmp_path / "short.zip"
    z.write_bytes(_with_entry_count(_zip_bytes({f"m{i:03d}.xml": "<a/>" for i in range(200)}), 1))
    built = _count_entries_built(monkeypatch)
    extraction = extract_from_zip(z, tmp_path / "out")
    assert extraction.unreadable == "more than 100 entries — not read" and extraction.members == []
    assert built == []


@pytest.mark.parametrize("chunk", [1, 3, 4, 5, 7, 54, 1 << 20])
def test_records_are_counted_exactly_across_read_edges(tmp_path, monkeypatch, chunk):
    # Whatever reads the reader asks for, each directory record is counted once: one split
    # between two reads still counts, and one read twice counts once.
    plain = _zip_bytes({f"m{i:03d}.xml": "<a/>" for i in range(40)})
    for name, data in (("plain.zip", _with_entry_count(plain, 1)),
                       ("zip64.zip", _with_zip64_entry_count(_as_zip64(plain), 1))):
        z = tmp_path / name
        z.write_bytes(data)                         # both say 1 entry: only the count can refuse them
        for limit, refusal in ((40, None), (39, "more than 39 entries — not read")):
            monkeypatch.setattr(zip_extract, "_MAX_ENTRIES", limit)
            with z.open("rb") as raw:
                guard = zip_extract._GuardedFile(raw)
                try:
                    for _ in range(2):              # the whole file, twice
                        guard.seek(0)
                        while guard.read(chunk):
                            pass
                    outcome = None
                except zipfile.BadZipFile as exc:
                    outcome = str(exc)
            assert outcome == refusal, (name, chunk, limit)


def test_the_reads_together_are_bounded_too(tmp_path, monkeypatch):
    # However the reader splits its reads, together they may not pass the directory's cap and
    # what finding the end record takes.
    monkeypatch.setattr(zip_extract, "_MAX_ENTRIES", 1)                 # a 160-byte directory
    z = tmp_path / "a.zip"
    z.write_bytes(b"x" * 1000)
    reads = 0
    with z.open("rb") as raw:
        guard = zip_extract._GuardedFile(raw)
        with pytest.raises(zipfile.BadZipFile, match="^entry list over 160 bytes — not read$"):
            for _ in range(10_000):                     # far more than the budget allows
                guard.seek(0)
                guard.read(100)
                reads += 1
    assert reads * 100 <= 160 + zip_extract._END_RECORD_READS < (reads + 1) * 100


def test_member_reads_are_not_counted_as_the_entry_list(tmp_path, monkeypatch):
    # A stored nested archive holds directory records of its own: reading it out of its parent
    # is not reading the parent's entry list.
    monkeypatch.setattr(zip_extract, "_MAX_ENTRIES", 2)
    inner = _make_zip(tmp_path / "inner.zip", {"i1.xml": "<i1/>", "i2.xml": "<i2/>"})
    z = _make_zip(tmp_path / "outer.zip", {"inner.zip": inner.read_bytes(), "a.xml": "<a/>"})
    extraction = extract_from_zip(z, tmp_path / "out")
    assert sorted(m.name for m in extraction.members) == ["a.xml", "i1.xml", "i2.xml"]
    assert (extraction.unreadable, extraction.skipped) == ("", [])


def _with_zip64_entry_count(data: bytes, count: int) -> bytes:
    """*data*, a ZIP64 archive, with its ZIP64 end record claiming *count* entries."""
    out = bytearray(data)
    struct.pack_into("<2Q", out, out.rfind(b"PK\x06\x06") + 24, count, count)
    return bytes(out)


def test_a_zip64_record_is_what_counts_whatever_the_classic_record_says(tmp_path, monkeypatch):
    # The ZIP reader takes the ZIP64 record whenever its locator is there, not only behind
    # 0xFFFF placeholders: a classic record saying 1 entry of 46 bytes must not hide it.
    monkeypatch.setattr(zip_extract, "_MAX_ENTRIES", 40)
    z = tmp_path / "zip64.zip"
    z.write_bytes(_as_zip64(_zip_bytes({f"m{i:03d}.xml": "<a/>" for i in range(50)}), classic=(1, 46)))
    with zipfile.ZipFile(z) as zf:
        assert len(zf.infolist()) == 50                 # what the reader would build
    built = _count_entries_built(monkeypatch)
    assert extract_from_zip(z, tmp_path / "out").unreadable == "more than 40 entries — not read"
    assert built == []


def test_an_end_record_holding_its_own_signature_is_read_where_the_reader_reads_it(tmp_path, monkeypatch):
    # A directory offset of 0x06054B50 puts the end record's signature inside the end record:
    # the last match in the archive's tail is then not the record the reader uses.
    monkeypatch.setattr(zip_extract, "_MAX_ENTRIES", 40)
    data = bytearray(_with_entry_count(_zip_bytes({f"m{i:03d}.xml": "<a/>" for i in range(50)}), 1))
    struct.pack_into("<L", data, data.rfind(b"PK\x05\x06") + 16, 0x06054B50)
    z = tmp_path / "inner_signature.zip"
    z.write_bytes(bytes(data))
    with zipfile.ZipFile(z) as zf:
        assert len(zf.infolist()) == 50                 # what the reader would build
    assert extract_from_zip(z, tmp_path / "out").unreadable == "more than 40 entries — not read"


def _with_comment(data: bytes) -> bytes:
    """*data* with an archive comment after its end record: the reader then searches the last
    64 KiB of the archive for the end record, and reads part of the directory twice."""
    out = bytearray(data)
    struct.pack_into("<H", out, out.rfind(b"PK\x05\x06") + 20, 9)
    return bytes(out) + b"a comment"


def _prepended(data: bytes) -> bytes:
    """*data* behind 300 bytes of something else, as a self-extracting archive is."""
    return b"MZ" + b"\0" * 298 + data


@pytest.mark.parametrize("shape", ["comment", "prepended", "zip64 comment", "zip64 prepended"])
def test_an_archive_with_a_comment_or_prepended_data_is_counted_exactly(tmp_path, monkeypatch, shape):
    data = _zip_bytes({f"m{i:03d}.xml": "<a/>" for i in range(40)})
    data = _with_entry_count(data, 1) if "zip64" not in shape else _with_zip64_entry_count(_as_zip64(data), 1)
    data = _with_comment(data) if shape.endswith("comment") else _prepended(data)
    z = tmp_path / "shaped.zip"
    z.write_bytes(data)
    with zipfile.ZipFile(z) as zf:
        assert len(zf.infolist()) == 40                 # what the reader would build
    monkeypatch.setattr(zip_extract, "_MAX_ENTRIES", 40)
    assert extract_from_zip(z, tmp_path / "a").unreadable == ""                      # none counted twice
    monkeypatch.setattr(zip_extract, "_MAX_ENTRIES", 39)
    assert extract_from_zip(z, tmp_path / "b").unreadable == "more than 39 entries — not read"
    # The directory is 40 records of 54 bytes: a cap of exactly that reads it, whatever else the
    # reader reads to find it (with a comment, the whole of this small archive); one less does not.
    monkeypatch.setattr(zip_extract, "_MAX_ENTRIES", 40)
    monkeypatch.setattr(zip_extract, "_DIRECTORY_BYTES_PER_ENTRY", 54)
    assert extract_from_zip(z, tmp_path / "c").unreadable == ""
    monkeypatch.setattr(zip_extract, "_DIRECTORY_BYTES_PER_ENTRY", 53)
    assert extract_from_zip(z, tmp_path / "d").unreadable == "entry list over 2,120 bytes — not read"


def test_an_ordinary_archive_is_well_inside_the_entry_list_limit(tmp_path):
    z = _make_zip(tmp_path / "ok.zip", {f"d/m{i}.xml": f"<m{i}/>" for i in range(50)})
    assert len(extract_from_zip(z, tmp_path / "out").members) == 50


# --- a full disk ends extraction as a limit -------------------------------------------------------

def test_a_full_disk_stops_the_archive_as_a_size_limit(tmp_path, monkeypatch):
    import errno
    archive = tmp_path / "scans.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for n in range(3):
            zf.writestr(f"scan{n}.xml", f"<TestResult n='{n}'/>")
    real = zip_extract._bounded_extract
    calls = []

    def disk_fills(zf, info, target, budgets, charged=0):
        calls.append(info.filename)
        if len(calls) == 2:
            with target.open("wb") as partial:
                partial.write(b"<Test")
            raise OSError(errno.ENOSPC, "No space left on device")
        return real(zf, info, target, budgets, charged)

    monkeypatch.setattr(zip_extract, "_bounded_extract", disk_fills)
    out = tmp_path / "out"
    extraction = extract_from_zip(archive, out)
    assert [m.name for m in extraction.members] == ["scan0.xml"]
    assert (extraction.limit, extraction.not_read, extraction.skipped) == ("size", 2, [])
    assert calls == ["scan0.xml", "scan1.xml"]                  # nothing more is read
    assert sorted(p.name for p in out.iterdir()) == [extraction.members[0].path.name]   # no partial file left
