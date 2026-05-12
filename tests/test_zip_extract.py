"""Tests for the DISA STIG ZIP extraction utility."""
from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from app.utils.zip_extract import expand_benchmark_paths, extract_xccdf_from_zip

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
        extracted = extract_xccdf_from_zip(zip_path, dest)
        assert len(extracted) == 1
        assert extracted[0].name.endswith("xccdf.xml")
        assert extracted[0].read_text(encoding="utf-8").startswith("<?xml")

    def test_strips_internal_folder_structure(self, tmp_path):
        zip_path = _make_zip(
            tmp_path / "stig.zip",
            {"some/nested/folder/U_RHEL_9_STIG_V1R1_Manual-xccdf.xml": _FAKE_XCCDF},
        )
        dest = tmp_path / "out"
        extracted = extract_xccdf_from_zip(zip_path, dest)
        assert len(extracted) == 1
        # Folder structure flattened — file lives directly in dest
        assert extracted[0].parent == dest
        assert extracted[0].name == "U_RHEL_9_STIG_V1R1_Manual-xccdf.xml"

    def test_returns_empty_when_no_xccdf(self, tmp_path):
        zip_path = _make_zip(
            tmp_path / "stig.zip",
            {"readme.txt": "no xccdf here", "Overview.pdf": b"%PDF"},
        )
        dest = tmp_path / "out"
        extracted = extract_xccdf_from_zip(zip_path, dest)
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
        extracted = extract_xccdf_from_zip(wrapper, dest)
        assert len(extracted) == 1
        assert extracted[0].name == "U_MS_Windows_Server_2022_STIG_V2R8_Manual-xccdf.xml"
        # Nested zip itself is cleaned up
        assert not (dest / "U_MS_Windows_Server_2022_V2R8_STIG.zip").exists()

    def test_handles_filename_collisions(self, tmp_path):
        zip_path = _make_zip(
            tmp_path / "stig.zip",
            {
                "a/Manual-xccdf.xml": "<a/>",
                "b/Manual-xccdf.xml": "<b/>",
            },
        )
        dest = tmp_path / "out"
        extracted = extract_xccdf_from_zip(zip_path, dest)
        assert len(extracted) == 2
        # Both files exist with distinct names
        names = {p.name for p in extracted}
        assert "Manual-xccdf.xml" in names
        assert any(n.startswith("Manual-xccdf_") and n.endswith(".xml") for n in names)

    def test_invalid_zip_returns_empty(self, tmp_path):
        bad = tmp_path / "not-a-zip.zip"
        bad.write_bytes(b"this is not a zip file")
        dest = tmp_path / "out"
        extracted = extract_xccdf_from_zip(bad, dest)
        assert extracted == []

    def test_case_insensitive_xccdf_match(self, tmp_path):
        zip_path = _make_zip(
            tmp_path / "stig.zip",
            {"WEIRD_MIXED_CASE_XCCDF.XML": _FAKE_XCCDF},
        )
        dest = tmp_path / "out"
        extracted = extract_xccdf_from_zip(zip_path, dest)
        assert len(extracted) == 1


class TestExpandBenchmarkPaths:
    def test_xml_paths_pass_through_unchanged(self, tmp_path):
        xml1 = tmp_path / "a.xml"
        xml1.write_text("<x/>")
        xml2 = tmp_path / "b.xml"
        xml2.write_text("<y/>")
        resolved, warnings = expand_benchmark_paths([xml1, xml2], tmp_path / "extract")
        assert resolved == [xml1, xml2]
        assert warnings == []

    def test_zip_paths_get_expanded(self, tmp_path):
        zip_path = _make_zip(
            tmp_path / "stig.zip",
            {"U_Manual-xccdf.xml": _FAKE_XCCDF},
        )
        xml = tmp_path / "extra.xml"
        xml.write_text("<x/>")
        resolved, warnings = expand_benchmark_paths([zip_path, xml], tmp_path / "extract")
        # zip replaced by extracted xml, regular xml passes through
        assert len(resolved) == 2
        assert any(p.name == "U_Manual-xccdf.xml" for p in resolved)
        assert xml in resolved
        assert warnings == []

    def test_empty_zip_produces_warning(self, tmp_path):
        zip_path = _make_zip(tmp_path / "stig.zip", {"readme.txt": "no xml"})
        resolved, warnings = expand_benchmark_paths([zip_path], tmp_path / "extract")
        assert resolved == []
        assert len(warnings) == 1
        assert "stig.zip" in warnings[0]
        assert "No XCCDF" in warnings[0]

    def test_uppercase_zip_extension(self, tmp_path):
        zip_path = _make_zip(
            tmp_path / "STIG.ZIP",
            {"Manual-xccdf.xml": _FAKE_XCCDF},
        )
        resolved, warnings = expand_benchmark_paths([zip_path], tmp_path / "extract")
        assert len(resolved) == 1
        assert resolved[0].name == "Manual-xccdf.xml"
