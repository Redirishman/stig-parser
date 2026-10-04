"""Tests for BenchmarkParser (XCCDF 1.1 STIG benchmark definitions)."""
import time as _time
from pathlib import Path

import pytest
from lxml import etree as _etree

from app.parsers import benchmark_parser as _bpmod
from app.parsers.benchmark_parser import BenchmarkParser
from app.parsers.benchmark_parser import BenchmarkParser as _BP

FIXTURES = Path(__file__).parent / "fixtures"
PARSER = BenchmarkParser()


class TestSampleBenchmark:
    def setup_method(self):
        self.bm = PARSER.read_all(FIXTURES / "sample_benchmark.xml")[0][0]

    def test_parses_successfully(self):
        assert self.bm is not None

    def test_benchmark_id(self):
        assert "MS_Windows_Server_2022_STIG" in self.bm.benchmark_id

    def test_title(self):
        assert "Windows Server 2022" in self.bm.title

    def test_rule_count(self):
        assert len(self.bm.rules) == 7

    def test_cat_i_severity(self):
        rule = self.bm.rules.get("xccdf_mil.disa.stig_rule_SV-254239r945408_rule")
        assert rule is not None
        assert rule.severity == "CAT I"

    def test_cat_ii_severity(self):
        rule = self.bm.rules.get("xccdf_mil.disa.stig_rule_SV-254240r945411_rule")
        assert rule is not None
        assert rule.severity == "CAT II"

    def test_cat_iii_severity(self):
        rule = self.bm.rules.get("xccdf_mil.disa.stig_rule_SV-254242r945417_rule")
        assert rule is not None
        assert rule.severity == "CAT III"

    def test_vuln_id(self):
        rule = self.bm.rules.get("xccdf_mil.disa.stig_rule_SV-254239r945408_rule")
        assert rule.vuln_id == "V-254239"

    def test_check_text_nonempty(self):
        rule = self.bm.rules.get("xccdf_mil.disa.stig_rule_SV-254239r945408_rule")
        assert len(rule.check_text) > 10

    def test_fix_text_nonempty(self):
        rule = self.bm.rules.get("xccdf_mil.disa.stig_rule_SV-254239r945408_rule")
        assert len(rule.fix_text) > 10

    def test_check_text_content(self):
        rule = self.bm.rules.get("xccdf_mil.disa.stig_rule_SV-254239r945408_rule")
        assert "multifactor" in rule.check_text.lower()

    def test_fix_text_content(self):
        rule = self.bm.rules.get("xccdf_mil.disa.stig_rule_SV-254239r945408_rule")
        assert "multifactor" in rule.fix_text.lower() or "Configure" in rule.fix_text


class TestXCCDF12Benchmark:
    """BenchmarkParser must handle XCCDF 1.2 files (SCC result files with inline defs)."""

    def setup_method(self):
        xml = Path(__file__).parent / "_tmp_xccdf12_bench.xml"
        xml.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<cdf:Benchmark xmlns:cdf="http://checklists.nist.gov/xccdf/1.2"'
            '  id="xccdf_mil.disa.stig_benchmark_MS_Defender_Antivirus">'
            '<cdf:title>Microsoft Defender Antivirus STIG SCAP Benchmark</cdf:title>'
            '<cdf:Group id="xccdf_mil.disa.stig_group_V-213426">'
            '  <cdf:title>SRG-APP-000279</cdf:title>'
            '  <cdf:Rule id="xccdf_mil.disa.stig_rule_SV-213426r961197_rule"'
            '    weight="10.0" severity="high">'
            '    <cdf:version>WNDF-AV-000001</cdf:version>'
            '    <cdf:title>Defender AV must block PUA.</cdf:title>'
            '    <cdf:fixtext fixref="F-1">Set PUAProtection to Enabled and Block.</cdf:fixtext>'
            '    <cdf:fix id="F-1"/>'
            '  </cdf:Rule>'
            '</cdf:Group>'
            '<cdf:Group id="xccdf_mil.disa.stig_group_V-213427">'
            '  <cdf:Rule id="xccdf_mil.disa.stig_rule_SV-213427r961197_rule"'
            '    severity="medium">'
            '    <cdf:fixtext>Disable routine remediation policy.</cdf:fixtext>'
            '  </cdf:Rule>'
            '</cdf:Group>'
            '</cdf:Benchmark>',
            encoding="utf-8",
        )
        self.path = xml
        self.bm = PARSER.read_all(xml)[0][0]

    def teardown_method(self):
        self.path.unlink(missing_ok=True)

    def test_parses_successfully(self):
        assert self.bm is not None

    def test_benchmark_id(self):
        assert "MS_Defender_Antivirus" in self.bm.benchmark_id

    def test_title(self):
        assert "Defender Antivirus" in self.bm.title

    def test_rule_count(self):
        assert len(self.bm.rules) == 2

    def test_vuln_id_stripped_from_qualified_group_id(self):
        rule = self.bm.rules.get("xccdf_mil.disa.stig_rule_SV-213426r961197_rule")
        assert rule is not None
        assert rule.vuln_id == "V-213426"

    def test_severity_high(self):
        rule = self.bm.rules.get("xccdf_mil.disa.stig_rule_SV-213426r961197_rule")
        assert rule.severity == "CAT I"

    def test_severity_medium(self):
        rule = self.bm.rules.get("xccdf_mil.disa.stig_rule_SV-213427r961197_rule")
        assert rule.severity == "CAT II"

    def test_fix_text(self):
        rule = self.bm.rules.get("xccdf_mil.disa.stig_rule_SV-213426r961197_rule")
        assert "PUAProtection" in rule.fix_text


class TestEdgeCases:
    def test_invalid_xml_returns_nothing_and_says_why(self, tmp_path):
        bad = tmp_path / "bad.xml"
        bad.write_text("<broken", encoding="utf-8")
        found, why = PARSER.read_all(bad)
        assert found == [] and why.startswith("invalid XML: ")

    def test_empty_benchmark_returns_object_with_no_rules(self, tmp_path):
        xml = tmp_path / "empty.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="empty_benchmark">'
            '<title>Empty Test</title>'
            '</Benchmark>',
            encoding="utf-8",
        )
        result = PARSER.read_all(xml)[0][0]
        assert result is not None
        assert result.benchmark_id == "empty_benchmark"
        assert result.title == "Empty Test"
        assert len(result.rules) == 0


# --- reference enrichment: parse_all, STIG ID, release ---
_FIX = Path(__file__).parent / "fixtures"


class TestParseAllAndNewFields:
    def test_manual_stig_rules_carry_stig_id_and_release(self):
        bm = _BP().read_all(_FIX / "manual_stig_win11.xml")[0][0]
        assert bm.release == "V2R9"
        assert bm.rules["SV-253284r958928_rule"].stig_id == "WN11-00-000150"

    def test_scap_release_label(self):
        bm = _BP().read_all(_FIX / "scc_embedded_results.xml")[0][0]
        assert bm.release == "V2R8"

    def test_parse_all_finds_a_benchmark_inside_a_datastream(self):
        found = _BP().read_all(_FIX / "scap_datastream_win11.xml")[0]
        assert len(found) == 1
        assert found[0].benchmark_id == "xccdf_mil.disa.stig_benchmark_Microsoft_Windows_11_STIG"
        assert list(found[0].rules) == ["xccdf_mil.disa.stig_rule_SV-253284r958928_rule"]
        assert found[0].rules["xccdf_mil.disa.stig_rule_SV-253284r958928_rule"].fix_text

    def test_parse_all_returns_empty_for_results_without_a_benchmark(self):
        assert _BP().read_all(_FIX / "evaluate_stig_results.xml")[0] == []

    def test_parse_all_returns_empty_on_invalid_xml(self, tmp_path):
        bad = tmp_path / "bad.xml"
        bad.write_text("<Benchmark", encoding="utf-8")
        assert _BP().read_all(bad)[0] == []

    def test_parse_still_returns_first_benchmark(self):
        assert _BP().read_all(_FIX / "scap_datastream_win11.xml")[0][0].rules


# --- nested groups, duplicates, Benchmark discovery, hostile XML ---
_X11 = 'xmlns="http://checklists.nist.gov/xccdf/1.1"'
_XXE_MARKER = "TOP-SECRET-MARKER-12345"


def _write_xml(tmp_path, body, name="b.xml"):
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def _parsed_text(benchmarks):
    """Every string field the parser produced, for leak assertions."""
    texts = []
    for bm in benchmarks:
        texts += [bm.benchmark_id, bm.title, bm.release]
        for rule in bm.rules.values():
            texts += [
                rule.vuln_id, rule.rule_id, rule.severity,
                rule.stig_id, rule.check_text, rule.fix_text,
            ]
    return texts


def _xxe_document(tmp_path):
    """A valid benchmark whose element text references an external entity.

    The entity is used in element text only (never in attributes), so the
    document is well-formed and the parser reads it. A parser that resolves
    external entities would copy the secret file into the parsed fields.
    """
    secret = tmp_path / "secret.txt"
    secret.write_text(_XXE_MARKER, encoding="utf-8")
    return _write_xml(tmp_path, f'''<?xml version="1.0"?>
<!DOCTYPE Benchmark [<!ENTITY xxe SYSTEM "{secret.as_uri()}">]>
<Benchmark {_X11} id="xxe-test">
  <title>Title &xxe;</title>
  <plain-text id="release-info">Release: 4 &xxe;</plain-text>
  <version>2</version>
  <Group id="V-1">
    <Rule id="SV-1r1_rule" severity="high">
      <version>WN11-00-000150</version>
      <fixtext>Fix &xxe;</fixtext>
      <check system="c"><check-content>Check &xxe;</check-content></check>
    </Rule>
  </Group>
</Benchmark>''', name="xxe.xml")


def _nested_groups_document(levels, rules_per_level):
    """One Benchmark with ``levels`` nested Groups, each holding some rules."""
    parts = [f'<Benchmark {_X11} id="deep">']
    n = 0
    for level in range(levels):
        parts.append(f'<Group id="V-{level}">')
        for _ in range(rules_per_level):
            parts.append(f'<Rule id="SV-{n}r1_rule" severity="low"><fixtext>f</fixtext></Rule>')
            n += 1
    parts.append("</Group>" * levels)
    parts.append("</Benchmark>")
    return "".join(parts)


def _nested_benchmarks_document(levels, rules_per_level):
    """``levels`` Benchmarks nested one inside the next, each with its own rules."""
    parts = []
    n = 0
    for level in range(levels):
        parts.append(f'<Benchmark {_X11} id="b{level}"><Group id="V-{level}">')
        for _ in range(rules_per_level):
            parts.append(f'<Rule id="SV-{n}r1_rule"/>')
            n += 1
        parts.append("</Group>")
    parts.append("</Benchmark>" * levels)
    return "".join(parts)


class TestBenchmarkDiscovery:
    def test_two_sibling_benchmarks_in_a_wrapper_are_both_found_in_order(self, tmp_path):
        path = _write_xml(tmp_path, f'''<?xml version="1.0"?>
<wrapper {_X11}>
  <Benchmark id="first"><title>One</title>
    <Group id="V-1"><Rule id="SV-1r1_rule" severity="high"><version>A-1</version></Rule></Group>
  </Benchmark>
  <Benchmark id="second"><title>Two</title>
    <Group id="V-2"><Rule id="SV-2r1_rule" severity="low"><version>B-2</version></Rule></Group>
  </Benchmark>
</wrapper>''')
        found = _BP().read_all(path)[0]
        assert [b.benchmark_id for b in found] == ["first", "second"]
        assert [set(b.rules) for b in found] == [{"SV-1r1_rule"}, {"SV-2r1_rule"}]
        first = _BP().read_all(path)[0][0]
        assert first.benchmark_id == "first"
        assert set(first.rules) == {"SV-1r1_rule"}

    def test_namespaced_and_unnamespaced_benchmarks_are_both_found(self, tmp_path):
        path = _write_xml(tmp_path, '''<?xml version="1.0"?>
<wrapper>
  <Benchmark id="plain"><Group id="V-1"><Rule id="SV-1r1_rule"/></Group></Benchmark>
  <x:Benchmark xmlns:x="http://checklists.nist.gov/xccdf/1.2" id="ns">
    <x:Group id="V-2"><x:Rule id="SV-2r1_rule"/></x:Group>
  </x:Benchmark>
</wrapper>''')
        found = _BP().read_all(path)[0]
        assert [b.benchmark_id for b in found] == ["plain", "ns"]
        assert [set(b.rules) for b in found] == [{"SV-1r1_rule"}, {"SV-2r1_rule"}]

    def test_outer_benchmark_does_not_own_rules_of_an_inner_benchmark(self, tmp_path):
        path = _write_xml(tmp_path, f'''<?xml version="1.0"?>
<Benchmark {_X11} id="outer">
  <Group id="V-1"><Rule id="SV-1r1_rule"/></Group>
  <Group id="V-9">
    <Benchmark id="inner">
      <Group id="V-2"><Rule id="SV-2r1_rule"/></Group>
    </Benchmark>
  </Group>
  <Group id="V-3"><Rule id="SV-3r1_rule"/></Group>
</Benchmark>''')
        outer, inner = _BP().read_all(path)[0]
        assert (outer.benchmark_id, inner.benchmark_id) == ("outer", "inner")
        assert set(outer.rules) == {"SV-1r1_rule", "SV-3r1_rule"}
        assert set(inner.rules) == {"SV-2r1_rule"}
        assert inner.rules["SV-2r1_rule"].vuln_id == "V-2"


class TestRuleDiscovery:
    def test_rule_in_a_nested_group_is_found_with_the_inner_group_id(self, tmp_path):
        path = _write_xml(tmp_path, f'''<?xml version="1.0"?>
<Benchmark {_X11} id="b">
  <Group id="V-OUTER"><title>outer</title>
    <Group id="xccdf_mil.disa.stig_group_V-INNER"><title>inner</title>
      <Rule id="SV-1r1_rule" severity="medium"><version>X-1</version><fixtext>fix</fixtext></Rule>
    </Group>
  </Group>
</Benchmark>''')
        bm = _BP().read_all(path)[0][0]
        assert list(bm.rules) == ["SV-1r1_rule"]
        rule = bm.rules["SV-1r1_rule"]
        assert rule.vuln_id == "V-INNER"
        assert rule.stig_id == "X-1"
        assert rule.severity == "CAT II"
        assert rule.fix_text == "fix"

    def test_rule_directly_under_the_benchmark_is_found_with_a_blank_vuln_id(self, tmp_path):
        path = _write_xml(tmp_path, f'''<?xml version="1.0"?>
<Benchmark {_X11} id="b">
  <Rule id="SV-1r1_rule" severity="high"><version>X-1</version></Rule>
</Benchmark>''')
        bm = _BP().read_all(path)[0][0]
        assert list(bm.rules) == ["SV-1r1_rule"]
        assert bm.rules["SV-1r1_rule"].vuln_id == ""

    def test_rules_keep_document_order_across_groups(self, tmp_path):
        path = _write_xml(tmp_path, f'''<?xml version="1.0"?>
<Benchmark {_X11} id="b">
  <Group id="V-1"><Rule id="SV-1r1_rule"/><Rule id="SV-2r1_rule"/></Group>
  <Group id="V-3"><Rule id="SV-3r1_rule"/></Group>
</Benchmark>''')
        assert list(_BP().read_all(path)[0][0].rules) == ["SV-1r1_rule", "SV-2r1_rule", "SV-3r1_rule"]


class TestDuplicateRuleIds:
    _DOC = f'''<?xml version="1.0"?>
<Benchmark {_X11} id="dupes">
  <Group id="V-1"><Rule id="SV-1r1_rule"><fixtext>first</fixtext></Rule></Group>
  <Group id="V-2">
    <Rule id="SV-1r1_rule"><fixtext>last</fixtext></Rule>
    <Rule id="SV-2r1_rule"><fixtext>a</fixtext></Rule>
    <Rule id="SV-2r1_rule"><fixtext>b</fixtext></Rule>
    <Rule id="SV-3r1_rule"><fixtext>only</fixtext></Rule>
  </Group>
</Benchmark>'''

    def test_last_definition_wins(self, tmp_path):
        bm = _BP().read_all(_write_xml(tmp_path, self._DOC))[0][0]
        assert list(bm.rules) == ["SV-1r1_rule", "SV-2r1_rule", "SV-3r1_rule"]
        assert bm.rules["SV-1r1_rule"].fix_text == "last"
        assert bm.rules["SV-1r1_rule"].vuln_id == "V-2"
        assert bm.rules["SV-2r1_rule"].fix_text == "b"

    def test_one_warning_per_benchmark_names_the_duplicates(self, tmp_path, caplog):
        _BP().read_all(_write_xml(tmp_path, self._DOC))[0][0]
        dupes = [r for r in caplog.records if "duplicate rule ID" in r.getMessage()]
        assert len(dupes) == 1
        message = dupes[0].getMessage()
        assert "dupes" in message
        assert "2 duplicate rule ID(s)" in message
        assert "SV-1r1_rule" in message and "SV-2r1_rule" in message
        assert "SV-3r1_rule" not in message

    def test_no_warning_without_duplicates(self, caplog):
        _BP().read_all(_FIX / "manual_stig_win11.xml")[0][0]
        assert not any("duplicate" in r.getMessage() for r in caplog.records)

    def test_duplicate_listing_is_capped(self, tmp_path, caplog):
        rules = "".join(f'<Rule id="SV-{n}r1_rule"/><Rule id="SV-{n}r1_rule"/>' for n in range(20))
        path = _write_xml(tmp_path, f'<Benchmark {_X11} id="many"><Group id="V-1">{rules}</Group></Benchmark>')
        _BP().read_all(path)[0][0]
        message = next(r.getMessage() for r in caplog.records if "duplicate rule ID" in r.getMessage())
        assert "20 duplicate rule ID(s)" in message
        assert "SV-19r1_rule" not in message

    def test_duplicate_warning_escapes_and_bounds_hostile_ids(self, tmp_path, caplog):
        # &#10; survives XML attribute normalisation, so the ID holds a real newline.
        long_id = "SV-L" + "x" * 5000
        path = _write_xml(tmp_path, f'''<?xml version="1.0"?>
<Benchmark {_X11} id="bench&#10;FORGED-BENCH-LINE">
  <Group id="V-1">
    <Rule id="SV-1&#10;FORGED LOG LINE"/><Rule id="SV-1&#10;FORGED LOG LINE"/>
    <Rule id="{long_id}"/><Rule id="{long_id}"/>
  </Group>
</Benchmark>''')
        _BP().read_all(path)[0][0]
        message = next(r.getMessage() for r in caplog.records if "duplicate rule ID" in r.getMessage())
        assert "\n" not in message and "\r" not in message
        assert "\\n" in message                        # escaped, not raw
        assert "2 duplicate rule ID(s)" in message
        assert "x" * 81 not in message
        assert len(message) < 1000


class TestRuleWalk:
    """Rules are read by one walk that descends only through Groups."""

    def test_rules_outside_groups_and_the_benchmark_itself_are_not_collected(self, tmp_path):
        path = _write_xml(tmp_path, f'''<?xml version="1.0"?>
<Benchmark {_X11} id="b">
  <Group id="V-1"><Rule id="SV-1r1_rule"/></Group>
  <Rule id="SV-2r1_rule"/>
  <TestResult id="t"><Rule id="SV-STRAY-1"/></TestResult>
  <wrapper><Group id="V-9"><Rule id="SV-STRAY-2"/></Group></wrapper>
  <Profile id="p"><Rule id="SV-STRAY-3"/></Profile>
</Benchmark>''')
        bm = _BP().read_all(path)[0][0]
        assert list(bm.rules) == ["SV-1r1_rule", "SV-2r1_rule"]
        assert bm.rules["SV-1r1_rule"].vuln_id == "V-1"
        assert bm.rules["SV-2r1_rule"].vuln_id == ""

    def test_comments_between_elements_are_ignored(self, tmp_path):
        path = _write_xml(tmp_path, f'''<?xml version="1.0"?>
<Benchmark {_X11} id="b"><!-- c1 -->
  <Group id="V-1"><!-- c2 --><Rule id="SV-1r1_rule"/><?pi x?></Group>
</Benchmark>''')
        assert list(_BP().read_all(path)[0][0].rules) == ["SV-1r1_rule"]

    def test_group_nesting_is_walked_in_document_order(self, tmp_path):
        path = _write_xml(tmp_path, f'''<?xml version="1.0"?>
<Benchmark {_X11} id="b">
  <Rule id="SV-A_rule"/>
  <Group id="V-1">
    <Rule id="SV-B_rule"/>
    <Group id="V-2"><Rule id="SV-C_rule"/></Group>
    <Rule id="SV-D_rule"/>
  </Group>
  <Group id="V-3"><Rule id="SV-E_rule"/></Group>
</Benchmark>''')
        rules = _BP().read_all(path)[0][0].rules
        assert list(rules) == ["SV-A_rule", "SV-B_rule", "SV-C_rule", "SV-D_rule", "SV-E_rule"]
        assert [r.vuln_id for r in rules.values()] == ["", "V-1", "V-2", "V-1", "V-3"]

    def test_twenty_thousand_rules_in_two_hundred_nested_groups_parse_quickly(self, tmp_path):
        path = _write_xml(tmp_path, _nested_groups_document(levels=200, rules_per_level=100))
        start = _time.perf_counter()
        bm = _BP().read_all(path)[0][0]
        elapsed = _time.perf_counter() - start
        assert len(bm.rules) == 20000
        assert bm.rules["SV-0r1_rule"].vuln_id == "V-0"
        assert bm.rules["SV-19999r1_rule"].vuln_id == "V-199"
        assert elapsed < 3, f"took {elapsed:.2f}s"

    def test_two_hundred_nested_benchmarks_parse_quickly_and_own_their_rules(self, tmp_path):
        path = _write_xml(tmp_path, _nested_benchmarks_document(levels=200, rules_per_level=100))
        start = _time.perf_counter()
        found = _BP().read_all(path)[0]
        elapsed = _time.perf_counter() - start
        assert [b.benchmark_id for b in found] == [f"b{n}" for n in range(200)]
        assert all(len(b.rules) == 100 for b in found)
        assert found[7].rules["SV-700r1_rule"].vuln_id == "V-7"
        assert elapsed < 3, f"took {elapsed:.2f}s"


class TestHostileXml:
    def test_external_entity_is_never_resolved(self, tmp_path):
        path = _xxe_document(tmp_path)
        found = _BP().read_all(path)[0]
        # The document was read, not rejected, so the leak check below means something.
        assert [b.benchmark_id for b in found] == ["xxe-test"]
        assert found[0].title.startswith("Title")
        rule = found[0].rules["SV-1r1_rule"]
        assert rule.stig_id == "WN11-00-000150"
        assert rule.fix_text.startswith("Fix")
        assert rule.check_text.startswith("Check")
        assert not any(_XXE_MARKER in t for t in _parsed_text(found))
        first = _BP().read_all(path)[0][0]
        assert first is not None and first.rules
        assert not any(_XXE_MARKER in t for t in _parsed_text([first]))

    def test_the_xxe_document_does_leak_under_a_permissive_parser(self, tmp_path, monkeypatch):
        """Sensitivity check: the same document and assertions DO detect a leak
        once entity resolution is switched on, so the test above can fail."""
        def permissive(path):
            parser = _etree.XMLParser(resolve_entities=True, no_network=False, load_dtd=False)
            return _etree.parse(str(path), parser)

        monkeypatch.setattr(_bpmod, "_safe_xml_parse", permissive)
        found = _BP().read_all(_xxe_document(tmp_path))[0]
        assert any(_XXE_MARKER in t for t in _parsed_text(found))

    def test_entity_expansion_bomb_neither_hangs_nor_expands(self, tmp_path):
        levels = ['<!ENTITY l0 "LOLLOLLOLL">']
        for n in range(1, 10):
            levels.append(f'<!ENTITY l{n} "' + f"&l{n - 1};" * 10 + '">')
        path = _write_xml(tmp_path, f'''<?xml version="1.0"?>
<!DOCTYPE Benchmark [{"".join(levels)}]>
<Benchmark {_X11} id="bomb"><title>&l9;</title>
  <Group id="V-1"><Rule id="SV-1r1_rule"><fixtext>&l9;</fixtext></Rule></Group>
</Benchmark>''')
        start = _time.perf_counter()
        found = _BP().read_all(path)[0]
        assert _time.perf_counter() - start < 5
        for bm in found:
            assert len(bm.title) < 1000
            assert all(len(r.fix_text) < 1000 for r in bm.rules.values())
