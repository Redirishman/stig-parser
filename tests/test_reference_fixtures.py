# tests/test_reference_fixtures.py
"""The reference fixtures must keep the real-world shapes the feature exists for."""
from pathlib import Path

from app.parsers.benchmark_parser import BenchmarkParser
from app.parsers.xccdf_parser import XCCDFResultsParser

FIXTURES = Path(__file__).parent / "fixtures"


def test_scc_fixture_embeds_a_benchmark_with_fix_text_but_no_check_text():
    bm = BenchmarkParser().read_all(FIXTURES / "scc_embedded_results.xml")[0][0]
    assert bm.benchmark_id == "xccdf_mil.disa.stig_benchmark_Microsoft_Windows_11_STIG"
    assert len(bm.rules) == 4
    assert all(r.fix_text for r in bm.rules.values())
    assert not any(r.check_text for r in bm.rules.values())


def test_scc_fixture_has_results_for_the_embedded_rules():
    scan = XCCDFResultsParser().read(FIXTURES / "scc_embedded_results.xml")[0]
    assert scan.hostname == "WKSTN-01"
    assert {rr.status for rr in scan.rule_results} == {"fail", "pass"}
    assert len(scan.rule_results) == 4


def test_manual_fixtures_use_short_rule_ids_and_carry_check_text():
    for name, expected_id in (
        ("manual_stig_win11.xml", "MS_Windows_11_STIG"),
        ("manual_stig_server2022.xml", "MS_Windows_Server_2022_STIG"),
    ):
        bm = BenchmarkParser().read_all(FIXTURES / name)[0][0]
        assert bm.benchmark_id == expected_id
        assert all(rid.startswith("SV-") for rid in bm.rules)
        assert all(r.check_text and r.fix_text for r in bm.rules.values())
