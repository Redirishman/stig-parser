# tests/test_pipeline.py
"""Tests for the shared parse→export pipeline."""
import re
from pathlib import Path

import pytest

from app.core.pipeline import (
    ParseResult,
    PipelineError,
    compute_summary,
    default_delta_output_name,
    default_output_name,
    export_delta_stage,
    export_stage,
    parse_stage,
)
from app.parsers.base import Finding
from app.processors.delta import DeltaFinding, DeltaResult


def _finding(severity="CAT II", server="host1"):
    return Finding(
        stig_title="Test STIG",
        vuln_id="V-1",
        rule_id="SV-1r1_rule",
        severity=severity,
        status="Open",
        server=server,
        ip_address="10.0.0.1",
        check_text="check",
        fix_text="fix",
    )


def test_compute_summary_counts_by_severity_and_host():
    findings = [
        _finding("CAT I", "a"),
        _finding("CAT II", "a"),
        _finding("CAT III", "b"),
    ]
    summary = compute_summary(findings, source_file_count=2)
    assert summary == {
        "files": 2,
        "hosts": 2,
        "findings": 3,
        "cat1": 1,
        "cat2": 1,
        "cat3": 1,
    }


def test_default_output_name_is_timestamped_xlsx():
    name = default_output_name()
    assert name.startswith("stig_findings_")
    assert name.endswith(".xlsx")


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_stage_happy_path_yields_findings(tmp_path):
    fixture = FIXTURES / "scc_results.xml"
    assert fixture.exists(), f"missing fixture: {fixture}"
    # benchmark_paths=[] also exercises the "no benchmarks supplied → use
    # results files as benchmarks" fallback branch.
    result = parse_stage([fixture], [], tmp_path / "e")
    assert isinstance(result, ParseResult)
    assert result.source_file_count == 1
    assert isinstance(result.findings, list)
    assert all(isinstance(f, Finding) for f in result.findings)
    assert len(result.findings) == 5


_ALL_PASS_XCCDF = """<?xml version="1.0" encoding="UTF-8"?>
<cdf:TestResult xmlns:cdf="http://checklists.nist.gov/xccdf/1.2"
    id="xccdf_mil.disa.scc_testresult_test" version="1.0">
  <cdf:benchmark href="test-xccdf.xml" id="xccdf_test_benchmark"/>
  <cdf:title>All-pass results</cdf:title>
  <cdf:target>HOST-A</cdf:target>
  <cdf:target-address>10.0.0.5</cdf:target-address>
  <cdf:rule-result idref="xccdf_test_rule_SV-1r1_rule" severity="high">
    <cdf:result>pass</cdf:result>
  </cdf:rule-result>
  <cdf:rule-result idref="xccdf_test_rule_SV-2r1_rule" severity="medium">
    <cdf:result>pass</cdf:result>
  </cdf:rule-result>
</cdf:TestResult>
"""


def test_parse_stage_raises_when_rules_present_but_none_actionable(tmp_path):
    # rule-results parse successfully (total_rules > 0) but all pass, so the
    # actionable-status filter yields zero findings — the "actionable status"
    # PipelineError branch.
    src = tmp_path / "all_pass.xml"
    src.write_text(_ALL_PASS_XCCDF, encoding="utf-8")
    with pytest.raises(PipelineError) as exc:
        parse_stage([src], [], tmp_path / "e")
    assert "actionable status" in str(exc.value).lower()


def test_parse_stage_allow_empty_returns_empty_result(tmp_path):
    # Same input as the test above: with allow_empty the zero-actionable-
    # findings case is permissible (a delta baseline/current side may be
    # fully remediated) and yields an empty ParseResult instead of raising.
    src = tmp_path / "all_pass.xml"
    src.write_text(_ALL_PASS_XCCDF, encoding="utf-8")
    result = parse_stage([src], [], tmp_path / "e", allow_empty=True)
    assert isinstance(result, ParseResult)
    assert result.findings == []
    assert result.source_file_count == 1


def test_parse_stage_allow_empty_still_raises_when_nothing_parses(tmp_path):
    # allow_empty relaxes ONLY the "no actionable findings" case. A results
    # set where nothing parsed at all is still a genuine error. (Invalid XML,
    # not merely non-XCCDF XML: a well-formed file yields a ScanResult with
    # zero rule-results, which is the *empty* case, not the *unparseable* one.)
    bad = tmp_path / "broken.xml"
    bad.write_text("<TestResult><unclosed>", encoding="utf-8")
    with pytest.raises(PipelineError) as exc:
        parse_stage([bad], [], tmp_path / "e", allow_empty=True)
    assert "no valid results files" in str(exc.value).lower()


def test_parse_stage_raises_pipelineerror_when_no_results_parse(tmp_path):
    bad = tmp_path / "not_xccdf.xml"
    bad.write_text("<html><body>nope</body></html>", encoding="utf-8")
    with pytest.raises(PipelineError) as exc:
        parse_stage(
            results_paths=[bad],
            benchmark_paths=[],
            extract_dir=tmp_path / "extract",
        )
    assert "results" in str(exc.value).lower()


def test_export_stage_writes_xlsx(tmp_path):
    out = tmp_path / "report.xlsx"
    export_stage([_finding()], out)
    assert out.exists() and out.stat().st_size > 0


def test_parse_stage_cancel_check_is_invoked(tmp_path):
    bad = tmp_path / "x.xml"
    bad.write_text("<x/>", encoding="utf-8")
    calls = []

    def cancel():
        calls.append(1)

    with pytest.raises(PipelineError):
        parse_stage([bad], [], tmp_path / "e", cancel_check=cancel)
    assert calls, "cancel_check should be invoked at least once"


def test_default_delta_output_name_shape():
    name = default_delta_output_name()
    assert name.startswith("stig_delta_") and name.endswith(".xlsx")


def test_export_delta_stage_writes_file(tmp_path):
    delta = DeltaResult(
        findings=[
            DeltaFinding(
                stig_title="t", vuln_id="V-1", rule_id="SV-1r1_rule",
                severity="CAT I", server="SERVER01", ip_address="10.0.0.1",
                check_text="c", fix_text="f", delta_status="New",
                baseline_status="", current_status="Open",
            )
        ],
        only_current_hosts={"SERVER01"},
    )
    out = tmp_path / "d.xlsx"
    export_delta_stage(delta, out)
    assert out.exists()


# ---------------------------------------------------------------------------
# Coverage (spec Revision 2, R2-1) and zero-rule-results handling (R2-7)
# ---------------------------------------------------------------------------

def test_parse_stage_coverage_from_all_pass_scan(tmp_path):
    # A scan with nothing actionable still says which (host, STIG) it
    # covered -- the delta report needs that to tell "fully remediated"
    # apart from "not re-scanned".
    src = tmp_path / "all_pass.xml"
    src.write_text(_ALL_PASS_XCCDF, encoding="utf-8")
    result = parse_stage([src], [], tmp_path / "e", allow_empty=True)
    assert result.findings == []
    assert len(result.coverage) == 1
    assert {server for server, _ in result.coverage} == {"HOST-A"}


def test_parse_stage_coverage_is_superset_of_finding_pairs(tmp_path):
    result = parse_stage([FIXTURES / "scc_results.xml"], [], tmp_path / "e")
    assert result.findings
    assert {(f.server, f.stig_title) for f in result.findings} <= result.coverage


def test_parse_stage_cklb_coverage_survives_actionable_filter(tmp_path):
    # Self-contained formats build coverage from every parsed row BEFORE the
    # actionable filter, so a checklist with every rule Not A Finding still
    # contributes its (host, STIG) pair.
    src = FIXTURES / "evaluate_stig_checklist.cklb"
    text = src.read_text(encoding="utf-8")
    clean = tmp_path / "clean.cklb"
    clean.write_text(
        text.replace('"status": "open"', '"status": "not_a_finding"')
            .replace('"status": "not_reviewed"', '"status": "not_a_finding"'),
        encoding="utf-8",
    )
    full = parse_stage([src], [], tmp_path / "e1")
    result = parse_stage([clean], [], tmp_path / "e2", allow_empty=True)
    assert result.findings == []
    assert result.coverage == {(f.server, f.stig_title) for f in full.findings}


def test_parse_stage_zero_rule_results_raises_even_with_allow_empty(tmp_path):
    # allow_empty relaxes ONLY the zero-actionable case. A well-formed XML
    # file with no <rule-result> elements at all (here: a benchmark handed
    # in as a results file) is a wrong input, not a clean scan, and must
    # still fail loudly.
    with pytest.raises(PipelineError) as exc:
        parse_stage(
            [FIXTURES / "sample_benchmark.xml"], [], tmp_path / "e", allow_empty=True
        )
    assert "no rule results" in str(exc.value).lower()


def _strip_rule_results(src: Path, dest: Path) -> Path:
    """Copy *src* with every <cdf:rule-result> block removed."""
    text = src.read_text(encoding="utf-8")
    stripped = re.sub(
        r"<cdf:rule-result[ >].*?</cdf:rule-result>", "", text, flags=re.DOTALL
    )
    assert "<cdf:rule-result" not in stripped and "<cdf:target>" in stripped
    dest.write_text(stripped, encoding="utf-8")
    return dest


def test_parse_stage_zero_rule_result_scan_is_warned_and_not_covered(tmp_path):
    # A results file with no <rule-result> at all is not a scan. It must
    # not put its (host, STIG) pair into coverage — the delta would then
    # read every baseline finding on that pair as Resolved — and the
    # operator must be told which file, by name.
    good = tmp_path / "all_pass.xml"
    good.write_text(_ALL_PASS_XCCDF, encoding="utf-8")
    empty = _strip_rule_results(FIXTURES / "scc_results.xml", tmp_path / "empty.xml")
    result = parse_stage([good, empty], [], tmp_path / "e", allow_empty=True)
    assert {server for server, _ in result.coverage} == {"HOST-A"}
    assert any(
        w.startswith("empty.xml: 0 rule results") and "--benchmarks" in w
        for w in result.warnings
    ), result.warnings
