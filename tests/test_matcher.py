"""Tests for matcher.py — cross-reference results ↔ benchmarks."""
from pathlib import Path

import pytest

from app.parsers.base import Benchmark, BenchmarkRule, RuleResult, ScanResult
from app.processors.matcher import match_results_to_benchmarks


def _make_rule(rule_id: str, vuln_id: str = "V-000001", severity: str = "CAT I") -> BenchmarkRule:
    return BenchmarkRule(
        vuln_id=vuln_id,
        rule_id=rule_id,
        severity=severity,
        check_text="Check text.",
        fix_text="Fix text.",
    )


def _make_benchmark(bid: str, rules: list[BenchmarkRule]) -> Benchmark:
    bm = Benchmark(benchmark_id=bid, title=f"STIG for {bid}")
    bm.rules = {r.rule_id: r for r in rules}
    return bm


def _make_scan(
    hostname: str = "SERVER01",
    ip: str = "10.0.0.1",
    benchmark_href: str = "",
    benchmark_id: str = "xccdf_mil.disa.stig_benchmark_MS_Windows_Server_2022_STIG",
    rule_results: list[RuleResult] | None = None,
) -> ScanResult:
    return ScanResult(
        source_file="test.xml",
        hostname=hostname,
        ip_address=ip,
        benchmark_href=benchmark_href,
        benchmark_id=benchmark_id,
        scanner="SCC",
        rule_results=rule_results or [],
    )


RULE_ID = "xccdf_mil.disa.stig_rule_SV-254239r945408_rule"
BENCHMARK_ID = "xccdf_mil.disa.stig_benchmark_MS_Windows_Server_2022_STIG"


class TestMatchedResults:
    def setup_method(self):
        rule = _make_rule(RULE_ID, "V-254239", "CAT I")
        self.benchmark = _make_benchmark(BENCHMARK_ID, [rule])
        scan = _make_scan(
            benchmark_id=BENCHMARK_ID,
            rule_results=[RuleResult(rule_id=RULE_ID, status="fail")],
        )
        self.findings = match_results_to_benchmarks([scan], [self.benchmark])

    def test_one_finding_produced(self):
        assert len(self.findings) == 1

    def test_finding_status(self):
        assert self.findings[0].status == "Open"

    def test_finding_severity(self):
        assert self.findings[0].severity == "CAT I"

    def test_finding_vuln_id(self):
        assert self.findings[0].vuln_id == "V-254239"

    def test_finding_check_text(self):
        assert self.findings[0].check_text == "Check text."

    def test_finding_fix_text(self):
        assert self.findings[0].fix_text == "Fix text."

    def test_finding_server(self):
        assert self.findings[0].server == "SERVER01"

    def test_stig_title(self):
        assert "STIG for" in self.findings[0].stig_title


class TestStatusMapping:
    def _run(self, status: str) -> str:
        rule = _make_rule(RULE_ID)
        bm = _make_benchmark(BENCHMARK_ID, [rule])
        scan = _make_scan(
            benchmark_id=BENCHMARK_ID,
            rule_results=[RuleResult(rule_id=RULE_ID, status=status)],
        )
        findings = match_results_to_benchmarks([scan], [bm])
        return findings[0].status if findings else ""

    def test_fail_maps_to_open(self):
        assert self._run("fail") == "Open"

    def test_notchecked_maps_to_not_reviewed(self):
        assert self._run("notchecked") == "Not Reviewed"

    def test_notselected_maps_to_not_reviewed(self):
        assert self._run("notselected") == "Not Reviewed"

    def test_error_maps_to_error(self):
        assert self._run("error") == "Error"

    def test_unknown_maps_to_unknown(self):
        assert self._run("unknown") == "Unknown"

    def test_pass_discarded(self):
        assert self._run("pass") == ""

    def test_notapplicable_discarded(self):
        assert self._run("notapplicable") == ""

    def test_informational_discarded(self):
        assert self._run("informational") == ""

    def test_fixed_discarded(self):
        assert self._run("fixed") == ""


class TestUnmatchedBenchmark:
    def test_no_benchmarks_produces_blank_text(self):
        scan = _make_scan(
            rule_results=[RuleResult(rule_id=RULE_ID, status="fail")],
        )
        findings = match_results_to_benchmarks([scan], [])
        assert len(findings) == 1
        assert findings[0].check_text == ""
        assert findings[0].fix_text == ""
        assert findings[0].status == "Open"

    def test_wrong_benchmark_id_still_blank_text(self):
        bm = _make_benchmark("xccdf_different_benchmark", [_make_rule(RULE_ID)])
        scan = _make_scan(
            benchmark_id="xccdf_mil.disa.stig_benchmark_RHEL9_STIG",
            rule_results=[RuleResult(rule_id=RULE_ID, status="fail")],
        )
        findings = match_results_to_benchmarks([scan], [bm])
        assert len(findings) == 1
        assert findings[0].check_text == ""


class TestBenchmarkMatchFallback:
    def test_href_stem_matches_benchmark_id(self):
        """Benchmark matched via href filename stem when IDs differ in path form."""
        rule = _make_rule(RULE_ID, "V-254239", "CAT I")
        bm = _make_benchmark(BENCHMARK_ID, [rule])
        scan = _make_scan(
            benchmark_href=f"./scans/{BENCHMARK_ID}.xml",
            benchmark_id="",
            rule_results=[RuleResult(rule_id=RULE_ID, status="fail")],
        )
        findings = match_results_to_benchmarks([scan], [bm])
        assert findings[0].check_text == "Check text."

    def test_substring_fallback(self):
        """Partial ID match falls back correctly."""
        rule = _make_rule(RULE_ID)
        bm = _make_benchmark("xccdf_mil.disa.stig_benchmark_MS_Windows_Server_2022_STIG", [rule])
        scan = _make_scan(
            benchmark_href="",
            benchmark_id="MS_Windows_Server_2022_STIG",
            rule_results=[RuleResult(rule_id=RULE_ID, status="fail")],
        )
        findings = match_results_to_benchmarks([scan], [bm])
        assert findings[0].check_text == "Check text."


class TestFullyQualifiedBenchmarkIds:
    """Regression: XCCDF ids like xccdf_mil.disa.stig_benchmark_X must not all
    normalise to 'xccdf_mil.disa' via Path.stem."""

    def test_each_scan_matches_its_own_benchmark(self):
        rule_av = _make_rule("xccdf_mil.disa.stig_rule_SV-213426r961197_rule", "V-213426", "CAT I")
        rule_win = _make_rule("xccdf_mil.disa.stig_rule_SV-254239r945408_rule", "V-254239", "CAT II")

        bm_av = _make_benchmark("xccdf_mil.disa.stig_benchmark_MS_Defender_Antivirus", [rule_av])
        bm_win = _make_benchmark("xccdf_mil.disa.stig_benchmark_Microsoft_Windows_11_STIG", [rule_win])

        scan_av = _make_scan(
            benchmark_id="xccdf_mil.disa.stig_benchmark_MS_Defender_Antivirus",
            rule_results=[RuleResult(rule_av.rule_id, "fail")],
        )
        scan_win = _make_scan(
            benchmark_id="xccdf_mil.disa.stig_benchmark_Microsoft_Windows_11_STIG",
            rule_results=[RuleResult(rule_win.rule_id, "fail")],
        )

        findings = match_results_to_benchmarks([scan_av, scan_win], [bm_av, bm_win])
        assert len(findings) == 2
        by_rule = {f.rule_id: f for f in findings}

        av_finding = by_rule[rule_av.rule_id]
        assert av_finding.vuln_id == "V-213426"
        assert av_finding.severity == "CAT I"

        win_finding = by_rule[rule_win.rule_id]
        assert win_finding.vuln_id == "V-254239"
        assert win_finding.severity == "CAT II"


class TestDuplicateTargets:
    def test_both_rows_kept(self):
        rule = _make_rule(RULE_ID)
        bm = _make_benchmark(BENCHMARK_ID, [rule])
        scan1 = _make_scan("SERVER01", benchmark_id=BENCHMARK_ID,
                           rule_results=[RuleResult(RULE_ID, "fail")])
        scan2 = _make_scan("SERVER01", benchmark_id=BENCHMARK_ID,
                           rule_results=[RuleResult(RULE_ID, "fail")])
        findings = match_results_to_benchmarks([scan1, scan2], [bm])
        assert len(findings) == 2
