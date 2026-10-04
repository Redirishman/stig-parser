"""Tests for matcher.py — cross-reference results ↔ benchmarks."""
from pathlib import Path

import pytest

from app.parsers.base import Benchmark, BenchmarkRule, Finding, RuleResult, ScanResult
from app.parsers.benchmark_parser import BenchmarkParser as _BPm
from app.parsers.xccdf_parser import XCCDFResultsParser as _XP
from app.processors.matcher import (
    MatchIssue,
    match_results_by_scan,
    results_fingerprint,
    scan_coverage_pairs,
    unresolved_issue_warnings,
)


def _match(scans, benchmarks, issues=None) -> list[Finding]:
    """Every scan's findings, in order (what the pipeline joins from match_results_by_scan)."""
    return [f for rows in match_results_by_scan(scans, benchmarks, issues) for f in rows]


def _coverage(scans, benchmarks) -> set[tuple[str, str]]:
    """The coverage pairs of the scans that have rule results."""
    return {pair for pair in scan_coverage_pairs(scans, benchmarks) if pair is not None}


def _keys(issue: MatchIssue) -> set[tuple[str, str]]:
    """(server, rule ID) of every finding *issue* affects."""
    return {(f.server, f.rule_id) for f in issue.findings}


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
    embedded: list[Benchmark] | None = None,
    source_file: str = "test.xml",
) -> ScanResult:
    """*embedded* is the benchmark(s) carried by the scan's own results file: the
    only place the matcher takes rule data from."""
    return ScanResult(
        source_file=source_file,
        hostname=hostname,
        ip_address=ip,
        benchmark_href=benchmark_href,
        benchmark_id=benchmark_id,
        scanner="SCC",
        rule_results=rule_results or [],
        embedded_benchmarks=embedded or [],
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
            embedded=[self.benchmark],
        )
        self.findings = _match([scan], [])

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
        findings = _match([scan], [bm])
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
        findings = _match([scan], [])
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
        findings = _match([scan], [bm])
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
            embedded=[bm],
        )
        findings = _match([scan], [])
        assert findings[0].check_text == "Check text."

    def test_short_id_matches_fully_qualified_id(self):
        """The XCCDF prefix is not part of the ID: a short ID is the same benchmark."""
        rule = _make_rule(RULE_ID)
        bm = _make_benchmark("xccdf_mil.disa.stig_benchmark_MS_Windows_Server_2022_STIG", [rule])
        scan = _make_scan(
            benchmark_href="",
            benchmark_id="MS_Windows_Server_2022_STIG",
            rule_results=[RuleResult(rule_id=RULE_ID, status="fail")],
            embedded=[bm],
        )
        findings = _match([scan], [])
        assert findings[0].check_text == "Check text."


class TestFullyQualifiedBenchmarkIds:
    """Regression: XCCDF ids like xccdf_mil.disa.stig_benchmark_X must not all
    normalise to 'xccdf_mil.disa' via Path.stem."""

    def test_each_scan_matches_its_own_benchmark(self):
        rule_av = _make_rule("xccdf_mil.disa.stig_rule_SV-213426r961197_rule", "V-213426", "CAT I")
        rule_win = _make_rule("xccdf_mil.disa.stig_rule_SV-254239r945408_rule", "V-254239", "CAT II")

        bm_av = _make_benchmark("xccdf_mil.disa.stig_benchmark_MS_Defender_Antivirus", [rule_av])
        bm_win = _make_benchmark("xccdf_mil.disa.stig_benchmark_Microsoft_Windows_11_STIG", [rule_win])

        # Both benchmarks sit in each results file (an SCC session file can carry
        # several): every scan must still pick its own.
        scan_av = _make_scan(
            benchmark_id="xccdf_mil.disa.stig_benchmark_MS_Defender_Antivirus",
            rule_results=[RuleResult(rule_av.rule_id, "fail")],
            embedded=[bm_av, bm_win],
        )
        scan_win = _make_scan(
            benchmark_id="xccdf_mil.disa.stig_benchmark_Microsoft_Windows_11_STIG",
            rule_results=[RuleResult(rule_win.rule_id, "fail")],
            embedded=[bm_av, bm_win],
        )

        findings = _match([scan_av, scan_win], [])
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
        findings = _match([scan1, scan2], [bm])
        assert len(findings) == 2


class TestScanCoverage:
    """Coverage: one (hostname, STIG title) pair per scan file, whether
    or not the scan produced any actionable finding. This is what lets the
    delta report tell "fully remediated" apart from "not re-scanned"."""

    def test_all_pass_scan_yields_a_pair_and_zero_findings(self):
        rule = _make_rule(RULE_ID)
        bm = _make_benchmark(BENCHMARK_ID, [rule])
        scan = _make_scan(
            "SERVER01",
            benchmark_id=BENCHMARK_ID,
            rule_results=[RuleResult(RULE_ID, "pass"), RuleResult("SV-2r1_rule", "pass")],
        )
        assert _match([scan], [bm]) == []
        assert _coverage([scan], [bm]) == {("SERVER01", bm.title)}

    def test_unmatched_benchmark_yields_blank_title(self):
        scan = _make_scan(
            "SERVER01",
            benchmark_id="xccdf_other_benchmark",
            rule_results=[RuleResult(RULE_ID, "fail")],
        )
        assert _coverage([scan], []) == {("SERVER01", "")}

    def test_one_pair_per_scan_file(self):
        rule = _make_rule(RULE_ID)
        bm = _make_benchmark(BENCHMARK_ID, [rule])
        passed = [RuleResult(RULE_ID, "pass")]
        scans = [
            _make_scan("SERVER01", benchmark_id=BENCHMARK_ID, rule_results=passed),
            _make_scan("SERVER02", benchmark_id=BENCHMARK_ID, rule_results=passed),
            _make_scan("SERVER01", benchmark_id="xccdf_other_benchmark", rule_results=passed),
        ]
        assert _coverage(scans, [bm]) == {
            ("SERVER01", bm.title),
            ("SERVER02", bm.title),
            ("SERVER01", ""),
        }

    def test_zero_rule_result_scan_yields_no_pair(self):
        # A file with no <rule-result> at all (a benchmark handed in as
        # results, or a scan that never ran) covers nothing. Counting it
        # would let every baseline finding on that host/STIG read as
        # Resolved in a delta — the one thing the report must never do.
        rule = _make_rule(RULE_ID)
        bm = _make_benchmark(BENCHMARK_ID, [rule])
        empty = _make_scan("SERVER01", benchmark_id=BENCHMARK_ID, rule_results=[])
        assert _coverage([empty], [bm]) == set()
        assert _coverage([empty], []) == set()


# --- STIG ID, scanned release, and matching problems returned as data ---------------
_FIXm = Path(__file__).parent / "fixtures"


class TestNewFindingFieldsAndIssues:
    def test_findings_carry_stig_id_and_scanned_release(self):
        scan = _XP().read(_FIXm / "scc_embedded_results.xml")[0]
        scan.embedded_benchmarks = [_BPm().read_all(_FIXm / "scc_embedded_results.xml")[0][0]]
        findings = _match([scan], [])
        assert {f.stig_id for f in findings} == {"WN11-00-000150", "WN11-00-000160", "WN11-00-000170"}
        assert {f.scan_release for f in findings} == {"V2R8"}

    def test_rule_id_mismatch_is_returned_as_an_issue(self):
        # The file's own benchmark spells the rule IDs differently from its results.
        scan = _XP().read(_FIXm / "evaluate_stig_results.xml")[0]
        scan.embedded_benchmarks = [_BPm().read_all(_FIXm / "manual_stig_server2022.xml")[0][0]]
        issues: list[MatchIssue] = []
        findings = _match([scan], [], issues)
        assert len(findings) == 3 and all(f.stig_title for f in findings)
        assert [i.kind for i in issues] == ["rules-not-found"]
        assert len(_keys(issues[0])) == 3
        assert _keys(issues[0]) == {(f.server, f.rule_id) for f in findings}

    def test_no_benchmark_at_all_is_an_issue(self):
        scan = _XP().read(_FIXm / "evaluate_stig_results.xml")[0]
        issues: list[MatchIssue] = []
        _match([scan], [], issues)
        assert [i.kind for i in issues] == ["no-benchmark"]

    def test_unresolved_no_benchmark_warns_and_resolved_one_does_not(self):
        scan = _XP().read(_FIXm / "evaluate_stig_results.xml")[0]
        issues: list[MatchIssue] = []
        findings = _match([scan], [], issues)
        warnings = unresolved_issue_warnings(issues, findings, references_supplied=False)
        assert len(warnings) == 1 and "evaluate_stig_results.xml" in warnings[0]
        assert "no matching STIG benchmark" in warnings[0]
        assert "3 finding(s) have no STIG title, severity, or check/fix text" in warnings[0]
        for f in findings:
            f.stig_title = "Filled later"
        assert unresolved_issue_warnings(issues, findings, references_supplied=False) == []

    def test_rules_not_found_is_left_to_the_enrichment_report_when_references_exist(self):
        scan = _XP().read(_FIXm / "evaluate_stig_results.xml")[0]
        scan.embedded_benchmarks = [_BPm().read_all(_FIXm / "manual_stig_server2022.xml")[0][0]]
        issues: list[MatchIssue] = []
        findings = _match([scan], [], issues)
        assert unresolved_issue_warnings(issues, findings, references_supplied=True) == []
        unresolved = unresolved_issue_warnings(issues, findings, references_supplied=False)
        assert len(unresolved) == 1
        assert "3 rule(s) not found in benchmark 'MS_Windows_Server_2022_STIG'" in unresolved[0]

    def test_issues_are_optional(self):
        scan = _XP().read(_FIXm / "evaluate_stig_results.xml")[0]
        assert len(_match([scan], [])) == 3


def _release(bm: Benchmark, release: str, text: str) -> Benchmark:
    bm.release = release
    for rule in bm.rules.values():
        rule.check_text, rule.fix_text, rule.stig_id = f"check {text}", f"fix {text}", "WN22-00-000010"
    return bm


class TestScanIsBoundToItsOwnBenchmark:
    """Rule data and the scanned release come only from the benchmark embedded in the
    scan's own results file. A benchmark passed as the second argument is an
    operator-supplied reference: it names the STIG and nothing else, because whatever
    a reference adds is added (and labelled) by reference enrichment."""

    def test_a_reference_gives_the_title_and_no_rule_data(self):
        reference = _release(_make_benchmark(BENCHMARK_ID, [_make_rule(RULE_ID, "V-254239", "CAT I")]), "V2R8", "ref")
        scan = _make_scan(benchmark_id=BENCHMARK_ID, rule_results=[RuleResult(RULE_ID, "fail")])
        issues: list[MatchIssue] = []
        finding, = _match([scan], [reference], issues)
        assert finding.stig_title == reference.title
        assert (finding.check_text, finding.fix_text) == ("", "")
        assert (finding.vuln_id, finding.stig_id) == ("", "")
        assert finding.severity == ""                 # never "Unknown": blank is what enrichment fills
        assert finding.scan_release == ""             # the reference's release is not what was scanned
        assert issues == []                           # the enrichment report names what it could not fill

    def test_two_scans_of_one_benchmark_each_keep_their_own_release_and_text(self):
        scans = []
        for host, release in (("HOST-A", "V1R4"), ("HOST-B", "V2R8")):
            own = _release(_make_benchmark(BENCHMARK_ID, [_make_rule(RULE_ID)]), release, release)
            scans.append(_make_scan(host, benchmark_id=BENCHMARK_ID,
                                    rule_results=[RuleResult(RULE_ID, "fail")], embedded=[own]))
        findings = _match(scans, [])
        assert [(f.server, f.scan_release, f.check_text) for f in findings] == [
            ("HOST-A", "V1R4", "check V1R4"), ("HOST-B", "V2R8", "check V2R8")]

    def test_the_scans_own_benchmark_wins_over_a_reference_with_the_same_id(self):
        own = _release(_make_benchmark(BENCHMARK_ID, [_make_rule(RULE_ID, "V-254239", "CAT I")]), "V1R4", "own")
        own.title = "Title in the results file"
        reference = _release(_make_benchmark(BENCHMARK_ID, [_make_rule(RULE_ID, "V-9", "CAT III")]), "V2R8", "ref")
        scan = _make_scan(benchmark_id=BENCHMARK_ID, rule_results=[RuleResult(RULE_ID, "fail")], embedded=[own])
        finding, = _match([scan], [reference])
        assert (finding.stig_title, finding.scan_release) == ("Title in the results file", "V1R4")
        assert (finding.check_text, finding.fix_text) == ("check own", "fix own")
        assert (finding.vuln_id, finding.severity, finding.stig_id) == ("V-254239", "CAT I", "WN22-00-000010")
        assert _coverage([scan], [reference]) == {("SERVER01", "Title in the results file")}

    def test_a_rule_the_own_benchmark_does_not_describe_is_blank_and_reported(self):
        own = _release(_make_benchmark(BENCHMARK_ID, [_make_rule(RULE_ID)]), "V1R4", "own")
        reference = _release(_make_benchmark(BENCHMARK_ID, [_make_rule("SV-2r1_rule", "V-2")]), "V2R8", "ref")
        scan = _make_scan(benchmark_id=BENCHMARK_ID, embedded=[own],
                          rule_results=[RuleResult(RULE_ID, "fail"), RuleResult("SV-2r1_rule", "fail")])
        issues: list[MatchIssue] = []
        described, missing = _match([scan], [reference], issues)
        assert described.check_text == "check own"
        assert (missing.severity, missing.vuln_id, missing.check_text, missing.fix_text) == ("", "", "", "")
        assert (missing.stig_title, missing.scan_release) == (own.title, "V1R4")
        assert [(i.kind, i.benchmark_id, _keys(i)) for i in issues] == [
            ("rules-not-found", BENCHMARK_ID, {("SERVER01", "SV-2r1_rule")})]

    def test_coverage_uses_the_reference_title_when_the_file_has_no_benchmark(self):
        reference = _make_benchmark(BENCHMARK_ID, [_make_rule(RULE_ID)])
        scan = _make_scan(benchmark_id=BENCHMARK_ID, rule_results=[RuleResult(RULE_ID, "fail")])
        finding, = _match([scan], [reference])
        assert _coverage([scan], [reference]) == {(finding.server, finding.stig_title)}
        assert finding.stig_title == reference.title

    def test_a_scan_with_nothing_actionable_raises_no_issue(self):
        scan = _make_scan(benchmark_id="xccdf_other_benchmark", rule_results=[RuleResult(RULE_ID, "pass")])
        issues: list[MatchIssue] = []
        assert _match([scan], [], issues) == []
        assert issues == []


class TestUnresolvedIssueWarnings:
    def _two_files_same_host_and_rule(self):
        own = _make_benchmark(BENCHMARK_ID, [_make_rule(RULE_ID)])
        with_benchmark = _make_scan(benchmark_id=BENCHMARK_ID, rule_results=[RuleResult(RULE_ID, "fail")],
                                    embedded=[own], source_file="with_benchmark.xml")
        without = _make_scan(benchmark_id=BENCHMARK_ID, rule_results=[RuleResult(RULE_ID, "fail")],
                             source_file="without.xml")
        return with_benchmark, without

    @pytest.mark.parametrize("order", [(0, 1), (1, 0)])
    def test_a_filled_row_from_another_file_never_hides_a_blank_one(self, order):
        scans = self._two_files_same_host_and_rule()
        issues: list[MatchIssue] = []
        findings = _match([scans[i] for i in order], [], issues)
        warnings = unresolved_issue_warnings(issues, findings, references_supplied=False)
        assert len(warnings) == 1 and warnings[0].startswith("without.xml: no matching STIG benchmark — 1 finding(s)")

    def test_a_finding_dropped_before_the_report_is_not_counted(self):
        _, without = self._two_files_same_host_and_rule()
        issues: list[MatchIssue] = []
        _match([without], [], issues)
        assert unresolved_issue_warnings(issues, [], references_supplied=False) == []

    def test_an_untitled_finding_that_was_given_text_is_not_said_to_have_none(self):
        _, without = self._two_files_same_host_and_rule()
        without.rule_results.append(RuleResult("SV-2r1_rule", "fail"))
        issues: list[MatchIssue] = []
        findings = _match([without], [], issues)
        findings[0].fix_text = "filled from a reference that has no title"
        warning, = unresolved_issue_warnings(issues, findings, references_supplied=True)
        assert "2 finding(s) have no STIG title (1 of them also have no severity or check/fix text)" in warning

    def test_the_file_name_and_benchmark_id_are_escaped_and_bounded(self):
        own = _make_benchmark("B\nforged line " + "b" * 5000, [_make_rule("SV-9r1_rule")])
        scans = [
            _make_scan(benchmark_id="x", rule_results=[RuleResult(RULE_ID, "fail")],
                       source_file="a\nforged line " + "n" * 5000 + ".xml"),
            _make_scan(benchmark_id=own.benchmark_id, rule_results=[RuleResult(RULE_ID, "fail")],
                       embedded=[own], source_file="b.xml"),
        ]
        issues: list[MatchIssue] = []
        findings = _match(scans, [], issues)
        warnings = unresolved_issue_warnings(issues, findings, references_supplied=False)
        assert len(warnings) == 2
        assert all("\n" not in w and len(w) < 400 for w in warnings), warnings


# --- naming: the same benchmark ID, never a substring of one ---------------------------------

FULL_ID = "xccdf_mil.disa.stig_benchmark_MS_Windows_Server_2022_STIG"


def _named(scan_id: str, reference_id: str, *, href: str = ""):
    """(title given to the finding, issue kinds, coverage) for one benchmark-less scan and one reference."""
    reference = _make_benchmark(reference_id, [_make_rule("SV-9r1_rule")])
    reference.title = "Reference title"
    scan = _make_scan(benchmark_id=scan_id, benchmark_href=href, rule_results=[RuleResult(RULE_ID, "fail")])
    issues: list[MatchIssue] = []
    finding, = _match([scan], [reference], issues)
    return finding.stig_title, [i.kind for i in issues], _coverage([scan], [reference])


class TestAScanIsNamedOnlyByABenchmarkWithTheSameId:
    @pytest.mark.parametrize("scan_id,reference_id", [
        (FULL_ID, FULL_ID),
        (FULL_ID, "MS_Windows_Server_2022_STIG"),                        # fully-qualified vs short
        ("MS_Windows_Server_2022_STIG", FULL_ID),
        (FULL_ID.upper(), "ms_windows_server_2022_stig"),                # case is not part of the ID
        ("xccdf_org.ssgproject.content_benchmark_RHEL-9", "RHEL-9"),     # another publisher's prefix
        ("xccdf_my_own_org_benchmark_X", "xccdf_my_own_org_benchmark_X"),  # a prefix that is not stripped
        ("  " + FULL_ID + " ", "MS_Windows_Server_2022_STIG"),
    ])
    def test_the_same_id_names_the_scan(self, scan_id, reference_id):
        assert _named(scan_id, reference_id) == ("Reference title", [], {("SERVER01", "Reference title")})

    @pytest.mark.parametrize("scan_id,reference_id", [
        (FULL_ID, "STIG"),                                               # a substring of the scan's ID
        (FULL_ID, "Windows"),
        (FULL_ID, "MS_Windows_Server_2022"),
        ("MS_Windows_Server_2022_STIG", FULL_ID + "_DC"),                # the scan's ID is a substring of it
        (FULL_ID + "_DC", "MS_Windows_Server_2022_STIG"),
        ("xccdf_mil.disa.stig_benchmark_Microsoft_Windows_11_STIG", "MS_Windows_11_STIG"),
        (FULL_ID, ""),                                                   # a blank ID never matches
        ("", ""),
        ("", FULL_ID),
        ("   ", "   "),
    ])
    def test_a_different_or_blank_id_does_not(self, scan_id, reference_id):
        assert _named(scan_id, reference_id) == ("", ["no-benchmark"], {("SERVER01", "")})

    def test_a_path_style_href_names_the_scan_when_it_gives_no_id(self):
        assert _named("", FULL_ID, href=f"./scans/{FULL_ID}.xml")[0] == "Reference title"
        assert _named("", "MS_Windows_Server_2022_STIG", href=f"C:/scans/{FULL_ID}.XML")[0] == "Reference title"

    @pytest.mark.parametrize("href", ["benchmark.xml", "stig.xml", "U_MS_Windows_Server_2022_STIG_V1R4_Manual-xccdf.xml",
                                      "", ".xml", "/"])
    def test_an_href_that_is_not_the_benchmark_id_names_nothing(self, href):
        assert _named("", FULL_ID, href=href) == ("", ["no-benchmark"], {("SERVER01", "")})

    def test_the_href_is_not_consulted_when_the_scan_gives_an_id(self):
        assert _named("xccdf_mil.disa.stig_benchmark_RHEL_9_STIG", FULL_ID, href=f"{FULL_ID}.xml")[0] == ""

    def test_the_first_reference_with_the_id_wins(self):
        first = _make_benchmark("MS_Windows_Server_2022_STIG", [])
        first.title = "First"
        second = _make_benchmark(FULL_ID, [])
        second.title = "Second"
        scan = _make_scan(benchmark_id=FULL_ID, rule_results=[RuleResult(RULE_ID, "fail")])
        assert _match([scan], [first, second])[0].stig_title == "First"


class TestTheScansOwnBenchmark:
    """A results file that embeds exactly one benchmark was scanned against it. With several,
    the scan's benchmark ID (or href) picks one by equality, never by substring."""

    def _own(self, other_id="xccdf_mil.disa.stig_benchmark_Other_STIG"):
        own = _release(_make_benchmark(other_id, [_make_rule(RULE_ID, "V-254239", "CAT I")]), "V1R4", "own")
        own.title = "Own title"
        return own

    @pytest.mark.parametrize("scan_id,href", [("", "U_MS_Windows_Server_2022_STIG_V1R4_Manual-xccdf.xml"),
                                              ("", ""), (FULL_ID, ""), ("", "benchmark.xml")])
    def test_a_lone_embedded_benchmark_is_the_scans_own_whatever_the_scan_calls_it(self, scan_id, href):
        scan = _make_scan(benchmark_id=scan_id, benchmark_href=href,
                          rule_results=[RuleResult(RULE_ID, "fail")], embedded=[self._own()])
        issues: list[MatchIssue] = []
        finding, = _match([scan], [], issues)
        assert (finding.stig_title, finding.check_text, finding.scan_release) == ("Own title", "check own", "V1R4")
        assert issues == [] and _coverage([scan], []) == {("SERVER01", "Own title")}

    def test_a_lone_embedded_benchmark_with_no_id_is_still_the_scans_own(self):
        scan = _make_scan(benchmark_id=FULL_ID, rule_results=[RuleResult(RULE_ID, "fail")], embedded=[self._own("")])
        assert _match([scan], [])[0].check_text == "check own"

    def test_with_several_embedded_benchmarks_the_id_picks_one_by_equality(self):
        wanted = self._own(FULL_ID)
        longer = self._own(FULL_ID + "_DC")
        longer.title = "Longer ID"
        shorter = self._own("STIG")
        shorter.title = "Shorter ID"
        for embedded in ([longer, shorter, wanted], [wanted, longer, shorter]):
            scan = _make_scan(benchmark_id="MS_Windows_Server_2022_STIG",
                              rule_results=[RuleResult(RULE_ID, "fail")], embedded=embedded)
            assert _match([scan], [])[0].stig_title == "Own title"

    def test_with_several_embedded_benchmarks_an_href_only_scan_is_matched_by_the_href_stem(self):
        wanted, other = self._own(FULL_ID), self._own("xccdf_mil.disa.stig_benchmark_RHEL_9_STIG")
        other.title = "Other"
        scan = _make_scan(benchmark_id="", benchmark_href=f"./x/{FULL_ID}.xml",
                          rule_results=[RuleResult(RULE_ID, "fail")], embedded=[other, wanted])
        assert _match([scan], [])[0].stig_title == "Own title"

    def test_with_several_embedded_benchmarks_and_no_equal_id_none_is_the_scans_own(self):
        one, two = self._own("STIG"), self._own("Windows")
        scan = _make_scan(benchmark_id=FULL_ID, rule_results=[RuleResult(RULE_ID, "fail")], embedded=[one, two])
        issues: list[MatchIssue] = []
        finding, = _match([scan], [], issues)
        assert (finding.stig_title, finding.check_text, finding.scan_release) == ("", "", "")
        assert [i.kind for i in issues] == ["no-benchmark"]
        # ... and a reference with the scan's ID then names it, title only.
        reference = _make_benchmark("MS_Windows_Server_2022_STIG", [_make_rule(RULE_ID)])
        finding, = _match([scan], [reference])
        assert (finding.stig_title, finding.check_text) == (reference.title, "")


# --- the fingerprint of a results file --------------------------------------------------------

def _row(rule_id: str = "xccdf_mil.disa.stig_rule_SV-1r1_rule", status: str = "Open", *, server: str = "HOST-A",
         ip: str = "10.0.0.1", vuln_id: str = "", check_text: str = "", fix_text: str = "") -> Finding:
    return Finding(stig_title="", vuln_id=vuln_id, rule_id=rule_id, severity="", status=status, server=server,
                   ip_address=ip, check_text=check_text, fix_text=fix_text)


class TestResultsFingerprint:
    def _rows(self, **overrides) -> list[Finding]:
        return [_row(**overrides), _row("xccdf_mil.disa.stig_rule_SV-2r1_rule", "Not Reviewed", **overrides)]

    def test_the_same_results_in_another_format_have_one_fingerprint(self):
        # A checklist spells the rules without the XCCDF prefix, may carry another revision, a V-ID,
        # text and a title, and lists its rows in another order: it is still the same scan.
        checklist = [
            Finding("Some STIG", "V-2", "SV-2r9_rule", "CAT II", "Not Reviewed", "HOST-A", "10.0.0.1", "c", "f"),
            Finding("Some STIG", "V-1", "SV-1r9_rule", "CAT I", "Open", "HOST-A", "10.0.0.1", "c", ""),
        ]
        assert results_fingerprint(self._rows()) == results_fingerprint(checklist)
        assert len(results_fingerprint(self._rows())) == 64

    def test_a_row_listed_twice_is_the_same_results(self):
        assert results_fingerprint(self._rows()) == results_fingerprint(self._rows() + [_row()])

    @pytest.mark.parametrize("change", [
        {"server": "HOST-B"},
        {"ip": "10.0.0.2"},
        {"status": "Error"},
        {"rule_id": "xccdf_mil.disa.stig_rule_SV-3r1_rule"},
    ])
    def test_a_different_host_address_rule_or_status_is_a_different_scan(self, change):
        assert results_fingerprint(self._rows()) != results_fingerprint([_row(**change), self._rows()[1]])

    def test_a_missing_or_extra_row_is_a_different_scan(self):
        assert results_fingerprint(self._rows()) != results_fingerprint(self._rows()[:1])
        assert results_fingerprint(self._rows()) != results_fingerprint(self._rows() + [_row("SV-9r1_rule")])

    def test_a_rule_with_no_disa_stem_is_keyed_by_its_rule_id_then_its_v_id(self):
        ssg = "xccdf_org.ssgproject.content_rule_accounts_tmout"
        assert results_fingerprint([_row(ssg)]) == results_fingerprint([_row("ACCOUNTS_TMOUT")])
        assert results_fingerprint([_row(ssg)]) != results_fingerprint([_row("accounts_umask")])
        assert results_fingerprint([_row("", vuln_id="V-5")]) == results_fingerprint([_row("", vuln_id="v-5")])
        assert results_fingerprint([_row("", vuln_id="V-5")]) != results_fingerprint([_row("", vuln_id="V-6")])

    def test_where_one_field_ends_cannot_be_forged(self):
        one = [_row("SV-1r1_rule", "c", server="AB", ip="C")]
        two = [_row("SV-1r1_rule", "c", server="A", ip="BC")]
        three = [_row("SV-1r1_rule", "Bc", server="A", ip="C")]
        four = [_row("SV-1r1_rule", "c", server="A", ip="CB")]
        assert len({results_fingerprint(rows) for rows in (one, two, three, four)}) == 4

    def test_a_file_with_no_actionable_rows_has_no_fingerprint(self):
        assert results_fingerprint([]) is None


def test_a_display_name_is_shown_as_it_is_not_escaped_again():
    # The pipeline hands the matcher the file's display name, already escaped and bounded.
    shown = "evil\\r\\nINJECTED.xml"
    finding = Finding("", "", "SV-1r1_rule", "", "Open", "h", "i", "", "")
    line, = unresolved_issue_warnings([MatchIssue("no-benchmark", shown, "", [finding])], [finding],
                                      references_supplied=False)
    assert line.startswith(shown + ": no matching STIG benchmark")
