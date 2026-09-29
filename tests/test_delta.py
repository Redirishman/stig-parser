"""Tests for app.processors.delta — baseline-vs-current comparison.

Coverage semantics follow the design spec's Revision 2 (2026-09-28): host and
STIG coverage is passed in explicitly (built by parse_stage from every parsed
row plus one pair per scan file), never derived from the actionable finding
lists. Every ``compute_delta`` call here therefore carries explicit
``baseline_coverage`` / ``current_coverage``; ``cov()`` builds them for the
simple cases where every scanned pair still has at least one finding.
"""
from __future__ import annotations

import logging

from app.parsers.base import Finding
from app.processors.delta import (
    DELTA_STATUSES,
    DeltaFinding,
    DeltaResult,
    compute_delta,
)


def _finding(
    vuln_id: str,
    server: str = "SERVER01",
    status: str = "Open",
    severity: str = "CAT II",
    rule_id: str | None = None,
    stig_title: str = "Win2022 STIG",
) -> Finding:
    if rule_id is None:
        # Distinct Vuln IDs get distinct Rule IDs, as in real benchmark data
        # (a Rule ID belongs to exactly one Vuln ID). "V-1" -> "SV-1r1_rule"
        # keeps the historical default for the single-finding cases.
        rule_id = f"SV-{vuln_id.removeprefix('V-') or '1'}r1_rule"
    return Finding(
        stig_title=stig_title,
        vuln_id=vuln_id,
        rule_id=rule_id,
        severity=severity,
        status=status,
        server=server,
        ip_address="10.0.0.1",
        check_text="check",
        fix_text="fix",
    )


def cov(findings: list[Finding]) -> set[tuple[str, str]]:
    """Coverage pairs implied by *findings*.

    Only valid for the simple cases where every scanned (host, STIG) pair
    still has at least one actionable finding. A fully remediated host or
    STIG has no findings left and must be added to the coverage set by hand
    — that gap is exactly the bug Revision 2 fixes.
    """
    return {(f.server, f.stig_title) for f in findings}


def _by_status(result: DeltaResult) -> dict[str, list[DeltaFinding]]:
    out: dict[str, list[DeltaFinding]] = {s: [] for s in DELTA_STATUSES}
    for f in result.findings:
        out[f.delta_status].append(f)  # KeyError on an unknown status
    return out


class TestClassificationSameHost:
    def test_persisting_when_in_both(self):
        base = [_finding("V-1")]
        curr = [_finding("V-1")]
        buckets = _by_status(
            compute_delta(base, curr, baseline_coverage=cov(base), current_coverage=cov(curr))
        )
        assert len(buckets["Persisting"]) == 1
        assert buckets["New"] == []
        assert buckets["Resolved"] == []

    def test_new_when_only_current(self):
        base = [_finding("V-1")]
        curr = [_finding("V-1"), _finding("V-2")]
        buckets = _by_status(
            compute_delta(base, curr, baseline_coverage=cov(base), current_coverage=cov(curr))
        )
        new = buckets["New"]
        assert len(new) == 1
        assert new[0].vuln_id == "V-2"
        assert new[0].baseline_status == ""
        assert new[0].current_status == "Open"

    def test_resolved_when_only_baseline(self):
        base = [_finding("V-1"), _finding("V-2")]
        curr = [_finding("V-1")]
        buckets = _by_status(
            compute_delta(base, curr, baseline_coverage=cov(base), current_coverage=cov(curr))
        )
        resolved = buckets["Resolved"]
        assert len(resolved) == 1
        assert resolved[0].vuln_id == "V-2"
        assert resolved[0].current_status == ""
        assert resolved[0].baseline_status == "Open"


class TestCoverageScoping:
    def test_baseline_only_host_is_not_rescanned_never_resolved(self):
        # SERVER02 present in baseline coverage only -> its findings are
        # tagged Not re-scanned (kept on the report), never Resolved.
        base = [_finding("V-1", "SERVER01"), _finding("V-9", "SERVER02")]
        curr = [_finding("V-1", "SERVER01")]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        buckets = _by_status(result)
        assert buckets["Resolved"] == []
        assert [f.vuln_id for f in buckets["Not re-scanned"]] == ["V-9"]
        assert buckets["Not re-scanned"][0].server == "SERVER02"
        assert result.only_baseline_hosts == {"SERVER02"}
        assert result.common_hosts == {"SERVER01"}

    def test_current_only_host_is_newly_scanned_never_new(self):
        base = [_finding("V-1", "SERVER01")]
        curr = [_finding("V-1", "SERVER01"), _finding("V-5", "SERVER03")]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        buckets = _by_status(result)
        assert buckets["New"] == []
        assert [f.vuln_id for f in buckets["Newly scanned"]] == ["V-5"]
        assert buckets["Newly scanned"][0].server == "SERVER03"
        assert result.only_current_hosts == {"SERVER03"}

    def test_resolved_only_on_common_host(self):
        base = [_finding("V-1", "SERVER01"), _finding("V-2", "SERVER01")]
        curr = [_finding("V-1", "SERVER01")]
        buckets = _by_status(
            compute_delta(base, curr, baseline_coverage=cov(base), current_coverage=cov(curr))
        )
        assert [f.vuln_id for f in buckets["Resolved"]] == ["V-2"]


class TestCoverageFromScans:
    """Revision 2: coverage is per (host, STIG) pair and comes from the scans,
    not from the actionable finding lists. These encode the live defect —
    a STIG that was not re-scanned reported as Resolved, and a fully
    remediated host vanishing from the report."""

    def test_delta_statuses_constant(self):
        assert DELTA_STATUSES == (
            "New", "Resolved", "Persisting", "Not re-scanned", "Newly scanned",
        )

    def test_fully_remediated_host_is_all_resolved(self):
        # HOST-A has no findings left, but the current scan set DID scan it
        # (its pair is in current_coverage) -> both baseline findings are
        # Resolved. Old behaviour: HOST-A was invisible and dropped.
        base = [_finding("V-1", "HOST-A"), _finding("V-2", "HOST-A")]
        curr: list[Finding] = []
        result = compute_delta(
            base, curr,
            baseline_coverage=cov(base),
            current_coverage={("HOST-A", "Win2022 STIG")},
        )
        buckets = _by_status(result)
        assert sorted(f.vuln_id for f in buckets["Resolved"]) == ["V-1", "V-2"]
        assert len(result.findings) == 2
        assert result.common_hosts == {"HOST-A"}
        assert result.only_baseline_hosts == set()
        assert result.not_rescanned_pairs == set()

    def test_stig_not_rescanned_is_not_resolved(self):
        # HOST-A is in both sets via Win2022, but the Edge STIG scan was
        # left out of the current set -> its findings are Not re-scanned,
        # zero Resolved. Old behaviour: 'Resolved' (false remediation claim).
        edge = "Microsoft Edge STIG SCAP Benchmark"
        base = [
            _finding("V-1", "HOST-A"),
            _finding("V-7", "HOST-A", stig_title=edge),
            _finding("V-8", "HOST-A", stig_title=edge),
        ]
        curr = [_finding("V-1", "HOST-A")]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        buckets = _by_status(result)
        assert buckets["Resolved"] == []
        assert sorted(f.vuln_id for f in buckets["Not re-scanned"]) == ["V-7", "V-8"]
        assert len(buckets["Persisting"]) == 1
        assert result.not_rescanned_pairs == {("HOST-A", edge)}
        assert result.newly_scanned_pairs == set()
        assert result.common_hosts == {"HOST-A"}
        assert result.only_baseline_hosts == set()

    def test_newly_scanned_stig_is_not_new(self):
        edge = "Microsoft Edge STIG SCAP Benchmark"
        base = [_finding("V-1", "HOST-A")]
        curr = [
            _finding("V-1", "HOST-A"),
            _finding("V-7", "HOST-A", stig_title=edge),
        ]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        buckets = _by_status(result)
        assert buckets["New"] == []
        assert [f.vuln_id for f in buckets["Newly scanned"]] == ["V-7"]
        assert result.newly_scanned_pairs == {("HOST-A", edge)}
        assert result.not_rescanned_pairs == set()

    def test_host_only_in_current_coverage_is_all_newly_scanned(self):
        base = [_finding("V-1", "HOST-A")]
        curr = [
            _finding("V-1", "HOST-A"),
            _finding("V-2", "HOST-B"),
            _finding("V-3", "HOST-B"),
        ]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        buckets = _by_status(result)
        assert buckets["New"] == []
        assert sorted(f.vuln_id for f in buckets["Newly scanned"]) == ["V-2", "V-3"]
        assert result.only_current_hosts == {"HOST-B"}
        assert result.newly_scanned_pairs == {("HOST-B", "Win2022 STIG")}

    def test_host_only_in_baseline_coverage_is_all_not_rescanned(self):
        base = [
            _finding("V-1", "HOST-A"),
            _finding("V-2", "HOST-B"),
            _finding("V-3", "HOST-B"),
        ]
        curr = [_finding("V-1", "HOST-A")]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        buckets = _by_status(result)
        assert buckets["Resolved"] == []
        assert sorted(f.vuln_id for f in buckets["Not re-scanned"]) == ["V-2", "V-3"]
        assert result.only_baseline_hosts == {"HOST-B"}
        assert result.not_rescanned_pairs == {("HOST-B", "Win2022 STIG")}

    def test_scap_and_manual_editions_share_a_pair(self):
        # The same STIG spelled as its SCAP benchmark in one run and its
        # Manual XCCDF in the other must be ONE (host, STIG) pair, or every
        # benchmark-edition change looks like a not-re-scanned + newly-scanned
        # swap.
        scap = "Microsoft Windows 11 STIG SCAP Benchmark"
        manual = "Microsoft Windows 11 Security Technical Implementation Guide"
        base = [
            _finding("V-1", "HOST-A", stig_title=scap),
            _finding("V-2", "HOST-A", stig_title=scap),
        ]
        curr = [_finding("V-1", "HOST-A", stig_title=manual)]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        buckets = _by_status(result)
        assert len(buckets["Persisting"]) == 1
        assert [f.vuln_id for f in buckets["Resolved"]] == ["V-2"]
        assert buckets["Not re-scanned"] == []
        assert buckets["Newly scanned"] == []
        assert result.not_rescanned_pairs == set()
        assert result.newly_scanned_pairs == set()

    def test_nessus_audit_revisions_share_a_pair(self):
        v8 = "DISA_STIG_MS_Windows_11_v2r8.audit"
        v9 = "DISA_STIG_MS_Windows_11_v2r9.audit"
        base = [
            _finding("V-1", "HOST-A", stig_title=v8),
            _finding("V-2", "HOST-A", stig_title=v8),
        ]
        curr = [_finding("V-1", "HOST-A", stig_title=v9)]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        buckets = _by_status(result)
        assert len(buckets["Persisting"]) == 1
        assert [f.vuln_id for f in buckets["Resolved"]] == ["V-2"]
        assert buckets["Not re-scanned"] == []
        assert buckets["Newly scanned"] == []
        assert result.not_rescanned_pairs == set()
        assert result.newly_scanned_pairs == set()

    def test_pass_two_never_matches_blank_rule_ids(self):
        # V-2 (baseline) and V-3 (current) both carry a blank rule_id. A
        # rule-keyed pass that treats "" as a key pairs them up as one
        # Persisting finding — hiding a real remediation and a real
        # regression at once.
        base = [_finding("V-1", rule_id="SV-1_rule"), _finding("V-2", rule_id="")]
        curr = [_finding("V-1", rule_id="SV-1_rule"), _finding("V-3", rule_id="")]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        buckets = _by_status(result)
        assert [f.vuln_id for f in buckets["Persisting"]] == ["V-1"]
        assert [f.vuln_id for f in buckets["Resolved"]] == ["V-2"]
        assert [f.vuln_id for f in buckets["New"]] == ["V-3"]

    def test_findings_with_no_identity_are_never_persisting(self):
        # Blank vuln_id AND blank rule_id on both sides: nothing says these
        # are the same finding, so they must not be paired.
        base = [_finding("V-1"), _finding("", rule_id="")]
        curr = [_finding("V-1"), _finding("", rule_id="")]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        buckets = _by_status(result)
        assert [f.vuln_id for f in buckets["Persisting"]] == ["V-1"]
        assert len(buckets["Resolved"]) == 1 and buckets["Resolved"][0].rule_id == ""
        assert len(buckets["New"]) == 1 and buckets["New"][0].rule_id == ""

    def test_pass_two_matches_on_rule_stem_across_revisions(self):
        # No vuln_id on either side (no --benchmarks); rule IDs differ only
        # by the XCCDF namespace prefix and the rNNN revision -> Persisting.
        base = [_finding("", rule_id="xccdf_mil.disa.stig_rule_SV-1r1_rule")]
        curr = [_finding("", rule_id="SV-1r2_rule")]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        buckets = _by_status(result)
        assert len(buckets["Persisting"]) == 1
        assert buckets["New"] == [] and buckets["Resolved"] == []

    def test_rows_sort_by_normalised_host_key(self):
        # Raw-string sort puts "Zeta" before "apple" (uppercase first).
        base = [_finding("V-1", "Zeta"), _finding("V-1", "apple")]
        curr = [_finding("V-1", "Zeta"), _finding("V-1", "apple")]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        assert [f.server for f in result.findings] == ["apple", "Zeta"]

    def test_no_overlap_warning_is_on_the_result(self):
        base = [_finding("V-1", "A")]
        curr = [_finding("V-1", "B")]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        assert any("no hosts appear in both" in w.lower() for w in result.warnings), (
            result.warnings
        )

    def test_not_rescanned_pairs_warning_names_the_pair(self):
        edge = "Microsoft Edge STIG SCAP Benchmark"
        base = [_finding("V-1", "HOST-A"), _finding("V-7", "HOST-A", stig_title=edge)]
        curr = [_finding("V-1", "HOST-A")]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        assert any(
            "not re-scanned" in w.lower() and "HOST-A" in w and edge in w
            for w in result.warnings
        ), result.warnings

    def test_newly_scanned_pairs_warning_names_the_pair(self):
        edge = "Microsoft Edge STIG SCAP Benchmark"
        base = [_finding("V-1", "HOST-A")]
        curr = [_finding("V-1", "HOST-A"), _finding("V-7", "HOST-A", stig_title=edge)]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        assert any(
            "newly scanned" in w.lower() and "HOST-A" in w and edge in w
            for w in result.warnings
        ), result.warnings


class TestPersistingDetail:
    def test_status_flip_retained(self):
        base = [_finding("V-1", status="Not Reviewed")]
        curr = [_finding("V-1", status="Open")]
        f = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        ).findings[0]
        assert f.delta_status == "Persisting"
        assert f.baseline_status == "Not Reviewed"
        assert f.current_status == "Open"

    def test_benchmark_revision_churn_is_persisting(self):
        # Same vuln_id, different rule_id revision -> Persisting, not New+Resolved
        base = [_finding("V-1", rule_id="SV-1r1_rule")]
        curr = [_finding("V-1", rule_id="SV-1r2_rule")]
        buckets = _by_status(
            compute_delta(base, curr, baseline_coverage=cov(base), current_coverage=cov(curr))
        )
        assert len(buckets["Persisting"]) == 1
        assert buckets["New"] == [] and buckets["Resolved"] == []


class TestEmptySets:
    def test_empty_baseline_coverage_all_newly_scanned(self):
        # Nothing was scanned in the baseline -> every current host is a
        # newly scanned host -> all Newly scanned, nothing New.
        curr = [_finding("V-1"), _finding("V-2")]
        buckets = _by_status(
            compute_delta([], curr, baseline_coverage=set(), current_coverage=cov(curr))
        )
        assert len(buckets["Newly scanned"]) == 2
        assert buckets["New"] == []
        assert buckets["Resolved"] == []

    def test_empty_current_coverage_all_not_rescanned(self):
        # Nothing was scanned in the current set -> nothing can be Resolved;
        # the baseline findings stay on the report as Not re-scanned.
        base = [_finding("V-1"), _finding("V-2")]
        result = compute_delta(
            base, [], baseline_coverage=cov(base), current_coverage=set()
        )
        buckets = _by_status(result)
        assert len(buckets["Not re-scanned"]) == 2
        assert buckets["Resolved"] == []
        assert result.only_baseline_hosts == {"SERVER01"}

    def test_both_empty(self):
        result = compute_delta([], [], baseline_coverage=set(), current_coverage=set())
        assert result.findings == []


class TestBlankVulnIdIdentity:
    def test_blank_vuln_id_findings_kept_distinct(self):
        # vuln_id is blank when a rule can't be matched to a benchmark
        # (matcher.py) or the source has no V-ID (Nessus non-DISA, CKLB
        # without group_id). A naive (server, vuln_id) key would collapse
        # all three baseline findings onto one dict slot and silently drop
        # two of them. rule_id must be used as the tiebreaker.
        base = [
            _finding("", rule_id="SV-1_rule", status="Open"),
            _finding("", rule_id="SV-2_rule", status="Open"),
            _finding("", rule_id="SV-3_rule", status="Open"),
        ]
        curr = [
            _finding("", rule_id="SV-1_rule", status="Open"),  # persists
            _finding("", rule_id="SV-2_rule", status="Open"),  # persists
            # SV-3_rule dropped -> resolved
        ]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        assert len(result.findings) == 3
        buckets = _by_status(result)
        assert len(buckets["Persisting"]) == 2
        assert [f.rule_id for f in buckets["Resolved"]] == ["SV-3_rule"]

    def test_duplicate_key_within_one_set_keeps_first_and_warns(self, caplog):
        # Two findings on the same host with the same vuln_id (or both
        # blank vuln_id + same rule_id) are a genuine key collision, not a
        # dropped-finding scenario. Silent last-write-wins would hide it;
        # the implementation should keep the first and log a warning.
        base = [_finding("V-1")]
        curr = [_finding("V-1"), _finding("V-1")]
        with caplog.at_level(logging.WARNING):
            result = compute_delta(
                base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
            )
        assert len(result.findings) == 1
        assert result.findings[0].delta_status == "Persisting"
        assert any("duplicate" in rec.message.lower() for rec in caplog.records)
        # DeltaResult.warnings is the user-visible channel (mirrors
        # ParseResult.warnings) -- the pipeline's log.warning alone isn't
        # enough for an operator to see it in the CLI/exporter output.
        assert any("duplicate" in w.lower() for w in result.warnings)


class TestHostMatching:
    def test_disjoint_hosts_hostname_mismatch(self):
        # No host overlap: A was not re-scanned, B is newly scanned. Nothing
        # is New or Resolved, because nothing was compared.
        base = [_finding("V-1", "A")]
        curr = [_finding("V-1", "B")]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        assert result.common_hosts == set()
        buckets = _by_status(result)
        assert buckets["Resolved"] == []
        assert buckets["New"] == []
        assert [f.server for f in buckets["Not re-scanned"]] == ["A"]
        assert [f.server for f in buckets["Newly scanned"]] == ["B"]

    def test_case_insensitive_host_match(self):
        base = [_finding("V-1", "SERVER01")]
        curr = [_finding("V-1", "server01")]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        assert len(result.common_hosts) == 1
        buckets = _by_status(result)
        assert len(buckets["Persisting"]) == 1
        assert buckets["New"] == []
        assert buckets["Resolved"] == []
        assert buckets["Not re-scanned"] == []
        assert buckets["Newly scanned"] == []


class TestResolvedRowData:
    def test_resolved_row_carries_baseline_data(self):
        base = [
            Finding(
                stig_title="Baseline STIG Title",
                vuln_id="V-9",
                rule_id="SV-9r1_rule",
                severity="CAT I",
                status="Open",
                server="SERVER01",
                ip_address="10.0.0.9",
                check_text="baseline check text",
                fix_text="baseline fix text",
            )
        ]
        curr = [_finding("V-1", "SERVER01")]  # keeps SERVER01 in common hosts
        result = compute_delta(
            base, curr,
            baseline_coverage=cov(base),
            # The baseline STIG was re-scanned (pair present) but is clean now.
            current_coverage=cov(curr) | {("SERVER01", "Baseline STIG Title")},
        )
        resolved = [f for f in result.findings if f.delta_status == "Resolved"]
        assert len(resolved) == 1
        f = resolved[0]
        assert f.stig_title == "Baseline STIG Title"
        assert f.severity == "CAT I"
        assert f.check_text == "baseline check text"
        assert f.fix_text == "baseline fix text"
        assert f.baseline_status == "Open"
        assert f.current_status == ""


class TestAsymmetricBenchmarkCoverage:
    """Regression coverage for the round-2 review finding: a single-key
    scheme (vuln_id-or-rule_id) fails when one run is parsed WITH a
    benchmark and the other WITHOUT. The reviewer reproduced this by
    running the same fixture file through parse_stage twice -- once with
    ``benchmarks=[]`` and once with a real benchmark -- and got
    Counter({'Resolved': 5, 'New': 5}) for identical scan data.

    These finding lists are constructed by hand rather than via a live
    parse_stage() call (keeping this module's test suite pure-unit like
    the rest of the file), but mirror exactly what parse_stage produces
    for that scenario: blank vuln_id + full rule_id when no benchmark is
    supplied, populated vuln_id + the SAME rule_id when one is.
    """

    def test_same_scan_no_benchmark_vs_with_benchmark_is_all_persisting(self):
        rule_ids = [
            f"xccdf_mil.disa.stig_rule_SV-25423{i}r945408_rule" for i in range(5)
        ]
        # baseline: parsed WITHOUT --benchmarks -> vuln_id blank everywhere
        base = [
            _finding("", server="HOST1", rule_id=rid, status="Open")
            for rid in rule_ids
        ]
        # current: parsed WITH --benchmarks -> vuln_id populated
        curr = [
            _finding(f"V-25423{i}", server="HOST1", rule_id=rid, status="Open")
            for i, rid in enumerate(rule_ids)
        ]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        buckets = _by_status(result)
        assert buckets["Resolved"] == []
        assert buckets["New"] == []
        assert len(buckets["Persisting"]) == 5
        # Two-pass matching fully recovered every finding as Persisting --
        # no residual Resolved/New -- so there's nothing unreliable to warn
        # about here (see TestAsymmetricBenchmarkCoverage's other test for
        # the case where a coverage-mismatch warning SHOULD fire).
        assert result.warnings == []

    def test_asymmetric_coverage_with_a_genuine_change_still_resolves_correctly(self):
        # Same asymmetric-coverage setup, but one finding is genuinely
        # fixed (present in baseline, absent from current) and one is
        # genuinely new (present in current only, no baseline rule_id
        # match at all). Two-pass rule_id matching should not paper over
        # real changes -- only recover the ones that are byte-identical.
        base = [
            _finding("", server="HOST1", rule_id="SV-1_rule", status="Open"),
            _finding("", server="HOST1", rule_id="SV-2_rule", status="Open"),
        ]
        curr = [
            _finding("V-1", server="HOST1", rule_id="SV-1_rule", status="Open"),
            # SV-2_rule genuinely fixed -- absent from current
            _finding("V-3", server="HOST1", rule_id="SV-3_rule", status="Open"),
        ]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        buckets = _by_status(result)
        assert len(buckets["Persisting"]) == 1
        assert buckets["Persisting"][0].rule_id == "SV-1_rule"
        assert [f.rule_id for f in buckets["Resolved"]] == ["SV-2_rule"]
        assert [f.vuln_id for f in buckets["New"]] == ["V-3"]
        # Residual Resolved/New remains AND the two runs have different
        # Vuln-ID coverage (100% blank in baseline, 0% in current) -- this
        # is exactly the condition under which the coverage-mismatch
        # warning should fire, so the operator knows to double-check
        # SV-2_rule's "Resolved" classification.
        assert any(
            "vuln-id coverage" in w.lower() or "benchmark" in w.lower()
            for w in result.warnings
        )


class TestDeterministicOrdering:
    def test_stable_across_repeated_calls(self):
        base = [_finding("", rule_id=f"SV-{i}_rule") for i in range(6)]
        curr = [_finding("", rule_id=f"SV-{i}_rule") for i in range(6)]
        orders = [
            [
                f.rule_id
                for f in compute_delta(
                    base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
                ).findings
            ]
            for _ in range(3)
        ]
        assert orders[0] == orders[1] == orders[2]

    def test_explicit_order_for_blank_vuln_id_tie(self):
        # All on the same server, all blank vuln_id, all Persisting -> the
        # sort key ties down to rule_id, which must break the tie
        # deterministically (host key, vuln_id, rule_id, delta_status).
        base = [_finding("", rule_id=f"SV-{i}_rule") for i in (3, 1, 4, 0, 5, 2)]
        curr = [_finding("", rule_id=f"SV-{i}_rule") for i in (3, 1, 4, 0, 5, 2)]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        assert [f.rule_id for f in result.findings] == [
            "SV-0_rule",
            "SV-1_rule",
            "SV-2_rule",
            "SV-3_rule",
            "SV-4_rule",
            "SV-5_rule",
        ]


class TestWarningsField:
    def test_defaults_to_empty_list(self):
        base = [_finding("V-1")]
        curr = [_finding("V-1")]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        assert result.warnings == []


class TestBlankStigTitleCoverage:
    def test_blank_stig_title_pairs_warn_and_name_the_host(self):
        # A scan that could not be matched to a benchmark has stig_title "",
        # so every such STIG on a host shares ONE coverage pair — a STIG not
        # re-scanned there cannot be told apart from one fully remediated.
        # The delta fails closed (see TestBlankStigTitleFailsClosed) and
        # the operator is told to supply --benchmarks.
        base = [_finding("V-1", "HOST-A", stig_title="")]
        curr = [_finding("V-1", "HOST-A", stig_title="")]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        assert any(
            "no stig title" in w.lower() and "HOST-A" in w and "--benchmarks" in w
            for w in result.warnings
        ), result.warnings

    def test_blank_title_warning_says_findings_are_tagged_not_rescanned(self):
        # The warning must say what the report did about it, not hint that
        # a Resolved count "may" be wrong.
        base = [_finding("V-1", "HOST-A", stig_title="")]
        curr = [_finding("V-1", "HOST-A", stig_title="")]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        assert any(
            "cannot be verified as re-scanned" in w
            and "Not re-scanned / Newly scanned" in w
            and "--benchmarks for both sets" in w
            and "HOST-A" in w
            for w in result.warnings
        ), result.warnings

    def test_titled_pairs_do_not_warn(self):
        base = [_finding("V-1", "HOST-A")]
        curr = [_finding("V-1", "HOST-A")]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        assert result.warnings == []


class TestBlankStigTitleFailsClosed:
    """R2-9: a scan that matched no benchmark has no STIG title, so a
    finding on it cannot be verified as re-scanned. Leftover baseline
    findings on such a pair are Not re-scanned (never Resolved) and leftover
    current findings are Newly scanned (never New); matched pairs stay
    Persisting. Before this, a blank pair present on both sides made every
    dropped finding Resolved — a false remediation claim."""

    def test_untitled_both_sides_dropped_finding_is_not_resolved(self):
        base = [
            _finding("V-1", "HOST-A", stig_title=""),
            _finding("V-2", "HOST-A", stig_title=""),
        ]
        curr = [_finding("V-1", "HOST-A", stig_title="")]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        buckets = _by_status(result)
        assert buckets["Resolved"] == []
        assert [f.vuln_id for f in buckets["Not re-scanned"]] == ["V-2"]
        assert [f.vuln_id for f in buckets["Persisting"]] == ["V-1"]

    def test_untitled_both_sides_added_finding_is_not_new(self):
        base = [_finding("V-1", "HOST-A", stig_title="")]
        curr = [
            _finding("V-1", "HOST-A", stig_title=""),
            _finding("V-3", "HOST-A", stig_title=""),
        ]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        buckets = _by_status(result)
        assert buckets["New"] == []
        assert [f.vuln_id for f in buckets["Newly scanned"]] == ["V-3"]
        assert [f.vuln_id for f in buckets["Persisting"]] == ["V-1"]

    def test_untitled_both_sides_same_findings_all_persisting(self):
        base = [
            _finding("V-1", "HOST-A", stig_title=""),
            _finding("V-2", "HOST-A", stig_title=""),
        ]
        curr = [
            _finding("V-1", "HOST-A", stig_title=""),
            _finding("V-2", "HOST-A", stig_title=""),
        ]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        buckets = _by_status(result)
        assert sorted(f.vuln_id for f in buckets["Persisting"]) == ["V-1", "V-2"]
        assert len(result.findings) == 2

    def test_untitled_baseline_vs_titled_current_leftovers_not_resolved(self):
        # --benchmarks supplied for the current run only: the baseline pair
        # is (HOST-A, "") and the current pair is (HOST-A, "Win2022 STIG").
        # V-1 still matches (identity is host + vuln_id); the dropped V-2
        # cannot be shown re-scanned and must not be Resolved.
        base = [
            _finding("V-1", "HOST-A", stig_title=""),
            _finding("V-2", "HOST-A", stig_title=""),
        ]
        curr = [_finding("V-1", "HOST-A", stig_title="Win2022 STIG")]
        result = compute_delta(
            base, curr, baseline_coverage=cov(base), current_coverage=cov(curr)
        )
        buckets = _by_status(result)
        assert buckets["Resolved"] == []
        assert [f.vuln_id for f in buckets["Not re-scanned"]] == ["V-2"]
        assert [f.vuln_id for f in buckets["Persisting"]] == ["V-1"]
