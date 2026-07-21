"""Tests for app.processors.delta — baseline-vs-current comparison."""
from __future__ import annotations

from app.parsers.base import Finding
from app.processors.delta import DeltaFinding, DeltaResult, compute_delta


def _finding(
    vuln_id: str,
    server: str = "SERVER01",
    status: str = "Open",
    severity: str = "CAT II",
    rule_id: str = "SV-1r1_rule",
) -> Finding:
    return Finding(
        stig_title="Win2022 STIG",
        vuln_id=vuln_id,
        rule_id=rule_id,
        severity=severity,
        status=status,
        server=server,
        ip_address="10.0.0.1",
        check_text="check",
        fix_text="fix",
    )


def _by_status(result: DeltaResult) -> dict[str, list[DeltaFinding]]:
    out: dict[str, list[DeltaFinding]] = {"New": [], "Resolved": [], "Persisting": []}
    for f in result.findings:
        out[f.delta_status].append(f)
    return out


class TestClassificationSameHost:
    def test_persisting_when_in_both(self):
        base = [_finding("V-1")]
        curr = [_finding("V-1")]
        buckets = _by_status(compute_delta(base, curr))
        assert len(buckets["Persisting"]) == 1
        assert buckets["New"] == []
        assert buckets["Resolved"] == []

    def test_new_when_only_current(self):
        base = [_finding("V-1")]
        curr = [_finding("V-1"), _finding("V-2")]
        buckets = _by_status(compute_delta(base, curr))
        new = buckets["New"]
        assert len(new) == 1
        assert new[0].vuln_id == "V-2"
        assert new[0].baseline_status == ""
        assert new[0].current_status == "Open"

    def test_resolved_when_only_baseline(self):
        base = [_finding("V-1"), _finding("V-2")]
        curr = [_finding("V-1")]
        buckets = _by_status(compute_delta(base, curr))
        resolved = buckets["Resolved"]
        assert len(resolved) == 1
        assert resolved[0].vuln_id == "V-2"
        assert resolved[0].current_status == ""
        assert resolved[0].baseline_status == "Open"


class TestCoverageScoping:
    def test_baseline_only_host_not_counted_resolved(self):
        # SERVER02 present in baseline only -> its findings are NOT resolved
        base = [_finding("V-1", "SERVER01"), _finding("V-9", "SERVER02")]
        curr = [_finding("V-1", "SERVER01")]
        result = compute_delta(base, curr)
        buckets = _by_status(result)
        assert [f.vuln_id for f in buckets["Resolved"]] == []
        assert result.only_baseline_hosts == {"SERVER02"}
        assert result.common_hosts == {"SERVER01"}

    def test_current_only_host_all_new(self):
        base = [_finding("V-1", "SERVER01")]
        curr = [_finding("V-1", "SERVER01"), _finding("V-5", "SERVER03")]
        result = compute_delta(base, curr)
        buckets = _by_status(result)
        new_on_new_host = [f for f in buckets["New"] if f.server == "SERVER03"]
        assert len(new_on_new_host) == 1
        assert result.only_current_hosts == {"SERVER03"}

    def test_resolved_only_on_common_host(self):
        base = [_finding("V-1", "SERVER01"), _finding("V-2", "SERVER01")]
        curr = [_finding("V-1", "SERVER01")]
        buckets = _by_status(compute_delta(base, curr))
        assert [f.vuln_id for f in buckets["Resolved"]] == ["V-2"]


class TestPersistingDetail:
    def test_status_flip_retained(self):
        base = [_finding("V-1", status="Not Reviewed")]
        curr = [_finding("V-1", status="Open")]
        f = compute_delta(base, curr).findings[0]
        assert f.delta_status == "Persisting"
        assert f.baseline_status == "Not Reviewed"
        assert f.current_status == "Open"

    def test_benchmark_revision_churn_is_persisting(self):
        # Same vuln_id, different rule_id revision -> Persisting, not New+Resolved
        base = [_finding("V-1", rule_id="SV-1r1_rule")]
        curr = [_finding("V-1", rule_id="SV-1r2_rule")]
        buckets = _by_status(compute_delta(base, curr))
        assert len(buckets["Persisting"]) == 1
        assert buckets["New"] == [] and buckets["Resolved"] == []


class TestEmptySets:
    def test_empty_baseline_all_new(self):
        # No baseline hosts -> every current host is a new host -> all New
        curr = [_finding("V-1"), _finding("V-2")]
        buckets = _by_status(compute_delta([], curr))
        assert len(buckets["New"]) == 2
        assert buckets["Resolved"] == []

    def test_empty_current_all_not_rescanned(self):
        # No current hosts -> baseline hosts all unscanned -> nothing Resolved
        base = [_finding("V-1"), _finding("V-2")]
        result = compute_delta(base, [])
        assert result.findings == []
        assert result.only_baseline_hosts == {"SERVER01"}

    def test_both_empty(self):
        result = compute_delta([], [])
        assert result.findings == []
