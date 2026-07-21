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
