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
        assert all(f.server != "SERVER02" for f in result.findings)

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
        result = compute_delta(base, curr)
        assert len(result.findings) == 3
        buckets = _by_status(result)
        assert len(buckets["Persisting"]) == 2
        assert [f.rule_id for f in buckets["Resolved"]] == ["SV-3_rule"]

    def test_duplicate_key_within_one_set_keeps_first_and_warns(self, caplog):
        # Two findings on the same host with the same vuln_id (or both
        # blank vuln_id + same rule_id) are a genuine key collision, not a
        # dropped-finding scenario. Silent last-write-wins would hide it;
        # the implementation should keep the first and log a warning.
        import logging

        base = [_finding("V-1")]
        curr = [_finding("V-1"), _finding("V-1")]
        with caplog.at_level(logging.WARNING):
            result = compute_delta(base, curr)
        assert len(result.findings) == 1
        assert result.findings[0].delta_status == "Persisting"
        assert any("duplicate" in rec.message.lower() for rec in caplog.records)


class TestHostMatching:
    def test_disjoint_hosts_hostname_mismatch(self):
        base = [_finding("V-1", "A")]
        curr = [_finding("V-1", "B")]
        result = compute_delta(base, curr)
        assert result.common_hosts == set()
        buckets = _by_status(result)
        assert buckets["Resolved"] == []
        assert len(buckets["New"]) == 1
        assert buckets["New"][0].server == "B"

    def test_case_insensitive_host_match(self):
        base = [_finding("V-1", "SERVER01")]
        curr = [_finding("V-1", "server01")]
        result = compute_delta(base, curr)
        assert len(result.common_hosts) == 1
        buckets = _by_status(result)
        assert len(buckets["Persisting"]) == 1
        assert buckets["New"] == []
        assert buckets["Resolved"] == []


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
        result = compute_delta(base, curr)
        resolved = [f for f in result.findings if f.delta_status == "Resolved"]
        assert len(resolved) == 1
        f = resolved[0]
        assert f.stig_title == "Baseline STIG Title"
        assert f.severity == "CAT I"
        assert f.check_text == "baseline check text"
        assert f.fix_text == "baseline fix text"
        assert f.baseline_status == "Open"
        assert f.current_status == ""
