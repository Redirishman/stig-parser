"""Tests for filter.py."""
from app.parsers.base import Finding
from app.processors.filter import filter_findings


def _finding(status: str) -> Finding:
    return Finding(
        stig_title="Test STIG",
        vuln_id="V-000001",
        rule_id="SV-000001r000000_rule",
        severity="CAT I",
        status=status,
        server="SERVER01",
        ip_address="10.0.0.1",
        check_text="check",
        fix_text="fix",
    )


def test_open_kept():
    assert len(filter_findings([_finding("Open")])) == 1


def test_not_reviewed_kept():
    assert len(filter_findings([_finding("Not Reviewed")])) == 1


def test_error_kept():
    assert len(filter_findings([_finding("Error")])) == 1


def test_unknown_kept():
    assert len(filter_findings([_finding("Unknown")])) == 1


def test_unknown_status_discarded():
    assert len(filter_findings([_finding("SomeOtherStatus")])) == 0


def test_empty_list():
    assert filter_findings([]) == []


def test_mixed_list():
    findings = [
        _finding("Open"),
        _finding("SomeOtherStatus"),
        _finding("Not Reviewed"),
        _finding("Error"),
    ]
    result = filter_findings(findings)
    assert len(result) == 3
    assert all(f.status in {"Open", "Not Reviewed", "Error"} for f in result)
