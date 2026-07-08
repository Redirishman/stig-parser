# tests/test_pipeline.py
"""Tests for the shared parse→export pipeline."""
from pathlib import Path

import pytest

from app.core.pipeline import (
    ParseResult,
    PipelineError,
    compute_summary,
    default_output_name,
    export_stage,
    parse_stage,
)
from app.parsers.base import Finding


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
