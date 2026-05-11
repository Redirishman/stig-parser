"""Cross-reference XCCDF scan results against STIG benchmark definitions."""
from __future__ import annotations

import logging
from pathlib import Path

from app.parsers.base import Benchmark, Finding, ScanResult

log = logging.getLogger(__name__)

_STATUS_MAP = {
    "fail": "Open",
    "notchecked": "Not Reviewed",
    "notselected": "Not Reviewed",
    "error": "Error",
    "unknown": "Unknown",
}

_KEEP_STATUSES = frozenset(_STATUS_MAP)


def _normalize_id(raw: str) -> str:
    """Strip file path, extension, and whitespace from a benchmark reference string."""
    return Path(raw).stem.strip().lower()


def _find_benchmark(
    benchmark_href: str,
    benchmark_id: str,
    benchmarks: list[Benchmark],
) -> Benchmark | None:
    """Find the best-matching benchmark for a results file.

    Strategy:
    1. Match by benchmark_id attribute (exact, case-insensitive).
    2. Match by href stem against benchmark_id (handles path-style hrefs).
    3. Substring match — benchmark_id contains or is contained in the href stem.
    """
    if not benchmarks:
        return None

    # Build a normalised id from results
    candidates = [benchmark_href, benchmark_id]
    ref_stems = {_normalize_id(c) for c in candidates if c}

    # Exact match on benchmark id
    for bm in benchmarks:
        bm_id_lower = bm.benchmark_id.lower()
        if bm_id_lower in ref_stems or any(s == bm_id_lower for s in ref_stems):
            return bm

    # Substring match
    for bm in benchmarks:
        bm_id_lower = bm.benchmark_id.lower()
        for ref in ref_stems:
            if bm_id_lower in ref or ref in bm_id_lower:
                return bm

    return None


def match_results_to_benchmarks(
    scan_results: list[ScanResult],
    benchmarks: list[Benchmark],
) -> list[Finding]:
    """Merge scan results with benchmark data to produce Finding objects.

    Only actionable statuses (fail, notchecked, notselected, error, unknown)
    are included in output — all others are discarded here.
    """
    findings: list[Finding] = []

    for scan in scan_results:
        benchmark = _find_benchmark(scan.benchmark_href, scan.benchmark_id, benchmarks)
        if benchmark is None and benchmarks:
            log.warning(
                "%s: Could not match to any benchmark (href=%r, id=%r) — "
                "check/fix text will be blank for all rules",
                scan.source_file,
                scan.benchmark_href,
                scan.benchmark_id,
            )

        stig_title = benchmark.title if benchmark else ""
        unmatched_rule_ids: list[str] = []

        for rr in scan.rule_results:
            display_status = _STATUS_MAP.get(rr.status)
            if display_status is None:
                # Discard: pass, notapplicable, informational, fixed, etc.
                continue

            rule_def = benchmark.rules.get(rr.rule_id) if benchmark else None
            if rule_def is None and benchmark is not None:
                unmatched_rule_ids.append(rr.rule_id)

            findings.append(
                Finding(
                    stig_title=stig_title,
                    vuln_id=rule_def.vuln_id if rule_def else "",
                    rule_id=rr.rule_id,
                    severity=rule_def.severity if rule_def else "",
                    status=display_status,
                    server=scan.hostname,
                    ip_address=scan.ip_address,
                    check_text=rule_def.check_text if rule_def else "",
                    fix_text=rule_def.fix_text if rule_def else "",
                )
            )

        if unmatched_rule_ids:
            log.warning(
                "%s: %d rule(s) not found in benchmark '%s' — check/fix text blank: %s",
                scan.source_file,
                len(unmatched_rule_ids),
                benchmark.benchmark_id if benchmark else "N/A",
                ", ".join(unmatched_rule_ids[:5])
                + ("..." if len(unmatched_rule_ids) > 5 else ""),
            )

    return findings
