"""Abstract base parser and shared data models."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

_ROW_WARNINGS = 5   # per-row problems of one file logged at WARNING; the rest at DEBUG


class RowLog:
    """Logs the per-row problems of one file: the first five at WARNING, the rest at
    DEBUG. A file can hold 50,000 bad rows, and the web UI shows every WARNING line;
    what counts reaches the operator as a count instead. Callers pass every value
    that comes from the file through ``safe_name``."""

    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger
        self._count = 0

    def __call__(self, msg: str, *args: object) -> None:
        self._count += 1
        self._logger.log(logging.WARNING if self._count <= _ROW_WARNINGS else logging.DEBUG, msg, *args)


@dataclass
class RuleResult:
    """A single rule result extracted from an XCCDF results file."""
    rule_id: str
    status: str  # raw XCCDF value: fail, pass, notchecked, error, unknown, etc.


@dataclass
class ScanResult:
    """All results extracted from one XCCDF results file."""
    source_file: str               # filename (stem used as hostname fallback)
    hostname: str
    ip_address: str
    benchmark_href: str            # href attribute from <benchmark> element
    benchmark_id: str              # id attribute from <benchmark> element
    scanner: str                   # detected scanner name
    rule_results: list[RuleResult] = field(default_factory=list)
    # Benchmarks embedded in this same results file (SCC). The matcher takes rule
    # data and the scanned release from these only; the pipeline attaches them.
    embedded_benchmarks: list[Benchmark] = field(default_factory=list)


@dataclass(slots=True)
class BenchmarkRule:
    """A single rule extracted from a STIG benchmark definition."""
    vuln_id: str        # V-XXXXXX from Group id
    rule_id: str        # SV-XXXXXXrYYYYYY_rule from Rule id
    severity: str       # "CAT I" | "CAT II" | "CAT III"
    check_text: str
    fix_text: str
    stig_id: str = ""   # XCCDF <version>, e.g. WN22-00-000010


@dataclass
class Benchmark:
    """All data extracted from one STIG benchmark XML file."""
    benchmark_id: str
    title: str
    rules: dict[str, BenchmarkRule] = field(default_factory=dict)  # keyed by rule_id
    release: str = ""   # "V2R8"


@dataclass
class Finding:
    """A merged, filtered finding ready for Excel export."""
    stig_title: str
    vuln_id: str
    rule_id: str
    severity: str       # "CAT I" | "CAT II" | "CAT III"
    status: str         # "Open" | "Not Reviewed" | "Error" | "Unknown"
    server: str
    ip_address: str
    check_text: str
    fix_text: str
    stig_id: str = ""        # WN22-00-000010 — the stable cross-source rule key
    text_source: str = ""    # where check/fix text came from (workbook column K)
    scan_release: str = ""   # release of the benchmark that was scanned, e.g. V2R8


class BaseParser:
    """Base of the file parsers. Each one's ``read`` (``read_all`` for benchmarks)
    returns what the file holds and, when it cannot be read, why, in words fit
    for the operator; it never raises on an upload and never logs that reason:
    the caller reports it. *name* is what to call the file when it is not
    ``path.name`` (an archive member is extracted under a generated name).
    """
