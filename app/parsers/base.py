"""Abstract base parser and shared data models."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


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


@dataclass
class BenchmarkRule:
    """A single rule extracted from a STIG benchmark definition."""
    vuln_id: str        # V-XXXXXX from Group id
    rule_id: str        # SV-XXXXXXrYYYYYY_rule from Rule id
    severity: str       # "CAT I" | "CAT II" | "CAT III"
    check_text: str
    fix_text: str


@dataclass
class Benchmark:
    """All data extracted from one STIG benchmark XML file."""
    benchmark_id: str
    title: str
    rules: dict[str, BenchmarkRule] = field(default_factory=dict)  # keyed by rule_id


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


class BaseParser(ABC):
    """Abstract base for all file parsers."""

    @abstractmethod
    def parse(self, path: Path) -> Any:
        """Parse a file and return the extracted data object."""
