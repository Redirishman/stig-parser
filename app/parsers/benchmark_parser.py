"""STIG Benchmark (XCCDF 1.1) definition file parser."""
from __future__ import annotations

import logging
from pathlib import Path

from lxml import etree

from app.parsers.base import BaseParser, Benchmark, BenchmarkRule

log = logging.getLogger(__name__)

# DISA STIG benchmarks use XCCDF 1.1
_NS_XCCDF_11 = "http://checklists.nist.gov/xccdf/1.1"
_NS = {"xccdf": _NS_XCCDF_11}

_SEVERITY_MAP = {
    "high": "CAT I",
    "medium": "CAT II",
    "low": "CAT III",
}


def _ns(local: str) -> str:
    return f"{{{_NS_XCCDF_11}}}{local}"


def _find_text_ns(el: etree._Element, local_name: str) -> str:
    """Find a direct child by local name (namespace-agnostic) and return its text."""
    target = f"xccdf:{local_name}"
    found = el.find(target, _NS)
    if found is not None and found.text:
        return found.text.strip()
    # Fallback: match by local name only
    for child in el:
        tag = child.tag
        if not callable(tag) and etree.QName(tag).localname == local_name:
            if child.text:
                return child.text.strip()
    return ""


def _get_check_text(rule_el: etree._Element) -> str:
    """Extract check text from <check><check-content>."""
    for check in rule_el.findall("xccdf:check", _NS):
        cc = check.find("xccdf:check-content", _NS)
        if cc is not None and cc.text:
            return cc.text.strip()
    # Fallback: any-namespace traversal
    for el in rule_el.iter():
        if not callable(el.tag) and etree.QName(el.tag).localname == "check-content":
            if el.text:
                return el.text.strip()
    return ""


def _get_fix_text(rule_el: etree._Element) -> str:
    """Extract fix text from <fixtext>."""
    ft = rule_el.find("xccdf:fixtext", _NS)
    if ft is not None and ft.text:
        return ft.text.strip()
    # Fallback
    for el in rule_el.iter():
        if not callable(el.tag) and etree.QName(el.tag).localname == "fixtext":
            if el.text:
                return el.text.strip()
    return ""


class BenchmarkParser(BaseParser):
    """Parse DISA STIG benchmark (XCCDF 1.1) definition files."""

    def parse(self, path: Path) -> Benchmark | None:
        """Parse a benchmark file and return a Benchmark object.

        Returns None on XML parse error; logs a warning.
        """
        try:
            tree = etree.parse(str(path))
        except etree.XMLSyntaxError as exc:
            log.warning("Skipping benchmark %s — invalid XML: %s", path.name, exc)
            return None

        root = tree.getroot()

        benchmark_id = root.get("id", "")
        title = _find_text_ns(root, "title")

        rules: dict[str, BenchmarkRule] = {}

        for group_el in root.findall("xccdf:Group", _NS):
            vuln_id = group_el.get("id", "")

            for rule_el in group_el.findall("xccdf:Rule", _NS):
                rule_id = rule_el.get("id", "")
                if not rule_id:
                    continue

                severity_raw = rule_el.get("severity", "").lower()
                severity = _SEVERITY_MAP.get(severity_raw, "Unknown")

                check_text = _get_check_text(rule_el)
                fix_text = _get_fix_text(rule_el)

                rules[rule_id] = BenchmarkRule(
                    vuln_id=vuln_id,
                    rule_id=rule_id,
                    severity=severity,
                    check_text=check_text,
                    fix_text=fix_text,
                )

        if not rules:
            log.warning("Benchmark %s: no rules found", path.name)

        return Benchmark(
            benchmark_id=benchmark_id,
            title=title,
            rules=rules,
        )
