"""STIG Benchmark definition file parser — supports XCCDF 1.1 and 1.2."""
from __future__ import annotations

import logging
from pathlib import Path

from lxml import etree

from app.parsers.base import BaseParser, Benchmark, BenchmarkRule

log = logging.getLogger(__name__)


def _safe_xml_parse(path: Path) -> etree._ElementTree:
    """Parse XML with entity resolution and network access disabled.

    Untrusted benchmark uploads must not be able to read local files via XXE,
    reach internal hosts via SSRF, or exhaust memory via billion-laughs entity
    expansion. A fresh parser is created per call: lxml parser instances are
    not safe to share across the worker threads the web app spawns.
    """
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        dtd_validation=False,
        load_dtd=False,
    )
    return etree.parse(str(path), parser)


_NS_XCCDF_11 = "http://checklists.nist.gov/xccdf/1.1"
_NS_XCCDF_12 = "http://checklists.nist.gov/xccdf/1.2"
_NS = {"xccdf": _NS_XCCDF_11}

_SEVERITY_MAP = {
    "high": "CAT I",
    "medium": "CAT II",
    "low": "CAT III",
}


def _findall_local(el: etree._Element, local_name: str) -> list[etree._Element]:
    """Return direct children matching local_name, regardless of namespace prefix."""
    return [
        child for child in el
        if not callable(child.tag) and etree.QName(child.tag).localname == local_name
    ]


def _extract_vuln_id(raw_id: str) -> str:
    """Return the V-XXXXXX portion of a group id.

    XCCDF 1.1 benchmark files use short ids (e.g. 'V-254239'); XCCDF 1.2
    SCC result files use fully-qualified ids (e.g.
    'xccdf_mil.disa.stig_group_V-213426').
    """
    if "_group_" in raw_id:
        return raw_id.split("_group_")[-1]
    return raw_id


def _find_text_ns(el: etree._Element, local_name: str) -> str:
    """Find a direct child by local name (namespace-agnostic) and return its text."""
    found = el.find(f"xccdf:{local_name}", _NS)
    if found is not None and found.text:
        return found.text.strip()
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
    for el in rule_el.iter():
        if not callable(el.tag) and etree.QName(el.tag).localname == "fixtext":
            if el.text:
                return el.text.strip()
    return ""


class BenchmarkParser(BaseParser):
    """Parse DISA STIG benchmark definition files (XCCDF 1.1 or 1.2)."""

    def parse(self, path: Path) -> Benchmark | None:
        """Parse a benchmark file and return a Benchmark object.

        Accepts both standalone XCCDF 1.1 benchmark files and XCCDF 1.2
        SCC result files that embed benchmark definitions inline.
        Returns None on XML parse error; logs a warning.
        """
        try:
            tree = _safe_xml_parse(path)
        except etree.XMLSyntaxError as exc:
            log.warning("Skipping benchmark %s — invalid XML: %s", path.name, exc)
            return None

        root = tree.getroot()

        benchmark_id = root.get("id", "")
        title = _find_text_ns(root, "title")

        rules: dict[str, BenchmarkRule] = {}

        groups = root.findall("xccdf:Group", _NS) or _findall_local(root, "Group")
        for group_el in groups:
            vuln_id = _extract_vuln_id(group_el.get("id", ""))

            rule_els = group_el.findall("xccdf:Rule", _NS) or _findall_local(group_el, "Rule")
            for rule_el in rule_els:
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
