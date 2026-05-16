"""XCCDF 1.2 results parser supporting SCC, OpenSCAP, Nessus, and Evaluate-STIG."""
from __future__ import annotations

import logging
from pathlib import Path

from lxml import etree

from app.parsers.base import BaseParser, RuleResult, ScanResult
from app.utils.scanner_detect import detect_scanner

log = logging.getLogger(__name__)


def _safe_xml_parse(path: Path) -> etree._ElementTree:
    """Parse XML with entity resolution and network access disabled.

    Untrusted uploads must not be able to read local files via XXE, reach
    internal hosts via SSRF, or exhaust memory via billion-laughs entity
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


# XCCDF 1.2 namespace URI
_NS_XCCDF_12 = "http://checklists.nist.gov/xccdf/1.2"

# XPath helper: try both namespaced and un-namespaced forms
_XCCDF_NS = {"cdf": _NS_XCCDF_12}

# SCAP fact URNs for hostname and IP, searched in preference order
_FACT_HOSTNAME_URNS: list[str] = [
    "urn:scap:fact:asset:identifier:host_name",
    "urn:scap:fact:asset:identifier:fqdn",
]
_FACT_IP_URNS: list[str] = [
    "urn:scap:fact:asset:identifier:ipv4",
    "urn:scap:fact:asset:identifier:ipv6",
]


def _find_test_result(root: etree._Element) -> etree._Element:
    """Return the <TestResult> element to operate on.

    XCCDF results files come in two shapes in the wild:
      1. <TestResult> is the document root (most SCC, OpenSCAP output)
      2. <Benchmark> is the root with <TestResult> nested inside (some
         scanners, including certain SCC Windows 11 outputs)

    Returns the <TestResult> if found anywhere in the tree, otherwise the
    original root (callers will then find no rule-results and surface a
    clear warning).
    """
    if etree.QName(root.tag).localname == "TestResult":
        return root
    # Direct child first (cheap, common case)
    for el in root:
        if callable(el.tag):
            continue
        if etree.QName(el.tag).localname == "TestResult":
            return el
    # Fall back to a deeper search
    for el in root.iter():
        if callable(el.tag):
            continue
        if etree.QName(el.tag).localname == "TestResult":
            return el
    return root


def _find_fact(root: etree._Element, urns: list[str]) -> str:
    """Search a <target-facts> child for the first matching URN, in preference order.

    Handles any namespace prefix on both <target-facts> and <fact> elements.
    """
    found: dict[str, str] = {}
    for el in root:
        if callable(el.tag):
            continue
        if etree.QName(el.tag).localname == "target-facts":
            for fact in el:
                if callable(fact.tag):
                    continue
                name_attr = fact.get("name", "")
                if name_attr in urns and fact.text and name_attr not in found:
                    found[name_attr] = fact.text.strip()
    for urn in urns:
        if urn in found:
            return found[urn]
    return ""


def _find_text(root: etree._Element, *local_names: str) -> str:
    """Return the text of the first matching element by local name, stripped.

    Tries the XCCDF 1.2 namespace first, then falls back to no-namespace search.
    Handles any prefix the scanner may have used.
    """
    for local in local_names:
        # Namespaced lookup
        el = root.find(f"cdf:{local}", _XCCDF_NS)
        if el is not None and el.text:
            return el.text.strip()
        # Fallback: any-namespace search (skip comment/PI nodes which have callable tags)
        for el in root:
            if callable(el.tag):
                continue
            if etree.QName(el.tag).localname == local and el.text:
                return el.text.strip()
    return ""


def _findall_results(root: etree._Element) -> list[etree._Element]:
    """Return all <rule-result> elements regardless of namespace prefix."""
    # Try namespaced first
    results = root.findall("cdf:rule-result", _XCCDF_NS)
    if results:
        return results
    # Fallback: iterate and match by local name (skip comment/PI nodes)
    return [
        el for el in root
        if not callable(el.tag) and etree.QName(el.tag).localname == "rule-result"
    ]


def _find_child_text(el: etree._Element, local_name: str) -> str:
    """Return text of a direct child element matched by local name."""
    for child in el:
        if callable(child.tag):
            continue
        if etree.QName(child.tag).localname == local_name:
            if child.text:
                return child.text.strip()
    return ""


def _get_benchmark_attrs(root: etree._Element) -> tuple[str, str]:
    """Return (benchmark_href, benchmark_id) from the <benchmark> child element."""
    # Try namespaced
    bm = root.find("cdf:benchmark", _XCCDF_NS)
    if bm is None:
        # Fallback: match by local name (skip comment/PI nodes)
        for el in root:
            if callable(el.tag):
                continue
            if etree.QName(el.tag).localname == "benchmark":
                bm = el
                break
    if bm is None:
        return "", ""
    href = bm.get("href", "")
    bid = bm.get("id", "")
    return href, bid


class XCCDFResultsParser(BaseParser):
    """Parse XCCDF 1.2 results files from all supported scanners."""

    def parse(self, path: Path) -> ScanResult | None:
        """Parse an XCCDF results file and return a ScanResult.

        Returns None if the file cannot be parsed; logs a warning.
        """
        try:
            tree = _safe_xml_parse(path)
        except etree.XMLSyntaxError as exc:
            log.warning("Skipping %s — invalid XML: %s", path.name, exc)
            return None

        document_root = tree.getroot()
        scanner = detect_scanner(path)
        # XCCDF target/result data lives inside <TestResult> — locate it whether
        # it is the root element or nested inside a <Benchmark>
        root = _find_test_result(document_root)

        # Hostname: <target> → <target-facts> host_name/fqdn → <title> → filename stem
        hostname = (
            _find_text(root, "target")
            or _find_fact(root, _FACT_HOSTNAME_URNS)
            or _find_text(root, "title")
        )
        if not hostname:
            hostname = path.stem
            log.warning(
                "%s: No hostname found in <target>, <target-facts>, or <title>"
                " — using filename '%s'",
                path.name,
                hostname,
            )

        # IP address: <target-facts> ipv4/ipv6 → <target-address> → "N/A"
        # Prefer target-facts because scanners like SCC emit one canonical IP there;
        # <target-address> may list every network adapter (including virtual ones).
        ip_address = (
            _find_fact(root, _FACT_IP_URNS)
            or _find_text(root, "target-address")
        )
        if not ip_address:
            ip_address = "N/A"
            log.warning(
                "%s: No IP address found in <target-address> or <target-facts>"
                " — using 'N/A'",
                path.name,
            )

        benchmark_href, benchmark_id = _get_benchmark_attrs(root)

        rule_results: list[RuleResult] = []
        for rr_el in _findall_results(root):
            rule_id = rr_el.get("idref", "").strip()
            if not rule_id:
                continue
            status = _find_child_text(rr_el, "result")
            if not status:
                log.warning(
                    "%s: rule-result '%s' has no <result> element — skipping",
                    path.name,
                    rule_id,
                )
                continue
            rule_results.append(RuleResult(rule_id=rule_id, status=status))

        if not rule_results:
            log.warning(
                "%s: 0 <rule-result> elements found — file may not be an XCCDF "
                "results file, or may use an unrecognised structure",
                path.name,
            )

        return ScanResult(
            source_file=path.name,
            hostname=hostname,
            ip_address=ip_address,
            benchmark_href=benchmark_href,
            benchmark_id=benchmark_id,
            scanner=scanner,
            rule_results=rule_results,
        )
