"""XCCDF 1.2 results parser supporting SCC, OpenSCAP, Nessus, and Evaluate-STIG."""
from __future__ import annotations

import logging
from pathlib import Path

from lxml import etree

from app.parsers.base import BaseParser, RowLog, RuleResult, ScanResult
from app.reference.normalize import error_text, safe_name
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


def _find_test_result(root: etree._Element, file_name: str) -> etree._Element:
    """Return the <TestResult> element to operate on.

    XCCDF results files come in two shapes in the wild:
      1. <TestResult> is the document root (most SCC, OpenSCAP output)
      2. <Benchmark> is the root with <TestResult> nested inside (some
         scanners, including certain SCC Windows 11 outputs)

    OpenSCAP remediation runs embed TWO TestResult elements (initial scan,
    then post-remediation). The LAST one reflects the machine's final state,
    so that is the one reported — with a warning, since the choice matters.

    Returns the <TestResult> if found anywhere in the tree, otherwise the
    original root (callers will then find no rule-results and surface a
    clear warning).
    """
    if etree.QName(root.tag).localname == "TestResult":
        return root
    matches = [
        el for el in root.iter()
        if not callable(el.tag) and etree.QName(el.tag).localname == "TestResult"
    ]
    if not matches:
        return root
    if len(matches) > 1:
        log.warning(
            "%s: %d <TestResult> elements found (remediation-style output) — "
            "using the last one (post-remediation state)",
            file_name,
            len(matches),
        )
    return matches[-1]


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

    def read(
        self, path: Path, *, name: str | None = None, tree: etree._ElementTree | None = None,
    ) -> tuple[ScanResult | None, str]:
        """Parse an XCCDF results file: ``(scan, "")``, or ``(None, why)`` when it
        cannot be parsed, *why* fit for the operator's warning. What it returns
        is not logged: the caller reports it (detail the caller is not given,
        such as a host name taken from the file name, is logged here).

        *name* is what to call the file in messages (and what to fall back on
        for the host name) when that is not the path's own name: an archive
        member is extracted under a generated file name. *tree*, when given, is
        the file already parsed (by :func:`app.parsers.benchmark_parser.load_xml`):
        it is not parsed again.
        """
        name = name or path.name
        if tree is None:
            try:
                tree = _safe_xml_parse(path)
            except etree.XMLSyntaxError as exc:
                return None, f"invalid XML: {error_text(exc)}"

        document_root = tree.getroot()

        # A legacy .ckl checklist (STIG Viewer 2 XML) is not XCCDF results —
        # parsing it here would silently yield 0 rule-results. Fail loud with
        # a pointer to the supported route instead.
        if etree.QName(document_root.tag).localname == "CHECKLIST":
            return None, (
                "a STIG Viewer .ckl checklist, not XCCDF results; save it as .cklb in STIG Viewer 3 "
                "and upload that"
            )

        scanner = detect_scanner(path, name, tree=tree)
        # XCCDF target/result data lives inside <TestResult> — locate it whether
        # it is the root element or nested inside a <Benchmark>
        root = _find_test_result(document_root, name)

        # Hostname: <target> → <target-facts> host_name/fqdn → <title> → filename stem
        hostname = (
            _find_text(root, "target")
            or _find_fact(root, _FACT_HOSTNAME_URNS)
            or _find_text(root, "title")
        )
        if not hostname:
            hostname = Path(name).stem
            log.warning(
                "%s: No hostname found in <target>, <target-facts>, or <title>"
                " — using filename '%s'",
                name,
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
                name,
            )

        benchmark_href, benchmark_id = _get_benchmark_attrs(root)

        rule_results: list[RuleResult] = []
        row_log = RowLog(log)
        for rr_el in _findall_results(root):
            rule_id = rr_el.get("idref", "").strip()
            if not rule_id:
                continue
            status = _find_child_text(rr_el, "result")
            if not status:
                row_log("%s: rule-result '%s' has no <result> element — skipping", name, safe_name(rule_id))
                continue
            rule_results.append(RuleResult(rule_id=rule_id, status=status))

        return ScanResult(
            source_file=name,
            hostname=hostname,
            ip_address=ip_address,
            benchmark_href=benchmark_href,
            benchmark_id=benchmark_id,
            scanner=scanner,
            rule_results=rule_results,
        ), ""
