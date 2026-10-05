"""STIG Benchmark definition file parser — supports XCCDF 1.1 and 1.2."""
from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

from lxml import etree

from app.parsers.base import BaseParser, Benchmark, BenchmarkRule
from app.reference.normalize import CAT_BY_SEVERITY, MAX_STORED_CHARS, clip, error_text, release_label

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


def load_xml(path: Path) -> tuple[etree._ElementTree | None, str]:
    """*path* parsed once, hardened, for every reader of it to share: ``(tree, "")``,
    or ``(None, why)`` when it is not well-formed. An OSError is the caller's."""
    try:
        return _safe_xml_parse(path), ""
    except etree.XMLSyntaxError as exc:
        return None, f"invalid XML: {error_text(exc)}"


_NS_XCCDF_11 = "http://checklists.nist.gov/xccdf/1.1"
_NS_XCCDF_12 = "http://checklists.nist.gov/xccdf/1.2"
_NS = {"xccdf": _NS_XCCDF_11}


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


def _release_info(benchmark_el: etree._Element) -> str:
    for child in benchmark_el:
        if (
            not callable(child.tag)
            and etree.QName(child.tag).localname == "plain-text"
            and child.get("id") == "release-info"
        ):
            return (child.text or "").strip()
    return ""


_DUPLICATES_SHOWN = 5
_LOGGED_ID_CHARS = 80


def _log_id(value: str) -> str:
    """An identifier that is safe to put in a log line.

    Rule and benchmark IDs come from uploaded files: truncate first (so a huge
    ID costs nothing), then repr-escape (so a newline cannot forge a log line).
    """
    text = repr(value[:_LOGGED_ID_CHARS])
    return text + "..." if len(value) > _LOGGED_ID_CHARS else text


def _benchmark_from_element(root: etree._Element) -> Benchmark:
    """Build a Benchmark from one <Benchmark> element (any namespace).

    One iterative walk in document order, with no recursion and no ancestor
    lookups. It starts at the Benchmark's children and descends only through
    <Group> elements, carrying the nearest Group's V-ID. It collects the <Rule>
    children of the Benchmark itself (blank V-ID) and of every Group, however
    deeply the Groups nest. It never enters an inner <Benchmark> (that
    Benchmark owns its own rules) and never descends into any other element, so
    a stray <Rule> inside <TestResult>, <Profile> or any other wrapper is not a
    rule. A rule ID defined more than once keeps its last definition and is
    reported in one warning.
    """
    rules: dict[str, BenchmarkRule] = {}
    duplicates: dict[str, None] = {}  # insertion-ordered set
    stack: list[tuple[Iterator[etree._Element], str]] = [(iter(root), "")]
    while stack:
        children, vuln_id = stack[-1]
        for child in children:
            tag = child.tag
            if callable(tag):  # comment, processing instruction, entity reference
                continue
            name = tag.rpartition("}")[2]
            if name == "Rule":
                rule_id = child.get("id", "")
                if not rule_id:
                    continue
                if rule_id in rules:
                    duplicates[rule_id] = None
                severity_raw = child.get("severity", "").lower()
                rules[rule_id] = BenchmarkRule(
                    vuln_id=vuln_id,
                    rule_id=rule_id,
                    severity=CAT_BY_SEVERITY.get(severity_raw, "Unknown"),
                    check_text=_get_check_text(child),
                    fix_text=_get_fix_text(child),
                    stig_id=_find_text_ns(child, "version"),
                )
            elif name == "Group":
                stack.append((iter(child), _extract_vuln_id(child.get("id", ""))))
                break  # walk the Group's children, then resume this level
        else:
            stack.pop()
    if duplicates:
        shown = [_log_id(rule_id) for rule_id in list(duplicates)[:_DUPLICATES_SHOWN]]
        more = ", ..." if len(duplicates) > _DUPLICATES_SHOWN else ""
        log.warning(
            "Benchmark %s: %d duplicate rule ID(s) — the last definition of each is used: %s%s",
            _log_id(root.get("id", "")),
            len(duplicates),
            ", ".join(shown),
            more,
        )
    return Benchmark(
        benchmark_id=clip(root.get("id", ""), MAX_STORED_CHARS),
        title=clip(_find_text_ns(root, "title"), MAX_STORED_CHARS),
        rules=rules,
        release=release_label(_find_text_ns(root, "version"), _release_info(root)),
    )


class BenchmarkParser(BaseParser):
    """Parse DISA STIG benchmark definition files (XCCDF 1.1 or 1.2)."""

    def read_all(
        self, path: Path, *, name: str | None = None, tree: etree._ElementTree | None = None,
    ) -> tuple[list[Benchmark], str]:
        """Every <Benchmark> in the file, at any depth, and, when there is none,
        why (for the operator's warning: invalid XML, or no Benchmark element).

        Covers standalone XCCDF benchmarks, SCC result files (Benchmark root
        with the TestResult nested inside), and SCAP datastreams (Benchmark
        inside a component). What it returns is not logged: the caller
        reports it. *name* is what to call the file in log lines. *tree*, when
        given, is the file already parsed (see :func:`load_xml`): it is not
        parsed again.
        """
        name = name or path.name
        if tree is None:
            tree, why = load_xml(path)
            if tree is None:
                return [], why

        found = [_benchmark_from_element(el) for el in tree.getroot().iter("{*}Benchmark")]
        return found, "" if found else "no Benchmark element"
