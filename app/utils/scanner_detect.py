"""Auto-detect which scanner produced an XCCDF results file."""
from __future__ import annotations

import logging
from pathlib import Path

from lxml import etree

log = logging.getLogger(__name__)

# Known scanner identifiers in order of specificity
_SCANNER_SIGNATURES: list[tuple[str, str]] = [
    # (scanner_name, hint_string_lowercased)
    ("Evaluate-STIG", "evaluate-stig"),
    ("Nessus", "nessus"),
    ("OpenSCAP", "openscap"),
    ("SCC", "scc"),
]

# Namespaces that uniquely identify specific scanners
_NAMESPACE_HINTS: dict[str, str] = {
    "http://www.nessus.org/cm": "Nessus",
    "http://www.nessus.org": "Nessus",
}

# SCC-specific namespace hint
_SCC_NAMESPACE = "http://scap.nist.gov/schema/scap/source/1.2"


def detect_scanner(path: Path) -> str:
    """Return the scanner name that produced *path*.

    Inspects XML namespace declarations and generator metadata.
    Returns one of: "SCC", "OpenSCAP", "Nessus", "Evaluate-STIG", or "Unknown".
    """
    try:
        tree = etree.parse(str(path))
    except etree.XMLSyntaxError:
        log.warning("Cannot detect scanner — invalid XML in %s", path.name)
        return "Unknown"

    root = tree.getroot()

    # Check namespace map for known scanner namespaces
    ns_map = _collect_namespaces(root)
    for ns_uri, scanner in _NAMESPACE_HINTS.items():
        if ns_uri in ns_map:
            return scanner

    if _SCC_NAMESPACE in ns_map:
        return "SCC"

    # Check generator/product elements in any namespace
    generator_text = _extract_generator_text(root)
    if generator_text:
        lower = generator_text.lower()
        for scanner_name, hint in _SCANNER_SIGNATURES:
            if hint in lower:
                return scanner_name

    # Check root element id attribute for Evaluate-STIG pattern
    root_id = root.get("id", "")
    if "evaluate-stig" in root_id.lower():
        return "Evaluate-STIG"

    # SCC uses the cdf: prefix namespace throughout — check xmlns declarations
    root_tag = root.tag
    if "checklists.nist.gov/xccdf/1.2" in root_tag:
        # Prefixed namespace in element tag suggests SCC-style cdf: prefix usage
        # but this is also valid for Nessus — already handled above
        pass

    log.warning("Could not identify scanner for %s — defaulting to Unknown", path.name)
    return "Unknown"


def _collect_namespaces(element: etree._Element) -> set[str]:
    """Collect all namespace URIs used in the document."""
    namespaces: set[str] = set()
    for el in element.iter():
        if el.nsmap:
            namespaces.update(v for v in el.nsmap.values() if v)
    return namespaces


def _extract_generator_text(root: etree._Element) -> str:
    """Extract concatenated text from generator/product elements in any namespace."""
    texts: list[str] = []
    for el in root.iter():
        local = etree.QName(el.tag).localname.lower() if el.tag and not callable(el.tag) else ""
        if local in ("generator", "product", "scanner-version", "creator"):
            if el.text and el.text.strip():
                texts.append(el.text.strip())
    return " ".join(texts)
