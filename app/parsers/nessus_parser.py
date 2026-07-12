"""Tenable .nessus compliance-scan parser.

Real-world Nessus DISA compliance scans export ``NessusClientData_v2`` XML
(the native .nessus format), not XCCDF. Compliance data lives in
``ReportItem`` elements with ``pluginFamily="Policy Compliance"`` and
``cm:``-namespaced child tags. DISA .audit files embed STIG cross-references
(Vuln-ID / Rule-ID / STIG-ID / CAT) in ``cm:compliance-reference`` as
comma-separated ``KEY|value`` tokens.

Like CKLB, the format is self-contained — check text, fix text, severity,
and titles are inline — so this parser produces ``Finding`` objects directly
with no benchmark matching. Structure verified against real Tenable output.
"""
from __future__ import annotations

import logging
from pathlib import Path

from lxml import etree

from app.parsers.base import BaseParser, Finding

log = logging.getLogger(__name__)

_CM_NS = "http://www.nessus.org/cm"
_CM = f"{{{_CM_NS}}}"

# cm:compliance-result → report status strings
_RESULT_MAP = {
    "FAILED": "Open",
    "PASSED": "Not A Finding",
    "WARNING": "Not Reviewed",  # Nessus flags manual-verification items WARNING
    "ERROR": "Error",
}

# CAT token in cm:compliance-reference → report severity
_CAT_MAP = {
    "I": "CAT I",
    "II": "CAT II",
    "III": "CAT III",
}


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
        huge_tree=True,  # real compliance scans run to several MB
    )
    return etree.parse(str(path), parser)


def _parse_reference_tokens(reference: str) -> dict[str, str]:
    """Parse ``KEY|value,KEY|value,...`` from cm:compliance-reference.

    First occurrence of each key wins (CCI et al. repeat; the keys we use —
    Vuln-ID, Rule-ID, STIG-ID, CAT — appear once).
    """
    tokens: dict[str, str] = {}
    for pair in reference.split(","):
        key, sep, value = pair.partition("|")
        if sep and key.strip() and key.strip() not in tokens:
            tokens[key.strip()] = value.strip()
    return tokens


def _host_metadata(report_host: etree._Element) -> tuple[str, str]:
    """Return (hostname, ip) for a <ReportHost>."""
    props: dict[str, str] = {}
    hp = report_host.find("HostProperties")
    if hp is not None:
        for tag in hp:
            if not callable(tag.tag) and tag.get("name") and tag.text:
                props[tag.get("name")] = tag.text.strip()
    name_attr = (report_host.get("name") or "").strip()
    hostname = (
        props.get("hostname")
        or props.get("host-fqdn")
        or props.get("netbios-name")
        or name_attr
    )
    ip = props.get("host-ip") or name_attr or "N/A"
    return hostname, ip


class NessusComplianceParser(BaseParser):
    """Parse a .nessus compliance scan into a list of Findings."""

    def parse(self, path: Path) -> list[Finding] | None:
        """Parse *path* and return its compliance findings.

        Returns None (with a logged warning) when the file is not a
        NessusClientData_v2 document, so the pipeline surfaces a per-file
        warning instead of silently emitting nothing.
        """
        try:
            tree = _safe_xml_parse(path)
        except etree.XMLSyntaxError as exc:
            log.warning("Skipping %s — invalid XML: %s", path.name, exc)
            return None

        root = tree.getroot()
        if etree.QName(root.tag).localname != "NessusClientData_v2":
            log.warning(
                "%s: root element is <%s>, expected <NessusClientData_v2> — "
                "not a Nessus export",
                path.name,
                etree.QName(root.tag).localname,
            )
            return None

        findings: list[Finding] = []
        compliance_items = 0

        for report_host in root.iter("ReportHost"):
            hostname, ip = _host_metadata(report_host)
            if not hostname:
                hostname = path.stem
                log.warning(
                    "%s: ReportHost with no name/fqdn — using filename '%s'",
                    path.name,
                    hostname,
                )

            for item in report_host.iter("ReportItem"):
                if item.get("pluginFamily") != "Policy Compliance":
                    continue
                compliance_items += 1

                raw_result = (item.findtext(_CM + "compliance-result") or "").strip()
                status = _RESULT_MAP.get(raw_result.upper())
                if status is None:
                    # Fail loud, not silent: keep the item visible in the report
                    log.warning(
                        "%s: compliance item with unrecognised result '%s' — "
                        "recording as 'Unknown' so it is not silently dropped",
                        path.name,
                        raw_result or "(missing)",
                    )
                    status = "Unknown"

                check_name = (
                    item.findtext(_CM + "compliance-check-name") or ""
                ).strip()
                reference = (
                    item.findtext(_CM + "compliance-reference") or ""
                ).strip()
                tokens = _parse_reference_tokens(reference)

                vuln_id = tokens.get("Vuln-ID", "")
                rule_id = tokens.get("Rule-ID", "") or tokens.get("STIG-ID", "")
                if not rule_id:
                    # Non-DISA audit (e.g. CIS or site-custom): the check name
                    # is the only stable identifier
                    rule_id = check_name

                severity = _CAT_MAP.get(tokens.get("CAT", ""), "Unknown")

                info = (item.findtext(_CM + "compliance-info") or "").strip()
                actual = (
                    item.findtext(_CM + "compliance-actual-value") or ""
                ).strip()
                check_text = info
                if actual:
                    # The scanner's observed value is the finding's evidence —
                    # operators need it to verify or remediate
                    check_text = f"{info}\n\nScan output: {actual}" if info else (
                        f"Scan output: {actual}"
                    )

                stig_title = (
                    (item.findtext(_CM + "compliance-benchmark-name") or "").strip()
                    or (item.findtext(_CM + "compliance-audit-file") or "").strip()
                    or (item.get("pluginName") or "").strip()
                    or "Nessus Compliance"
                )

                findings.append(
                    Finding(
                        stig_title=stig_title,
                        vuln_id=vuln_id,
                        rule_id=rule_id,
                        severity=severity,
                        status=status,
                        server=hostname,
                        ip_address=ip,
                        check_text=check_text,
                        fix_text=(
                            item.findtext(_CM + "compliance-solution") or ""
                        ).strip(),
                    )
                )

        if compliance_items == 0:
            log.warning(
                "%s: no Policy Compliance items found — this looks like a "
                "vulnerability scan, not a compliance scan. Re-run the scan "
                "with a compliance/audit policy to get STIG results.",
                path.name,
            )

        return findings
