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

from app.parsers.base import BaseParser, Finding, RowLog
from app.reference.normalize import (
    MAX_SHOWN_CHARS,
    MAX_STORED_CHARS,
    clip,
    error_text,
    norm_stig_id,
    safe_name,
)

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
    # huge_tree is deliberately NOT enabled: it removes libxml2's structural
    # safety limits (max depth ~256, max text-node size), which on untrusted
    # uploads is a non-entity DoS vector — a deeply-nested document a few MB in
    # size can overflow the C parser's stack and crash the worker. Real
    # multi-MB compliance scans stay well within the default limits; a file that
    # legitimately exceeds them fails loud as a catchable XMLSyntaxError, which
    # the caller already handles.
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        dtd_validation=False,
        load_dtd=False,
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

    def read(self, path: Path, *, name: str | None = None) -> tuple[list[Finding] | None, str]:
        """Parse *path*: ``(findings, "")``, or ``(None, why)`` when it is not a
        Nessus export, *why* fit for the operator's warning. What it returns is
        not logged: the caller reports it.

        Returns None (with a logged warning) when the file is not a
        NessusClientData_v2 document, so the pipeline surfaces a per-file
        warning instead of silently emitting nothing.

        *name* is what to call the file in messages (and what to fall back on
        for the host name) when that is not the path's own name: an archive
        member is extracted under a generated file name.
        """
        name = name or path.name
        try:
            tree = _safe_xml_parse(path)
        except etree.XMLSyntaxError as exc:
            return None, f"invalid XML: {error_text(exc)}"

        root = tree.getroot()
        if etree.QName(root.tag).localname != "NessusClientData_v2":
            found = safe_name(etree.QName(root.tag).localname, MAX_SHOWN_CHARS)
            return None, f"not a Nessus export (root element is <{found}>, expected <NessusClientData_v2>)"

        findings: list[Finding] = []
        compliance_items = 0
        row_log = RowLog(log)

        for report_host in root.iter("ReportHost"):
            hostname, ip = _host_metadata(report_host)
            if not hostname:
                hostname = Path(name).stem
                row_log(
                    "%s: ReportHost with no name/fqdn — using filename '%s'",
                    name,
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
                    row_log(
                        "%s: compliance item with unrecognised result '%s' — "
                        "recording as 'Unknown' so it is not silently dropped",
                        name,
                        safe_name(raw_result) or "(missing)",
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
                        # Set whenever the token exists, so it is also set when the
                        # STIG ID stands in for a missing Rule-ID above.
                        stig_id=clip(norm_stig_id(tokens.get("STIG-ID", "")), MAX_STORED_CHARS),
                    )
                )

        return findings, ""
