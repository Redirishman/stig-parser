"""CKLB checklist parser — STIG Viewer 3 / Evaluate-STIG native format.

CKLB files are JSON (unlike the legacy XML .ckl) and are self-contained:
severity, check text, fix text, and titles are all inline, so no benchmark
cross-referencing is needed. The parser therefore produces ``Finding``
objects directly rather than the ``ScanResult`` intermediate used by the
XCCDF path.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from app.parsers.base import BaseParser, Finding, RowLog
from app.reference.cklb_loader import checklist_problem, read_checklist
from app.reference.normalize import (
    CAT_BY_SEVERITY,
    MAX_STORED_CHARS,
    JsonText,
    clip,
    norm_stig_id,
    release_label,
    safe_name,
    shown_file_name,
)

log = logging.getLogger(__name__)

# CKLB status values → report status strings (filter keeps Open / Not
# Reviewed / Error / Unknown; the rest are recorded but filtered out)
_STATUS_MAP = {
    "open": "Open",
    "not_reviewed": "Not Reviewed",
    "not_a_finding": "Not A Finding",
    "not_applicable": "Not Applicable",
    "error": "Error",
}


def _effective_severity(rule: dict, text: JsonText) -> str:
    """Return the rule's severity, honouring a STIG Viewer severity override."""
    raw = text(rule.get("severity")).lower()
    override = rule.get("overrides")
    sev_override = override.get("severity") if isinstance(override, dict) else None
    if isinstance(sev_override, dict):
        # STIG Viewer 3 writes {"severity": "...", "reason": "..."}; be
        # tolerant of a {"value": "..."} shape as well.
        raw_override = (
            text(sev_override.get("severity")) or text(sev_override.get("value"))
        ).lower()
        if raw_override:
            raw = raw_override
    return CAT_BY_SEVERITY.get(raw, "Unknown")


def _scan_release(stig: dict, text: JsonText) -> str:
    """The ``V1R4`` label of the STIG a checklist was made from; "" when it has none."""
    # STIG Viewer writes the version as a number, Evaluate-STIG as a string.
    return release_label(text.version(stig.get("version")), text(stig.get("release_info")))


# Why a results checklist was not read, as the log line says it.
@dataclass(frozen=True)
class ChecklistResult:
    """The findings of one results checklist, with what reading it left out; the
    pipeline turns each count into an operator warning."""

    findings: list[Finding]
    # Values that were not text where text belongs, and were ignored.
    ignored_values: int = 0
    # Rules left out because they give no status (blank, null or missing).
    skipped_rules: int = 0
    # Entries left out for their shape: a rule or STIG entry that is not an
    # object, a rule with no usable ID, a STIG entry with no rules list.
    malformed_entries: int = 0
    # Rules the checklist holds, read or left out.
    rule_count: int = 0


class _NoFinding(Enum):
    """Why _finding_from_rule gives no finding for a rule."""

    NO_ID = "no-id"             # an entry of the wrong shape: counted in malformed_entries
    NO_STATUS = "no-status"     # counted in skipped_rules


def _finding_from_rule(
    rule: dict, text: JsonText, row_log: RowLog, name: str, *,
    stig_title: str, scan_release: str, hostname: str, ip_address: str,
) -> Finding | _NoFinding:
    """The finding one rule entry of the checklist *name* reports, or why it reports
    none; each problem is logged through *row_log*."""
    vuln_id = text(rule.get("group_id")) or text(rule.get("group_id_src"))
    rule_id = text(rule.get("rule_id_src")) or text(rule.get("rule_id"))
    if not vuln_id and not rule_id:
        row_log("%s: rule with no group_id/rule_id — skipping", name)
        return _NoFinding.NO_ID

    status_value = rule.get("status")
    raw_status = text(status_value).lower()
    status: str | None
    if status_value is not None and not isinstance(status_value, str):
        # The rule has a status, but not one that can be read. Fail
        # closed: show the row for review rather than drop it, and
        # never read ["open"] as "open".
        row_log(
            "%s: rule %s has a status that is not text — recording as "
            "'Unknown' so it is not silently dropped",
            name,
            safe_name(vuln_id or rule_id),
        )
        status = "Unknown"
    elif not raw_status:
        row_log(
            "%s: rule %s has no status — skipping",
            name,
            safe_name(vuln_id or rule_id),
        )
        return _NoFinding.NO_STATUS
    else:
        status = _STATUS_MAP.get(raw_status)
    if status is None:
        # Fail loud, not silent: keep the rule visible in the report
        row_log(
            "%s: rule %s has unrecognised status '%s' — recording as "
            "'Unknown' so it is not silently dropped",
            name,
            safe_name(vuln_id or rule_id),
            safe_name(raw_status),
        )
        status = "Unknown"

    return Finding(
        stig_title=stig_title,
        vuln_id=vuln_id,
        rule_id=rule_id,
        severity=_effective_severity(rule, text),
        status=status,
        server=hostname,
        ip_address=ip_address,
        check_text=text(rule.get("check_content")),
        fix_text=text(rule.get("fix_text")),
        stig_id=clip(norm_stig_id(text(rule.get("rule_version"))), MAX_STORED_CHARS),
        scan_release=scan_release,
    )


class CKLBParser(BaseParser):
    """Parse a CKLB (JSON) checklist into a list of Findings."""

    def read(self, path: Path, *, name: str | None = None) -> tuple[ChecklistResult | None, str]:
        """Parse *path*: ``(result, "")``, or ``(None, why)`` when it is not a
        checklist (see :func:`checklist_problem`).

        Returns None (with a logged warning) when the file is not valid
        CKLB, so the pipeline can surface a per-file warning instead of
        silently emitting nothing.

        The file is untrusted JSON. No upload makes this raise, and text is
        taken from JSON strings only: a nested object, list, number or boolean
        where text belongs reads as missing, never as its ``str()``, and is
        counted in the result's ``ignored_values``. A rule with no status at
        all is left out and counted in ``skipped_rules``, and an entry of the
        wrong shape in ``malformed_entries``.

        *name* is what to call the file in messages (and what to fall back on
        for the host name) when that is not the path's own name: an archive
        member is extracted under a generated file name.
        """
        skipped_rules = 0
        malformed = 0
        text = JsonText()
        file_stem = Path(name or path.name).stem
        name = shown_file_name(name or path.name)
        read = read_checklist(path)
        if read.problem:
            return None, checklist_problem(read)
        doc, stigs = read.doc, read.stigs

        target = doc.get("target_data")
        if not isinstance(target, dict):
            target = {}
        hostname = text(target.get("host_name")) or text(target.get("fqdn"))
        if not hostname:
            hostname = file_stem
            log.warning(
                "%s: no host_name/fqdn in target_data — using filename '%s'",
                name,
                safe_name(hostname),
            )
        ip_address = text(target.get("ip_address"))
        if not ip_address:
            ip_address = "N/A"
            log.warning("%s: no ip_address in target_data — using 'N/A'", name)

        findings: list[Finding] = []
        rule_count = 0
        row_log = RowLog(log)
        for stig in stigs:
            if not isinstance(stig, dict):
                malformed += 1
                continue
            stig_title = (
                text(stig.get("display_name"))
                or text(stig.get("stig_name"))
                or text(stig.get("stig_id"))
                or "Unknown STIG"
            )
            scan_release = _scan_release(stig, text)
            rules = stig.get("rules")
            if not isinstance(rules, list):
                row_log("%s: STIG '%s' has no rules list — skipping", name, safe_name(stig_title))
                malformed += 1
                continue
            for rule in rules:
                if not isinstance(rule, dict):
                    malformed += 1
                    continue
                rule_count += 1
                outcome = _finding_from_rule(
                    rule, text, row_log, name,
                    stig_title=stig_title, scan_release=scan_release, hostname=hostname, ip_address=ip_address,
                )
                if isinstance(outcome, Finding):
                    findings.append(outcome)
                elif outcome is _NoFinding.NO_ID:
                    malformed += 1
                elif outcome is _NoFinding.NO_STATUS:
                    skipped_rules += 1

        return ChecklistResult(
            findings, ignored_values=text.ignored, skipped_rules=skipped_rules, malformed_entries=malformed,
            rule_count=rule_count,
        ), ""
