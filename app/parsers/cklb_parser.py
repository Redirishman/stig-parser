"""CKLB checklist parser — STIG Viewer 3 / Evaluate-STIG native format.

CKLB files are JSON (unlike the legacy XML .ckl) and are self-contained:
severity, check text, fix text, and titles are all inline, so no benchmark
cross-referencing is needed. The parser therefore produces ``Finding``
objects directly rather than the ``ScanResult`` intermediate used by the
XCCDF path.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from app.parsers.base import BaseParser, Finding

log = logging.getLogger(__name__)

# CKLB severity values → report severity categories
_SEVERITY_MAP = {
    "high": "CAT I",
    "medium": "CAT II",
    "low": "CAT III",
}

# CKLB status values → report status strings (filter keeps Open / Not
# Reviewed / Error / Unknown; the rest are recorded but filtered out)
_STATUS_MAP = {
    "open": "Open",
    "not_reviewed": "Not Reviewed",
    "not_a_finding": "Not A Finding",
    "not_applicable": "Not Applicable",
    "error": "Error",
}


def _effective_severity(rule: dict) -> str:
    """Return the rule's severity, honouring a STIG Viewer severity override."""
    raw = str(rule.get("severity", "")).strip().lower()
    override = rule.get("overrides") or {}
    sev_override = override.get("severity")
    if isinstance(sev_override, dict):
        # STIG Viewer 3 writes {"severity": "...", "reason": "..."}; be
        # tolerant of a {"value": "..."} shape as well.
        raw_override = str(
            sev_override.get("severity") or sev_override.get("value") or ""
        ).strip().lower()
        if raw_override:
            raw = raw_override
    return _SEVERITY_MAP.get(raw, "Unknown")


class CKLBParser(BaseParser):
    """Parse a CKLB (JSON) checklist into a list of Findings."""

    def parse(self, path: Path) -> list[Finding] | None:
        """Parse *path* and return its findings.

        Returns None (with a logged warning) when the file is not valid
        CKLB, so the pipeline can surface a per-file warning instead of
        silently emitting nothing.
        """
        try:
            doc = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            log.warning("Skipping %s — not valid JSON: %s", path.name, exc)
            return None

        if not isinstance(doc, dict) or "stigs" not in doc:
            log.warning(
                "%s: no 'stigs' array — file does not look like a CKLB "
                "checklist (STIG Viewer 3 / Evaluate-STIG output)",
                path.name,
            )
            return None
        stigs = doc.get("stigs")
        if not isinstance(stigs, list):
            log.warning("%s: 'stigs' is not a list — malformed CKLB", path.name)
            return None

        target = doc.get("target_data") or {}
        hostname = str(target.get("host_name") or target.get("fqdn") or "").strip()
        if not hostname:
            hostname = path.stem
            log.warning(
                "%s: no host_name/fqdn in target_data — using filename '%s'",
                path.name,
                hostname,
            )
        ip_address = str(target.get("ip_address") or "").strip()
        if not ip_address:
            ip_address = "N/A"
            log.warning("%s: no ip_address in target_data — using 'N/A'", path.name)

        findings: list[Finding] = []
        rule_count = 0
        for stig in stigs:
            if not isinstance(stig, dict):
                continue
            stig_title = str(
                stig.get("display_name")
                or stig.get("stig_name")
                or stig.get("stig_id")
                or "Unknown STIG"
            ).strip()
            rules = stig.get("rules")
            if not isinstance(rules, list):
                log.warning(
                    "%s: STIG '%s' has no rules list — skipping", path.name, stig_title
                )
                continue
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                rule_count += 1
                vuln_id = str(
                    rule.get("group_id") or rule.get("group_id_src") or ""
                ).strip()
                rule_id = str(
                    rule.get("rule_id_src") or rule.get("rule_id") or ""
                ).strip()
                if not vuln_id and not rule_id:
                    log.warning(
                        "%s: rule with no group_id/rule_id — skipping", path.name
                    )
                    continue

                raw_status = str(rule.get("status") or "").strip().lower()
                if not raw_status:
                    log.warning(
                        "%s: rule %s has no status — skipping",
                        path.name,
                        vuln_id or rule_id,
                    )
                    continue
                status = _STATUS_MAP.get(raw_status)
                if status is None:
                    # Fail loud, not silent: keep the rule visible in the report
                    log.warning(
                        "%s: rule %s has unrecognised status '%s' — recording as "
                        "'Unknown' so it is not silently dropped",
                        path.name,
                        vuln_id or rule_id,
                        raw_status,
                    )
                    status = "Unknown"

                findings.append(
                    Finding(
                        stig_title=stig_title,
                        vuln_id=vuln_id,
                        rule_id=rule_id,
                        severity=_effective_severity(rule),
                        status=status,
                        server=hostname,
                        ip_address=ip_address,
                        check_text=str(rule.get("check_content") or "").strip(),
                        fix_text=str(rule.get("fix_text") or "").strip(),
                    )
                )

        if rule_count == 0:
            log.warning(
                "%s: checklist contains 0 rules — nothing to report", path.name
            )

        return findings
