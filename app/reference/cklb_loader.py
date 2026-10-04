"""Read a CKLB checklist (STIG Viewer 3 / Evaluate-STIG) as a STIG reference.

A CKLB carries the whole STIG text, so one made from the Manual STIG is as
good a source of check text as the Manual STIG itself.

The file is untrusted JSON. Text is taken from JSON strings only: a nested
object, list, number or boolean in a text field is ignored, never turned into
text with ``str()``, and the file gets one warning saying how many were ignored.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.reference.models import ReferenceRule, ReferenceSource, indexable, make_rule
from app.reference.normalize import (
    CAT_BY_SEVERITY,
    MAX_STORED_CHARS,
    JsonText,
    clip,
    error_text,
    release_label,
)


@dataclass
class ChecklistJson:
    """A checklist file read as JSON (see :func:`read_checklist`)."""
    doc: dict[str, Any] = field(default_factory=dict)
    stigs: list[Any] = field(default_factory=list)
    # Why it could not be read: "json" (not JSON, not UTF-8, unreadable; the text
    # is in ``error``), "nesting" (nested too deep), "no-stigs", "stigs-not-a-list";
    # "" when it was read.
    problem: str = ""
    error: str = ""


def read_checklist(path: Path) -> ChecklistJson:
    """What every checklist reader does first: read *path* as UTF-8 (a BOM is
    allowed), parse it as JSON and find its "stigs" list. Never raises on an
    upload; each reader says in its own words why a file was not read."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        # ValueError covers bad JSON, bad UTF-8, and an integer literal longer
        # than int()'s digit limit (a plain ValueError, not a JSONDecodeError).
        return ChecklistJson(problem="json", error=error_text(exc))
    except RecursionError:
        # A nesting bomb overflows the stack inside json.loads. Untrusted upload.
        return ChecklistJson(problem="nesting")
    if not isinstance(doc, dict) or "stigs" not in doc:
        return ChecklistJson(problem="no-stigs")
    if not isinstance(doc["stigs"], list):
        return ChecklistJson(problem="stigs-not-a-list")
    return ChecklistJson(doc=doc, stigs=doc["stigs"])


def checklist_problem(read: ChecklistJson) -> str:
    """Why *read* could not be used as a checklist, as the operator's warning
    says it after the file name ("" when it was read). Every checklist reader
    says the same: the results parser and the reference loader alike."""
    if read.problem == "json":
        return f"not valid JSON: {read.error}"
    if read.problem == "nesting":
        return "JSON nesting too deep"
    if read.problem == "no-stigs":
        return "not a CKLB checklist (no 'stigs' array)"
    if read.problem == "stigs-not-a-list":
        return "not a CKLB checklist ('stigs' is not a list)"
    return ""


@dataclass
class ChecklistReference:
    """What one checklist file gave as a reference."""
    # One (source, rules) pair per STIG entry that has a rules list.
    stigs: list[tuple[ReferenceSource, list[ReferenceRule]]] = field(default_factory=list)
    # False when the file is not a checklist at all (unreadable, not JSON, no 'stigs'
    # array). True with no rules means a checklist that is simply empty.
    readable: bool = True
    # Why it was not readable (see checklist_problem); "" when it was.
    problem: str = ""
    ignored_values: int = 0     # values that were not text where text belongs, and were ignored
    # Entries left out for their shape: a STIG entry that is not an object or has
    # no rules list, a rule that is not an object or has no identifier a lookup
    # could find it by (see models.indexable).
    malformed_entries: int = 0
    # Rules left out because the run holds no more (see ReferenceLibrary.rules_left).
    rules_not_built: int = 0

    @property
    def rule_count(self) -> int:
        return sum(len(rules) for _, rules in self.stigs)


def load_cklb_reference(
    path: Path, *, embedded: bool, name: str | None = None, max_rules: int | None = None,
) -> ChecklistReference:
    """The STIGs of a checklist as reference rules, and what kind of file it turned out to be.

    Nothing is logged: what was not read, ignored or left out is in the result,
    and the caller reports it. *name* is the file name the sources carry when it
    is not ``path.name``: an archive member is extracted under a generated file name.
    At most *max_rules* rules are built (the rest are counted in ``rules_not_built``).
    """
    file_name = name or path.name
    read = read_checklist(path)
    if read.problem:
        return ChecklistReference(readable=False, problem=checklist_problem(read))
    stigs = read.stigs

    text = JsonText()
    out: list[tuple[ReferenceSource, list[ReferenceRule]]] = []
    malformed = 0
    room = max_rules
    not_built = 0
    for stig in stigs:
        if not isinstance(stig, dict) or not isinstance(stig.get("rules"), list):
            malformed += 1
            continue
        stig_id = text(stig.get("stig_id"))
        title = clip(text(stig.get("display_name")) or text(stig.get("stig_name")) or stig_id, MAX_STORED_CHARS)
        # Identifiers first: an entry nothing could find is left out before anything is
        # built for it, and no more rules are built than the run may hold.
        entries: list[tuple[dict, str, str, str]] = []
        for r in stig["rules"]:
            if not isinstance(r, dict):
                malformed += 1
                continue
            vuln_id = text(r.get("group_id")) or text(r.get("group_id_src"))
            rule_id = text(r.get("rule_id_src")) or text(r.get("rule_id"))
            rule_version = text(r.get("rule_version"))
            if not indexable(vuln_id=vuln_id, rule_id=rule_id, stig_id=rule_version):
                malformed += 1
            elif room is not None and room <= 0:
                not_built += 1
            else:
                entries.append((r, vuln_id, rule_id, rule_version))
                room = None if room is None else room - 1
        source = ReferenceSource(
            file_name=file_name,
            benchmark_id=stig_id,
            title=title,
            release=release_label(text.version(stig.get("version")), text(stig.get("release_info"))),
            embedded=embedded,
            edition="cklb",
            rule_count=len(entries),
        )
        rules = [
            make_rule(
                source,
                vuln_id=vuln_id,
                rule_id=rule_id,
                stig_id=rule_version,
                severity=CAT_BY_SEVERITY.get(text(r.get("severity")).lower(), ""),
                stig_title=title,
                check_text=text(r.get("check_content")),
                fix_text=text(r.get("fix_text")),
            )
            for r, vuln_id, rule_id, rule_version in entries
        ]
        out.append((source, rules))
    return ChecklistReference(
        stigs=out, ignored_values=text.ignored, malformed_entries=malformed, rules_not_built=not_built,
    )
