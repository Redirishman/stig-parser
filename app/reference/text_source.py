"""The Text Source column: where each row's check and fix text came from."""
from __future__ import annotations

from enum import StrEnum

from app.reference.models import ReferenceRule
from app.reference.normalize import MAX_RELEASE_CHARS, MAX_SHOWN_CHARS, clip, clip_left


class Outcome(StrEnum):
    """What became of a finding's text.

    The first group says how one text field ended up and drives the Text Source
    cell (``source_phrase``). The last three say why a finding that was matched
    still lacks text; they are only used for the report counts. The gap reasons
    in the middle serve both: the finding-level reason is derived from the
    outcomes of its blank fields, so a cell and the counts never disagree.
    """
    # how one field ended up
    SCANNER = "scanner"                         # the scan carried the text
    FILLED = "filled"                           # a reference rule reached by rule ID or stem filled it
    FILLED_BY_VULN_ID = "filled_by_vuln_id"
    FILLED_BY_STIG_ID = "filled_by_stig_id"
    # why nothing filled it (also the finding-level reason)
    AMBIGUOUS_VULN_ID = "ambiguous_vuln_id"     # the V-ID names several rules
    AMBIGUOUS_STIG_ID = "ambiguous_stig_id"     # the STIG ID names several STIGs
    PRODUCT_REFUSED = "product_refused"         # the STIG ID exists only under a different STIG title
    NOT_IN_REFERENCES = "not_in_references"     # references were supplied and none answers
    NO_REFERENCE = "no_reference"               # no reference was supplied
    IN_REFERENCE_NO_TEXT = "in_reference_no_text"   # a supplied reference holds the rule, without this text
    # a matched finding that still lacks text (finding level only)
    BLANK_CHECK = "blank_check"                 # has fix text, no check text
    BLANK_FIX = "blank_fix"                     # has check text, no fix text
    BLANK_BOTH = "blank_both"                   # neither


_GAP_PHRASES = {
    Outcome.AMBIGUOUS_VULN_ID: "V-ID matches several rules, not filled",
    Outcome.AMBIGUOUS_STIG_ID: "STIG ID matches several STIGs, not filled",
    Outcome.PRODUCT_REFUSED: "STIG ID found under a different STIG title, not filled",
    Outcome.NOT_IN_REFERENCES: "not in supplied references",
    Outcome.NO_REFERENCE: "no reference supplied",
}
_MATCH_SUFFIXES = {
    Outcome.FILLED: "",
    Outcome.FILLED_BY_VULN_ID: ", matched by V-ID",
    Outcome.FILLED_BY_STIG_ID: ", matched by STIG ID",
}


def source_phrase(
    origin: ReferenceRule | None,
    outcome: Outcome,
    *,
    finding_revision: str,
    scan_release: str,
    field: str = "check",
) -> str:
    """Describe the source of one text field (``field`` is "check" or "fix").

    ``outcome`` says how the field ended up. ``origin`` is the reference rule
    that filled it, required for the ``FILLED*`` outcomes, or for
    ``IN_REFERENCE_NO_TEXT`` the supplied rule that was found without the text.
    """
    if outcome is Outcome.SCANNER:
        return "scanner"
    if outcome in _GAP_PHRASES:
        return _GAP_PHRASES[outcome]
    if outcome not in _MATCH_SUFFIXES and outcome is not Outcome.IN_REFERENCE_NO_TEXT:
        raise ValueError(f"{outcome!r} is not the outcome of a single text field")
    if origin is None:
        raise ValueError(f"{outcome!r} needs the reference rule that filled the field")
    # File name and releases come from uploads: bound them before they reach a cell.
    release = clip(origin.source.release, MAX_RELEASE_CHARS)
    scan_release = clip(scan_release, MAX_RELEASE_CHARS)
    # A display name ends with the file's own name (an archive member's is "zip/…/name").
    label = f"{clip_left(origin.source.file_name, MAX_SHOWN_CHARS)} {release}".strip()
    if outcome is Outcome.IN_REFERENCE_NO_TEXT:
        return f"in {label}, which has no {field} text"
    differs = bool(finding_revision) and bool(origin.revision) and origin.revision != finding_revision
    if not differs:
        phrase = label
    elif scan_release and scan_release != release:
        phrase = f"{label}, scanned {scan_release}"
    else:
        phrase = f"{label}, revision differs from scan"
    return phrase + _MATCH_SUFFIXES[outcome]


def text_source_cell(check_phrase: str, fix_phrase: str) -> str:
    if check_phrase == fix_phrase:
        return f"Check and fix: {check_phrase}"
    return f"Check: {check_phrase} | Fix: {fix_phrase}"
