"""Data carried by the reference library."""
from __future__ import annotations

from dataclasses import dataclass

from app.reference.normalize import (
    MAX_FILE_NAME_CHARS,
    MAX_RELEASE_CHARS,
    MAX_STORED_CHARS,
    clip,
    clip_left,
    is_vuln_id,
    norm_stig_id,
    rule_revision,
    rule_stem,
    strip_group_prefix,
    strip_rule_prefix,
)


@dataclass(frozen=True, slots=True)
class ReferenceSource:
    """One STIG benchmark the run loaded, from one file."""
    file_name: str
    benchmark_id: str   # prefix stripped
    title: str
    release: str        # "V2R8"
    embedded: bool      # True when lifted from a results file (SCC, results CKLB)
    edition: str        # "manual" | "scap" | "cklb"
    rule_count: int

    def __post_init__(self) -> None:
        # File name, title, benchmark ID and release come from an upload and reach cells, warnings and
        # the report. Bounding them here covers every way a source is built, including a loaded report.
        # A file name is cut from the left: its end is the file's own name.
        object.__setattr__(self, "file_name", clip_left(self.file_name, MAX_FILE_NAME_CHARS))
        object.__setattr__(self, "title", clip(self.title, MAX_STORED_CHARS))
        object.__setattr__(self, "benchmark_id", clip(self.benchmark_id, MAX_STORED_CHARS))
        object.__setattr__(self, "release", clip(self.release, MAX_RELEASE_CHARS))


@dataclass(slots=True)
class ReferenceRule:
    """One rule of one source."""
    vuln_id: str
    rule_id: str        # prefix stripped, revision kept
    rule_stem: str
    revision: str
    stig_id: str
    severity: str
    stig_title: str
    check_text: str
    fix_text: str
    source: ReferenceSource


def indexable(*, vuln_id: str, rule_id: str, stig_id: str) -> bool:
    """True when a rule with these raw identifiers can be found by some key of the
    library: a rule ID, a V-ID-shaped group ID, or a STIG ID. One with none of
    them can never be found, so it is not worth building."""
    return bool(strip_rule_prefix(rule_id) or is_vuln_id(vuln_id) or norm_stig_id(stig_id))


def make_rule(
    source: ReferenceSource,
    *,
    vuln_id: str,
    rule_id: str,
    stig_id: str,
    severity: str,
    stig_title: str,
    check_text: str,
    fix_text: str,
) -> ReferenceRule:
    """A reference rule from raw benchmark or checklist values.

    The one place identifiers are normalised and bounded (they come from an
    upload), so an XCCDF benchmark and a checklist cannot spell the same rule
    differently: XCCDF prefixes stripped, stem and revision derived from the
    rule ID, the STIG ID folded, and ``Unknown`` severity left blank.
    """
    return ReferenceRule(
        vuln_id=clip(strip_group_prefix(vuln_id), MAX_STORED_CHARS),
        rule_id=clip(strip_rule_prefix(rule_id), MAX_STORED_CHARS),
        rule_stem=clip(rule_stem(rule_id), MAX_STORED_CHARS),
        revision=rule_revision(rule_id),
        stig_id=clip(norm_stig_id(stig_id), MAX_STORED_CHARS),
        severity="" if severity == "Unknown" else severity,
        stig_title=clip(stig_title, MAX_STORED_CHARS),
        check_text=check_text,
        fix_text=fix_text,
        source=source,
    )
