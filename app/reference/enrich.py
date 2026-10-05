"""Fill blank finding fields from the reference library and report what happened.

Runs on actionable findings only, so every count here is a row of the report.
Scanner-supplied values are never overwritten: the finding was evaluated
against the scanned benchmark, and the reference only fills gaps.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field, fields

from app.parsers.base import Finding
from app.reference.library import MAX_REFUSED_TITLES, Lookup, MatchKey, ReferenceLibrary
from app.reference.models import ReferenceRule, ReferenceSource
from app.reference.normalize import MAX_RELEASE_CHARS, MAX_SHOWN_CHARS, clip, rule_revision, rule_stem
from app.reference.text_source import Outcome, source_phrase, text_source_cell

_FILL_FIELDS = ("check_text", "fix_text", "severity", "vuln_id", "stig_id", "stig_title")
_NO_TITLE = "(no STIG title)"
_MAX_IDS = 5            # IDs named in one warning line
MAX_STORED_IDS = 50     # IDs kept per STIG in the report; the count stays exact
_MAX_LOADED = 5         # reference sources named in the wrong-product line
_MAX_TITLES = 5         # STIG titles named in an aggregated blank-text line


def source_key(source: ReferenceSource) -> str:
    """Key of one source in ``EnrichmentReport.source_counts``.

    A checklist can hold several STIGs under one file name, so the file name
    alone would merge their counts.
    """
    return f"{source.file_name}|{source.benchmark_id}"


@dataclass
class StigCounts:
    findings: int = 0
    needed: int = 0             # findings that lacked check or fix text before enrichment
    filled_check: int = 0
    filled_fix: int = 0
    filled_severity: int = 0
    drifted: int = 0            # findings that took text from a different revision
    unmatched: int = 0          # findings no supplied reference answered
    unmatched_rules: int = 0    # distinct rules among them
    blank_check_with_fix: int = 0
    blank_fix_with_check: int = 0
    blank_both: int = 0         # titled findings left with neither check nor fix text
    ambiguous: int = 0          # findings whose V-ID or STIG ID names several rules/STIGs; not filled
    product_refused: int = 0    # findings whose STIG ID exists only under a different STIG title; not filled
    refused_titles: list[str] = field(default_factory=list)   # those reference titles, distinct, at most 5
    refused_more: bool = False  # more than 5 distinct titles
    unmatched_ids: list[str] = field(default_factory=list)   # distinct, first seen first, capped
    drift_pair: str = ""        # most common "reference VxRy, scanned VaRb"


@dataclass
class EnrichmentReport:
    stigs: dict[str, StigCounts] = field(default_factory=dict)
    sources: list[ReferenceSource] = field(default_factory=list)
    # source_key(source) -> {"filled_check": n, "filled_fix": n, "drifted": n, "filled_severity": n}
    source_counts: dict[str, dict[str, int]] = field(default_factory=dict)

    @property
    def standalone_sources(self) -> list[ReferenceSource]:
        return [s for s in self.sources if not s.embedded]

    def warnings(self) -> list[str]:
        """Operator-facing lines, one per STIG and kind, only when non-zero."""
        out: list[str] = []
        standalone = self.standalone_sources
        loaded = "; ".join(
            f"{clip(s.title, MAX_SHOWN_CHARS)} {clip(s.release, MAX_RELEASE_CHARS)}".strip()
            for s in standalone[:_MAX_LOADED])
        loaded += "…" if len(standalone) > _MAX_LOADED else ""
        for title, c in self.stigs.items():
            title = clip(title, MAX_SHOWN_CHARS)     # the keys are bounded when written; a payload may not be
            if c.drifted:
                pair = f" ({clip(c.drift_pair, MAX_SHOWN_CHARS)})" if c.drift_pair else ""
                out.append(
                    f"{title}: {c.drifted} finding(s) took check/fix text from a different "
                    f"release{pair} — see the Text Source column"
                )
            if c.unmatched and c.unmatched == c.needed:
                out.append(
                    f"{title}: none of {c.needed} finding(s) that need text matched a supplied "
                    f"reference (loaded: {loaded}) — wrong product or STIG?"
                )
            elif c.unmatched:
                # A payload written before unmatched_rules existed has 0 here: say nothing about rules.
                rules = c.unmatched_rules or len(c.unmatched_ids)
                ids = ", ".join(clip(i, MAX_SHOWN_CHARS) for i in c.unmatched_ids[:_MAX_IDS])
                ids += "…" if rules > _MAX_IDS else ""
                across = f" across {c.unmatched_rules} rule(s)" if c.unmatched_rules else ""
                out.append(f"{title}: {c.unmatched} finding(s){across} not found in any supplied reference: {ids}")
            if c.ambiguous:
                out.append(
                    f"{title}: {c.ambiguous} finding(s) match more than one rule or STIG "
                    "and were not filled — supply the scan's own benchmark or only the matching STIG"
                )
            if c.product_refused:
                shown = "; ".join(clip(t, MAX_SHOWN_CHARS) for t in c.refused_titles[:MAX_REFUSED_TITLES])
                shown += "…" if c.refused_more else ""
                out.append(
                    f"{title}: {c.product_refused} finding(s) carry a STIG ID found only under a different "
                    f"STIG title ({shown}) and were not filled — if this is the right STIG, supply the "
                    "scan's own benchmark or a checklist"
                )
            if c.blank_both:
                out.append(
                    f"{title}: {c.blank_both} finding(s) have neither check nor fix text — "
                    "add the STIG as a reference"
                )
        blank = {t: c.blank_check_with_fix for t, c in self.stigs.items() if c.blank_check_with_fix}
        if blank:
            out.append(
                f"Check text is blank for {sum(blank.values())} finding(s) in {len(blank)} STIG(s): "
                f"{_names(blank)}. SCC results and SCAP Benchmark files carry fix text but no "
                "check text — add the Manual STIG (DISA STIG ZIP or *_Manual-xccdf.xml) as a "
                "reference to fill it."
            )
        no_fix = {t: c.blank_fix_with_check for t, c in self.stigs.items() if c.blank_fix_with_check}
        if no_fix:
            out.append(
                f"Fix text is blank for {sum(no_fix.values())} finding(s) in {len(no_fix)} STIG(s): "
                f"{_names(no_fix)}."
            )
        return out

    def to_dict(self) -> dict:
        return {
            "stigs": {t: asdict(c) for t, c in self.stigs.items()},
            "sources": [asdict(s) for s in self.sources],
            "source_counts": self.source_counts,
        }

    @classmethod
    def from_dict(cls, data: object) -> "EnrichmentReport":
        """Load a report from a JSON payload; never raises on one of the wrong shape.

        Unknown keys (a newer writer) are ignored, missing or mistyped fields take
        their defaults, and an entry that is not an object is skipped.
        """
        if not isinstance(data, dict):
            return cls()
        stigs, sources, counts = data.get("stigs"), data.get("sources"), data.get("source_counts")
        return cls(
            stigs={t: _load_counts(c) for t, c in stigs.items() if isinstance(c, dict)}
            if isinstance(stigs, dict) else {},
            sources=[_load_source(s) for s in sources if isinstance(s, dict)] if isinstance(sources, list) else [],
            source_counts=_load_source_counts(counts),
        )


def _names(titles: dict[str, int]) -> str:
    """The distinct STIG titles of an aggregated line, each bounded, at most five named."""
    distinct = list(dict.fromkeys(clip(t, MAX_SHOWN_CHARS) for t in titles))
    shown = "; ".join(distinct[:_MAX_TITLES])
    more = len(distinct) - _MAX_TITLES
    return f"{shown} … and {more} more" if more > 0 else shown


def _load_counts(raw: dict) -> StigCounts:
    """A StigCounts from a payload entry: each field keeps its default unless the value has the right type."""
    counts = StigCounts()
    for f in fields(StigCounts):
        value, default = raw.get(f.name), getattr(counts, f.name)
        if isinstance(default, bool):
            ok = isinstance(value, bool)
        elif isinstance(default, int):
            ok = isinstance(value, int) and not isinstance(value, bool) and value >= 0
        elif isinstance(default, str):
            ok = isinstance(value, str)
            value = clip(value, MAX_SHOWN_CHARS) if ok else value
        else:   # the two lists of text
            ok = isinstance(value, list)
            limit = MAX_STORED_IDS if f.name == "unmatched_ids" else MAX_REFUSED_TITLES
            value = [clip(v, MAX_SHOWN_CHARS) for v in value if isinstance(v, str)][:limit] if ok else value
        if ok:
            setattr(counts, f.name, value)
    return counts


def _load_source(raw: dict) -> ReferenceSource:
    def text(name: str) -> str:
        value = raw.get(name)
        return value if isinstance(value, str) else ""

    rule_count = raw.get("rule_count")
    return ReferenceSource(
        file_name=text("file_name"), benchmark_id=text("benchmark_id"), title=text("title"),
        release=text("release"), embedded=raw.get("embedded") is True, edition=text("edition"),
        rule_count=rule_count if isinstance(rule_count, int) and not isinstance(rule_count, bool) else 0,
    )


def _load_source_counts(raw: object) -> dict[str, dict[str, int]]:
    if not isinstance(raw, dict):
        return {}
    return {
        key: {name: n for name, n in entry.items() if isinstance(n, int) and not isinstance(n, bool)}
        for key, entry in raw.items() if isinstance(entry, dict)
    }


def _source_counts(report: EnrichmentReport, source: ReferenceSource) -> dict[str, int]:
    """The counts of *source* in *report*, created at zero."""
    return report.source_counts.setdefault(
        source_key(source), {"filled_check": 0, "filled_fix": 0, "drifted": 0, "filled_severity": 0})


def _is_blank(name: str, value: str) -> bool:
    """Blank for filling purposes: empty, or a severity the scanner could not resolve."""
    return not value or (name == "severity" and value == "Unknown")


def _fill(
    finding: Finding,
    matches: list[tuple[ReferenceRule, MatchKey]],
    origin: dict[str, ReferenceRule],
    via: dict[str, MatchKey],
) -> None:
    for name in _FILL_FIELDS:
        if not _is_blank(name, getattr(finding, name)):
            continue
        for rule, key in matches:
            value = getattr(rule, name)
            if not _is_blank(name, value):
                setattr(finding, name, value)
                origin[name] = rule
                via[name] = key
                break


_FILLED_OUTCOME = {MatchKey.VULN_ID: Outcome.FILLED_BY_VULN_ID, MatchKey.STIG_ID: Outcome.FILLED_BY_STIG_ID}


def _field_outcome(
    had: bool, origin: ReferenceRule | None, key: MatchKey | None, found: Lookup,
    supplied: ReferenceRule | None, references_supplied: bool,
) -> Outcome:
    """How one text field of a finding ended up: its Text Source phrase and, for a
    blank field, the reason the report counts. ``supplied`` is the best-ranked
    operator-supplied candidate, if any."""
    if had:
        return Outcome.SCANNER
    if origin is not None:
        return _FILLED_OUTCOME.get(key, Outcome.FILLED)
    if found.ambiguous:
        return Outcome.AMBIGUOUS_VULN_ID if found.ambiguous_by == MatchKey.VULN_ID else Outcome.AMBIGUOUS_STIG_ID
    if supplied is not None:
        return Outcome.IN_REFERENCE_NO_TEXT
    if found.refused_products:
        return Outcome.PRODUCT_REFUSED
    return Outcome.NOT_IN_REFERENCES if references_supplied else Outcome.NO_REFERENCE


_GAP_ORDER = (Outcome.AMBIGUOUS_VULN_ID, Outcome.AMBIGUOUS_STIG_ID, Outcome.PRODUCT_REFUSED, Outcome.NOT_IN_REFERENCES)


def _finding_outcome(f: Finding, check: Outcome, fix: Outcome) -> Outcome | None:
    """Why a finding still lacks text after enrichment (None when it has both).

    Derived from the outcomes of its blank fields, in report-count order, so the
    counts say what the Text Source cell says.
    """
    gaps = {o for o, text in ((check, f.check_text), (fix, f.fix_text)) if not text}
    if not gaps:
        return None
    for reason in _GAP_ORDER:
        if reason in gaps:
            return reason
    if not f.check_text and f.fix_text:
        return Outcome.BLANK_CHECK
    if f.check_text and not f.fix_text:
        return Outcome.BLANK_FIX
    # Untitled findings are deliberately left out: the pipeline reports those per results file.
    return Outcome.BLANK_BOTH if f.stig_title else None


def enrich_findings(findings: list[Finding], library: ReferenceLibrary) -> EnrichmentReport:
    """Fill blanks in place and return the report."""
    report = EnrichmentReport(sources=list(library.sources))
    references_supplied = library.has_standalone
    drift_pairs: dict[str, Counter] = {}
    unmatched_seen: dict[str, set[str]] = {}    # title -> distinct unmatched rule references

    for f in findings:
        had_check, had_fix = bool(f.check_text), bool(f.fix_text)
        origin: dict[str, ReferenceRule] = {}
        via: dict[str, MatchKey] = {}   # field -> key that reached the rule that filled it
        found = library.lookup(f)
        _fill(f, found.matches, origin, via)
        if "vuln_id" in origin or "stig_id" in origin:
            # New identifiers can reach rules the first pass could not.
            found = library.lookup(f)
            _fill(f, found.matches, origin, via)
        supplied = next((rule for rule, _ in found.matches if not rule.source.embedded), None)

        revision = rule_revision(f.rule_id)
        outcomes = {
            name: _field_outcome(had, origin.get(name), via.get(name), found, supplied, references_supplied)
            for name, had in (("check_text", had_check), ("fix_text", had_fix))
        }
        phrases = {
            name: source_phrase(
                supplied if outcome is Outcome.IN_REFERENCE_NO_TEXT else origin.get(name), outcome,
                finding_revision=revision, scan_release=f.scan_release, field=name.removesuffix("_text"),
            )
            for name, outcome in outcomes.items()
        }
        f.text_source = text_source_cell(phrases["check_text"], phrases["fix_text"])

        title = clip(f.stig_title, MAX_SHOWN_CHARS) or _NO_TITLE
        counts = report.stigs.setdefault(title, StigCounts())
        counts.findings += 1
        counts.needed += not (had_check and had_fix)
        counts.filled_severity += "severity" in origin
        if "severity" in origin:
            _source_counts(report, origin["severity"].source)["filled_severity"] += 1
        drifted_from: dict[str, str] = {}   # source key -> "reference VxRy, scanned VaRb" ("" when unknown)
        for name, counter in (("check_text", "filled_check"), ("fix_text", "filled_fix")):
            rule = origin.get(name)
            if rule is None:
                continue
            setattr(counts, counter, getattr(counts, counter) + 1)
            key = source_key(rule.source)
            _source_counts(report, rule.source)[counter] += 1
            if revision and rule.revision and rule.revision != revision:
                parts = []
                release = clip(rule.source.release, MAX_RELEASE_CHARS)
                scanned = clip(f.scan_release, MAX_RELEASE_CHARS)
                if release:
                    parts.append(f"reference {release}")
                if scanned and scanned != release:
                    parts.append(f"scanned {scanned}")
                drifted_from[key] = ", ".join(parts)
        for key, pair in drifted_from.items():       # once per finding per source, not per field
            report.source_counts[key]["drifted"] += 1
            if pair:
                drift_pairs.setdefault(title, Counter())[pair] += 1
        counts.drifted += bool(drifted_from)

        match _finding_outcome(f, outcomes["check_text"], outcomes["fix_text"]):
            case Outcome.AMBIGUOUS_VULN_ID | Outcome.AMBIGUOUS_STIG_ID:
                counts.ambiguous += 1
            case Outcome.PRODUCT_REFUSED:
                counts.product_refused += 1
                for refused in found.refused_products:
                    if refused not in counts.refused_titles:
                        if len(counts.refused_titles) < MAX_REFUSED_TITLES:
                            counts.refused_titles.append(refused)
                        else:
                            counts.refused_more = True
                counts.refused_more = counts.refused_more or found.refused_more
            case Outcome.NOT_IN_REFERENCES:
                counts.unmatched += 1
                rule_ref = clip(rule_stem(f.rule_id) or f.vuln_id or "(no rule ID)", MAX_SHOWN_CHARS)
                seen = unmatched_seen.setdefault(title, set())
                if rule_ref not in seen:
                    seen.add(rule_ref)
                    counts.unmatched_rules += 1
                    if len(counts.unmatched_ids) < MAX_STORED_IDS:
                        counts.unmatched_ids.append(rule_ref)
            case Outcome.BLANK_CHECK:
                counts.blank_check_with_fix += 1
            case Outcome.BLANK_FIX:
                counts.blank_fix_with_check += 1
            case Outcome.BLANK_BOTH:
                counts.blank_both += 1

    for title, pairs in drift_pairs.items():
        report.stigs[title].drift_pair = pairs.most_common(1)[0][0]
    return report
