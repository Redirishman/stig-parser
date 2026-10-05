"""Every STIG rule the run knows about, indexed by the three stable keys."""
from __future__ import annotations

import hashlib
import itertools
from collections import defaultdict
from collections.abc import Callable
from enum import StrEnum
from typing import NamedTuple

from app.parsers.base import Benchmark, Finding
from app.reference.models import ReferenceRule, ReferenceSource, make_rule
from app.reference.normalize import (
    MAX_RELEASE_CHARS,
    MAX_SHOWN_CHARS,
    clip,
    fold,
    is_disa_stem,
    is_vuln_id,
    norm_benchmark_id,
    norm_stig_id,
    product_key,
    release_key,
    rule_revision,
    rule_stem,
    shown_file_name,
    strip_group_prefix,
    strip_rule_prefix,
)

# Reference files are untrusted, so one key value never indexes more rules than
# this. Real STIGs hold a handful of rules per key (one per revision loaded).
_MAX_RULES_PER_KEY = 32
# Rules the library holds for one run, every source together. Each one lives
# for the whole run; a DISA STIG library of every STIG holds about 100,000.
MAX_RULES_PER_RUN = 250_000
MAX_REFUSED_TITLES = 5      # reference STIG titles named when the product guard refused a STIG ID
UNTITLED_REFERENCE = "(untitled reference)"


class MatchKey(StrEnum):
    """The key through which a finding reached a reference rule (strongest first)."""
    RULE_ID = "rule_id"
    STEM = "stem"
    VULN_ID = "vuln_id"
    STIG_ID = "stig_id"


class Lookup(NamedTuple):
    """The outcome of looking one finding up."""
    matches: list[tuple[ReferenceRule, MatchKey]]   # (rule, first key that reached it), best first
    ambiguous_by: str = ""      # "vuln_id" | "stig_id": candidates were dropped because they name several rules/STIGs
    # Titles of the STIGs whose rules were reached only by STIG ID and refused because the
    # finding's STIG title names another product (distinct, at most 5; refused_more if cut).
    refused_products: tuple[str, ...] = ()
    refused_more: bool = False

    @property
    def ambiguous(self) -> bool:
        return bool(self.ambiguous_by)


class _Keys(NamedTuple):
    """The comparison forms of a finding's identifiers."""
    rule_id: str    # folded, prefix-stripped rule ID
    stem: str       # folded rule stem
    own_stem: str   # the stem when it is DISA-style, else "": only a DISA stem can contradict another
    vuln: str       # folded V-ID, or "" when the value is not V-ID-shaped
    stig_id: str


class _Gathered(NamedTuple):
    by_rule: list[tuple[ReferenceRule, MatchKey]]   # reached by rule ID or stem
    by_vuln_only: list[ReferenceRule]
    by_stig_id_only: list[ReferenceRule]


def _vuln_key(value: str) -> str:
    """The folded V-ID in *value*, or "" when it is not V-ID-shaped (a topic group ID)."""
    bare = strip_group_prefix(value)
    return fold(bare) if is_vuln_id(bare) else ""


def _finding_keys(finding: Finding) -> _Keys:
    stem = fold(rule_stem(finding.rule_id))
    return _Keys(
        rule_id=fold(strip_rule_prefix(finding.rule_id)),
        stem=stem,
        own_stem=stem if is_disa_stem(stem) else "",
        vuln=_vuln_key(finding.vuln_id),
        stig_id=norm_stig_id(finding.stig_id),
    )


def _acceptable(rule: ReferenceRule, keys: _Keys) -> bool:
    """False when the rule contradicts the finding: different DISA stems, or different V-IDs."""
    if keys.own_stem and is_disa_stem(rule.rule_stem) and fold(rule.rule_stem) != keys.own_stem:
        return False
    rule_vuln = _vuln_key(rule.vuln_id)
    return not (keys.vuln and rule_vuln and rule_vuln != keys.vuln)


def _rank_key(finding: Finding) -> Callable[[ReferenceRule], tuple[int, int, int, int, int]]:
    """Sort key for rules reached through one key, best first: same revision as the finding, operator-
    supplied before embedded, the release the finding was scanned against, then the newest release.
    Ties keep load order (the sort is stable and every index lists rules in load order)."""
    revision = rule_revision(finding.rule_id)
    scanned = clip(finding.scan_release, MAX_RELEASE_CHARS).strip()

    def rank(rule: ReferenceRule) -> tuple[int, int, int, int, int]:
        same_revision = bool(revision) and rule.revision == revision
        scanned_release = bool(scanned) and rule.source.release == scanned
        major, minor = release_key(rule.source.release)
        return (
            0 if same_revision else 1,
            1 if rule.source.embedded else 0,
            0 if scanned_release else 1,
            -major,
            -minor,
        )

    return rank


def _rule_identity(rule: ReferenceRule) -> tuple[str, str]:
    """Which rule this is, per naming dialect: DISA stem, else the folded rule ID."""
    if is_disa_stem(rule.rule_stem):
        return ("disa", fold(rule.rule_stem))
    return ("other", fold(strip_rule_prefix(rule.rule_id)))


def _guard_product(
    finding: Finding, by_stig_id_only: list[ReferenceRule]
) -> tuple[list[ReferenceRule], bool, list[str]]:
    """Keep the STIG-ID-only rules that describe the finding's product.

    Returns (kept, ambiguous, refused titles). A titled finding keeps the rules of its own
    product and the others are refused (their titles are reported). An untitled one keeps
    them only when they all describe one product; otherwise none are kept and it is ambiguous.
    """
    if not by_stig_id_only:
        return [], False, []
    if (finding.stig_title or "").strip():
        wanted = product_key(finding.stig_title)
        kept = [r for r in by_stig_id_only if product_key(r.stig_title) == wanted]
        kept_ids = {id(r) for r in kept}
        refused: list[str] = []
        for r in by_stig_id_only:
            title = clip(r.stig_title, MAX_SHOWN_CHARS) or UNTITLED_REFERENCE
            if id(r) not in kept_ids and title not in refused:
                refused.append(title)
        return kept, False, refused
    if len({product_key(r.stig_title) for r in by_stig_id_only}) > 1:
        return [], True, []
    return by_stig_id_only, False, []


def _content_digest(rules: list[ReferenceRule]) -> str:
    """SHA-256 over the sorted (rule ID, severity, check text, fix text) of every rule.

    Fields are length-prefixed so where one ends and the next begins cannot be forged.
    """
    digest = hashlib.sha256()
    for fields in sorted((r.rule_id, r.severity, r.check_text, r.fix_text) for r in rules):
        for value in fields:
            data = value.encode("utf-8", "surrogatepass")
            digest.update(len(data).to_bytes(8, "big"))
            digest.update(data)
    return digest.hexdigest()


class ReferenceLibrary:
    def __init__(self) -> None:
        self.sources: list[ReferenceSource] = []
        # Operator-facing notes about what the library could not index.
        self.warnings: list[str] = []
        self._held = 0          # rules held, every source together
        self._full = False      # a rule was left out for MAX_RULES_PER_RUN: nothing more is added
        self._warned: set[tuple[str, str]] = set()
        # Embedded benchmarks already loaded, by (benchmark ID, release, content digest): an
        # SCC run repeats the same embedded benchmark once per host.
        self._embedded: dict[tuple[str, str, str], ReferenceSource] = {}
        # Rules indexed per (index, key value, embedded?): supplied and embedded rules
        # are capped separately, so embedded copies cannot crowd out an operator reference.
        self._bucket_size: dict[tuple[str, str, bool], int] = defaultdict(int)
        self._by_rule_id: dict[str, list[ReferenceRule]] = defaultdict(list)
        self._by_stem: dict[str, list[ReferenceRule]] = defaultdict(list)
        self._by_vuln: dict[str, list[ReferenceRule]] = defaultdict(list)
        self._by_stig_id: dict[str, list[ReferenceRule]] = defaultdict(list)

    @property
    def has_standalone(self) -> bool:
        """True when the operator supplied at least one reference."""
        return any(not s.embedded for s in self.sources)

    @property
    def rules_left(self) -> int:
        """How many more rules the run may hold (see MAX_RULES_PER_RUN)."""
        return 0 if self._full else max(0, MAX_RULES_PER_RUN - self._held)

    def not_loaded(self, file_name: str) -> None:
        """Record that rules of *file_name* were left out for the run's limit: nothing
        more is added, and the operator is told once, naming the first such file."""
        if not self._full:
            self._full = True
            self.warnings.append(
                f"{shown_file_name(file_name)}: the limit of {MAX_RULES_PER_RUN:,} STIG reference rules for one "
                "run was reached — rules past it, in this file and any later reference, were not loaded; "
                'findings they would have filled read "not in supplied references"'
            )

    def add_benchmark(self, benchmark: Benchmark, file_name: str, *, embedded: bool) -> ReferenceSource:
        """Load a parsed XCCDF benchmark (Manual STIG, SCAP benchmark, SCC-embedded).

        No more rules are built than the run may still hold (see :meth:`not_loaded`).
        """
        edition = "manual" if any(r.check_text for r in benchmark.rules.values()) else "scap"
        room = self.rules_left
        source = ReferenceSource(
            file_name=file_name,
            benchmark_id=norm_benchmark_id(benchmark.benchmark_id),
            title=benchmark.title,
            release=benchmark.release,
            embedded=embedded,
            edition=edition,
            rule_count=min(len(benchmark.rules), room),
        )
        rules = [
            make_rule(
                source, vuln_id=r.vuln_id, rule_id=r.rule_id, stig_id=r.stig_id, severity=r.severity,
                stig_title=benchmark.title, check_text=r.check_text, fix_text=r.fix_text,
            )
            for r in itertools.islice(benchmark.rules.values(), room)
        ]
        held = self.add_rules(source, rules) if rules or not benchmark.rules else source
        if len(benchmark.rules) > room:
            self.not_loaded(file_name)
        return held

    def add_rules(self, source: ReferenceSource, rules: list[ReferenceRule]) -> ReferenceSource:
        """Index *rules* under *source*; returns the source the library holds.

        An embedded source identical to one already loaded (same benchmark ID,
        release, and rule IDs, severities, check and fix text) adds nothing and
        the existing source is returned. A copy whose text differs is kept.
        Once the run holds MAX_RULES_PER_RUN rules, nothing more is added.
        """
        if self._full:
            return source
        room = self.rules_left
        if len(rules) > room:
            self.not_loaded(source.file_name)
            rules = rules[:room]
            if not rules:
                return source
        if source.embedded:
            identity = (source.benchmark_id, source.release, _content_digest(rules))
            existing = self._embedded.get(identity)
            if existing is not None:
                return existing
            self._embedded[identity] = source
        self.sources.append(source)
        for rule in rules:
            for index, key, kind in (
                (self._by_rule_id, fold(rule.rule_id), "rule ID"),
                (self._by_stem, fold(rule.rule_stem), "rule stem"),
                (self._by_vuln, _vuln_key(rule.vuln_id), "V-ID"),
                (self._by_stig_id, rule.stig_id, "STIG ID"),
            ):
                if not key:
                    continue
                size_key = (kind, key, source.embedded)
                if self._bucket_size[size_key] < _MAX_RULES_PER_KEY:
                    self._bucket_size[size_key] += 1
                    index[key].append(rule)
                elif (source.file_name, kind) not in self._warned:
                    self._warned.add((source.file_name, kind))
                    self.warnings.append(
                        f"{shown_file_name(source.file_name)}: more than {_MAX_RULES_PER_KEY} rules "
                        f"share one {kind} — extra rules ignored for lookup"
                    )
        self._held += len(rules)
        return source

    def lookup(self, finding: Finding) -> Lookup:
        """Rules that may describe *finding*, best first, minus contradictions.

        Keys are tried in order: exact rule ID, rule stem, V-ID, STIG ID.
        Within one key: same revision as the finding first, then operator-
        supplied sources before embedded ones, then the release the finding
        was scanned against, then the newest release, then load order (so
        upload order never decides between two releases).

        A rule is never offered when it contradicts the finding:

        1. both have a DISA rule stem (``SV-`` and digits) and the stems differ
           (a V-ID Group can hold several Rules, so a shared V-ID alone does
           not make them one rule). A rule ID that is not DISA-style, such as
           an SSG rule name, a scanner check name, or a STIG ID, is no stem;
        2. both have a V-ID (V-ID-shaped: a topic group ID such as
           ``accounts-session`` is neither a key nor compared) and the V-IDs
           differ;
        3. the rule was reached only through its STIG ID, which DISA reuses
           across STIGs (router and switch NDM share ``CISC-ND-000010``), and
           it describes another product. An untitled finding accepts such
           rules only when they all describe one product; otherwise none are
           accepted and the lookup is reported as ambiguous.

        When the V-ID reaches more than one distinct rule within one naming
        dialect (DISA stems, or folded non-DISA rule IDs), the V-ID does not
        name one rule: every candidate reached only through it in that dialect
        is dropped. Exact rule-ID and stem hits stay. One DISA rule and one
        non-DISA rule under a V-ID are different dialects, not ambiguous; two
        releases of one rule share an identity.

        The lookup is reported ambiguous only when something was dropped and
        no rule matched by rule ID or stem: a finding whose own rule matched
        exactly is not ambiguous, whatever else shares its V-ID or STIG ID.
        """
        keys = _finding_keys(finding)
        gathered = self._gather(keys, _rank_key(finding))
        by_vuln, vuln_crowded = self._drop_crowded_vuln(keys, gathered.by_vuln_only)
        by_stig_id, stig_ambiguous, refused = _guard_product(finding, gathered.by_stig_id_only)

        ambiguous_by = MatchKey.VULN_ID if vuln_crowded else MatchKey.STIG_ID if stig_ambiguous else ""
        if gathered.by_rule:
            ambiguous_by = ""
        matches = list(gathered.by_rule)
        matches += [(rule, MatchKey.VULN_ID) for rule in by_vuln]
        matches += [(rule, MatchKey.STIG_ID) for rule in by_stig_id]
        return Lookup(matches, ambiguous_by, tuple(refused[:MAX_REFUSED_TITLES]), len(refused) > MAX_REFUSED_TITLES)

    def _gather(self, keys: _Keys, rank: Callable[[ReferenceRule], tuple]) -> _Gathered:
        """Every acceptable rule the four keys reach, filed under the first key that reached it."""
        lookups = (
            (MatchKey.RULE_ID, self._by_rule_id, keys.rule_id),
            (MatchKey.STEM, self._by_stem, keys.stem),
            (MatchKey.VULN_ID, self._by_vuln, keys.vuln),
            (MatchKey.STIG_ID, self._by_stig_id, keys.stig_id),
        )
        seen: set[int] = set()
        gathered = _Gathered([], [], [])
        for kind, index, key in lookups:
            if not key:
                continue
            for rule in sorted(index.get(key, ()), key=rank):
                if id(rule) in seen:
                    continue
                seen.add(id(rule))
                if not _acceptable(rule, keys):
                    continue
                if kind is MatchKey.STIG_ID:
                    gathered.by_stig_id_only.append(rule)
                elif kind is MatchKey.VULN_ID:
                    gathered.by_vuln_only.append(rule)
                else:
                    gathered.by_rule.append((rule, kind))
        return gathered

    def _drop_crowded_vuln(self, keys: _Keys, by_vuln_only: list[ReferenceRule]) -> tuple[list[ReferenceRule], bool]:
        """Drop the V-ID-only rules of every naming dialect in which the V-ID names several rules.

        The count covers everything the V-ID reaches, including rules the rule ID also reached.
        Returns (kept, whether any were dropped).
        """
        if not by_vuln_only:
            return [], False
        identities: dict[str, set[str]] = {}
        for rule in self._by_vuln.get(keys.vuln, ()):
            if _acceptable(rule, keys):
                dialect, name = _rule_identity(rule)
                identities.setdefault(dialect, set()).add(name)
        crowded = {dialect for dialect, names in identities.items() if len(names) > 1}
        kept = [r for r in by_vuln_only if _rule_identity(r)[0] not in crowded]
        return kept, len(kept) < len(by_vuln_only)
