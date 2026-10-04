"""Route uploaded files by what they contain, not by which slot they came from.

The GovCloud SPA sends one flat file list, and operators drop a Manual STIG in
the results zone as often as not. Only two cases are re-routed: a benchmark
found among the results becomes a reference, and scan results found among the
references become results. Everything else keeps its list, so the existing
parsers still produce their specific messages (legacy .ckl, invalid XML, …).

A ZIP is a folder: each member is routed exactly as the same file would be if
it had been uploaded loose in the slot the ZIP came from.

A file supplied twice (in both slots, under two names, loose and inside a ZIP)
is read once: a scan counted twice doubles its findings.

Every file and archive member the operator supplied is either routed or named
in ``ClassifiedInputs.warnings`` with the reason, and nothing here raises on a
bad one.

Nothing here parses a file. What an XML file is comes from its document element
(read from its first 64 KiB) and, when that does not settle it, from whether a
TestResult or Benchmark start tag occurs in its bytes; a file that is not
well-formed is routed by those, and the parser that reads it names it as not
parsed. What parsing a file would cost is measured in the pass that hashes it
(see :mod:`app.utils.parse_cost`): a file over the per-file caps, or past the
run's element budget, is named and never parsed.

Every file of the run has one display name (``ClassifiedInputs.name_of``),
unique in the run, that names something the operator supplied: a loose file's
own name; an archive member's base name when no other file of the run has it,
otherwise ``{archive}/{path inside it}``; and ``" (2)"``, ``" (3)"`` after a
name that is still not unique (two loose files with one name).
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping

from app.reference.normalize import MAX_FILE_NAME_CHARS, clip_left, display_file_name, safe_name
from app.utils.parse_cost import (
    ParseCost,
    measure,
    run_element_budget,
    run_reference_budget,
    start_tags,
    too_costly,
)
from app.utils.zip_extract import (
    LEGACY_CHECKLIST_ROOT,
    LEGACY_CHECKLIST_SUFFIX,
    Budget,
    ExtractedMember,
    extract_from_zip,
    is_support_name,
    is_support_root,
    run_budget,
    sniff_root,
)

_LEGACY_CHECKLIST = (
    "STIG Viewer .ckl checklists are not supported — save it as .cklb in "
    "STIG Viewer 3 and upload that"
)
# Why a file with no start tag in its first 64 KiB (see zip_extract.sniff_root)
# is not read: it is not parsed, so nothing else about it is known.
_NO_ELEMENT = "no XML element in its first 64 KiB — not read"
# Loose SCAP support files (recognised as an archive's are, see zip_extract.is_support_name
# and is_support_root) are named in one line per run: a library folder holds many.
_SUPPORT = "SCAP support file(s) (OVAL, CPE, OCIL, stylesheets) were not used: "
# A file the run's element budget has no room for (see app.utils.parse_cost).
_OVER_BUDGET = (
    "not read — the parse limit for one run was reached; any scan results or STIG references "
    "in it are missing from this report"
)
# A reference the run's reference-content budget has no room for (see app.utils.parse_cost).
_OVER_REFERENCE_BUDGET = (
    "not read — the limit on STIG reference content for one run was reached; "
    "any rules in it are missing from this report"
)
_MAX_REFUSALS_NAMED = 5     # files refused for their parse cost named per run; the rest are counted


@dataclass
class ClassifiedInputs:
    xccdf_results: list[Path] = field(default_factory=list)
    self_contained: list[Path] = field(default_factory=list)   # .cklb / .nessus results
    reference_xml: list[Path] = field(default_factory=list)
    reference_cklb: list[Path] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # The display name of every file of the run (see the module docstring),
    # bounded and escaped. Archive members are extracted under generated file
    # names, so for them this is the only name the operator knows.
    names: dict[Path, str] = field(default_factory=dict)
    # Where each routed file came in the order the operator supplied them (results
    # slot first): the lists above are split by kind and lose it.
    supply_order: dict[Path, int] = field(default_factory=dict)
    # Scan results that came in the reference slot: advice about one must not tell
    # the operator to pass it as a reference.
    results_from_references: set[Path] = field(default_factory=set)

    def name_of(self, path: Path) -> str:
        """What to call *path* in anything the operator reads."""
        return self.names.get(path) or safe_name(path.name, MAX_FILE_NAME_CHARS)


def _root_kind(path: Path) -> tuple[str, str | None]:
    """What an XML file is by its document element, and that element's local name:
    ``"results"`` (a TestResult), ``"legacy-checklist"`` (a STIG Viewer 2 ``.ckl``
    under any name), ``"support"`` (SCAP support content: not read further),
    ``"no-root"`` (no start tag in its first 64 KiB: not read at all, see
    :func:`app.utils.zip_extract.sniff_root`), ``"invalid"`` (it cannot be read),
    or ``""`` when the tags inside must tell (see :func:`_tag_kind`)."""
    try:
        with path.open("rb") as stream:
            first, exhausted = sniff_root(stream)
    except OSError:
        return "invalid", None
    if first is None and exhausted:
        return "no-root", None
    if is_support_root(first):
        return "support", first
    if first == LEGACY_CHECKLIST_ROOT:
        return "legacy-checklist", first
    if first == "TestResult":
        return "results", first
    return "", first


def _tag_kind(path: Path, root: str | None) -> str:
    """``"results"`` (it holds a TestResult), ``"benchmark"`` (a Benchmark and no
    TestResult — Manual STIG, SCAP benchmark or datastream) or ``"other"``, told
    from the start tags in its bytes, not by parsing it."""
    found = start_tags(path, ("TestResult",) if root == "Benchmark" else ("TestResult", "Benchmark"))
    if "TestResult" in found:
        return "results"
    if root == "Benchmark" or "Benchmark" in found:
        return "benchmark"
    return "other"


_MAX_SKIPS_NAMED = 5        # skipped members named per archive; the rest are counted


# A warning whose file names are rendered once every display name of the run is
# known: each part is text, or a file (a Path) to be named.
_Line = tuple["str | Path", ...]


class _Seen:
    """The files already taken, by resolved path and by content."""

    def __init__(self) -> None:
        self._paths: set[Path] = set()
        self._by_digest: dict[str, Path] = {}   # content digest -> the first file with it
        self.costs: dict[Path, ParseCost] = {}  # what parsing each file taken would cost

    def take(self, path: Path, warnings: list[_Line], identical: Counter | None = None) -> bool:
        """True when *path* is to be read; the first occurrence wins.

        The same path again is dropped silently. The same bytes under another
        path or name are dropped with one warning that names both; with
        *identical* (one archive's count of copies per first file), only the
        first _MAX_SKIPS_NAMED copies of a file get a line and the rest are
        counted there for the caller to summarise. A file that cannot be read
        is dropped with a warning too: no parser is asked to open it.
        """
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        if resolved in self._paths:
            return False
        self._paths.add(resolved)
        suffix = path.suffix.lower()
        cost = measure(path, kind="json" if suffix == ".cklb" else "" if suffix == ".zip" else "xml")
        if cost is None:
            warnings.append(("Could not read file: ", path))
            return False
        digest = cost.digest
        if digest not in self._by_digest:
            self._by_digest[digest] = path
            self.costs[path] = cost
            return True
        first = self._by_digest[digest]
        if identical is not None:
            identical[first] += 1
            if identical[first] > _MAX_SKIPS_NAMED:
                return False
        warnings.append((path, ": identical to ", first, " — read once"))
        return False


def _qualified(archive: str, path_in_archive: str) -> str:
    """``{archive}/{path inside it}``, escaped, at most MAX_FILE_NAME_CHARS long, cut from the left."""
    return clip_left(f"{archive}/{repr(path_in_archive)[1:-1]}", MAX_FILE_NAME_CHARS)


def _name_files(
    out: ClassifiedInputs, loose: list[Path], members: list[tuple[Path, ExtractedMember]],
    supplied: Mapping[Path, str],
) -> None:
    """Give every file of the run its display name (see the module docstring).

    *loose* are the files supplied, in order; *members* the archive members
    extracted, each with the loose archive it came from; *supplied* the names the
    operator gave loose files saved under another name. Linear in the number
    of files: names are counted once, and the number tried after a repeated
    name only ever goes up.
    """
    used: set[str] = set()
    next_number: dict[str, int] = {}

    def distinct(name: str) -> str:
        if name in used:
            number = next_number.get(name, 2)
            while f"{name} ({number})" in used:
                number += 1
            next_number[name] = number + 1
            name = f"{name} ({number})"
        used.add(name)
        return name

    loose = list(dict.fromkeys(loose))
    base = {path: safe_name(supplied.get(path) or path.name, MAX_FILE_NAME_CHARS) for path in loose}
    for path in loose:
        out.names[path] = distinct(base[path])
    shared = Counter(base.values()) + Counter(member.name for _, member in members)
    for archive, member in members:
        if shared[member.name] > 1:
            out.names[member.path] = distinct(_qualified(out.names[archive], member.path_in_archive))
        else:
            out.names[member.path] = distinct(member.name)


def _route(walk: _Classification, path: Path, *, as_reference: bool, from_zip: bool) -> str:
    """File *path* under the list it belongs to.

    Returns ``"routed"``; ``"legacy-checklist"`` for a STIG Viewer ``.ckl``
    (named as unsupported here, never handed to a parser); ``"no-root"`` for
    a file with no XML element near its start (named here when it is loose,
    never parsed); ``"support"`` for SCAP support content (OVAL, CPE, OCIL, a
    stylesheet), recognised as an archive's member is and never handed to a
    parser; ``"refused"`` for a file that would cost too much to parse (named
    here, never parsed); or ``"unrecognised"`` for a ZIP member that is XML
    but neither scan results nor a benchmark. The caller names loose support
    files once per run, and the ZIP members of the last two kinds once per archive.
    """
    out, warnings = walk.out, walk.lines
    suffix = path.suffix.lower()
    kind = "legacy-checklist" if suffix == LEGACY_CHECKLIST_SUFFIX else ""
    root: str | None = None
    if suffix == ".xml" and is_support_name(path.name):
        kind = "support"        # by its name, as in an archive: not read at all
    elif suffix not in (".cklb", ".nessus", LEGACY_CHECKLIST_SUFFIX):
        kind, root = _root_kind(path)
    if kind == "support":
        return kind
    if kind == "legacy-checklist":
        warnings.append((path, f": {_LEGACY_CHECKLIST}"))
        return kind
    if kind == "no-root":
        # Never handed to a parser, which would read all of it. An archive's
        # members are named together by the caller.
        if not from_zip:
            warnings.append((path, f": {_NO_ELEMENT}"))
        return kind
    if not walk.affordable(path):
        return "refused"
    if not kind and suffix not in (".cklb", ".nessus"):
        kind = _tag_kind(path, root)
    if from_zip and kind == "other":
        return "unrecognised"
    if suffix == ".cklb":
        # A checklist is both; the slot says which the operator meant.
        target = out.reference_cklb if as_reference else out.self_contained
    elif suffix == ".nessus":
        target = out.self_contained
    elif kind == "results":
        target = out.xccdf_results
    elif kind == "benchmark":
        target = out.reference_xml
    else:
        # Unrecognised or unreadable: it keeps its slot and that parser explains it.
        target = out.reference_xml if as_reference else out.xccdf_results
    if not walk.charge(path, reference=target is out.reference_xml or target is out.reference_cklb):
        return "refused"
    target.append(path)
    if as_reference and target is out.xccdf_results:
        out.results_from_references.add(path)
    out.supply_order.setdefault(path, len(out.supply_order))
    return "routed"


@dataclass
class _Classification:
    """One classify_inputs call: what it has taken, extracted and said so far."""
    out: ClassifiedInputs
    extract_dir: Path
    cancel_check: Callable[[], None] | None
    # The name the operator gave each loose file saved under another (display_file_name'd).
    supplied: dict[Path, str] = field(default_factory=dict)
    seen: _Seen = field(default_factory=_Seen)
    # Warnings are written as the files are walked and rendered at the end: a
    # name is unique in the run only once every file of the run is known.
    lines: list[_Line] = field(default_factory=list)
    loose: list[Path] = field(default_factory=list)
    members: list[tuple[Path, ExtractedMember]] = field(default_factory=list)
    run: Budget = field(default_factory=run_budget)     # what all the archives of this call may extract together
    support: list[Path] = field(default_factory=list)   # loose SCAP support files, named once at the end
    # What the files routed so far may still hold (see app.utils.parse_cost); once a
    # file does not fit, no later file is read either.
    elements: int = field(default_factory=run_element_budget)
    over_budget: int = 0        # files refused for the run's element budget
    too_costly: int = 0         # files refused for their own parse cost
    # The bytes of STIG reference files the run may still read; once one does not fit,
    # no later reference is read either.
    reference_bytes: int = field(default_factory=run_reference_budget)
    over_reference_budget: int = 0

    def poll(self) -> None:
        if self.cancel_check is not None:
            self.cancel_check()

    def affordable(self, path: Path) -> bool:
        """False, and *path* named (the first few), when parsing it alone would cost too much."""
        cost = self.seen.costs.get(path)
        why = too_costly(cost) if cost is not None else ""
        if not why:
            return True
        self.too_costly += 1
        if self.too_costly <= _MAX_REFUSALS_NAMED:
            self.lines.append((path, f": {why}"))
        return False

    def charge(self, path: Path, *, reference: bool) -> bool:
        """Take what parsing *path* costs from the run's budgets (a *reference* also from
        the reference-content one); False, and *path* named (the first few), when a
        budget has no room for it."""
        cost = self.seen.costs.get(path)
        needed = cost.elements if cost is not None else 0
        size = cost.size if cost is not None else 0
        if self.over_budget or needed > self.elements:
            self.over_budget += 1
            if self.over_budget <= _MAX_REFUSALS_NAMED:
                self.lines.append((path, f": {_OVER_BUDGET}"))
            return False
        if reference and (self.over_reference_budget or size > self.reference_bytes):
            self.over_reference_budget += 1
            if self.over_reference_budget <= _MAX_REFUSALS_NAMED:
                self.lines.append((path, f": {_OVER_REFERENCE_BUDGET}"))
            return False
        self.elements -= needed
        if reference:
            self.reference_bytes -= size
        return True

    def refusals_left_unnamed(self) -> list[_Line]:
        """One line each for the files refused for their parse cost past those named."""
        lines: list[_Line] = []
        if self.too_costly > _MAX_REFUSALS_NAMED:
            lines.append((
                f"… and {self.too_costly - _MAX_REFUSALS_NAMED} more file(s) too costly to parse safely — not read",
            ))
        if self.over_reference_budget > _MAX_REFUSALS_NAMED:
            lines.append((
                f"… and {self.over_reference_budget - _MAX_REFUSALS_NAMED} more STIG reference file(s) not read — "
                "the limit on STIG reference content for one run was reached",
            ))
        if self.over_budget > _MAX_REFUSALS_NAMED:
            lines.append((
                f"… and {self.over_budget - _MAX_REFUSALS_NAMED} more file(s) not read — the parse limit for one "
                "run was reached; any scan results or STIG references among them are missing from this report",
            ))
        return lines


def _listing(head: list[str | Path], named: list[Path]) -> _Line:
    """*head*, then at most five of *named*, comma-separated, and " …" when there are more."""
    line = list(head)
    for i, path in enumerate(named[:_MAX_SKIPS_NAMED]):
        line += [", ", path] if i else [path]
    if len(named) > _MAX_SKIPS_NAMED:
        line.append(" …")
    return tuple(line)


def _name_members(walk: _Classification, archive: Path, what: str, named: list[Path]) -> None:
    """One line naming at most five of an archive's *named* members, and how many there are."""
    if named:
        walk.lines.append(_listing([archive, f": {len(named)} {what}: "], named))


def _take_archive(walk: _Classification, path: Path, *, as_reference: bool) -> None:
    """Extract the ZIP *path* and route each member as the same file loose in its slot."""
    lines = walk.lines
    if walk.run.spent:
        lines.append((path, ": not read — the limit for one run was reached"))
        return
    archive = extract_from_zip(
        path, walk.extract_dir, name=safe_name(walk.supplied.get(path) or path.name, MAX_FILE_NAME_CHARS),
        run=walk.run,
        cancel_check=walk.cancel_check,
    )
    if archive.unreadable:
        lines.append((path, f": {archive.unreadable}"))
        return
    said = len(lines)
    lines.extend((path, f": {skip}") for skip in archive.skipped[:_MAX_SKIPS_NAMED])
    # The extraction lists only so many of a flood of too-deep ZIPs and counts the rest.
    unnamed = max(0, len(archive.skipped) - _MAX_SKIPS_NAMED) + archive.skipped_more
    if unnamed:
        lines.append((path, f": … and {unnamed} more skipped"))
    if archive.limit:
        lines.append((
            path, f": {archive.limit} limit reached — {archive.not_read} more file(s) not checked; "
            "any scan results or STIG references among them are missing from this report",
        ))
    used = 0
    unrecognised: list[Path] = []
    no_element: list[Path] = []
    identical: Counter = Counter()      # copies of each first file among the members
    for member in archive.members:
        walk.poll()
        walk.members.append((path, member))
        if not walk.seen.take(member.path, lines, identical):
            used += 1       # already taken from elsewhere (and said so): the ZIP was not empty
            continue
        routed = _route(walk, member.path, as_reference=as_reference, from_zip=True)
        if routed in ("routed", "refused"):     # a refused member was named
            used += 1
        elif routed == "unrecognised":
            unrecognised.append(member.path)
        elif routed == "no-root":
            no_element.append(member.path)
    lines.extend(
        (path, f": … and {copies - _MAX_SKIPS_NAMED} more identical to ", first, " — read once")
        for first, copies in identical.items() if copies > _MAX_SKIPS_NAMED
    )
    lines.extend((f"{legacy}: {_LEGACY_CHECKLIST}",) for legacy in archive.legacy_checklists[:_MAX_SKIPS_NAMED])
    if len(archive.legacy_checklists) > _MAX_SKIPS_NAMED:
        lines.append((
            path, f": … and {len(archive.legacy_checklists) - _MAX_SKIPS_NAMED} more "
            ".ckl checklist(s) not supported",
        ))
    # Known ancillary kinds (OVAL, CPE, OCIL, stylesheets) are never in either list.
    _name_members(walk, path, "XML file(s) were not recognised as scan results or STIG references", unrecognised)
    _name_members(walk, path, "file(s) have no XML element in their first 64 KiB — not read", no_element)
    if archive.other_archives:
        shown = ", ".join(archive.other_archives[:_MAX_SKIPS_NAMED])
        shown += " …" if len(archive.other_archives) > _MAX_SKIPS_NAMED else ""
        lines.append((
            path, f": {len(archive.other_archives)} archive(s) inside were not read "
            f"(only ZIP is supported): {shown}",
        ))
    if not used and len(lines) == said:
        lines.append((
            "No scan results or STIG references found in ", path,
            " (expected XCCDF results, a benchmark *xccdf.xml or *_Benchmark.xml, "
            ".cklb or .nessus files inside the zip)",
        ))


def classify_inputs(
    results_paths: list[Path],
    reference_paths: list[Path],
    extract_dir: Path,
    *,
    cancel_check: Callable[[], None] | None = None,
    display_names: Mapping[Path, str] | None = None,
) -> ClassifiedInputs:
    """Route every supplied file and archive member (see the module docstring).

    *cancel_check*, when given, is called before each file and each archive
    member; it may raise to stop. *display_names* maps a supplied path to the
    name the operator gave it when the file was saved under another (the web
    UI saves uploads under safe names); that name, through
    :func:`display_file_name`, is the one every warning and source shows.
    """
    supplied = {path: shown for path, name in (display_names or {}).items() if (shown := display_file_name(name))}
    walk = _Classification(ClassifiedInputs(), extract_dir, cancel_check, supplied)
    # Results slot first: of two copies of a file, the one given as results is kept.
    for as_reference, paths in ((False, results_paths), (True, reference_paths)):
        for path in paths:
            walk.poll()
            walk.loose.append(path)
            if not walk.seen.take(path, walk.lines):
                continue
            if path.suffix.lower() == ".zip":
                _take_archive(walk, path, as_reference=as_reference)
            elif _route(walk, path, as_reference=as_reference, from_zip=False) == "support":
                walk.support.append(path)
    walk.lines.extend(walk.refusals_left_unnamed())
    if walk.support:
        # Never a source file: one line for the run, however many a library folder holds.
        walk.lines.append(_listing([f"{len(walk.support)} {_SUPPORT}"], walk.support))
    out = walk.out
    _name_files(out, walk.loose, walk.members, walk.supplied)
    out.warnings = ["".join(out.name_of(p) if isinstance(p, Path) else p for p in line) for line in walk.lines]
    return out
