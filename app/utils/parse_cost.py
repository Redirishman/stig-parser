"""What parsing an upload would cost, read from its raw bytes before any parser sees it.

A hardened parse still builds every node of the document: flat XML or JSON
costs about thirty times its size in memory, and libxml2 checks the attributes
of one element against each other, so an element with very many attributes
costs time that grows with the square of their number. The archive budgets
bound how many bytes are extracted, not what parsing them costs, so every file
is measured here, in the same streaming pass that hashes it, and refused before
it is parsed when it would cost too much.

- XML: every ``<`` that does not open an end tag (elements, and the comments,
  CDATA sections, processing instructions and DOCTYPE the parser also builds or
  reads; a ``<`` inside a comment counts too), plus every ``=`` (each attribute has one, so
  attributes are charged too; one in text is over-counted, never under); and
  whether any start tag holds more than ``MAX_TAG_ATTRIBUTES`` attributes,
  counted as libxml2 reads them: name, ``=``, then a quoted value, which may
  hold ``>`` but not ``<``.
- JSON (a ``.cklb`` checklist): object and array starts and commas, a bound on
  the number of values.

The caps are module constants read at call time (tests lower them).
"""
from __future__ import annotations

import hashlib
import mmap
import re
from dataclasses import dataclass
from pathlib import Path

# Elements and attributes (XML) or values (JSON) one file may hold. Real
# content holds one of them per 40-95 bytes (the fixtures: 37-67; a DISA
# Manual STIG: 56 whole, 93 in its rules), so 200 MB of it stays under the
# cap: 200 MB of Manual-STIG rules counts about 2.3 million and peaked near
# 0.6 GB through parse_stage. Measured worst cases at the cap, one parse:
# about 0.5 GB for flat elements, about 1 GB for elements with many attributes.
MAX_FILE_ELEMENTS = 4_000_000
# Elements and values all the files of one run may hold together: about the
# 8 GiB the archives of one run may extract, at 80 bytes per element. Files
# are parsed one at a time, so this bounds the run's parse time, not its memory.
MAX_RUN_ELEMENTS = 100_000_000
# Attributes (``=`` signs) one XML start tag may hold. Real STIG, SCAP and
# Nessus content stays under 30 (a datastream's root, with its namespace
# declarations, holds the most).
MAX_TAG_ATTRIBUTES = 64
# Bytes of STIG reference files (benchmarks and checklists supplied as references)
# one run may read. Their rules are held for the whole run, so they get a budget of
# their own, well under the 8 GiB the archives of one run may extract.
MAX_RUN_REFERENCE_BYTES = 2 * 1024 * 1024 * 1024

_CHUNK = 1024 * 1024


@dataclass(frozen=True)
class ParseCost:
    """One file: its SHA-256 and what parsing it would cost."""
    digest: str
    elements: int = 0           # XML element starts, or JSON values (see the module docstring)
    crowded_tag: bool = False   # an XML start tag with more than MAX_TAG_ATTRIBUTES attributes
    size: int = 0               # bytes


def _crowded(limit: int) -> re.Pattern[bytes]:
    """A start tag followed by more than *limit* attributes, each read as libxml2 reads
    one: whitespace, a name, ``=`` (whitespace allowed around it), then a value in
    double or single quotes. A value may hold ``>``; one holding ``<`` is an error at
    which libxml2 stops, so the count stops there too. Every quantifier is possessive
    and no two can take the same byte, so a match attempt never backtracks: it reads
    one tag, at most *limit* + 1 attributes of it, and attempts cannot overlap past
    the next ``<``."""
    attribute = rb"""\s++[^\s=/>"'<]++\s*+=\s*+(?:"[^"<]*+"|'[^'<]*+')"""
    return re.compile(rb"<[A-Za-z_:\x80-\xff][^\s/>\"'<=]*+(?:" + attribute + rb"){%d}" % (limit + 1))


def _crowded_tag(path: Path) -> bool:
    """Whether any start tag of *path* holds more than MAX_TAG_ATTRIBUTES attributes.
    Searched over the file mapped into memory, so no tag is ever split between reads."""
    with path.open("rb") as stream:
        if not stream.seek(0, 2):
            return False
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
            return _crowded(MAX_TAG_ATTRIBUTES).search(mapped) is not None


def _nodes(chunk: bytes, before: bytes) -> int:
    """'<' that open no end tag, and '=' signs, in *chunk*; *before* is the byte that
    precedes it, so a two-byte '</' split between two chunks is seen once."""
    return chunk.count(b"<") + chunk.count(b"=") - (before + chunk).count(b"</")


def measure(path: Path, *, kind: str) -> ParseCost | None:
    """Hash *path* and count what parsing it would build, in one pass; None when it
    cannot be read. *kind* says how it would be parsed: ``"xml"``, ``"json"`` (a
    checklist), or ``""`` (not parsed: hashed only)."""
    digest = hashlib.sha256()
    elements = 0
    before = b""
    size = 0
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(_CHUNK):
                digest.update(chunk)
                size += len(chunk)
                if kind == "json":
                    elements += chunk.count(b"{") + chunk.count(b"[") + chunk.count(b",")
                elif kind == "xml":
                    elements += _nodes(chunk, before)
                    before = chunk[-1:]
        # A file already over the element cap is refused for that: no need to look further.
        crowded = kind == "xml" and elements <= MAX_FILE_ELEMENTS and _crowded_tag(path)
    except (OSError, ValueError):
        return None
    return ParseCost(digest.hexdigest(), elements, crowded, size)


def too_costly(cost: ParseCost) -> str:
    """Why *cost* is too much for one file, as the operator's warning says it after
    the file name; "" when it is within the caps."""
    if cost.elements > MAX_FILE_ELEMENTS:
        return "too many elements to parse safely — not read"
    if cost.crowded_tag:
        return "an element has too many attributes to parse safely — not read"
    return ""


def run_element_budget() -> int:
    """What all the files of one run may hold together (see MAX_RUN_ELEMENTS)."""
    return MAX_RUN_ELEMENTS


def run_reference_budget() -> int:
    """The bytes of STIG reference files one run may read (see MAX_RUN_REFERENCE_BYTES)."""
    return MAX_RUN_REFERENCE_BYTES


# What ends each construct start_tags steps over: nothing inside one is a tag.
_SKIPPED = {b"!--": b"-->", b"![CDATA[": b"]]>", b"?": b"?>"}


def _doctype_end(mapped: mmap.mmap, start: int) -> int:
    """Where a DOCTYPE that starts before *start* ends ('>' after its internal subset,
    when it has one); -1 when it does not."""
    bracket = re.compile(rb"[\[>]").search(mapped, start)
    if bracket is None:
        return -1
    if bracket.group() == b">":
        return bracket.end()
    close = re.compile(rb"\]\s*+>").search(mapped, bracket.end())
    return -1 if close is None else close.end()


def _opener(names: set[str]) -> re.Pattern[bytes]:
    """A comment, CDATA section, processing instruction or DOCTYPE opening (group 1), or
    a start tag of one of *names* under a namespace prefix of any length (group 2).
    The file is searched whole, so no read window bounds a prefix; the prefix is
    possessive, so an attempt reads one name, stops at the first byte that cannot be
    part of it, and never overlaps the next attempt ('<' is no name character)."""
    alternatives = b"|".join(re.escape(name.encode()) for name in sorted(names))
    return re.compile(rb"<(?:(!--|!\[CDATA\[|\?|!DOCTYPE)|(?:[A-Za-z_\x80-\xff][\w.\-\x80-\xff]*+:)?("
                      + alternatives + rb")[\s/>])")


def start_tags(path: Path, names: tuple[str, ...]) -> set[str]:
    """Which of *names* occur as an element's start tag (any namespace prefix) in
    *path*: what an XML file is, told without parsing it. A name inside a comment,
    a CDATA section, a processing instruction or a DOCTYPE is not a tag, and is
    stepped over. The file is mapped into memory, so nothing is split between
    reads; reading stops once every name is found, or at a construct never closed
    (the rest of the file is inside it)."""
    found: set[str] = set()
    try:
        with path.open("rb") as stream:
            if not stream.seek(0, 2):
                return found
            with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                left = set(names)
                pattern = _opener(left)
                position = 0
                while left and (match := pattern.search(mapped, position)) is not None:
                    opener = match.group(1)
                    if opener is None:
                        name = match.group(2).decode()
                        found.add(name)
                        left.discard(name)
                        if left:
                            pattern = _opener(left)
                        position = match.end()
                        continue
                    if opener == b"!DOCTYPE":
                        position = _doctype_end(mapped, match.end())
                    else:
                        close = _SKIPPED[opener]
                        at = mapped.find(close, match.end())
                        position = -1 if at < 0 else at + len(close)
                    if position < 0:
                        break
    except (OSError, ValueError):
        pass
    return found
