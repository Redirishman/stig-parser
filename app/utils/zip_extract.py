"""Extract scan results and STIG reference files from uploaded ZIPs.

DISA distributes STIGs as ZIP files (e.g. U_MS_Windows_Server_2022_V2R8_STIG.zip)
containing a folder with the XCCDF benchmark XML, supplementary docs, and
sometimes nested ZIPs (the "wrapper" pattern). Operators zip a folder of scan
results the same way. This module unwraps both: a ZIP is a folder, and what
each member is gets decided by the caller exactly as for a loose file.

An archive is an untrusted upload. Nothing in it can make extraction raise:
a member that cannot be read is skipped and named, and the rest are read.
"""
from __future__ import annotations

import contextlib
import errno
import logging
import os
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Callable

from lxml import etree

from app.limits import MAX_UPLOAD_BYTES
from app.reference.normalize import MAX_FILE_NAME_CHARS, error_text, safe_name, shown_file_name

log = logging.getLogger(__name__)

# Archive members that can be scan results or a STIG reference (case-insensitive
# suffixes). Everything else (PDF, XSL, images, text) is never extracted.
_MEMBER_SUFFIXES = (".xml", ".cklb", ".nessus")
# XML members that are neither, recognised without reading them: by the names
# DISA gives the parts of a SCAP bundle ...
_ANCILLARY_XML_SUFFIXES = ("-oval.xml", "-cpe-dictionary.xml", "-ocil.xml")
# ... and, for the same content under any other name, by the document element.
_ANCILLARY_XML_ROOTS = frozenset({
    "oval_definitions", "oval_results", "oval_system_characteristics", "oval_variables",
    "cpe-list", "ocil", "stylesheet", "transform",
})


def is_support_name(name: str) -> bool:
    """True for a file named as a part of a DISA SCAP bundle that is neither results nor a
    benchmark (OVAL, CPE dictionary, OCIL). Decided without reading the file."""
    return name.lower().endswith(_ANCILLARY_XML_SUFFIXES)


def is_support_root(root: str | None) -> bool:
    """True for the document element (local name) of SCAP support content: OVAL, a CPE
    dictionary, OCIL, or a stylesheet."""
    return root in _ANCILLARY_XML_ROOTS


# A STIG Viewer 2 checklist: XML, but not a format this tool reads. Recognised
# by suffix or by document element, named to the operator, never extracted.
LEGACY_CHECKLIST_SUFFIX = ".ckl"
LEGACY_CHECKLIST_ROOT = "CHECKLIST"

# Archives of another format (".tar.gz" ends in ".gz"): never opened, named to
# the operator, because only ZIP is read.
_OTHER_ARCHIVE_SUFFIXES = (".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz")

# Decompressed-size cap per archive member and nested-ZIP recursion limit.
# Without these, a crafted ZIP (high compression ratio, or self-nesting)
# exhausts disk/stack — a classic zip bomb DoS on untrusted uploads. A member
# may be no larger than the same file uploaded loose: a few KB of ZIP must not
# buy a file the upload limit would have refused.
_MAX_EXTRACTED_BYTES = MAX_UPLOAD_BYTES
_MAX_ZIP_DEPTH = 2
_CHUNK = 65536
# ZIPs nested too deep are never opened, so no budget limits how many one
# archive names: each is logged and listed up to this many, then only counted.
_MAX_TOO_DEEP_LISTED = 5
# What one archive the operator supplied may extract in all, nested ZIPs
# included: members opened (sniffed or written), and bytes decompressed
# (counted as they stream, kept or not). Each member costs a file write and a parse, so a ZIP of many
# tiny members is as much a denial of service as one huge member.
_MAX_MEMBERS = 5000
_MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
# ... and what all the archives of one run may extract together (see run_budget).
_MAX_RUN_MEMBERS = 20000
_MAX_RUN_BYTES = 8 * 1024 * 1024 * 1024
# How much of an XML member is read to find its document element. Whitespace,
# comments or processing instructions before it cost almost nothing compressed:
# 400 MB of padding fits in under 1 MB of ZIP.
_SNIFF_BYTES = 64 * 1024

# Entries an archive may hold. The ZIP reader builds an object for every
# entry before any other limit applies (200,000 entries, a 20 MB ZIP, took
# 4.6 s and 120 MB), whatever count the end record gives: it walks the
# central directory by its size. So the reader reads through _GuardedFile,
# which sees exactly what it reads, wherever this Python's reader looks for
# the end record and places the directory: the directory's size is capped
# (160 bytes an entry, room for ordinary names) and its records are counted
# by their signature as they are read.
_MAX_ENTRIES = 100_000
_DIRECTORY_BYTES_PER_ENTRY = 160
_CENTRAL_RECORD = b"PK\x01\x02"
# What the reader reads besides the directory, to find it: the end record, a
# comment's 64 KiB, a ZIP64 locator and record: 65,711 bytes at most.
_END_RECORD_READS = 128 * 1024

# Opening an archive or reading one of its members can raise almost anything
# on a hostile or damaged upload: a file system error, an encrypted member, a
# bad CRC or header, a damaged deflate, LZMA or Zstandard stream, a ZIP version
# or compression method this Python lacks, a name that is not the UTF-8 it
# claims to be. Both boundaries catch Exception (never BaseException) and name
# the archive or member instead.

NOT_A_ZIP = "not a readable ZIP — not read"
PASSWORD_PROTECTED = "password-protected — not read"


def _too_many_entries() -> str:
    """Why an archive whose entry list holds more than _MAX_ENTRIES entries is not read."""
    return f"more than {_MAX_ENTRIES:,} entries — not read"


def _max_directory_bytes() -> int:
    return _MAX_ENTRIES * _DIRECTORY_BYTES_PER_ENTRY


def _directory_too_large() -> str:
    """Why an archive whose central directory is larger than _max_directory_bytes() is not read."""
    return f"entry list over {_max_directory_bytes():,} bytes — not read"


class _DirectoryRefused(zipfile.BadZipFile):
    """Raised through the ZIP reader by _GuardedFile: *line* says why the archive is not read."""

    def __init__(self, line: str) -> None:
        super().__init__(line)
        self.line = line


class _GuardedFile:
    """An archive file as the ZIP reader reads it to build its entry list.

    Each read the reader asks for is checked before the reader sees its bytes:
    one larger than _max_directory_bytes() (the reader reads the directory in
    one) that is not an end record read, or reads totalling more than that and
    _END_RECORD_READS, refuse the archive; so do more than _MAX_ENTRIES
    directory record signatures across the reads, each counted once by where
    it is in the file (the reader may read some bytes twice). Once the reader
    is built, ``armed`` is set false and member reads pass straight through.
    """

    def __init__(self, raw: IO[bytes]) -> None:
        self._raw = raw
        self._bytes_left = _max_directory_bytes() + _END_RECORD_READS
        self._records: set[int] = set()                # where each signature seen starts
        self._edge: tuple[int, bytes] | None = None     # where the last read ended, and its last bytes
        self.armed = True

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        return self._raw.seek(offset, whence)

    def tell(self) -> int:
        return self._raw.tell()

    def seekable(self) -> bool:
        return True

    def read(self, size: int | None = -1) -> bytes:
        if not self.armed:
            return self._raw.read(size)
        start = self._raw.tell()
        end = self._raw.seek(0, os.SEEK_END)
        self._raw.seek(start)
        left_in_file = max(0, end - start)              # what the read can return: its size is a ceiling
        size = left_in_file if size is None or size < 0 else min(size, left_in_file)
        # A read reaching the end of the file looks for the end record: the
        # directory never does, the end record follows it. Only the total
        # bounds those reads.
        end_record_read = start + size == end and size <= _END_RECORD_READS
        if size > self._bytes_left or (size > _max_directory_bytes() and not end_record_read):
            raise _DirectoryRefused(_directory_too_large())
        data = self._raw.read(size)
        self._bytes_left -= len(data)
        self._count(start, data)
        return data

    def _count(self, start: int, data: bytes) -> None:
        width = len(_CENTRAL_RECORD) - 1
        before = self._edge[1] if self._edge is not None and self._edge[0] == start else b""
        if before:
            # This read goes on from the last one: a signature may span the two.
            self._add(before + data[:width], start - len(before))
        self._add(data, start)
        self._edge = (start + len(data), (before + data[-width:])[-width:])

    def _add(self, data: bytes, start: int) -> None:
        at = data.find(_CENTRAL_RECORD)
        while at >= 0:
            self._records.add(start + at)
            if len(self._records) > _MAX_ENTRIES:
                raise _DirectoryRefused(_too_many_entries())
            at = data.find(_CENTRAL_RECORD, at + 1)


@dataclass
class ExtractedMember:
    """One archive member on disk."""
    path: Path      # where it was extracted, under a file name generated here
    name: str       # its base name in the archive, bounded and escaped: for display only
    # Its path inside the archive the operator supplied, through any nested ZIP, with
    # "/" separators; raw (not escaped), and only the last MAX_FILE_NAME_CHARS + 1
    # characters: a display name cut from the left never shows more.
    path_in_archive: str = ""


@dataclass
class Extraction:
    """What one archive gave."""
    members: list[ExtractedMember] = field(default_factory=list)
    # One line per member that was skipped, and why (the caller says which archive):
    # unreadable, over the size cap, a ZIP nested too deep or not readable itself.
    skipped: list[str] = field(default_factory=list)
    # Members skipped and not in ``skipped``: ZIPs nested too deep past the first
    # _MAX_TOO_DEEP_LISTED of an archive, nested archives included.
    skipped_more: int = 0
    # ZIPs nested too deep found in this archive itself (listed or counted).
    too_deep: int = 0
    # Why the archive as a whole was not read: NOT_A_ZIP, PASSWORD_PROTECTED, or "".
    unreadable: str = ""
    # Display names of the legacy STIG Viewer .ckl checklists found (not extracted).
    legacy_checklists: list[str] = field(default_factory=list)
    # Display names of the archives of another format found (not opened).
    other_archives: list[str] = field(default_factory=list)
    # The limit that stopped extraction early ("member" or "size"; "" when none
    # did), and how many files it left unread here and in any nested archive.
    limit: str = ""
    not_read: int = 0


@dataclass
class Budget:
    """What may still be extracted: members opened (sniffed or written), and bytes
    decompressed (sniffed or extracted, kept or not). One per archive the operator supplied, nested ZIPs
    included, and one per run (see :func:`run_budget`)."""
    members: int
    bytes: int

    @property
    def spent(self) -> bool:
        return self.members <= 0 or self.bytes <= 0


def run_budget() -> Budget:
    """The budget every archive of one run shares: pass it to each :func:`extract_from_zip` call."""
    return Budget(_MAX_RUN_MEMBERS, _MAX_RUN_BYTES)


class _Charged:
    """A member's decompressed stream, read for the sniff: at most *limit* bytes,
    each one taken from every budget in *budgets*. After that it reads as ended."""

    def __init__(self, stream: IO[bytes], budgets: tuple[Budget, ...], limit: int) -> None:
        self._stream, self._budgets, self._left = stream, budgets, limit
        self.read_bytes = 0     # how many were read, and charged

    @property
    def exhausted(self) -> bool:
        """True once the limit was read: nothing more will be."""
        return self._left <= 0

    def read(self, size: int = -1) -> bytes:
        if self._left <= 0:
            return b""
        size = self._left if size is None or size < 0 else min(size, self._left)
        data = self._stream.read(size)
        self._left -= len(data)
        self.read_bytes += len(data)
        for budget in self._budgets:
            budget.bytes -= len(data)
        return data


def _unread(infos: list[zipfile.ZipInfo]) -> int:
    """How many of *infos* the walk would have read or named: what a stop leaves unread."""
    counted = (*_MEMBER_SUFFIXES, ".zip", LEGACY_CHECKLIST_SUFFIX, *_OTHER_ARCHIVE_SUFFIXES)
    count = 0
    for info in infos:
        lower = _base_name(info.filename).lower()
        if not info.is_dir() and lower.endswith(counted) and not is_support_name(lower):
            count += 1
    return count


def _size_limit(limit: int) -> str:
    """The size cap as the operator reads it: ``200 MB``, or ``2048-byte`` for a small one."""
    megabyte = 1024 * 1024
    return f"{limit // megabyte} MB" if limit >= megabyte else f"{limit}-byte"


def _bounded_extract(
    zf: zipfile.ZipFile, info: zipfile.ZipInfo, target: Path, budgets: tuple[Budget, ...], charged: int = 0
) -> str:
    """Stream one archive member to *target*, aborting past any size cap.

    Returns ``"ok"``; ``"member"`` when the member is over the per-member cap,
    or ``"archive"`` when a byte budget ran out (the partial file is removed
    either way). Sizes are measured as data is decompressed, never taken from
    the archive's declared sizes, and every byte decompressed is taken from
    each of *budgets*, kept or not, once: the first *charged* bytes were
    already taken by the sniff that read them.
    """
    written = 0
    with zf.open(info) as src, target.open("wb") as dst:
        while True:
            chunk = src.read(_CHUNK)
            if not chunk:
                break
            fresh = max(0, written + len(chunk) - max(written, charged))
            written += len(chunk)
            for budget in budgets:
                budget.bytes -= fresh
            overspent = any(budget.bytes < 0 for budget in budgets)
            if overspent or written > _MAX_EXTRACTED_BYTES:
                dst.close()
                target.unlink(missing_ok=True)
                if overspent:
                    return "archive"
                return "member"
            dst.write(chunk)
    return "ok"


def _generated_path(dest_dir: Path, suffix: str) -> Path:
    """A new, empty file in *dest_dir* whose name comes from here, not from the archive.

    A member name is whatever the archive's author typed: a colon, 300
    characters, ``CON``, a trailing dot. None of it may reach the file system.
    *suffix* is one of this module's own suffix constants.
    """
    handle, name = tempfile.mkstemp(prefix="member_", suffix=suffix, dir=dest_dir)
    os.close(handle)
    return Path(name)


def _base_name(member_name: str) -> str:
    """The last path component of an archive member name, whichever slash it uses."""
    return member_name.replace("\\", "/").rpartition("/")[2]


def _root_name(stream: IO[bytes] | _Charged) -> str | None:
    """Local name of an XML document's root element; None when it has none.

    Reads up to the first start tag and stops, so the cost does not grow with
    the size of the document. Entities are not resolved, nothing is fetched,
    no DTD is loaded, and libxml2's limits stay on.
    """
    try:
        for _event, element in etree.iterparse(
            stream, events=("start",), resolve_entities=False, no_network=True, load_dtd=False,
        ):
            tag = element.tag
            return tag.rpartition("}")[2] if isinstance(tag, str) else None
    except etree.XMLSyntaxError:
        return None
    return None


def sniff_root(stream: IO[bytes], budgets: tuple[Budget, ...] = ()) -> tuple[str | None, bool]:
    """The local name of a document's element, read from at most ``_SNIFF_BYTES``
    of *stream* (each byte taken from *budgets*), and whether that limit was reached.

    ``(None, True)``: no start tag in the first ``_SNIFF_BYTES``, and nothing more
    is read. Whitespace, comments or processing instructions before the document
    element cost almost nothing compressed and a great deal to parse; no scan or
    STIG starts so. ``(None, False)``: the document ended, or was not well-formed,
    before its first start tag.
    """
    reader = _Charged(stream, budgets, _SNIFF_BYTES)
    return _root_name(reader), reader.exhausted


def _member_kind(
    zf: zipfile.ZipFile, info: zipfile.ZipInfo, lower_name: str, budgets: tuple[Budget, ...]
) -> tuple[str, int]:
    """``"ancillary"``, ``"legacy-checklist"`` or ``"candidate"`` for an XML member,
    and how many of its bytes were read (and charged) to tell.

    Ancillary is XML known to be neither results nor a benchmark (OVAL
    definitions, a CPE dictionary, OCIL, a stylesheet). A 20 MB OVAL file must
    not be extracted and parsed just to learn that: the name decides when it
    can (the caller checks it before opening the member), otherwise the first
    start tag read straight from the archive by :func:`sniff_root`, charged to
    *budgets*. Any other member is a candidate: it is extracted (and charged in
    full) and classified like a loose file, which names one with no start tag
    near its start for that, without parsing it.
    """
    if is_support_name(lower_name):
        return "ancillary", 0
    with zf.open(info) as stream:
        reader = _Charged(stream, budgets, _SNIFF_BYTES)
        root = _root_name(reader)
    if is_support_root(root):
        return "ancillary", reader.read_bytes
    return ("legacy-checklist" if root == LEGACY_CHECKLIST_ROOT else "candidate"), reader.read_bytes


def _name_kind(lower_name: str, depth: int) -> str:
    """What a member is by its name alone: ``"legacy-checklist"``, ``"other-archive"``,
    ``"ignored"`` (nothing this tool reads, or known ancillary SCAP content),
    ``"too-deep"`` (a ZIP past the nesting limit), or the suffix it is read by."""
    if lower_name.endswith(LEGACY_CHECKLIST_SUFFIX):
        return "legacy-checklist"
    if lower_name.endswith(_OTHER_ARCHIVE_SUFFIXES):
        return "other-archive"
    suffix = next((s for s in (*_MEMBER_SUFFIXES, ".zip") if lower_name.endswith(s)), "")
    if not suffix:
        return "ignored"
    if suffix == ".zip" and depth >= _MAX_ZIP_DEPTH:
        return "too-deep"
    if suffix == ".xml" and is_support_name(lower_name):
        return "ignored"        # known ancillary SCAP content, by name: never opened
    return suffix


@dataclass
class _Walk:
    """One archive the operator supplied, walked through its nested ZIPs."""
    dest_dir: Path
    budget: Budget                         # the archive's own, nested ZIPs included
    run: Budget | None                     # the run's, when one was given
    cancel_check: Callable[[], None] | None

    @property
    def budgets(self) -> tuple[Budget, ...]:
        return (self.budget, self.run) if self.run is not None else (self.budget,)

    def poll(self) -> None:
        if self.cancel_check is not None:
            self.cancel_check()


def _extract_member(
    zf: zipfile.ZipFile, info: zipfile.ZipInfo, suffix: str, lower_name: str, shown: str, shown_zip: str,
    walk: _Walk,
) -> tuple[str, Path | None, str]:
    """Sniff (an XML member) and extract one member; ``(outcome, path, why)``.

    The outcome is ``"extracted"`` (with its path), ``"ancillary"``,
    ``"legacy-checklist"``, ``"too-large"`` (over the per-member cap),
    ``"size"`` (a byte budget ran out, or the disk is full: nothing more is read
    from the archive) or ``"unreadable"`` (with *why*: the error, through ``error_text``).
    Nothing it reads can make it raise; a partial file is removed.
    """
    target: Path | None = None
    try:
        kind, sniffed = _member_kind(zf, info, lower_name, walk.budgets) if suffix == ".xml" else ("candidate", 0)
        if any(b.bytes < 0 for b in walk.budgets):
            # The sniff spent what was left: this member is not read either.
            return "size", None, ""
        if kind != "candidate":
            return kind, None, ""
        target = _generated_path(walk.dest_dir, suffix)
        extracted = _bounded_extract(zf, info, target, walk.budgets, sniffed)
    except Exception as exc:        # see the note above NOT_A_ZIP
        if target is not None:
            with contextlib.suppress(OSError):
                target.unlink(missing_ok=True)
        if isinstance(exc, OSError) and exc.errno == errno.ENOSPC:
            # Not this member's fault: no later one would fit either.
            return "size", None, ""
        return "unreadable", None, error_text(exc)
    if extracted == "archive":
        return "size", None, ""
    if extracted == "member":
        return "too-large", None, ""
    return "extracted", target, ""


def _merge_nested(
    out: Extraction, target: Path, shown: str, in_archive: str, walk: _Walk, depth: int,
    rest: list[zipfile.ZipInfo],
) -> bool:
    """Read the nested ZIP extracted to *target* into *out*, then remove it (DISA's
    wrapper-zip pattern). True when its budget ran out in there: the budget is the
    supplied archive's, so nothing more is read from it either."""
    inner = _extract(target, shown, walk, depth=depth + 1, prefix=in_archive + "/")
    with contextlib.suppress(OSError):
        target.unlink(missing_ok=True)
    if inner.unreadable == NOT_A_ZIP:
        out.skipped.append(f"{shown} is not a readable ZIP — skipped")
    elif inner.unreadable == PASSWORD_PROTECTED:
        out.skipped.append(f"{shown} is password-protected — skipped")
    elif inner.unreadable == _too_many_entries():
        out.skipped.append(f"{shown} has more than {_MAX_ENTRIES:,} entries — skipped")
    elif inner.unreadable == _directory_too_large():
        out.skipped.append(f"{shown} has an entry list over {_max_directory_bytes():,} bytes — skipped")
    out.members.extend(inner.members)
    out.skipped.extend(inner.skipped)
    out.skipped_more += inner.skipped_more
    out.legacy_checklists.extend(inner.legacy_checklists)
    out.other_archives.extend(inner.other_archives)
    if inner.limit:
        out.limit, out.not_read = inner.limit, inner.not_read + _unread(rest)
        return True
    return False


def _take_member(
    zf: zipfile.ZipFile, infos: list[zipfile.ZipInfo], index: int, out: Extraction, walk: _Walk,
    shown_zip: str, depth: int, prefix: str,
) -> bool:
    """Read or name member *index* of *infos* into *out*; True when the archive stops there."""
    info = infos[index]
    inner_name = _base_name(info.filename)
    lower = inner_name.lower()
    # Cut from the left when too long: the end of a name is its extension.
    shown = shown_file_name(inner_name, MAX_FILE_NAME_CHARS)
    # Bounded as it is built: nesting must not grow it past what can be shown.
    in_archive = (prefix + info.filename.replace("\\", "/"))[-(MAX_FILE_NAME_CHARS + 1):]
    kind = _name_kind(lower, depth)
    if kind == "legacy-checklist":
        out.legacy_checklists.append(shown)
        return False
    if kind == "other-archive":
        out.other_archives.append(shown)
        return False
    if kind == "ignored":
        return False
    if kind == "too-deep":
        # Not opened: every level deeper is another archive to unpack (zip bomb).
        # Opening none costs no budget, so a flood of them is listed only so far.
        out.too_deep += 1
        if out.too_deep > _MAX_TOO_DEEP_LISTED:
            out.skipped_more += 1
            return False
        out.skipped.append(f"{shown} is nested more than {_MAX_ZIP_DEPTH} ZIPs deep — skipped")
        return False

    # Every member opened counts, whether it is only sniffed or extracted.
    if any(b.members <= 0 for b in walk.budgets):
        out.limit, out.not_read = "member", _unread(infos[index:])
        return True
    for b in walk.budgets:
        b.members -= 1
    outcome, target, why = _extract_member(zf, info, kind, lower, shown, shown_zip, walk)
    if outcome == "size":
        out.limit, out.not_read = "size", _unread(infos[index:])
        return True
    if outcome == "legacy-checklist":
        out.legacy_checklists.append(shown)
    elif outcome == "too-large":
        out.skipped.append(f"{shown} is larger than the {_size_limit(_MAX_EXTRACTED_BYTES)} limit — skipped")
    elif outcome == "unreadable":
        out.skipped.append(f"could not read {shown}: {why} — skipped")
    if outcome != "extracted" or target is None:
        return False
    if kind != ".zip":
        out.members.append(ExtractedMember(target, shown, in_archive))
        return False
    return _merge_nested(out, target, shown, in_archive, walk, depth, infos[index + 1:])


def _extract(zip_path: Path, shown_zip: str, walk: _Walk, *, depth: int, prefix: str) -> Extraction:
    """:func:`extract_from_zip` for one archive at *depth* of the walk; *prefix* is its own
    path inside the archive supplied ("" at the top)."""
    out = Extraction()
    walk.dest_dir.mkdir(parents=True, exist_ok=True)

    with contextlib.ExitStack() as files:
        try:
            guard = _GuardedFile(files.enter_context(zip_path.open("rb")))
            zf = files.enter_context(zipfile.ZipFile(guard))
        except _DirectoryRefused as refused:
            out.unreadable = refused.line
            return out
        except Exception:               # see the note above NOT_A_ZIP
            out.unreadable = NOT_A_ZIP
            return out
        guard.armed = False             # the entry list is built: member reads are not the directory's
        infos = zf.infolist()
        if any(info.flag_bits & 0x1 for info in infos):
            out.unreadable = PASSWORD_PROTECTED
            return out
        for index, info in enumerate(infos):
            if info.is_dir():
                continue
            walk.poll()
            if _take_member(zf, infos, index, out, walk, shown_zip, depth, prefix):
                break

    # Skips, refusals and a limit reached are in *out*: the caller reports them.
    if out.members:
        log.info("Extracted %d file(s) from %s", len(out.members), shown_zip)
    return out


def extract_from_zip(
    zip_path: Path,
    dest_dir: Path,
    *,
    name: str | None = None,
    run: Budget | None = None,
    cancel_check: Callable[[], None] | None = None,
) -> Extraction:
    """Extract every member of *zip_path* that may be scan results or a STIG
    reference into *dest_dir*.

    That is every ``.xml`` member except known ancillary SCAP content and
    legacy ``.ckl`` checklists (see :func:`_member_kind`), every checklist
    (``.cklb``) and every ``.nessus`` scan. What each one is, the caller decides from its content,
    as for a loose file. Recurses into nested ZIPs (DISA's wrapper-zip
    pattern), at most ``_MAX_ZIP_DEPTH`` deep. Archives of another format are
    listed, not opened.

    One archive the operator supplied extracts at most ``_MAX_MEMBERS``
    members and ``_MAX_ARCHIVE_BYTES`` decompressed bytes, its nested ZIPs
    included, and the bytes read to sniff an XML member count. *run*, when
    given, is the budget of the whole run (:func:`run_budget`), charged too.
    Reaching any limit stops the whole archive there: ``Extraction.limit``
    says which kind, and ``Extraction.not_read`` how many files were left.
    *cancel_check*, when given, is called before each member (nested archives
    too); it may raise to stop, and what it raises is never caught here.

    Each member is written under a generated file name and keeps its own base
    name and its path inside the archive for display (``ExtractedMember``);
    no name is made up here, because only the caller knows every name in the
    run. Never raises on a bad archive: see :class:`Extraction`. *name* is
    what to call the archive in log lines when it is not ``zip_path.name``.
    """
    shown_zip = name or safe_name(zip_path.name, MAX_FILE_NAME_CHARS)
    # Read the caps here, not at import: they are module constants tests may lower.
    walk = _Walk(dest_dir, Budget(_MAX_MEMBERS, _MAX_ARCHIVE_BYTES), run, cancel_check)
    return _extract(zip_path, shown_zip, walk, depth=0, prefix="")
