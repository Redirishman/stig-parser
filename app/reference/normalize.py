"""Identifier normalisation shared by every reference lookup.

Scan results, Manual STIGs, SCAP benchmarks, and checklists spell the same
rule differently (XCCDF 1.2 prefixes, revision suffixes that change between
STIG releases). Everything that compares identifiers goes through here.
"""
from __future__ import annotations

import re
import unicodedata
from functools import lru_cache

_RULE_PREFIX = re.compile(r"^xccdf_[^_]+_rule_", re.IGNORECASE)
_GROUP_PREFIX = re.compile(r"^xccdf_[^_]+_group_", re.IGNORECASE)
_BENCHMARK_PREFIX = re.compile(r"^xccdf_[^_]+_benchmark_", re.IGNORECASE)
# The revision must follow a digit (``SV-254239r945408``), and the ``_rule``
# suffix is optional: STIG Viewer checklists carry ``rule_id`` without it.
_REVISION = re.compile(r"(?<=[0-9])(r[0-9]+)(?:_rule)?$", re.IGNORECASE)
_RULE_SUFFIX = re.compile(r"_rule$", re.IGNORECASE)
_STIG_ID_PREFIX = re.compile(r"^DISA[-_]STIG[-_]", re.IGNORECASE)
# These values come from uploaded files, so every pattern is hostile-input safe:
# ASCII digits only (``\d`` and ``str.isdigit()`` also accept characters such as
# U+00B2 that ``int()`` rejects), every digit group bounded at nine digits (no
# polynomial backtracking, and ``int()`` never meets its 4300-digit limit).
# ``int()`` already drops leading zeros.
_SCAP_VERSION = re.compile(r"([0-9]{1,9})\.([0-9]{1,9})")
_PLAIN_DIGITS = re.compile(r"[0-9]{1,9}")
_RELEASE = re.compile(r"(?<![A-Za-z-])Release:\s*([0-9]{1,9})(?![0-9])", re.IGNORECASE)
_RELEASE_KEY = re.compile(r"V([0-9]{1,9})(?:R([0-9]{1,9}))?", re.IGNORECASE)
_DISA_STEM = re.compile(r"SV-[0-9]{1,12}", re.IGNORECASE)
_VULN_ID = re.compile(r"V-[0-9]{1,12}", re.IGNORECASE)
_NON_ALNUM = re.compile(r"[\W_]+")
_VERSION_TOKEN = re.compile(r"v[0-9]{1,9}r[0-9]{1,9}")
# Words that name the document, not the product it covers.
_PRODUCT_NOISE = frozenset({"stig", "scap", "benchmark", "manual", "disa", "audit"})
_STIG_PHRASE = ("security", "technical", "implementation", "guide")
_PRODUCT_KEY_CHARS = 1000   # product_key reads this much of a title; a product name is never longer

# Text from uploaded files is bounded before it is stored, shown or reported.
MAX_RELEASE_CHARS = 40      # a release label ("V2R8"); anything longer is not one
MAX_STORED_CHARS = 200      # a STIG title, benchmark ID or rule/STIG/V-ID kept from an upload
MAX_SHOWN_CHARS = 120       # an uploaded string put in an operator-facing line or a report key
MAX_LOGGED_NAME_CHARS = 80  # a file name put in a log line or warning
MAX_FILE_NAME_CHARS = 255   # a file name kept on a reference source (the longest a file system allows)

# A STIG severity as the report states it. Every reader maps severities through
# this one table; what an unknown severity becomes is each reader's own choice.
CAT_BY_SEVERITY = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}


def clip(value: str, limit: int) -> str:
    """At most *limit* characters of *value* (``""`` for None); never copies more than that."""
    return str(value or "")[:limit]


def clip_left(value: str, limit: int) -> str:
    """At most *limit* characters of *value*, keeping its end: ``"…"`` and the last
    ``limit - 1`` when it is longer. For a display name, whose end is the file's own
    name (``lib.zip/…/win11/manual-xccdf.xml``); never copies more than that."""
    value = str(value or "")
    return value if len(value) <= limit else "…" + value[-(limit - 1):]


def json_text(value: object) -> str:
    """A JSON string, stripped; ``""`` for anything else.

    A checklist is untrusted JSON. A nested object, list, number or boolean
    where text belongs is not text, and is never turned into text with
    ``str()``: the report would then show ``{'a': 1}`` as if a STIG said it.
    """
    return value.strip() if isinstance(value, str) else ""


class JsonText:
    """Reads text out of untrusted JSON values (see :func:`json_text`) and counts
    every value it refused because it was not text."""

    def __init__(self) -> None:
        self.ignored = 0

    def __call__(self, value: object) -> str:
        if value is not None and not isinstance(value, str):
            self.ignored += 1
        return json_text(value)

    def version(self, value: object) -> str:
        """A STIG version: a string, or an integer (STIG Viewer writes ``"version": 2``)."""
        if isinstance(value, int) and not isinstance(value, bool):
            return str(value)
        return self(value)


def fold(value: str) -> str:
    """The comparison form of an ID: upper-cased when it is ASCII, otherwise as it is.

    ``str.upper()`` on non-ASCII text can change length (U+00DF -> ``SS``) and
    would make distinct IDs collide, so a non-ASCII ID only matches itself.
    """
    return value.upper() if value.isascii() else value


def safe_name(name: str, limit: int = MAX_LOGGED_NAME_CHARS) -> str:
    """A file name that is safe to put in a log line or warning.

    Truncated first (a huge name costs nothing), then escaped like ``%r`` (so a
    newline or control character cannot forge a line). *limit* is 80 for a log
    line; a name the operator must recognise (a display name) passes
    ``MAX_FILE_NAME_CHARS``, which no real file name exceeds.
    """
    return repr(clip(name, limit))[1:-1][:limit]


# C0 and C1 controls and DEL; the line and paragraph separators (U+2028,
# U+2029), which end a line for many viewers; and the bidi controls (U+200E,
# U+200F, U+202A-U+202E, U+2066-U+2069), which make a line read differently
# from what it holds.
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def escape_controls(text: str) -> str:
    """*text* with each control character, line or paragraph separator and bidi
    control written as its escape (``\\n``, ``\\x1b``, ``\\u2028``, ``\\u202e``),
    and nothing else changed.

    For a whole line that carries uploaded text (a warning naming a STIG title
    or a host) as it is printed: a line break in a title must not start a line
    of its own in the log, nor a bidi control disguise one. A name
    :func:`safe_name` already escaped holds none of these (``repr`` escapes
    them), so it is never escaped twice.
    """
    return _CONTROL_CHARS.sub(lambda m: repr(m.group())[1:-1], text)


def display_file_name(name: str) -> str:
    """The name an operator gave an upload, fit to show back to them: NFC-normalised
    (a name typed on one system and pasted on another compares equal), every control
    character, line or paragraph separator and bidi control removed (none can forge a
    line or disguise one), at most MAX_FILE_NAME_CHARS long, cut from the left so the
    extension stays. Never a file system name: uploads are saved under a safe one."""
    cleaned = _CONTROL_CHARS.sub("", unicodedata.normalize("NFC", str(name or "")))
    return clip_left(cleaned.strip(), MAX_FILE_NAME_CHARS)


def shown_file_name(name: str, limit: int = MAX_SHOWN_CHARS) -> str:
    """A file name for a log line or warning: escaped (see :func:`safe_name`) and, when
    longer than *limit*, cut from the left so that the file's own name remains."""
    name = str(name or "")
    escaped = repr(name[-limit:])[1:-1]     # only the end is shown; escaping never shortens it
    if len(name) > limit:                   # cut already: the mark must show even when it fits
        return "…" + escaped[-(limit - 1):]
    return clip_left(escaped, limit)


def error_text(exc: BaseException) -> str:
    """What went wrong with an uploaded file, fit for a line the operator reads.

    The exception's own message without its location: lxml's ends with the
    file's URL and an OSError's names the path it failed on, and for an upload
    or an archive member that is a temp directory and a generated file name on
    this server. A file name the exception carries is removed from any other
    message. Bounded and escaped (see :func:`safe_name`); the line number is
    added when the message does not already give it.
    """
    if isinstance(exc, SyntaxError) and isinstance(exc.msg, str):
        message = exc.msg   # lxml's XMLSyntaxError: str() appends "(file:/..., line N)"
    elif isinstance(exc, OSError):
        message = exc.strerror if isinstance(exc.strerror, str) else "the file could not be read"
    else:
        message = str(exc)
    for attr in ("filename", "filename2"):
        path = getattr(exc, attr, None)
        if isinstance(path, str) and path:
            message = message.replace(path, "…")
    message = safe_name(message, MAX_SHOWN_CHARS) or type(exc).__name__
    line = getattr(exc, "lineno", None)
    if isinstance(line, int) and not isinstance(line, bool) and line > 0 and f"line {line}" not in message:
        message += f" (line {line})"
    return message


def strip_rule_prefix(rule_id: str) -> str:
    """``xccdf_mil.disa.stig_rule_SV-1r2_rule`` -> ``SV-1r2_rule``."""
    return _RULE_PREFIX.sub("", (rule_id or "").strip())


def rule_revision(rule_id: str) -> str:
    """``SV-254239r945408_rule`` -> ``r945408``; ``""`` when there is none."""
    m = _REVISION.search(strip_rule_prefix(rule_id))
    return m.group(1).lower() if m else ""


def rule_stem(rule_id: str) -> str:
    """The revision-free rule identity: ``SV-254239r945408_rule`` -> ``SV-254239``."""
    bare = strip_rule_prefix(rule_id)
    stem = _REVISION.sub("", bare)
    return _RULE_SUFFIX.sub("", stem) if stem == bare else stem


def strip_group_prefix(group_id: str) -> str:
    """``xccdf_mil.disa.stig_group_V-254239`` -> ``V-254239``."""
    return _GROUP_PREFIX.sub("", (group_id or "").strip())


def norm_stig_id(stig_id: str) -> str:
    """Uppercase, ``_`` -> ``-``, optional ``DISA-STIG-`` prefix removed.

    Only ASCII values are uppercased (see :func:`fold`).
    """
    return fold(_STIG_ID_PREFIX.sub("", (stig_id or "").strip()).replace("_", "-"))


def norm_benchmark_id(benchmark_id: str) -> str:
    """``xccdf_mil.disa.stig_benchmark_X`` -> ``X``."""
    return _BENCHMARK_PREFIX.sub("", (benchmark_id or "").strip())


def release_label(version: str, release_info: str = "") -> str:
    """A ``V2R8`` label from the two shapes DISA uses.

    Manual STIGs carry ``<version>2</version>`` plus a release-info line
    ``Release: 8 Benchmark Date: ...``; SCAP benchmarks carry
    ``<version>002.008</version>``. Anything else is returned as it is, cut to
    ``MAX_RELEASE_CHARS``: it comes from an upload and ends up in every cell.
    """
    version = str(version or "").strip()
    scap = _SCAP_VERSION.fullmatch(version)
    if scap:
        return f"V{int(scap.group(1))}R{int(scap.group(2))}"
    if _PLAIN_DIGITS.fullmatch(version):
        release = _RELEASE.search(release_info or "")
        return f"V{int(version)}R{int(release.group(1))}" if release else f"V{int(version)}"
    return version[:MAX_RELEASE_CHARS]


def is_disa_stem(stem: str) -> bool:
    """True for a DISA rule stem such as ``SV-254239``.

    Scanner rule names (SSG ``accounts_tmout``, a Nessus check name, a STIG ID)
    are not DISA stems, so two of them never prove two rules are different.
    """
    return bool(_DISA_STEM.fullmatch(stem or ""))


def is_vuln_id(value: str) -> bool:
    """True for a DISA V-ID such as ``V-254239`` (an XCCDF group prefix is ignored).

    The innermost Group ID of a benchmark is only a V-ID in DISA STIGs;
    ComplianceAsCode groups are named for a topic (``accounts-session``) and
    hold several Rules, so they must never act as a lookup key.
    """
    return bool(_VULN_ID.fullmatch(strip_group_prefix(value)))


def release_key(label: str) -> tuple[int, int]:
    """Sort key for a ``V2R8`` label: ``V2R10`` -> ``(2, 10)``, ``V3`` -> ``(3, 0)``.

    Anything that is not a version/release label sorts below every real one
    as ``(-1, -1)``. Digit groups are ASCII and bounded at nine digits, so
    ``int()`` only ever sees a short string.
    """
    m = _RELEASE_KEY.fullmatch(str(label or "").strip())
    if not m:
        return (-1, -1)
    return (int(m.group(1)), int(m.group(2) or 0))


def product_key(title: str) -> str:
    """The product a STIG title names, with document wording removed.

    ``Microsoft Windows 11 STIG SCAP Benchmark`` and ``Microsoft Windows 11
    Security Technical Implementation Guide`` share a key; a router STIG and a
    switch STIG of the same family do not. When nothing is left after removing
    the document wording, the folded, whitespace-collapsed title is returned.
    Only the first 1,000 characters are read.
    """
    return _product_key(clip(title, _PRODUCT_KEY_CHARS))


@lru_cache(maxsize=4096)
def _product_key(title: str) -> str:
    folded = title.casefold()
    tokens = [t for t in _NON_ALNUM.split(folded) if t]
    kept: list[str] = []
    i = 0
    while i < len(tokens):
        if tuple(tokens[i:i + len(_STIG_PHRASE)]) == _STIG_PHRASE:
            i += len(_STIG_PHRASE)
            continue
        token = tokens[i]
        i += 1
        if token not in _PRODUCT_NOISE and not _VERSION_TOKEN.fullmatch(token):
            kept.append(token)
    return " ".join(kept) or " ".join(folded.split())
