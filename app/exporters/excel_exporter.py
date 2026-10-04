"""Excel workbook generation using openpyxl."""
from __future__ import annotations

import ipaddress
import logging
import re
from collections import Counter
from collections.abc import Sequence
from functools import partial
from pathlib import Path

from openpyxl import Workbook
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from app.parsers.base import Finding
from app.processors.delta import DELTA_STATUSES, DeltaFinding, DeltaResult, coverage_gaps
from app.reference.enrich import EnrichmentReport, source_key

log = logging.getLogger(__name__)

# Sheet the Summary COUNTIFS/COUNTIF formulas address.
_FINDINGS_SHEET = "Findings"

# Excel/Calc treat a leading =, +, -, @, or control char as a formula.
# Scan-derived text (hostname, check/fix text) is attacker-controllable, so
# any such value is prefixed with an apostrophe to force literal-text display.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "|", "\t", "\r")
# A control character a workbook cannot hold (openpyxl refuses the cell, so one
# in an upload would abort the export) is shown as U+FFFD, the replacement
# character: the cell keeps the rest of its text and says something was there.
_REPLACEMENT_CHAR = "\ufffd"
# A lone surrogate (valid in JSON, e.g. "\ud800") cannot be written as UTF-8:
# the save would fail. It is shown as U+FFFD too.
_SURROGATES = re.compile(r"[\ud800-\udfff]")
# Excel decodes _xHHHH_ in stored text (_x000D_ is a CR). openpyxl writes text
# as it is, so uploaded text holding such a sequence would read differently in
# the cell; the underscore that starts one is stored as _x005F_ ("_").
_OOXML_ESCAPE = re.compile(r"_(?=x[0-9A-Fa-f]{4}_)")
# Excel holds at most this many characters in a cell and "repairs" a workbook
# with a longer one by cutting it, without saying where. Check and fix text
# come from uploads unbounded, so a longer value is cut here, visibly. Excel
# counts UTF-16 units: a character outside the BMP (an emoji) counts twice.
_MAX_CELL_CHARS = 32_767
_TRUNCATED = "… [truncated by STIG Condenser]"


def _utf16_units(text: str) -> int:
    """The length of *text* as Excel counts it."""
    return len(text.encode("utf-16-le")) // 2


def _cut_to_cell_limit(text: str) -> str:
    """*text*, or as much of it as fits in a cell with the marker after it, cut
    between characters (never inside a surrogate pair).

    Measured only when the code points cannot tell: up to 16,383 of them
    always fit, over 32,767 never do, so a huge value is never encoded whole.
    """
    if len(text) * 2 <= _MAX_CELL_CHARS:
        return text
    if len(text) <= _MAX_CELL_CHARS and _utf16_units(text) <= _MAX_CELL_CHARS:
        return text
    budget = _MAX_CELL_CHARS - _utf16_units(_TRUNCATED)
    kept = 0
    for ch in text:
        units = 2 if ord(ch) > 0xFFFF else 1
        if units > budget:
            break
        budget -= units
        kept += 1
    return text[:kept] + _TRUNCATED


def _sanitize_cell(value: object) -> object:
    if not isinstance(value, str):
        return value
    value = ILLEGAL_CHARACTERS_RE.sub(_REPLACEMENT_CHAR, value)
    value = _SURROGATES.sub(_REPLACEMENT_CHAR, value)
    if value.startswith(_FORMULA_PREFIXES):
        value = "'" + value
    value = _cut_to_cell_limit(value)
    # Last: the limits above apply to the text Excel shows, which this does not change.
    return _OOXML_ESCAPE.sub("_x005F_", value)


def _formula_quote(value: object) -> str:
    """Return an Excel double-quoted string literal with embedded quotes escaped.

    Values interpolated into COUNTIFS criteria (hostname, STIG title) are
    scan-derived and attacker-controllable. Excel escapes a literal " inside a
    quoted string as "". Without this, a value containing a " breaks out of the
    criteria literal and lets the upload author inject arbitrary formula text
    into the accreditation-facing Summary sheet (CWE-1236).
    """
    return '"' + str(value).replace('"', '""') + '"'


# COUNTIFS reads ~ * ? in a criterion as its escape character and wildcards.
_CRITERION_SPECIALS = frozenset("~*?")
# Excel refuses a longer COUNTIFS criterion (in UTF-16 units): the cell shows #VALUE!.
_MAX_CRITERION_CHARS = 255


def _criterion_text(value: object) -> str:
    """The COUNTIFS criterion (before :func:`_formula_quote`) that matches
    exactly the cells written from *value*, for any text from an upload.

    It is built from what the cell holds, ``_sanitize_cell(value)`` (apostrophe
    in front of a formula prefix, U+FFFD for a character a workbook cannot
    hold): a criterion built from the raw value counted 0 for ``-HOST``, whose
    cell reads ``'-HOST``, and stopped the export on a control character. A
    leading ``=`` makes the whole text an equality test, so a value starting
    with ``= < >`` is literal too. Text with ``*`` or ``?`` gets the documented
    ``~`` escape before each; other text is used as it is. Text holding a ``~``
    is never given a criterion (:func:`_severity_count` gives its rows fixed
    counts): Excel 16 (English-US) read ``~`` as an escape only in a criterion
    that holds a wildcard, which is undocumented and unchecked elsewhere.
    A blank value gives ``""``, which matches a blank cell and one holding
    empty text alike (``"="`` would match only the first).
    """
    stored = str(_sanitize_cell(value))
    if not stored:
        return ""
    if "*" not in stored and "?" not in stored:
        return "=" + stored
    return "=" + "".join("~" + ch if ch in _CRITERION_SPECIALS else ch for ch in stored)


def _excel_upper(text: str) -> str:
    """*text* as Excel compares it when letter case is ignored: each character
    upper-cased on its own, and kept as it is when its upper case is longer
    than one character. So "ς" (final sigma) and "σ" are both "Σ", while "ß"
    stays "ß" and never equals "SS" (``str.upper()`` and ``casefold()`` would
    make it "SS"; ``str.lower()`` would keep the two sigmas apart)."""
    return "".join(up if len(up := ch.upper()) == 1 else ch for ch in text)


def _compared(value: object) -> str:
    """A value as COUNTIFS compares it: the text its cell holds, letter case
    ignored as Excel ignores it (:func:`_excel_upper`). Rows are grouped,
    and fixed counts made, by this one rule."""
    return _excel_upper(str(_sanitize_cell(value)))


# COUNTIF reads criterion text that looks like a number, a date, a time or a
# truth value as that value (Excel's documented behaviour): "0123" then also
# matches cells holding "123", "Dec-1" matches "dec-01". A row whose criterion
# could be read so gets fixed counts instead, which are always exact, so
# erring towards them is safe. Text is taken to be read so, conservatively,
# when it has no letter at all (digits, spaces and punctuation: numbers,
# dates, times) unless it is a well-formed IP address (four dot-separated
# parts are neither a number nor a date; IPv6 has colons), is TRUE or
# FALSE, starts with an English month name (3-letter or full) followed by
# a digit, a space or a separator, or with a day number, a separator and a
# month name, or with a year, a separator and a month name ("2026-Jan-15"),
# ends in AM or PM after a digit, or is a number with an exponent ("1E5").
# Text that is exactly one of Excel's error literals ("#N/A") is read as that
# error value, which counts 0: it gets a fixed count too. Only English names
# are known here; the Summary footer says so.
_MONTHS = (
    "january|february|march|april|may|june|july|august|september|october|november|december"
    "|sept|jan|feb|mar|apr|jun|jul|aug|sep|oct|nov|dec"
)
_MONTH_FIRST = re.compile(rf"(?:{_MONTHS})[\s0-9./,-]", re.IGNORECASE)
_DAY_MONTH = re.compile(rf"[0-9]{{1,2}}[\s./,-](?:{_MONTHS})", re.IGNORECASE)
_YEAR_MONTH = re.compile(rf"[0-9]{{4}}[\s./,-](?:{_MONTHS})", re.IGNORECASE)
_ERROR_LITERALS = frozenset(
    {"#N/A", "#NULL!", "#DIV/0!", "#VALUE!", "#REF!", "#NAME?", "#NUM!", "#SPILL!", "#CALC!"}
)
_AM_PM = re.compile(r"[0-9]\s*[AaPp][Mm]$")
_EXPONENT = re.compile(r"[+-]?[0-9.]+[Ee][+-]?[0-9]+")


def _is_ip_address(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _excel_would_coerce(text: str) -> bool:
    """True when COUNTIF might read the criterion *text* (the cell's text, before
    the ``=`` and the ``~`` escapes) as a number, date, time, truth value or
    error value."""
    if not text:
        return False        # the blank criterion: blank cells only
    stripped = text.strip()
    return (
        (not any(ch.isalpha() for ch in text) and not _is_ip_address(stripped))
        or stripped.upper() in ("TRUE", "FALSE")
        or stripped.upper() in _ERROR_LITERALS
        or _MONTH_FIRST.match(stripped) is not None
        or _DAY_MONTH.match(stripped) is not None
        or _YEAR_MONTH.match(stripped) is not None
        or _AM_PM.search(stripped) is not None
        or _EXPONENT.fullmatch(stripped) is not None
    )


class _Tally:
    """The findings of one Summary table, read once.

    ``rows`` maps each row's key (its *attrs* values as COUNTIFS compares
    them, :func:`_compared`) to the first spelling seen: values COUNTIFS
    cannot tell apart share a row, or each row would count the other's
    findings too. ``counts`` holds the findings per (row key, severity as
    compared), so a fixed count is a lookup, not a pass over every finding:
    each field is compared once per distinct value, not once per cell.
    """

    def __init__(self, findings: list[Finding], attrs: tuple[str, ...]) -> None:
        compared: dict[object, str] = {}

        def compare(value: object) -> str:
            text = compared.get(value)
            if text is None:
                text = compared[value] = _compared(value)
            return text

        self.rows: dict[tuple[str, ...], tuple[str, ...]] = {}
        self.counts: Counter[tuple[tuple[str, ...], str]] = Counter()
        for f in findings:
            values = tuple(getattr(f, attr, "") for attr in attrs)
            key = tuple(compare(value) for value in values)
            self.rows.setdefault(key, values)
            self.counts[(key, compare(f.severity))] += 1

    def count(self, key: tuple[str, ...], severities: tuple[str, ...]) -> int:
        return sum(self.counts[(key, _compared(severity))] for severity in severities)


# Severities that are no CAT: blank (a rule the scan's own benchmark does not
# describe and no reference filled) or "Unknown" (a value a parser could not
# map). Counted in the Summary's "No severity" column, so Totals miss no row.
_NO_SEVERITY = ("", "Unknown")


def _severity_count(
    tally: _Tally, key: tuple[str, ...], criteria: list[tuple[str, str]], severities: tuple[str, ...]
) -> str | int:
    """The Summary cell counting the findings of row *key* of *tally* whose
    severity is one of *severities*: one COUNTIFS per severity, summed, with a
    ``(Findings column, value)`` criterion for each of *criteria*.

    A host name, IP address or STIG title from an upload can be too long for a
    COUNTIFS criterion, hold a ``~`` (whose reading by COUNTIF is undocumented
    and differs from what Microsoft describes), or be text COUNTIF would read
    as a number, date, time or truth value (:func:`_excel_would_coerce`); that
    cell holds the count from
    *tally* instead, which compares what the formula compares
    (:func:`_compared`), so both kinds of cell count alike.
    """
    texts = [_criterion_text(value) for _column, value in criteria]
    if all(
        _utf16_units(text) <= _MAX_CRITERION_CHARS
        and "~" not in (stored := str(_sanitize_cell(value)))
        and not _excel_would_coerce(stored)
        for text, (_column, value) in zip(texts, criteria)
    ):
        terms = []
        for severity in severities:
            parts = [
                f"{_FINDINGS_SHEET}!${column}:${column},{_formula_quote(text)}"
                for (column, _value), text in zip(criteria, texts)
            ]
            parts.append(f"{_FINDINGS_SHEET}!${_COL_SEVERITY}:${_COL_SEVERITY},{_formula_quote(severity)}")
            if not severity:
                # A blank criterion also matches the empty rows below the data;
                # every finding has a status, so that column keeps the data rows.
                parts.append(f'{_FINDINGS_SHEET}!${_COL_STATUS}:${_COL_STATUS},"<>"')
            terms.append(f"COUNTIFS({','.join(parts)})")
        return "=" + "+".join(terms)
    return tally.count(key, severities)


_FILL_CAT_I = PatternFill("solid", fgColor="FFCCCC")
_FILL_CAT_II = PatternFill("solid", fgColor="FFEB9C")
_FILL_CAT_III = PatternFill("solid", fgColor="C6EFCE")
_SEVERITY_FILL = {"CAT I": _FILL_CAT_I, "CAT II": _FILL_CAT_II, "CAT III": _FILL_CAT_III}

# Delta-status fills (delta findings sheet "Delta" column). Colours are keyed
# by status NAME, never by position in DELTA_STATUSES: reordering that tuple
# must not swap remediated-green onto a regression. Building the fill map by
# iterating DELTA_STATUSES (app/processors/delta.py) means a status that is
# renamed or added there raises KeyError at import time rather than silently
# rendering with no fill.
_DELTA_STATUS_COLOR = {
    "New":            "FFC7CE",  # red-ish: regression
    "Resolved":       "C6EFCE",  # green: remediated
    "Persisting":     "FFEB9C",  # amber: still open
    "Not re-scanned": "D9D9D9",  # grey: no current scan to compare against
    "Newly scanned":  "DDEBF7",  # light blue: no baseline scan to compare against
}
_DELTA_FILL = {
    status: PatternFill("solid", fgColor=_DELTA_STATUS_COLOR[status])
    for status in DELTA_STATUSES
}

_HEADER_FONT = Font(name="Arial", size=10, bold=True)
_BODY_FONT = Font(name="Arial", size=10)
# Shared: a new style object per cell costs openpyxl a style lookup per cell
# (most of an export's time on a large scan).
_ALIGN_HEADER = Alignment(vertical="center")
_ALIGN_TEXT = Alignment(wrap_text=False, vertical="center")
_ALIGN_WRAP = Alignment(wrap_text=True, vertical="top")

# (header_label, Finding_attr, max_col_width)
_FINDINGS_COLS: list[tuple[str, str, int]] = [
    ("STIG Title",  "stig_title",  50),
    ("Vuln ID",     "vuln_id",     12),
    ("Rule ID",     "rule_id",     40),
    ("Severity",    "severity",    10),
    ("Status",      "status",      14),
    ("Server",      "server",      30),
    ("IP Address",  "ip_address",  18),
    ("Check Text",  "check_text",  80),
    ("Fix Text",    "fix_text",    80),
    ("STIG ID",     "stig_id",     18),
    ("Text Source", "text_source", 60),
]

_WRAP_HEADERS = {"Check Text", "Fix Text", "Text Source"}

# Header row of the Summary sheet's Reference sources table.
_SOURCES_HEADERS = [
    "File", "STIG", "Edition", "Release", "Embedded in results", "Rules loaded",
    "Check text filled", "Fix text filled", "From a different release", "Severity filled",
]

# Findings sheet column letters (A=1 … I=9); new columns are only ever appended
_COL_STIG     = "A"   # col 1
_COL_SEVERITY = "D"   # col 4
_COL_STATUS   = "E"   # col 5
_COL_SERVER   = "F"   # col 6
_COL_IP       = "G"   # col 7

# (header_label, DeltaFinding_attr, max_col_width) — delta findings sheet
_DELTA_COLS: list[tuple[str, str, int]] = [
    ("Delta",            "delta_status",    12),
    ("STIG Title",       "stig_title",      50),
    ("Vuln ID",          "vuln_id",         12),
    ("Rule ID",          "rule_id",         40),
    ("Severity",         "severity",        10),
    ("Baseline Status",  "baseline_status", 16),
    ("Current Status",   "current_status",  16),
    ("Server",           "server",          30),
    ("IP Address",       "ip_address",      18),
    ("Check Text",       "check_text",      80),
    ("Fix Text",         "fix_text",        80),
    ("STIG ID",          "stig_id",         18),
    ("Text Source",      "text_source",     60),
]

# Delta findings sheet column letters (for Summary COUNTIFS)
_DELTA_COL_DELTA    = "A"   # col 1
_DELTA_COL_SEVERITY = "E"   # col 5


def _as_text(cell):
    """Keep a string that is not one of the exporter's own formulas as text.

    openpyxl stores a string equal to an Excel error code (``#N/A``, ``#REF!``,
    ``#DIV/0!`` …) as that error value: a host or STIG title so named would
    become an error cell. Uploaded text never starts with ``=`` (see
    ``_sanitize_cell``), so only the exporter's own formulas do.
    """
    if isinstance(cell.value, str) and cell.data_type != "f":
        cell.data_type = "s"
    return cell


def _h(ws, row: int, col: int, text):
    """Write a header-styled cell."""
    cell = _as_text(ws.cell(row=row, column=col, value=text))
    cell.font = _HEADER_FONT
    return cell


def _b(ws, row: int, col: int, value):
    """Write a body-styled cell."""
    cell = _as_text(ws.cell(row=row, column=col, value=value))
    cell.font = _BODY_FONT
    return cell


def _countifs2(col_a: str, crit_a: str, col_b: str, crit_b: str) -> str:
    """A two-criteria COUNTIFS over the Findings sheet.

    *crit_a* / *crit_b* must already be Excel string literals — pass
    scan-derived values through ``_criterion_text`` and ``_formula_quote``
    (CWE-1236).
    """
    return (
        f'=COUNTIFS({_FINDINGS_SHEET}!${col_a}:${col_a},{crit_a},'
        f'{_FINDINGS_SHEET}!${col_b}:${col_b},{crit_b})'
    )


def _write_findings_sheet(
    ws,
    rows: Sequence[Finding | DeltaFinding],
    cols: list[tuple[str, str, int]],
    fills: dict[str, dict[str, PatternFill]],
) -> None:
    """Write a findings-style sheet: header row, one row per record, widths.

    *cols* is a (header, attribute, max_width) layout; *fills* maps a header to
    a value -> PatternFill lookup applied to that column's cells.

    Shared by the single-run and delta reports so the invariants that have to
    hold for both — every value through ``_sanitize_cell``, ``_WRAP_HEADERS``
    honoured, widths measured off the first line — live in exactly one place
    and cannot drift apart.
    """
    # Header row
    for col_idx, (header, _attr, _mw) in enumerate(cols, start=1):
        cell = ws.cell(row=1, column=col_idx, value=header)
        cell.font = _HEADER_FONT
        cell.alignment = _ALIGN_HEADER

    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:{get_column_letter(len(cols))}1"

    # Data rows
    alignments = [_ALIGN_WRAP if header in _WRAP_HEADERS else _ALIGN_TEXT for header, _a, _w in cols]
    for row_idx, record in enumerate(rows, start=2):
        for col_idx, (header, attr, _mw) in enumerate(cols, start=1):
            value = getattr(record, attr, "")
            cell = _as_text(ws.cell(row=row_idx, column=col_idx, value=_sanitize_cell(value)))
            cell.font = _BODY_FONT
            cell.alignment = alignments[col_idx - 1]
            fill = fills.get(header, {}).get(value)
            if fill:
                cell.fill = fill

    # Column widths — measure actual content, cap at max_width
    for col_idx, (header, _attr, max_w) in enumerate(cols, start=1):
        col_letter = get_column_letter(col_idx)
        measured = len(header)
        for row_idx in range(2, ws.max_row + 1):
            val = ws.cell(row=row_idx, column=col_idx).value or ""
            measured = max(measured, min(len(str(val).split("\n")[0]), max_w))
        ws.column_dimensions[col_letter].width = min(measured + 2, max_w)


def _autofit_summary(ws, ncols: int, last_row: int) -> None:
    """Width summary columns 1..*ncols* to their widest non-formula content."""
    for col_idx in range(1, ncols + 1):
        col_letter = get_column_letter(col_idx)
        max_len = 10
        for r in range(1, last_row + 1):
            val = ws.cell(row=r, column=col_idx).value or ""
            if not str(val).startswith("="):
                max_len = max(max_len, len(str(val)))
        ws.column_dimensions[col_letter].width = min(max_len + 2, 60)


# Warning lines written to a Summary sheet, as many as the web UI shows; the rest are counted.
_MAX_WARNING_ROWS = 200


def _write_warnings(ws, row: int, heading: str, warnings: Sequence[str]) -> int:
    """Write *warnings* under *heading* from *row*; return the row after its spacer.

    Nothing at all when there are none, so an empty heading never implies that
    something went wrong. Warnings name uploaded files, hosts and titles, so each
    line passes ``_sanitize_cell``; at most _MAX_WARNING_ROWS, then one line
    saying how many more there were.
    """
    if not warnings:
        return row
    _h(ws, row, 1, heading)
    row += 1
    shown = list(warnings[:_MAX_WARNING_ROWS])
    if len(warnings) > _MAX_WARNING_ROWS:
        shown.append(f"… and {len(warnings) - _MAX_WARNING_ROWS} more warnings not shown")
    for warning in shown:
        # Long lines wrap rather than spill across the sheet.
        _b(ws, row, 1, _sanitize_cell(warning)).alignment = _ALIGN_WRAP
        row += 1
    return row + 1  # spacer


_COUNT_SEVERITIES = ("CAT I", "CAT II", "CAT III")


def _write_count_table(
    ws, row: int, title: str, labels: list[tuple[str, str, str]], findings: list[Finding],
    *, blank_label: str | None = None,
) -> tuple[int, bool]:
    """Write one "Findings by …" table of the Summary from *row*.

    *labels* gives each label column as ``(header, Finding attribute, Findings
    column)``; a row per distinct combination as COUNTIFS compares it
    (:class:`_Tally`), shown in its first spelling, *blank_label* for a blank
    single label. Then CAT I, CAT II, CAT III, Total, and "No severity" after
    Total (Total counts it), so the CAT columns and Total keep the letters
    other cells address. Returns the row after the table's spacer, and
    whether any cell holds a fixed count.
    """
    n = len(labels)
    _h(ws, row, 1, title)
    row += 1
    headers = [header for header, _attr, _column in labels]
    for ci, lbl in enumerate([*headers, *_COUNT_SEVERITIES, "Total", "No severity"], 1):
        _h(ws, row, ci, lbl)
    row += 1
    first, last, no_severity = get_column_letter(n + 1), get_column_letter(n + 3), get_column_letter(n + 5)
    count_columns = list(zip((n + 1, n + 2, n + 3, n + 5), [*((sev,) for sev in _COUNT_SEVERITIES), _NO_SEVERITY]))
    tally = _Tally(findings, tuple(attr for _header, attr, _column in labels))
    fixed = False
    for key, values in tally.rows.items():
        for ci, value in enumerate(values, 1):
            shown = blank_label if blank_label is not None and not value else _sanitize_cell(value)
            _b(ws, row, ci, shown)
        criteria = [(column, value) for (_header, _attr, column), value in zip(labels, values)]
        for ci, severities in count_columns:
            count = _severity_count(tally, key, criteria, severities)
            fixed |= isinstance(count, int)
            _b(ws, row, ci, count)
        _b(ws, row, n + 4, f"=SUM({first}{row}:{last}{row},{no_severity}{row})")
        row += 1
    return row + 1, fixed


class ExcelExporter:
    """Generate an Excel workbook from a list of Finding objects."""

    def export(
        self,
        findings: list[Finding],
        output_path: Path,
        *,
        enrichment: EnrichmentReport | None = None,
        warnings: Sequence[str] | None = None,
    ) -> Path:
        """Write *findings* to *output_path* and return it.

        *enrichment* adds the Reference sources table to the Summary sheet
        when the operator supplied at least one reference. *warnings* (the
        run's operator warnings) are listed on the Summary sheet, so the
        workbook alone says what the run could not read or count. Raises
        ValueError when *findings* is empty.
        """
        if not findings:
            raise ValueError("No findings to export — workbook not generated.")

        wb = Workbook()
        findings_ws = wb.active
        findings_ws.title = "Findings"
        _write_findings_sheet(
            findings_ws, findings, _FINDINGS_COLS, {"Severity": _SEVERITY_FILL}
        )

        summary_ws = wb.create_sheet("Summary")
        self._write_summary(summary_ws, findings, enrichment, warnings or [])

        wb.save(str(output_path))
        log.info("Workbook written to %s", output_path)
        return output_path

    def export_delta(self, delta: DeltaResult, output_path: Path) -> Path:
        """Write a delta workbook (Findings + Summary) and return the path.

        Unlike ``export``, an all-one-bucket result (e.g. every finding New, or
        every finding Resolved) is valid. Only a delta with no findings AND no
        host coverage information is rejected.
        """
        if not delta.findings and not (
            delta.common_hosts
            or delta.only_baseline_hosts
            or delta.only_current_hosts
        ):
            raise ValueError("Empty delta — workbook not generated.")

        wb = Workbook()
        findings_ws = wb.active
        findings_ws.title = "Findings"
        _write_findings_sheet(
            findings_ws,
            delta.findings,
            _DELTA_COLS,
            {"Delta": _DELTA_FILL, "Severity": _SEVERITY_FILL},
        )

        summary_ws = wb.create_sheet("Summary")
        self._write_delta_summary(summary_ws, delta)

        wb.save(str(output_path))
        log.info("Delta workbook written to %s", output_path)
        return output_path

    # ------------------------------------------------------------------
    # Summary sheet
    # ------------------------------------------------------------------

    def _write_summary(
        self, ws, findings: list[Finding], enrichment: EnrichmentReport | None = None,
        warnings: Sequence[str] = (),
    ) -> None:
        severities = ["CAT I", "CAT II", "CAT III"]
        statuses   = ["Open", "Not Reviewed", "Error", "Unknown"]
        h, b, countifs2 = _h, _b, _countifs2

        row = 1

        # ── Table 1: By Severity ──────────────────────────────────────
        h(ws, row, 1, "Findings by Severity")
        row += 1
        for ci, lbl in enumerate(["Severity", *statuses, "Total"], 1):
            h(ws, row, ci, lbl)
        row += 1

        for sev in severities:
            b(ws, row, 1, sev)
            for ci, stat in enumerate(statuses, 2):
                b(ws, row, ci, countifs2(_COL_SEVERITY, f'"{sev}"', _COL_STATUS, f'"{stat}"'))
            b(ws, row, 6, f"=SUM(B{row}:E{row})")
            row += 1
        row += 1  # spacer

        # ── Tables 2 and 3: by server (a row per host and IP: one host
        # reported with two IPs is two rows, each counting its own findings)
        # and by STIG (untitled findings get a row of their own).
        row, fixed_server = _write_count_table(
            ws, row, "Findings by Server", [("Server", "server", _COL_SERVER), ("IP Address", "ip_address", _COL_IP)],
            findings,
        )
        row, fixed_stig = _write_count_table(
            ws, row, "Findings by STIG", [("STIG Title", "stig_title", _COL_STIG)], findings,
            blank_label="(no STIG title)",
        )
        fixed_counts = fixed_server or fixed_stig

        # ── Table 4: Reference sources ────────────────────────────────
        # Only when the operator supplied a reference: a run without one keeps
        # the historical Summary layout. Literal values, not formulas — this
        # is the audit trail of where filled text came from.
        if enrichment is not None and enrichment.standalone_sources:
            row = self._write_reference_sources(ws, row, enrichment)

        # ── Table 5: the run's warnings ───────────────────────────────
        # Files not read, limits reached, copies merged, files not counted: a
        # reviewer holding only this workbook must still see them.
        row = _write_warnings(ws, row, "Warnings from this run", warnings)

        # ── Footer note ───────────────────────────────────────────────
        # The exception is named only when a cell holds a fixed count, so a
        # workbook without one keeps the note it always had.
        except_fixed = (
            ", except where a host, IP address or title is too long for COUNTIFS, "
            "holds a ~, or would be read by it as a number, date, time, TRUE/FALSE "
            "or an error value; those cells hold a fixed count"
        ) if fixed_counts else ""
        note_cell = ws.cell(
            row=row,
            column=1,
            value=(
                f"Note: Counts use COUNTIFS and reflect all data{except_fixed}. "
                "Filtering the Findings sheet does not update these counts. "
                # Always: month and truth-value names in other Excel languages
                # ("Okt-1", "WAHR") are not recognised above. Says what the
                # design follows, not that a workbook was checked in Excel.
                "Counts follow English-language Excel's matching rules; in another "
                "language a host or STIG named like a date or TRUE/FALSE may be "
                "counted differently. "
                "See README for details."
            ),
        )
        note_cell.font = Font(name="Arial", size=9, italic=True, color="808080")
        ws.merge_cells(
            start_row=row, start_column=1,
            end_row=row, end_column=6,
        )

        _autofit_summary(ws, len(_SOURCES_HEADERS), row)

    @staticmethod
    def _write_reference_sources(ws, row: int, enrichment: EnrichmentReport) -> int:
        """Write the Reference sources table from *row*; return the row after its spacer.

        One row per source the run loaded (embedded ones too), then three
        totals, so a finding that was matched but refused is never counted as
        "not found". Every string here comes from an upload (a loaded report
        included), so each passes ``_sanitize_cell``.
        """
        h, b = _h, _b
        h(ws, row, 1, "Reference sources")
        row += 1
        for ci, lbl in enumerate(_SOURCES_HEADERS, 1):
            h(ws, row, ci, lbl)
        row += 1
        for src in enrichment.sources:
            counts = enrichment.source_counts.get(source_key(src), {})
            values = [
                src.file_name, src.title, src.edition, src.release,
                "yes" if src.embedded else "no", src.rule_count,
                counts.get("filled_check", 0), counts.get("filled_fix", 0), counts.get("drifted", 0),
                counts.get("filled_severity", 0),
            ]
            for ci, value in enumerate(values, 1):
                b(ws, row, ci, _sanitize_cell(value))
            row += 1
        stigs = enrichment.stigs.values()
        for label, total in (
            ("Not found in any supplied reference", sum(c.unmatched for c in stigs)),
            ("Matches more than one rule or STIG — not filled", sum(c.ambiguous for c in stigs)),
            ("STIG ID found under a different STIG title — not filled", sum(c.product_refused for c in stigs)),
        ):
            b(ws, row, 1, label)
            b(ws, row, 2, total)
            row += 1
        return row + 1  # spacer

    # ------------------------------------------------------------------
    # Delta summary sheet
    # ------------------------------------------------------------------

    def _write_delta_summary(self, ws, delta: DeltaResult) -> None:
        severities = ["CAT I", "CAT II", "CAT III"]
        h, b, countifs2 = partial(_h, ws), partial(_b, ws), _countifs2

        row = 1

        # ── Table 1: Delta status × severity ──────────────────────────
        h(row, 1, "Delta Summary")
        row += 1
        for ci, lbl in enumerate(["Delta", *severities, "Total"], 1):
            h(row, ci, lbl)
        row += 1

        for ds in DELTA_STATUSES:
            b(row, 1, ds)
            for ci, sev in enumerate(severities, 2):
                b(row, ci, countifs2(
                    _DELTA_COL_DELTA, _formula_quote(ds),
                    _DELTA_COL_SEVERITY, _formula_quote(sev),
                ))
            # Total counts the Delta column directly rather than SUMming the
            # three CAT columns: severity is NOT guaranteed to be one of them.
            # Both benchmark_parser and cklb_parser emit "Unknown" when the
            # source attribute is missing or unrecognized, and this table is
            # the delta workbook's only count surface — a SUM would drop those
            # findings silently. Counting independently makes an unrecognized
            # severity show up as a visible B+C+D < Total discrepancy instead.
            b(row, 5, f'=COUNTIF({_FINDINGS_SHEET}!'
                      f'${_DELTA_COL_DELTA}:${_DELTA_COL_DELTA},'
                      f'{_formula_quote(ds)})')
            row += 1
        row += 1  # spacer

        # ── Table 2: Coverage ─────────────────────────────────────────
        # Each compared host on its own row (column B) under the count, and
        # one row per (host, STIG) pair that was NOT compared — host in
        # column B, STIG in column C — so a STIG nobody re-scanned can never
        # be read as remediated. A blank STIG title (scan matched no
        # benchmark) is spelled out rather than left as an empty cell that
        # reads as "nothing missing". The pairs are split as the warning
        # lines split them (coverage_gaps): a pair of a host both runs
        # scanned, one of them with no STIG title, is not "not re-scanned",
        # it cannot be verified. All values are scan-derived text.
        gaps = coverage_gaps(delta)
        h(row, 1, "Coverage")
        row += 1
        b(row, 1, "Hosts compared")
        b(row, 2, len(delta.common_hosts))
        row += 1
        for host in sorted(delta.common_hosts):
            b(row, 2, _sanitize_cell(host))
            row += 1
        for label, pairs in (
            ("Host / STIG pairs not re-scanned", gaps.not_rescanned),
            ("Host / STIG pairs newly scanned", gaps.newly_scanned),
            ("Host / STIG pairs that cannot be verified as re-scanned (a run has no STIG title "
             "for the host)", gaps.unverifiable),
        ):
            b(row, 1, label)
            b(row, 2, len(pairs))
            row += 1
            for host, stig in sorted(pairs):
                b(row, 2, _sanitize_cell(host))
                b(row, 3, _sanitize_cell(stig.strip() or "(no STIG title)"))
                row += 1
        row += 1  # spacer

        # ── Table 3: Warnings ─────────────────────────────────────────
        # The CLI also prints these, but terminal output is gone by the time
        # someone opens this workbook for accreditation months later — and the
        # coverage warning specifically says Resolved counts may be unreliable.
        # Omitted entirely on a clean run so an empty heading never implies
        # something went wrong.
        row = _write_warnings(ws, row, "Warnings", delta.warnings)

        # ── Footer note ───────────────────────────────────────────────
        note = ws.cell(
            row=row,
            column=1,
            value=(
                "Note: 'Resolved' means a baseline finding is absent from the "
                "current scan of the SAME host and STIG. Pairs not re-scanned, "
                "or without a STIG title, are listed above; their findings are "
                "never counted as resolved."
            ),
        )
        note.font = Font(name="Arial", size=9, italic=True, color="808080")
        ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=5)

        _autofit_summary(ws, 5, row)
