"""Excel workbook generation using openpyxl."""
from __future__ import annotations

import logging
from collections.abc import Sequence
from functools import partial
from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from app.parsers.base import Finding
from app.processors.delta import DELTA_STATUSES, DeltaFinding, DeltaResult

log = logging.getLogger(__name__)

# Sheet the Summary COUNTIFS/COUNTIF formulas address.
_FINDINGS_SHEET = "Findings"

# Excel/Calc treat a leading =, +, -, @, or control char as a formula.
# Scan-derived text (hostname, check/fix text) is attacker-controllable, so
# any such value is prefixed with an apostrophe to force literal-text display.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "|", "\t", "\r")


def _sanitize_cell(value: object) -> object:
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def _formula_quote(value: object) -> str:
    """Return an Excel double-quoted string literal with embedded quotes escaped.

    Values interpolated into COUNTIFS criteria (hostname, STIG title) are
    scan-derived and attacker-controllable. Excel escapes a literal " inside a
    quoted string as "". Without this, a value containing a " breaks out of the
    criteria literal and lets the upload author inject arbitrary formula text
    into the accreditation-facing Summary sheet (CWE-1236).
    """
    return '"' + str(value).replace('"', '""') + '"'


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
]

_WRAP_HEADERS = {"Check Text", "Fix Text"}

# Findings sheet column letters (A=1 … I=9)
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
]

# Delta findings sheet column letters (for Summary COUNTIFS)
_DELTA_COL_DELTA    = "A"   # col 1
_DELTA_COL_SEVERITY = "E"   # col 5


def _h(ws, row: int, col: int, text):
    """Write a header-styled cell."""
    cell = ws.cell(row=row, column=col, value=text)
    cell.font = _HEADER_FONT
    return cell


def _b(ws, row: int, col: int, value):
    """Write a body-styled cell."""
    cell = ws.cell(row=row, column=col, value=value)
    cell.font = _BODY_FONT
    return cell


def _countifs2(col_a: str, crit_a: str, col_b: str, crit_b: str) -> str:
    """A two-criteria COUNTIFS over the Findings sheet.

    *crit_a* / *crit_b* must already be Excel string literals — pass
    scan-derived values through ``_formula_quote`` (CWE-1236).
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
        cell.alignment = Alignment(vertical="center")

    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:{get_column_letter(len(cols))}1"

    # Data rows
    for row_idx, record in enumerate(rows, start=2):
        for col_idx, (header, attr, _mw) in enumerate(cols, start=1):
            value = getattr(record, attr, "")
            wrap = header in _WRAP_HEADERS
            cell = ws.cell(row=row_idx, column=col_idx, value=_sanitize_cell(value))
            cell.font = _BODY_FONT
            cell.alignment = Alignment(
                wrap_text=wrap,
                vertical="top" if wrap else "center",
            )
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


class ExcelExporter:
    """Generate an Excel workbook from a list of Finding objects."""

    def export(self, findings: list[Finding], output_path: Path) -> Path:
        """Write *findings* to *output_path* and return it.

        Raises ValueError when *findings* is empty.
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
        self._write_summary(summary_ws, findings)

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

    def _write_summary(self, ws, findings: list[Finding]) -> None:
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

        # ── Table 2: By Server ────────────────────────────────────────
        h(ws, row, 1, "Findings by Server")
        row += 1
        for ci, lbl in enumerate(["Server", "IP Address", *severities, "Total"], 1):
            h(ws, row, ci, lbl)
        row += 1

        for server, ip in _unique_pairs(findings, "server", "ip_address"):
            b(ws, row, 1, _sanitize_cell(server))
            b(ws, row, 2, _sanitize_cell(ip))
            for ci, sev in enumerate(severities, 3):
                b(ws, row, ci, countifs2(_COL_SERVER, _formula_quote(server), _COL_SEVERITY, f'"{sev}"'))
            b(ws, row, 6, f"=SUM(C{row}:E{row})")
            row += 1
        row += 1  # spacer

        # ── Table 3: By STIG ──────────────────────────────────────────
        h(ws, row, 1, "Findings by STIG")
        row += 1
        for ci, lbl in enumerate(["STIG Title", *severities, "Total"], 1):
            h(ws, row, ci, lbl)
        row += 1

        for stig in _unique_values(findings, "stig_title"):
            b(ws, row, 1, _sanitize_cell(stig))
            for ci, sev in enumerate(severities, 2):
                b(ws, row, ci, countifs2(_COL_STIG, _formula_quote(stig), _COL_SEVERITY, f'"{sev}"'))
            b(ws, row, 5, f"=SUM(B{row}:D{row})")
            row += 1
        row += 1  # spacer

        # ── Footer note ───────────────────────────────────────────────
        note_cell = ws.cell(
            row=row,
            column=1,
            value=(
                "Note: Counts use COUNTIFS and reflect all data. "
                "Filtering the Findings sheet does not update these counts. "
                "See README for details."
            ),
        )
        note_cell.font = Font(name="Arial", size=9, italic=True, color="808080")
        ws.merge_cells(
            start_row=row, start_column=1,
            end_row=row, end_column=6,
        )

        _autofit_summary(ws, 6, row)

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
        h(row, 1, "Coverage")
        row += 1
        b(row, 1, "Hosts compared")
        b(row, 2, len(delta.common_hosts))
        row += 1
        b(row, 1, "Hosts not re-scanned")
        b(row, 2, len(delta.only_baseline_hosts))
        row += 1
        for host in sorted(delta.only_baseline_hosts):
            b(row, 2, _sanitize_cell(host))
            row += 1
        b(row, 1, "New hosts")
        b(row, 2, len(delta.only_current_hosts))
        row += 1
        for host in sorted(delta.only_current_hosts):
            b(row, 2, _sanitize_cell(host))
            row += 1
        row += 1  # spacer

        # ── Table 3: Warnings ─────────────────────────────────────────
        # The CLI also prints these, but terminal output is gone by the time
        # someone opens this workbook for accreditation months later — and the
        # coverage warning specifically says Resolved counts may be unreliable.
        # Omitted entirely on a clean run so an empty heading never implies
        # something went wrong.
        if delta.warnings:
            h(row, 1, "Warnings")
            row += 1
            for warning in delta.warnings:
                cell = b(row, 1, _sanitize_cell(warning))
                # Warnings interpolate scanner-supplied hostnames and can run
                # long; wrap rather than letting one spill across the sheet.
                cell.alignment = Alignment(wrap_text=True, vertical="top")
                row += 1
            row += 1  # spacer

        # ── Footer note ───────────────────────────────────────────────
        note = ws.cell(
            row=row,
            column=1,
            value=(
                "Note: 'Resolved' means a baseline finding is absent from the "
                "current scan on a host present in BOTH runs. Hosts not "
                "re-scanned are listed above and are never counted as resolved."
            ),
        )
        note.font = Font(name="Arial", size=9, italic=True, color="808080")
        ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=5)

        _autofit_summary(ws, 5, row)


def _unique_pairs(
    findings: list[Finding], attr1: str, attr2: str
) -> list[tuple[str, str]]:
    seen: dict[tuple[str, str], None] = {}
    for f in findings:
        key = (getattr(f, attr1, ""), getattr(f, attr2, ""))
        seen.setdefault(key, None)
    return list(seen)


def _unique_values(findings: list[Finding], attr: str) -> list[str]:
    seen: dict[str, None] = {}
    for f in findings:
        seen.setdefault(getattr(f, attr, ""), None)
    return [v for v in seen if v]
