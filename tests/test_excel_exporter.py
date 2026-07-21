"""Tests for ExcelExporter."""
from pathlib import Path

import pytest
from openpyxl import load_workbook

from openpyxl.utils import get_column_letter

from app.exporters.excel_exporter import (
    ExcelExporter,
    _DELTA_COL_DELTA,
    _DELTA_COL_SEVERITY,
    _DELTA_COLS,
    _FORMULA_PREFIXES,
    _formula_quote,
    _sanitize_cell,
)
from app.parsers.base import Finding
from app.processors.delta import DeltaFinding, DeltaResult


def _finding(
    status: str = "Open",
    severity: str = "CAT I",
    server: str = "SERVER01",
    ip: str = "10.0.0.1",
    stig_title: str = "Windows Server 2022 STIG",
    vuln_id: str = "V-254239",
    rule_id: str = "SV-254239r945408_rule",
    check: str = "Check text here.",
    fix: str = "Fix text here.",
) -> Finding:
    return Finding(
        stig_title=stig_title,
        vuln_id=vuln_id,
        rule_id=rule_id,
        severity=severity,
        status=status,
        server=server,
        ip_address=ip,
        check_text=check,
        fix_text=fix,
    )


@pytest.fixture()
def sample_findings():
    return [
        _finding("Open",        "CAT I",   "SERVER01"),
        _finding("Not Reviewed","CAT II",  "SERVER02"),
        _finding("Error",       "CAT III", "SERVER01"),
        _finding("Unknown",     "CAT II",  "SERVER02"),
    ]


@pytest.fixture()
def workbook(tmp_path, sample_findings):
    exporter = ExcelExporter()
    path = tmp_path / "findings.xlsx"
    exporter.export(sample_findings, path)
    return load_workbook(str(path))


class TestFindingsSheet:
    def test_sheet_exists(self, workbook):
        assert "Findings" in workbook.sheetnames

    def test_header_row(self, workbook):
        ws = workbook["Findings"]
        headers = [ws.cell(1, c).value for c in range(1, 10)]
        assert "STIG Title" in headers
        assert "Severity" in headers
        assert "Status" in headers
        assert "Check Text" in headers
        assert "Fix Text" in headers

    def test_data_rows(self, workbook):
        ws = workbook["Findings"]
        # 4 data rows + 1 header = max_row 5
        assert ws.max_row == 5

    def test_freeze_pane(self, workbook):
        ws = workbook["Findings"]
        assert ws.freeze_panes == "A2"

    def test_auto_filter_set(self, workbook):
        ws = workbook["Findings"]
        assert ws.auto_filter.ref is not None


class TestSummarySheet:
    def test_sheet_exists(self, workbook):
        assert "Summary" in workbook.sheetnames

    def test_table1_header(self, workbook):
        ws = workbook["Summary"]
        # "Findings by Severity" should appear somewhere in col 1
        col1_values = [ws.cell(r, 1).value for r in range(1, ws.max_row + 1)]
        assert "Findings by Severity" in col1_values

    def test_table2_header(self, workbook):
        ws = workbook["Summary"]
        col1_values = [ws.cell(r, 1).value for r in range(1, ws.max_row + 1)]
        assert "Findings by Server" in col1_values

    def test_table3_header(self, workbook):
        ws = workbook["Summary"]
        col1_values = [ws.cell(r, 1).value for r in range(1, ws.max_row + 1)]
        assert "Findings by STIG" in col1_values

    def test_countifs_formulas_present(self, workbook):
        ws = workbook["Summary"]
        formula_cells = []
        for row in ws.iter_rows():
            for cell in row:
                if isinstance(cell.value, str) and cell.value.startswith("=COUNTIFS"):
                    formula_cells.append(cell.value)
        assert len(formula_cells) > 0, "No COUNTIFS formulas found in Summary sheet"

    def test_countifs_reference_findings_sheet(self, workbook):
        ws = workbook["Summary"]
        formula_cells = [
            cell.value
            for row in ws.iter_rows()
            for cell in row
            if isinstance(cell.value, str) and cell.value.startswith("=COUNTIFS")
        ]
        assert len(formula_cells) > 0
        assert all("Findings!" in v for v in formula_cells)


class TestFormulaInjection:
    """Guards the CWE-1236 fix: scan-derived text must never execute as a
    formula in the accreditation-facing workbook."""

    # ── _formula_quote: values interpolated into COUNTIFS criteria ────────
    def test_formula_quote_wraps_plain_value(self):
        assert _formula_quote("SERVER01") == '"SERVER01"'

    def test_formula_quote_escapes_embedded_double_quote(self):
        # A bare " would close the criteria literal and let the rest of the
        # value become live formula text; it must be doubled per Excel rules.
        assert _formula_quote('a"b') == '"a""b"'

    def test_formula_quote_neutralizes_criteria_breakout(self):
        # Classic breakout payload: close the string, inject a call, reopen.
        payload = '","")+cmd|calc!A1&COUNTIF(A:A,"'
        quoted = _formula_quote(payload)
        # Every input quote is doubled; no lone " survives to break the literal.
        assert quoted.count('""') == payload.count('"')
        assert quoted.startswith('"') and quoted.endswith('"')

    def test_formula_quote_stringifies_non_str(self):
        assert _formula_quote(42) == '"42"'

    # ── _sanitize_cell: leading formula-trigger characters ────────────────
    @pytest.mark.parametrize("prefix", _FORMULA_PREFIXES)
    def test_sanitize_prefixes_dangerous_leading_char(self, prefix):
        payload = f"{prefix}HYPERLINK(\"http://evil\")"
        assert _sanitize_cell(payload) == "'" + payload

    def test_sanitize_leaves_safe_value_untouched(self):
        assert _sanitize_cell("SERVER01") == "SERVER01"

    def test_sanitize_passes_non_str_through(self):
        assert _sanitize_cell(7) == 7

    # ── End-to-end: the saved workbook is not injectable ──────────────────
    def test_malicious_server_is_escaped_in_summary_countifs(self, tmp_path):
        evil = 'HOST","")+SUM(1,1)+COUNTIF(A:A,"'
        exporter = ExcelExporter()
        path = tmp_path / "evil.xlsx"
        exporter.export([_finding(server=evil)], path)
        wb = load_workbook(str(path))
        ws = wb["Summary"]

        countifs = [
            cell.value
            for row in ws.iter_rows()
            for cell in row
            if isinstance(cell.value, str) and cell.value.startswith("=COUNTIFS")
        ]
        server_formulas = [f for f in countifs if "$F:$F" in f]
        assert server_formulas, "no By-Server COUNTIFS formula found"
        for f in server_formulas:
            # The payload's quotes must be doubled inside the formula; a lone
            # HOST" fragment would mean the literal was broken out of.
            assert 'HOST""' in f
            assert 'HOST","' not in f

    def test_malicious_leading_char_is_neutralized_in_findings_sheet(self, tmp_path):
        evil = '=1+1'
        exporter = ExcelExporter()
        path = tmp_path / "lead.xlsx"
        exporter.export([_finding(server=evil)], path)
        wb = load_workbook(str(path))
        ws = wb["Findings"]

        # Server is column F (6); data starts at row 2.
        cell = ws.cell(row=2, column=6).value
        assert cell == "'=1+1", "leading '=' was not neutralized to literal text"
        # data_type 's' (string), not 'f' (formula) — Excel won't evaluate it.
        assert ws.cell(row=2, column=6).data_type == "s"


class TestErrorCases:
    def test_empty_findings_raises(self, tmp_path):
        exporter = ExcelExporter()
        with pytest.raises(ValueError, match="No findings"):
            exporter.export([], tmp_path / "empty.xlsx")

    def test_output_file_created(self, tmp_path):
        exporter = ExcelExporter()
        path = tmp_path / "output.xlsx"
        exporter.export([_finding()], path)
        assert path.exists()


def _delta_finding(
    delta_status: str,
    vuln_id: str = "V-1",
    server: str = "SERVER01",
    severity: str = "CAT I",
    baseline_status: str = "Open",
    current_status: str = "Open",
) -> DeltaFinding:
    return DeltaFinding(
        stig_title="Win2022 STIG",
        vuln_id=vuln_id,
        rule_id="SV-1r1_rule",
        severity=severity,
        server=server,
        ip_address="10.0.0.1",
        check_text="check",
        fix_text="fix",
        delta_status=delta_status,
        baseline_status=baseline_status,
        current_status=current_status,
    )


def test_export_delta_findings_sheet_has_delta_column(tmp_path):
    result = DeltaResult(
        findings=[
            _delta_finding("New", "V-2", current_status="Open"),
            _delta_finding("Resolved", "V-3", current_status=""),
            _delta_finding("Persisting", "V-1"),
        ],
        common_hosts={"SERVER01"},
    )
    out = tmp_path / "delta.xlsx"
    ExcelExporter().export_delta(result, out)

    wb = load_workbook(out)
    ws = wb["Findings"]
    assert ws.cell(row=1, column=1).value == "Delta"
    tags = {ws.cell(row=r, column=1).value for r in range(2, ws.max_row + 1)}
    assert tags == {"New", "Resolved", "Persisting"}


_EXPECTED_DELTA_HEADERS = [
    "Delta", "STIG Title", "Vuln ID", "Rule ID", "Severity",
    "Baseline Status", "Current Status", "Server", "IP Address",
    "Check Text", "Fix Text",
]


def test_delta_findings_layout_header_and_row_order(tmp_path):
    """Pin the whole 11-column layout — headers and the values beneath them."""
    result = DeltaResult(
        findings=[
            _delta_finding(
                "New",
                vuln_id="V-9",
                severity="CAT III",
                baseline_status="Not Reviewed",
                current_status="Open",
            )
        ],
        common_hosts={"SERVER01"},
    )
    out = tmp_path / "delta.xlsx"
    ExcelExporter().export_delta(result, out)
    ws = load_workbook(out)["Findings"]

    ncols = len(_EXPECTED_DELTA_HEADERS)
    assert [ws.cell(row=1, column=c).value for c in range(1, ncols + 1)] == (
        _EXPECTED_DELTA_HEADERS
    )
    assert ws.cell(row=1, column=ncols + 1).value is None, "unexpected extra column"
    assert [ws.cell(row=2, column=c).value for c in range(1, ncols + 1)] == [
        "New", "Win2022 STIG", "V-9", "SV-1r1_rule", "CAT III",
        "Not Reviewed", "Open", "SERVER01", "10.0.0.1", "check", "fix",
    ]


@pytest.mark.parametrize(
    ("header", "constant"),
    [("Delta", _DELTA_COL_DELTA), ("Severity", _DELTA_COL_SEVERITY)],
)
def test_delta_summary_countifs_columns_track_layout(header, constant):
    """The Delta Summary COUNTIFS address the Findings sheet by column letter.

    If a future edit reorders or inserts into _DELTA_COLS without updating the
    matching _DELTA_COL_* constant, every count silently evaluates to 0 — the
    workbook then shows an all-zero accreditation summary with no error. Derive
    the letter from the layout so that drift cannot happen rather than merely
    asserting today's values.
    """
    index = [h for h, _attr, _w in _DELTA_COLS].index(header)
    assert get_column_letter(index + 1) == constant


def test_delta_column_fill_per_status(tmp_path):
    """Red must mean regression and green must mean remediated — a swap here
    misreports remediation status to an accreditation reader."""
    result = DeltaResult(
        findings=[
            _delta_finding("New", "V-1"),
            _delta_finding("Resolved", "V-2", current_status=""),
            _delta_finding("Persisting", "V-3"),
        ],
        common_hosts={"SERVER01"},
    )
    out = tmp_path / "delta.xlsx"
    ExcelExporter().export_delta(result, out)
    ws = load_workbook(out)["Findings"]

    fills = {
        ws.cell(row=r, column=1).value: ws.cell(row=r, column=1).fill.start_color.rgb[-6:]
        for r in range(2, ws.max_row + 1)
    }
    assert fills == {
        "New": "FFC7CE",         # red-ish: regression
        "Resolved": "C6EFCE",    # green: remediated
        "Persisting": "FFEB9C",  # amber: still open
    }


def test_export_delta_sanitizes_formula_injection(tmp_path):
    evil = DeltaFinding(
        stig_title="=cmd()",
        vuln_id="V-1",
        rule_id="SV-1r1_rule",
        severity="CAT I",
        server="=HYPERLINK(1)",
        ip_address="10.0.0.1",
        check_text="check",
        fix_text="fix",
        delta_status="New",
        baseline_status="",
        current_status="Open",
    )
    out = tmp_path / "delta.xlsx"
    ExcelExporter().export_delta(
        DeltaResult(findings=[evil], only_current_hosts={"=HYPERLINK(1)"}), out
    )
    wb = load_workbook(out)
    ws = wb["Findings"]
    # STIG Title is column 2 in the delta layout
    title_cell = next(
        ws.cell(row=r, column=2).value for r in range(2, ws.max_row + 1)
    )
    assert str(title_cell).startswith("'=")

    # The coverage block on the Summary sheet echoes hostnames verbatim, so
    # it needs the same neutralization.
    summary = wb["Summary"]
    host_cells = [
        summary.cell(row=r, column=2).value
        for r in range(1, summary.max_row + 1)
        if isinstance(summary.cell(row=r, column=2).value, str)
    ]
    assert "'=HYPERLINK(1)" in host_cells
    assert "=HYPERLINK(1)" not in host_cells


def test_export_delta_accepts_single_bucket_result(tmp_path):
    """An all-Resolved (or all-New) delta is a legitimate result, not an error."""
    result = DeltaResult(
        findings=[
            _delta_finding("Resolved", "V-1", current_status=""),
            _delta_finding("Resolved", "V-2", current_status=""),
        ],
        common_hosts={"SERVER01"},
    )
    out = tmp_path / "delta.xlsx"
    ExcelExporter().export_delta(result, out)
    assert out.exists()


def test_export_delta_empty_raises(tmp_path):
    with pytest.raises(ValueError, match="Empty delta"):
        ExcelExporter().export_delta(DeltaResult(), tmp_path / "empty.xlsx")


def test_export_delta_summary_has_coverage_block(tmp_path):
    result = DeltaResult(
        findings=[_delta_finding("Persisting", "V-1", server="SERVER01")],
        common_hosts={"SERVER01"},
        only_baseline_hosts={"OLDHOST"},
        only_current_hosts={"NEWHOST"},
    )
    out = tmp_path / "delta.xlsx"
    ExcelExporter().export_delta(result, out)

    wb = load_workbook(out)
    ws = wb["Summary"]
    text = "\n".join(
        str(ws.cell(row=r, column=c).value)
        for r in range(1, ws.max_row + 1)
        for c in range(1, 4)
        if ws.cell(row=r, column=c).value is not None
    )
    assert "OLDHOST" in text     # not re-scanned host listed
    assert "NEWHOST" in text     # new host listed
    assert "Coverage" in text


def test_export_delta_summary_counts_by_status(tmp_path):
    result = DeltaResult(
        findings=[
            _delta_finding("New", "V-2", severity="CAT I"),
            _delta_finding("Resolved", "V-3", severity="CAT II"),
            _delta_finding("Persisting", "V-1", severity="CAT II"),
        ],
        common_hosts={"SERVER01"},
    )
    out = tmp_path / "delta.xlsx"
    ExcelExporter().export_delta(result, out)
    wb = load_workbook(out)
    ws = wb["Summary"]
    labels = {
        str(ws.cell(row=r, column=1).value)
        for r in range(1, ws.max_row + 1)
    }
    assert "Delta Summary" in labels
    assert "New" in labels and "Resolved" in labels and "Persisting" in labels


def _summary_col1(ws) -> list[str]:
    return [
        str(ws.cell(row=r, column=1).value)
        for r in range(1, ws.max_row + 1)
        if ws.cell(row=r, column=1).value is not None
    ]


def test_export_delta_summary_renders_warnings(tmp_path):
    """The workbook outlives the CLI run, so warnings must be durable in it."""
    warning = (
        "Baseline and current scans have different Vuln-ID coverage on hosts "
        "common to both runs (0% vs 40% of findings missing a Vuln-ID) — this "
        "usually means --benchmarks was supplied for only one run. "
        "Resolved/New counts on those hosts may be unreliable."
    )
    result = DeltaResult(
        findings=[_delta_finding("Persisting", "V-1")],
        common_hosts={"SERVER01"},
        warnings=[warning],
    )
    out = tmp_path / "delta.xlsx"
    ExcelExporter().export_delta(result, out)

    ws = load_workbook(out)["Summary"]
    col1 = _summary_col1(ws)
    assert "Warnings" in col1
    assert warning in col1, "warning text must be stored whole, not truncated"
    # Falsifiable width guard: this warning is far longer than the column cap,
    # so without the cap the measured width would track its full length. (A
    # `<= 60` assertion would be unfalsifiable — the footer note already pins
    # column A at exactly 60 whether or not any warning exists.)
    assert len(warning) > 60
    assert ws.column_dimensions["A"].width < len(warning)


def test_export_delta_summary_omits_warnings_block_when_clean(tmp_path):
    """A clean run shouldn't show an empty heading implying something failed."""
    result = DeltaResult(
        findings=[_delta_finding("Persisting", "V-1")],
        common_hosts={"SERVER01"},
    )
    out = tmp_path / "delta.xlsx"
    ExcelExporter().export_delta(result, out)

    ws = load_workbook(out)["Summary"]
    assert "Warnings" not in _summary_col1(ws)


def test_export_delta_summary_sanitizes_warning_text(tmp_path):
    """Warning text embeds scan-derived hostnames, so it is attacker-influenced."""
    result = DeltaResult(
        findings=[_delta_finding("Persisting", "V-1")],
        common_hosts={"SERVER01"},
        warnings=['=HYPERLINK("http://evil") duplicate finding'],
    )
    out = tmp_path / "delta.xlsx"
    ExcelExporter().export_delta(result, out)

    ws = load_workbook(out)["Summary"]
    col1 = _summary_col1(ws)
    assert '\'=HYPERLINK("http://evil") duplicate finding' in col1
    assert '=HYPERLINK("http://evil") duplicate finding' not in col1
