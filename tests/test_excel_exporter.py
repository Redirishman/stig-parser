"""Tests for ExcelExporter."""
import re
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
from app.processors.delta import DELTA_STATUSES, DeltaFinding, DeltaResult


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
    stig_id: str = "",
    text_source: str = "",
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
        stig_id=stig_id,
        text_source=text_source,
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
    "Check Text", "Fix Text", "STIG ID", "Text Source",
]


def test_delta_findings_layout_header_and_row_order(tmp_path):
    """Pin the whole 13-column layout — headers and the values beneath them."""
    result = DeltaResult(
        findings=[
            _delta_finding(
                "New",
                vuln_id="V-9",
                severity="CAT III",
                baseline_status="Not Reviewed",
                current_status="Open",
                stig_id="WN22-00-000090",
                text_source="Check and fix: scanner",
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
        "WN22-00-000090", "Check and fix: scanner",
    ]


def _delta_col_letter(header: str) -> str:
    """Column letter the live _DELTA_COLS layout assigns to *header*."""
    return get_column_letter([h for h, _a, _w in _DELTA_COLS].index(header) + 1)


def _row_of(ws, label: str) -> int:
    """Row number whose column A equals *label*."""
    return next(
        r for r in range(1, ws.max_row + 1) if ws.cell(row=r, column=1).value == label
    )


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
            _delta_finding("Not re-scanned", "V-4", current_status=""),
            _delta_finding("Newly scanned", "V-5", baseline_status=""),
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
    assert set(fills) == set(DELTA_STATUSES), "every status must carry a fill"
    assert fills == {
        "New": "FFC7CE",             # red-ish: regression
        "Resolved": "C6EFCE",        # green: remediated
        "Persisting": "FFEB9C",      # amber: still open
        "Not re-scanned": "D9D9D9",  # grey: nothing to compare against
        "Newly scanned": "DDEBF7",   # light blue: nothing to compare against
    }


def test_delta_findings_sheet_freeze_filter_and_wrap(tmp_path):
    result = DeltaResult(findings=[_delta_finding("New")], common_hosts={"SERVER01"})
    out = tmp_path / "delta.xlsx"
    ExcelExporter().export_delta(result, out)
    ws = load_workbook(out)["Findings"]

    assert ws.freeze_panes == "A2"
    assert ws.auto_filter.ref == f"A1:{get_column_letter(len(_DELTA_COLS))}1"
    # Long free text wraps; short identifiers must not.
    for header in ("Check Text", "Fix Text"):
        col = ws[f"{_delta_col_letter(header)}2"]
        assert col.alignment.wrap_text, f"{header} should wrap"
        assert col.alignment.vertical == "top"
    for header in ("Delta", "Severity", "Server"):
        col = ws[f"{_delta_col_letter(header)}2"]
        assert not col.alignment.wrap_text, f"{header} should not wrap"


def test_delta_summary_countifs_addresses_live_layout(tmp_path):
    """Assert the formulas the writer actually emits, with expected column
    letters derived from _DELTA_COLS.

    Comparing the module constants to _DELTA_COLS (above) never invokes the
    writer, so it cannot catch a wrong letter hardcoded inside the writer, nor
    the formulas being dropped entirely. Either produces an all-zero
    accreditation summary with no error.
    """
    out = tmp_path / "delta.xlsx"
    ExcelExporter().export_delta(
        DeltaResult(findings=[_delta_finding("New")], common_hosts={"SERVER01"}), out
    )
    ws = load_workbook(out)["Summary"]

    formulas = {
        c.value
        for r in ws.iter_rows()
        for c in r
        if isinstance(c.value, str) and c.value.startswith("=COUNTIFS")
    }
    d = _delta_col_letter("Delta")
    s = _delta_col_letter("Severity")
    expected = {
        f'=COUNTIFS(Findings!${d}:${d},"{status}",Findings!${s}:${s},"{sev}")'
        for status in DELTA_STATUSES
        for sev in ("CAT I", "CAT II", "CAT III")
    }
    assert formulas == expected
    assert len(DELTA_STATUSES) == 5  # spec R2-5
    assert len(formulas) == 3 * len(DELTA_STATUSES)  # every status x 3 severities


def test_delta_summary_total_is_severity_independent(tmp_path):
    """severity is not guaranteed to be CAT I/II/III — benchmark_parser and
    cklb_parser both emit "Unknown". A SUM over the three CAT columns would
    drop those findings from the delta workbook's only count surface."""
    result = DeltaResult(
        findings=[
            _delta_finding("New", "V-1", severity="CAT I"),
            _delta_finding("New", "V-2", severity="Unknown"),
            _delta_finding("New", "V-3", severity="Unknown"),
        ],
        common_hosts={"SERVER01"},
    )
    out = tmp_path / "delta.xlsx"
    ExcelExporter().export_delta(result, out)
    wb = load_workbook(out)

    assert wb["Findings"].max_row == 4, "3 findings + header"
    ws = wb["Summary"]
    d = _delta_col_letter("Delta")
    total = ws.cell(row=_row_of(ws, "New"), column=5).value
    assert total == f'=COUNTIF(Findings!${d}:${d},"New")'


def test_delta_summary_has_a_row_per_status(tmp_path):
    """Spec R2-5: the Summary counts every status, so a reader sees how much
    of the baseline was never compared (Not re-scanned) next to Resolved."""
    out = tmp_path / "delta.xlsx"
    ExcelExporter().export_delta(
        DeltaResult(findings=[_delta_finding("New")], common_hosts={"SERVER01"}), out
    )
    ws = load_workbook(out)["Summary"]
    d = _delta_col_letter("Delta")
    for status in DELTA_STATUSES:
        r = _row_of(ws, status)
        assert ws.cell(row=r, column=5).value == f'=COUNTIF(Findings!${d}:${d},"{status}")'


def test_delta_summary_coverage_block_lists_pairs(tmp_path):
    """The Coverage block names every (host, STIG) pair that was not compared
    — host in column B, STIG in column C, one row per pair — so a STIG that
    nobody re-scanned can never be read as remediated. Assert it
    positionally, not by substring search over a flattened blob."""
    not_rescanned = {("SERVER01", "Microsoft Edge STIG"), ("OLDHOST", "Win2022 STIG")}
    newly_scanned = {("NEWHOST", "Win11 STIG")}
    result = DeltaResult(
        findings=[_delta_finding("Persisting", "V-1")],
        common_hosts={"SERVER01", "SERVER02", "SERVER03"},
        only_baseline_hosts={"OLDHOST"},
        only_current_hosts={"NEWHOST"},
        not_rescanned_pairs=not_rescanned,
        newly_scanned_pairs=newly_scanned,
    )
    out = tmp_path / "delta.xlsx"
    ExcelExporter().export_delta(result, out)
    ws = load_workbook(out)["Summary"]

    # Distinct counts (3 / 2 / 1) so a bucket mix-up can't coincidentally match.
    assert ws.cell(row=_row_of(ws, "Hosts compared"), column=2).value == 3

    for label, pairs in (
        ("Host / STIG pairs not re-scanned", not_rescanned),
        ("Host / STIG pairs newly scanned", newly_scanned),
    ):
        r = _row_of(ws, label)
        assert ws.cell(row=r, column=2).value == len(pairs), f"{label} count"
        listed = [
            (ws.cell(row=r + 1 + i, column=2).value, ws.cell(row=r + 1 + i, column=3).value)
            for i in range(len(pairs))
        ]
        assert listed == sorted(pairs), f"{label} pair rows"


def test_delta_summary_coverage_block_names_blank_stig_title(tmp_path):
    """A pair whose STIG title is blank (the scan matched no benchmark)
    shows "(no STIG title)" in the STIG cell — never an empty cell, which
    reads as "nothing missing". SERVER01 is not in the current run, so its
    pair was not re-scanned; were it in both runs, the untitled pair would be
    listed as one that cannot be verified instead (as the warnings say)."""
    for hosts, heading in (
        ({"only_baseline_hosts": {"SERVER01"}}, "Host / STIG pairs not re-scanned"),
        ({"common_hosts": {"SERVER01"}},
         "Host / STIG pairs that cannot be verified as re-scanned (a run has no STIG title for the host)"),
    ):
        result = DeltaResult(
            findings=[_delta_finding("Not re-scanned", "V-1", current_status="")],
            not_rescanned_pairs={("SERVER01", "")},
            **hosts,
        )
        out = tmp_path / "delta.xlsx"
        ExcelExporter().export_delta(result, out)
        ws = load_workbook(out)["Summary"]
        r = _row_of(ws, heading)
        assert ws.cell(row=r, column=2).value == 1
        assert ws.cell(row=r + 1, column=2).value == "SERVER01"
        assert ws.cell(row=r + 1, column=3).value == "(no STIG title)"


def test_delta_summary_coverage_count_matches_not_rescanned_rows(tmp_path):
    """The Coverage count must agree with the Findings sheet: every (host,
    STIG) pair that carries a Not re-scanned row is listed under "Host /
    STIG pairs not re-scanned" and the count is the number of such pairs.
    Driven through compute_delta with a blank pair present on BOTH sides —
    the case where the tags and the coverage block used to disagree ("0"
    beside non-zero Not re-scanned rows, and a footer claiming the pairs
    are "listed above")."""
    from app.processors.delta import compute_delta

    def untitled(vuln_id: str) -> Finding:
        n = vuln_id.removeprefix("V-")
        return _finding(vuln_id=vuln_id, rule_id=f"SV-{n}r1_rule", stig_title="")

    base = [untitled("V-1"), untitled("V-2")]
    curr = [untitled("V-1")]
    pair = ("SERVER01", "")
    delta = compute_delta(
        base, curr, baseline_coverage={pair}, current_coverage={pair}
    )
    out = tmp_path / "delta.xlsx"
    ExcelExporter().export_delta(delta, out)
    wb = load_workbook(out)

    fs = wb["Findings"]
    header = [fs.cell(row=1, column=c).value for c in range(1, fs.max_column + 1)]
    c_delta = header.index("Delta") + 1
    c_host = header.index("Server") + 1
    c_stig = header.index("STIG Title") + 1
    tagged = {
        (fs.cell(row=r, column=c_host).value, fs.cell(row=r, column=c_stig).value or "")
        for r in range(2, fs.max_row + 1)
        if fs.cell(row=r, column=c_delta).value == "Not re-scanned"
    }
    assert tagged == {pair}, "scenario must produce exactly one Not re-scanned pair"

    ws = wb["Summary"]
    # The blank pair is in both runs: it is listed as one that cannot be verified (as the
    # warning lines say), with the count beside it, and not under "not re-scanned".
    assert ws.cell(row=_row_of(ws, "Host / STIG pairs not re-scanned"), column=2).value == 0
    r = _row_of(ws, "Host / STIG pairs that cannot be verified as re-scanned (a run has no STIG title for the host)")
    assert ws.cell(row=r, column=2).value == len(tagged)
    listed = {
        (ws.cell(row=r + 1 + i, column=2).value, ws.cell(row=r + 1 + i, column=3).value)
        for i in range(len(tagged))
    }
    assert listed == {(host, stig or "(no STIG title)") for host, stig in tagged}


def test_delta_summary_lists_each_compared_host(tmp_path):
    """Hosts compared: the count stays in column B of the label row and
    every host is listed (sanitised) on its own row beneath it, so the
    reader sees WHICH hosts were compared, not only how many."""
    result = DeltaResult(
        findings=[_delta_finding("Persisting", "V-1")],
        common_hosts={"SERVER02", "SERVER01", "=HOST"},
    )
    out = tmp_path / "delta.xlsx"
    ExcelExporter().export_delta(result, out)
    ws = load_workbook(out)["Summary"]
    r = _row_of(ws, "Hosts compared")
    assert ws.cell(row=r, column=2).value == 3
    listed = [ws.cell(row=r + 1 + i, column=2).value for i in range(3)]
    assert listed == ["'=HOST", "SERVER01", "SERVER02"]
    # The next label follows the host rows directly.
    assert ws.cell(row=r + 4, column=1).value == "Host / STIG pairs not re-scanned"


def test_delta_summary_keeps_resolved_caveat_footer(tmp_path):
    """The sentence that stops a reader over-reading the Resolved count."""
    result = DeltaResult(
        findings=[_delta_finding("Resolved", "V-1", current_status="")],
        common_hosts={"SERVER01"},
        only_baseline_hosts={"OLDHOST"},
    )
    out = tmp_path / "delta.xlsx"
    ExcelExporter().export_delta(result, out)
    ws = load_workbook(out)["Summary"]

    text = " ".join(
        str(ws.cell(row=r, column=1).value)
        for r in range(1, ws.max_row + 1)
        if ws.cell(row=r, column=1).value is not None
    )
    assert "never counted as resolved" in text
    assert "same host and stig" in text.lower()


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
        DeltaResult(
            findings=[evil],
            only_current_hosts={"=HYPERLINK(1)"},
            newly_scanned_pairs={("=HYPERLINK(1)", "=cmd()")},
            not_rescanned_pairs={("+OLDHOST", "-Edge STIG")},
        ),
        out,
    )
    wb = load_workbook(out)
    ws = wb["Findings"]
    # STIG Title is column 2 in the delta layout
    title_cell = next(
        ws.cell(row=r, column=2).value for r in range(2, ws.max_row + 1)
    )
    assert str(title_cell).startswith("'=")

    # The coverage block on the Summary sheet echoes hostnames AND STIG
    # titles verbatim (one pair per row), so both columns need the same
    # neutralization.
    summary = wb["Summary"]
    cells = [
        summary.cell(row=r, column=c).value
        for r in range(1, summary.max_row + 1)
        for c in (2, 3)
        if isinstance(summary.cell(row=r, column=c).value, str)
    ]
    for evil_value in ("=HYPERLINK(1)", "=cmd()", "+OLDHOST", "-Edge STIG"):
        assert "'" + evil_value in cells, f"{evil_value!r} not written to the coverage block"
        assert evil_value not in cells, f"{evil_value!r} written unsanitised"


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
    # Shaped as compute_delta builds it: a host only in one side's coverage
    # always carries at least one not-re-scanned / newly-scanned pair, and
    # the Coverage block lists those pairs (spec R2-5).
    result = DeltaResult(
        findings=[_delta_finding("Persisting", "V-1", server="SERVER01")],
        common_hosts={"SERVER01"},
        only_baseline_hosts={"OLDHOST"},
        only_current_hosts={"NEWHOST"},
        not_rescanned_pairs={("OLDHOST", "Win2022 STIG")},
        newly_scanned_pairs={("NEWHOST", "Win2022 STIG")},
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
    assert "OLDHOST" in text     # not re-scanned pair listed
    assert "NEWHOST" in text     # newly scanned pair listed
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
    # Warnings interpolate scanner-supplied hostnames and run long — wrapped so
    # one entry can't spill across the sheet.
    warn_cell = ws.cell(row=_row_of(ws, warning), column=1)
    assert warn_cell.alignment.wrap_text
    assert warn_cell.alignment.vertical == "top"


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


# ── STIG ID / Text Source columns and the Reference sources table ─────────

_FIXTURES = Path(__file__).parent / "fixtures"
_SOURCES_HEADER = [
    "File", "STIG", "Edition", "Release", "Embedded in results", "Rules loaded",
    "Check text filled", "Fix text filled", "From a different release", "Severity filled",
]
_TOTAL_LABELS = (
    "Not found in any supplied reference",
    "Matches more than one rule or STIG — not filled",
    "STIG ID found under a different STIG title — not filled",
)


def _summary_rows(ws) -> list[list]:
    return [[c.value for c in row] for row in ws.iter_rows()]


def _sources_block(rows: list[list]) -> tuple[list[list], dict[str, object]]:
    """(one row per source, {total label: value}) under the Reference sources heading."""
    start = next(i for i, r in enumerate(rows) if r[0] == "Reference sources")
    assert rows[start + 1][:10] == _SOURCES_HEADER
    end = next(i for i in range(start + 2, len(rows)) if rows[i][0] in _TOTAL_LABELS)
    totals = {rows[i][0]: rows[i][1] for i in range(end, end + len(_TOTAL_LABELS))}
    assert list(totals) == list(_TOTAL_LABELS), "the three total rows, in order, under the table"
    return rows[start + 2:end], totals


class TestReferenceColumnsAndTable:
    def _run(self, tmp_path, references):
        from app.core.pipeline import export_stage, parse_stage
        result = parse_stage(
            [_FIXTURES / "scc_embedded_results.xml"], [_FIXTURES / n for n in references], tmp_path / "x"
        )
        out = tmp_path / "r.xlsx"
        export_stage(result.findings, out, enrichment=result.enrichment)
        return load_workbook(out)

    def test_new_columns_are_appended_and_old_letters_do_not_move(self, tmp_path):
        ws = self._run(tmp_path, ["manual_stig_win11.xml"])["Findings"]
        headers = [c.value for c in ws[1]]
        assert headers[:9] == ["STIG Title", "Vuln ID", "Rule ID", "Severity", "Status", "Server",
                               "IP Address", "Check Text", "Fix Text"]
        assert headers[9:] == ["STIG ID", "Text Source"]
        assert ws["J2"].value == "WN11-00-000150"
        assert ws["K2"].value == "Check: manual_stig_win11.xml V2R9 | Fix: scanner"
        assert ws["K4"].value == "Check: not in supplied references | Fix: scanner"
        assert ws["K2"].alignment.wrap_text, "Text Source wraps like Check/Fix Text"
        assert ws.auto_filter.ref == "A1:K1"

    def test_summary_formulas_still_point_at_the_same_columns(self, tmp_path):
        summary = self._run(tmp_path, ["manual_stig_win11.xml"])["Summary"]
        formulas = [c.value for row in summary.iter_rows() for c in row
                    if isinstance(c.value, str) and c.value.startswith("=COUNTIFS")]
        assert formulas and all("$D:$D" in f for f in formulas)          # Severity stays in D
        assert any("$E:$E" in f for f in formulas) and any("$F:$F" in f for f in formulas)

    def test_reference_sources_table_lists_the_supplied_reference(self, tmp_path):
        rows = _summary_rows(self._run(tmp_path, ["manual_stig_win11.xml"])["Summary"])
        body, totals = _sources_block(rows)
        # One row per source the run loaded: the Manual STIG and the benchmark the SCC file embeds.
        assert [r[:10] for r in body] == [
            ["manual_stig_win11.xml", "Microsoft Windows 11 Security Technical Implementation Guide",
             "manual", "V2R9", "no", 3, 2, 0, 1, 0],
            ["scc_embedded_results.xml", "Microsoft Windows 11 STIG SCAP Benchmark",
             "scap", "V2R8", "yes", 4, 0, 0, 0, 0],
        ]
        assert totals == dict.fromkeys(_TOTAL_LABELS, 0) | {"Not found in any supplied reference": 1}

    def test_no_reference_supplied_means_no_table(self, tmp_path):
        summary = self._run(tmp_path, [])["Summary"]
        assert all(row[0].value != "Reference sources" for row in summary.iter_rows())


def _export_with(tmp_path, report, findings=None):
    out = tmp_path / "r.xlsx"
    ExcelExporter().export(findings or [_finding()], out, enrichment=report)
    return load_workbook(out)


def test_reference_sources_counts_are_per_source_and_totals_cover_every_stig(tmp_path):
    """One checklist can hold several STIGs: one file name, several sources. Their counts are
    looked up by source_key, so they are never merged or lost, and each total sums every STIG."""
    from app.reference.enrich import EnrichmentReport, StigCounts, source_key
    from app.reference.models import ReferenceSource

    a = ReferenceSource("lib.cklb", "Product_A_STIG", "Product A STIG", "V1R2", False, "cklb", 10)
    b = ReferenceSource("lib.cklb", "Product_B_STIG", "Product B STIG", "V3R1", False, "cklb", 20)
    report = EnrichmentReport(
        stigs={
            "Product A STIG": StigCounts(unmatched=1, ambiguous=2, product_refused=3),
            "Product B STIG": StigCounts(unmatched=4, ambiguous=5, product_refused=6),
        },
        sources=[a, b],
        source_counts={
            source_key(a): {"filled_check": 7, "filled_fix": 8, "drifted": 9, "filled_severity": 2},
            source_key(b): {"filled_check": 1, "filled_fix": 0, "drifted": 0},     # a payload from before
        },
    )
    body, totals = _sources_block(_summary_rows(_export_with(tmp_path, report)["Summary"]))
    assert [r[:10] for r in body] == [
        ["lib.cklb", "Product A STIG", "cklb", "V1R2", "no", 10, 7, 8, 9, 2],
        ["lib.cklb", "Product B STIG", "cklb", "V3R1", "no", 20, 1, 0, 0, 0],
    ]
    assert totals == dict(zip(_TOTAL_LABELS, (5, 7, 9)))


def _utf16_units(text: str) -> int:
    return len(text.encode("utf-16-le")) // 2


@pytest.mark.parametrize("text, kept_whole", [
    ("\U0001F600" * 30_000, False),             # 30,000 code points, 60,000 UTF-16 units
    ("a\U0001F600" * 20_000, False),            # BMP and non-BMP mixed: 60,000 units
    ("\U0001F600" * 16_383 + "a", True),        # exactly 32,767 units
], ids=["emoji", "mixed", "at-the-limit"])     # short ids: pytest puts the id in an environment variable
def test_the_cell_limit_is_counted_in_utf16_units(tmp_path, text, kept_whole):
    # Excel counts a cell's length in UTF-16 units: a character outside the BMP is two.
    from app.exporters.excel_exporter import _TRUNCATED
    out = tmp_path / "units.xlsx"
    ExcelExporter().export([_finding(check=text)], out)
    cell = load_workbook(out)["Findings"]["H2"].value
    if kept_whole:
        assert cell == text
        return
    assert cell.endswith(_TRUNCATED) and _utf16_units(cell) <= 32_767
    kept = cell[:-len(_TRUNCATED)]
    assert text.startswith(kept)                                    # cut between characters
    assert _utf16_units(kept) + _utf16_units(_TRUNCATED) > 32_767 - 2   # and no more than needed


def test_the_cut_falls_on_the_uploaded_text_not_on_its_escape():
    # The cell limit applies to the text Excel shows; _x005F_ escaping comes after the cut.
    # Escaping first would make the cut fall inside "_x005F_x000D_", and the cell would show
    # "_" where the upload had "_x000D_".
    from openpyxl.utils.escape import unescape

    from app.exporters.excel_exporter import _TRUNCATED
    kept = "a" * (32_767 - len(_TRUNCATED) - len("_x000D_")) + "_x000D_"
    stored = _sanitize_cell(kept + "b" * 100)
    assert unescape(stored) == kept + _TRUNCATED
    assert stored.endswith("_x005F_x000D_" + _TRUNCATED)


def test_a_value_far_over_the_limit_is_cut_without_encoding_all_of_it(monkeypatch):
    # Encoding a 5,000,000-character value to measure it cost time and a transient copy;
    # more than 32,767 code points are over the limit whatever they are.
    import app.exporters.excel_exporter as exporter
    measured: list[int] = []
    real = exporter._utf16_units

    def recording(text: str) -> int:
        measured.append(len(text))
        return real(text)

    monkeypatch.setattr(exporter, "_utf16_units", recording)
    for text in ("C" * 5_000_000, "\U0001F600" * 2_000_000):
        cell = exporter._sanitize_cell(text)
        assert cell.endswith(exporter._TRUNCATED) and _utf16_units(cell) <= 32_767
        assert _utf16_units(cell) > 32_767 - 2                          # and no shorter than needed
    assert max(measured) <= 32_767, max(measured)


def test_the_criterion_limit_is_counted_in_utf16_units_too(tmp_path):
    # 200 emoji: 201 characters of criterion, 401 UTF-16 units: too long for COUNTIFS.
    host = "\U0001F600" * 200
    out = tmp_path / "emoji_host.xlsx"
    ExcelExporter().export([_finding(server=host, severity="CAT II")], out)
    row = next(r for r in load_workbook(out)["Summary"].iter_rows() if r[0].value == host)
    assert [c.value for c in row[2:5]] == [0, 1, 0]


_LOCALE = ("Counts follow English-language Excel's matching rules; in another language a host or STIG "
           "named like a date or TRUE/FALSE may be counted differently.")
_FOOTER = ("Note: Counts use COUNTIFS and reflect all data. Filtering the Findings sheet does not "
           f"update these counts. {_LOCALE} See README for details.")


def _footer(path: Path) -> str:
    return next(r[0].value for r in load_workbook(path)["Summary"].iter_rows()
                if isinstance(r[0].value, str) and r[0].value.startswith("Note: "))


def test_the_footer_names_fixed_count_cells_only_when_there_are_some(tmp_path):
    short, long = tmp_path / "short.xlsx", tmp_path / "long.xlsx"
    ExcelExporter().export([_finding()], short)
    assert _footer(short) == _FOOTER
    ExcelExporter().export([_finding(server="H" * 300)], long)
    assert _footer(long) == (
        "Note: Counts use COUNTIFS and reflect all data, except where a host, IP address or title is "
        "too long for COUNTIFS, holds a ~, or would be read by it as a number, date, time, TRUE/FALSE or "
        "an error value; those cells hold a fixed count. Filtering the Findings sheet does not update "
        f"these counts. {_LOCALE} See README for details.")


def test_a_cell_never_exceeds_excels_limit_and_says_it_was_cut(tmp_path):
    # Excel holds at most 32,767 characters in a cell and "repairs" (truncates) a workbook
    # with a longer one, silently. Check and fix text come from uploads and are not bounded.
    from app.exporters.excel_exporter import _MAX_CELL_CHARS, _TRUNCATED
    assert _MAX_CELL_CHARS == 32_767 and _TRUNCATED == "… [truncated by STIG Condenser]"
    long_check = "C" * 40_000
    exact = "F" * 32_767
    finding = _finding(check=long_check, fix=exact)
    finding.text_source = "Check and fix: scanner"
    out = tmp_path / "long.xlsx"
    ExcelExporter().export([finding, _finding(check="=" + "x" * 40_000, vuln_id="V-2")], out)
    ws = load_workbook(out)["Findings"]
    check = ws["H2"].value
    assert len(check) == 32_767 and check.endswith(_TRUNCATED) and check.startswith("C" * 32_000)
    assert ws["I2"].value == exact                                   # at the limit: kept whole
    assert ws["K2"].value == "Check and fix: scanner"
    assert (ws["A2"].value, ws["F2"].value) == ("Windows Server 2022 STIG", "SERVER01")
    formula_like = ws["H3"].value
    assert len(formula_like) == 32_767 and formula_like.startswith("'=x") and formula_like.endswith(_TRUNCATED)
    assert _sanitize_cell("short") == "short"


def test_sanitize_cell_replaces_characters_a_workbook_cannot_hold():
    # openpyxl refuses these control characters outright, so one in an upload
    # would otherwise abort the whole export.
    assert _sanitize_cell("a\x00b\x07c\x0bd\x1fe") == "a\ufffdb\ufffdc\ufffdd\ufffde"
    assert _sanitize_cell("tab\tand\nnewline") == "tab\tand\nnewline"


def test_a_lone_surrogate_is_shown_as_the_replacement_character(tmp_path):
    # Valid JSON can carry one (a checklist's "before \ud800 after"); it cannot be written as
    # UTF-8, so it stopped the save with a UnicodeEncodeError.
    assert _sanitize_cell("before \ud800 after \udfff") == "before \ufffd after \ufffd"
    out = tmp_path / "surrogate.xlsx"
    ExcelExporter().export([_finding(check="before \ud800 after", server="H\udc00ST")], out)
    ws = load_workbook(out)["Findings"]
    assert (ws["H2"].value, ws["F2"].value) == ("before \ufffd after", "H\ufffdST")


def _xml_text_of(path: Path, sheet: str, needle: str) -> str:
    """The text of the first <t> element in *sheet*'s XML that contains *needle*, as stored."""
    import zipfile

    from lxml import etree
    with zipfile.ZipFile(path) as z:
        root = etree.fromstring(z.read(f"xl/worksheets/{sheet}.xml"))
    return next(t.text for t in root.iter("{*}t") if t.text and needle in t.text)


@pytest.mark.parametrize("text", [
    "Run _x000D_ then _x0041_ here",
    "already _x005F_x000D_ escaped, lower _x000d_, not one _x00G1_ or _x12_",
])
def test_a_literal_xhhhh_sequence_reads_back_as_the_uploaded_text(tmp_path, text):
    # Excel decodes _xHHHH_ in stored text (_x000D_ is a CR, _x0041_ an "A"). openpyxl writes
    # the text as it is and does not decode on load either, so the cell would show something
    # other than the upload. The underscore that starts each such sequence is stored as _x005F_.
    from openpyxl.utils.escape import unescape        # the OOXML decoding Excel applies
    out = tmp_path / "xesc.xlsx"
    ExcelExporter().export([_finding(check=text)], out)
    stored = _xml_text_of(out, "sheet1", "_x")
    assert unescape(stored) == text
    assert "_x005F_x000D_" in stored


@pytest.mark.parametrize("lead", ["=", "+", "-", "@", "\t", "\r", "\x01", "\x1b"])
def test_hostile_reference_strings_are_neutralised(tmp_path, lead):
    """A title, file name or release from an upload never becomes a formula, never carries a
    character the workbook cannot hold, and stays readable — in the Reference sources table
    and in the Text Source column."""
    from app.reference.enrich import EnrichmentReport, source_key
    from app.reference.models import ReferenceSource

    evil = f'{lead}HYPERLINK("http://e")\x07'
    src = ReferenceSource(f"{evil}.xml", "X", evil, evil, False, evil, 1)
    report = EnrichmentReport(sources=[src], source_counts={source_key(src): {"filled_check": 1}})
    findings = [_finding(), _finding(vuln_id="V-2", rule_id="SV-2r1_rule")]
    findings[0].text_source = f"Check: {evil}.xml {evil} | Fix: scanner"    # as enrichment writes it
    findings[1].text_source = evil                                          # a loaded findings file
    wb = _export_with(tmp_path, report, findings)

    body, _ = _sources_block(_summary_rows(wb["Summary"]))
    ws = wb["Findings"]
    col = [c.value for c in ws[1]].index("Text Source") + 1
    text_cells = [ws.cell(row=r, column=col) for r in (2, 3)]
    row = next(r for r in wb["Summary"].iter_rows() if r[0].value == body[0][0])
    for cell in [*row[:4], *text_cells]:
        value = cell.value
        assert cell.data_type == "s", (cell.coordinate, value)
        assert not value.startswith(_FORMULA_PREFIXES), (cell.coordinate, value)
        assert not any(ord(ch) < 32 and ch not in "\t\n\r" for ch in value), (cell.coordinate, value)
        assert 'HYPERLINK("http://e")' in value, "the text itself is kept"


def test_delta_sheet_appends_stig_id_and_text_source(tmp_path):
    from app.processors.delta import compute_delta
    f = Finding("T", "V-1", "SV-1r1_rule", "CAT I", "Open", "H", "i", "c", "x",
                stig_id="WN11-00-000150", text_source="Check and fix: scanner")
    scanned = {("H", "T")}
    out = tmp_path / "d.xlsx"
    ExcelExporter().export_delta(
        compute_delta([f], [f], baseline_coverage=scanned, current_coverage=scanned), out
    )
    ws = load_workbook(out)["Findings"]
    headers = [c.value for c in ws[1]]
    assert headers[0] == "Delta" and headers[4] == "Severity"            # COUNTIFS columns A and E unchanged
    assert headers[-2:] == ["STIG ID", "Text Source"]
    assert ws.cell(row=2, column=len(headers) - 1).value == "WN11-00-000150"
    text_source = ws.cell(row=2, column=len(headers))
    assert text_source.value == "Check and fix: scanner"
    assert text_source.alignment.wrap_text, "Text Source wraps like Check/Fix Text"


# ── Summary criteria: each one matches exactly the cells it counts ────────

_CRITERION_HOSTS = ["-HOST", "=HOST", "<HOST", "*HOST", "HOST?", "HOST~1", "WIN\x1b[31m-01"]
_CRITERION_TITLES = ["Windows Server 2022 STIG\x07", "@Windows STIG", ">Title*?", "Plain STIG"]


def _tilde(text: str) -> str:
    """COUNTIFS's own escape for its wildcards and the escape character, as Excel applies it:
    only in text that holds a * or ?; elsewhere ~ is an ordinary character."""
    if "*" not in text and "?" not in text:
        return text
    return "".join("~" + ch if ch in "~*?" else ch for ch in text)


def _criteria(summary, label_column_of: str) -> dict[str, set[str]]:
    """{label cell value: the criteria its COUNTIFS put on Findings column *label_column_of*}."""
    head = f"=COUNTIFS(Findings!${label_column_of}:${label_column_of},"
    out: dict[str, set[str]] = {}
    for row in summary.iter_rows():
        for cell in row:
            if isinstance(cell.value, str) and cell.value.startswith(head):
                # The quoted literal right after the column (more criteria may follow it).
                criterion = re.match(r'"(?:[^"]|"")*"', cell.value[len(head):]).group(0)
                out.setdefault(row[0].value, set()).add(criterion)
    return out


def _terms(formula: str) -> list[str]:
    """The "+"-joined terms of *formula* (without its "="), split outside string literals."""
    terms, current, quoted = [], "", False
    for ch in formula[1:]:
        if ch == '"':
            quoted = not quoted
        if ch == "+" and not quoted:
            terms.append(current)
            current = ""
        else:
            current += ch
    return [*terms, current]


def _countifs(rows: list[dict[str, object]], formula: str) -> int:
    """What Excel gives for *formula* — one COUNTIFS, or several joined by "+" — over the
    Findings *rows* ({column letter: value}). In each COUNTIFS every criterion must hold:
    - "" matches a blank cell or one holding empty text; "=" alone only a truly blank cell;
      "<>" any cell that is not blank;
    - "=text" (or plain "text") is an equality test, ~ escaping the next character and
      * ? as wildcards, letter case ignored (str.lower()).
    The Findings rows hold only data rows; COUNTIFS over whole columns also sees the empty
    rows below them, so a term whose criteria all match blank cells would count about a
    million rows: the evaluator fails such a term."""
    total = 0
    for term in _terms(formula):
        criteria = [(col, crit.replace('""', '"'))
                    for col, crit in re.findall(r'Findings!\$([A-Z]):\$[A-Z],"((?:[^"]|"")*)"', term)]
        assert term.startswith("COUNTIFS(") and criteria, formula
        assert any(crit not in ("", "=") for _col, crit in criteria), f"counts every empty row: {term}"
        total += sum(1 for row in rows if all(_holds(crit, row.get(col)) for col, crit in criteria))
    return total


def _holds(crit: str, value: object) -> bool:
    blank = value is None or value == ""
    if crit == "":
        return blank
    if crit == "=":
        return value is None
    if crit == "<>":
        return not blank
    body, out, i = crit[1:] if crit.startswith("=") else crit, "", 0
    if "*" not in body and "?" not in body:
        # Excel reads "~" as an escape only in a criterion that holds a wildcard (escaped or
        # not); otherwise the comparison is literal (see _EXCEL_TILDE_OBSERVED).
        return _excel_upper(body) == _excel_upper(str(value or ""))
    while i < len(body):
        ch = body[i]
        if ch == "~" and i + 1 < len(body):
            out, i = out + re.escape(_excel_upper(body[i + 1])), i + 2
            continue
        out += ".*" if ch == "*" else "." if ch == "?" else re.escape(_excel_upper(ch))
        i += 1
    return re.fullmatch(out, _excel_upper(str(value or "")), re.DOTALL) is not None


def _excel_upper(text: str) -> str:
    """Text as Excel compares it ignoring case: each character upper-cased on its own, and
    kept when its upper case is longer than one character ("ß" stays "ß"; "ς" and "σ" are "Σ").

    The same rule as the exporter's own ``_excel_upper``: tests that evaluate the Summary with
    this evaluator show that its formulas and fixed counts agree with each other, not that they
    agree with Excel. Fidelity rests on the documented cases in
    test_the_evaluator_follows_excels_documented_matching."""
    return "".join(ch.upper() if len(ch.upper()) == 1 else ch for ch in text)


@pytest.mark.parametrize("criterion, cell, match", [
    # COUNTIF/COUNTIFS as Microsoft documents them: text comparison ignores letter case; "*"
    # is any run of characters and "?" any one; "~" makes the next character literal; ""
    # matches an empty cell, "<>" a non-empty one, "=" alone only a truly blank one.
    ("=apples", "APPLES", True), ("=apples", "apple", False),
    ("=app*", "apples", True), ("=app*", "app", True), ("=*les", "apples", True),
    ("=appl?s", "apples", True), ("=appl?s", "appls", False),
    ("=what~?", "what?", True), ("=what~?", "whats", False),
    ("=a~*b", "a*b", True), ("=a~*b", "axb", False), ("=a~~*", "a~b", True),
    # Observed in Excel 16 (en-US), not documented: with no * or ? in the criterion, ~ is literal.
    ("=a~~b", "a~b", False), ("=a~b", "a~b", True),
    ("", None, True), ("", "x", False), ("<>", "x", True), ("<>", None, False),
    ("=", None, True), ("=", "x", False),
    ("CAT I", "cat i", True), ("CAT I", "CAT II", False),
])
def test_the_evaluator_follows_excels_documented_matching(criterion, cell, match):
    assert _holds(criterion, cell) is match


def _evaluated(path: Path, title: str) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """The rows of the Summary table *title* as {header: value}, every COUNTIFS and SUM
    evaluated, and the Findings rows."""
    wb = load_workbook(path)
    rows = [{c.column_letter: c.value for c in r} for r in wb["Findings"].iter_rows(min_row=2)]
    summary = wb["Summary"]
    start = next(r[0].row for r in summary.iter_rows() if r[0].value == title) + 1
    headers = [c.value for c in summary[start]]
    out = []
    for r in summary.iter_rows(min_row=start + 1):
        if r[0].value is None:
            break
        values = {c.column_letter: (_countifs(rows, c.value) if isinstance(c.value, str)
                                    and c.value.startswith("=COUNTIFS") else c.value) for c in r}
        for letter, value in list(values.items()):
            if isinstance(value, str) and value.startswith("=SUM("):
                parts = value[len("=SUM("):-1].split(",")
                cells = []
                for part in parts:
                    first, _, last = part.partition(":")
                    lo, hi = first.rstrip("0123456789"), (last or first).rstrip("0123456789")
                    cells += [chr(c) for c in range(ord(lo), ord(hi) + 1)]
                values[letter] = sum(values[c] for c in cells)
        out.append({h: values[c.column_letter] for h, c in zip(headers, r) if h is not None})
    return out, rows


def _summary_tables(path: Path) -> tuple[list[list], list[list], list[dict[str, object]]]:
    """(server rows, STIG rows) of the Summary with every count evaluated, and the Findings rows."""
    wb = load_workbook(path)
    rows = [{c.column_letter: c.value for c in r} for r in wb["Findings"].iter_rows(min_row=2)]
    summary = [[c.value for c in r] for r in wb["Summary"].iter_rows()]

    def table(title: str, first_count: int) -> list[list]:
        start = next(i for i, r in enumerate(summary) if r[0] == title) + 2
        body = []
        for r in summary[start:]:
            if r[0] is None:
                break
            counts = [_countifs(rows, v) if isinstance(v, str) else v for v in r[first_count:first_count + 3]]
            body.append(r[:first_count] + counts)
        return body

    return table("Findings by Server", 2), table("Findings by STIG", 1), rows


def _assert_tables_add_up(servers, stigs, rows) -> None:
    for i, sev in enumerate(("CAT I", "CAT II", "CAT III")):
        total = sum(1 for r in rows if r["D"] == sev)
        assert sum(r[2 + i] for r in servers) == total, (sev, servers)
        assert sum(r[1 + i] for r in stigs) == total, (sev, stigs)


def test_a_host_with_two_ips_gets_a_row_per_ip_each_counting_its_own(tmp_path):
    # Two checklists of WKSTN-01, one with its IP and one with "N/A": each row counted both.
    findings = [
        _finding(server="WKSTN-01", ip="10.0.0.21", severity="CAT I", vuln_id="V-1"),
        _finding(server="WKSTN-01", ip="10.0.0.21", severity="CAT II", vuln_id="V-2"),
        _finding(server="WKSTN-01", ip="N/A", severity="CAT I", vuln_id="V-1"),
        _finding(server="WKSTN-01", ip="N/A", severity="CAT II", vuln_id="V-2"),
    ]
    out = tmp_path / "ips.xlsx"
    ExcelExporter().export(findings, out)
    servers, stigs, rows = _summary_tables(out)
    assert servers == [["WKSTN-01", "10.0.0.21", 1, 1, 0], ["WKSTN-01", "N/A", 1, 1, 0]]
    _assert_tables_add_up(servers, stigs, rows)


def test_values_differing_only_in_letter_case_share_one_row(tmp_path):
    # COUNTIFS ignores letter case: two rows would each count the other's findings.
    findings = [
        _finding(server="WKSTN-01", stig_title="Windows Server 2022 STIG", severity="CAT I", vuln_id="V-1"),
        _finding(server="wkstn-01", stig_title="WINDOWS SERVER 2022 STIG", severity="CAT I", vuln_id="V-2"),
        _finding(server="wkstn-01", stig_title="WINDOWS SERVER 2022 STIG", severity="CAT II", vuln_id="V-3"),
    ]
    out = tmp_path / "case.xlsx"
    ExcelExporter().export(findings, out)
    servers, stigs, rows = _summary_tables(out)
    assert servers == [["WKSTN-01", "10.0.0.1", 2, 1, 0]]          # the first spelling seen
    assert stigs == [["Windows Server 2022 STIG", 2, 1, 0]]
    _assert_tables_add_up(servers, stigs, rows)


def test_long_values_that_only_casefold_alike_keep_their_own_rows(tmp_path):
    # Over 255 characters the count is computed; "ß" and "SS" are different text to COUNTIFS
    # (str.lower), though casefold() would merge them.
    eszett, double_s = "H" * 260 + "ß", "H" * 260 + "SS"
    findings = [
        _finding(server=eszett, stig_title="T" * 260 + "ß", severity="CAT I", vuln_id="V-1"),
        _finding(server=double_s, stig_title="T" * 260 + "SS", severity="CAT I", vuln_id="V-2"),
        _finding(server=double_s, stig_title="T" * 260 + "SS", severity="CAT III", vuln_id="V-3"),
    ]
    out = tmp_path / "eszett.xlsx"
    ExcelExporter().export(findings, out)
    servers, stigs, rows = _summary_tables(out)
    assert [r[0][-2:] for r in servers] == ["Hß", "SS"] and [r[2:] for r in servers] == [[1, 0, 0], [1, 0, 1]]
    assert [r[1:] for r in stigs] == [[1, 0, 0], [1, 0, 1]]
    _assert_tables_add_up(servers, stigs, rows)


def test_every_summary_criterion_matches_the_cells_it_counts(tmp_path):
    """A host or title from an upload may start with = + - @ < > (formula prefixes, which the
    cell stores behind an apostrophe, and COUNTIFS operators), hold * ? ~ (COUNTIFS
    wildcards), or a control character a workbook cannot hold. Each criterion must equal the
    text of the cells it counts, so every count is right and the export never fails."""
    findings = [
        _finding(server=host, stig_title=_CRITERION_TITLES[i % len(_CRITERION_TITLES)], vuln_id=f"V-{i}")
        for i, host in enumerate(_CRITERION_HOSTS)
    ]
    out = tmp_path / "criteria.xlsx"
    ExcelExporter().export(findings, out)                  # a control character used to stop it here
    wb = load_workbook(out)
    cells = wb["Findings"]
    by_server = _criteria(wb["Summary"], "F")
    by_title = _criteria(wb["Summary"], "A")
    for r in range(2, cells.max_row + 1):
        for column, criteria in ((6, by_server), (1, by_title)):
            stored = cells.cell(row=r, column=column).value
            if "~" in stored:       # Excel's reading of "~" is not documented: a fixed count, no criterion
                assert stored not in criteria, (stored, criteria.get(stored))
                continue
            assert criteria[stored] == {_formula_quote("=" + _tilde(stored))}, (stored, criteria.get(stored))
    # The labels show what the cells hold: the sanitised value, never a raw control character.
    assert sorted(by_server) == sorted(v for r in range(2, cells.max_row + 1)
                                       if "~" not in (v := cells.cell(row=r, column=6).value))
    assert "'-HOST" in by_server and "WIN\ufffd[31m-01" in by_server
    assert "Windows Server 2022 STIG\ufffd" in by_title and "'@Windows STIG" in by_title


def test_a_value_too_long_for_a_countifs_criterion_gets_its_count_not_a_formula(tmp_path):
    # Excel refuses a COUNTIFS criterion over 255 characters (#VALUE!). Checklist hosts and
    # titles are not clipped at parse time; such a row holds the count, computed from the same
    # stored cell values (the host's starts with "-", so its cells read "'-HHH\u2026").
    long_host, long_title = "-" + "H" * 299, "T" * 300
    findings = [
        _finding(server=long_host, stig_title=long_title, severity="CAT I", vuln_id="V-1"),
        _finding(server=long_host, stig_title=long_title, severity="CAT I", vuln_id="V-2"),
        _finding(server=long_host, stig_title=long_title, severity="CAT II", vuln_id="V-3"),
        _finding(server="SHORT", stig_title="Short STIG", severity="CAT III", vuln_id="V-4"),
    ]
    out = tmp_path / "long.xlsx"
    ExcelExporter().export(findings, out)
    summary = load_workbook(out)["Summary"]
    rows = {row[0].value: [c.value for c in row] for row in summary.iter_rows() if row[0].value}
    assert rows["'" + long_host][2:5] == [2, 1, 0]        # Findings by Server: CAT I, II, III
    assert rows[long_title][1:4] == [2, 1, 0]             # Findings by STIG
    assert rows["SHORT"][2].startswith("=COUNTIFS(") and rows["Short STIG"][1].startswith("=COUNTIFS(")
    formulas = [c.value for row in summary.iter_rows() for c in row
                if isinstance(c.value, str) and c.value.startswith("=")]
    assert formulas and all(len(f) <= 255 for f in formulas), max(formulas, key=len)
    assert rows["'" + long_host][5].startswith("=SUM(C") and rows[long_title][4].startswith("=SUM(B")


# ── Summary totals: every Findings row is counted somewhere ───────────────

def _assert_totals_match(path: Path) -> None:
    """Both tables' Totals add up to the Findings rows, and so does each count column."""
    servers, rows = _evaluated(path, "Findings by Server")
    stigs, _ = _evaluated(path, "Findings by STIG")
    for table in (servers, stigs):
        assert sum(r["Total"] for r in table) == len(rows), table
        for column in ("CAT I", "CAT II", "CAT III"):
            assert sum(r[column] for r in table) == sum(1 for x in rows if x["D"] == column), (column, table)
        assert sum(r["No severity"] for r in table) == sum(1 for x in rows if x["D"] in (None, "", "Unknown"))


def test_a_host_total_counts_findings_with_no_severity(tmp_path):
    # Evaluate-STIG results against the Server 2022 Manual: SV-254243 is not in the
    # reference, so its row has no severity; WIN-SERVER-04's Total used to say 2 for 3 rows.
    from app.core.pipeline import export_stage, parse_stage
    result = parse_stage([_FIXTURES / "evaluate_stig_results.xml"], [_FIXTURES / "manual_stig_server2022.xml"],
                         tmp_path / "x")
    out = tmp_path / "r.xlsx"
    export_stage(result.findings, out, enrichment=result.enrichment)
    servers, rows = _evaluated(out, "Findings by Server")
    assert len(rows) == 3
    (host,) = [r for r in servers if r["Server"] == "WIN-SERVER-04"]
    assert (host["No severity"], host["Total"]) == (1, 3)
    # Columns that other formulas and tests address keep their letters: No severity is appended.
    summary = load_workbook(out)["Summary"]
    header = next(r for r in summary.iter_rows() if r[0].value == "Server")
    assert [c.value for c in header[:7]] == ["Server", "IP Address", "CAT I", "CAT II", "CAT III", "Total",
                                             "No severity"]
    _assert_totals_match(out)


def test_untitled_findings_have_a_row_of_their_own(tmp_path):
    findings = [
        _finding(stig_title="", severity="CAT I", vuln_id="V-1"),
        _finding(stig_title="", severity="", vuln_id="V-2"),
        _finding(stig_title="", severity="Unknown", vuln_id="V-3", server="OTHER", ip=""),
        _finding(stig_title="Windows Server 2022 STIG", severity="CAT II", vuln_id="V-4"),
    ]
    out = tmp_path / "untitled.xlsx"
    ExcelExporter().export(findings, out)
    stigs, _ = _evaluated(out, "Findings by STIG")
    untitled = next(r for r in stigs if r["STIG Title"] == "(no STIG title)")
    assert (untitled["CAT I"], untitled["No severity"], untitled["Total"]) == (1, 2, 3)
    servers, _ = _evaluated(out, "Findings by Server")
    other = next(r for r in servers if r["Server"] == "OTHER")       # a blank IP is matched too
    assert (other["No severity"], other["Total"]) == (1, 1)
    _assert_totals_match(out)


# ── cost: linear in findings plus rows ────────────────────────────────────

def _long_host_findings(hosts: int, per_host: int) -> list[Finding]:
    """Findings on hosts whose names are too long for COUNTIFS: every Summary count is fixed."""
    severities = ("CAT I", "CAT II", "CAT III", "", "Unknown")
    return [
        _finding(server=f"H{h:03d}" + "x" * 296, severity=severities[i % 5], vuln_id=f"V-{h}-{i}")
        for h in range(hosts) for i in range(per_host)
    ]


def test_fixed_counts_read_each_finding_once_not_once_per_cell(tmp_path, monkeypatch):
    # The fixed-count path looped over every finding for every cell, sanitising each field
    # again each time: 2,000 long-named hosts with 100,000 findings took about 15 minutes.
    import app.exporters.excel_exporter as exporter
    calls = [0]
    real = exporter._sanitize_cell

    def counting(value):
        calls[0] += 1
        return real(value)

    monkeypatch.setattr(exporter, "_sanitize_cell", counting)
    findings = _long_host_findings(hosts=40, per_host=10)
    out = tmp_path / "many.xlsx"
    ExcelExporter().export(findings, out)
    per_finding_cells = len(exporter._FINDINGS_COLS)            # the Findings sheet's own cells
    summary_calls = calls[0] - per_finding_cells * len(findings)
    assert summary_calls < 10 * len(findings), summary_calls     # was about 60 per finding here
    servers, rows = _evaluated(out, "Findings by Server")
    assert len(servers) == 40 and all(r["Total"] == 10 and r["No severity"] == 4 for r in servers)
    _assert_totals_match(out)


def test_findings_cells_share_their_alignment_styles(monkeypatch, tmp_path):
    # A new Alignment per cell made openpyxl hash a style for every cell written.
    import app.exporters.excel_exporter as exporter
    made = [0]
    real = exporter.Alignment

    def counting(*args, **kwargs):
        made[0] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(exporter, "Alignment", counting)
    ExcelExporter().export([_finding(vuln_id=f"V-{i}") for i in range(50)], tmp_path / "styles.xlsx")
    assert made[0] == 0, made[0]


# ── values COUNTIFS would coerce; one comparison rule ─────────────────────

@pytest.mark.parametrize("text, coerced", [
    ("0123", True), ("123", True), ("1/2/2026", True), ("12:30", True), ("", False),
    # A well-formed IP address is neither a number nor a date to COUNTIF; anything else
    # without a letter still is taken to be one.
    ("10.0.0.21", False), (" 10.0.0.21 ", False), ("fe80::1", False), ("::1", False),
    ("10.0.0", True), ("192.168.1.256", True), ("10.0.0.21.5", True),
    ("TRUE", True), (" false ", True), ("True host", False),
    ("dec-01", True), ("Dec-1", True), ("December 5", True), ("sept.3", True), ("1-Dec", True),
    ("12:30 PM", True), ("9am", True), ("1E5", True), ("2.5e-3", True),
    ("WKSTN-01", False), ("Decker-01", False), ("DC01", False), ("HOST~1", False), ("pm-server", False),
    ("Windows Server 2022 STIG", False), ("N/A", False),
    # Excel's error literals, which a criterion would read as an error value (counting 0).
    ("#N/A", True), ("#null!", True), ("#DIV/0!", True), ("#VALUE!", True), ("#REF!", True),
    ("#NAME?", True), ("#NUM!", True), ("#SPILL!", True), ("#calc!", True),
    ("#N/A host", False), (" #REF! ", True),
    # Year-first dates with a month name (a prefix is enough: fixed counts are always safe).
    ("2026-Jan-15", True), ("2026 Jan 15", True), ("2026/january/15", True), ("2026-Janus", True),
    ("20261-Jan", False), ("Host-2026-Jan", False),
])
def test_which_criteria_excel_would_coerce(text, coerced):
    from app.exporters.excel_exporter import _excel_would_coerce
    assert _excel_would_coerce(text) is coerced


def test_values_excel_would_read_as_numbers_or_dates_get_exact_fixed_counts(tmp_path):
    # COUNTIF reads "0123" and "123" as one number, "dec-01" and "Dec-1" as one date: as formulas
    # each row would count the other's findings. Fixed counts are exact.
    findings = [
        _finding(server="0123", ip="N/A", severity="CAT I", vuln_id="V-1"),
        _finding(server="123", ip="N/A", severity="CAT I", vuln_id="V-2"),
        _finding(server="123", ip="N/A", severity="CAT II", vuln_id="V-3"),
        _finding(server="dec-01", ip="N/A", severity="CAT I", vuln_id="V-4"),
        _finding(server="Dec-1", ip="N/A", severity="CAT III", vuln_id="V-5"),
        _finding(server="10.0.0", ip="N/A", severity="CAT II", vuln_id="V-6"),        # not an IP: a number?
        _finding(server="#N/A", ip="N/A", severity="CAT III", vuln_id="V-11"),        # an error literal
        _finding(server="2026-Jan-15", ip="N/A", severity="CAT I", vuln_id="V-12"),   # a year-first date
        _finding(server="WKSTN-01", ip="N/A", severity="CAT I", vuln_id="V-7"),       # ordinary
        _finding(server="WKSTN-02", ip="10.0.0.21", severity="CAT I", vuln_id="V-8"),  # a well-formed IPv4
        _finding(server="WKSTN-03", ip="fe80::1", severity="CAT I", vuln_id="V-9"),    # a well-formed IPv6
        _finding(server="192.168.1.10", ip="N/A", severity="CAT II", vuln_id="V-10"),  # a host named by its IP
    ]
    out = tmp_path / "coerced.xlsx"
    ExcelExporter().export(findings, out)
    summary = load_workbook(out)["Summary"]
    cells = {r[0].value: [c.value for c in r[2:5]] for r in summary.iter_rows()
             if r[0].value in {f.server for f in findings}}
    assert cells["0123"] == [1, 0, 0] and cells["123"] == [1, 1, 0]
    assert cells["dec-01"] == [1, 0, 0] and cells["Dec-1"] == [0, 0, 1]
    assert cells["10.0.0"] == [0, 1, 0]
    assert cells["#N/A"] == [0, 0, 1] and cells["2026-Jan-15"] == [1, 0, 0]
    for host in ("WKSTN-01", "WKSTN-02", "WKSTN-03", "192.168.1.10"):
        assert all(isinstance(v, str) and v.startswith("=COUNTIFS(") for v in cells[host]), host
    _assert_totals_match(out)


def test_letter_case_is_ignored_as_excel_ignores_it(tmp_path):
    # Excel upper-cases one character at a time: "ς" (final sigma) and "σ" are both "Σ", so
    # their titles share a row; "ß" has no one-character upper case and stays apart from "SS".
    findings = [
        _finding(stig_title="Λογος STIG", ip="N/A", severity="CAT I", vuln_id="V-1"),
        _finding(stig_title="Λογοσ STIG", ip="N/A", severity="CAT II", vuln_id="V-2"),
        _finding(stig_title="Straße STIG", ip="N/A", severity="CAT I", vuln_id="V-3"),
        _finding(stig_title="STRASSE STIG", ip="N/A", severity="CAT I", vuln_id="V-4"),
    ]
    out = tmp_path / "case.xlsx"
    ExcelExporter().export(findings, out)
    stigs, _ = _evaluated(out, "Findings by STIG")
    assert [(r["STIG Title"], r["Total"]) for r in stigs] == [
        ("Λογος STIG", 2), ("Straße STIG", 1), ("STRASSE STIG", 1)]
    _assert_totals_match(out)


# ── Excel's tilde rule, as observed; error-looking text stays text ─────────

# COUNTIF results observed in Microsoft Excel 16 (English-US, recalculated through COM over
# these cells): what that Excel did, not what its documentation says. "~" escapes the next
# character only when the criterion holds a "*" or "?" (escaped or not); otherwise the
# comparison is literal and "~" is ordinary. Other builds, Excel for Mac, LibreOffice and
# Sheets were not observed, so the exporter writes no criterion for text holding a "~" (fixed
# counts); these results pin the test evaluator, which models that one observed Excel.
_EXCEL_TILDE_CELLS = ["HOST~1", "A~*B", "A~B", "X~?", "T~", "~", "A*", "HOST1"]
_EXCEL_TILDE_OBSERVED = [
    ("=HOST~~1", 0), ("HOST~~1", 0), ("=HOST~1", 1), ("HOST~1", 1),
    ("=A~~~*B", 1), ("=A~~*B", 2), ("=A~*B", 0), ("=A~~B", 0), ("=A~B", 1),
    ("=X~~~?", 1), ("=X~?", 0), ("=T~~", 0), ("=T~", 1), ("=~~", 0), ("=~", 1),
    ("=A~*", 1), ("A~*", 1),
]


@pytest.mark.parametrize("criterion, count", _EXCEL_TILDE_OBSERVED)
def test_the_evaluator_counts_as_excel_did(criterion, count):
    assert sum(_holds(criterion, cell) for cell in _EXCEL_TILDE_CELLS) == count


@pytest.mark.parametrize("value", [cell for cell in _EXCEL_TILDE_CELLS if "~" not in cell])
def test_each_criterion_counts_exactly_the_cells_with_its_text(value):
    # Text with "*" or "?" and no "~": the documented escape, which Excel and the evaluator agree on.
    from app.exporters.excel_exporter import _criterion_text
    criterion = _criterion_text(value)
    assert criterion == "=" + _tilde(value)
    assert [cell for cell in _EXCEL_TILDE_CELLS if _holds(criterion, cell)] == [value]


@pytest.mark.parametrize("host", [cell for cell in _EXCEL_TILDE_CELLS if "~" in cell])
def test_a_value_holding_a_tilde_gets_a_fixed_count(tmp_path, host):
    out = tmp_path / "tilde.xlsx"
    ExcelExporter().export([_finding(server=host, ip="N/A", severity="CAT II"),
                            _finding(server="HOST1", ip="N/A", severity="CAT I", vuln_id="V-2")], out)
    summary = load_workbook(out)["Summary"]
    row = next(r for r in summary.iter_rows() if r[0].value == host)
    assert [c.value for c in row[2:5]] == [0, 1, 0]            # numbers, not formulas
    plain = next(r for r in summary.iter_rows() if r[0].value == "HOST1")
    assert all(isinstance(c.value, str) and c.value.startswith("=COUNTIFS(") for c in plain[2:5])
    assert "holds a ~" in _footer(out)
    _assert_totals_match(out)


def test_a_wildcard_without_a_tilde_keeps_its_formula_with_the_documented_escape(tmp_path):
    out = tmp_path / "wild.xlsx"
    ExcelExporter().export([_finding(server="*HOST?", ip="N/A", severity="CAT II")], out)
    row = next(r for r in load_workbook(out)["Summary"].iter_rows() if r[0].value == "*HOST?")
    assert '"=~*HOST~?"' in row[3].value
    _assert_totals_match(out)


@pytest.mark.parametrize("literal", ["#N/A", "#NULL!", "#DIV/0!", "#VALUE!", "#REF!", "#NAME?", "#NUM!"])
def test_an_error_literal_from_an_upload_is_written_as_text(tmp_path, literal):
    out = tmp_path / "errors.xlsx"
    ExcelExporter().export([_finding(server=literal, stig_title=literal, ip="N/A")], out)
    wb = load_workbook(out)
    findings = wb["Findings"]
    for column in (1, 6):                                   # STIG Title, Server
        cell = findings.cell(row=2, column=column)
        assert (cell.value, cell.data_type) == (literal, "s"), (column, cell.data_type)
    labels = [c for r in wb["Summary"].iter_rows() for c in r[:1] if c.value == literal]
    assert len(labels) == 2 and all(c.data_type == "s" for c in labels)      # by Server, by STIG


def test_an_error_literal_in_a_delta_is_written_as_text(tmp_path):
    finding = _delta_finding("Persisting", server="#N/A")
    result = DeltaResult(findings=[finding], common_hosts={"#N/A"},
                         not_rescanned_pairs={("#N/A", "#REF!")})
    out = tmp_path / "delta_errors.xlsx"
    ExcelExporter().export_delta(result, out)
    wb = load_workbook(out)
    server = wb["Findings"][f"{_delta_col_letter('Server')}2"]
    assert (server.value, server.data_type) == ("#N/A", "s")
    texts = [c for r in wb["Summary"].iter_rows() for c in r if c.value in ("#N/A", "#REF!")]
    assert texts and all(c.data_type == "s" for c in texts)


# --- the workbook carries the run's warnings -------------------------------------------------------

_RUN_WARNINGS = "Warnings from this run"


def run_warning_rows(path) -> list[str] | None:
    """The lines under the Summary sheet's run-warnings heading; None when there is no heading."""
    ws = load_workbook(path)["Summary"]
    column = [ws.cell(row=r, column=1).value for r in range(1, ws.max_row + 1)]
    if _RUN_WARNINGS not in column:
        return None
    rows = []
    for value in column[column.index(_RUN_WARNINGS) + 1:]:
        if value is None:
            break
        rows.append(value)
    return rows


def test_the_summary_lists_the_runs_warnings(tmp_path, sample_findings):
    path = tmp_path / "w.xlsx"
    warnings = ["Could not parse results file: bad.xml — invalid XML: tag mismatch", "=HYPERLINK(\"x\")"]
    ExcelExporter().export(sample_findings, path, warnings=warnings)
    assert run_warning_rows(path) == [warnings[0], "'" + warnings[1]]


def test_a_run_without_warnings_has_no_warnings_block(tmp_path, sample_findings):
    for warnings in (None, []):
        path = tmp_path / "w.xlsx"
        ExcelExporter().export(sample_findings, path, warnings=warnings)
        assert run_warning_rows(path) is None


def test_the_warnings_block_is_capped_like_the_web_ui(tmp_path, sample_findings):
    path = tmp_path / "w.xlsx"
    ExcelExporter().export(sample_findings, path, warnings=[f"line {n}" for n in range(203)])
    rows = run_warning_rows(path)
    assert rows[:200] == [f"line {n}" for n in range(200)] and rows[200:] == ["… and 3 more warnings not shown"]
