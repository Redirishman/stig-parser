# Delta Reporting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a baseline-vs-current delta report to STIG Condenser — compare two scan sets and emit an Excel workbook tagging each finding New / Resolved / Persisting, coverage-scoped so unscanned hosts are never counted as remediated.

**Architecture:** A pure comparison module (`app/processors/delta.py`) diffs two `list[Finding]` (each produced by the existing `parse_stage`). A new `ExcelExporter.export_delta` renders the result. A new `delta` CLI subcommand orchestrates parse → compute_delta → export, while the existing bare `--results` invocation stays working via a back-compat shim.

**Tech Stack:** Python 3.14, dataclasses, openpyxl, pytest, argparse subparsers.

Spec: `docs/superpowers/specs/2026-07-20-delta-reporting-design.md`

---

## File Structure

- **Create** `app/processors/delta.py` — `DeltaFinding`, `DeltaResult`, `compute_delta`. Pure, no I/O.
- **Create** `tests/test_delta.py` — comparison logic tests.
- **Modify** `app/exporters/excel_exporter.py` — add `export_delta` + delta-specific column/fill constants. Existing `export` untouched.
- **Modify** `tests/test_excel_exporter.py` — delta workbook tests.
- **Modify** `app/core/pipeline.py` — add `export_delta_stage`, `default_delta_output_name`.
- **Modify** `app/cli.py` — argparse subparsers (`report`, `delta`) + back-compat shim.
- **Modify** `tests/test_cli.py` — subcommand parsing + end-to-end delta run + back-compat.

**Boundary note:** the delta findings sheet uses its OWN column layout and its OWN summary column constants (`_DELTA_COL_*`). Do NOT mutate the existing `_COL_*` constants — those still serve the single-run report sheet.

---

## Task 1: Delta dataclasses + core classification

**Files:**
- Create: `app/processors/delta.py`
- Test: `tests/test_delta.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_delta.py
"""Tests for app.processors.delta — baseline-vs-current comparison."""
from __future__ import annotations

from app.parsers.base import Finding
from app.processors.delta import DeltaFinding, DeltaResult, compute_delta


def _finding(
    vuln_id: str,
    server: str = "SERVER01",
    status: str = "Open",
    severity: str = "CAT II",
    rule_id: str = "SV-1r1_rule",
) -> Finding:
    return Finding(
        stig_title="Win2022 STIG",
        vuln_id=vuln_id,
        rule_id=rule_id,
        severity=severity,
        status=status,
        server=server,
        ip_address="10.0.0.1",
        check_text="check",
        fix_text="fix",
    )


def _by_status(result: DeltaResult) -> dict[str, list[DeltaFinding]]:
    out: dict[str, list[DeltaFinding]] = {"New": [], "Resolved": [], "Persisting": []}
    for f in result.findings:
        out[f.delta_status].append(f)
    return out


class TestClassificationSameHost:
    def test_persisting_when_in_both(self):
        base = [_finding("V-1")]
        curr = [_finding("V-1")]
        buckets = _by_status(compute_delta(base, curr))
        assert len(buckets["Persisting"]) == 1
        assert buckets["New"] == []
        assert buckets["Resolved"] == []

    def test_new_when_only_current(self):
        base = [_finding("V-1")]
        curr = [_finding("V-1"), _finding("V-2")]
        buckets = _by_status(compute_delta(base, curr))
        new = buckets["New"]
        assert len(new) == 1
        assert new[0].vuln_id == "V-2"
        assert new[0].baseline_status == ""
        assert new[0].current_status == "Open"

    def test_resolved_when_only_baseline(self):
        base = [_finding("V-1"), _finding("V-2")]
        curr = [_finding("V-1")]
        buckets = _by_status(compute_delta(base, curr))
        resolved = buckets["Resolved"]
        assert len(resolved) == 1
        assert resolved[0].vuln_id == "V-2"
        assert resolved[0].current_status == ""
        assert resolved[0].baseline_status == "Open"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_delta.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.processors.delta'`

- [ ] **Step 3: Write minimal implementation**

```python
# app/processors/delta.py
"""Baseline-vs-current comparison of two actionable finding sets.

Pure and I/O-free. Consumes two ``list[Finding]`` (each the output of the
existing parse pipeline) and classifies every finding as New, Resolved, or
Persisting. Identity is keyed on ``(server, vuln_id)`` — ``vuln_id`` is stable
across DISA benchmark revisions, where ``rule_id`` is not.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.parsers.base import Finding

_NEW = "New"
_RESOLVED = "Resolved"
_PERSISTING = "Persisting"


@dataclass
class DeltaFinding:
    """A finding tagged with its cross-run delta status."""
    stig_title: str
    vuln_id: str
    rule_id: str
    severity: str
    server: str
    ip_address: str
    check_text: str
    fix_text: str
    delta_status: str      # "New" | "Resolved" | "Persisting"
    baseline_status: str   # "" for New
    current_status: str    # "" for Resolved


@dataclass
class DeltaResult:
    """Full delta between a baseline and a current scan set."""
    findings: list[DeltaFinding] = field(default_factory=list)
    common_hosts: set[str] = field(default_factory=set)
    only_baseline_hosts: set[str] = field(default_factory=set)
    only_current_hosts: set[str] = field(default_factory=set)


def _tag(
    f: Finding, delta_status: str, baseline_status: str, current_status: str
) -> DeltaFinding:
    return DeltaFinding(
        stig_title=f.stig_title,
        vuln_id=f.vuln_id,
        rule_id=f.rule_id,
        severity=f.severity,
        server=f.server,
        ip_address=f.ip_address,
        check_text=f.check_text,
        fix_text=f.fix_text,
        delta_status=delta_status,
        baseline_status=baseline_status,
        current_status=current_status,
    )


def compute_delta(
    baseline: list[Finding], current: list[Finding]
) -> DeltaResult:
    """Compare two actionable finding sets and classify each finding.

    Classification is keyed on ``(server, vuln_id)``. This step assumes both
    hosts overlap; coverage scoping (unscanned / new hosts) is layered on in a
    later step.
    """
    b_index = {(f.server, f.vuln_id): f for f in baseline}
    c_index = {(f.server, f.vuln_id): f for f in current}

    result = DeltaResult()
    for key in set(b_index) | set(c_index):
        b = b_index.get(key)
        c = c_index.get(key)
        if b and c:
            result.findings.append(_tag(c, _PERSISTING, b.status, c.status))
        elif c is not None:
            result.findings.append(_tag(c, _NEW, "", c.status))
        else:
            result.findings.append(_tag(b, _RESOLVED, b.status, ""))

    result.findings.sort(key=lambda f: (f.server, f.vuln_id, f.delta_status))
    return result
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_delta.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add app/processors/delta.py tests/test_delta.py
git commit -m "feat(delta): add compute_delta core classification"
```

---

## Task 2: Coverage scoping (unscanned + new hosts)

**Files:**
- Modify: `app/processors/delta.py`
- Test: `tests/test_delta.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_delta.py — append
class TestCoverageScoping:
    def test_baseline_only_host_not_counted_resolved(self):
        # SERVER02 present in baseline only -> its findings are NOT resolved
        base = [_finding("V-1", "SERVER01"), _finding("V-9", "SERVER02")]
        curr = [_finding("V-1", "SERVER01")]
        result = compute_delta(base, curr)
        buckets = _by_status(result)
        assert [f.vuln_id for f in buckets["Resolved"]] == []
        assert result.only_baseline_hosts == {"SERVER02"}
        assert result.common_hosts == {"SERVER01"}

    def test_current_only_host_all_new(self):
        base = [_finding("V-1", "SERVER01")]
        curr = [_finding("V-1", "SERVER01"), _finding("V-5", "SERVER03")]
        result = compute_delta(base, curr)
        buckets = _by_status(result)
        new_on_new_host = [f for f in buckets["New"] if f.server == "SERVER03"]
        assert len(new_on_new_host) == 1
        assert result.only_current_hosts == {"SERVER03"}

    def test_resolved_only_on_common_host(self):
        base = [_finding("V-1", "SERVER01"), _finding("V-2", "SERVER01")]
        curr = [_finding("V-1", "SERVER01")]
        buckets = _by_status(compute_delta(base, curr))
        assert [f.vuln_id for f in buckets["Resolved"]] == ["V-2"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_delta.py::TestCoverageScoping -v`
Expected: FAIL — `only_baseline_hosts` empty / baseline-only findings wrongly tagged Resolved.

- [ ] **Step 3: Update `compute_delta` to scope by host coverage**

Replace the body of `compute_delta` from `result = DeltaResult()` onward with:

```python
    baseline_hosts = {f.server for f in baseline}
    current_hosts = {f.server for f in current}
    common = baseline_hosts & current_hosts

    result = DeltaResult(
        common_hosts=common,
        only_baseline_hosts=baseline_hosts - current_hosts,
        only_current_hosts=current_hosts - baseline_hosts,
    )

    for key in set(b_index) | set(c_index):
        server, _vuln = key
        b = b_index.get(key)
        c = c_index.get(key)

        if server in result.only_current_hosts:
            # Whole host is new — every finding on it is New.
            result.findings.append(_tag(c, _NEW, "", c.status))
            continue
        if server in result.only_baseline_hosts:
            # Host was not re-scanned — cannot infer remediation. Exclude.
            continue

        # server in common
        if b and c:
            result.findings.append(_tag(c, _PERSISTING, b.status, c.status))
        elif c is not None:
            result.findings.append(_tag(c, _NEW, "", c.status))
        else:
            result.findings.append(_tag(b, _RESOLVED, b.status, ""))

    result.findings.sort(key=lambda f: (f.server, f.vuln_id, f.delta_status))
    return result
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_delta.py -v`
Expected: PASS (all Task 1 + Task 2 tests)

- [ ] **Step 5: Commit**

```bash
git add app/processors/delta.py tests/test_delta.py
git commit -m "feat(delta): coverage-scope resolution to hosts in both runs"
```

---

## Task 3: Status-flip retention + benchmark-revision stability + empty sets

**Files:**
- Test: `tests/test_delta.py` (no implementation change expected — these assert existing behavior; if any fails, fix `compute_delta`)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_delta.py — append
class TestPersistingDetail:
    def test_status_flip_retained(self):
        base = [_finding("V-1", status="Not Reviewed")]
        curr = [_finding("V-1", status="Open")]
        f = compute_delta(base, curr).findings[0]
        assert f.delta_status == "Persisting"
        assert f.baseline_status == "Not Reviewed"
        assert f.current_status == "Open"

    def test_benchmark_revision_churn_is_persisting(self):
        # Same vuln_id, different rule_id revision -> Persisting, not New+Resolved
        base = [_finding("V-1", rule_id="SV-1r1_rule")]
        curr = [_finding("V-1", rule_id="SV-1r2_rule")]
        buckets = _by_status(compute_delta(base, curr))
        assert len(buckets["Persisting"]) == 1
        assert buckets["New"] == [] and buckets["Resolved"] == []


class TestEmptySets:
    def test_empty_baseline_all_new(self):
        # No baseline hosts -> every current host is a new host -> all New
        curr = [_finding("V-1"), _finding("V-2")]
        buckets = _by_status(compute_delta([], curr))
        assert len(buckets["New"]) == 2
        assert buckets["Resolved"] == []

    def test_empty_current_all_not_rescanned(self):
        # No current hosts -> baseline hosts all unscanned -> nothing Resolved
        base = [_finding("V-1"), _finding("V-2")]
        result = compute_delta(base, [])
        assert result.findings == []
        assert result.only_baseline_hosts == {"SERVER01"}

    def test_both_empty(self):
        result = compute_delta([], [])
        assert result.findings == []
```

- [ ] **Step 2: Run tests**

Run: `python -m pytest tests/test_delta.py -v`
Expected: PASS. If `test_empty_current_all_not_rescanned` or others fail, the coverage logic in Task 2 needs review — fix `compute_delta` until green.

- [ ] **Step 3: Commit**

```bash
git add tests/test_delta.py
git commit -m "test(delta): cover status flips, revision churn, empty sets"
```

---

## Task 4: Exporter — delta findings sheet

**Files:**
- Modify: `app/exporters/excel_exporter.py`
- Test: `tests/test_excel_exporter.py`

Delta findings sheet column layout (1-indexed):
`1 Delta · 2 STIG Title · 3 Vuln ID · 4 Rule ID · 5 Severity · 6 Baseline Status · 7 Current Status · 8 Server · 9 IP Address · 10 Check Text · 11 Fix Text`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_excel_exporter.py — append near the other tests
from app.processors.delta import DeltaFinding, DeltaResult


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
    ExcelExporter().export_delta(DeltaResult(findings=[evil], only_current_hosts={"=HYPERLINK(1)"}), out)
    wb = load_workbook(out)
    ws = wb["Findings"]
    # STIG Title is column 2 in the delta layout
    title_cell = next(
        ws.cell(row=r, column=2).value for r in range(2, ws.max_row + 1)
    )
    assert str(title_cell).startswith("'=")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_excel_exporter.py -k export_delta -v`
Expected: FAIL — `AttributeError: 'ExcelExporter' object has no attribute 'export_delta'`

- [ ] **Step 3: Add delta constants + `export_delta` findings sheet**

In `app/exporters/excel_exporter.py`, after the existing `_SEVERITY_FILL` block add:

```python
# Delta-status fills (findings sheet "Delta" column)
_FILL_NEW        = PatternFill("solid", fgColor="FFC7CE")  # red-ish: regression
_FILL_RESOLVED   = PatternFill("solid", fgColor="C6EFCE")  # green: remediated
_FILL_PERSISTING = PatternFill("solid", fgColor="FFEB9C")  # amber: still open
_DELTA_FILL = {
    "New": _FILL_NEW,
    "Resolved": _FILL_RESOLVED,
    "Persisting": _FILL_PERSISTING,
}

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
_DELTA_COL_SERVER   = "H"   # col 8
```

Then add these methods to the `ExcelExporter` class (below `export`):

```python
    def export_delta(self, delta: "DeltaResult", output_path: Path) -> Path:
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
        self._write_delta_findings(findings_ws, delta)

        summary_ws = wb.create_sheet("Summary")
        self._write_delta_summary(summary_ws, delta)

        wb.save(str(output_path))
        log.info("Delta workbook written to %s", output_path)
        return output_path

    def _write_delta_findings(self, ws, delta: "DeltaResult") -> None:
        for col_idx, (header, _, _mw) in enumerate(_DELTA_COLS, start=1):
            cell = ws.cell(row=1, column=col_idx, value=header)
            cell.font = _HEADER_FONT
            cell.alignment = Alignment(vertical="center")

        ws.freeze_panes = "A2"
        ws.auto_filter.ref = f"A1:{get_column_letter(len(_DELTA_COLS))}1"

        for row_idx, finding in enumerate(delta.findings, start=2):
            for col_idx, (header, attr, _mw) in enumerate(_DELTA_COLS, start=1):
                value = getattr(finding, attr, "")
                wrap = header in _WRAP_HEADERS
                cell = ws.cell(row=row_idx, column=col_idx, value=_sanitize_cell(value))
                cell.font = _BODY_FONT
                cell.alignment = Alignment(
                    wrap_text=wrap,
                    vertical="top" if wrap else "center",
                )
                if header == "Delta":
                    fill = _DELTA_FILL.get(value)
                    if fill:
                        cell.fill = fill
                elif header == "Severity":
                    fill = _SEVERITY_FILL.get(value)
                    if fill:
                        cell.fill = fill

        for col_idx, (header, attr, max_w) in enumerate(_DELTA_COLS, start=1):
            col_letter = get_column_letter(col_idx)
            measured = len(header)
            for row_idx in range(2, ws.max_row + 1):
                val = ws.cell(row=row_idx, column=col_idx).value or ""
                measured = max(measured, min(len(str(val).split("\n")[0]), max_w))
            ws.column_dimensions[col_letter].width = min(measured + 2, max_w)
```

(`_write_delta_summary` is added in Task 5. To keep this task's tests green, add a temporary stub now:)

```python
    def _write_delta_summary(self, ws, delta: "DeltaResult") -> None:
        pass  # implemented in Task 5
```

Add the import for the type at the top of the file (used only for annotations):

```python
from app.processors.delta import DeltaResult
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_excel_exporter.py -k export_delta -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add app/exporters/excel_exporter.py tests/test_excel_exporter.py
git commit -m "feat(delta): export delta findings sheet with status tags"
```

---

## Task 5: Exporter — delta summary sheet (counts + coverage)

**Files:**
- Modify: `app/exporters/excel_exporter.py`
- Test: `tests/test_excel_exporter.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_excel_exporter.py — append
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_excel_exporter.py -k delta_summary -v`
Expected: FAIL — Summary sheet is empty (stub), assertions miss.

- [ ] **Step 3: Replace the `_write_delta_summary` stub with the real implementation**

```python
    def _write_delta_summary(self, ws, delta: "DeltaResult") -> None:
        f = "Findings"
        severities = ["CAT I", "CAT II", "CAT III"]
        delta_statuses = ["New", "Resolved", "Persisting"]

        def countifs2(col_a: str, crit_a: str, col_b: str, crit_b: str) -> str:
            return (
                f'=COUNTIFS({f}!${col_a}:${col_a},{crit_a},'
                f'{f}!${col_b}:${col_b},{crit_b})'
            )

        def h(row, col, text):
            c = ws.cell(row=row, column=col, value=text)
            c.font = _HEADER_FONT
            return c

        def b(row, col, value):
            c = ws.cell(row=row, column=col, value=value)
            c.font = _BODY_FONT
            return c

        row = 1

        # ── Table 1: Delta status × severity ──────────────────────────
        h(row, 1, "Delta Summary")
        row += 1
        for ci, lbl in enumerate(["Delta", *severities, "Total"], 1):
            h(row, ci, lbl)
        row += 1
        for ds in delta_statuses:
            b(row, 1, ds)
            for ci, sev in enumerate(severities, 2):
                b(row, ci, countifs2(
                    _DELTA_COL_DELTA, _formula_quote(ds),
                    _DELTA_COL_SEVERITY, _formula_quote(sev),
                ))
            b(row, 5, f"=SUM(B{row}:D{row})")
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

        for col_idx in range(1, 6):
            col_letter = get_column_letter(col_idx)
            max_len = 10
            for r in range(1, row + 1):
                val = ws.cell(row=r, column=col_idx).value or ""
                if not str(val).startswith("="):
                    max_len = max(max_len, len(str(val)))
            ws.column_dimensions[col_letter].width = min(max_len + 2, 60)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_excel_exporter.py -v`
Expected: PASS (all existing + new delta tests)

- [ ] **Step 5: Commit**

```bash
git add app/exporters/excel_exporter.py tests/test_excel_exporter.py
git commit -m "feat(delta): delta summary sheet with counts and coverage"
```

---

## Task 6: Pipeline helpers

**Files:**
- Modify: `app/core/pipeline.py`
- Test: `tests/test_pipeline.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_pipeline.py — append
from app.core.pipeline import default_delta_output_name, export_delta_stage
from app.processors.delta import DeltaResult


def test_default_delta_output_name_shape():
    name = default_delta_output_name()
    assert name.startswith("stig_delta_") and name.endswith(".xlsx")


def test_export_delta_stage_writes_file(tmp_path):
    from app.processors.delta import DeltaFinding
    delta = DeltaResult(
        findings=[
            DeltaFinding(
                stig_title="t", vuln_id="V-1", rule_id="SV-1r1_rule",
                severity="CAT I", server="SERVER01", ip_address="10.0.0.1",
                check_text="c", fix_text="f", delta_status="New",
                baseline_status="", current_status="Open",
            )
        ],
        only_current_hosts={"SERVER01"},
    )
    out = tmp_path / "d.xlsx"
    export_delta_stage(delta, out)
    assert out.exists()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_pipeline.py -k delta -v`
Expected: FAIL — `ImportError: cannot import name 'default_delta_output_name'`

- [ ] **Step 3: Add helpers to `app/core/pipeline.py`**

Add near `export_stage` / `default_output_name`:

```python
def export_delta_stage(delta, output_path: Path) -> None:
    """Write a delta result to an Excel workbook at ``output_path``."""
    ExcelExporter().export_delta(delta, output_path)


def default_delta_output_name() -> str:
    """Timestamped default delta output filename."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"stig_delta_{ts}.xlsx"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_pipeline.py -k delta -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add app/core/pipeline.py tests/test_pipeline.py
git commit -m "feat(delta): pipeline export_delta_stage + default name"
```

---

## Task 7: CLI subparsers + back-compat shim

**Files:**
- Modify: `app/cli.py`
- Test: `tests/test_cli.py`

This task restructures `_build_parser` to use subparsers (`report`, `delta`)
while keeping bare `--results` working. Existing tests call
`parser.parse_args(["--results", "a.xml"])` with NO subcommand — those must
still pass. Achieve this by injecting an implicit `report` subcommand when the
first arg is not a known subcommand.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli.py — append
class TestDeltaArgs:
    def test_delta_subcommand_parses(self):
        parser = _build_parser()
        args = parser.parse_args(
            ["delta", "--baseline", "a.xml", "--current", "b.xml"]
        )
        assert args.command == "delta"
        assert args.baseline == ["a.xml"]
        assert args.current == ["b.xml"]

    def test_delta_accepts_benchmarks_and_output(self):
        parser = _build_parser()
        args = parser.parse_args([
            "delta", "--baseline", "a.xml", "--current", "b.xml",
            "--benchmarks", "x.xml", "--output", "d.xlsx",
        ])
        assert args.benchmarks == ["x.xml"]
        assert args.output == "d.xlsx"

    def test_report_subcommand_parses(self):
        parser = _build_parser()
        args = parser.parse_args(["report", "--results", "a.xml"])
        assert args.command == "report"
        assert args.results == ["a.xml"]

    def test_bare_results_still_works(self):
        # Back-compat: no subcommand + --results routes to report
        args = _normalize_argv(["--results", "a.xml"])
        assert args[0] == "report"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cli.py::TestDeltaArgs -v`
Expected: FAIL — subparsers/`command` attr and `_normalize_argv` do not exist.

- [ ] **Step 3: Rewrite `_build_parser` and add `_normalize_argv`**

Replace `_build_parser` in `app/cli.py` with:

```python
_SUBCOMMANDS = ("report", "delta")


def _add_common_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--output", metavar="FILE", default=None,
        help="Output Excel file path.",
    )
    p.add_argument(
        "--verbose", action="store_true",
        help="Enable detailed logging output.",
    )


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="stig-parser",
        description=(
            "Parse XCCDF compliance scan results and STIG benchmark "
            "definitions into a consolidated Excel findings report, or diff "
            "two scan sets (delta)."
        ),
    )
    sub = p.add_subparsers(dest="command")

    # ── report (default single-run behavior) ──────────────────────────
    rp = sub.add_parser("report", help="Single-run findings report.")
    rp.add_argument(
        "--results", nargs="+", required=True, metavar="PATH",
        help=(
            "XCCDF results files (.xml) and/or Evaluate-STIG / STIG Viewer 3 "
            "checklists (.cklb) / .nessus, or a directory (supports globs)."
        ),
    )
    rp.add_argument(
        "--benchmarks", nargs="*", required=False, default=None, metavar="PATH",
        help=(
            "STIG benchmark XML/ZIP files or directory (supports globs). "
            "Optional for SCC — result files already embed benchmarks."
        ),
    )
    _add_common_flags(rp)

    # ── delta (baseline vs current) ───────────────────────────────────
    dp = sub.add_parser("delta", help="Diff a baseline scan set against a current one.")
    dp.add_argument(
        "--baseline", nargs="+", required=True, metavar="PATH",
        help="Baseline (older) scan results — same formats as report --results.",
    )
    dp.add_argument(
        "--current", nargs="+", required=True, metavar="PATH",
        help="Current (newer) scan results — same formats as report --results.",
    )
    dp.add_argument(
        "--benchmarks", nargs="*", required=False, default=None, metavar="PATH",
        help="STIG benchmark XML/ZIP applied to BOTH sets (optional for SCC).",
    )
    _add_common_flags(dp)

    return p


def _normalize_argv(argv: list[str]) -> list[str]:
    """Inject an implicit ``report`` subcommand for back-compat.

    Historically the CLI was invoked as ``stig-parser --results ...`` with no
    subcommand. If the first token is not a known subcommand (and not a bare
    ``-h``/``--help``), prepend ``report`` so old invocations keep working.
    """
    if argv and argv[0] not in _SUBCOMMANDS and argv[0] not in ("-h", "--help"):
        return ["report", *argv]
    return argv
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_cli.py::TestDeltaArgs -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Update existing `TestArgumentParsing` tests to route through `_normalize_argv`**

The existing tests call `parser.parse_args(["--results", "a.xml"])` directly.
With subparsers those now need the implicit `report`. Update each call in
`tests/test_cli.py`'s `TestArgumentParsing` class to wrap argv:

Change every `parser.parse_args([...])` in that class to
`parser.parse_args(_normalize_argv([...]))`, and add `_normalize_argv` to the
import line:

```python
from app.cli import _build_parser, _normalize_argv, _resolve_paths, main
```

- [ ] **Step 6: Run the full CLI arg test to verify it passes**

Run: `python -m pytest tests/test_cli.py -k "Argument or Delta" -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add app/cli.py tests/test_cli.py
git commit -m "feat(delta): CLI subparsers with report back-compat shim"
```

---

## Task 8: CLI delta command wiring (end-to-end)

**Files:**
- Modify: `app/cli.py`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Write the failing test**

Reuse existing XCCDF fixtures. Locate a valid results fixture first:

Run: `ls tests/fixtures/*.xml` (pick one SCC/XCCDF results file; the test below
uses a placeholder name — replace `RESULTS_FIXTURE` with a real file present in
`tests/fixtures/`).

```python
# tests/test_cli.py — append
class TestDeltaEndToEnd:
    def test_delta_run_writes_workbook(self, tmp_path):
        # Same file as both baseline and current -> every finding Persisting.
        fixture = FIXTURES / "RESULTS_FIXTURE.xml"  # replace with a real fixture
        out = tmp_path / "delta.xlsx"
        rc = main([
            "delta",
            "--baseline", str(fixture),
            "--current", str(fixture),
            "--output", str(out),
        ])
        assert rc == 0
        assert out.exists()
        wb = load_workbook(out)
        assert "Findings" in wb.sheetnames and "Summary" in wb.sheetnames
        ws = wb["Findings"]
        tags = {ws.cell(row=r, column=1).value for r in range(2, ws.max_row + 1)}
        assert tags == {"Persisting"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cli.py::TestDeltaEndToEnd -v`
Expected: FAIL — `main` does not dispatch on `command == "delta"`.

- [ ] **Step 3: Refactor `main` to dispatch by subcommand**

At the top of `main`, normalize argv and split the report path into a helper.
Replace the `main` signature/head and add a delta branch:

```python
def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    raw = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(_normalize_argv(raw))

    level = logging.DEBUG if getattr(args, "verbose", False) else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s  %(name)s  %(message)s",
        stream=sys.stderr,
    )

    if args.command == "delta":
        return _run_delta(args)
    return _run_report(args)
```

Move the existing report body (everything after logging setup in the old
`main`) into a new `_run_report(args) -> int` function. Then add `_run_delta`:

```python
def _run_delta(args) -> int:
    log = logging.getLogger("app.cli")
    from app.core.pipeline import (
        compute_summary,  # noqa: F401  (kept for parity; optional)
        default_delta_output_name,
        export_delta_stage,
        parse_stage,
    )
    from app.processors.delta import compute_delta

    baseline_paths = _resolve_paths(args.baseline, extensions=(".xml", ".cklb", ".nessus"))
    current_paths = _resolve_paths(args.current, extensions=(".xml", ".cklb", ".nessus"))
    benchmark_paths = (
        _resolve_paths(args.benchmarks, extensions=(".xml", ".zip"))
        if args.benchmarks else []
    )

    if not baseline_paths:
        log.error("No baseline results files found for: %s", args.baseline)
        return 1
    if not current_paths:
        log.error("No current results files found for: %s", args.current)
        return 1

    extract_dir = Path(tempfile.mkdtemp(prefix="stig_zip_"))
    try:
        try:
            base_res = parse_stage(baseline_paths, benchmark_paths, extract_dir)
            curr_res = parse_stage(current_paths, benchmark_paths, extract_dir)
        except PipelineError as exc:
            log.error("%s", exc)
            return 1

        for w in (*base_res.warnings, *curr_res.warnings):
            log.warning(w)

        delta = compute_delta(base_res.findings, curr_res.findings)
        if not delta.common_hosts:
            log.warning(
                "No hosts appear in BOTH scan sets — check that hostnames "
                "match. All baseline hosts are 'not re-scanned' and all "
                "current hosts are 'new'."
            )

        output_path = Path(args.output) if args.output else Path(default_delta_output_name())
        log.info("Exporting delta to %s…", output_path)
        try:
            export_delta_stage(delta, output_path)
        except ValueError as exc:
            log.error("Export failed: %s", exc)
            return 1

        print(f"Delta report written: {output_path.resolve()}")
        return 0
    finally:
        shutil.rmtree(extract_dir, ignore_errors=True)
```

Verify the imports `shutil`, `tempfile`, `sys`, `PipelineError`, `Path` are
present at the top of `app/cli.py` (the existing report path already uses
`tempfile` and `Path`; add `import shutil` if the report path's cleanup does
not already import it — check the existing `finally` block).

- [ ] **Step 4: Fill in the real fixture name**

Replace `RESULTS_FIXTURE.xml` in the test with an actual file from
`tests/fixtures/` (from the `ls` in Step 1).

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_cli.py -v`
Expected: PASS (all CLI tests incl. delta end-to-end and back-compat)

- [ ] **Step 6: Run the full suite**

Run: `python -m pytest -q`
Expected: PASS (no regressions)

- [ ] **Step 7: Commit**

```bash
git add app/cli.py tests/test_cli.py
git commit -m "feat(delta): wire delta subcommand end-to-end"
```

---

## Task 9: Docs — README delta usage

**Files:**
- Modify: `README.md` (or `stig-parser/README.md` — whichever documents CLI usage)

- [ ] **Step 1: Find the CLI usage section**

Run: `grep -rn "\-\-results" README.md stig-parser/README.md 2>/dev/null`

- [ ] **Step 2: Add a delta usage subsection**

Document the new subcommand next to the existing usage:

```markdown
### Delta report (compare two scans)

Compare a baseline scan set against a current one to see what changed:

    stig-parser delta --baseline old/*.xml --current new/*.xml

Findings are tagged **New** (appeared since baseline), **Resolved** (fixed —
present in baseline, gone from current), or **Persisting** (still open). To
avoid overstating progress, comparison is scoped to hosts present in BOTH
scans; hosts only in the baseline are listed as "not re-scanned" and never
counted as resolved.

The single-run report is unchanged and can also be invoked explicitly:

    stig-parser report --results scans/*.xml
```

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs(delta): document delta subcommand usage"
```

---

## Self-Review Notes

- **Spec coverage:** compute_delta (T1–3) · coverage scoping (T2) · identity `(server, vuln_id)` (T1 index keys) · exporter Delta column + fills (T4) · summary counts + coverage block (T5) · CLI subcommand + back-compat (T7–8) · error handling for empty/one-bucket and no-overlap (T4 guard, T8 warning) · web UI explicitly deferred (spec §5, not planned). All spec requirements mapped.
- **Type consistency:** `DeltaFinding` / `DeltaResult` field names identical across delta.py, exporter, pipeline, CLI. `compute_delta`, `export_delta`, `export_delta_stage`, `default_delta_output_name`, `_normalize_argv` names consistent throughout.
- **Placeholder:** one intentional fixture placeholder (`RESULTS_FIXTURE.xml`, T8 Step 4) — resolved by the `ls` in T8 Step 1 against real fixtures, since fixture filenames aren't known at plan-write time.
