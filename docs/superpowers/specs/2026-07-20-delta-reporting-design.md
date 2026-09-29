# Delta Reporting — Design

**Date:** 2026-07-20
**Status:** Approved (design), pending implementation plan

## Problem

STIG compliance scans are re-run over time against the same hosts. Engineers
need to answer "what changed since the last scan" for POA&M / accreditation
progress reporting: which findings are newly open (regressions), which were
remediated, and which persist. Today the tool produces a single-run findings
report with no cross-run comparison, forcing manual diffing.

## Scope

Baseline-vs-current delta of two scan sets, CLI-first. Web UI is a follow-up.

### Locked decisions

| Decision | Choice | Rationale |
|---|---|---|
| Comparison model | Baseline vs current (directional) | Matches POA&M "progress" job; "New"/"Resolved" only meaningful with old/new labels. Superset-compatible with future multi-run trend. |
| Finding identity | `(server, vuln_id)` | `vuln_id` (V-XXXXXX) is stable across DISA benchmark revisions; `rule_id` revision churn would otherwise flag every rule new+resolved. |
| "Resolved" honesty | Coverage-scoped | Findings list is actionable-only (Pass never appears), so absence is ambiguous. Only compare hosts present in BOTH runs; baseline-only hosts flagged "not re-scanned," never counted resolved. |
| Input | Two scan sets | Each set runs the existing `parse_stage` pipeline; delta compares the two `list[Finding]` outputs. |
| Output | Single delta workbook | One Findings sheet with a `Delta` tag column + a Summary sheet (delta counts + coverage). Matches existing single-sheet exporter shape. |
| CLI surface | `delta` subcommand | Distinct inputs (baseline/current) warrant their own command; keeps existing single-run invocation intact. |

### Out of scope (future upgrades, do not build now)

- Multi-run trend / finding lifecycle across N scans.
- Re-import prior Excel report as baseline (round-trip via `findings_io`).
- Retaining Pass status to *prove* Open→Pass rather than infer via absence.
- Web UI (follow-up commit after CLI lands).

## Architecture

### 1. New module `app/processors/delta.py`

Pure, I/O-free. Reuses two `parse_stage` outputs.

```python
compute_delta(baseline: list[Finding], current: list[Finding]) -> DeltaResult
```

New dataclasses (add to `app/processors/delta.py`, or `base.py` if shared):

```python
@dataclass
class DeltaFinding:
    # all Finding fields (stig_title, vuln_id, rule_id, severity, server,
    # ip_address, check_text, fix_text) plus:
    delta_status: str          # "New" | "Resolved" | "Persisting"
    baseline_status: str       # "" for New
    current_status: str        # "" for Resolved

@dataclass
class DeltaResult:
    findings: list[DeltaFinding]
    common_hosts: set[str]
    only_baseline_hosts: set[str]   # "not re-scanned"
    only_current_hosts: set[str]    # "new host"
    # counts derived (helper methods or computed fields):
    #   new/resolved/persisting totals, and per-severity breakdown
```

### 2. Matching logic

- Build host sets from `{f.server}` of each input list.
- `common = baseline_hosts & current_hosts`
- `only_baseline = baseline_hosts - current_hosts`  → "Not re-scanned"
- `only_current  = current_hosts - baseline_hosts`  → "New host"
- Classification (only for findings whose host is in `common`, plus new-host findings):
  - key present in current only (host in common) → **New**
  - key present in baseline only (host in common) → **Resolved**
  - key in both → **Persisting** (`baseline_status`, `current_status` retained to
    surface within-actionable flips, e.g. Not Reviewed → Open)
  - host in `only_current` → all its findings **New** (new host)
  - host in `only_baseline` → findings **excluded** from New/Resolved (host is
    reported under coverage, not as remediation)
- A **Resolved** row carries the baseline finding's data (check/fix/severity/title);
  `current_status` is blank. A **New** row carries current data; `baseline_status` blank.

### 3. Exporter — extend `app/exporters/excel_exporter.py`

New method `export_delta(delta: DeltaResult, output_path: Path) -> Path`.

- **Findings** sheet: existing 9 columns with a prepended **Delta** column
  (values New / Resolved / Persisting). Conditional fill by delta status
  (New = red-ish, Resolved = green, Persisting = amber). Column-letter
  constants shift by one — update the `_COL_*` refs used by Summary COUNTIFS.
- **Summary** sheet: delta counts by severity (New/Resolved/Persisting × CAT I/II/III)
  and a **Coverage** block: hosts compared, hosts not re-scanned (listed),
  new hosts (listed).
- Reuse `_sanitize_cell` and `_formula_quote` for all scan-derived text
  (CWE-1236 formula-injection protection must remain intact).

### 4. CLI wiring — `app/cli.py`

Introduce argparse subparsers:

- `report` — existing behavior (`--results`, `--benchmarks`, `--output`, `--verbose`).
- `delta` — `--baseline PATH...`, `--current PATH...`, shared `--benchmarks`,
  `--output`, `--verbose`.

**Backward compatibility:** existing invocation `stig-parser --results ...`
(no subcommand) must keep working. Route no-subcommand + `--results` to the
`report` path via a compatibility shim so existing scripts/docs don't break.

`delta` flow: `parse_stage(baseline)` + `parse_stage(current)` →
`compute_delta` → `export_delta`. Default output name
`stig_delta_<timestamp>.xlsx`.

### 5. Web (follow-up, not this iteration)

Sketch only: new `POST /api/delta` route taking `baseline` / `current` /
`benchmarks` file lists; `_run_delta_job` mirroring `_run_job`; two dropzones
in the template. Deferred to a separate commit after CLI ships.

## Error handling

- Either set producing zero actionable findings: still valid (e.g. all
  remediated → all Resolved, or clean baseline → all New). Do **not** reuse
  `ExcelExporter.export`'s empty-list `ValueError`; `export_delta` must handle
  an all-one-bucket result. Only a genuinely empty delta (no findings either
  side) is an error.
- `parse_stage` `PipelineError` on either set surfaces per-set (message names
  baseline vs current).
- No host overlap at all (`common` empty): valid but emit a prominent warning —
  the report is effectively "all baseline hosts not re-scanned, all current
  hosts new," which usually signals a hostname-mismatch mistake.

## Testing (TDD)

`tests/test_delta.py`:
- New / Resolved / Persisting classification on overlapping hosts.
- Coverage scoping: baseline-only host's findings NOT counted resolved; listed
  as not-re-scanned.
- New-host findings all tagged New.
- Persisting with status flip (Not Reviewed → Open) retains both statuses.
- Benchmark-version churn: same `vuln_id`, different `rule_id` revision →
  Persisting, not New+Resolved.
- Empty baseline (all New), empty current (all Resolved).
- Zero host overlap → warning path.

`tests/test_excel_exporter.py` (extend):
- `export_delta` writes a Delta column with correct tags.
- Summary coverage block lists not-re-scanned and new hosts.
- Formula-injection sanitization still applied to delta rows.

`tests/test_cli.py` (extend):
- `delta` subcommand end-to-end (two fixture sets → xlsx).
- Backward-compat: `--results` without subcommand still runs `report`.

## Module boundaries

- `delta.py` — pure comparison, depends only on `Finding` / new dataclasses.
  Testable without files or Excel.
- `excel_exporter.export_delta` — presentation only; consumes `DeltaResult`.
- `cli.py` — orchestration; composes existing `parse_stage`/`export_stage`
  with the new delta path.

---

## Revision 2 — 2026-09-28: coverage is per host and STIG, taken from the scans

**Why.** Live run on a real SCC session (one host, seven STIGs, 322 Open findings): a current set that omitted two of the seven STIG scans, with nothing fixed, produced **90 Resolved** and exit 0 with no warning. Two independent reviews found the same root cause: host coverage is derived from the *actionable finding lists*, so a host or STIG with no findings left is invisible, and a STIG that was not re-scanned looks identical to one that was fully remediated. The same defect makes a fully remediated host disappear from the report as "not re-scanned", contradicting §Error handling ("all remediated → all Resolved").

**Decisions (supersede §2 "Matching logic" and the host-level coverage bullets).**

| # | Decision |
|---|---|
| R2-1 | `parse_stage` returns `coverage: set[(server, stig_title)]` built from every parsed row **before** the actionable filter, plus one pair per XCCDF scan file from its hostname and matched benchmark title. A scan with zero findings still contributes its pairs. |
| R2-2 | `compute_delta(baseline, current, *, baseline_coverage, current_coverage)`; coverage is required, never derived from findings. Keys are `(_host_key(server), _stig_key(stig_title))`. `_stig_key` casefolds and drops product-neutral tokens (`stig`, `scap`, `benchmark`, `security technical implementation guide`, `manual`, `disa`, version tokens like `v2r8`, `.audit`) so the SCAP and Manual editions of one STIG share a key. |
| R2-3 | Host sets come from coverage. A host only in current coverage: every finding is **Newly scanned**. A host only in baseline coverage: every finding is **Not re-scanned**. Neither is ever counted as New or Resolved. |
| R2-4 | On common hosts the two-pass match stays host-scoped (pass 1 `(host, vuln_id)`, pass 2 `(host, rule stem)` with the XCCDF prefix and `rNNNNNN` revision stripped, blank rule IDs never matched). Matched pairs are **Persisting**. A leftover baseline finding is **Resolved** only if its `(host, stig)` pair is in current coverage, otherwise **Not re-scanned**. A leftover current finding is **New** only if its pair is in baseline coverage, otherwise **Newly scanned**. |
| R2-5 | `DELTA_STATUSES = ("New", "Resolved", "Persisting", "Not re-scanned", "Newly scanned")`. The Findings sheet keeps the 11-column layout; the Summary counts every status; the Coverage block lists hosts compared, and each `(host, STIG)` pair not re-scanned and newly scanned. |
| R2-6 | Every coverage warning (no host overlap, hosts or STIGs not re-scanned, asymmetric Vuln-ID coverage, duplicates) is appended to `DeltaResult.warnings`, so it reaches the workbook, not only the CLI log. |
| R2-7 | `allow_empty` relaxes only the zero-*actionable* case. Zero rule results still raises `PipelineError`. |
| R2-8 | Rows sort by normalised host key. |

**Recorded as built (undocumented until now):** two-pass identity match with host-name normalisation; Baseline Status / Current Status split; `export()` shares the findings-sheet writer with `export_delta()` and its output is unchanged.

**Acceptance on the real session:** same set both sides → 322 Persisting; current adds two STIG scans → 90 Newly scanned, 0 New; current omits two STIG scans → 90 Not re-scanned, 0 Resolved; current with every result set to pass → 322 Resolved.
