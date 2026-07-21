# STIG Compliance Parser

A Python tool that ingests compliance scan results from multiple scanning tools — XCCDF results, Evaluate-STIG / STIG Viewer CKLB checklists, and Nessus compliance scans — cross-references XCCDF results against STIG benchmark definition files, and produces a consolidated Excel workbook of actionable findings. Includes a Flask web UI for interactive use and a CLI for scripted or headless workflows.

---

## Supported Scanners

| Scanner | Format | Status | Notes |
|---|---|---|---|
| DISA SCC (SCAP Compliance Checker) | XCCDF `.xml` | ✅ Tested | **Self-contained** — result files embed full benchmark definitions, so a separate benchmark upload is not required |
| OpenSCAP | XCCDF `.xml` | ✅ Tested | Separate benchmark XML (or DISA ZIP) required. Remediation-style outputs (two `<TestResult>` elements) report the post-remediation state |
| Evaluate-STIG / STIG Viewer 3 | `.cklb` (JSON) | ✅ Validated against real checklists | **Self-contained** — severity, check, and fix text are inline; no benchmark upload needed. Honors severity overrides and multi-STIG checklists |
| Nessus / ACAS compliance scans | `.nessus` | ✅ Validated against real Tenable exports | **Self-contained** — DISA `.audit` scans map Vuln-ID/Rule-ID/CAT from the compliance references; no benchmark upload needed |

For XCCDF files, scanner type is auto-detected from XML namespace declarations, the `test-system` attribute on `<TestResult>`, and generator metadata — no manual tagging required. Legacy `.ckl` checklists (STIG Viewer 2) are not supported — export as `.cklb` from STIG Viewer 3.

---

## Output

The tool generates an Excel workbook (`stig_findings_YYYYMMDD_HHMMSS.xlsx`) with two sheets:

**Findings** — One row per actionable finding:

| Column | Description |
|---|---|
| STIG Title | Benchmark name |
| Vuln ID | V-number (e.g. V-254239) |
| Rule ID | Full XCCDF rule ID |
| Severity | CAT I / CAT II / CAT III |
| Status | Open / Not Reviewed / Error / Unknown |
| Server | Target hostname |
| IP Address | Target IP address |
| Check Text | From STIG benchmark definition |
| Fix Text | From STIG benchmark definition |

**Summary** — Three rollup tables (by Severity, by Server, by STIG) with `COUNTIFS` formulas that update when rows are added or deleted from the Findings sheet.

> **Note:** Summary counts use `COUNTIFS` and reflect all data in the Findings sheet. Applying auto-filter on the Findings sheet does **not** update Summary counts — this is a known Excel limitation for cross-sheet formula references.

---

## Installation

### pip (local)

Requires Python 3.11+.

```bash
git clone https://github.com/your-username/stig-parser.git
cd stig-parser
pip install -e .
```

### Docker

```bash
docker compose up
```

Then open `http://localhost:5000` in your browser.

---

## Usage

### Web UI

Start the Flask server:

```bash
python -m flask --app app.web:create_app run
```

Open `http://localhost:5000`. Upload your scan results files (and, for non-SCC scanners, the matching STIG benchmark files), click **Process**, then download the Excel report.

### GovCloud SPA

A React frontend for the private GovCloud deployment lives in `frontend/`. The
Flask UI above still works and is the recommended way to run the tool locally or
air-gapped — it needs no AWS account and no Node toolchain.

### CLI

The CLI has two subcommands: `report` (single-run findings) and `delta`
(compare two scan sets). The historical flat form — `stig-parser --results
...` with no subcommand — still works and routes to `report`, so existing
scripts are unaffected.

#### `report` — single-run findings report

```bash
# SCC results — no separate benchmarks needed; result files are self-contained
python -m app.cli report --results ./scc-results/ --output findings.xlsx

# Other scanners — supply benchmark XMLs or DISA ZIPs
python -m app.cli report --results ./results/ --benchmarks ./benchmarks/ --output findings.xlsx

# Individual files
python -m app.cli report --results scan1.xml scan2.xml --benchmarks stig1.xml stig2.xml

# Glob patterns (Windows-safe — expanded internally)
python -m app.cli report --results "scans/*.xml" --benchmarks "stigs/*.xml" --verbose

# Default output filename (stig_findings_<timestamp>.xlsx)
python -m app.cli report --results ./results/ --benchmarks ./benchmarks/

# Flat form (no subcommand) — still supported, routes to `report`
python -m app.cli --results ./scc-results/ --output findings.xlsx
```

**Arguments:**

| Argument | Description |
|---|---|
| `--results` | Results file(s), directory, or glob pattern — `.xml`, `.cklb`, or `.nessus` (**required**) |
| `--benchmarks` | Benchmark file(s), directory, or glob pattern. **Only needed for OpenSCAP** — SCC results embed their own benchmark definitions, and `.cklb` / `.nessus` files are self-contained. |
| `--output` | Output Excel path (default: `stig_findings_<timestamp>.xlsx`) |
| `--verbose` | Enable detailed logging |

#### `delta` — compare two scan sets

Diffs a baseline scan set against a current one to show what changed between
runs — new findings, resolved findings, and findings that persist.

```bash
# Compare a baseline directory against a current one
python -m app.cli delta --baseline ./scans-2026-06/ --current ./scans-2026-07/

# Individual files, with benchmarks applied to both sides
python -m app.cli delta --baseline old1.xml old2.xml --current new1.xml new2.xml \
    --benchmarks ./benchmarks/ --output delta.xlsx

# Glob patterns
python -m app.cli delta --baseline "baseline/*.xml" --current "current/*.xml"
```

**Arguments:**

| Argument | Description |
|---|---|
| `--baseline` | Older scan results — file(s), directory, or glob pattern; same formats as `report --results` (**required**) |
| `--current` | Newer scan results — file(s), directory, or glob pattern; same formats as `report --results` (**required**) |
| `--benchmarks` | Benchmark file(s), directory, or glob pattern, applied to **both** scan sets. Optional for SCC — result files embed their own benchmark definitions. |
| `--output` | Output Excel path (default: `stig_delta_<timestamp>.xlsx`) |
| `--verbose` | Enable detailed logging |

The output workbook's **Findings** sheet carries a leading **Delta** column
tagging every row `New` (absent from baseline, present in current),
`Resolved` (present in baseline, absent from current), or `Persisting`
(present in both), plus separate `Baseline Status` and `Current Status`
columns. The **Summary** sheet breaks delta status down by severity and adds
a coverage block.

Findings lists only ever contain actionable results — passing rules never
appear — so `Resolved` is *inferred* from a finding's absence in the current
scan, not proven from a passing re-check. To keep that inference honest, the
comparison is scoped to hosts present in **both** scans: a host that only
appears in the baseline is reported under "hosts not re-scanned" and its
findings are never counted as resolved, so forgetting to re-scan a host can't
look like remediation. A host that only appears in the current scan is a
"new host," and every finding on it is tagged `New`.

Findings are matched across runs by Vuln ID (V-XXXXXX) where available,
falling back to Rule ID — Vuln ID is stable across DISA benchmark revisions
where Rule ID is not. If the two runs have different benchmark coverage
(e.g. `--benchmarks` supplied for only one of them), the tool warns that
Resolved/New counts may be unreliable; the warning appears both in the
terminal and in the workbook's Summary sheet.

---

## How It Works

1. **Route by format** — `.cklb` and `.nessus` files are self-contained and parse directly to findings; `.xml` files take the XCCDF path below
2. **Auto-detect scanner** (XCCDF) — inspects XML namespaces, the `test-system` attribute, and generator metadata
3. **Parse results** — extracts hostname, IP, benchmark reference, and all rule results from each XCCDF file
4. **Parse benchmarks** — extracts STIG title, Vuln IDs, Rule IDs, severity, check text, and fix text. For SCC scans the benchmark definitions live inside the same result files, so no separate benchmark upload is required
5. **Match** — links each XCCDF result file to its benchmark via the embedded `<benchmark>` reference; falls back to ID string matching
6. **Filter** — retains only Open, Not Reviewed, Error, and Unknown findings; discards Pass, Not Applicable, etc.
7. **Export** — generates a formatted Excel workbook with COUNTIFS formulas in the Summary sheet

---

## STIG Benchmark Files

STIG benchmark definition XML files are publicly available from DISA:

- **Public source:** [https://public.cyber.mil/stigs/downloads/](https://public.cyber.mil/stigs/downloads/)
- Download the STIG for your operating system or application
- Extract the `*_Manual-xccdf.xml` file from the ZIP

---

## LibreOffice Compatibility

The workbook is generated in `.xlsx` format and tested in both Microsoft Excel and LibreOffice Calc. Known differences:

- `COUNTIFS` formulas work correctly in both applications
- Cell formatting (colors, fonts, freeze panes) renders correctly in both

---

## Contributing

1. Fork the repository and create a feature branch
2. Add tests for any new functionality (`tests/` directory, run with `pytest`)
3. Ensure all tests pass: `pytest tests/ -v`
4. Submit a pull request with a clear description of the change

---

## Roadmap

The following features are planned for future releases:

- **Standalone OVAL Results Parsing** — implement `oval_parser.py` to handle `.oval.xml` output from OpenSCAP, including OVAL-to-STIG rule ID mapping
- **STIG ID Prefix Fallback Matching** — improved benchmark matching via Rule ID STIG identifier extraction when the benchmark reference is missing
- **Local STIG Library** — maintain a local cache of STIG benchmarks so users don't need to manually import benchmark files
- **CKL Export** — generate STIG Viewer `.ckl` checklist files from parsed results
- **Delta Reporting in the Web UI** — the CLI `delta` subcommand ships today (see [CLI](#cli)); a web UI equivalent is a follow-up
- **REST API** — JSON endpoint for integration with CI/CD pipelines

---

## License

MIT — see [LICENSE](LICENSE).
