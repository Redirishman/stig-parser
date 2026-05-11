# STIG Compliance Parser

A Python tool that ingests XCCDF compliance scan results from multiple scanning tools, cross-references them against STIG benchmark definition files, and produces a consolidated Excel workbook of actionable findings. Includes a Flask web UI for interactive use and a CLI for scripted or headless workflows.

---

## Supported Scanners

| Scanner | Status |
|---|---|
| DISA SCC (SCAP Compliance Checker) | ✅ Tested |
| OpenSCAP | ✅ Tested |
| Nessus SCAP | ⚠️ Built from documentation — not yet validated with real output |
| Evaluate-STIG | ⚠️ Built from documentation — not yet validated with real output |

Scanner type is auto-detected from XML namespace declarations and generator metadata — no manual tagging required.

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

Open `http://localhost:5000`. Upload your scan results files and STIG benchmark files, click **Process**, then download the Excel report.

### CLI

```bash
# Directory inputs
python -m app.cli --results ./results/ --benchmarks ./benchmarks/ --output findings.xlsx

# Individual files
python -m app.cli --results scan1.xml scan2.xml --benchmarks stig1.xml stig2.xml

# Glob patterns (Windows-safe — expanded internally)
python -m app.cli --results "scans/*.xml" --benchmarks "stigs/*.xml" --verbose

# Default output filename (stig_findings_<timestamp>.xlsx)
python -m app.cli --results ./results/ --benchmarks ./benchmarks/
```

**Arguments:**

| Argument | Description |
|---|---|
| `--results` | Results file(s), directory, or glob pattern (required) |
| `--benchmarks` | Benchmark file(s), directory, or glob pattern (required) |
| `--output` | Output Excel path (default: `stig_findings_<timestamp>.xlsx`) |
| `--verbose` | Enable detailed logging |

---

## How It Works

1. **Auto-detect scanner** — inspects XML namespaces and generator metadata
2. **Parse results** — extracts hostname, IP, benchmark reference, and all rule results from each XCCDF file
3. **Parse benchmarks** — extracts STIG title, Vuln IDs, Rule IDs, severity, check text, and fix text from each STIG benchmark XML
4. **Match** — links each result file to its benchmark via the embedded `<benchmark>` reference; falls back to ID string matching
5. **Filter** — retains only Open, Not Reviewed, Error, and Unknown findings; discards Pass, Not Applicable, etc.
6. **Export** — generates a formatted Excel workbook with COUNTIFS formulas in the Summary sheet

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
- **Nessus SCAP / Evaluate-STIG Validation** — validate and harden parsers against real output from these scanners
- **Local STIG Library** — maintain a local cache of STIG benchmarks so users don't need to manually import benchmark files
- **CKL Export** — generate STIG Viewer `.ckl` checklist files from parsed results
- **Delta Reporting** — compare two scan runs to show remediation progress
- **REST API** — JSON endpoint for integration with CI/CD pipelines

---

## License

MIT — see [LICENSE](LICENSE).
