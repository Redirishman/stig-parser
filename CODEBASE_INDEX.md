# STIG Compliance Parser — Codebase Index

Complete catalogue of every module, function, class, route, template section, CSS rule, test, and configuration artefact in the project.

**Repo root:** `G:\AI Apps\STIG Condenser\stig-parser`
**Language:** Python 3.11+ · **Web framework:** Flask 3 · **XML:** lxml · **Excel:** openpyxl
**Test count:** 146 passing

---

## 1. Top-Level File Tree

```
stig-parser/
├── .github/workflows/ci.yml        GitHub Actions test matrix
├── .gitattributes / .gitignore
├── CODEBASE_INDEX.md               This file
├── Dockerfile                      Container build
├── docker-compose.yml              Service orchestration
├── LICENSE                         MIT
├── pyproject.toml                  Package metadata + deps
├── README.md                       User-facing documentation
├── app/                            Application source (one Python package)
│   ├── __init__.py                 Empty package marker
│   ├── cli.py                      CLI entry point
│   ├── web.py                      Flask app factory + background jobs
│   ├── exporters/                  Output generators
│   │   ├── __init__.py
│   │   └── excel_exporter.py       Two-sheet Excel workbook
│   ├── parsers/                    XML ingestion
│   │   ├── __init__.py
│   │   ├── base.py                 Abstract parser + dataclasses
│   │   ├── benchmark_parser.py     STIG benchmark definitions (XCCDF 1.1/1.2)
│   │   ├── oval_parser.py          Stub — raises NotImplementedError
│   │   └── xccdf_parser.py         Scan result files (4 scanner formats)
│   ├── processors/                 Business logic
│   │   ├── __init__.py
│   │   ├── filter.py               Discard non-actionable findings
│   │   └── matcher.py              Cross-reference results ↔ benchmarks
│   ├── static/style.css            Single CSS stylesheet (no framework)
│   ├── templates/index.html        Single Flask template + inline JS
│   └── utils/                      Cross-cutting helpers
│       ├── __init__.py
│       ├── scanner_detect.py       Auto-identify SCC / OpenSCAP / Nessus / Evaluate-STIG
│       └── zip_extract.py          Unwrap DISA STIG ZIP archives
└── tests/                          pytest suite — 146 tests
    ├── __init__.py
    ├── fixtures/                   Fabricated XCCDF samples
    │   ├── evaluate_stig_results.xml
    │   ├── nessus_results.xml
    │   ├── openscap_results.xml
    │   ├── sample_benchmark.xml
    │   └── scc_results.xml
    ├── test_benchmark_parser.py    19 tests
    ├── test_cli.py                 16 tests
    ├── test_excel_exporter.py      11 tests
    ├── test_filter.py              7 tests
    ├── test_matcher.py             19 tests
    ├── test_oval_parser.py         1 test
    ├── test_web.py                 9 tests
    ├── test_xccdf_parser.py        51 tests
    └── test_zip_extract.py         13 tests
```

---

## 2. Data Models (`app/parsers/base.py`)

Defined as `@dataclass` types. All field types are `str` unless noted.

| Class | Field | Type | Notes |
|---|---|---|---|
| `RuleResult` | `rule_id` | str | Full XCCDF rule id (`xccdf_mil.disa.stig_rule_SV-…_rule`) |
| | `status` | str | Raw XCCDF value: `fail`, `pass`, `notchecked`, `error`, `unknown`, `notselected`, `notapplicable`, etc. |
| `ScanResult` | `source_file` | str | Filename of source XCCDF (used for hostname fallback) |
| | `hostname` | str | Target hostname |
| | `ip_address` | str | Target IP — `"N/A"` if unresolvable |
| | `benchmark_href` | str | `href` attribute from `<benchmark>` element |
| | `benchmark_id` | str | `id` attribute from `<benchmark>` element |
| | `scanner` | str | `SCC` / `OpenSCAP` / `Nessus` / `Evaluate-STIG` / `Unknown` |
| | `rule_results` | `list[RuleResult]` | All rule results in the file |
| `BenchmarkRule` | `vuln_id` | str | V-number (e.g. `V-254239`) |
| | `rule_id` | str | Full XCCDF rule id |
| | `severity` | str | `CAT I` / `CAT II` / `CAT III` |
| | `check_text` | str | Body of `<check-content>` (may be empty for SCAP-style files) |
| | `fix_text` | str | Body of `<fixtext>` |
| `Benchmark` | `benchmark_id` | str | Root `<Benchmark>` `id` attribute |
| | `title` | str | Benchmark title |
| | `rules` | `dict[str, BenchmarkRule]` | Keyed by full rule id |
| `Finding` | `stig_title` | str | From parent `Benchmark.title` |
| | `vuln_id` | str | From `BenchmarkRule.vuln_id` (blank if unmatched) |
| | `rule_id` | str | From `RuleResult.rule_id` |
| | `severity` | str | CAT I/II/III |
| | `status` | str | `Open` / `Not Reviewed` / `Error` / `Unknown` |
| | `server` | str | From `ScanResult.hostname` |
| | `ip_address` | str | From `ScanResult.ip_address` |
| | `check_text` / `fix_text` | str | From benchmark; blank if unmatched |
| `BaseParser` | — | abstract | Abstract method `parse(self, path) -> Any` |

---

## 3. Parsers (`app/parsers/`)

### 3.1 `xccdf_parser.py` — Scan result ingestion

**Class:** `XCCDFResultsParser(BaseParser)`

**Public method:**
| Method | Returns | Description |
|---|---|---|
| `parse(path)` | `ScanResult \| None` | Parse XCCDF results file. Returns `None` on XML syntax error. |

**Module-private helpers:**
| Function | Returns | Description |
|---|---|---|
| `_find_test_result(root)` | `Element` | Locate `<TestResult>` whether it is the root or nested inside `<Benchmark>` |
| `_find_fact(root, urns)` | str | Look up `<fact>` text within `<target-facts>` by URN, in preference order |
| `_find_text(root, *local_names)` | str | Find direct-child text by local name (namespace-agnostic) |
| `_findall_results(root)` | `list[Element]` | All `<rule-result>` children regardless of prefix |
| `_find_child_text(el, local_name)` | str | Direct child text by local name |
| `_get_benchmark_attrs(root)` | `tuple[str, str]` | `(href, id)` from `<benchmark>` element |

**Constants:**
- `_NS_XCCDF_12 = "http://checklists.nist.gov/xccdf/1.2"`
- `_XCCDF_NS = {"cdf": _NS_XCCDF_12}`
- `_FACT_HOSTNAME_URNS` — `[host_name, fqdn]` preference order
- `_FACT_IP_URNS` — `[ipv4, ipv6]` preference order

**Hostname resolution order:** `<target>` → `<target-facts>` host_name/fqdn → `<title>` → filename stem
**IP resolution order:** `<target-facts>` ipv4/ipv6 → `<target-address>` → `"N/A"`

### 3.2 `benchmark_parser.py` — STIG definition ingestion

**Class:** `BenchmarkParser(BaseParser)` — handles both XCCDF 1.1 *and* 1.2

**Public method:**
| Method | Returns | Description |
|---|---|---|
| `parse(path)` | `Benchmark \| None` | Parse benchmark XML; returns `None` on syntax error |

**Module-private helpers:**
| Function | Returns | Description |
|---|---|---|
| `_findall_local(el, local_name)` | `list[Element]` | Direct children by local name (namespace-agnostic) |
| `_extract_vuln_id(raw_id)` | str | Strips `xccdf_mil.disa.stig_group_` prefix from XCCDF 1.2 ids |
| `_find_text_ns(el, local_name)` | str | Direct-child text with namespace fallback |
| `_get_check_text(rule_el)` | str | Text from `<check><check-content>` |
| `_get_fix_text(rule_el)` | str | Text from `<fixtext>` |

**Constants:**
- `_NS_XCCDF_11 = "http://checklists.nist.gov/xccdf/1.1"`
- `_NS_XCCDF_12 = "http://checklists.nist.gov/xccdf/1.2"`
- `_SEVERITY_MAP = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}`

### 3.3 `oval_parser.py` — Stub for future work

**Class:** `OVALParser(BaseParser)` — `parse()` raises `NotImplementedError`. Listed in README roadmap.

---

## 4. Processors (`app/processors/`)

### 4.1 `matcher.py` — Cross-reference

**Public function:**
| Function | Returns | Description |
|---|---|---|
| `match_results_to_benchmarks(scan_results, benchmarks)` | `list[Finding]` | Joins each `RuleResult` to its `BenchmarkRule` via parent benchmark match; emits only actionable statuses |

**Module-private helpers:**
| Function | Returns | Description |
|---|---|---|
| `_normalize_id(raw)` | str | `Path(raw).stem.strip().lower()` — used only on hrefs |
| `_find_benchmark(href, bid, benchmarks)` | `Benchmark \| None` | 3-tier match: exact id → href stem → substring |

**Constants:**
- `_STATUS_MAP` — XCCDF → display: `fail→Open`, `notchecked→Not Reviewed`, `notselected→Not Reviewed`, `error→Error`, `unknown→Unknown`
- `_KEEP_STATUSES` — frozenset of `_STATUS_MAP` keys (actionable statuses)

### 4.2 `filter.py` — Defensive re-filter

**Public function:** `filter_findings(findings) -> list[Finding]` — keep only `Open` / `Not Reviewed` / `Error` / `Unknown`.

---

## 5. Exporters (`app/exporters/`)

### 5.1 `excel_exporter.py`

**Class:** `ExcelExporter`

**Public method:**
| Method | Returns | Raises |
|---|---|---|
| `export(findings, output_path)` | `Path` | `ValueError` if findings list empty |

**Private methods:**
| Method | Description |
|---|---|
| `_write_findings(ws, findings)` | Build Findings sheet — header row, data rows, severity colouring, freeze panes, auto-filter, column widths |
| `_write_summary(ws, findings)` | Build Summary sheet — three COUNTIFS tables + footer note |

**Module-private utilities:**
| Function | Description |
|---|---|
| `_unique_pairs(findings, attr1, attr2)` | Order-preserving deduplication on a two-attribute key |
| `_unique_values(findings, attr)` | Order-preserving deduplication on a single attribute |

**Findings sheet columns** (`_FINDINGS_COLS`):
| # | Header | Source attr | Max width |
|---|---|---|---|
| A | STIG Title | `stig_title` | 50 |
| B | Vuln ID | `vuln_id` | 12 |
| C | Rule ID | `rule_id` | 40 |
| D | Severity | `severity` | 10 |
| E | Status | `status` | 14 |
| F | Server | `server` | 30 |
| G | IP Address | `ip_address` | 18 |
| H | Check Text | `check_text` | 80 |
| I | Fix Text | `fix_text` | 80 |

**Severity fills:** CAT I = `#FFCCCC` (light red); CAT II = `#FFEB9C` (amber); CAT III = `#C6EFCE` (light green).
**Wrap-text columns:** Check Text, Fix Text.
**Freeze panes:** `A2`. **Auto-filter:** `A1:I1`.

**Summary sheet tables:**
1. *Findings by Severity* — columns: Severity, Open, Not Reviewed, Error, Unknown, Total
2. *Findings by Server* — columns: Server, IP, CAT I, CAT II, CAT III, Total
3. *Findings by STIG* — columns: STIG Title, CAT I, CAT II, CAT III, Total
4. Footer note (merged A:F) — italic grey "auto-filter doesn't update counts" disclaimer

---

## 6. Utils (`app/utils/`)

### 6.1 `scanner_detect.py`

**Public function:**
| Function | Returns | Description |
|---|---|---|
| `detect_scanner(path)` | str | One of `SCC` / `OpenSCAP` / `Nessus` / `Evaluate-STIG` / `Unknown` |

**Private helpers:**
| Function | Description |
|---|---|
| `_collect_namespaces(element)` | Every namespace URI used anywhere in the document |
| `_extract_generator_text(root)` | Concatenated text from `generator` / `product` / `scanner-version` / `creator` elements |

**Detection precedence:**
1. Nessus namespaces (`http://www.nessus.org/cm`, `http://www.nessus.org`)
2. SCAP source namespace (`http://scap.nist.gov/schema/scap/source/1.2`) → SCC
3. `test-system="cpe:/a:niwc:scc:…"` on `<TestResult>` → SCC *(added when working with real SCC files)*
4. Generator text substring match against `Evaluate-STIG` / `Nessus` / `OpenSCAP` / `SCC`
5. Root `id` contains `evaluate-stig` → Evaluate-STIG

### 6.2 `zip_extract.py`

**Public functions:**
| Function | Returns | Description |
|---|---|---|
| `extract_xccdf_from_zip(zip_path, dest_dir)` | `list[Path]` | Pull every `*xccdf.xml` out of a DISA STIG ZIP; recurses one level into nested ZIPs |
| `expand_benchmark_paths(paths, extract_dir)` | `tuple[list[Path], list[str]]` | Replace `.zip` entries with extracted XCCDF files; returns `(resolved_paths, warnings)` |

**Private helper:** `_unique_path(path)` — appends numeric suffix on filename collision.

**Constant:** `_XCCDF_SUFFIX = "xccdf.xml"` (case-insensitive match).

---

## 7. Web Application (`app/web.py`)

### 7.1 App factory

`create_app(secret_key=None) -> Flask` — configures Flask, registers routes, runs orphan-job sweep on startup.

### 7.2 HTTP routes

| Method | Path | Handler | Returns |
|---|---|---|---|
| `GET` | `/` | `index()` | Renders `index.html` with `existing_job_id` from session |
| `POST` | `/api/process` | `process()` | `{job_id, status}` 200 · `{error}` 400 |
| `GET` | `/api/status/<job_id>` | `job_status()` | `{status, progress, warnings, error}` 200 · `{error}` 404 |
| `GET` | `/api/download/<job_id>` | `download()` | `.xlsx` attachment 200; deletes job dir on response close |

### 7.3 Background processing

| Function | Description |
|---|---|
| `_run_job(job_id, results_paths, benchmark_paths)` | Threaded pipeline — extracts ZIPs, parses both sides, matches, filters, exports |
| `_set_job(job_id, **fields)` | Thread-safe update of in-memory `_jobs` dict |
| `_get_job(job_id)` | Thread-safe shallow-copy read |
| `_delete_job(job_id)` | Remove temp dir + job entry |
| `_sweep_orphaned_jobs()` | Startup cleanup of dirs older than 8 hours |
| `_job_dir(job_id)` | `_TEMP_DIR / job_id` |

### 7.4 Logging integration

**Class:** `_WarningCollector(logging.Handler)` — captures WARNING+ log records into a job's `warnings` list so they can be surfaced through `/api/status`.

### 7.5 Module-level state

| Name | Type | Purpose |
|---|---|---|
| `_jobs` | `dict[str, dict]` | UUID → job state |
| `_jobs_lock` | `threading.Lock` | Guards `_jobs` |
| `_TEMP_DIR` | `Path` | `$STIG_TEMP_DIR` or `<repo>/tmp` |
| `_ORPHAN_MAX_AGE_HOURS` | int | `8` |

### 7.6 Behaviour notes

- Benchmark upload is **optional** — when omitted, results files are used for both scan and benchmark parsing (SCC self-contained format).
- Max upload size: 500 MB (`MAX_CONTENT_LENGTH`).
- Session cookie stores `job_id` to allow page-reload reconnection.

---

## 8. CLI (`app/cli.py`)

### 8.1 Entry point

`main(argv=None) -> int` — exits 0 on success, 1 on error.

### 8.2 Arguments

| Flag | Required | Description |
|---|---|---|
| `--results` | yes | Files/directories/globs for XCCDF results |
| `--benchmarks` | no | Files/dirs/globs for benchmark XMLs/ZIPs; *optional for SCC* |
| `--output` | no | Output `.xlsx` path; default `stig_findings_<UTC timestamp>.xlsx` |
| `--verbose` | no | DEBUG logging |

### 8.3 Helpers

| Function | Returns | Description |
|---|---|---|
| `_resolve_paths(args, extensions)` | `list[Path]` | Expands directories (by extension) and shell globs |
| `_build_parser()` | `ArgumentParser` | Constructs the argparse spec |

### 8.4 Console-script entry

Declared in `pyproject.toml` as `stig-parser = "app.cli:main"`.

---

## 9. UI — Templates (`app/templates/`)

### 9.1 `index.html` — the single page

This is a **single-page application** with three top-level sections rendered conditionally via CSS `hidden`. **There are no true modals** — only inline sections that show/hide. Catalogue:

| Section ID | Element | Visible When | Contents |
|---|---|---|---|
| `#app` | `<main>` | Always | Wraps all sections below |
| `#upload-section` | `<section>` | Initial state · after Reset | Upload form |
| `#progress-section` | `<section>` | While job is running | Progress bar + warnings panel |
| `#result-section` | `<section>` | Job complete or error | Either `#result-success` or `#result-error` |

#### Page header (`<header>`)
- `h1`: "STIG Compliance Parser"
- `p.subtitle`: brief description noting SCC files are self-contained

#### Upload section (`#upload-section`)
- `<form id="upload-form">` with `enctype="multipart/form-data"`
- `.upload-grid` — 2-column responsive grid
  - **`#results-zone` (`.upload-zone`)** — required
    - Icon, "Scan Results" heading, helper text
    - `label.btn.btn-secondary[for=results-input]`: Choose Files
    - `input#results-input[type=file][name=results][multiple][accept=.xml]` (hidden)
    - `ul#results-file-list.file-list`
  - **`#benchmarks-zone` (`.upload-zone`)** — optional
    - Icon, "STIG Benchmarks" heading + **`.badge-optional`** ("Optional for SCC")
    - Helper text explaining SCC files don't need it
    - `label.btn.btn-secondary[for=benchmarks-input]`: Choose Files
    - `input#benchmarks-input[type=file][name=benchmarks][multiple][accept=.xml,.zip]` (hidden)
    - `ul#benchmarks-file-list.file-list`
- `.form-actions`
  - `button#process-btn.btn.btn-primary[type=submit]` — disabled until results uploaded

#### Progress section (`#progress-section`, hidden by default)
- `h2`: "Processing"
- `.progress-bar-wrap` > `#progress-bar.progress-bar`
- `#progress-text.progress-text`
- `#warnings-box.warnings-box` (hidden until warnings arrive)
  - `h3`: "Warnings"
  - `ul#warnings-list`

#### Result section (`#result-section`, hidden by default)
- **`#result-success.result-card.success`** (hidden until complete)
  - `.result-icon` (checkmark)
  - `h2`: "Report Ready"
  - `a#download-link.btn.btn-primary`: "Download Excel Report"
  - `button#reset-btn.btn.btn-secondary`: "Process Another Set"
- **`#result-error.result-card.error`** (hidden until error)
  - `.result-icon` (✗)
  - `h2`: "Processing Failed"
  - `p#error-message`
  - `#error-warnings-box.warnings-box` (hidden when no warnings)
    - `h3`: "Warnings"
    - `ul#error-warnings-list`
  - `button#reset-btn-error.btn.btn-secondary`: "Try Again"

#### Footer (`<footer>`)
- Supported-scanner list
- `.small` disclaimer about Nessus / Evaluate-STIG being untested

### 9.2 Inline JavaScript (IIFE inside `<script>`)

All event handlers and DOM manipulation live in a single IIFE for namespace hygiene. No external JS dependencies.

**State variables:**
- `pollTimer` — `setInterval` handle for `/api/status` polling
- `currentJobId` — UUID of active job (seeded from server-rendered template var)
- `lastWarnings` — most recent warnings (for re-display on error)

**Functions:**
| Function | Purpose |
|---|---|
| `removeFileAt(input, listEl, index)` | Remove one file from a `FileList` by rebuilding via `DataTransfer` |
| `updateFileList(input, listEl)` | Render selected files with remove buttons |
| `setupZone(zone, input, listEl, allowedExts)` | Wire click + drag-and-drop on an upload zone |
| `updateProcessBtn()` | Enable Process button when results files are selected |
| `startPolling(jobId)` | 1-second interval polling of `/api/status` |
| `poll(jobId)` | One poll round — updates progress, handles complete/error |
| `setProgress(pct, text)` | Animate progress bar |
| `showWarnings(warnings)` | Render running-state warnings |
| `showSuccess(jobId)` | Reveal success card; set download link |
| `showError(msg)` | Reveal error card; re-render last warnings |
| `resetUI()` | Clear all state and return to upload section |

**Bottom of script:** auto-reconnect block that polls `/api/status/<existing_job_id>` on page load if the session held a job ID.

---

## 10. UI — Stylesheet (`app/static/style.css`)

Pure custom CSS — **no framework**. Single file, well under 320 lines. Catalogued by section:

### 10.1 Reset & root variables
- Universal box-sizing reset (`*`, `*::before`, `*::after`)
- `:root` CSS variables:

| Variable | Value | Purpose |
|---|---|---|
| `--color-bg` | `#f5f6fa` | Page background |
| `--color-surface` | `#ffffff` | Card / panel background |
| `--color-border` | `#dde1ea` | Default borders |
| `--color-primary` | `#2563eb` | Primary actions |
| `--color-primary-h` | `#1d4ed8` | Primary hover state |
| `--color-danger` | `#dc2626` | Errors |
| `--color-success` | `#16a34a` | Success state |
| `--color-warning-bg` | `#fffbeb` | Warning panel background |
| `--color-warning-br` | `#fbbf24` | Warning panel border |
| `--color-text` | `#1e293b` | Body text |
| `--color-muted` | `#64748b` | Secondary text |
| `--radius` | `8px` | Border radius |
| `--shadow` | `0 1px 4px rgba(0,0,0,.08)` | Card shadow |

### 10.2 Base typography & layout
- `body` — Arial sans-serif, 14px, slate text on grey background
- `.container` — max 860px, centred, 2rem padding top

### 10.3 Header
| Selector | Role |
|---|---|
| `header` | Centred block, 2rem bottom margin |
| `header h1` | 1.75rem, 700 weight, tight letter-spacing |
| `.subtitle` | Muted text under h1 |

### 10.4 Upload grid
| Selector | Role |
|---|---|
| `.upload-grid` | 2-column CSS grid, collapses to 1-column under 580px |
| `.upload-zone` | Dashed-border card, 2rem padding, hover/dragover highlight |
| `.upload-zone:hover`, `.upload-zone.dragover` | Blue border + tinted background |
| `.zone-icon` | 2.5rem emoji/glyph |
| `.upload-zone h2` | 1rem 700 weight |
| `.badge-optional` | Small blue pill next to "STIG Benchmarks" heading — `Optional for SCC` indicator |
| `.upload-zone p` | Muted helper text under heading |
| `.file-list` | List-style none, max-height 120px, scrollable |
| `.file-list li` | Flex row, name + remove button |
| `.file-list .file-name` | Truncated with ellipsis |
| `.file-list .file-name::before` | Green check pseudo-element |
| `.file-list .file-remove` | Transparent X button, hover highlights red |
| `.file-list .file-remove:hover/:focus` | Red tint background |

### 10.5 Buttons
| Selector | Role |
|---|---|
| `.btn` | Base button — padding, radius, weight, transition |
| `.btn-primary` | Blue background, white text |
| `.btn-primary:hover:not(:disabled)` | Darker blue |
| `.btn-secondary` | White background, default border |
| `.btn-secondary:hover` | Grey tint |
| `.btn:disabled` | 45% opacity, not-allowed cursor |
| `.form-actions` | Centred container for submit button |

### 10.6 Progress
| Selector | Role |
|---|---|
| `#progress-section` | Card with shadow + padding |
| `#progress-section h2` | 1rem bottom margin |
| `.progress-bar-wrap` | 10px high track |
| `.progress-bar` | Animated fill (`width` transitions 400ms) |
| `.progress-text` | Muted, min-height 1.2em |

### 10.7 Warnings
| Selector | Role |
|---|---|
| `.warnings-box` | Amber tinted panel |
| `.warnings-box h3` | Dark amber heading |
| `.warnings-box ul` | List-style none |
| `.warnings-box li + li` | Top-margin spacer |
| `.warnings-box li::before` | "⚠ " pseudo-element |

### 10.8 Result cards
| Selector | Role |
|---|---|
| `#result-section` | Top spacing |
| `.result-card` | Big card, 2.5rem padding, centred text |
| `.result-icon` | 3rem icon (check or X) |
| `.result-card h2` | 1.25rem bottom margin |
| `.result-card.success .result-icon` | Green colour |
| `.result-card.error .result-icon` | Red colour |
| `.result-card .btn + .btn` | Left margin between buttons |
| `#result-error p` | Danger-red error message text |

### 10.9 Footer
| Selector | Role |
|---|---|
| `footer` | Centred, muted, 3rem top margin |
| `footer .small` | Smaller disclaimer text |

---

## 11. Test Suite (`tests/`)

### 11.1 Coverage by module

| Test file | Class / Group | # tests | What it covers |
|---|---|---|---|
| `test_xccdf_parser.py` | `TestSCCResults` | 13 | Real SCC fixture: hostname, IP, benchmark refs, scanner detection, all 7 status codes |
| | `TestOpenSCAPResults` | 6 | OpenSCAP fixture |
| | `TestNessusResults` | 5 | Nessus fixture |
| | `TestEvaluateSTIGResults` | 5 | Evaluate-STIG fixture |
| | `TestEdgeCases` | 22 | Invalid XML, missing target/IP, `<target-facts>` fallbacks, nested TestResult, no-result fallback |
| `test_benchmark_parser.py` | `TestSampleBenchmark` | 11 | XCCDF 1.1 sample parsing — severity mapping, vuln IDs, check/fix text |
| | `TestXCCDF12Benchmark` | 7 | XCCDF 1.2 inline-from-SCC parsing + vuln_id stripping |
| | `TestEdgeCases` | 2 | Invalid XML, empty benchmark |
| `test_matcher.py` | `TestMatchedResults` | 8 | End-to-end finding assembly |
| | `TestStatusMapping` | 9 | All XCCDF status → display mappings, including discards |
| | `TestUnmatchedBenchmark` | 2 | Missing/wrong benchmark → blank check/fix |
| | `TestBenchmarkMatchFallback` | 2 | href stem + substring fallbacks |
| | `TestFullyQualifiedBenchmarkIds` | 1 | Regression: real-world XCCDF ids don't all collapse to `xccdf_mil.disa` |
| | `TestDuplicateTargets` | 1 | Same host parsed twice → both rows kept |
| `test_filter.py` | (module-level) | 7 | All four kept statuses + discards + mixed |
| `test_excel_exporter.py` | `TestFindingsSheet` | 5 | Sheet existence, headers, row count, freeze panes, auto-filter |
| | `TestSummarySheet` | 5 | All three table headers + COUNTIFS presence and `Findings!` references |
| | `TestErrorCases` | 2 | Empty findings raises; file gets created |
| `test_zip_extract.py` | `TestExtractXccdfFromZip` | 7 | Single XCCDF, folder flattening, no XCCDF, nested ZIP, collisions, bad ZIP, case-insensitive |
| | `TestExpandBenchmarkPaths` | 4 | XML pass-through, ZIP expansion, empty-zip warning, uppercase `.ZIP` |
| `test_oval_parser.py` | (module-level) | 1 | Stub raises `NotImplementedError` |
| `test_cli.py` | `TestArgumentParsing` | 7 | `--results` required, `--benchmarks` optional/empty/multi, `--output`/`--verbose` |
| | `TestResolvePaths` | 4 | Directory expansion (.xml only / .xml+.zip), explicit file, glob pattern |
| | `TestMainSeparateBenchmarks` | 1 | End-to-end run with `--benchmarks` supplied |
| | `TestMainOptionalBenchmarks` | 2 | `--benchmarks` omitted / empty flag — results files used for both sides |
| | `TestMainErrorCases` | 1 | Empty results dir → exit 1 |
| `test_web.py` | `TestIndexRoute` | 2 | `/` returns 200, "Optional for SCC" badge present |
| | `TestProcessValidation` | 2 | Missing/empty results → 400 |
| | `TestProcessWithSeparateBenchmark` | 2 | Pipeline completes; download serves a valid `.xlsx` |
| | `TestProcessWithoutBenchmark` | 2 | Results-only upload accepted; worker thread runs to completion |
| | `TestStatusRoute` / `TestDownloadRoute` | 2 | Unknown job → 404 |
| **Total** | | **146** | |

### 11.2 Fixtures (`tests/fixtures/`)

| File | Bytes | `rule-result` count | `<Rule>` defs | Scanner |
|---|---|---|---|---|
| `scc_results.xml` | 2,822 | 14 | 0 | SCC |
| `openscap_results.xml` | 2,338 | 12 | 0 | OpenSCAP |
| `nessus_results.xml` | 2,108 | 8 | 0 | Nessus |
| `evaluate_stig_results.xml` | 2,003 | 8 | 0 | Evaluate-STIG |
| `sample_benchmark.xml` | 9,637 | 0 | 7 | n/a — benchmark definitions |

All fabricated; no real DoD data in the repo.

---

## 12. Configuration

### 12.1 `pyproject.toml`

| Section | Key | Value |
|---|---|---|
| `[build-system]` | requires | `setuptools>=68`, `wheel` |
| | build-backend | `setuptools.build_meta` |
| `[project]` | name | `stig-parser` |
| | version | `0.1.0` |
| | requires-python | `>=3.11` |
| | license | MIT |
| | dependencies | `flask>=3.0`, `lxml>=5.0`, `openpyxl>=3.1` |
| `[project.optional-dependencies].dev` | | `pytest>=8.0`, `pytest-cov>=4.0` |
| `[project.scripts]` | stig-parser | `app.cli:main` |
| `[tool.pytest.ini_options]` | testpaths | `["tests"]` |

### 12.2 `.github/workflows/ci.yml`

GitHub Actions workflow `CI`:
- Triggers: push & PR to `main`
- Matrix: Python `3.11`, `3.12` on `ubuntu-latest`
- Steps: checkout → setup-python → `pip install -e ".[dev]"` → `pytest tests/ -v --tb=short`

---

## 13. Deployment

### 13.1 `Dockerfile`

- Base: `python:3.11-slim`
- System deps: `libxml2`, `libxslt1.1` (for lxml)
- Copies `pyproject.toml` + `app/`, installs via `pip install -e .`
- Sets `STIG_TEMP_DIR=/tmp/stig-parser-jobs`
- Exposes port `5000`
- CMD: `python -m flask --app app.web:create_app run --host 0.0.0.0 --port 5000`

### 13.2 `docker-compose.yml`

Single service `stig-parser`:
- Build from local Dockerfile
- Port mapping `5000:5000`
- Named volume `stig-tmp` mounted at `/tmp/stig-parser-jobs`
- Environment: `FLASK_SECRET_KEY` (placeholder), `STIG_TEMP_DIR`
- `restart: unless-stopped`

---

## 14. Documentation

### 14.1 `README.md` — sections

1. **Title + description**
2. **Supported Scanners** — status table
3. **Output** — workbook column reference + auto-filter caveat
4. **Installation** — pip & Docker
5. **Usage** — Web UI + CLI examples + argument table
6. **How It Works** — six-step pipeline summary
7. **STIG Benchmark Files** — DISA public source link
8. **LibreOffice Compatibility** — formula + formatting parity notes
9. **Contributing** — fork → tests → PR
10. **Roadmap** — OVAL parsing, STIG ID prefix fallback, scanner validation, local STIG library, CKL export, delta reporting, REST API
11. **License** — MIT

### 14.2 `LICENSE`
Standard MIT licence text.

---

## 15. Data Flow Summary

```
┌──────────────┐     ┌──────────────┐
│ Upload form  │     │ CLI invocation│
└──────┬───────┘     └──────┬───────┘
       └────────┬───────────┘
                ▼
┌──────────────────────────────────────────┐
│ expand_benchmark_paths   (zip_extract)   │  ⟵  optional ZIP unwrap
└──────────────┬───────────────────────────┘
               ▼
┌──────────────────────────────────────────┐
│ detect_scanner           (scanner_detect)│
│ XCCDFResultsParser.parse → ScanResult    │
│ BenchmarkParser.parse    → Benchmark     │  ⟵  same SCC file may feed both
└──────────────┬───────────────────────────┘
               ▼
┌──────────────────────────────────────────┐
│ match_results_to_benchmarks  (matcher)   │
│ filter_findings              (filter)    │
└──────────────┬───────────────────────────┘
               ▼
┌──────────────────────────────────────────┐
│ ExcelExporter.export                     │
│ → Findings + Summary sheets              │
└──────────────────────────────────────────┘
```

---

*Generated 2026-05-15.*
