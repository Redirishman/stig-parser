# STIG Compliance Parser — Codebase Index

Complete catalogue of every module, class, function, route, template section, CSS rule, test, and configuration artefact in the project.

**Repo root:** `G:\AI Apps\STIG Condenser\stig-parser`
**Language:** Python 3.11+ · **Web framework:** Flask 3 · **XML:** lxml · **Excel:** openpyxl · **Cloud:** boto3 (S3 / DynamoDB boundaries)
**Test count:** 234 test functions across 20 files

---

## 1. Top-Level File Tree

```
stig-parser/
├── .github/workflows/ci.yml        GitHub Actions test matrix (3.11 / 3.12)
├── .gitattributes / .gitignore
├── CODEBASE_INDEX.md               This file
├── RESIDUALS.md                    Residual-risk / known-limitations notes
├── Dockerfile                      Container build
├── docker-compose.yml              Service orchestration
├── LICENSE                         MIT
├── pyproject.toml                  Package metadata + deps
├── README.md                       User-facing documentation
├── docs/superpowers/
│   ├── plans/2026-07-07-backend-async-rearchitecture.md
│   └── specs/2026-07-07-govcloud-replatform-design.md
├── app/                            Application source (one Python package)
│   ├── __init__.py                 Empty package marker
│   ├── cli.py                      CLI entry point → app.core.pipeline
│   ├── web.py                      Flask app factory + threaded jobs
│   ├── core/                       AWS-agnostic pipeline + storage boundaries
│   │   ├── __init__.py
│   │   ├── pipeline.py             Single source of truth: parse→match→filter→export
│   │   ├── stages.py               Async stage entrypoints (future Lambda handlers)
│   │   ├── artifact_store.py       Blob boundary: Local + S3 implementations
│   │   ├── job_store.py            Job-status boundary: Memory + Dynamo implementations
│   │   └── findings_io.py          Finding ↔ JSON serialization
│   ├── exporters/
│   │   ├── __init__.py
│   │   └── excel_exporter.py       Two-sheet Excel workbook
│   ├── parsers/                    File ingestion
│   │   ├── __init__.py
│   │   ├── base.py                 Abstract parser + dataclasses
│   │   ├── benchmark_parser.py     STIG benchmark defs (XCCDF 1.1/1.2)
│   │   ├── xccdf_parser.py         XCCDF scan results (SCC/OpenSCAP/…)
│   │   ├── cklb_parser.py          CKLB JSON checklists (Evaluate-STIG / STIG Viewer 3)
│   │   ├── nessus_parser.py        Tenable .nessus compliance scans
│   │   └── oval_parser.py          Stub — raises NotImplementedError
│   ├── processors/
│   │   ├── __init__.py
│   │   ├── filter.py               Discard non-actionable findings
│   │   └── matcher.py              Cross-reference results ↔ benchmarks
│   ├── static/
│   │   ├── style.css               Single CSS stylesheet (no framework)
│   │   ├── favicon.svg
│   │   └── fonts/                  Public Sans (self-hosted, SIL OFL)
│   │       ├── OFL.txt
│   │       ├── PublicSans-Regular.woff2
│   │       ├── PublicSans-SemiBold.woff2
│   │       └── PublicSans-Bold.woff2
│   ├── templates/index.html        Single Flask template + inline JS
│   └── utils/
│       ├── __init__.py
│       ├── scanner_detect.py       Auto-identify SCC / OpenSCAP / Nessus / Evaluate-STIG
│       └── zip_extract.py          Unwrap DISA STIG ZIP archives
└── tests/                          pytest suite — 234 test functions
    ├── __init__.py
    ├── fixtures/                   Fabricated XCCDF / CKLB / .nessus samples
    │   ├── evaluate_stig_results.xml
    │   ├── nessus_results.xml
    │   ├── openscap_results.xml
    │   ├── sample_benchmark.xml
    │   └── scc_results.xml
    ├── test_artifact_store_local.py    5
    ├── test_artifact_store_s3.py       4  (moto-mocked)
    ├── test_benchmark_parser.py        22
    ├── test_cklb_parser.py             17
    ├── test_cli.py                     15
    ├── test_core_import.py             3
    ├── test_excel_exporter.py          13
    ├── test_filter.py                  7
    ├── test_findings_io.py             4
    ├── test_job_store_dynamo.py        4  (moto-mocked)
    ├── test_job_store_memory.py        5
    ├── test_matcher.py                 23
    ├── test_nessus_parser.py           16
    ├── test_oval_parser.py             1
    ├── test_parser_hardening.py        11
    ├── test_pipeline.py                7
    ├── test_stages.py                  5
    ├── test_web.py                     17
    ├── test_xccdf_parser.py            44
    └── test_zip_extract.py             11
```

---

## 2. Data Models (`app/parsers/base.py`)

All `@dataclass`. Field types are `str` unless noted.

| Class | Field | Type | Notes |
|---|---|---|---|
| `RuleResult` | `rule_id` | str | Full XCCDF rule id |
| | `status` | str | Raw XCCDF value: `fail`, `pass`, `notchecked`, `error`, `unknown`, `notselected`, `notapplicable`, … |
| `ScanResult` | `source_file` | str | Filename (stem used as hostname fallback) |
| | `hostname` | str | Target hostname |
| | `ip_address` | str | Target IP — `"N/A"` if unresolvable |
| | `benchmark_href` | str | `href` from `<benchmark>` element |
| | `benchmark_id` | str | `id` from `<benchmark>` element |
| | `scanner` | str | Detected scanner name |
| | `rule_results` | `list[RuleResult]` | default `[]` |
| `BenchmarkRule` | `vuln_id` | str | V-number (e.g. `V-254239`) |
| | `rule_id` | str | Full XCCDF rule id |
| | `severity` | str | `CAT I` / `CAT II` / `CAT III` |
| | `check_text` / `fix_text` | str | May be empty for SCAP-style files |
| `Benchmark` | `benchmark_id` | str | Root `<Benchmark>` `id` |
| | `title` | str | Benchmark title |
| | `rules` | `dict[str, BenchmarkRule]` | keyed by rule_id, default `{}` |
| `Finding` | `stig_title` | str | Report row — the common currency all parsers emit |
| | `vuln_id` / `rule_id` / `severity` / `status` | str | |
| | `server` / `ip_address` | str | |
| | `check_text` / `fix_text` | str | |
| `BaseParser` | — | ABC | abstract `parse(self, path) -> Any` |

**`Finding` is the pipeline's common output type.** XCCDF results become `ScanResult` then get matched into `Finding`s; CKLB and .nessus parsers emit `Finding`s directly (self-contained formats).

---

## 3. Parsers (`app/parsers/`)

All XML parsers share a per-call `_safe_xml_parse` hardened against XXE / SSRF / billion-laughs (`resolve_entities=False`, `no_network=True`, `load_dtd=False`).

### 3.1 `xccdf_parser.py` — XCCDF scan results

**Class:** `XCCDFResultsParser(BaseParser)` → `parse(path) -> ScanResult | None`

| Helper | Returns | Description |
|---|---|---|
| `_find_test_result(root, file_name)` | Element | Locate `<TestResult>` (root or nested); **uses the LAST of multiple** (OpenSCAP post-remediation state), warns |
| `_find_fact(root, urns)` | str | `<fact>` text by URN, preference order |
| `_find_text(root, *local_names)` | str | Direct-child text, namespace-agnostic |
| `_findall_results(root)` | list | All `<rule-result>` children |
| `_find_child_text(el, local)` | str | Direct child text by local name |
| `_get_benchmark_attrs(root)` | (str, str) | `(href, id)` from `<benchmark>` |

Constants: `_NS_XCCDF_12`, `_XCCDF_NS`, `_FACT_HOSTNAME_URNS` (host_name, fqdn), `_FACT_IP_URNS` (ipv4, ipv6).
**Hostname order:** `<target>` → target-facts host_name/fqdn → `<title>` → filename stem.
**IP order:** target-facts ipv4/ipv6 → `<target-address>` → `"N/A"`.
**Rejects legacy `.ckl`** (root `<CHECKLIST>`) with a warning pointing to the CKLB route.

### 3.2 `benchmark_parser.py` — STIG definitions (XCCDF 1.1 *and* 1.2)

**Class:** `BenchmarkParser(BaseParser)` → `parse(path) -> Benchmark | None`

| Helper | Description |
|---|---|
| `_findall_local(el, local)` | Direct children by local name |
| `_extract_vuln_id(raw_id)` | Strip `…_group_` prefix from XCCDF 1.2 ids |
| `_find_text_ns(el, local)` | Direct-child text with namespace fallback |
| `_get_check_text(rule_el)` | Text from `<check><check-content>` |
| `_get_fix_text(rule_el)` | Text from `<fixtext>` |

Constants: `_NS_XCCDF_11`, `_NS_XCCDF_12`, `_SEVERITY_MAP` (`high→CAT I`, `medium→CAT II`, `low→CAT III`; else `Unknown`).

### 3.3 `cklb_parser.py` — CKLB JSON checklists (self-contained → emits `Finding`s)

**Class:** `CKLBParser(BaseParser)` → `parse(path) -> list[Finding] | None`
Reads UTF-8-BOM-tolerant JSON; requires a `stigs` array; per-host `target_data`.
Helper `_effective_severity(rule)` honours STIG Viewer severity overrides.
Constants: `_SEVERITY_MAP`, `_STATUS_MAP` (`open→Open`, `not_reviewed→Not Reviewed`, `not_a_finding→Not A Finding`, `not_applicable→Not Applicable`, `error→Error`). Unrecognised status → `Unknown` (never silently dropped).

### 3.4 `nessus_parser.py` — Tenable .nessus compliance scans (self-contained → emits `Finding`s)

**Class:** `NessusComplianceParser(BaseParser)` → `parse(path) -> list[Finding] | None`
Requires root `<NessusClientData_v2>`; reads `ReportItem[pluginFamily="Policy Compliance"]` with `cm:`-namespaced children.

| Helper | Description |
|---|---|
| `_safe_xml_parse(path)` | hardened lxml parse (`huge_tree=True` — real scans run to several MB) |
| `_parse_reference_tokens(ref)` | Parse `KEY\|value,…` from `cm:compliance-reference`; first key wins |
| `_host_metadata(report_host)` | `(hostname, ip)` from `<HostProperties>` |

Constants: `_CM_NS`/`_CM`, `_RESULT_MAP` (`FAILED→Open`, `PASSED→Not A Finding`, `WARNING→Not Reviewed`, `ERROR→Error`), `_CAT_MAP` (I/II/III). STIG cross-refs (Vuln-ID / Rule-ID / STIG-ID / CAT) pulled from `cm:compliance-reference`; check text appends observed `compliance-actual-value` as evidence.

### 3.5 `oval_parser.py` — stub

**Class:** `OVALParser(BaseParser)` — `parse()` raises `NotImplementedError`. On the README roadmap.

---

## 4. Processors (`app/processors/`)

### 4.1 `matcher.py`
`match_results_to_benchmarks(scan_results, benchmarks) -> list[Finding]` — joins each `RuleResult` to its `BenchmarkRule` via parent benchmark; emits only actionable statuses; warns on unmatched benchmarks and unmatched rule ids.
Helpers: `_normalize_id(raw)` (Path.stem.lower, hrefs only), `_find_benchmark(href, bid, benchmarks)` — 3-tier match (exact id → href stem → substring).
Constants: `_STATUS_MAP` (`fail→Open`, `notchecked/notselected→Not Reviewed`, `error→Error`, `unknown→Unknown`), `_KEEP_STATUSES`.

### 4.2 `filter.py`
`filter_findings(findings) -> list[Finding]` — defensive keep of `Open` / `Not Reviewed` / `Error` / `Unknown` (`_KEEP_STATUSES`).

---

## 5. Core Pipeline & Boundaries (`app/core/`)

AWS-agnostic. `pipeline.py`, `stages.py`, and `findings_io.py` must not import boto3; only `S3ArtifactStore` / `DynamoJobStore` may.

### 5.1 `pipeline.py` — single source of truth
| Symbol | Kind | Description |
|---|---|---|
| `PipelineError` | Exception | User-safe message for UI / CLI |
| `ParseResult` | dataclass | `findings`, `warnings`, `source_file_count` |
| `parse_stage(results_paths, benchmark_paths, extract_dir, *, cancel_check=None)` | fn | Routes `.cklb`/`.nessus` to self-contained parsers (`_SELF_CONTAINED`), rest through XCCDF; expands ZIPs; matches + filters; raises `PipelineError` when no actionable findings, with a diagnostic message |
| `compute_summary(findings, source_file_count)` | fn | `{files, hosts, findings, cat1, cat2, cat3}` |
| `export_stage(findings, output_path)` | fn | Delegates to `ExcelExporter` |
| `default_output_name()` | fn | `stig_findings_<UTC timestamp>.xlsx` |

Optional benchmarks: when none supplied, XCCDF result files feed both sides (SCC self-contained); CKLB/.nessus never need benchmarks.

### 5.2 `stages.py` — async stage entrypoints (future Lambda)
`run_parse_stage(job_id, input_filenames, store, jobs, *, work_dir) -> bool` and `run_export_stage(job_id, store, jobs, *, work_dir) -> bool` — take an `ArtifactStore` + `JobStore`, never raise (errors captured into job record), pass findings between stages as `findings.json`. `_is_safe_name(name)` rejects path-traversal filenames. Keys: `INPUT_PREFIX`, `FINDINGS_KEY`, `REPORT_KEY`.

### 5.3 `artifact_store.py` — blob boundary
`ArtifactStore` Protocol (`put_bytes`/`get_bytes`/`exists`/`upload_from`/`download_to`/`presign_get`/`presign_put`).
- `LocalArtifactStore(root)` — filesystem; `_resolve` rejects keys escaping root; presign returns `file://` URI.
- `S3ArtifactStore(bucket, region, client=None)` — the only boto3-touching blob member; real presigned URLs.

### 5.4 `job_store.py` — job-status boundary
`JobStore` Protocol (`create`/`update`/`get`/`delete`).
- `MemoryJobStore` — thread-safe dict; backs Flask / CLI / tests.
- `DynamoJobStore(table_name, region, client=None)` — single item per `job_id`, fields JSON-encoded into a `data` attribute; **non-atomic read-modify-write** (docstring notes single-writer-per-job requirement).

### 5.5 `findings_io.py`
`findings_to_json(findings) -> str` / `findings_from_json(data) -> list[Finding]` — `asdict`-based; unknown keys ignored for forward/backward compatibility.

---

## 6. Exporters (`app/exporters/excel_exporter.py`)

**Class:** `ExcelExporter.export(findings, output_path) -> Path` — raises `ValueError` on empty list. Builds `Findings` + `Summary` sheets.
- `_write_findings(ws, findings)` — header row, data rows, severity fill, freeze `A2`, auto-filter `A1:I1`, measured column widths.
- `_write_summary(ws, findings)` — three COUNTIFS tables + italic footer note.
- Module utils: `_unique_pairs`, `_unique_values` (order-preserving dedup).
- **CSV-injection defense:** `_sanitize_cell` prefixes `'` to any value starting with `= + - @ | \t \r` (`_FORMULA_PREFIXES`) — scan text is attacker-controllable.

**Findings columns (`_FINDINGS_COLS`):** A STIG Title(50) · B Vuln ID(12) · C Rule ID(40) · D Severity(10) · E Status(14) · F Server(30) · G IP Address(18) · H Check Text(80, wrap) · I Fix Text(80, wrap).
**Severity fills:** CAT I `#FFCCCC` · CAT II `#FFEB9C` · CAT III `#C6EFCE`. Fonts: Arial 10 (bold header).
**Summary tables:** By Severity (Severity × statuses) · By Server (Server, IP × CAT I/II/III) · By STIG (Title × CAT I/II/III), each with a SUM total; footer disclaims that filtering doesn't update COUNTIFS.

---

## 7. Utils (`app/utils/`)

### 7.1 `scanner_detect.py`
`detect_scanner(path) -> str` → `SCC` / `OpenSCAP` / `Nessus` / `Evaluate-STIG` / `Unknown`.
Precedence: Nessus namespaces → SCAP source namespace (SCC) → `test-system="…scc…"` on `<TestResult>` → generator-text signature match → root `id` contains `evaluate-stig`.
Helpers: `_collect_namespaces`, `_extract_generator_text`. Constants: `_SCANNER_SIGNATURES`, `_NAMESPACE_HINTS`, `_SCC_NAMESPACE`.

### 7.2 `zip_extract.py`
`extract_xccdf_from_zip(zip_path, dest_dir, _depth=0) -> list[Path]` — pulls every `*xccdf.xml`; recurses into nested ZIPs (wrapper pattern).
`expand_benchmark_paths(paths, extract_dir) -> (list[Path], list[str])` — replaces `.zip` entries with extracted XMLs; returns warnings for ZIPs with no XCCDF.
**Zip-bomb defenses:** `_bounded_extract` streams with a 500 MB decompressed cap (`_MAX_EXTRACTED_BYTES`); `_MAX_ZIP_DEPTH=2` recursion limit. Helper `_unique_path` on collision. Constant `_XCCDF_SUFFIX="xccdf.xml"`.

---

## 8. Web Application (`app/web.py`)

### 8.1 Factory
`create_app(secret_key=None) -> Flask` — sets secret (env `FLASK_SECRET_KEY`, else ephemeral + warning), `MAX_CONTENT_LENGTH = 500 MB`, sweeps orphaned jobs on startup.

### 8.2 HTTP routes
| Method | Path | Handler | Returns |
|---|---|---|---|
| GET | `/` | `index()` | Renders `index.html` with `existing_job_id` from session |
| GET | `/readme` | `readme()` | `README.md` as `text/plain`; 404 if not bundled |
| POST | `/api/process` | `process()` | `{job_id, status}` 200 · `{error}` 400 · `{error}` 429 (rate-limited) |
| GET | `/api/status/<job_id>` | `job_status()` | `{status, progress, warnings, error, summary}`; 404 unless session owns the job |
| POST | `/api/cancel/<job_id>` | `cancel()` | `{status: "cancelling"}`; sets `cancelled` flag |
| GET | `/api/download/<job_id>` | `download()` | `.xlsx` attachment; deletes job dir on response close; 400 unless complete |

**Ownership check:** status/cancel/download all require `session["job_id"] == job_id` (404 otherwise) — a client can only touch its own job.

### 8.3 Rate limiting
`_rate_limited(client_ip)` — in-process sliding window, `_RATE_MAX=10` per `_RATE_WINDOW=60s`, per IP (`_rate_hits`). Caps unauthenticated job spam; not a WAF replacement.

### 8.4 Background processing
`_run_job(job_id, results_paths, benchmark_paths)` — threaded: `parse_stage` (with cancel check) → `export_stage` → `compute_summary`; catches `PipelineError` (user-safe) vs generic `Exception` (logs traceback, returns "see server logs").
Cancellation: `_JobCancelled` exception + `_raise_if_cancelled(job_id)`; cancelled jobs drop files but keep the status entry.
State helpers: `_set_job`, `_get_job`, `_job_dir`. Log capture: `_WarningCollector(logging.Handler)` funnels WARNING+ from `app.*` into the job's `warnings`.

### 8.5 Module state & cleanup
`_jobs` / `_jobs_lock`, `_TEMP_DIR` (`$STIG_TEMP_DIR` or `<repo>/tmp`), `_ORPHAN_MAX_AGE_HOURS=8`. `_delete_job`, `_sweep_orphaned_jobs` (startup dir sweep).

---

## 9. CLI (`app/cli.py`)

`main(argv=None) -> int` — 0 success / 1 error. Routes through `app.core.pipeline`.
Args: `--results` (required; `.xml`/`.cklb`/`.nessus`, dirs, globs) · `--benchmarks` (optional; `.xml`/`.zip`) · `--output` (default timestamped) · `--verbose`.
Helpers: `_resolve_paths(args, extensions)` (dir/glob expansion), `_build_parser()`. Console script: `stig-parser = app.cli:main`.

---

## 10. UI — Template (`app/templates/index.html`)

Single-page app. Sections show/hide via the `hidden` attribute — **no true modals**.

| Section | Visible when | Contents |
|---|---|---|
| `<header>` | always | `h1` + `.subtitle` (notes SCC self-contained) |
| `#app` `<main>` | always | wraps everything; `<noscript>` CLI fallback note |
| `#upload-section` | initial / after reset | upload form |
| `#progress-section` | job running | activity log, cancel, warnings |
| `#result-section` | complete or error | success or error card |
| `<footer>` | always | supported-scanner line + `/readme` link |

**Upload section:** `<form id="upload-form">` › `.upload-grid` with two `.upload-zone`s:
- `#results-zone` (required) — inline SVG icon, "Scan Results", accepts `.xml,.cklb,.nessus`; `#results-browse` button, hidden `#results-input`, `#results-zone-notice` (drop-reject `role=status`), `ul#results-file-list`.
- `#benchmarks-zone` (optional) — `<h2>` with `.badge-optional` "Optional for SCC", accepts `.xml,.zip`; parallel browse/input/notice/list ids.
- `.form-actions` › `#process-btn` (disabled until results selected).

**Progress section:** `h2` "Processing" · `#activity-log` (`role=log`, `aria-live=polite`, timestamped lines) · `#stall-note` (revealed after ~20 silent polls) · `.progress-actions` › `#cancel-btn` · `#warnings-box` (lead + `ul#warnings-list`).

**Result section:**
- `#result-success` (`role=status`) — drawn-check SVG, "Report Ready", `dl#report-summary` (`#sum-files`/`-hosts`/`-findings`/`-cat1`/`-cat2`/`-cat3`), `#summary-note` (zero-severity warning), `#download-link`, `#reset-btn`, `#success-warnings-box` + `#success-warnings-list`.
- `#result-error` (`role=alert`) — ✕ SVG, "Processing Failed", `#error-message`, `#error-warnings-box` + `#error-warnings-list`, `#reset-btn-error`.

### 10.1 Inline JavaScript (IIFE)
State: `pollTimer`, `currentJobId` (seeded from template var), `lastWarnings`, `lastSummary`, `pollFailures`, `lastProgressMsg`, `unchangedPolls`.

| Function | Purpose |
|---|---|
| `removeFileAt` / `updateFileList` | Rebuild `FileList` via `DataTransfer`; render rows with remove buttons |
| `showZoneNotice` | Show/hide per-zone drop-reject message |
| `setupZone(zone, input, listEl, browseBtn, noticeEl, allowedExts)` | Wire browse/click/drag-drop; drop filters by extension, counts skipped |
| `updateProcessBtn` | Enable Process when results selected |
| `startPolling` / `poll` | 1 s `/api/status` loop; branches complete/cancelled/error; stall detection |
| `logLine` | Append timestamped activity-log line |
| `showWarnings` | Render warnings; skips identical re-renders (aria-live hygiene) |
| `showSuccess` / `renderSummary` | Reveal success card, set download href, render summary + zero-severity note |
| `showError` | Reveal error card, re-render last warnings |
| `resetSections` / `resetUI` / `softReset` | Full reset (clears files) vs soft reset (keeps file selections after error/cancel) |
| cancel handler | POSTs `/api/cancel/<id>`, disables button |
| reconnect block | On load, polls `/api/status/<existing_job_id>` and re-attaches to a running/complete job |

Poll fault tolerance: `pollFailures >= 10` → give-up message; `unchangedPolls >= 20` → stall note.

---

## 11. UI — Stylesheet (`app/static/style.css`)

Pure custom CSS, no framework, ~596 lines. Light + dark via `color-scheme` + `prefers-color-scheme`.

### 11.1 Fonts & reset
Three `@font-face` (Public Sans 400/600/700, self-hosted woff2, `font-display: swap` — works air-gapped). Universal box-sizing + margin/padding reset.

### 11.2 Tokens (`:root`)
Type scale: `--text-caption .75` / `--text-small .875` / `--text-body 1` / `--text-title 1.25` / `--text-display 1.75` rem, `--text-mono .8125`, `--leading-body`.
Light palette: `--color-bg #f3f4f7`, `--color-surface #fdfdfe`, `--color-border #d8dce4`, `--color-primary #1f5fc4` (+`-h`, `--color-on-primary`), `--color-accent-bg/-br`, `--color-danger #b42318` (+`-tint`), `--color-success #1a7f37`, `--color-warning-bg/-br/-text`, `--color-text #20262e`, `--color-muted #4b5768` (WCAG AA ≥4.5:1), `--radius 8px`, `--shadow`.
**Dark override** (`@media prefers-color-scheme: dark`): deep-slate re-map of every token, no neon; bumped `--leading-body 1.55`.

### 11.3 Sections
| Group | Selectors |
|---|---|
| Layout | `body`, `a`, `.container` (max 860px) |
| Header | `header`, `header h1` (display, `-.02em`), `.subtitle` |
| Upload grid | `.upload-grid` (2-col → 1-col ≤580px, `minmax(0,1fr)`), `.upload-zone` (+`:hover`/`.dragover`), `.zone-icon`, `.upload-zone h2` (uppercase small caps), `.badge-optional` (pill), `.upload-zone p`, `.zone-notice`, `.noscript-note` |
| File list | `.file-list` (scroll, max 120px), `.file-list li`, `.file-name` (mono, ellipsis, `::before` green ✓), `.file-remove` (+`:hover`/`:focus-visible` red tint) |
| Focus | `.btn/.file-remove/a :focus-visible` — 2px primary outline |
| Buttons | `.btn`, `.btn-primary` (+hover), `.btn-secondary` (+hover), `.btn:disabled`, `.form-actions` |
| Touch | `@media (pointer: coarse)` — 44px min targets |
| Progress | `#progress-section`, shared `h2`, `.activity-log` (mono, scroll 14rem), `.log-line`, `.log-time` (tabular), `.progress-text`, `.stall-note`, `.progress-actions` (right-aligned) |
| Warnings | `.warnings-box` (+`h3`, `.warnings-lead`, `ul`, `li + li`, `li::before` ⚠) |
| Result cards | `#result-section`, `.result-card`, `.result-icon` (success green / error red), `.result-card h2`, `.btn + .btn` |
| Summary | `.report-summary` (+`:has(#summary-note…)` gap), `.summary-row`/`dt`/`dd` (tabular), `.summary-total`, `.summary-cat`, `.summary-cat1-open` (danger red), `.summary-note`, `#result-error p` |
| Footer | `footer`, `footer .small` |
| Motion | `@keyframes rise-in`, `draw-check`; card rise-in, self-drawing checkmark (`pathLength=1`), staggered summary rows, log-line fade, `.btn:active` press; **`@media (prefers-reduced-motion: reduce)`** kills all animation/transition |

---

## 12. Test Suite (`tests/`) — 234 functions / 20 files

| File | # | Focus |
|---|---|---|
| `test_xccdf_parser.py` | 44 | SCC/OpenSCAP/Nessus/Evaluate-STIG fixtures, status codes, edge cases, multi-TestResult, `.ckl` rejection |
| `test_matcher.py` | 23 | Finding assembly, status mapping/discards, benchmark fallbacks, duplicate targets |
| `test_benchmark_parser.py` | 22 | XCCDF 1.1 + 1.2 parsing, severity, vuln-id stripping, edge cases |
| `test_web.py` | 17 | Routes, validation, rate limit, cancel, download, ownership 404s |
| `test_cklb_parser.py` | 17 | CKLB JSON parsing, severity overrides, status mapping, malformed input |
| `test_nessus_parser.py` | 16 | `.nessus` compliance parsing, reference tokens, host metadata, vuln-scan warning |
| `test_cli.py` | 15 | Arg parsing, path resolution, optional/omitted benchmarks, error exit |
| `test_excel_exporter.py` | 13 | Sheet structure, headers, freeze/filter, COUNTIFS, empty raises, CSV sanitize |
| `test_parser_hardening.py` | 11 | XXE / billion-laughs / SSRF protections across parsers |
| `test_zip_extract.py` | 11 | XCCDF extraction, nesting, collisions, bad ZIP, size/depth caps |
| `test_filter.py` | 7 | Kept vs discarded statuses |
| `test_pipeline.py` | 7 | `parse_stage` routing, self-contained formats, PipelineError messages, summary |
| `test_artifact_store_local.py` | 5 | Local blob round-trip, traversal rejection |
| `test_job_store_memory.py` | 5 | Memory store CRUD, thread safety |
| `test_stages.py` | 5 | Async stage entrypoints, unsafe-filename rejection |
| `test_artifact_store_s3.py` | 4 | S3 store via moto |
| `test_job_store_dynamo.py` | 4 | Dynamo store via moto |
| `test_findings_io.py` | 4 | JSON round-trip, unknown-key tolerance |
| `test_core_import.py` | 3 | `app.core` imports stay boto3-free where required |
| `test_oval_parser.py` | 1 | Stub raises `NotImplementedError` |

**Fixtures (`tests/fixtures/`):** `scc_results.xml`, `openscap_results.xml`, `nessus_results.xml`, `evaluate_stig_results.xml`, `sample_benchmark.xml` — all fabricated, no real DoD data.

---

## 13. Configuration

### 13.1 `pyproject.toml`
- `[project]` name `stig-parser`, version `0.1.0`, requires-python `>=3.11`, MIT.
- deps: `flask>=3.0`, `lxml>=5.0`, `openpyxl>=3.1`, `boto3>=1.34`.
- `[optional-dependencies].dev`: `pytest>=8.0`, `pytest-cov>=4.0`, `moto[s3,dynamodb]>=5.0`.
- `[project.scripts]` `stig-parser = app.cli:main`. `[tool.pytest.ini_options]` testpaths `["tests"]`. Packages: `app*`.

### 13.2 `.github/workflows/ci.yml`
`CI` on push/PR to `main`; matrix Python 3.11 & 3.12 on ubuntu-latest; `pip install -e ".[dev]"` → `pytest tests/ -v --tb=short`.

---

## 14. Deployment

### 14.1 `Dockerfile`
`python:3.11-slim`; installs `libxml2` + `libxslt1.1`; copies `pyproject.toml` + `app/`, `pip install -e .`; `STIG_TEMP_DIR=/tmp/stig-parser-jobs`; EXPOSE 5000; CMD flask run `app.web:create_app` on `0.0.0.0:5000`.

### 14.2 `docker-compose.yml`
Service `stig-parser`: build local, `5000:5000`, named volume `stig-tmp` at `/tmp/stig-parser-jobs`, env `FLASK_SECRET_KEY` (placeholder) + `STIG_TEMP_DIR`, `restart: unless-stopped`.

---

## 15. Documentation & Design Docs

- `README.md` — scanners, output reference, install (pip/Docker), Web+CLI usage, pipeline overview, DISA benchmark source, LibreOffice notes, contributing, roadmap, MIT.
- `RESIDUALS.md` — residual-risk / known-limitations notes.
- `docs/superpowers/specs/2026-07-07-govcloud-replatform-design.md` — GovCloud/Bedrock/React/Terraform re-platform spec (motivates the `app/core/` boundaries + `stages.py`).
- `docs/superpowers/plans/2026-07-07-backend-async-rearchitecture.md` — async rearchitecture plan.
- `LICENSE` — MIT.

---

## 16. Data Flow Summary

```
┌──────────────┐     ┌───────────────┐
│ Upload form  │     │ CLI invocation│
│ (web.py)     │     │ (cli.py)      │
└──────┬───────┘     └──────┬────────┘
       └────────┬───────────┘
                ▼
      app.core.pipeline.parse_stage
                │
   ┌────────────┼─────────────────────────┐
   ▼            ▼                          ▼
.cklb/.nessus   XCCDF (.xml)          expand ZIPs
self-contained  detect_scanner        (zip_extract)
→ Finding[]     XCCDFResultsParser         │
                BenchmarkParser ◄───────────┘
                        │
                match_results_to_benchmarks → filter_findings
                        ▼
                 list[Finding]  ── compute_summary ──► {files,hosts,cat1..3}
                        ▼
              export_stage → ExcelExporter
                        ▼
              Findings + Summary  .xlsx

Async variant (stages.py, future Lambda):
  run_parse_stage → ArtifactStore(findings.json) → run_export_stage → report.xlsx
  status via JobStore (Memory today, Dynamo in GovCloud)
```

---

*Regenerated 2026-07-13 against current tree (adds `app/core/`, CKLB + .nessus parsers, cancel/readme routes, rate limiting, run summary, hardening tests).*
