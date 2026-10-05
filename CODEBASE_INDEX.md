# STIG Compliance Parser — Codebase Index

Complete catalogue of every module, class, function, route, template section, CSS rule, test, and configuration artefact in the project.

**Language:** Python 3.11+ · **Web framework:** Flask 3 · **XML:** lxml · **Excel:** openpyxl · **Cloud:** boto3 (S3 / DynamoDB boundaries)
**Test count:** 1,136 pytest test functions across 32 files (1,491 cases once parametrised); the SPA has its own Vitest suite in `frontend/`

---

## 1. Top-Level File Tree

```
stig-parser/
├── .github/workflows/              ci.yml (pytest matrix), frontend.yml, infra.yml
├── .gitattributes / .gitignore
├── CODEBASE_INDEX.md               This file
├── RESIDUALS.md                    Residual-risk / known-limitations notes
├── Dockerfile                      Container build
├── docker-compose.yml              Service orchestration
├── LICENSE                         MIT
├── pyproject.toml                  Package metadata + deps
├── README.md                       User-facing documentation
├── docs/superpowers/               Design specs and implementation plans
├── frontend/                       React + TypeScript SPA for the GovCloud deployment (Vite, Vitest)
├── infra/                          Terraform modules for the GovCloud deployment
├── app/                            Application source (one Python package)
│   ├── __init__.py                 Empty package marker
│   ├── cli.py                      CLI entry point → app.core.pipeline
│   ├── web.py                      Flask app factory + threaded jobs
│   ├── limits.py                   MAX_UPLOAD_BYTES (200 MB), shared by uploads and the archive reader
│   ├── core/                       AWS-agnostic pipeline + storage boundaries
│   │   ├── __init__.py
│   │   ├── pipeline.py             Single source of truth: route→parse→match→filter→enrich→export
│   │   ├── inputs.py               classify_inputs: route uploads by content; ZIPs read as folders
│   │   ├── uploads.py              Upload allow-list + size check, shared by Flask and the API Lambda
│   │   ├── stages.py               Async stage entrypoints (called by the Lambda handlers)
│   │   ├── artifact_store.py       Blob boundary: Local + S3 implementations
│   │   ├── job_store.py            Job-status boundary: Memory + Dynamo implementations
│   │   └── findings_io.py          Finding ↔ JSON serialization
│   ├── exporters/
│   │   ├── __init__.py
│   │   └── excel_exporter.py       Findings + Summary workbook; delta workbook
│   ├── lambdas/                    Lambda handler shims (api, parser, enricher, exporter, mark_error, common)
│   ├── parsers/                    File ingestion
│   │   ├── __init__.py
│   │   ├── base.py                 Abstract parser + dataclasses + RowLog
│   │   ├── benchmark_parser.py     STIG benchmark defs (XCCDF 1.1/1.2, at any depth, data streams)
│   │   ├── xccdf_parser.py         XCCDF scan results (SCC/OpenSCAP/…)
│   │   ├── cklb_parser.py          CKLB JSON checklists (Evaluate-STIG / STIG Viewer 3)
│   │   ├── nessus_parser.py        Tenable .nessus compliance scans
│   │   └── oval_parser.py          Stub — raises NotImplementedError
│   ├── processors/
│   │   ├── __init__.py
│   │   ├── filter.py               Discard non-actionable findings
│   │   ├── matcher.py              Read each scan against its own embedded benchmark
│   │   └── delta.py                Baseline-vs-current comparison
│   ├── reference/                  STIG reference library: fills blank finding text
│   │   ├── __init__.py
│   │   ├── normalize.py            Identifier normalisation; bounds and escaping for uploaded text
│   │   ├── models.py               ReferenceSource, ReferenceRule, make_rule
│   │   ├── library.py              ReferenceLibrary: four indexes, guarded lookup
│   │   ├── cklb_loader.py          Checklist → reference rules
│   │   ├── text_source.py          The Text Source cell
│   │   └── enrich.py               enrich_findings, EnrichmentReport (+ JSON round trip, warnings)
│   ├── static/
│   │   ├── app.js                  Page script (strict CSP: no inline JS)
│   │   ├── style.css               Single CSS stylesheet (no framework)
│   │   ├── favicon.svg
│   │   └── fonts/                  Self-hosted woff2 + OFL licences
│   ├── templates/index.html        Single Flask template
│   └── utils/
│       ├── __init__.py
│       ├── scanner_detect.py       Auto-identify SCC / OpenSCAP / Nessus / Evaluate-STIG
│       ├── parse_cost.py           Pre-parse cost scan (elements, attributes, tags) and caps
│       └── zip_extract.py          Bounded ZIP reader (nested ZIPs, root sniff, budgets)
└── tests/                          pytest suite — 1,136 test functions
    ├── __init__.py
    ├── fixtures/                   Fabricated XCCDF / CKLB / .nessus / benchmark samples
    │   ├── evaluate_stig_checklist.cklb
    │   ├── evaluate_stig_results.xml
    │   ├── legacy_checklist.ckl.xml
    │   ├── manual_stig_server2022.xml
    │   ├── manual_stig_win11.xml
    │   ├── nessus_compliance.nessus
    │   ├── nessus_results.xml
    │   ├── openscap_remediation_results.xml
    │   ├── openscap_results.xml
    │   ├── sample_benchmark.xml
    │   ├── scap_datastream_win11.xml
    │   ├── scc_embedded_results.xml
    │   └── scc_results.xml
    └── test_*.py                   32 files — see §12
```

---

## 2. Data Models (`app/parsers/base.py`)

All `@dataclass`. Field types are `str` unless noted.

| Class | Field | Type | Notes |
|---|---|---|---|
| `RuleResult` | `rule_id` | str | Full XCCDF rule id |
| | `status` | str | Raw XCCDF value: `fail`, `pass`, `notchecked`, `error`, `unknown`, `notselected`, `notapplicable`, … |
| `ScanResult` | `source_file` | str | Display name of the results file (stem used as hostname fallback) |
| | `hostname` | str | Target hostname |
| | `ip_address` | str | Target IP — `"N/A"` if unresolvable |
| | `benchmark_href` | str | `href` from `<benchmark>` element |
| | `benchmark_id` | str | `id` from `<benchmark>` element |
| | `scanner` | str | Detected scanner name |
| | `rule_results` | `list[RuleResult]` | default `[]` |
| | `embedded_benchmarks` | `list[Benchmark]` | Benchmarks embedded in the same results file (SCC); the matcher takes rule data and the scanned release from these only |
| `BenchmarkRule` | `vuln_id` | str | V-number (e.g. `V-254239`) |
| | `rule_id` | str | Full XCCDF rule id |
| | `severity` | str | `CAT I` / `CAT II` / `CAT III` |
| | `check_text` / `fix_text` | str | Check text is empty in SCAP benchmarks |
| | `stig_id` | str | XCCDF `<version>`, e.g. `WN22-00-000010` |
| `Benchmark` | `benchmark_id` | str | `<Benchmark>` `id` |
| | `title` | str | Benchmark title |
| | `rules` | `dict[str, BenchmarkRule]` | keyed by rule_id, default `{}` |
| | `release` | str | e.g. `V2R8` |
| `Finding` | `stig_title` | str | Report row — the common currency all parsers emit |
| | `vuln_id` / `rule_id` / `severity` / `status` | str | Severity is `""` when no benchmark or reference describes the rule |
| | `server` / `ip_address` | str | |
| | `check_text` / `fix_text` | str | |
| | `stig_id` | str | Findings column J |
| | `text_source` | str | Findings column K — where check/fix text came from |
| | `scan_release` | str | Release of the benchmark that was scanned |
| `BaseParser` | — | class | Base of the file parsers: `read()` (`read_all()` for benchmarks) returns what the file holds and why it could not be read, never raising on an upload; *name* is the display name |
| `RowLog` | — | class | Per-row parser problems: the first five per file at WARNING, the rest at DEBUG |

**`Finding` is the pipeline's common output type.** XCCDF results become `ScanResult` then get matched into `Finding`s; CKLB and .nessus parsers emit `Finding`s directly (self-contained formats). Reference enrichment fills blank fields afterwards.

---

## 3. Parsers (`app/parsers/`)

All XML parsers share a per-call `_safe_xml_parse` hardened against XXE / SSRF / billion-laughs (`resolve_entities=False`, `no_network=True`, `load_dtd=False`). Each parser's `read()` (`read_all()` for benchmarks) returns what it could not read and why, and logs none of it: the pipeline words every problem once, from what the readers return (`load_cklb_reference` and `extract_from_zip` likewise log nothing they return). Readers log at WARNING only detail the run does not report (a host or IP taken from the file name, the TestResult used, per-row lines, duplicate rule IDs); `_DETAIL_TEMPLATES` in `tests/test_reference_pipeline.py` holds that list, checked statically (`test_every_reader_log_call_is_a_known_detail_line`) and against what the run reports (`test_no_reader_log_line_repeats_a_reason_the_run_reports`).

### 3.1 `xccdf_parser.py` — XCCDF scan results

**Class:** `XCCDFResultsParser(BaseParser)` → `read(path, *, name=None, tree=None) -> (ScanResult | None, why)` — *why* is the operator's reason when nothing was read (`invalid XML: …`, a `.ckl` checklist)

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

**Class:** `BenchmarkParser(BaseParser)`
- `read_all(path, *, name=None, tree=None) -> (list[Benchmark], why)` — every `<Benchmark>` at any depth: standalone XCCDF, SCC results (Benchmark root with the TestResult inside), SCAP data streams; *why* is `invalid XML: …` or `no Benchmark element` when there are none. `load_xml(path)` is the one hardened parse the pipeline shares between readers.

Rules are collected by one walk per Benchmark that descends only through `Group` elements (nested groups supported; an inner Benchmark owns its own rules). Duplicate rule IDs keep the last definition and log one bounded, escaped warning.

| Helper | Description |
|---|---|
| `_extract_vuln_id(raw_id)` | Strip `…_group_` prefix from XCCDF 1.2 ids |
| `_find_text_ns(el, local)` | Direct-child text with namespace fallback |
| `_get_check_text(rule_el)` | Text from `<check><check-content>` |
| `_get_fix_text(rule_el)` | Text from `<fixtext>` |
| `_release_info(benchmark_el)` | Release line feeding `normalize.release_label` |
| `_benchmark_from_element(root)` | One `Benchmark` (title clipped to 200 characters) |

Constants: `_NS_XCCDF_11`, `_NS_XCCDF_12`; severity via `normalize.CAT_BY_SEVERITY` (`high→CAT I`, `medium→CAT II`, `low→CAT III`).

### 3.3 `cklb_parser.py` — CKLB JSON checklists (self-contained → emits `Finding`s)

**Class:** `CKLBParser(BaseParser)` → `read(path, *, name=None) -> (ChecklistResult | None, why)` (`findings` plus `ignored_values`, `skipped_rules`, `malformed_entries`, each turned into an operator warning by the pipeline; *why* is `cklb_loader.checklist_problem`'s reason).
Reads UTF-8-BOM-tolerant JSON through `cklb_loader.read_checklist`; requires a `stigs` array; per-host `target_data`; survives hostile JSON and takes text from JSON strings only.
Helper `_effective_severity(rule)` honours STIG Viewer severity overrides.
Constants: severity via `normalize.CAT_BY_SEVERITY` (unmapped → `Unknown`), `_STATUS_MAP` (`open→Open`, `not_reviewed→Not Reviewed`, `not_a_finding→Not A Finding`, `not_applicable→Not Applicable`, `error→Error`). Unrecognised or non-text status → `Unknown` (never silently dropped).

### 3.4 `nessus_parser.py` — Tenable .nessus compliance scans (self-contained → emits `Finding`s)

**Class:** `NessusComplianceParser(BaseParser)` → `read(path, *, name=None) -> (list[Finding] | None, why)` (`invalid XML: …`, `not a Nessus export (root element is <x>, …)`)
Requires root `<NessusClientData_v2>`; reads `ReportItem[pluginFamily="Policy Compliance"]` with `cm:`-namespaced children.

| Helper | Description |
|---|---|
| `_safe_xml_parse(path)` | hardened lxml parse (`huge_tree=True` — real scans run to several MB) |
| `_parse_reference_tokens(ref)` | Parse `KEY\|value,…` from `cm:compliance-reference`; first key wins |
| `_host_metadata(report_host)` | `(hostname, ip)` from `<HostProperties>` |

Constants: `_CM_NS`/`_CM`, `_RESULT_MAP` (`FAILED→Open`, `PASSED→Not A Finding`, `WARNING→Not Reviewed`, `ERROR→Error`), `_CAT_MAP` (I/II/III). STIG cross-refs (Vuln-ID / Rule-ID / STIG-ID / CAT) pulled from `cm:compliance-reference`; `stig_id` is set whenever the STIG ID doubles as the rule ID; check text appends observed `compliance-actual-value` as evidence.

### 3.5 `oval_parser.py` — stub

**Class:** `OVALParser(BaseParser)` — `parse()` raises `NotImplementedError`. On the README roadmap.

---

## 4. Processors and the reference library (`app/processors/`, `app/reference/`)

### 4.1 `matcher.py`
`match_results_by_scan(scan_results, benchmarks, issues=None) -> list[list[Finding]]` (one list per scan) — each scan is read against the benchmark embedded in its own results file (`ScanResult.embedded_benchmarks`): V-ID, severity, check and fix text, STIG ID and `scan_release` come from it only. A results file that embeds one benchmark owns it; with several, the one whose folded `norm_benchmark_id` equals the scan's ID (or href stem). *benchmarks* (operator references) give a scan with no embedded benchmark its STIG title only, by the same ID equality. Severity for a rule the scan's own benchmark does not describe is `""`.
`MatchIssue(kind, source_file, benchmark_id, findings)` — `no-benchmark` (neither own nor named benchmark) or `rules-not-found` (own benchmark lacks the rule); `unresolved_issue_warnings(issues, findings, *, references_supplied)` turns the ones enrichment did not repair into operator lines.
`scan_coverage_pairs(scan_results, benchmarks)` — one `(hostname, STIG title)` pair per XCCDF scan with rule results (None for one without) (title `""` when no benchmark names it); feeds `ParseResult.coverage`.
`results_fingerprint(findings)` (host, IP, rule key, status of actionable rows) and `rule_key(finding)` — used by the pipeline to recognise copies of one scan.
Constants: `_STATUS_MAP` (`fail→Open`, `notchecked/notselected→Not Reviewed`, `error→Error`, `unknown→Unknown`), `_KEEP_STATUSES`.

### 4.2 `filter.py`
`filter_findings(findings) -> list[Finding]` — defensive keep of `Open` / `Not Reviewed` / `Error` / `Unknown` (`_KEEP_STATUSES`).

### 4.3 `delta.py`
`compute_delta(baseline, current, *, baseline_coverage, current_coverage) -> DeltaResult` — pure, I/O-free baseline-vs-current comparison of two `list[Finding]`. Coverage — the `(server, stig_title)` pairs each run scanned (`ParseResult.coverage`) — is required and never derived from the findings. `DELTA_STATUSES = ("New", "Resolved", "Persisting", "Not re-scanned", "Newly scanned")`. Host sets (`common_hosts`, `only_baseline_hosts`, `only_current_hosts`) come from coverage: a host only in one side is wholly `Not re-scanned` / `Newly scanned`. On common hosts, identity is a two-pass match (`_match_two_pass`): `(host, vuln_id)` first, then `(host, rule stem)` for leftovers (`_rule_stem` strips the `xccdf_*_rule_` prefix and `rNNN_rule` revision; blank rule IDs never match) — tolerates asymmetric V-ID coverage. A leftover baseline finding is `Resolved` only if its `(host, STIG)` pair is in the current coverage, else `Not re-scanned`; a leftover current finding is `New` only if its pair is in the baseline coverage, else `Newly scanned`. Keys: `_host_key` (case/whitespace-insensitive), `_stig_key` (edition-neutral: drops stig/scap/benchmark/manual/disa/audit tokens, "Security Technical Implementation Guide", `vNrN`), `_pair_key`. `DeltaResult.not_rescanned_pairs` / `newly_scanned_pairs` keep raw spellings. `coverage_gaps(result) -> CoverageGaps(not_rescanned, newly_scanned, unverifiable)` — a pair is unverifiable when a run scanned its host with no STIG title; it feeds the warnings and the workbook's Coverage block. `DeltaFinding` rows carry `stig_id` and `text_source`. Rows sort by normalised host key. `DeltaResult.warnings` carries every coverage warning (no host overlap, pairs not re-scanned / newly scanned / unverifiable, scans with no STIG title, asymmetric Vuln-ID coverage, duplicates) so it reaches the workbook.

### 4.4 `app/reference/` — STIG reference library

Pure package (no I/O beyond reading a checklist). Fills blank finding text from every STIG benchmark the run sees: operator references, and the benchmarks and checklists embedded in results files.

| Module | Symbols | Description |
|---|---|---|
| `normalize.py` | `strip_rule_prefix`, `rule_revision`, `rule_stem`, `strip_group_prefix`, `norm_stig_id`, `norm_benchmark_id`, `release_label`, `release_key`, `is_disa_stem`, `is_vuln_id`, `product_key`, `fold`, `clip`, `clip_left`, `safe_name`, `shown_file_name`, `escape_controls`, `error_text`, `json_text`/`JsonText` | Identifier normalisation (XCCDF prefixes, `rNNN` revisions, ASCII-only folding); bounds for uploaded text (`MAX_STORED_CHARS` 200, `MAX_SHOWN_CHARS` 120, `MAX_FILE_NAME_CHARS` 255, `MAX_RELEASE_CHARS` 40); escaping for log lines and warnings |
| `models.py` | `ReferenceSource`, `ReferenceRule`, `make_rule` | A loaded source (file name, benchmark ID, title, release, `embedded`, edition `manual`/`scap`/`cklb`, rule count; fields clipped on construction) and one rule; `make_rule` is the only constructor of a rule |
| `library.py` | `ReferenceLibrary` (`add_benchmark`, `add_rules`, `lookup`, `has_standalone`, `sources`, `warnings`), `Lookup`, `MatchKey` | Four indexes (rule ID, DISA stem, V-ID, STIG ID), at most 32 rules per key value (supplied and embedded counted apart; overflow named in `warnings`). `lookup` = gather → drop crowded V-IDs → product guard on STIG-ID-only matches; ranking within a key: same revision, supplied before embedded, scanned release, newest release, load order. An embedded benchmark equal to one already loaded is not added again. At most `MAX_RULES_PER_RUN = 250,000` rules are held per run (`rules_left`; `not_loaded(file)` names the first file past it once; `add_benchmark` builds no more than fit) |
| `cklb_loader.py` | `read_checklist`, `load_cklb_reference(path, *, embedded, name=None, max_rules=None)` → `ChecklistReference(stigs, readable, ignored_values, malformed_entries, rules_not_built)` | A checklist as reference rules; tells an unreadable file from an empty checklist; a rule with no indexable ID (`models.indexable`) is a malformed entry and is never built; at most *max_rules* are built |
| `text_source.py` | `Outcome`, `source_phrase`, `text_source_cell` | The Text Source cell: `scanner`; `<file> <release>` (+ `, scanned VxRy` / `, revision differs from scan`, `, matched by V-ID` / `, matched by STIG ID`); `no reference supplied`; `not in supplied references`; `in <file> <release>, which has no check text` (or `fix`); `V-ID matches several rules, not filled`; `STIG ID matches several STIGs, not filled`; `STIG ID found under a different STIG title, not filled` |
| `enrich.py` | `enrich_findings(findings, library) -> EnrichmentReport`, `StigCounts`, `source_key` | Fills blank check/fix text, severity, V-ID, STIG ID and STIG title; never overwrites scanner values. `EnrichmentReport` (`stigs`, `sources`, `source_counts` keyed by `source_key`, `standalone_sources`, `warnings()`, `to_dict()` / `from_dict()` — the latter never raises on well-formed JSON of the wrong shape) |

---

## 5. Core Pipeline & Boundaries (`app/core/`)

AWS-agnostic. `pipeline.py`, `stages.py`, and `findings_io.py` must not import boto3; only `S3ArtifactStore` / `DynamoJobStore` may.

### 5.1 `pipeline.py` — single source of truth
| Symbol | Kind | Description |
|---|---|---|
| `PipelineError(message, warnings=None)` | Exception | User-safe message for UI / CLI; `warnings` carries the per-file lines collected before the failure |
| `ParseResult` | dataclass | `findings`, `warnings`, `source_file_count` (results files read, less copies of one scan), `coverage` (set of `(server, stig_title)` scanned, built before the actionable filter), `enrichment` (`EnrichmentReport`) |
| `parse_stage(results_paths, reference_paths, extract_dir, *, cancel_check=None, allow_empty=False, progress_cb=None)` | fn | `classify_inputs` → load supplied references into a `ReferenceLibrary` (benchmarks; checklists, each also giving a title-only `Benchmark` that can name a scan) → parse results (XCCDF with its embedded benchmarks; `.cklb`/`.nessus`) → match → read one scan supplied twice once (`_one_per_scan`) → feed embedded STIG text to the library → filter → `enrich_findings` → warnings (matcher issues, enrichment, library, files reporting the same rules of one host). Raises `PipelineError` when nothing can be reported. No single bad input raises out of it |
| `compute_summary(findings, source_file_count)` | fn | `{files, hosts, findings, cat1, cat2, cat3}` |
| `export_stage(findings, output_path, *, enrichment=None, warnings=None)` | fn | Delegates to `ExcelExporter`; *enrichment* adds the Reference sources table; *warnings* (the run's, from `ParseResult.warnings` or the Lambda job record) become the Summary's "Warnings from this run" block (at most 200, then a count) |
| `default_output_name()` | fn | `stig_findings_<UTC timestamp>.xlsx` |
| `export_delta_stage(delta, output_path)` / `default_delta_output_name()` | fn | Delta workbook counterparts |

### 5.2 `inputs.py` — content routing
`classify_inputs(results_paths, reference_paths, extract_dir, *, cancel_check=None, display_names=None) -> ClassifiedInputs(xccdf_results, self_contained, reference_xml, reference_cklb, warnings, names, supply_order, results_from_references)` (the last: scan results that came in the reference slot, so the 0-rule-results advice fits the slot) — the only entry to ZIP handling. A ZIP is a folder: each member is routed as the same file would be loose in the ZIP's slot. A benchmark among the results becomes a reference, results among the references become results; a `.cklb` keeps its slot. Nothing is parsed here: a root-element sniff (first 64 KiB) recognises results (`TestResult` root), legacy `.ckl` (named as unsupported) and SCAP support files (named once when loose, silent in a ZIP); a file with no element in its first 64 KiB is named and not read; otherwise `parse_cost.start_tags` (a `TestResult` / `Benchmark` start tag in the bytes) decides results or benchmark. Files are de-duplicated by resolved path, then SHA-256 (`identical to … — read once`), in the same pass that measures their parse cost (`parse_cost.measure`); a file over `MAX_FILE_ELEMENTS` or with a crowded start tag, or past the run's `MAX_RUN_ELEMENTS`, is named and not routed (five per reason named, the rest counted). `name_of(path)` is the display name: base name (for a loose file saved under another name, the operator's own from *display_names*, through `normalize.display_file_name`: NFC, control characters removed, at most 255 characters), `{zip}/{path inside it}` on a collision, ` (2)` when still equal, cut from the left when long. `parse_stage(..., display_names=None)` passes the map through.

### 5.3 `uploads.py` / `app/limits.py`
`ALLOWED_UPLOAD_EXT = {.xml, .zip, .cklb, .nessus}`, `reject_filename`, `reject_size`, `is_safe_name` — the one allow-list, used by Flask and the API Lambda. `MAX_UPLOAD_BYTES` (200 MB) lives in `app/limits.py` so the archive reader can share it.

### 5.4 `stages.py` — async stage entrypoints
`run_parse_stage(job_id, input_filenames, store, jobs, *, work_dir, input_store=None, reference_filenames=None) -> bool` — downloads the inputs, splits them by *reference_filenames* (the names `POST /uploads` recorded as STIG references: the reference slot; the rest are results), runs `parse_stage`, writes `findings.json` and `enrichment.json`, and records at most 200 warnings of at most 500 characters and 200,000 bytes in all, counted as stored (JSON-escaped) (`_bounded_warnings`, success and failure alike — one DynamoDB item). Removes *work_dir* on every exit.
`run_export_stage(job_id, store, jobs, *, work_dir) -> bool` — reads `findings.json` and, when the job record says the parse stage stored it (`enrichment_stored`, set in the same update that records the parse), `enrichment.json` — never asking S3 whether the key exists, which the exporter role cannot list (403, not 404); a job parsed before the flag existed exports without the Reference sources table, writes and uploads `report.xlsx`, then removes the workbook from *work_dir*.
Both take an `ArtifactStore` + `JobStore` and never raise (errors captured into the job record). `_is_safe_name(name)` rejects path-traversal filenames. Keys: `INPUT_PREFIX`, `FINDINGS_KEY`, `ENRICHMENT_KEY`, `REPORT_KEY`.

### 5.5 `artifact_store.py` — blob boundary
`ArtifactStore` Protocol (`put_bytes`/`get_bytes`/`exists`/`size`/`upload_from`/`download_to(key, path, *, max_bytes=None)`/`presign_get`/`presign_put`). With *max_bytes*, `download_to` reads no more than that (S3: a ranged GET of `max_bytes + 1`), removes the partial file and raises `ObjectTooLarge`; `run_parse_stage` passes `MAX_UPLOAD_BYTES` and turns it into the same `File too large` job error as the size check.
- `LocalArtifactStore(root)` — filesystem; `_resolve` rejects keys escaping root; presign returns `file://` URI.
- `S3ArtifactStore(bucket, region, client=None)` — the only boto3-touching blob member; real presigned URLs.

### 5.6 `job_store.py` — job-status boundary
`JobStore` Protocol (`create`/`update`/`get`/`delete`, guarded `transition` / `update_if_status`).
- `MemoryJobStore` — thread-safe dict; backs tests and local stage runs.
- `DynamoJobStore(table_name, region, client=None)` — single item per `job_id`.

### 5.7 `findings_io.py`
`findings_to_json(findings) -> str` / `findings_from_json(data) -> list[Finding]` — `asdict`-based; unknown keys ignored for forward/backward compatibility.

### 5.8 `app/lambdas/` — Lambda handler shims (GovCloud)
- `api.py` — `GET /config` (AI gate, upload limits), `POST /uploads` (filenames → presigned PUT URLs; optional `referenceFilenames`, names from `filenames`, recorded as `reference_filenames`; duplicate names refused; the names may total at most 32,000 bytes as stored, `_MAX_FILENAME_BYTES`), `POST /jobs` (Step Functions start; `_execution_input` carries `inputFilenames`, `referenceFilenames`, `aiEnabled`), `GET /jobs/{id}`, `GET /jobs/{id}/result`, `POST /jobs/{id}/cancel`.
- `parser.py` → `run_parse_stage` (passes `referenceFilenames`); `exporter.py` → `run_export_stage`; `enricher.py` (AI enrichment shell); `mark_error.py` (Catch target); `common.py` (environment wiring).

---

## 6. Exporters (`app/exporters/excel_exporter.py`)

**Class:** `ExcelExporter.export(findings, output_path, *, enrichment=None) -> Path` — raises `ValueError` on empty list. Builds `Findings` + `Summary` sheets.
- `_write_findings_sheet(ws, rows, cols, fills)` — shared by `export` and `export_delta`: header row, data rows, fills, freeze `A2`, auto-filter, measured column widths.
- `_write_summary(ws, findings, enrichment, warnings)` — Findings by Severity, by Server (one row per host and IP), by STIG (`(no STIG title)` row for untitled findings), each count table with CAT I/II/III, Total and **No severity** (`""` or `Unknown`, included in Total) so it sums to the Findings sheet; then, when a reference was supplied, **Reference sources** (`_SOURCES_HEADERS`: File, STIG, Edition, Release, Embedded in results, Rules loaded, Check text filled, Fix text filled, From a different release, Severity filled; one row per `enrichment.sources` entry, counts via `source_key`) and three totals (not found / several matches / other STIG title); then **Warnings from this run** (`_write_warnings`, also the delta's Warnings block: each line sanitised, at most 200 then a count; absent when there are none); then the italic footer note.
- **COUNTIFS:** rows grouped as COUNTIFS compares text (`_excel_upper`, `_Tally`); each criterion is `=` + the stored text, with the documented `~` escape before each `*` and `?` when the text holds one. A value holding a `~` gets no criterion (Excel 16 en-US was observed reading `~` as an escape only beside a wildcard, which is undocumented; the observations pin the test evaluator), and nor does a value COUNTIFS would coerce (`_excel_would_coerce`: no letters unless an IP address, TRUE/FALSE, error literals, month-name and year-first dates, AM/PM, exponents) or a criterion over 255 characters gets a fixed count, and the footer says so. The footer always notes that counts follow English-language Excel's matching rules.
- **Cell defence (`_sanitize_cell`, every cell of every sheet):** characters a workbook refuses and lone surrogates → U+FFFD; a leading `= + - @ | \t \r` (`_FORMULA_PREFIXES`) gets an apostrophe; cut to 32,767 UTF-16 units ending `… [truncated by STIG Condenser]`; a literal `_xHHHH_` stored as `_x005F_xHHHH_`. `_as_text` keeps every string that is not the exporter's own formula as text, so a host or title spelled like an error code (`#N/A`) is not written as an error cell. `_formula_quote` escapes `"` in formula literals.

**Findings columns (`_FINDINGS_COLS`):** A STIG Title(50) · B Vuln ID(12) · C Rule ID(40) · D Severity(10) · E Status(14) · F Server(30) · G IP Address(18) · H Check Text(80, wrap) · I Fix Text(80, wrap) · J STIG ID(18) · K Text Source(60, wrap). New columns are only ever appended, so the Summary's COUNTIFS letters (A, D, E, F, G) are unchanged.
**Severity fills:** CAT I `#FFCCCC` · CAT II `#FFEB9C` · CAT III `#C6EFCE`. Fonts: Arial 10 (bold header).

**`export_delta(delta: DeltaResult, output_path) -> Path`** — delta workbook counterpart. Unlike `export`, an all-one-bucket result (every finding New, or every finding Resolved) is valid; only a delta with no findings *and* no host-coverage data raises `ValueError`.
- **Findings** sheet (`_DELTA_COLS`): Delta(12) · STIG Title(50) · Vuln ID(12) · Rule ID(40) · Severity(10) · Baseline Status(16) · Current Status(16) · Server(30) · IP Address(18) · Check Text(80, wrap) · Fix Text(80, wrap) · STIG ID(18) · Text Source(60, wrap). Delta column color-coded via `_DELTA_FILL`.
- **Summary** sheet (`_write_delta_summary`): Delta Summary table (every `DELTA_STATUSES` entry × CAT I/II/III + Total, via COUNTIFS/COUNTIF) · Coverage block from `coverage_gaps` (hosts compared, then pairs not re-scanned, newly scanned, and that cannot be verified as re-scanned — one row per pair, host in col B, STIG in col C, both sanitised) · Warnings block (only present when `delta.warnings` is non-empty) · italic footer note: Resolved requires the same host and STIG in the current scan.

---

## 7. Utils (`app/utils/`)

### 7.1 `scanner_detect.py`
`detect_scanner(path, name=None, *, tree=None) -> str` (*tree*: the file already parsed, shared with the results and benchmark parsers) → `SCC` / `OpenSCAP` / `Nessus` / `Evaluate-STIG` / `Unknown`.
Precedence: Nessus namespaces → SCAP source namespace (SCC) → `test-system="…scc…"` on `<TestResult>` → generator-text signature match → root `id` contains `evaluate-stig`.
Helpers: `_collect_namespaces`, `_extract_generator_text`. Constants: `_SCANNER_SIGNATURES`, `_NAMESPACE_HINTS`, `_SCC_NAMESPACE`.

### 7.2 `parse_cost.py`
`measure(path, *, kind) -> ParseCost(digest, elements, crowded_tag) | None` — one streaming pass: SHA-256 plus, for `kind="xml"`, element starts (every `<` not opening an end tag, comment, CDATA, DOCTYPE or PI) plus every `=` (attributes are charged), and whether a start tag holds more than `MAX_TAG_ATTRIBUTES = 64` attributes (quote-aware, possessive regex over the memory-mapped file: a `>` in a value does not end the tag); for `"json"`, `{` + `[` + `,`. `too_costly(cost)` (over `MAX_FILE_ELEMENTS = 4,000,000` or crowded), `run_element_budget()` (`MAX_RUN_ELEMENTS = 100,000,000`), `start_tags(path, names)` (over the memory-mapped file; comments, CDATA, processing instructions and a DOCTYPE are stepped over, and an unclosed one ends the search). Comments, CDATA, PIs and DOCTYPE count as nodes too. The XCCDF results path parses each file once (`benchmark_parser.load_xml`) and hands the tree to `XCCDFResultsParser.read(..., tree=)`, `detect_scanner(..., tree=)` and `BenchmarkParser.read_all(..., tree=)`.

### 7.3 `zip_extract.py`
`extract_from_zip(zip_path, dest_dir, *, name=None, run=None, cancel_check=None) -> Extraction(members, skipped, skipped_more, too_deep, unreadable, legacy_checklists, other_archives, limit, not_read)` — extracts every XML member (except SCAP support content and legacy `.ckl`), `.cklb` and `.nessus` member under a generated file name (`ExtractedMember(path, name, path_in_archive)`), recursing into nested ZIPs up to `_MAX_ZIP_DEPTH = 2`; other archive formats are listed, not opened. Never raises on a bad archive (`NOT_A_ZIP`, `PASSWORD_PROTECTED`).
**Limits:** a member at most `MAX_UPLOAD_BYTES` (measured while decompressing); per supplied archive `_MAX_MEMBERS = 5000` and `_MAX_ARCHIVE_BYTES = 2 GiB`; per run `run_budget()` = 20,000 members and 8 GiB; a central directory over `_MAX_ENTRIES = 100,000` records or 16,000,000 bytes is refused before any entry object is built (`_GuardedFile`); the 64 KiB root sniff (`sniff_root`) is charged to the budgets. Helpers `is_support_name`, `is_support_root`; constants `LEGACY_CHECKLIST_ROOT`, `LEGACY_CHECKLIST_SUFFIX`.

---

## 8. Web Application (`app/web.py`)

### 8.1 Factory
`create_app(secret_key=None) -> Flask` — sets secret (env `FLASK_SECRET_KEY`, else ephemeral + warning), `MAX_CONTENT_LENGTH = 500 MB`, strict security headers (CSP without inline script or style), sweeps orphaned jobs on startup.

### 8.2 HTTP routes
| Method | Path | Handler | Returns |
|---|---|---|---|
| GET | `/` | `index()` | Renders `index.html` with `existing_job_id` from session |
| GET | `/readme` | `readme()` | `README.md` as `text/plain`; 404 if not bundled |
| POST | `/api/process` | `process()` | `{job_id, status}` 200 · `{error}` 400 · `{error}` 429 (rate-limited). Form fields `results` and `benchmarks` (the STIG References zone) |
| GET | `/api/status/<job_id>` | `job_status()` | `{status, progress, warnings, error, summary}`; 404 unless session owns the job |
| POST | `/api/cancel/<job_id>` | `cancel()` | `{status: "cancelling"}`; sets `cancelled` flag |
| GET | `/api/download/<job_id>` | `download()` | `.xlsx` attachment; deletes job dir on response close; 400 unless complete |

**Ownership check:** status/cancel/download all require `session["job_id"] == job_id` (404 otherwise) — a client can only touch its own job.
**Upload saving:** every upload is validated (`uploads.reject_filename` / `reject_size`) before any job dir exists, then saved in a numbered folder of its own, so two uploads with one name are both read. `_saved_name(filename, fallback_stem)` keeps `secure_filename`'s name when it keeps the extension, else `upload.<ext>` / `reference.<ext>` (the extension routes ZIPs, checklists and Nessus scans). The name on disk is never shown: `_run_job(..., display_names=)` passes `{saved path: uploaded name}` to `parse_stage`, so warnings, Text Source and the Reference-sources table name each file as it was uploaded.

### 8.3 Rate limiting
`_rate_limited(client_ip)` — in-process sliding window, `_RATE_MAX=10` per `_RATE_WINDOW=60s`, per IP (`_rate_hits`). Caps unauthenticated job spam; not a WAF replacement.

### 8.4 Background processing
`_run_job(job_id, results_paths, reference_paths)` — threaded: `parse_stage` (with cancel check and per-file progress) → `export_stage(…, enrichment=result.enrichment, warnings=result.warnings)` → `compute_summary`; `result.warnings` join the job's through `_WarningCollector.add_new` (each once, within the 200-line cap), as a `PipelineError`'s do; removes the extraction dir right after parsing; catches `PipelineError` (user-safe; its warnings join the job's, each once, within the cap) vs generic `Exception` (logs traceback, returns "see server logs").
Cancellation: `_JobCancelled` exception + `_raise_if_cancelled(job_id)`; cancelled jobs drop files but keep the status entry.
State helpers: `_set_job`, `_get_job`, `_job_dir`. Log capture: `_WarningCollector(logging.Handler)` funnels WARNING+ from `app.*` into the job's `warnings` — only records of its own worker thread (fails closed without a thread id), the message only (never a traceback), at most 200 lines plus one "… and N more warnings not shown" line.

### 8.5 Module state & cleanup
`_jobs` / `_jobs_lock`, `_TEMP_DIR` (`$STIG_TEMP_DIR` or `<repo>/tmp`), `_ORPHAN_MAX_AGE_HOURS=8`. `_delete_job`, `_purge_job_files`, `_sweep_orphaned_jobs` (startup dir sweep; never a running job's dir), `_start_orphan_sweeper` (periodic, from `__main__` only).

---

## 9. CLI (`app/cli.py`)

`main(argv=None) -> int` — 0 success / 1 error. Two subcommands via `argparse` subparsers, `dest="command"`:

- `report` — single-run findings report. Routes through `app.core.pipeline` (`parse_stage` → `export_stage(…, enrichment=)`). Args: `--results` (required; `.xml`/`.cklb`/`.nessus`/`.zip`, files, globs, directories not walked recursively) · `--references` (alias `--benchmarks`, `dest="references"`; `.xml`/`.zip`/`.cklb`; directories walked recursively, so a folder of STIGs is a library) · `--output` (default `stig_findings_<timestamp>.xlsx`) · `--verbose`. Prints one enrichment line per STIG (filled check / fix, different release, not found, several matches, other STIG title; at most 50).
- `delta` — diffs a baseline scan set against a current one. Runs `parse_stage` on each side with the same references (`allow_empty=True`), then `app.processors.delta.compute_delta` with both sides' `ParseResult.coverage`, then `ExcelExporter.export_delta`; drains `delta.warnings` to the log and prints a summary line counting all five statuses. Args: `--baseline` / `--current` (both required, same formats as `report --results`) · `--references` (alias `--benchmarks`, applied to both sides) · `--output` (default `stig_delta_<timestamp>.xlsx`) · `--verbose`.

**Back-compat:** `_normalize_argv()` prepends `report` when the first token isn't a known subcommand or `-h`/`--help`, so the historical flat invocation `stig-parser --results ...` still works.

Helpers: `_resolve_paths(args, extensions, *, recursive=False)` (dir/glob expansion; suffixes in any case), `_files_in` (symlinked directories followed once by `(st_dev, st_ino)` or resolved path; unreadable directories warned, five named; dangling links kept), `_build_parser()`, `_normalize_argv(argv)`, `_utf8(stream)`. Every printed warning and error passes `normalize.escape_controls`. Console script: `stig-parser = app.cli:main`.

---

## 10. UI — Template (`app/templates/index.html`)

Single-page app. Sections show/hide via the `hidden` attribute — **no true modals**.

| Section | Visible when | Contents |
|---|---|---|
| `<header>` | always | `h1` + `.subtitle` (add the Manual STIG as a reference for check text; SCC results carry fix text only) |
| `#app` `<main>` | always | wraps everything; `<noscript>` CLI fallback note |
| `#upload-section` | initial / after reset | upload form |
| `#progress-section` | job running | activity log, cancel, warnings |
| `#result-section` | complete or error | success or error card |
| `<footer>` | always | supported-scanner line + `/readme` link |

**Upload section:** `<form id="upload-form">` › `.upload-grid` with two `.upload-zone`s:
- `#results-zone` (required) — inline SVG icon, "Scan Results", accepts `.xml,.zip,.cklb,.nessus` ("A ZIP is read as a folder."); `#results-browse` button, hidden `#results-input`, `#results-zone-notice` (drop-reject `role=status`), `ul#results-file-list`.
- `#benchmarks-zone` (optional) — `<h2>` "STIG References" with `.badge-optional` "Optional"; copy: Manual STIG ZIPs add check text; accepts `.xml,.zip,.cklb`; parallel browse/input/notice/list ids (form field `benchmarks`).
- `.form-actions` › `#process-btn` (disabled until results selected; `#process-hint` explains why).

**Progress section:** `h2` "Processing" · `#activity-log` (`role=log`, `aria-live=polite`, timestamped lines) · `#stall-note` (revealed after ~20 silent polls) · `.progress-actions` › `#cancel-btn` · `#warnings-box` (lead + `ul#warnings-list`).

**Result section:**
- `#result-success` (`role=status`) — drawn-check SVG, "Report Ready", `dl#report-summary` ("Result files read" `#sum-files`, `#sum-hosts`, `#sum-findings`, `#sum-cat1`/`-cat2`/`-cat3`), `#summary-note` (zero-severity warning), `#download-link`, `#reset-btn`, `#success-warnings-box` + `#success-warnings-list`.
- `#result-error` (`role=alert`) — ✕ SVG, "Processing Failed", `#error-message`, `#error-warnings-box` + `#error-warnings-list`, `#reset-btn-error`.

### 10.1 JavaScript (`app/static/app.js`, IIFE)
State: `pollTimer`, `currentJobId` (seeded from the `data-job-id` attribute — strict CSP, no inline JS), `lastWarnings`, `lastSummary`, `pollFailures`, `lastProgressMsg`, `unchangedPolls`.

| Function | Purpose |
|---|---|
| `removeFileAt` / `updateFileList` | Rebuild `FileList` via `DataTransfer`; render rows with remove buttons |
| `showZoneNotice` | Show/hide per-zone drop-reject message |
| `setupZone(zone, input, listEl, browseBtn, noticeEl, allowedExts)` | Wire browse/click/drag-drop; drop filters by extension (results `.xml/.zip/.cklb/.nessus`, references `.xml/.zip/.cklb`), counts skipped |
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

The GovCloud SPA (`frontend/src/App.tsx`) mirrors the two zones; `useJob.submit(files, ai, referenceNames)` sends the reference zone's names through `api.createUploads(filenames, referenceFilenames)`.

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

## 12. Test Suite (`tests/`) — 1,204 functions / 33 files

| File | # | Focus |
|---|---|---|
| `test_reference_pipeline.py` | 126 | End-to-end through `parse_stage`: routing, references, enrichment, copies and overlaps, every operator warning |
| `test_cli.py` | 83 | Arg parsing, `--references` / `--benchmarks`, recursive reference folders, directory rules, delta, escaping |
| `test_excel_exporter.py` | 81 | Sheet structure, columns J/K, Summary tables, COUNTIFS criteria and fixed counts, Reference sources, cell sanitising |
| `test_enrich.py` | 79 | `enrich_findings`: fills, guards, refusals, counts, warnings, JSON round trip |
| `test_inputs.py` | 79 | `classify_inputs`: content routing, ZIPs as folders, display names, de-duplication, limits |
| `test_delta.py` | 69 | Delta statuses, coverage, `coverage_gaps`, STIG ID / Text Source on rows |
| `test_zip_extract.py` | 68 | Extraction, nesting, budgets, central-directory guard, bad archives |
| `test_matcher.py` | 62 | Each scan read against its own benchmark, issues, coverage pairs, fingerprints |
| `test_lambda_handlers.py` | 60 | Handler shims, API routes, upload allow-list, reference hint, AI gate, cancel |
| `test_web.py` | 55 | Routes, validation, zones, reference flow, each warning shown once, collector, cleanup |
| `test_cklb_parser.py` | 49 | CKLB parsing, severity overrides, hostile JSON, counts |
| `test_reference_library.py` | 48 | Indexes, lookup guards, ranking, caps, embedded de-duplication |
| `test_benchmark_parser.py` | 47 | XCCDF 1.1 + 1.2, nested groups, data streams, STIG ID, release, duplicate rules |
| `test_xccdf_parser.py` | 44 | SCC/OpenSCAP/Nessus/Evaluate-STIG fixtures, status codes, edge cases, multi-TestResult, `.ckl` rejection |
| `test_normalize.py` | 36 | Identifier normalisation, release labels, product key, bounds, escaping |
| `test_stages.py` | 29 | Async stages, reference hint, `enrichment.json`, bounded warnings, work-directory cleanup |
| `test_pipeline.py` | 25 | `parse_stage` routing, self-contained formats, PipelineError messages, summary |
| `test_cklb_reference_loader.py` | 21 | A checklist as a reference: non-text values, malformed entries, unreadable files |
| `test_nessus_parser.py` | 19 | `.nessus` compliance parsing, reference tokens, host metadata, vuln-scan warning |
| `test_parser_hardening.py` | 17 | XXE / billion-laughs / SSRF protections across parsers |
| `test_text_source.py` | 17 | Text Source phrases |
| `test_reference_bounds.py` | 14 | Uploaded text is bounded before it reaches a cell, a warning or the report |
| `test_parse_cost.py` | 13 | Pre-parse cost scan: element and value counts, crowded tags, start tags, the per-file, run and reference budgets |
| `test_job_store_dynamo.py` | 10 | Dynamo store via moto |
| `test_job_store_memory.py` | 10 | Memory store CRUD, guarded transitions, thread safety |
| `test_reference_pins.py` | 10 | Behaviour only these tests pin |
| `test_artifact_store_s3.py` | 8 | S3 store via moto |
| `test_filter.py` | 7 | Kept vs discarded statuses |
| `test_artifact_store_local.py` | 6 | Local blob round-trip, traversal rejection |
| `test_findings_io.py` | 5 | JSON round-trip, unknown-key tolerance |
| `test_core_import.py` | 3 | `app.core` imports stay boto3-free where required |
| `test_reference_fixtures.py` | 3 | The reference fixtures keep the real-world shapes |
| `test_oval_parser.py` | 1 | Stub raises `NotImplementedError` |

**Fixtures (`tests/fixtures/`):** see §1 — all fabricated, no real scan data.

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

- `README.md` — scanners, output reference (Text Source, Summary, Reference sources), install (pip/Docker), Web+CLI usage (`report` and `delta` subcommands, `--references`, back-compat flat form), pipeline overview, STIG references, uploads and archives, spreadsheet applications, contributing, roadmap and follow-ups, MIT.
- `RESIDUALS.md` — residual-risk / known-limitations notes.
- `docs/superpowers/specs/2026-07-07-govcloud-replatform-design.md` — GovCloud/Bedrock/React/Terraform re-platform spec (motivates the `app/core/` boundaries + `stages.py`).
- `docs/superpowers/plans/2026-07-07-backend-async-rearchitecture.md` — async rearchitecture plan.
- `docs/superpowers/specs/2026-07-20-delta-reporting-design.md` — delta reporting design (locked decisions: baseline-vs-current model, coverage-scoped Resolved, `delta` subcommand).
- `docs/superpowers/plans/2026-07-20-delta-reporting.md` — delta reporting implementation plan.
- `docs/superpowers/specs/2026-09-26-reference-enrichment-and-ansible-remediation-design.md` — STIG reference enrichment design.
- `docs/superpowers/plans/2026-10-01-reference-enrichment-pr-a.md` — reference enrichment (check text) implementation plan, with the amendments made during execution.
- `LICENSE` — MIT.

---

## 16. Data Flow Summary

```
┌──────────────┐     ┌───────────────┐     ┌──────────────────────┐
│ Upload form  │     │ CLI invocation│     │ Lambda parse stage   │
│ (web.py)     │     │ (cli.py)      │     │ (stages.py)          │
└──────┬───────┘     └──────┬────────┘     └──────────┬───────────┘
       └────────────────────┼─────────────────────────┘
                            ▼
              app.core.pipeline.parse_stage(results, references)
                            │
                  classify_inputs (route by content; ZIPs as folders)
                            │
        ┌───────────────────┼───────────────────────────┐
        ▼                   ▼                           ▼
  supplied references   XCCDF results               .cklb / .nessus
  (benchmarks,          XCCDFResultsParser          self-contained
   checklists)          + embedded benchmarks       → Finding[]
        │                   │                           │
        │           match_results_by_scan               │
        │           (each scan vs its own benchmark)    │
        │                   └─────────────┬─────────────┘
        │                     one scan supplied twice → read once
        ▼                                 ▼
  ReferenceLibrary ◄── embedded STIG text of results files
        │                                 ▼
        │                          filter_findings
        └──────────────► enrich_findings → EnrichmentReport
                                          ▼
                 list[Finding] ── compute_summary ──► {files,hosts,cat1..3}
                                          ▼
                 export_stage(findings, enrichment) → ExcelExporter
                                          ▼
                         Findings + Summary (+ Reference sources) .xlsx

Async variant (stages.py, Lambda):
  run_parse_stage → ArtifactStore(findings.json, enrichment.json) → run_export_stage → report.xlsx
  status via JobStore (Memory locally, Dynamo in GovCloud)
```

---

*Updated for STIG reference enrichment (reference library, content routing, Text Source, Reference sources). Section 11 predates the current stylesheet and fonts.*
