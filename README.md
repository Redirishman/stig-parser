# STIG Compliance Parser

A Python tool that ingests compliance scan results from multiple scanning tools — XCCDF results, Evaluate-STIG / STIG Viewer CKLB checklists, and Nessus compliance scans — fills blank check and fix text from STIG references (the Manual STIG, a SCAP benchmark, or a checklist), and produces a consolidated Excel workbook of actionable findings in which every row says where its text came from. Includes a Flask web UI for interactive use and a CLI for scripted or headless workflows.

---

## Supported Scanners

| Scanner | Format | Status | Notes |
|---|---|---|---|
| DISA SCC (SCAP Compliance Checker) | XCCDF `.xml` | ✅ Tested | Result files embed the scanned SCAP benchmark: fix text, severity and V-ID come from the scan. **Check text is not in SCC output — add the Manual STIG as a reference.** |
| OpenSCAP | XCCDF `.xml` | ✅ Tested | A results file that does not embed its benchmark carries no STIG title, severity or rule text — add the STIG as a reference (Manual XCCDF or DISA STIG ZIP). Remediation-style outputs (two `<TestResult>` elements) report the post-remediation state |
| Evaluate-STIG / STIG Viewer 3 | `.cklb` (JSON) | ✅ Validated against real checklists | **Self-contained** — severity, check, and fix text are inline. Honors severity overrides and multi-STIG checklists. Supplied as a reference instead (the **STIG References** zone, or `--references`), a checklist fills blanks in other scans and is not counted as a scan |
| Nessus / ACAS compliance scans | `.nessus` | ✅ Validated against real Tenable exports | **Self-contained** — DISA `.audit` scans map Vuln-ID/Rule-ID/STIG-ID/CAT from the compliance references |

For XCCDF files, scanner type is auto-detected from XML namespace declarations, the `test-system` attribute on `<TestResult>`, and generator metadata — no manual tagging required. Legacy `.ckl` checklists (STIG Viewer 2) are not supported — export as `.cklb` from STIG Viewer 3.

---

## Output

The tool generates an Excel workbook (`stig_findings_YYYYMMDD_HHMMSS.xlsx`) with two sheets:

**Findings** — One row per actionable finding:

| Column | Description |
|---|---|
| STIG Title | Benchmark name, from the scan or, when the scan names none, from a reference |
| Vuln ID | V-number (e.g. V-254239) |
| Rule ID | Full XCCDF rule ID |
| Severity | CAT I / CAT II / CAT III; blank or `Unknown` when neither the scan nor a reference gives one |
| Status | Open / Not Reviewed / Error / Unknown |
| Server | Target hostname |
| IP Address | Target IP address |
| Check Text | From the scan, or filled from a STIG reference |
| Fix Text | From the scan, or filled from a STIG reference |
| STIG ID | STIG rule identifier, e.g. WN22-00-000010 |
| Text Source | Where the row's check and fix text came from: scanner, the reference file and release, or "no reference supplied" |

**Text Source** reads `Check and fix: <source>` when both fields have one source, otherwise `Check: <source> | Fix: <source>`. A source is one of:

| Source | Meaning |
|---|---|
| `scanner` | The scan carried the text. Text a scan carried is never overwritten. |
| `<file> <release>` | Filled from that reference file and STIG release, e.g. `U_Example_STIG_V2R2_Manual-xccdf.xml V2R2`. |
| `…, scanned <release>` | The reference's revision of the rule differs from the one scanned, and the scan was of release `<release>` (e.g. `V2R1`). Compare the text before relying on it. |
| `…, revision differs from scan` | The reference's revision of the rule differs from the one scanned; the scanned release is unknown or the same. |
| `…, matched by V-ID` | The reference rule was found by its V-ID, not by rule ID or DISA rule number. |
| `…, matched by STIG ID` | The reference rule was found by its STIG ID, in a STIG for the same product. |
| `no reference supplied` | The field is blank and no reference was supplied. |
| `not in supplied references` | References were supplied and none holds this rule (see [Known limits](#known-limits) for the cases this includes). |
| `in <file> <release>, which has no check text` | A supplied reference holds this rule but has no check text for it (`… no fix text` for the fix field). SCAP benchmarks carry fix text only; add the Manual STIG. |
| `V-ID matches several rules, not filled` | The V-ID names more than one rule in the supplied references, and nothing else identifies the rule. |
| `STIG ID matches several STIGs, not filled` | The STIG ID names rules of more than one STIG, and the row's STIG title cannot tell which. |
| `STIG ID found under a different STIG title, not filled` | The STIG ID exists only in a reference for another product. |

Every cell is written as text, whatever the upload held: a value that starts like a formula (`=`, `+`, `-`, `@`, `|`, tab, carriage return) gets a leading apostrophe; a value spelled like an Excel error (`#N/A`, `#REF!`, `#DIV/0!` …) stays text, not an error cell; a character a workbook cannot store becomes `�` (U+FFFD); a value longer than Excel's 32,767-character cell limit is cut and ends `… [truncated by STIG Condenser]`.

**Summary** — Rollup tables with `COUNTIFS` formulas that update when rows are added or deleted from the Findings sheet:

- **Findings by Severity** — CAT I / II / III by status.
- **Findings by Server** — one row per host and IP address (one host reported with two IP addresses is two rows).
- **Findings by STIG** — one row per STIG title, and a `(no STIG title)` row when any finding is untitled.

The by-Server and by-STIG tables count CAT I, CAT II, CAT III, Total, and **No severity** (blank or `Unknown`, included in Total), so each sums to the Findings sheet. Rows group values the way `COUNTIFS` compares them (letter case ignored), and each formula matches its own row's cells. Where `COUNTIFS` would read a host, IP address or title as a number, date, time, `TRUE`/`FALSE` or an error value, where one holds a `~` (Excel's reading of `~` in a criterion is undocumented), or where one is longer than a `COUNTIFS` criterion allows (255 characters), the cell holds a fixed count computed when the workbook was written, and the footer says so. The footer also notes that counts follow English-language Excel's matching rules: in another language a host or STIG named like a date or `TRUE`/`FALSE` may be counted differently.

When a reference is supplied the Summary sheet adds a **Reference sources** table: each file, its edition and release, how many rows it filled, and how many came from a different release than the one scanned. One row per source the run loaded — supplied references, and the benchmarks embedded in results files (`Embedded in results`: yes) — with the columns File, STIG, Edition (`manual`, `scap` or `cklb`), Release, Embedded in results, Rules loaded, Check text filled, Fix text filled, From a different release, Severity filled (rows whose blank or `Unknown` severity it filled). Three totals follow: **Not found in any supplied reference**, **Matches more than one rule or STIG — not filled**, and **STIG ID found under a different STIG title — not filled**.

When the run had warnings (files not read, limits reached, copies read once, files not counted), the Summary sheet lists them under **Warnings from this run** — at most 200, then `… and N more warnings not shown` — so the workbook alone says what the run could not read or count. A run without warnings has no such block.

> **Note:** Summary counts use `COUNTIFS` and reflect all data in the Findings sheet. Applying auto-filter on the Findings sheet does **not** update Summary counts — this is a known Excel limitation for cross-sheet formula references. Fixed counts do not change when rows are edited.

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

Open `http://localhost:5000`. Add scan results in **Scan Results**. To fill check text, add the Manual STIG — the DISA STIG ZIP, the Manual XCCDF, or a checklist made from it — in **STIG References** (optional). A ZIP in either zone is read as a folder. Click **Process**, then download the Excel report.

Warnings stay on the result card: each names a file, STIG or host and what was skipped or left blank. **Result files read** counts the results files the run read — including one with 0 rule results, and not a copy of one scan whose rows were not repeated (see [Uploads and archives](#uploads-and-archives)).

### GovCloud SPA

A React frontend for the private GovCloud deployment lives in `frontend/`. The
Flask UI above still works and is the recommended way to run the tool locally or
air-gapped — it needs no AWS account and no Node toolchain.

The SPA has the same two zones. It sends one list of files to the API and names
the files from **STIG References** in a `referenceFilenames` hint, so a
checklist there is read as a reference rather than as a scan. Two files with one
name are refused on this path; rename one. The names of one upload may add up to
at most 32,000 bytes (a job record is one database item); upload more files in a
second run. A job keeps at most 200 warnings and 200,000 bytes of them; a last
line says how many more there were.

### CLI

The CLI has two subcommands: `report` (single-run findings) and `delta`
(compare two scan sets). The historical flat form — `stig-parser --results
...` with no subcommand — still works and routes to `report`, so existing
scripts are unaffected.

#### `report` — single-run findings report

```bash
# SCC results alone: fix text, severity and V-ID come from the scan; check text is blank
python -m app.cli report --results ./scc-results/ --output findings.xlsx

# Add the Manual STIGs to fill check text (a folder of STIGs is read recursively)
python -m app.cli report --results ./scc-results/ --references ./stigs/ --output findings.xlsx

# Individual files and DISA STIG ZIPs
python -m app.cli report --results scan1.xml scan2.xml --references U_Example_STIG_V2R2_Manual-xccdf.xml stig2.zip

# Glob patterns (Windows-safe — expanded internally)
python -m app.cli report --results "scans/*.xml" --references "stigs/*.zip" --verbose

# Default output filename (stig_findings_<timestamp>.xlsx)
python -m app.cli report --results ./results/ --references ./stigs/

# Flat form (no subcommand) — still supported, routes to `report`
python -m app.cli --results ./scc-results/ --output findings.xlsx
```

**Arguments:**

| Argument | Description |
|---|---|
| `--results` | Results file(s), directory, or glob pattern — `.xml`, `.cklb`, `.nessus`, or a `.zip` of them (**required**). A directory is not scanned recursively. |
| `--references` | STIG references that fill blank check/fix text: Manual STIG XML, DISA STIG ZIP, SCAP benchmark, or `.cklb` checklist — file(s), directory, or glob pattern. A directory is scanned recursively, so one folder of STIGs works as a library. `--benchmarks` remains an alias. |
| `--output` | Output Excel path (default: `stig_findings_<timestamp>.xlsx`) |
| `--verbose` | Enable detailed logging |

Directory rules: suffixes match in any letter case; a symlinked directory is followed and each directory is read once, so a link loop ends; a directory that cannot be read is named in a warning (five by name, then a count); a dangling link is kept, so the run names it ("Could not read file") rather than skipping it.

After the warnings, `report` prints one line per STIG (at most 50):
`<STIG> — check text filled: N, fix text filled: N, severity filled: N, from a different release: N, not in a supplied reference: N, several matches: N, other STIG title: N`.
Each problem is printed once, as the run's own warning with its reason. Every warning and error the CLI prints escapes control characters (C0 and C1 controls, DEL, line and paragraph separators, bidi controls), and its log output is UTF-8.

#### `delta` — compare two scan sets

Diffs a baseline scan set against a current one to show what changed between
runs — new, resolved and persisting findings — and which host/STIG pairs were
not re-scanned, so a missing scan can never be mistaken for remediation.

```bash
# Compare a baseline directory against a current one
python -m app.cli delta --baseline ./scans-baseline/ --current ./scans-current/

# Individual files, with references applied to both sides
python -m app.cli delta --baseline old1.xml old2.xml --current new1.xml new2.xml \
    --references ./stigs/ --output delta.xlsx

# Glob patterns
python -m app.cli delta --baseline "baseline/*.xml" --current "current/*.xml"
```

**Arguments:**

| Argument | Description |
|---|---|
| `--baseline` | Older scan results — file(s), directory, or glob pattern; same formats as `report --results` (**required**) |
| `--current` | Newer scan results — file(s), directory, or glob pattern; same formats as `report --results` (**required**) |
| `--references` | STIG references, applied to **both** scan sets, so a rule is filled and titled alike in each (see `report --references`; `--benchmarks` remains an alias). |
| `--output` | Output Excel path (default: `stig_delta_<timestamp>.xlsx`) |
| `--verbose` | Enable detailed logging |

The output workbook's **Findings** sheet carries a leading **Delta** column
tagging every row with one of five statuses, plus separate `Baseline Status`
and `Current Status` columns; like the report, each row also carries its
`STIG ID` and `Text Source`:

| Delta | Meaning |
|---|---|
| `New` | Absent from the baseline, present in the current scan of the same host and STIG. |
| `Resolved` | Present in the baseline, absent from the current scan of the **same host and STIG** — the pair was re-scanned and the finding is gone. |
| `Persisting` | Present in both. `Baseline Status` / `Current Status` show a within-actionable flip (e.g. Not Reviewed → Open). |
| `Not re-scanned` | Baseline finding whose host/STIG pair has no scan in the current set. Never counted as resolved. |
| `Newly scanned` | Current finding whose host/STIG pair has no scan in the baseline set. Never counted as new. |

The **Summary** sheet counts every status by severity and adds a **Coverage**
block: hosts compared, then every host/STIG pair not re-scanned, every pair
newly scanned, and every pair that cannot be verified as re-scanned (a run
scanned the host with no STIG title), one row each. Every coverage warning is
written to the Summary sheet as well as the terminal.

Findings lists only ever contain actionable results — passing rules never
appear — so `Resolved` is *inferred* from a finding's absence in the current
scan, not proven from a passing re-check. To keep that inference honest, the
tool records which host/STIG pairs each scan set actually covered (taken from
the scan files themselves, before the actionable filter), and **`Resolved`
requires the same host and STIG in the current set**. Forgetting to re-scan a
host, or leaving one STIG out of a re-scan, shows up as `Not re-scanned` and
can't look like remediation; a fully remediated host still shows every
baseline finding as `Resolved`. STIG titles are matched edition-neutrally, so
the SCAP and Manual editions of one STIG (or successive `.audit` revisions)
count as the same STIG.

Findings are matched across runs by Vuln ID (V-XXXXXX) where available,
falling back to the Rule ID stem (namespace prefix and `rNNNNNN` revision
stripped; a blank Rule ID is never matched) — Vuln ID is stable across DISA
benchmark revisions where Rule ID is not. If a rule found in both runs has a
Vuln ID in only one of them, the tool warns that Resolved/New counts on those
hosts may be unreliable. A scan that could not be matched to a benchmark has
no STIG title (unless a reference titled every one of its open findings, when
it covers those titles), so its findings cannot be verified as re-scanned: they are
tagged `Not re-scanned` / `Newly scanned` rather than `Resolved` / `New`, and
the tool warns and says how to give the scan its benchmark (an SCC results
file that embeds it, or the matching benchmark as a reference). A results file
with no rule results at all is never counted as a scan and is named in a
warning. Every warning appears both in the terminal and in the workbook's
Summary sheet.

---

## How It Works

1. **Route by content** — each upload, and each member of a ZIP (a ZIP is read as a folder), is classified by its document element and extension: XCCDF results, benchmarks (Manual XCCDF, SCAP benchmark, SCAP data stream), `.cklb` checklists, and `.nessus` scans. A benchmark among the results is used as a reference, and results among the references are read as results; a `.cklb` is a scan unless it was supplied as a reference. A file supplied twice is read once
2. **Load references** — every supplied benchmark and checklist goes into one reference library, with the benchmark embedded in each SCC results file and the STIG text of each results checklist
3. **Auto-detect scanner** (XCCDF) — inspects XML namespaces, the `test-system` attribute, and generator metadata
4. **Parse results** — extracts hostname, IP, benchmark reference, and all rule results from each XCCDF file; `.cklb` and `.nessus` files parse directly to findings
5. **Match** — reads each XCCDF results file against the benchmark embedded in it: rule data (V-ID, severity, check and fix text, STIG ID) comes from that benchmark only. A supplied reference with the same benchmark ID gives the scan its STIG title and nothing else
6. **Filter** — retains only Open, Not Reviewed, Error, and Unknown findings; discards Pass, Not Applicable, etc.
7. **Enrich** — fills each finding's blank check text, fix text, severity, V-ID, STIG ID and STIG title from the reference library, records the source in **Text Source**, and reports every gap as a warning
8. **Export** — generates a formatted Excel workbook with COUNTIFS formulas in the Summary sheet

---

## STIG references

### What to supply

- **For check text, the Manual STIG:** the DISA STIG ZIP for the product (it holds the `*_Manual-xccdf.xml`), or that XCCDF file itself. STIGs are published at [https://public.cyber.mil/stigs/downloads/](https://public.cyber.mil/stigs/downloads/).
- A STIG Viewer 3 checklist (`.cklb`) made from the Manual STIG works too.
- SCAP Benchmark ZIPs and SCAP data streams carry fix text, severity and V-IDs, but no check text.
- A ZIP may hold any number of these, including nested ZIPs (see [Uploads and archives](#uploads-and-archives)). With the CLI, one folder of STIGs works as a library: `--references ./stigs/` reads every subfolder.

### What is filled

Each actionable finding's blank check text, fix text, severity, V-ID, STIG ID and STIG title. A value the scan carried is never overwritten — supplying a reference never discards what a scan, or the benchmark embedded in it, holds. The STIG text inside results files (an SCC file's embedded benchmark, a results checklist) is used the same way, so it can fill blanks in another scan; **Text Source** then names that file.

### How a rule is matched

1. By rule ID (`SV-254239r958472_rule`; XCCDF 1.2 prefixes ignored) or by DISA rule number (`SV-254239`, the rule ID without its revision);
2. then by V-ID (`V-254239`);
3. then by STIG ID (`WN22-00-000010`).

Of several candidates, the one with the scanned revision is preferred, then a supplied reference over text embedded in results, then the release that was scanned, then the newest release. A candidate is refused rather than used when it could be a different rule:

- A candidate whose DISA rule number differs from the finding's is not used, even when its V-ID or STIG ID agrees.
- A V-ID that names more than one DISA rule (or more than one non-DISA rule) is not used; an exact rule ID or rule number match still is. With nothing else to go on: **V-ID matches several rules, not filled**.
- A STIG ID is used only when the reference's STIG title names the same product as the finding's STIG title; for an untitled finding, only when one product carries that STIG ID. Otherwise: **STIG ID matches several STIGs, not filled**, or **STIG ID found under a different STIG title, not filled**.

When the rule used has a different revision from the scanned one, **Text Source** says so: `, scanned VxRy` (the release that was scanned) or `, revision differs from scan` (the scanned release is unknown or the same).

### Routing

Files are routed by content, so a reference among the results, or results among the references, is still read correctly. The one exception is a `.cklb`: among the results it is a scan; among the references it is a reference. A ZIP is read as a folder: each member is routed as the same file would be loose in the ZIP's zone.

### What the run reports

Each gap is one warning per STIG, shown on the web UI's result card, printed by the CLI, and counted in the workbook:

- `<STIG>: N finding(s) across M rule(s) not found in any supplied reference: <IDs>`
- `<STIG>: none of N finding(s) that need text matched a supplied reference (loaded: …) — wrong product or STIG?`
- `<STIG>: N finding(s) took check/fix text from a different release (reference VxRy, scanned VxRy) — see the Text Source column`
- `<STIG>: N finding(s) match more than one rule or STIG and were not filled — supply the scan's own benchmark or only the matching STIG`
- `<STIG>: N finding(s) carry a STIG ID found only under a different STIG title (<titles>) and were not filled — if this is the right STIG, supply the scan's own benchmark or a checklist`
- `<STIG>: N finding(s) have neither check nor fix text — add the STIG as a reference`
- `Check text is blank for N finding(s) in K STIG(s): <STIGs>. SCC results and SCAP Benchmark files carry fix text but no check text — add the Manual STIG (DISA STIG ZIP or *_Manual-xccdf.xml) as a reference to fill it.`
- `Fix text is blank for N finding(s) in K STIG(s): <STIGs>.`
- `<file>: no matching STIG benchmark — N finding(s) have no STIG title, severity, or check/fix text. Add the STIG as a reference.`

A reference that could not be used is named too: `Could not parse benchmark: <file> — <why>`, `<file>: reference contains 0 rules — ignored`, `Could not parse reference checklist: <file> — <why>`, `<file>: reference checklist contains 0 rules — ignored`, and `<file>: 0 of N rules carry check text` (a checklist made from a SCAP benchmark).

A file that could not be read says why in the same line, on every surface: `Could not parse results file: <file> — invalid XML: <parser message with line and column>`, `— not valid JSON: <message>`, `— not a Nessus export (root element is <x>, expected <NessusClientData_v2>)`, `— not a CKLB checklist (no 'stigs' array)`, `— no Benchmark element`; an archive member, `<zip>: could not read <member>: <error> — skipped`. Messages never carry a server path.

### Known limits

- **Renumbered rules.** A scan made before DISA renumbered a STIG's rules (around 2020: old `SV-`/`V-` numbers) is not filled from a current reference, even when the STIG ID is the same; its rows read `not in supplied references`. Supply the release that was scanned.
- **Benchmark IDs that differ.** A results file with no benchmark of its own (OpenSCAP, Evaluate-STIG XCCDF) is titled by a reference only when their benchmark IDs are equal. When they differ (e.g. `Microsoft_Windows_11_STIG` in the scan, `MS_Windows_11_STIG` in the Manual STIG), only the rows whose rule matched get the STIG title, and in a delta that scan's coverage may not be verifiable.

---

## Uploads and archives

- **Accepted uploads:** `.xml`, `.zip`, `.cklb` and `.nessus`, at most 200 MB each. The web UI accepts at most 500 MB per request. On the AWS path the cap is checked before a file is read and again on the bytes read, so a file replaced after its upload is refused all the same (`File too large: …`).
- **What is read from a ZIP:** XML, `.cklb`, `.nessus` and nested ZIP members. Other archive formats inside a ZIP (`.7z`, `.rar`, `.tar`, `.gz`, `.tgz`, `.bz2`, `.xz`) are named as not read; other extensions are ignored without mention. A legacy `.ckl` checklist, loose or zipped, is named as not supported. SCAP support files (OVAL, CPE, OCIL, stylesheets) are not used: loose ones are named in one line, those inside a ZIP are not mentioned.
- **A file with no XML element in its first 64 KiB** is not read, and is named.
- **How a file is recognised:** nothing is parsed to decide what a file is. An XML file is results when its document element is `TestResult` or a `TestResult` start tag occurs in it, a STIG reference when a `Benchmark` does, otherwise it keeps the zone it came in (inside a ZIP it is named as not recognised). A tag inside a comment, CDATA section, processing instruction or DOCTYPE does not count. A damaged file is sent where its tags say, and the parser that reads it names it as not parsed. Each file is parsed once. A file with a `TestResult` but no rule results is named: `<file>: 0 rule results — not counted as a scan; if this file is a benchmark, pass it as a reference`, or, when it was supplied as a reference, `<file>: supplied as a STIG reference, but it holds a TestResult, so it was read as scan results — 0 rule results, not counted as a scan`.
- **Parse limits:** before a file is parsed, its elements and attributes (XML) or values (`.cklb` JSON) are counted from its bytes. A file holding more than 4,000,000 together, or an XML element with more than 64 attributes (counted as the XML parser reads them, quoted values included), is not read: `<file>: too many elements to parse safely — not read` / `<file>: an element has too many attributes to parse safely — not read`. All the files of one run may hold 100,000,000 together; once a file does not fit, it and every later file are not read: `<file>: not read — the parse limit for one run was reached; any scan results or STIG references in it are missing from this report`. Five files are named per run for each reason; the rest are counted (`… and N more …`).
- **Reference limits:** one run reads at most 2 GiB of STIG reference files (benchmarks and checklists supplied as references); once one does not fit, it and every later reference are not read: `<file>: not read — the limit on STIG reference content for one run was reached; any rules in it are missing from this report`. One run holds at most 250,000 reference rules, every source together (a library of every DISA STIG holds about 100,000); the first file past the limit is named, and its remaining rules and every later reference's are not loaded: `<file>: the limit of 250,000 STIG reference rules for one run was reached — …`. A checklist rule with no rule ID, V-ID or STIG ID can never be matched and is counted with the malformed entries (`<file>: N malformed checklist entries were skipped`).
- **Archive limits:** a member may be no larger than a loose upload (200 MB); one supplied archive extracts at most 5,000 members and 2 GiB, nested ZIPs included; one run extracts at most 20,000 members and 8 GiB; ZIPs nest at most two deep; an encrypted (password-protected) archive is not read; an archive whose entry list holds more than 100,000 entries, or is over 16,000,000 bytes, is not read. A disk that fills while an archive is extracted ends it as the size limit does. Each limit reached is named with what was not checked.
- **Names:** a file is named by its own name — the web UI saves each upload under a safe file name and still reports it under the name it was uploaded with (Unicode-normalised, control characters removed, at most 255 characters); an archive member by its base name when no other file of the run has it, otherwise `<zip>/<path inside it>`; ` (2)`, ` (3)` follow a name that is still not unique; a long name is cut from the left (`…`) so the file's own name remains.
- **The same file twice** (by content: in both zones, under two names, loose and inside a ZIP) is read once: `<b>: identical to <a> — read once`. Inside one archive, five copies of a file are named and the rest counted: `<zip>: … and N more identical to <a> — read once`.
- **One scan in two files** (SCC's XCCDF results and ARF report, Evaluate-STIG's XCCDF results and checklist) is read once when both report the same host and the same results: `<b>: same host and results as <a> — its rows are not repeated`. The copy whose rows carry the most check and fix text is kept; the others' STIG text can still fill blanks the kept copy left. A `.nessus` scan and another scanner's are never taken for copies, and a file with no open finding has nothing to compare and is never merged.
- **Files that disagree about one host** — not copies, but reporting some of the same rules — are all read, and the host is named: `<host>: N rule(s) appear in more than one of M files (…) — each file's rows are in the report, so totals count those rules more than once`.

---

## Spreadsheet applications

The workbook is an `.xlsx` file. Summary counts are `COUNTIFS` formulas where Excel's matching rules compare a cell's text exactly, and fixed counts, computed when the workbook is written, where they would not (see the Summary description under [Output](#output)); totals are `SUM` formulas. Formatting uses fills, fonts, wrapped text, merged cells, a frozen header row and an auto-filter.

Summary counts were checked in Microsoft Excel 16 (English-US): a workbook of hostile host names and STIG titles was recalculated and every count compared with an independent recount. LibreOffice Calc has not been re-checked since the Summary formulas changed; it should open the workbook, but treat its counts as unverified.

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
- **Local STIG Library** — maintain a local cache of STIG benchmarks so users don't need to supply references on every run (the CLI already reads a folder of STIGs recursively)
- **CKL Export** — generate STIG Viewer `.ckl` checklist files from parsed results
- **Delta Reporting in the Web UI** — the CLI `delta` subcommand ships today (see [CLI](#cli)); a web UI equivalent is a follow-up
- **REST API** — JSON endpoint for integration with CI/CD pipelines

Known follow-ups:

- **Host identity across formats** — a short host name and its FQDN are two hosts today, in the report and in a delta.
- **Delta and untitled rules** — a rule untitled in both runs can never be `Resolved` (it fails toward `Not re-scanned`); keying a benchmark-less scan's coverage by its benchmark ID would fix it.
- **Duplicate upload names on the GovCloud path** — two files with one name are refused; keeping both needs a new storage key layout and an SPA change.

---

## License

MIT — see [LICENSE](LICENSE).
