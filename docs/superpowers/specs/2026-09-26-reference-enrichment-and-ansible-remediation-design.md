# Reference Enrichment and Ansible Remediation — Design

**Date:** 2026-09-26
**Status:** Approved 2026-09-27 — brainstormed, self-reviewed (§12), and every decision confirmed with the maintainer (§13). Implementation plans live under `docs/superpowers/plans/`.
**Related:** [GovCloud re-platform master spec](2026-07-07-govcloud-replatform-design.md) (surfaces, stage contract, §4.1 AI rules); Bedrock enrichment spec `2026-07-14-bedrock-enrichment-design.md` on branch `docs/bedrock-enrichment-spec` (receives the AI-drafted Ansible follow-up, §9); Delta reporting spec `2026-07-20-delta-reporting-design.md` on branch `feat/delta-reporting` (lands before this work, §8)
**Branch:** created from `master` after the hardening PR and `feat/delta-reporting` have merged (§8)

---

## 1. Problem

Two operator complaints, one root cause.

### 1.1 "The report has fix text but no check text"

SCC results embed the DISA *SCAP Benchmark* edition of each STIG. That edition carries `<fixtext>` but no human-readable `<check-content>`: every check is an OVAL `<check-content-ref>`. Measured on a real SCC session (the maintainer's own scan data, verified locally and never committed), run through the pipeline as it then was: in every STIG's embedded SCAP benchmark, every rule carried fix text and none carried inline check text, so every finding in the report had fix text and none had check text. The run showed the operator no warning.

Check text exists only in the DISA *Manual STIG* (or a STIG Viewer CKLB built from it). Uploading a Manual STIG does not repair the report today, because the matcher does an exact string lookup on rule IDs and the two editions spell the same rule differently:

| DISA file (real) | Rules | Inline `<check-content>` | `<fixtext>` | Rule ID form | Benchmark id |
|---|---|---|---|---|---|
| `U_MS_Windows_11_V2R8_STIG_SCAP_1-3_Benchmark.xml` (SCAP 1.3 datastream) | 223 | 0 | 223 | `xccdf_mil.disa.stig_rule_SV-253254r991589_rule` | `xccdf_mil.disa.stig_benchmark_Microsoft_Windows_11_STIG` |
| `U_MS_Windows_Server_2022_STIG_V2R8_Manual-xccdf.xml` (XCCDF 1.1) | 282 | 282 | 282 | `SV-254239r1153440_rule` | `MS_Windows_Server_2022_STIG` |

Scan results use the long XCCDF 1.2 form. The Manual STIG uses the short form, and the `rNNNNNN` revision suffix drifts between STIG releases (`r945408` in the V1R4-era fixtures, `r1153440` in V2R8). Measured defects in today's code:

1. `BenchmarkParser` yields 0 rules for a SCAP datastream (root is `data-stream-collection`, not `Benchmark`), and `zip_extract` never extracts one, because the member name ends in `_Benchmark.xml`, not `xccdf.xml`.
2. `match_results_to_benchmarks` looks up `benchmark.rules.get(rr.rule_id)`. The repo's SCC fixture plus the real Server 2022 V2R8 Manual STIG produced 5 findings with 0 check text, 0 fix text, 0 V-IDs, and 0 severities.
3. That mismatch is reported **only to the server log** (`5 rule(s) not found in benchmark 'MS_Windows_Server_2022_STIG'`). `ParseResult.warnings`, which every UI renders, was empty.
4. **Supplying any benchmark destroys SCC data.** It switches off the "results files are their own benchmark" path in `parse_stage`. Measured on the same session: alone, every finding had fix text, severity, and V-ID; with one uploaded Manual STIG, no finding had any of the three, again with no warning. (Measured with a Manual STIG for a different product; a matching-product Manual STIG loses the same data through defect 2.) The current web UI invites exactly this upload.
5. CKLB and Nessus findings never pass through the matcher, so no upload can enrich them.
6. Every XCCDF test fixture spells rule IDs in the long form on both sides, which real DISA Manual STIGs do not, and the SCC fixture embeds no benchmark, which real SCC output does. That is why the suite caught none of 2–4.

### 1.2 "Give the remediator Ansible"

Facts verified while writing this design, for the Windows workstation STIGs it targets:

- DISA's Supplemental Automation Content page publishes Ansible for RHEL 8/9, Ubuntu 20.04/22.04/24.04, Oracle Linux 8/9, SLES 15, Windows Server 2022 (V1R1, 2023), and three network devices. It publishes nothing for the Windows 11, browser, Defender Antivirus, Windows Firewall, or .NET Framework STIGs.
- The community `ansible-lockdown` project publishes STIG roles including `Windows-10/11/2016/2019/2022/2025-STIG` and `WinFWADV-STIG` (Windows Firewall, last updated 2022). It has nothing for browsers, Defender Antivirus, or .NET.
- For about half of the open findings in the maintainer's own scan data, DISA's own OVAL check is a simple registry-value test (eligibility rules in §4.10). All of those are `HKEY_LOCAL_MACHINE` values of type `reg_dword` or `reg_sz`; example: V-253284 / WN11-00-000150, "Structured Exception Handling Overwrite Protection (SEHOP) must be enabled", whose OVAL check requires `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel` value `DisableExceptionChainValidation` to equal `0`.

| STIG | Community Ansible role |
|---|---|
| Windows 11 | `Windows-11-STIG` |
| Edge | none |
| Defender Antivirus | none |
| Chrome | none |
| Firefox | none |
| Windows Firewall | `WinFWADV-STIG` (2022) |
| .NET Framework 4.0 | none |

Uploaded playbooks alone could cover at most the Windows 11 and Firewall rows; generated registry tasks close a large share of the rest.

---

## 2. Goals and non-goals

**Goals**

- **G1.** When the operator supplies a matching Manual STIG (XCCDF or DISA ZIP) or a CKLB built from one, every finding from every input format gets check text, fix text, severity, V-ID, STIG ID, and STIG title filled wherever the scanner left them blank. Every row states where its check and fix text came from.
- **G2.** Each Open finding shows a remediation task from, in fixed order of precedence: (1) an uploaded playbook, (2) a registry task generated from DISA's own OVAL check, otherwise (3) the words "No automated fix". Each host gets a runnable, self-contained remediation bundle.
- **G3.** All three surfaces: CLI, Flask, GovCloud SPA + Lambda.
- **G4.** Fail loud. Every partial outcome is stated in the warnings the operator sees *and* on the face of the artifact. No mismatch is reported only to a server log, and no remediation step can succeed while doing nothing.

**Non-goals (deliberately cut)**

- AI-drafted remediation. It becomes the fourth, GovCloud-only step of the precedence order in the Bedrock enrichment spec (§9).
- A standing STIG library. Manual STIGs are uploaded per run; CLI users get reuse by pointing `--references` at one folder. The library stays on the roadmap.
- Overwriting scanner-supplied text with reference text.
- Re-emitting extracted tasks from uploaded roles as standalone playbooks. The bundle runs whole roles with narrowed selection (D7).
- Executing anything from an upload, and running any remediation from this tool.
- Playbooks for Not Reviewed, Error, or Unknown findings. They show their task in the workbook but are never run (D14).
- Linux-specific work for now. The design is platform-neutral and the ComplianceAsCode dialect is supported by the same code, but nothing Linux-specific is live-verified. Red Hat scap-security-guide (SSG) results, whose rule IDs (`xccdf_org.ssgproject.content_rule_…`) carry no DISA identifier, are deferred until a real SSG scan exists.
- Generated fixes for checks that are not simple registry values: audit policy, user rights, security policy, WMI, file permissions, certificate stores. Uploaded roles cover those.
- CKL export, delta of remediation, Terraform changes.

---

## 3. Decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | Remediation comes from **three sources in fixed precedence**: uploaded playbooks, then tasks generated from DISA OVAL registry checks, then (GovCloud only, §9) AI drafts. The tool vendors no remediation content. | Uploaded content is DISA- or maintainer-authored and wins. Generated tasks are deterministic and offline and fill most of the gap. AI is last and never local. No licensing or supply-chain exposure on a public MIT repo. |
| D2 | **Post-parse enrichment stage** over `Finding` objects, not an extension of the matcher. | Covers CKLB and Nessus findings, which bypass the matcher. Pure functions, unit-testable without I/O. |
| D3 | Uploads are **classified by content**. The upload slot is only a hint, used to mark a CKLB as reference-only. | The SPA sends one flat file list and `run_parse_stage` passes `[]` for benchmarks, so today a Manual STIG uploaded through the SPA is fed to the results parser and yields a spurious "0 rule-result" warning. Content routing makes every surface behave the same. |
| D4 | Every lookup uses **three keys**: V-ID, SV rule stem with revision stripped, and STIG ID (`WN11-00-000150`). | Revision drift breaks exact rule IDs; ComplianceAsCode roles carry only the STIG ID; Nessus carries `STIG-ID` and `Vuln-ID` tokens. |
| D5 | Enrichment **fills blanks only**, each field from the best candidate that has it. Text taken from a different release than the one scanned is filled and counted as drift. | Scanner text is what was evaluated. The operator sees drift per row (D12) and in totals. |
| D6 | `stig_id` becomes a **first-class `Finding` field** and a workbook column. | The stable join key across DISA XCCDF, CKLB, Nessus, and every Ansible dialect; remediators search by it. |
| D7 | The bundle **copies an uploaded role verbatim** and narrows it by setting the role's **own per-rule toggle variables**: every toggle off, matched ones on. Tag selection is a fallback only. | Verified: `ansible-lockdown/Windows-2022-STIG` defines one toggle per rule (`wn22_00_000030: true`, in `defaults/main/main.yml`); RedHatOfficial's RHEL 9 role defines about 390 (`DISA_STIG_RHEL_09_651010: true`). Toggles run the whole role, prelim facts and handlers included, which `--tags` does not guarantee. |
| D8 | Three workbook columns are **appended after Fix Text and always present**: J `STIG ID`, K `Text Source`, L `Ansible Task`. | Existing column letters and every Summary `COUNTIFS` stay put; downstream consumers see a fixed schema. |
| D9 | The remediation bundle is a **separate artifact** (`bundle.zip`); the workbook download is unchanged. | Operators who never supply remediation content see no change. The bundle can fail without touching the report. |
| D10 | The upload allow-list stays in `app/core/uploads.py` and gains `.yml`/`.yaml` there only. | One definition for Flask and Lambda. |
| D11 | A **deterministic OVAL registry generator** turns eligible DISA OVAL checks into `ansible.windows.win_regedit` tasks, under conservative rules (§4.10). It ships as its own PR after the upload path. | On the maintainer's own scan data it covers a large share of the findings that have no Ansible anywhere. It writes exactly the value DISA's own check tests for, with no model involved. |
| D12 | A **`Text Source` column on every row** names the file and release the check and fix text came from, and says when the reference's revision of the rule differs from the one scanned (naming the scanned release when it is known and differs). A reference of another release whose rule revision is the scanned one is the same text: nothing is added. | Accreditation reviewers read rows in isolation; totals in a Summary table do not travel with a copied row. |
| D13 | The bundle ships a **generated inventory** keyed by the scan's short host name, connecting to the scan's FQDN, and every host play starts with a **preflight guard** that fails when the host is missing from the inventory. | Ansible reports success when a play matches no hosts. Kerberos needs a host name, not an IP; the maintainer's scan lists three addresses per host. |
| D14 | Playbooks change **Open findings only**. | Change only what a scan proved non-compliant; never overwrite an unevaluated or deliberately deviated setting. |
| D15 | Manual STIGs are **uploaded per run**. | Stateless; fits the delete-after-download rule; a CLI folder gives reuse for free. |
| D16 | Real scan data is used **locally only**. CI gets a **scrubbed fixture** that keeps SCC's real structure and DISA's public text, with every host identifier faked; the maintainer reviews it before it is committed. | The repo is public. The fabricated SCC fixture is the gap that hid defects 2–4. |

---

## 4. Architecture

```
uploads ──► classify (§4.1) ──┬─ results ────► XCCDF / CKLB / Nessus parsers ──► matcher ──► filter ─┐
                              ├─ references ─► ReferenceLibrary + OvalIndex (§4.2)                  │
                              └─ playbooks ──► RemediationIndex (§4.5)                               ▼
                                                              actionable findings ──► enrich (§4.3) ──► attach (§4.6, §4.10)
                                                                                                             │
                     report.xlsx ◄── ExcelExporter (§4.7) ◄──────────────────────────────────────────────────┤
                     bundle.zip  ◄── write_bundle (§4.6) ◄── RemediationPlan ◄───────────────────────────────┘
```

New packages, pure Python, no boto3, no Flask:

- `app/reference/` — `models.py` (`ReferenceRule`, `ReferenceSource`), `normalize.py`, `xccdf_loader.py`, `cklb_loader.py`, `library.py`, `enrich.py`, `text_source.py`
- `app/remediation/` — `yaml_loader.py`, `index.py`, `attach.py`, `emit.py`, `bundle.py`, `oval_index.py`, `oval_generate.py`
- `app/core/inputs.py` — the classifier

Changed: `app/utils/zip_extract.py`, `app/parsers/base.py`, the three result parsers (new fields), `app/processors/matcher.py` (warnings returned, scanned release recorded), `app/core/pipeline.py`, `app/core/stages.py`, `app/core/findings_io.py` (unchanged code, new fields flow through), `app/exporters/excel_exporter.py`, `app/cli.py`, `app/web.py` + template + `app/static/app.js`, `app/lambdas/api.py`, `app/lambdas/exporter.py`, `frontend/src/` (types, api, ResultCard, App), `app/core/uploads.py`, `pyproject.toml` (adds `pyyaml>=6.0.2,<7.0`), README. `feat/delta-reporting` will have merged first, so PR A also updates the delta code's `parse_stage` calls and adds the new fields to `DeltaFinding`.

### 4.1 Input classification — `app/core/inputs.py`

`classify_inputs(paths, extract_dir, *, reference_hint: set[str]) -> ClassifiedInputs` with `results`, `references`, `playbooks` (role trees and loose task files), `sha256` (per original upload), and `warnings`. `reference_hint` holds the names of files that arrived through the reference slot or flag. Rules, applied per file after ZIP expansion:

| Content | Class |
|---|---|
| XML containing a `TestResult` element anywhere | results. Any `Benchmark` embedded in it is also loaded into the reference library as an embedded source (§4.2). |
| XML whose root is `Benchmark`, with no `TestResult` | reference (Manual STIG) |
| SCAP `data-stream-collection` with one or more `Benchmark` components, no `TestResult` | reference: its XCCDF rules go to the library, its OVAL component to the `OvalIndex` (§4.10) |
| XML root `NessusClientData_v2` | results |
| JSON object with a `stigs` array (CKLB), name in `reference_hint` | reference only (standalone source) |
| CKLB, name not in `reference_hint` | results, and also an embedded reference source |
| YAML inside a role tree (a directory with a `tasks/` child) | part of that role; the whole tree is kept, including non-YAML files such as `templates/*.j2` and `files/*.ps1` |
| Loose `.yml` / `.yaml` that parses to a task list or a play | playbook (loose task file) |
| Loose YAML that is neither | warning `YAML file is not a task list or play — skipped: <name>` |
| Anything else | warning `Unrecognised file skipped: <name>` |

The SHA-256 of every original upload is computed before extraction and carried through for provenance (§4.6).

ZIP handling extends `zip_extract.py`: members are typed by the same rules (including `*_Benchmark.xml` datastreams), and role trees are extracted whole with relative paths preserved. Each path component is checked by the existing `_is_safe_name` logic; `..`, absolute paths, and drive letters are rejected with a warning. The bounded-size and nested-depth limits apply unchanged. DISA's wrapper-ZIP pattern is already handled and extends to Ansible ZIPs.

XML detection is namespace-agnostic and uses `lxml` with the same hardened options as today (`resolve_entities=False`, `no_network=True`, no DTD).

### 4.2 Reference library — `app/reference/`

```python
@dataclass
class ReferenceRule:
    vuln_id: str        # V-253284
    rule_id: str        # SV-253284r958928_rule  (prefix stripped, revision kept)
    rule_stem: str      # SV-253284
    revision: str       # r958928  ("" if absent)
    stig_id: str        # WN11-00-000150  (XCCDF <version> / CKLB rule_version)
    severity: str       # CAT I | CAT II | CAT III | ""
    stig_title: str
    check_text: str
    fix_text: str
    oval_def: str       # OVAL definition id from <check-content-ref name=…>, "" if none
    source: ReferenceSource

@dataclass
class ReferenceSource:
    file_name: str
    benchmark_id: str   # normalised, prefix stripped
    title: str
    version: str        # "V2R8" from <version> + <plain-text id="release-info">, or CKLB version/release_info
    embedded: bool      # True when lifted from a results file (SCC, results CKLB)
    edition: str        # "manual" | "scap" | "cklb"
    rule_count: int
```

**Loaders.** `xccdf_loader.load(path)` handles XCCDF 1.1, XCCDF 1.2, and SCAP 1.2/1.3 datastreams by iterating every `Benchmark` element regardless of depth or namespace, then every `Group`/`Rule` beneath it. `check_text` comes from `check/check-content`; a rule with only a `check-content-ref` keeps `check_text=""` and records `oval_def`. `cklb_loader.load(path)` maps `group_id`, `rule_id`, `rule_version`, `severity`, `check_content`, `fix_text`, and the STIG `display_name`/`version`/`release_info`.

**Normalisation** (`normalize.py`), each with table tests:

| Function | Input | Output |
|---|---|---|
| `strip_rule_prefix` | `xccdf_mil.disa.stig_rule_SV-254239r945408_rule` | `SV-254239r945408_rule` |
| `rule_stem` | `SV-254239r945408_rule` | `SV-254239` |
| `rule_revision` | `SV-254239r945408_rule` | `r945408` |
| `strip_group_prefix` | `xccdf_mil.disa.stig_group_V-254239` | `V-254239` |
| `norm_stig_id` | `disa_stig_rhel_09_651010`, `wn22_00_000030`, `WNFWA-000001` | `RHEL-09-651010`, `WN22-00-000030`, `WNFWA-000001` (uppercase, optional `DISA-STIG-` prefix removed, `_` → `-`) |
| `norm_benchmark_id` | `xccdf_mil.disa.stig_benchmark_MS_Windows_Server_2022_STIG` | `MS_Windows_Server_2022_STIG` |
| `release_label` | Manual XCCDF: `<version>2</version>` + release-info `Release: 8 Benchmark Date: 01 Apr 2026`; SCAP datastream and SCC-embedded: `<version>002.008</version>` + release-info `Benchmark Date: 01 Apr 2026` (verified on the real files) | `V2R8` for both |

`ReferenceLibrary` holds every loaded rule and four indexes: `by_rule_id`, `by_stem`, `by_vuln`, `by_stig_id`. Each maps to a list, because several sources can define the same rule.

**Change to `parse_stage` (fixes defect 4):** XCCDF results files are **always** also used as benchmark sources for the matcher, whether or not references were supplied. `_find_benchmark` already prefers an exact benchmark-id match, so an SCC scan keeps matching its own embedded benchmark even when a Manual STIG with a shorter id is present. The matcher records the matched benchmark's release on each finding (`scan_release`, §4.4).

### 4.3 Enrichment — `app/reference/enrich.py`

`enrich_findings(findings, library) -> EnrichmentReport`, mutating in place. It runs on actionable findings only (after the filter, §4.8), so every count matches a report row. Per finding:

1. **Build the candidate list.** Look up the finding under each key in order: exact `rule_id` (prefix-stripped), `rule_stem`, `vuln_id`, `stig_id`. Concatenate the hits, dropping duplicates. Within one key's hits, order is: same revision as the finding first, then standalone sources before embedded ones, then load order.
2. **Fill each blank field independently.** For each of `check_text`, `fix_text`, `severity`, `vuln_id`, `stig_id`, `stig_title` that is blank on the finding, take the value from the first candidate whose value is non-blank. A non-blank field is never touched. This lets SCC's embedded rule supply nothing for check text while a Manual STIG of a later release supplies it.
3. **Re-resolve once.** If step 2 filled `vuln_id` or `stig_id`, rebuild the candidate list with the new identifiers and repeat step 2 once for the fields still blank.
4. **Record provenance** for check and fix text (who supplied each, which file, which release) and build the `Text Source` cell (below).
5. **Count drift** for the finding's STIG when `check_text` or `fix_text` came from a candidate whose revision differs from the finding's own rule revision.
6. **Count unmatched** for the finding's STIG when the candidate list is empty.

**`Text Source` cell** (`text_source.py`), deterministic. For each of check and fix text the source phrase is one of:

| Situation | Phrase |
|---|---|
| Scanner supplied the text | `scanner` |
| Filled from a rule of the same revision as the one scanned (whatever its release) | `<file name> <release>` |
| Filled from a rule of a different revision | `<file name> <release>, scanned <scan_release>`; when `scan_release` is unknown or equals the reference's release, `<file name> <release>, revision differs from scan` |
| A supplied reference holds the rule, without this field's text | `in <file name> <release>, which has no check text` (or `fix`) |
| References supplied, none had it | `not in supplied references` |
| No reference supplied | `no reference supplied` |

"Supplied" means uploaded by the operator; benchmarks embedded in results files do not count. The cell is `Check: <phrase> | Fix: <phrase>`, or `Check and fix: <phrase>` when both are identical. Examples: `Check: U_MS_Windows_11_STIG_V2R9_Manual-xccdf.xml V2R9, scanned V2R8 | Fix: scanner` for an SCC row with a newer Manual STIG; `Check: no reference supplied | Fix: scanner` for an SCC row with none; `Check and fix: scanner` for a CKLB row.

`EnrichmentReport` carries, per STIG: `filled_check`, `filled_fix`, `filled_severity`, `drifted`, `unmatched`, the most common drift release pair, and the list of `ReferenceSource`s consulted. It serialises to `enrichment.json` for the Lambda path.

**Operator warnings** (one line per STIG, only when non-zero), added to `ParseResult.warnings` so every surface renders them. Message formats, with illustrative values:

- `Microsoft Windows 11 STIG: 12 rule(s) took check/fix text from a different release (reference V2R9, scanned V2R8) — see the Text Source column`
- `Microsoft Windows 11 STIG: 3 rule(s) not found in any supplied reference: SV-253300, SV-253301, SV-253302`
- A STIG with references supplied but zero rules matched warns with the scan's benchmark id and the titles and releases of every reference loaded, so a wrong-product upload is obvious.
- When only SCAP-edition references were supplied for a STIG and check text is still blank: `Microsoft Edge STIG: SCAP Benchmark files carry no check text — upload the Manual STIG to fill it`.

**Matcher warnings.** `match_results_to_benchmarks` returns its two existing warnings ("could not match to any benchmark", "N rule(s) not found in benchmark") alongside the findings, instead of only logging them. When enrichment later fills every blank for those rules, the matcher warning is dropped as resolved; otherwise it reaches the operator.

### 4.4 Model changes — `app/parsers/base.py`

```python
@dataclass
class Finding:
    ...existing nine fields...
    stig_id: str = ""        # NEW, column J — WN11-00-000150
    text_source: str = ""    # NEW, column K — §4.3
    ansible_task: str = ""   # NEW, column L — §4.6
    scan_release: str = ""   # NEW, internal — release of the benchmark that was scanned, e.g. V2R8
    fqdn: str = ""           # NEW, internal — host FQDN from the scan, for the bundle inventory
```

Defaults keep every existing positional constructor call valid. `findings_from_json` already ignores unknown keys, so old and new `findings.json` payloads load in either direction. Parsers populate the new fields where their source carries them:

| Field | XCCDF | CKLB | Nessus |
|---|---|---|---|
| `stig_id` | benchmark rule `<version>` | `rule_version` | `STIG-ID|…` token |
| `scan_release` | matched benchmark's release (matcher) | STIG `version` + `release_info` | blank |
| `fqdn` | `target-facts` `…:fqdn` | `target_data.fqdn` | `HostProperties` `host-fqdn` |

### 4.5 Remediation index for uploaded content — `app/remediation/index.py`

**YAML loading** (`yaml_loader.py`): `yaml.SafeLoader` subclassed with a multi-constructor for any unknown `!tag` (Ansible's `!vault`, `!unsafe`) that returns the node's scalar text. A file that fails to parse produces a per-file warning, never an exception out of the stage.

**Unit extraction.** A YAML document that is a list is a task list; a dict with any of `tasks`, `pre_tasks`, `post_tasks`, `handlers` is a play and each of those lists is walked. Within a list, each item is a task or a `block`. Recursion enters `block`, `rescue`, and `always`; tags and `when` clauses are the **union** of the item's own and every enclosing block's. Items whose only key is one of `include_tasks`, `import_tasks`, `include_role`, `import_role`, `include_vars`, `meta` are skipped (the included file is walked on its own). The **unit** is the smallest node that carries at least one recognised key: if a block carries the keys, the whole block is the unit (ansible-lockdown style); if only a task does, the task is.

**Key extraction** runs over the unit's `tags`, `name`, and `when` clauses (stringified):

| Pattern (case-insensitive) | Yields |
|---|---|
| `\bV-(\d{4,7})\b` | V-ID |
| `\b(SV-\d{4,7})(?:r\d+)?_rule\b` | rule stem, plus the full rule ID with revision when present |
| `\b(?!SRG[-_])(?:DISA[-_]STIG[-_])?([A-Z][A-Z0-9]{1,15})[-_]([A-Z0-9]{2,4})[-_](\d{6})\b` | STIG ID, normalised by `norm_stig_id`. The `SRG-` exclusion stops `SRG-OS-000480-GPOS-00227` tags from reading as STIG IDs. Every STIG with published Ansible content uses this three-part form. |
| `\bstigrule_(\d{4,7})\b` | V-ID (DISA's generated roles; see below) |

**Role defaults.** Toggles are read from `defaults/main.yml`, or from every YAML file under `defaults/main/` when that directory form is used (ansible-lockdown uses it). A **rule toggle** is a top-level key whose value is a boolean and whose name yields a STIG ID or V-ID under the patterns above (`wn22_00_000030`, `DISA_STIG_RHEL_09_651010`). Other booleans, such as `win22stig_cat1_controls`, `win22stig_disruption_high`, `low_complexity`, or `package_aide_installed`, are role switches and are never changed.

**Selector per unit.** `("var", name)` when a bare variable in the unit's `when` clauses is a rule toggle of its role. Otherwise `("tag", value)`, where `value` is the tag exactly as written in the role, preferring a V-ID tag, then SV, then STIG ID, then `DISA-STIG-…`, then `stigrule_…`. A unit with neither is indexed for the workbook cell but flagged `unselectable`.

**Dialects.** Verified: `ansible-lockdown` (block-level tags `V-254238`, `SV-254238r848530_rule`, `WN22-00-000010`; names `HIGH | WN22-00-000030 | AUDIT | …`; `when: wn22_00_000030 | bool`; toggles in `defaults/main/main.yml`) and ComplianceAsCode / RedHatOfficial roles (task tags `DISA-STIG-RHEL-09-651010`; `when: DISA_STIG_RHEL_09_651010 | bool`; toggles in `defaults/main.yml`). DISA's own cyber.mil Ansible content is reported to use `rhel9STIG_stigrule_257777_Manage` toggles; that dialect is supported only after a real DISA ZIP has been inspected at build time. Until then its files produce the unsupported-dialect warning rather than a guessed selection.

**Role detection.** A directory with a `tasks/` child is a role, named after the directory. Loose task files with no enclosing role are bundled under `tasks/` and imported by the generated play; their units are selected by tag only, and the README says so.

`RemediationIndex` exposes the same four lookups as the reference library, each returning every unit for the key in file order, plus `roles: list[RoleInfo]` (name, root path, SHA-256 of the upload it came from, file count, dialect, rule toggles found).

### 4.6 Attachment, emission, bundle — `attach.py`, `emit.py`, `bundle.py`

**Attachment** (`attach_remediation(findings, index, oval) -> RemediationReport`), for every actionable finding, applies the precedence of D1:

1. Uploaded units found by exact rule ID → stem → V-ID → STIG ID: the cell shows them.
2. Otherwise, an eligible OVAL registry check (§4.10): the cell shows the generated task.
3. Otherwise: `No automated fix available`.

Cell format for uploaded units, shown with the verified `ansible-lockdown/Windows-2022-STIG` layout:

```
# source: Windows-2022-STIG/tasks/Cat1/WN22-00-xxxxxx.yml | matched by V-ID | role r848530, scan r945408 | selected by wn22_00_000030
- name: 'HIGH | WN22-00-000030 | AUDIT | …'
  block:
  …verbatim yaml.safe_dump of the unit, sort_keys=False, width=1000…
```

The `# source:` line names the file, the key that matched, both revisions when known, and the selector. Several units are concatenated in file order, separated by a blank line. Cells are truncated at 32,000 characters with `…[truncated — see bundle.zip]`. Because every cell starts with `#` or `No`, the exporter's formula-prefix guard is never triggered. `RemediationReport` counts, per host: Open findings, from uploaded playbook, generated from DISA OVAL, matched across a revision difference, no automated fix.

**Plan** (`plan_bundle(findings, index, oval) -> RemediationPlan`): **Open findings only** (D14), grouped by `server`. Per host: the roles with the rule toggles to switch on, any tag-fallback selectors, the generated OVAL tasks for findings no uploaded unit covered, the FQDN, and the Open findings with no automated fix (V-ID, STIG ID, title). Hosts with nothing selectable get no play and are listed in the README.

**Bundle** (`write_bundle(plan, index, out_zip)`):

```
bundle.zip
├── README.md                    provenance, exact commands, per-host coverage, no-fix list
├── inventory.yml                one entry per host (below); connection settings left to the operator
├── <host>.yml                   preflight guard + remediation play (below)
├── <host>.tags                  only when a role needed tag fallback for this host
├── generated/<host>-oval.yml    generated registry tasks for this host, when any
├── roles/<name>/…               uploaded role(s), verbatim
└── tasks/…                      loose uploaded task files, when any
```

`inventory.yml`:

```yaml
all:
  hosts:
    SERVER01:
      ansible_host: server01.example.mil   # FQDN from the scan
  vars:
    # Connection settings are yours to set. The Windows STIG forbids WinRM Basic
    # authentication and unencrypted traffic, so use HTTPS with Kerberos:
    # ansible_connection: winrm
    # ansible_port: 5986
    # ansible_winrm_transport: kerberos
    # ansible_winrm_server_cert_validation: validate
```

When the scan carried no FQDN, `ansible_host` is omitted and a comment says to set it. Host names are quoted in YAML and sanitised for file names.

`<host>.yml` (illustrative host, counts, and toggles; toggle names follow the verified Windows-2022-STIG pattern):

```yaml
# Generated by STIG Condenser on 2026-09-26T18:04:11Z from stig_findings_20260926_180411.xlsx
# Host SERVER01 — Open findings: 42; from uploaded playbooks: 20; generated from DISA OVAL: 15; no automated fix: 7
# Run from this directory, with no --limit (it would skip the preflight guard):
#   ansible-playbook -i inventory.yml SERVER01.yml
- name: Preflight | SERVER01 must be in the inventory
  hosts: localhost
  gather_facts: false
  tasks:
    - name: Stop here if SERVER01 is missing, instead of silently matching no hosts
      ansible.builtin.assert:
        that: "'SERVER01' in groups['all']"
        fail_msg: "SERVER01 is not in the inventory. Without this check the remediation play would match no hosts and still report success."

- name: STIG remediation for SERVER01, Open findings only
  hosts: "SERVER01"
  vars:
    # Every rule toggle found in each role's defaults is set false; the ones
    # matching this host's Open findings are set true. Role switches are untouched.
    wn22_00_000010: false
    wn22_00_000030: true
    # …one line per rule toggle…
  roles:
    - role: Windows-2022-STIG
  tasks:
    - name: Registry fixes generated from DISA OVAL checks
      ansible.builtin.import_tasks: generated/SERVER01-oval.yml
```

Play `vars:` outrank role defaults, so the run is narrowed without editing the role. When a role needs tag fallback, the header gives the `--tags "$(cat SERVER01.tags)"` form instead and the README warns that tag selection can skip setup tasks the role does not tag `always`. The `tasks:` section appears only when generated tasks exist.

`README.md` states: tool version and timestamp; source report filename; each uploaded role's name, dialect, file count, rule toggles found, and the SHA-256 of the **original uploaded file**; each SCAP benchmark used for generated tasks, with its SHA-256; per-host coverage table; the full no-automated-fix list; that role switches (for example `win22stig_disruption_high: false`) are left at the role's defaults, so a role may still skip a selected rule; that some registry settings apply only after an application restart or reboot, so rescan after rebooting; that the preflight guard must not be bypassed with `--limit`; and that the bundle was produced by static parsing, and nothing in it was executed by this tool.

### 4.7 Exporter — `app/exporters/excel_exporter.py`

`_FINDINGS_COLS` gains three entries at the end: `("STIG ID", "stig_id", 18)`, `("Text Source", "text_source", 60)`, and `("Ansible Task", "ansible_task", 80)`; `Text Source` and `Ansible Task` join `_WRAP_HEADERS`. Column letters A–I and every `COUNTIFS` are untouched; the auto-filter range grows to L.

`export(findings, output_path, *, enrichment=None, remediation=None)`. When `enrichment` is given, the Summary sheet gains **Table 4 — Reference sources**: file, STIG title, edition, release, embedded (yes/no), rules loaded, filled check, filled fix, drifted, unmatched. When `remediation` is given, **Table 5 — Remediation coverage**: host, Open findings, from uploaded playbook, generated from DISA OVAL, matched across revision, no automated fix. Both tables are literal values written with the existing helpers and omitted when their argument is `None`.

### 4.8 Pipeline and stages — `app/core/pipeline.py`, `app/core/stages.py`

`parse_stage(results_paths, reference_paths, playbook_paths, extract_dir, *, cancel_check, progress_cb)` replaces the `benchmark_paths` parameter. All three lists go through `classify_inputs` (§4.1); names from `reference_paths` form the `reference_hint`. Order of operations: classify → load references and OVAL → parse results (existing per-file progress) → matcher (results files always included as benchmark sources) → CKLB/Nessus findings → filter → the existing empty-findings `PipelineError` check → **enrich** → **index playbooks** → **attach**. `ParseResult` gains `enrichment`, `remediation`, `plan`, and `index`.

`pipeline.py` gains `bundle_stage(plan, index, out_zip) -> bool`, used directly by the CLI and Flask. It returns False and logs on any exception; the caller turns that into the operator warning.

The async stages keep the idempotency contract (fixed keys, overwritten on re-run):

| Stage | Reads | Writes |
|---|---|---|
| parse | `jobs/{id}/input/*`; job record `reference_filenames` | `findings.json`, `enrichment.json`; `remediation.json` (report, plan including generated task text, SHA-256s) and `roles.zip` (extracted role trees, re-zipped for transport) when any remediation exists |
| export | the four above | `report.xlsx` always; `bundle.zip` when the plan has ≥1 host with a selectable unit or a generated task; job record `bundle: true/false` |

A bundle failure logs, warns, and leaves `bundle: false`; the export stage still completes. The Step Functions definition does not change.

### 4.9 Surfaces

**CLI** (`app/cli.py`):

| Flag | Meaning |
|---|---|
| `--references PATH…` | Manual STIG XML or ZIP (check text), SCAP Benchmark ZIP (generated registry fixes), or CKLB. `--benchmarks` keeps working as an alias; help text lists `--references`. Directories are scanned recursively, so one folder works as a library. |
| `--playbooks PATH…` | DISA Ansible ZIP, role directory or ZIP, or loose `.yml`. Directories are scanned recursively. |
| `--remediation-out FILE` | Bundle path; default `<output stem>_remediation.zip`, written only when the plan has ≥1 host. |

The run summary prints filled, drifted, and unmatched counts per STIG, remediation coverage, and the bundle path or the reason none was written.

**Flask** (`app/web.py`, `templates/index.html`, `static/app.js`): the second upload zone is titled "STIG references and playbooks". Its microcopy lists what each file type adds: "Manual STIG ZIPs add check text. SCAP Benchmark ZIPs enable generated registry fixes. Ansible ZIPs or roles add playbook fixes." PR A ships the first sentence, and PRs B and C each add theirs. The old line "Not needed when uploading SCC result files" is removed, because it hid the missing check text. Its `accept` gains `.cklb,.yml,.yaml`. Files from this zone form the `reference_hint`. `/api/download/<job_id>` takes `?artifact=report|bundle` (default report). The job record gains `bundle_path` and a per-artifact `downloaded` map. **Cleanup change:** today the job directory is deleted as soon as the report download closes, which would make a later bundle download fail; it is now deleted once every artifact the job produced has been downloaded, with the existing 8-hour startup sweep as the backstop. The result card shows "Download remediation bundle (.zip)" only when `bundle_path` is set.

**Lambda API** (`app/lambdas/api.py`): `POST /uploads` accepts an optional `referenceFilenames` list, which must be a subset of `filenames`; it is stored on the job record as `reference_filenames` and becomes the parse stage's `reference_hint`. `GET /jobs/{id}/result?artifact=bundle` presigns `jobs/{id}/bundle.zip` and returns 404 when the record says `bundle: false`. `GET /config` advertises the grown allow-list automatically. `GET /jobs/{id}` includes `bundle`. S3 lifecycle rules already expire artifacts.

**SPA** (`frontend/src/`): `types.ts` adds `bundle?: boolean`; `api.ts` sends `referenceFilenames` from the reference zone and adds the artifact parameter; `ResultCard` renders the second button when `bundle` is true, with the same error handling as the report download (a 410 or 404 shows a message, never a silent no-op). The reference zone's title, microcopy, and accept list match Flask.

### 4.10 OVAL registry generator — `oval_index.py`, `oval_generate.py` (PR C)

**Input.** The OVAL component of every uploaded SCAP Benchmark datastream, indexed by definition id, with its tests, objects, and states. XCCDF rules link to definitions through `ReferenceRule.oval_def`. SCC results carry no OVAL, so the operator uploads the matching SCAP Benchmark ZIPs.

**Eligibility**, all conditions required, following every `extend_definition` whose target is not `class="inventory"` (applicability checks such as "Windows 11 is installed" are ignored):

1. The criteria tree is AND-only and contains no negation.
2. Every criterion is a `registry_test` with `check_existence` of `at_least_one_exists` or `only_one_exists`.
3. Each test has exactly one state; that state has one `value` holding a literal (no `var_ref`) with operation `equals`, `greater than or equal`, or `less than or equal`, and a `type` of `reg_dword`, `reg_qword`, or `reg_sz`.
4. Each object's `hive`, `key`, and `name` are literals with operation `equals`, and the hive is `HKEY_LOCAL_MACHINE`.
5. **Cross-check with the Manual STIG.** When the finding's check text (from PR A) names the setting in DISA's usual `Registry Path:` / `Value Name:` / `Value:` form, the generated path, name, and value must agree with it. Disagreement skips generation and is counted as `oval_disagrees_with_check_text`.

Measured on the maintainer's own scan data with rules 1–4: about half of the open findings are eligible, all `HKEY_LOCAL_MACHINE`, value types `reg_dword` and `reg_sz`.

**Value choice.** `equals` uses the literal; `greater than or equal N` and `less than or equal N` use `N`, which satisfies the check. `reg_dword` → `type: dword`, `reg_qword` → `qword`, `reg_sz` → `string`.

**Generated task**, one per eligible criterion, grouped per finding:

```yaml
- name: 'GENERATED FROM DISA OVAL | V-253284 | WN11-00-000150 | Structured Exception Handling Overwrite Protection (SEHOP) must be enabled.'
  ansible.windows.win_regedit:
    path: 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
    name: DisableExceptionChainValidation
    data: 0
    type: dword
  tags: [V-253284, WN11-00-000150, generated_oval]
```

(Real rule from the Windows 11 V2R8 SCAP benchmark; path, name, value, and type are exactly what its OVAL check tests.)

The workbook cell's first line reads `# source: generated from DISA OVAL definition <id> in <SCAP file name> | not DISA-authored Ansible`, so a reader can never mistake a generated task for published remediation content.

---

## 5. Error handling

| Situation | Behaviour |
|---|---|
| Scan rules not found in the matched benchmark, and enrichment cannot fill them | Operator warning (today log-only, §1 defect 3). |
| References uploaded alongside SCC results | Embedded benchmarks stay in use; nothing is wiped (§1 defect 4). |
| Reference file parses to zero rules | Warning names the file; run continues. |
| References supplied, but a scanned STIG matched none of them | Warning with the scan's benchmark id and the titles and releases of every reference loaded. |
| Only SCAP-edition references for a STIG, check text still blank | Warning that SCAP files carry no check text and the Manual STIG is needed. |
| Text filled from a different release | Filled; Text Source names both releases; drift warning per STIG; Summary Table 4. |
| CKLB reference contains no `check_content` | Rules load with blank text; warning `<file>: 0 of N rules carry check text`. |
| Playbook upload yields zero units with recognised keys | Warning `No V-/SV-/STIG-ID tags found in <file> — unsupported playbook dialect`. |
| Role has units but no rule toggles in its defaults | Tag fallback for that role; warning and README note that tag selection can skip untagged setup tasks. |
| Unit with neither a toggle nor a tag | Shown in the workbook cell; counted as no automated fix for the bundle; README lists it. |
| OVAL check ineligible, or disagrees with the Manual STIG check text | No generated task; counted; the finding falls through to "No automated fix available". |
| Open finding with no uploaded unit and no generated task | Listed in the README no-fix section and Summary Table 5; the workbook cell says so. |
| Host with nothing selectable | No play; listed in README. |
| Host missing from the inventory at run time | The preflight guard fails the run with a message naming the host. |
| Bundle assembly raises | Logged with `log.exception`; warning "Remediation bundle could not be written — workbook is complete"; `bundle: false`. |
| YAML that will not parse | Per-file warning; other files still indexed. |
| Archive member with an unsafe path | Member skipped with a warning; extraction continues. |
| `referenceFilenames` names a file not in `filenames` | `POST /uploads` returns 400 with a user-safe message. |

Nothing in this design turns a successful parse into a failed job.

---

## 6. Security

- XML: the same hardened `lxml` parser as every existing parser (no entities, no network, no DTD); `huge_tree=True` for datastreams, with the 200 MB upload cap as the outer bound.
- YAML: `SafeLoader` subclass only; unknown tags become strings; a test greps the package and fails on any `yaml.load(` call without an explicit safe loader.
- Archives: bounded extraction (500 MB per member, depth 2) and per-component path checks; role files are copied byte-for-byte and never imported, templated, or executed.
- Trust: the bundle is only as trustworthy as its inputs. An uploaded role can do anything, and a tampered SCAP ZIP could steer generated registry writes. Mitigations: generation is limited to `HKEY_LOCAL_MACHINE` literal values that the check itself tests; the Manual STIG cross-check (§4.10 rule 5) must agree when check text is present; every workbook cell names its source file; the README records the SHA-256 of every uploaded file so an ISSO can tie the bundle to DISA's published download.
- Workbook: every new cell passes through `_sanitize_cell`.
- Dependency: `pyyaml>=6.0.2,<7.0` pinned; `pip-audit` in CI covers it.
- API: `referenceFilenames` is validated against `filenames` and the same `reject_filename` checks.
- Real data: the maintainer's scan files never enter the repo; the scrubbed fixture is built by an allow-list (only DISA benchmark text and the chosen rule results are kept; `target`, `target-address`, every `target-facts` entry, and `identity` are replaced with fake values), leak-scanned for the real host name, FQDN, addresses, MACs, and account name as a negative control, and reviewed by the maintainer before commit.

---

## 7. Testing

**Fixtures.**
- A scrubbed SCC fixture built from the maintainer's own scan data (D16, §6): a few rules from each of two STIGs, with the embedded SCAP benchmark, so CI finally sees real SCC structure.
- Trimmed slices of real DISA files (public domain): the Server 2022 V2R8 Manual XCCDF, the Windows 11 V2R8 SCAP 1.3 datastream including the OVAL definitions behind the sliced rules, and a matching CKLB.
- Ansible fixtures that are synthetic but structurally exact to the verified dialects, including a `defaults/main/` directory role and a `defaults/main.yml` role. One opt-in test runs against local `ansible-lockdown` checkouts pinned by commit SHA and skips when they are absent.

**Regression first.** Before any fix, failing tests reproduce §1 defects 2, 3, and 4: blank text from a real-form Manual STIG, an empty `ParseResult.warnings`, and SCC data wiped by an uploaded reference.

**Unit** — `test_normalize.py` (every function in §4.2), `test_xccdf_loader.py` (1.1, 1.2, datastream; embedded vs standalone; `oval_def`), `test_cklb_loader.py`, `test_reference_library.py`, `test_enrich.py` (per-field fill from different candidates, never-overwrite, re-resolve, drift, unmatched, CKLB and Nessus enriched, matcher warning dropped when resolved), `test_text_source.py` (every row of the §4.3 phrase table), `test_matcher.py` (warnings returned, `scan_release` recorded), `test_inputs.py` (classification table, reference hint, mixed ZIP, role trees, unsafe paths, SHA-256), `test_yaml_loader.py`, `test_remediation_index.py` (block inheritance, both dialects, both defaults layouts, toggle versus role switch, SRG exclusion, selector choice, `unselectable`), `test_oval_generate.py` (each eligibility rule accepted and rejected, inventory extend_definitions ignored, value choice, cross-check agreement and disagreement, task text), `test_attach.py` (precedence uploaded > generated > none, source lines, truncation), `test_emit.py` (inventory with and without FQDN, preflight guard text, vars block, tag fallback header, generated-task import, host name quoting), `test_bundle.py` (layout, README contents, SHA-256s, hosts with nothing selectable), `test_excel_exporter.py` (columns J–L, unchanged `COUNTIFS` letters, Tables 4 and 5 only when passed), `test_findings_io.py`, `test_pipeline.py` (order; results always used as benchmark sources), `test_stages.py` (moto: new keys, `bundle` flag, bundle failure non-fatal), `test_cli.py`, `test_web.py` (zone copy, accept list, reference hint, `?artifact=bundle`, cleanup only after both downloads), `test_lambda_handlers.py` (`referenceFilenames` validation, artifact parameter). Frontend: vitest for the bundle button, its error path, and `referenceFilenames`; axe on the result state; Playwright download journey with a bundle.

**Live verification** (Definition of Done per the project's standing rule). Anything that touches a Windows machine is run by the maintainer; the implementer prepares the exact commands and reads the results.

| PR | Live check |
|---|---|
| A — check text | A real SCC session (the maintainer's own scan data, verified locally and never committed), untouched, plus the current Manual STIGs for its STIGs, through the CLI and through Flask in a real browser: every matched finding has check text, Text Source names file and release (with drift where releases differ), fix text and severity are intact, warnings list anything unmatched. Screenshot of the opened workbook attached to the PR. |
| B — uploaded Ansible | The same session plus pinned checkouts of `ansible-lockdown/Windows-11-STIG` and `WinFWADV-STIG`: bundle produced; `ansible-playbook --syntax-check` passes for every host play in a Docker Ansible image; the preflight guard is proven by running a play against an inventory without the host, which must exit non-zero with the message. The maintainer then runs the play in `--check --diff` mode against a throwaway Windows 11 VM; only the selected rules may report changes. |
| C — generated registry fixes | Syntax check as for B. The maintainer applies the generated tasks for real to the throwaway Windows 11 VM, reboots, and rescans with SCC; every rule that received a generated task must now pass. |
| SPA | vitest, axe, and Playwright green on each PR; no GovCloud apply. |

---

## 8. Coordination and sequencing

Prerequisites, all merged into `master` on or before 2026-10-01: the hardening PR (#9), delta reporting (#10), and the restyle (#11).

This work branches from `master` as three PRs, each with its own implementation plan:

| PR | Contents | Estimate |
|---|---|---|
| A — check text | Regression tests; §4.1 for references and the CKLB hint; §4.2–4.4; matcher warnings; results always used as benchmark sources; columns J and K; Table 4; references on all three surfaces; the delta code updated to the new `parse_stage` signature and `DeltaFinding` fields; scrubbed SCC fixture. | about 1 day |
| B — uploaded Ansible | §4.1 for YAML and role trees; §4.5–4.6 for uploaded units; inventory and preflight guard; column L; Table 5; bundle artifact and downloads on all three surfaces; Flask cleanup change. | 1–2 days |
| C — generated registry fixes | §4.10; OVAL loading from SCAP datastreams; precedence integration; Table 5 column; microcopy. | about 1 day |

---

## 9. Follow-up: AI-drafted Ansible (amendment to the Bedrock enrichment spec)

Agreed direction, to be written into `2026-07-14-bedrock-enrichment-design.md` as a second enrichment job beside POA&M, not built here:

- **GovCloud only**, through the existing enricher stage and Bedrock. Local CLI and Flask runs never call a model, including local servers such as LM Studio, per the all-LLM-via-Bedrock rule. Ships disabled with no model configured; killswitch fails closed.
- **Last in precedence**: drafts are requested solely for Open findings with neither an uploaded unit nor a generated OVAL task. Deterministic tasks always win and are never replaced.
- Output is a **separate artifact** `ansible_ai.json` and a separate bundle file, `<host>.ai-drafted.yml`, never merged into `<host>.yml`. Every task name is prefixed `AI-DRAFTED`, the file header names the model and prompt version, and the play carries `when: ai_drafted_review_complete | bool` with the variable defaulting to `false`, so the file does nothing until a person enables it.
- The POA&M hallucination guard applies: every returned `vuln_id` is verified against the deterministic finding set; unknown IDs are dropped and counted.
- The workbook cell for such a finding keeps "No automated fix available"; AI text never enters the Findings sheet.

---

## 10. Definition of Done

- Defects 2, 3, and 4 of §1 each have a regression test that failed before the fix.
- G1 proven on a real SCC session (the maintainer's own scan data, verified locally and never committed): check text filled; Text Source correct on every row; SCC fix text, severity, and V-ID intact when references are uploaded; unmatched rules warned.
- No reference mismatch is reported only to a log (asserted).
- G2 proven on real data: pinned `ansible-lockdown` roles index; every generated play passes `--syntax-check`; the preflight guard fails a run with a missing host; the maintainer's check-mode run touches only selected rules; generated registry tasks make their rules pass on the maintainer's SCC rescan.
- Workbook columns A–I and every `COUNTIFS` unchanged (asserted).
- A run with no references and no playbooks produces today's report plus three new columns, the Text Source column states `no reference supplied` for blank check text, and no bundle is written.
- Every row of the §5 table has a test.
- Python suite, `pip-audit`, frontend typecheck, vitest, axe, and Playwright green in CI.
- README documents the new flags, the reference zone, which DISA edition adds what, the bundle layout and run command, the Text Source semantics, the generator's eligibility rules, and which Ansible dialects are verified.

---

## 11. Items to settle at build time

1. **Downloads** of public reference content, each requested with exact name, source, and size when its PR starts: the current Manual STIG ZIPs for the STIGs in the maintainer's own scan data (PR A); `ansible-lockdown/Windows-11-STIG` and `WinFWADV-STIG` at pinned commits (PR B); optionally DISA's Windows Server 2022 Ansible ZIP, to verify the DISA toggle dialect (PR B).
2. **A throwaway Windows 11 VM** reachable over WinRM HTTPS with Kerberos, for the maintainer's check-mode run (PR B) and the apply-and-rescan run (PR C).
3. **the maintainer's review of the scrubbed SCC fixture** before it is committed (PR A).

---

## 12. Changes made in self-review

1. **Lookup no longer stops at the first hit.** The brainstormed rule would have let SCC's own embedded rule, which has no check text, block the Manual STIG's check text whenever the two releases differ. Fields are now filled one at a time from the first candidate that has them (§4.3).
2. **Bundle selection uses the roles' own per-rule toggle variables, not `--tags`.** Tag selection can skip setup tasks a role does not tag `always` (D7, §4.5).
3. **Flask cleanup waits for every artifact** (§4.9).
4. **Matcher mismatches reach the operator** (§4.3, §5).
5. **The SPA path carries the reference-slot hint** through `referenceFilenames` (D3, §4.9).
6. **Filtering runs before enrichment,** so every count matches a report row (§4.8).

---

## 13. Decisions confirmed with the maintainer (2026-09-26)

| # | Question | Decision | Where |
|---|---|---|---|
| 1 | Generate registry fixes from DISA OVAL for findings no uploaded playbook covers? | Yes, as its own PR after the upload path | D1, D11, §4.10 |
| 2 | How do Manual STIGs get in? | Uploaded per run; CLI folder for reuse | D15, §4.9 |
| 3 | Which Linux scans must this handle? | Windows only for now | §2 |
| 4 | Text from a different release than scanned? | Fill it and flag each row with a Text Source column | D5, D12, §4.3 |
| 5 | Which findings do playbooks change? | Open only | D14 |
| 6 | How do playbooks find each host? | Generated inventory plus preflight guard | D13, §4.6 |
| 7 | Where may AI-drafted Ansible exist? | GovCloud only, last resort | §9 |
| 8 | Landing order? | Hardening PR, then delta, then this work | §8 |
| 9 | Use of the maintainer's real scan data? | Local verification; scrubbed fixture in CI | D16, §6, §7 |
