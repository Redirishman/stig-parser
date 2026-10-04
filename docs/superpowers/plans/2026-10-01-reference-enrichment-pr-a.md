# Reference Enrichment (PR A: check text) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When the operator supplies a Manual STIG (XML or DISA ZIP) or a CKLB as a reference, every finding gets its blank check text, fix text, severity, V-ID, STIG ID and STIG title filled, each row says where its text came from, and every gap is reported to the operator.

**Architecture:** A new pure package `app/reference/` builds a `ReferenceLibrary` from every STIG benchmark the run sees (uploaded references and benchmarks embedded in SCC results) and a post-parse `enrich_findings()` pass fills blanks on `Finding` objects from it. `app/core/inputs.py` routes uploads by content. The matcher is unchanged except that it reports problems as data instead of log lines.

**Tech Stack:** Python 3.11+, lxml, openpyxl, pytest; Flask; React + TypeScript + vitest (SPA). No new dependency in this PR.

**Spec:** `docs/superpowers/specs/2026-09-26-reference-enrichment-and-ansible-remediation-design.md` (§1, §4.1–4.4, §4.7–4.9, §5, D2–D6, D8, D10, D12, D15, D16).

**Scope notes (deliberate, relative to the spec):**
- `Finding.ansible_task`, `Finding.fqdn`, YAML uploads, the bundle, and SHA-256 provenance belong to PR B. `ReferenceRule.oval_def` belongs to PR C.
- `parse_stage` keeps three positional parameters `(results_paths, reference_paths, extract_dir)`; PR B adds `playbook_paths` as a keyword argument, so no caller changes twice.
- The upload zone is titled **"STIG References"** in this PR; PR B renames it when playbooks arrive.
- Fixtures are hand-written to the real file shapes measured in spec §1 (SCC results with an embedded SCAP benchmark; an XCCDF 1.1 Manual STIG with short rule IDs). Real scan data is used only in the live verification at the end, never committed.

**Conventions for every task**
- Work in the worktree of branch `feat/reference-enrichment` and run commands from there.
- Test command: `python -m pytest -q -p no:cacheprovider` (all) or with a path. Baseline before Task 1: **502 passed**.
- Commit after each task: write the message to a temp file and `git commit -F <file>`; `git add` only the files the task names; end every message with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`. Never push.
- When an existing test fails because it pinned the **old silent behaviour** (for example `warnings == []` on a run that now, correctly, warns), update that expectation to the new behaviour and say so in the commit message. Never weaken an unrelated assertion to get green.

---

## File structure

| File | Responsibility |
|---|---|
| `app/reference/__init__.py` (new) | Package marker. |
| `app/reference/normalize.py` (new) | Identifier normalisation: rule prefix/stem/revision, group prefix, STIG ID, benchmark ID, release label. |
| `app/reference/models.py` (new) | `ReferenceSource`, `ReferenceRule` dataclasses. |
| `app/reference/library.py` (new) | `ReferenceLibrary`: four indexes, `add_benchmark`, `add_rules`, `candidates(finding)`. |
| `app/reference/cklb_loader.py` (new) | CKLB → reference rules. |
| `app/reference/text_source.py` (new) | The `Text Source` cell text. |
| `app/reference/enrich.py` (new) | `enrich_findings`, `EnrichmentReport` (+ JSON round trip, operator warnings). |
| `app/core/inputs.py` (new) | `classify_inputs`: content-based routing of uploads. |
| `app/parsers/base.py` | New fields on `BenchmarkRule`, `Benchmark`, `Finding`. |
| `app/parsers/benchmark_parser.py` | `parse_all` (benchmarks at any depth, datastreams), STIG ID, release. |
| `app/parsers/cklb_parser.py`, `nessus_parser.py` | Populate `stig_id` / `scan_release`. |
| `app/processors/matcher.py` | Populate `stig_id` / `scan_release`; return `MatchIssue`s. |
| `app/utils/zip_extract.py` | Also extract SCAP datastreams and `.cklb` members. |
| `app/core/pipeline.py` | New `parse_stage` flow; `export_stage(…, enrichment=)`. |
| `app/exporters/excel_exporter.py` | Columns J/K; Summary Table 4. |
| `app/processors/delta.py`, `app/cli.py` | Delta carries the new fields; `--references`. |
| `app/web.py`, `app/templates/index.html`, `app/static/app.js` | Zone copy, `.cklb` accepted as reference, enrichment passed to export. |
| `app/core/stages.py`, `app/lambdas/api.py`, `app/lambdas/parser.py` | `referenceFilenames` hint, `enrichment.json`. |
| `frontend/src/api.ts`, `useJob.ts`, `App.tsx` | Send the hint; zone copy. |
| `tests/fixtures/scc_embedded_results.xml`, `manual_stig_server2022.xml`, `manual_stig_win11.xml`, `scap_datastream_win11.xml` (new) | Real-shape fixtures. |

---

### Task 1: Real-shape fixtures

**Files:**
- Create: `tests/fixtures/scc_embedded_results.xml`, `tests/fixtures/manual_stig_win11.xml`, `tests/fixtures/manual_stig_server2022.xml`, `tests/fixtures/scap_datastream_win11.xml`
- Test: `tests/test_reference_fixtures.py`

- [ ] **Step 1: Write the fixture sanity test**

```python
# tests/test_reference_fixtures.py
"""The reference fixtures must keep the real-world shapes the feature exists for."""
from pathlib import Path

from app.parsers.benchmark_parser import BenchmarkParser
from app.parsers.xccdf_parser import XCCDFResultsParser

FIXTURES = Path(__file__).parent / "fixtures"


def test_scc_fixture_embeds_a_benchmark_with_fix_text_but_no_check_text():
    bm = BenchmarkParser().parse(FIXTURES / "scc_embedded_results.xml")
    assert bm.benchmark_id == "xccdf_mil.disa.stig_benchmark_Microsoft_Windows_11_STIG"
    assert len(bm.rules) == 4
    assert all(r.fix_text for r in bm.rules.values())
    assert not any(r.check_text for r in bm.rules.values())


def test_scc_fixture_has_results_for_the_embedded_rules():
    scan = XCCDFResultsParser().parse(FIXTURES / "scc_embedded_results.xml")
    assert scan.hostname == "WKSTN-01"
    assert {rr.status for rr in scan.rule_results} == {"fail", "pass"}
    assert len(scan.rule_results) == 4


def test_manual_fixtures_use_short_rule_ids_and_carry_check_text():
    for name, expected_id in (
        ("manual_stig_win11.xml", "MS_Windows_11_STIG"),
        ("manual_stig_server2022.xml", "MS_Windows_Server_2022_STIG"),
    ):
        bm = BenchmarkParser().parse(FIXTURES / name)
        assert bm.benchmark_id == expected_id
        assert all(rid.startswith("SV-") for rid in bm.rules)
        assert all(r.check_text and r.fix_text for r in bm.rules.values())
```

- [ ] **Step 2: Run it — it fails because the files do not exist**

Run: `python -m pytest tests/test_reference_fixtures.py -q -p no:cacheprovider`
Expected: 3 errors/failures (lxml `OSError` / file not found).

- [ ] **Step 3: Create `tests/fixtures/scc_embedded_results.xml`**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!--
  Fabricated SCC 5.x XCCDF results in the real SCC shape: the Benchmark is the
  document root, the scanned SCAP benchmark is embedded (fix text and OVAL check
  references, NO human check text), and the TestResult is nested inside it.
  Host values are fake. Rule text is representative but synthetic.
-->
<cdf:Benchmark xmlns:cdf="http://checklists.nist.gov/xccdf/1.2"
    id="xccdf_mil.disa.stig_benchmark_Microsoft_Windows_11_STIG" resolved="1" xml:lang="en">
  <cdf:status date="2026-04-01">accepted</cdf:status>
  <cdf:title>Microsoft Windows 11 STIG SCAP Benchmark</cdf:title>
  <cdf:plain-text id="release-info">Benchmark Date: 01 Apr 2026</cdf:plain-text>
  <cdf:version>002.008</cdf:version>

  <cdf:Group id="xccdf_mil.disa.stig_group_V-253284">
    <cdf:title>SRG-OS-000480-GPOS-00227</cdf:title>
    <cdf:Rule id="xccdf_mil.disa.stig_rule_SV-253284r958928_rule" severity="high" weight="10.0">
      <cdf:version>WN11-00-000150</cdf:version>
      <cdf:title>Structured Exception Handling Overwrite Protection (SEHOP) must be enabled.</cdf:title>
      <cdf:fixtext fixref="F-56737r958927_fix">Set the registry value DisableExceptionChainValidation to 0.</cdf:fixtext>
      <cdf:fix id="F-56737r958927_fix"/>
      <cdf:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
        <cdf:check-content-ref href="U_MS_Windows_11_V2R8_STIG_SCAP_1-3_Benchmark-oval.xml" name="oval:mil.disa.stig.windows11:def:253284"/>
      </cdf:check>
    </cdf:Rule>
  </cdf:Group>

  <cdf:Group id="xccdf_mil.disa.stig_group_V-253285">
    <cdf:title>SRG-OS-000480-GPOS-00227</cdf:title>
    <cdf:Rule id="xccdf_mil.disa.stig_rule_SV-253285r958930_rule" severity="medium" weight="10.0">
      <cdf:version>WN11-00-000160</cdf:version>
      <cdf:title>The Server Message Block (SMB) v1 protocol must be disabled on the system.</cdf:title>
      <cdf:fixtext fixref="F-56738r958929_fix">Disable the SMB 1.0/CIFS File Sharing Support feature.</cdf:fixtext>
      <cdf:fix id="F-56738r958929_fix"/>
      <cdf:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
        <cdf:check-content-ref href="U_MS_Windows_11_V2R8_STIG_SCAP_1-3_Benchmark-oval.xml" name="oval:mil.disa.stig.windows11:def:253285"/>
      </cdf:check>
    </cdf:Rule>
  </cdf:Group>

  <cdf:Group id="xccdf_mil.disa.stig_group_V-253286">
    <cdf:title>SRG-OS-000480-GPOS-00227</cdf:title>
    <cdf:Rule id="xccdf_mil.disa.stig_rule_SV-253286r958932_rule" severity="low" weight="10.0">
      <cdf:version>WN11-00-000170</cdf:version>
      <cdf:title>The SMB v1 protocol must be disabled on the SMB client.</cdf:title>
      <cdf:fixtext fixref="F-56739r958931_fix">Configure the policy value for Configure SMB v1 client driver to Disabled.</cdf:fixtext>
      <cdf:fix id="F-56739r958931_fix"/>
      <cdf:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
        <cdf:check-content-ref href="U_MS_Windows_11_V2R8_STIG_SCAP_1-3_Benchmark-oval.xml" name="oval:mil.disa.stig.windows11:def:253286"/>
      </cdf:check>
    </cdf:Rule>
  </cdf:Group>

  <cdf:Group id="xccdf_mil.disa.stig_group_V-253290">
    <cdf:title>SRG-OS-000480-GPOS-00227</cdf:title>
    <cdf:Rule id="xccdf_mil.disa.stig_rule_SV-253290r958940_rule" severity="medium" weight="10.0">
      <cdf:version>WN11-00-000200</cdf:version>
      <cdf:title>Automatic logons must be disabled.</cdf:title>
      <cdf:fixtext fixref="F-56743r958939_fix">Set AutoAdminLogon to 0.</cdf:fixtext>
      <cdf:fix id="F-56743r958939_fix"/>
      <cdf:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
        <cdf:check-content-ref href="U_MS_Windows_11_V2R8_STIG_SCAP_1-3_Benchmark-oval.xml" name="oval:mil.disa.stig.windows11:def:253290"/>
      </cdf:check>
    </cdf:Rule>
  </cdf:Group>

  <cdf:TestResult id="xccdf_mil.disa.stig_testresult_scc_1" start-time="2026-01-15T10:00:00" end-time="2026-01-15T10:01:24" test-system="cpe:/a:spawar:scc:5.14.1">
    <cdf:benchmark href="U_MS_Windows_11_V2R8_STIG_SCAP_1-3_Benchmark.xml" id="xccdf_mil.disa.stig_benchmark_Microsoft_Windows_11_STIG"/>
    <cdf:title>SCC scan of WKSTN-01</cdf:title>
    <cdf:target>WKSTN-01</cdf:target>
    <cdf:target-address>10.0.0.21</cdf:target-address>
    <cdf:target-address>172.16.5.21</cdf:target-address>
    <cdf:target-address>fe80::1</cdf:target-address>
    <cdf:target-facts>
      <cdf:fact name="urn:scap:fact:asset:identifier:host_name" type="string">WKSTN-01</cdf:fact>
      <cdf:fact name="urn:scap:fact:asset:identifier:fqdn" type="string">wkstn-01.example.mil</cdf:fact>
      <cdf:fact name="urn:scap:fact:asset:identifier:ipv4" type="string">10.0.0.21</cdf:fact>
    </cdf:target-facts>
    <cdf:rule-result idref="xccdf_mil.disa.stig_rule_SV-253284r958928_rule" severity="high"><cdf:result>fail</cdf:result></cdf:rule-result>
    <cdf:rule-result idref="xccdf_mil.disa.stig_rule_SV-253285r958930_rule" severity="medium"><cdf:result>fail</cdf:result></cdf:rule-result>
    <cdf:rule-result idref="xccdf_mil.disa.stig_rule_SV-253286r958932_rule" severity="low"><cdf:result>fail</cdf:result></cdf:rule-result>
    <cdf:rule-result idref="xccdf_mil.disa.stig_rule_SV-253290r958940_rule" severity="medium"><cdf:result>pass</cdf:result></cdf:rule-result>
  </cdf:TestResult>
</cdf:Benchmark>
```

- [ ] **Step 4: Create `tests/fixtures/manual_stig_win11.xml`** (newer release than the scan: 253284 same revision, 253285 a different revision, 253286 absent)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!--
  Fabricated DISA Manual STIG in its real shape: XCCDF 1.1, short group and rule
  IDs (no xccdf_ prefix), inline check-content. One release newer than the scan
  fixture, so one rule revision differs. Text is representative but synthetic.
-->
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="MS_Windows_11_STIG" xml:lang="en">
  <status date="2026-07-01">accepted</status>
  <title>Microsoft Windows 11 Security Technical Implementation Guide</title>
  <plain-text id="release-info">Release: 9 Benchmark Date: 01 Jul 2026</plain-text>
  <version>2</version>

  <Group id="V-253284">
    <title>SRG-OS-000480-GPOS-00227</title>
    <Rule id="SV-253284r958928_rule" severity="high" weight="10.0">
      <version>WN11-00-000150</version>
      <title>Structured Exception Handling Overwrite Protection (SEHOP) must be enabled.</title>
      <fixtext fixref="F-56737r958927_fix">Configure DisableExceptionChainValidation (REG_DWORD) to 0.</fixtext>
      <fix id="F-56737r958927_fix"/>
      <check system="C-56787r958926_chk">
        <check-content-ref href="Microsoft_Windows_11_STIG.xml" name="M"/>
        <check-content>Verify the registry value DisableExceptionChainValidation is 0. If it is not, this is a finding.</check-content>
      </check>
    </Rule>
  </Group>

  <Group id="V-253285">
    <title>SRG-OS-000480-GPOS-00227</title>
    <Rule id="SV-253285r991589_rule" severity="medium" weight="10.0">
      <version>WN11-00-000160</version>
      <title>The Server Message Block (SMB) v1 protocol must be disabled on the system.</title>
      <fixtext fixref="F-56738r991588_fix">Uninstall the SMB 1.0/CIFS File Sharing Support feature.</fixtext>
      <fix id="F-56738r991588_fix"/>
      <check system="C-56788r991587_chk">
        <check-content-ref href="Microsoft_Windows_11_STIG.xml" name="M"/>
        <check-content>Run Get-WindowsOptionalFeature for SMB1Protocol. If State is Enabled, this is a finding.</check-content>
      </check>
    </Rule>
  </Group>

  <Group id="V-253287">
    <title>SRG-OS-000480-GPOS-00227</title>
    <Rule id="SV-253287r958934_rule" severity="medium" weight="10.0">
      <version>WN11-00-000175</version>
      <title>The Secondary Logon service must be disabled.</title>
      <fixtext fixref="F-56740r958933_fix">Set the Secondary Logon service Startup Type to Disabled.</fixtext>
      <fix id="F-56740r958933_fix"/>
      <check system="C-56790r958932_chk">
        <check-content-ref href="Microsoft_Windows_11_STIG.xml" name="M"/>
        <check-content>Verify the Secondary Logon service is Disabled and not running. If it is not, this is a finding.</check-content>
      </check>
    </Rule>
  </Group>
</Benchmark>
```

- [ ] **Step 5: Create `tests/fixtures/manual_stig_server2022.xml`** (pairs with the existing `evaluate_stig_results.xml`: 254239 different revision, 254241 same revision, 254243 absent)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!--
  Fabricated DISA Manual STIG, real shape (XCCDF 1.1, short IDs). Pairs with the
  existing results fixtures, whose rule-result idrefs use the long XCCDF 1.2 form
  and an older revision. Text is representative but synthetic.
-->
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="MS_Windows_Server_2022_STIG" xml:lang="en">
  <status date="2026-04-01">accepted</status>
  <title>Microsoft Windows Server 2022 Security Technical Implementation Guide</title>
  <plain-text id="release-info">Release: 8 Benchmark Date: 01 Apr 2026</plain-text>
  <version>2</version>

  <Group id="V-254239">
    <title>SRG-OS-000480-GPOS-00227</title>
    <Rule id="SV-254239r1153440_rule" severity="high" weight="10.0">
      <version>WN22-00-000010</version>
      <title>Windows Server 2022 users with Administrative privileges must have separate accounts for administrative duties and normal operational tasks.</title>
      <fixtext fixref="F-57675r1153439_fix">Ensure each user with administrative privileges has a separate account for user duties.</fixtext>
      <fix id="F-57675r1153439_fix"/>
      <check system="C-57724r1153438_chk">
        <check-content-ref href="MS_Windows_Server_2022_STIG.xml" name="M"/>
        <check-content>Verify each user with administrative privileges has been assigned a unique administrative account. If not, this is a finding.</check-content>
      </check>
    </Rule>
  </Group>

  <Group id="V-254241">
    <title>SRG-OS-000480-GPOS-00227</title>
    <Rule id="SV-254241r945414_rule" severity="medium" weight="10.0">
      <version>WN22-00-000030</version>
      <title>Windows Server 2022 administrative accounts must not be used with applications that access the internet.</title>
      <fixtext fixref="F-57677r945413_fix">Establish a policy that restricts administrative accounts from internet-facing applications.</fixtext>
      <fix id="F-57677r945413_fix"/>
      <check system="C-57726r945412_chk">
        <check-content-ref href="MS_Windows_Server_2022_STIG.xml" name="M"/>
        <check-content>Determine whether administrative accounts are prevented from using internet applications. If not, this is a finding.</check-content>
      </check>
    </Rule>
  </Group>
</Benchmark>
```

- [ ] **Step 6: Create `tests/fixtures/scap_datastream_win11.xml`** (a SCAP 1.3 datastream: the Benchmark sits inside a component, not at the root)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!-- Fabricated SCAP 1.3 source datastream, real shape: data-stream-collection root,
     XCCDF 1.2 Benchmark nested in a component. Fix text, no human check text. -->
<ds:data-stream-collection xmlns:ds="http://scap.nist.gov/schema/scap/source/1.2"
    xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2"
    id="scap_mil.disa.stig_collection_U_MS_Windows_11_V2R8_STIG_SCAP_1-3_Benchmark" schematron-version="1.3">
  <ds:data-stream id="scap_mil.disa.stig_datastream_U_MS_Windows_11_V2R8_STIG_SCAP_1-3_Benchmark" scap-version="1.3" use-case="CONFIGURATION"/>
  <ds:component id="scap_mil.disa.stig_comp_U_MS_Windows_11_V2R8_STIG_SCAP_1-3_Benchmark-xccdf.xml" timestamp="2026-04-01T00:00:00">
    <xccdf:Benchmark id="xccdf_mil.disa.stig_benchmark_Microsoft_Windows_11_STIG" resolved="1" xml:lang="en">
      <xccdf:status date="2026-04-01">accepted</xccdf:status>
      <xccdf:title>Microsoft Windows 11 STIG SCAP Benchmark</xccdf:title>
      <xccdf:plain-text id="release-info">Benchmark Date: 01 Apr 2026</xccdf:plain-text>
      <xccdf:version>002.008</xccdf:version>
      <xccdf:Group id="xccdf_mil.disa.stig_group_V-253284">
        <xccdf:title>SRG-OS-000480-GPOS-00227</xccdf:title>
        <xccdf:Rule id="xccdf_mil.disa.stig_rule_SV-253284r958928_rule" severity="high" weight="10.0">
          <xccdf:version>WN11-00-000150</xccdf:version>
          <xccdf:title>Structured Exception Handling Overwrite Protection (SEHOP) must be enabled.</xccdf:title>
          <xccdf:fixtext fixref="F-56737r958927_fix">Set the registry value DisableExceptionChainValidation to 0.</xccdf:fixtext>
          <xccdf:fix id="F-56737r958927_fix"/>
          <xccdf:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
            <xccdf:check-content-ref href="U_MS_Windows_11_V2R8_STIG_SCAP_1-3_Benchmark-oval.xml" name="oval:mil.disa.stig.windows11:def:253284"/>
          </xccdf:check>
        </xccdf:Rule>
      </xccdf:Group>
    </xccdf:Benchmark>
  </ds:component>
</ds:data-stream-collection>
```

- [ ] **Step 7: Run the test**

Run: `python -m pytest tests/test_reference_fixtures.py -q -p no:cacheprovider`
Expected: 3 passed.

- [ ] **Step 8: Commit**

```bash
git add tests/fixtures/scc_embedded_results.xml tests/fixtures/manual_stig_win11.xml tests/fixtures/manual_stig_server2022.xml tests/fixtures/scap_datastream_win11.xml tests/test_reference_fixtures.py
git commit -F msg.txt   # "test(reference): fixtures in the real SCC and Manual STIG shapes"
```

---

### Task 2: Identifier normalisation

**Files:**
- Create: `app/reference/__init__.py`, `app/reference/normalize.py`
- Test: `tests/test_normalize.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_normalize.py
import pytest

from app.reference.normalize import (
    norm_benchmark_id,
    norm_stig_id,
    release_label,
    rule_revision,
    rule_stem,
    strip_group_prefix,
    strip_rule_prefix,
)


@pytest.mark.parametrize("raw,expected", [
    ("xccdf_mil.disa.stig_rule_SV-254239r945408_rule", "SV-254239r945408_rule"),
    ("SV-254239r945408_rule", "SV-254239r945408_rule"),
    ("  SV-254239r945408_rule ", "SV-254239r945408_rule"),
    ("xccdf_org.ssgproject.content_rule_package_aide_installed", "package_aide_installed"),
    ("", ""),
])
def test_strip_rule_prefix(raw, expected):
    assert strip_rule_prefix(raw) == expected


@pytest.mark.parametrize("raw,stem,revision", [
    ("xccdf_mil.disa.stig_rule_SV-254239r945408_rule", "SV-254239", "r945408"),
    ("SV-254239r1153440_rule", "SV-254239", "r1153440"),
    ("SV-254239_rule", "SV-254239", ""),
    ("WN22-00-000010", "WN22-00-000010", ""),
    ("", "", ""),
])
def test_rule_stem_and_revision(raw, stem, revision):
    assert rule_stem(raw) == stem
    assert rule_revision(raw) == revision


@pytest.mark.parametrize("raw,expected", [
    ("xccdf_mil.disa.stig_group_V-254239", "V-254239"),
    ("V-254239", "V-254239"),
    ("", ""),
])
def test_strip_group_prefix(raw, expected):
    assert strip_group_prefix(raw) == expected


@pytest.mark.parametrize("raw,expected", [
    ("WN22-00-000010", "WN22-00-000010"),
    ("wn22_00_000030", "WN22-00-000030"),
    ("DISA-STIG-RHEL-09-651010", "RHEL-09-651010"),
    ("disa_stig_rhel_09_651010", "RHEL-09-651010"),
    ("WNFWA-000001", "WNFWA-000001"),
    ("  ", ""),
])
def test_norm_stig_id(raw, expected):
    assert norm_stig_id(raw) == expected


@pytest.mark.parametrize("raw,expected", [
    ("xccdf_mil.disa.stig_benchmark_MS_Windows_Server_2022_STIG", "MS_Windows_Server_2022_STIG"),
    ("MS_Windows_Server_2022_STIG", "MS_Windows_Server_2022_STIG"),
])
def test_norm_benchmark_id(raw, expected):
    assert norm_benchmark_id(raw) == expected


@pytest.mark.parametrize("version,info,expected", [
    ("2", "Release: 8 Benchmark Date: 01 Apr 2026", "V2R8"),      # Manual STIG
    ("002.008", "Benchmark Date: 01 Apr 2026", "V2R8"),           # SCAP benchmark
    ("1", "Release: 4 Benchmark Date: 24 Jul 2024", "V1R4"),      # CKLB (version is an int there)
    ("V1R4", "", "V1R4"),                                         # already a label
    ("3", "", "V3"),
    ("", "", ""),
])
def test_release_label(version, info, expected):
    assert release_label(version, info) == expected
```

- [ ] **Step 2: Run — fails with `ModuleNotFoundError: No module named 'app.reference'`**

Run: `python -m pytest tests/test_normalize.py -q -p no:cacheprovider`

- [ ] **Step 3: Implement**

```python
# app/reference/__init__.py
"""STIG reference library: fills blank finding text from uploaded STIG content."""
```

```python
# app/reference/normalize.py
"""Identifier normalisation shared by every reference lookup.

Scan results, Manual STIGs, SCAP benchmarks, and checklists spell the same
rule differently (XCCDF 1.2 prefixes, revision suffixes that change between
STIG releases). Everything that compares identifiers goes through here.
"""
from __future__ import annotations

import re

_RULE_PREFIX = re.compile(r"^xccdf_[^_]+_rule_", re.IGNORECASE)
_GROUP_PREFIX = re.compile(r"^xccdf_[^_]+_group_", re.IGNORECASE)
_BENCHMARK_PREFIX = re.compile(r"^xccdf_[^_]+_benchmark_", re.IGNORECASE)
_REVISION = re.compile(r"(r\d+)_rule$", re.IGNORECASE)
_RULE_SUFFIX = re.compile(r"_rule$", re.IGNORECASE)
_STIG_ID_PREFIX = re.compile(r"^DISA[-_]STIG[-_]", re.IGNORECASE)
_SCAP_VERSION = re.compile(r"0*(\d+)\.0*(\d+)")
_RELEASE = re.compile(r"Release:\s*(\d+)", re.IGNORECASE)


def strip_rule_prefix(rule_id: str) -> str:
    """``xccdf_mil.disa.stig_rule_SV-1r2_rule`` -> ``SV-1r2_rule``."""
    return _RULE_PREFIX.sub("", (rule_id or "").strip())


def rule_revision(rule_id: str) -> str:
    """``SV-254239r945408_rule`` -> ``r945408``; ``""`` when there is none."""
    m = _REVISION.search(strip_rule_prefix(rule_id))
    return m.group(1).lower() if m else ""


def rule_stem(rule_id: str) -> str:
    """The revision-free rule identity: ``SV-254239r945408_rule`` -> ``SV-254239``."""
    bare = strip_rule_prefix(rule_id)
    stem = _REVISION.sub("", bare)
    return _RULE_SUFFIX.sub("", stem) if stem == bare else stem


def strip_group_prefix(group_id: str) -> str:
    """``xccdf_mil.disa.stig_group_V-254239`` -> ``V-254239``."""
    return _GROUP_PREFIX.sub("", (group_id or "").strip())


def norm_stig_id(stig_id: str) -> str:
    """Uppercase, ``_`` -> ``-``, optional ``DISA-STIG-`` prefix removed."""
    value = _STIG_ID_PREFIX.sub("", (stig_id or "").strip())
    return value.replace("_", "-").upper()


def norm_benchmark_id(benchmark_id: str) -> str:
    """``xccdf_mil.disa.stig_benchmark_X`` -> ``X``."""
    return _BENCHMARK_PREFIX.sub("", (benchmark_id or "").strip())


def release_label(version: str, release_info: str = "") -> str:
    """A ``V2R8`` label from the two shapes DISA uses.

    Manual STIGs carry ``<version>2</version>`` plus a release-info line
    ``Release: 8 Benchmark Date: ...``; SCAP benchmarks carry
    ``<version>002.008</version>``. Anything else is returned unchanged.
    """
    version = str(version or "").strip()
    scap = _SCAP_VERSION.fullmatch(version)
    if scap:
        return f"V{int(scap.group(1))}R{int(scap.group(2))}"
    if version.isdigit():
        release = _RELEASE.search(release_info or "")
        return f"V{int(version)}R{int(release.group(1))}" if release else f"V{int(version)}"
    return version
```

- [ ] **Step 4: Run — passes**

Run: `python -m pytest tests/test_normalize.py -q -p no:cacheprovider`
Expected: all passed.

- [ ] **Step 5: Commit** — `feat(reference): identifier normalisation`
Files: `app/reference/__init__.py app/reference/normalize.py tests/test_normalize.py`

---

### Task 3: Model fields and a benchmark parser that reads every Benchmark

**Files:**
- Modify: `app/parsers/base.py` (`BenchmarkRule`, `Benchmark`, `Finding`)
- Modify: `app/parsers/benchmark_parser.py`
- Test: `tests/test_benchmark_parser.py` (append), `tests/test_findings_io.py` (append)

- [ ] **Step 1: Write the failing tests** (append)

```python
# tests/test_benchmark_parser.py  (append)
from pathlib import Path as _Path

from app.parsers.benchmark_parser import BenchmarkParser as _BP

_FIX = _Path(__file__).parent / "fixtures"


class TestParseAllAndNewFields:
    def test_manual_stig_rules_carry_stig_id_and_release(self):
        bm = _BP().parse(_FIX / "manual_stig_win11.xml")
        assert bm.release == "V2R9"
        assert bm.rules["SV-253284r958928_rule"].stig_id == "WN11-00-000150"

    def test_scap_release_label(self):
        bm = _BP().parse(_FIX / "scc_embedded_results.xml")
        assert bm.release == "V2R8"

    def test_parse_all_finds_a_benchmark_inside_a_datastream(self):
        found = _BP().parse_all(_FIX / "scap_datastream_win11.xml")
        assert len(found) == 1
        assert found[0].benchmark_id == "xccdf_mil.disa.stig_benchmark_Microsoft_Windows_11_STIG"
        assert list(found[0].rules) == ["xccdf_mil.disa.stig_rule_SV-253284r958928_rule"]
        assert found[0].rules["xccdf_mil.disa.stig_rule_SV-253284r958928_rule"].fix_text

    def test_parse_all_returns_empty_for_results_without_a_benchmark(self):
        assert _BP().parse_all(_FIX / "evaluate_stig_results.xml", warn_if_empty=False) == []

    def test_parse_all_returns_empty_on_invalid_xml(self, tmp_path):
        bad = tmp_path / "bad.xml"
        bad.write_text("<Benchmark", encoding="utf-8")
        assert _BP().parse_all(bad) == []

    def test_parse_still_returns_first_benchmark(self):
        assert _BP().parse(_FIX / "scap_datastream_win11.xml").rules
```

```python
# tests/test_findings_io.py  (append)
def test_new_finding_fields_round_trip_and_old_payloads_load():
    import json
    from app.core.findings_io import findings_from_json, findings_to_json
    from app.parsers.base import Finding

    f = Finding("T", "V-1", "SV-1r1_rule", "CAT I", "Open", "h", "1.1.1.1", "c", "x",
                stig_id="WN11-00-000150", text_source="Check and fix: scanner", scan_release="V2R8")
    assert findings_from_json(findings_to_json([f]))[0] == f
    old = json.dumps([{"stig_title": "T", "vuln_id": "V-1", "rule_id": "r", "severity": "CAT I",
                       "status": "Open", "server": "h", "ip_address": "i", "check_text": "c", "fix_text": "x"}])
    loaded = findings_from_json(old)[0]
    assert (loaded.stig_id, loaded.text_source, loaded.scan_release) == ("", "", "")
```

- [ ] **Step 2: Run — fails** (`AttributeError: 'Benchmark' object has no attribute 'release'`, `parse_all` missing, `TypeError` on `Finding(stig_id=…)`)

Run: `python -m pytest tests/test_benchmark_parser.py tests/test_findings_io.py -q -p no:cacheprovider`

- [ ] **Step 3: Add the fields in `app/parsers/base.py`**

In `BenchmarkRule`, after `fix_text: str` add:

```python
    stig_id: str = ""   # XCCDF <version>, e.g. WN22-00-000010
```

In `Benchmark`, after the `rules` field add:

```python
    release: str = ""   # "V2R8"
```

In `Finding`, after `fix_text: str` add:

```python
    stig_id: str = ""        # WN22-00-000010 — the stable cross-source rule key
    text_source: str = ""    # where check/fix text came from (workbook column K)
    scan_release: str = ""   # release of the benchmark that was scanned, e.g. V2R8
```

- [ ] **Step 4: Rework `app/parsers/benchmark_parser.py`**

Add the import `from app.reference.normalize import release_label` and replace the `BenchmarkParser` class with:

```python
def _release_info(benchmark_el: etree._Element) -> str:
    for child in benchmark_el:
        if (
            not callable(child.tag)
            and etree.QName(child.tag).localname == "plain-text"
            and child.get("id") == "release-info"
        ):
            return (child.text or "").strip()
    return ""


def _benchmark_from_element(root: etree._Element) -> Benchmark:
    """Build a Benchmark from one <Benchmark> element (any namespace)."""
    rules: dict[str, BenchmarkRule] = {}
    groups = root.findall("xccdf:Group", _NS) or _findall_local(root, "Group")
    for group_el in groups:
        vuln_id = _extract_vuln_id(group_el.get("id", ""))
        rule_els = group_el.findall("xccdf:Rule", _NS) or _findall_local(group_el, "Rule")
        for rule_el in rule_els:
            rule_id = rule_el.get("id", "")
            if not rule_id:
                continue
            severity_raw = rule_el.get("severity", "").lower()
            rules[rule_id] = BenchmarkRule(
                vuln_id=vuln_id,
                rule_id=rule_id,
                severity=_SEVERITY_MAP.get(severity_raw, "Unknown"),
                check_text=_get_check_text(rule_el),
                fix_text=_get_fix_text(rule_el),
                stig_id=_find_text_ns(rule_el, "version"),
            )
    return Benchmark(
        benchmark_id=root.get("id", ""),
        title=_find_text_ns(root, "title"),
        rules=rules,
        release=release_label(_find_text_ns(root, "version"), _release_info(root)),
    )


class BenchmarkParser(BaseParser):
    """Parse DISA STIG benchmark definition files (XCCDF 1.1 or 1.2)."""

    def parse_all(self, path: Path, *, warn_if_empty: bool = True) -> list[Benchmark]:
        """Every <Benchmark> in the file, at any depth.

        Covers standalone XCCDF benchmarks, SCC result files (Benchmark root
        with the TestResult nested inside), and SCAP datastreams (Benchmark
        inside a component). Returns [] on invalid XML or when the file has
        no Benchmark element; ``warn_if_empty`` controls whether an empty
        result is logged (results files are probed quietly).
        """
        try:
            tree = _safe_xml_parse(path)
        except etree.XMLSyntaxError as exc:
            log.warning("Skipping benchmark %s — invalid XML: %s", path.name, exc)
            return []

        found = [
            _benchmark_from_element(el)
            for el in tree.getroot().iter()
            if not callable(el.tag) and etree.QName(el.tag).localname == "Benchmark"
        ]
        if warn_if_empty and not any(bm.rules for bm in found):
            log.warning("Benchmark %s: no rules found", path.name)
        return found

    def parse(self, path: Path) -> Benchmark | None:
        """The first Benchmark in the file (kept for existing callers).

        Returns None on XML parse error. A well-formed file with no Benchmark
        element yields an empty Benchmark built from the root, as before.
        """
        try:
            tree = _safe_xml_parse(path)
        except etree.XMLSyntaxError as exc:
            log.warning("Skipping benchmark %s — invalid XML: %s", path.name, exc)
            return None
        root = tree.getroot()
        for el in root.iter():
            if not callable(el.tag) and etree.QName(el.tag).localname == "Benchmark":
                benchmark = _benchmark_from_element(el)
                break
        else:
            benchmark = _benchmark_from_element(root)
        if not benchmark.rules:
            log.warning("Benchmark %s: no rules found", path.name)
        return benchmark
```

- [ ] **Step 5: Run the two files, then the whole suite**

Run: `python -m pytest tests/test_benchmark_parser.py tests/test_findings_io.py tests/test_reference_fixtures.py -q -p no:cacheprovider` → passed.
Run: `python -m pytest -q -p no:cacheprovider` → no regressions.

- [ ] **Step 6: Commit** — `feat(reference): benchmark parser reads every Benchmark, STIG ID and release; new Finding fields`
Files: `app/parsers/base.py app/parsers/benchmark_parser.py tests/test_benchmark_parser.py tests/test_findings_io.py`

---

### Task 4: Reference models and library

**Files:**
- Create: `app/reference/models.py`, `app/reference/library.py`
- Test: `tests/test_reference_library.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_reference_library.py
from pathlib import Path

from app.parsers.base import Finding
from app.parsers.benchmark_parser import BenchmarkParser
from app.reference.library import ReferenceLibrary

FIX = Path(__file__).parent / "fixtures"


def _finding(rule_id="", vuln_id="", stig_id=""):
    return Finding("", vuln_id, rule_id, "", "Open", "h", "i", "", "", stig_id=stig_id)


def _library():
    lib = ReferenceLibrary()
    scc = BenchmarkParser().parse(FIX / "scc_embedded_results.xml")
    manual = BenchmarkParser().parse(FIX / "manual_stig_win11.xml")
    lib.add_benchmark(scc, "scc_embedded_results.xml", embedded=True)
    lib.add_benchmark(manual, "manual_stig_win11.xml", embedded=False)
    return lib


def test_sources_record_edition_release_and_counts():
    lib = _library()
    by_file = {s.file_name: s for s in lib.sources}
    assert by_file["scc_embedded_results.xml"].edition == "scap"
    assert by_file["scc_embedded_results.xml"].embedded is True
    assert by_file["scc_embedded_results.xml"].rule_count == 4
    assert by_file["manual_stig_win11.xml"].edition == "manual"
    assert by_file["manual_stig_win11.xml"].release == "V2R9"
    assert by_file["manual_stig_win11.xml"].benchmark_id == "MS_Windows_11_STIG"
    assert lib.has_standalone is True


def test_long_form_rule_id_finds_the_short_form_manual_rule():
    cands = _library().candidates(_finding("xccdf_mil.disa.stig_rule_SV-253284r958928_rule"))
    assert [c.source.file_name for c in cands] == ["manual_stig_win11.xml", "scc_embedded_results.xml"]
    assert cands[0].check_text and not cands[1].check_text


def test_stem_match_across_revisions_prefers_the_same_revision():
    cands = _library().candidates(_finding("xccdf_mil.disa.stig_rule_SV-253285r958930_rule"))
    # exact-revision hit (the embedded SCAP rule) first, then the Manual rule of another revision
    assert [(c.source.file_name, c.revision) for c in cands] == [
        ("scc_embedded_results.xml", "r958930"),
        ("manual_stig_win11.xml", "r991589"),
    ]


def test_vuln_id_and_stig_id_lookups():
    lib = _library()
    assert lib.candidates(_finding(vuln_id="V-253287"))[0].rule_stem == "SV-253287"
    assert lib.candidates(_finding(stig_id="wn11_00_000175"))[0].vuln_id == "V-253287"


def test_no_keys_no_candidates():
    assert _library().candidates(_finding()) == []
    assert ReferenceLibrary().has_standalone is False
```

- [ ] **Step 2: Run — fails with `ModuleNotFoundError: app.reference.library`**

- [ ] **Step 3: Implement**

```python
# app/reference/models.py
"""Data carried by the reference library."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ReferenceSource:
    """One STIG benchmark the run loaded, from one file."""
    file_name: str
    benchmark_id: str   # prefix stripped
    title: str
    release: str        # "V2R8"
    embedded: bool      # True when lifted from a results file (SCC, results CKLB)
    edition: str        # "manual" | "scap" | "cklb"
    rule_count: int


@dataclass
class ReferenceRule:
    """One rule of one source."""
    vuln_id: str
    rule_id: str        # prefix stripped, revision kept
    rule_stem: str
    revision: str
    stig_id: str
    severity: str
    stig_title: str
    check_text: str
    fix_text: str
    source: ReferenceSource
    order: int = 0      # load order, set by the library
```

```python
# app/reference/library.py
"""Every STIG rule the run knows about, indexed by the three stable keys."""
from __future__ import annotations

from collections import defaultdict

from app.parsers.base import Benchmark, Finding
from app.reference.models import ReferenceRule, ReferenceSource
from app.reference.normalize import (
    norm_benchmark_id,
    norm_stig_id,
    rule_revision,
    rule_stem,
    strip_group_prefix,
    strip_rule_prefix,
)


class ReferenceLibrary:
    def __init__(self) -> None:
        self.sources: list[ReferenceSource] = []
        self._count = 0
        self._by_rule_id: dict[str, list[ReferenceRule]] = defaultdict(list)
        self._by_stem: dict[str, list[ReferenceRule]] = defaultdict(list)
        self._by_vuln: dict[str, list[ReferenceRule]] = defaultdict(list)
        self._by_stig_id: dict[str, list[ReferenceRule]] = defaultdict(list)

    @property
    def has_standalone(self) -> bool:
        """True when the operator supplied at least one reference."""
        return any(not s.embedded for s in self.sources)

    def add_benchmark(self, benchmark: Benchmark, file_name: str, *, embedded: bool) -> ReferenceSource:
        """Load a parsed XCCDF benchmark (Manual STIG, SCAP benchmark, SCC-embedded)."""
        edition = "manual" if any(r.check_text for r in benchmark.rules.values()) else "scap"
        source = ReferenceSource(
            file_name=file_name,
            benchmark_id=norm_benchmark_id(benchmark.benchmark_id),
            title=benchmark.title,
            release=benchmark.release,
            embedded=embedded,
            edition=edition,
            rule_count=len(benchmark.rules),
        )
        rules = [
            ReferenceRule(
                vuln_id=strip_group_prefix(r.vuln_id),
                rule_id=strip_rule_prefix(r.rule_id),
                rule_stem=rule_stem(r.rule_id),
                revision=rule_revision(r.rule_id),
                stig_id=norm_stig_id(r.stig_id),
                severity="" if r.severity == "Unknown" else r.severity,
                stig_title=benchmark.title,
                check_text=r.check_text,
                fix_text=r.fix_text,
                source=source,
            )
            for r in benchmark.rules.values()
        ]
        self.add_rules(source, rules)
        return source

    def add_rules(self, source: ReferenceSource, rules: list[ReferenceRule]) -> None:
        self.sources.append(source)
        for rule in rules:
            self._count += 1
            rule.order = self._count
            for index, key in (
                (self._by_rule_id, rule.rule_id.upper()),
                (self._by_stem, rule.rule_stem.upper()),
                (self._by_vuln, rule.vuln_id.upper()),
                (self._by_stig_id, rule.stig_id),
            ):
                if key:
                    index[key].append(rule)

    def candidates(self, finding: Finding) -> list[ReferenceRule]:
        """Rules that may describe *finding*, best first.

        Keys are tried in order: exact rule ID, rule stem, V-ID, STIG ID.
        Within one key: same revision as the finding first, then operator-
        supplied sources before embedded ones, then load order.
        """
        revision = rule_revision(finding.rule_id)

        def rank(rule: ReferenceRule) -> tuple[int, int, int]:
            same_revision = bool(revision) and rule.revision == revision
            return (0 if same_revision else 1, 1 if rule.source.embedded else 0, rule.order)

        lookups = (
            (self._by_rule_id, strip_rule_prefix(finding.rule_id).upper()),
            (self._by_stem, rule_stem(finding.rule_id).upper()),
            (self._by_vuln, (finding.vuln_id or "").strip().upper()),
            (self._by_stig_id, norm_stig_id(finding.stig_id)),
        )
        seen: set[int] = set()
        out: list[ReferenceRule] = []
        for index, key in lookups:
            if not key:
                continue
            for rule in sorted(index.get(key, ()), key=rank):
                if id(rule) not in seen:
                    seen.add(id(rule))
                    out.append(rule)
        return out
```

- [ ] **Step 4: Run — passes.** `python -m pytest tests/test_reference_library.py -q -p no:cacheprovider`

- [ ] **Step 5: Commit** — `feat(reference): reference library indexed by rule ID, stem, V-ID and STIG ID`
Files: `app/reference/models.py app/reference/library.py tests/test_reference_library.py`

---

### Task 5: CKLB as a reference

**Files:**
- Create: `app/reference/cklb_loader.py`
- Test: `tests/test_cklb_reference_loader.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_cklb_reference_loader.py
from pathlib import Path

from app.reference.cklb_loader import load_cklb_reference

FIX = Path(__file__).parent / "fixtures"


def test_loads_every_rule_with_text_and_ids():
    loaded = load_cklb_reference(FIX / "evaluate_stig_checklist.cklb", embedded=False)
    assert len(loaded) == 1
    source, rules = loaded[0]
    assert (source.edition, source.embedded, source.release) == ("cklb", False, "V1R4")
    assert source.title == "Microsoft Windows Server 2022 STIG"
    assert source.rule_count == 5
    first = rules[0]
    assert (first.vuln_id, first.rule_id, first.rule_stem, first.revision) == (
        "V-254239", "SV-254239r958472_rule", "SV-254239", "r958472")
    assert first.stig_id == "WN22-00-000010"
    assert first.severity == "CAT I"
    assert first.check_text and first.fix_text


def test_invalid_or_non_cklb_json_returns_empty(tmp_path):
    bad = tmp_path / "bad.cklb"
    bad.write_text("{not json", encoding="utf-8")
    assert load_cklb_reference(bad, embedded=False) == []
    other = tmp_path / "other.cklb"
    other.write_text('{"hello": 1}', encoding="utf-8")
    assert load_cklb_reference(other, embedded=False) == []
```

- [ ] **Step 2: Run — fails with `ModuleNotFoundError`**

- [ ] **Step 3: Implement**

```python
# app/reference/cklb_loader.py
"""Read a CKLB checklist (STIG Viewer 3 / Evaluate-STIG) as a STIG reference.

A CKLB carries the whole STIG text, so one made from the Manual STIG is as
good a source of check text as the Manual STIG itself.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from app.reference.models import ReferenceRule, ReferenceSource
from app.reference.normalize import norm_stig_id, release_label, rule_revision, rule_stem

log = logging.getLogger(__name__)

_SEVERITY = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}


def load_cklb_reference(path: Path, *, embedded: bool) -> list[tuple[ReferenceSource, list[ReferenceRule]]]:
    """One (source, rules) pair per STIG in the checklist; [] if it is not a CKLB."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        log.warning("Skipping reference %s — not valid JSON: %s", path.name, exc)
        return []
    stigs = doc.get("stigs") if isinstance(doc, dict) else None
    if not isinstance(stigs, list):
        log.warning("%s: no 'stigs' array — not a CKLB checklist", path.name)
        return []

    out: list[tuple[ReferenceSource, list[ReferenceRule]]] = []
    for stig in stigs:
        if not isinstance(stig, dict) or not isinstance(stig.get("rules"), list):
            continue
        title = str(stig.get("display_name") or stig.get("stig_name") or stig.get("stig_id") or "").strip()
        raw_rules = [r for r in stig["rules"] if isinstance(r, dict)]
        source = ReferenceSource(
            file_name=path.name,
            benchmark_id=str(stig.get("stig_id") or "").strip(),
            title=title,
            release=release_label(str(stig.get("version") or ""), str(stig.get("release_info") or "")),
            embedded=embedded,
            edition="cklb",
            rule_count=len(raw_rules),
        )
        rules = []
        for r in raw_rules:
            rule_id = str(r.get("rule_id_src") or r.get("rule_id") or "").strip()
            rules.append(ReferenceRule(
                vuln_id=str(r.get("group_id") or r.get("group_id_src") or "").strip(),
                rule_id=rule_id,
                rule_stem=rule_stem(rule_id),
                revision=rule_revision(rule_id),
                stig_id=norm_stig_id(str(r.get("rule_version") or "")),
                severity=_SEVERITY.get(str(r.get("severity") or "").strip().lower(), ""),
                stig_title=title,
                check_text=str(r.get("check_content") or "").strip(),
                fix_text=str(r.get("fix_text") or "").strip(),
                source=source,
            ))
        out.append((source, rules))
    return out
```

- [ ] **Step 4: Run — passes.** `python -m pytest tests/test_cklb_reference_loader.py -q -p no:cacheprovider`

- [ ] **Step 5: Commit** — `feat(reference): load a CKLB checklist as a STIG reference`
Files: `app/reference/cklb_loader.py tests/test_cklb_reference_loader.py`

---

### Task 6: The Text Source cell

**Files:**
- Create: `app/reference/text_source.py`
- Test: `tests/test_text_source.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_text_source.py
from app.reference.models import ReferenceRule, ReferenceSource
from app.reference.text_source import source_phrase, text_source_cell


def _rule(revision="r1", release="V2R9", file_name="manual.xml"):
    src = ReferenceSource(file_name, "X", "T", release, False, "manual", 1)
    return ReferenceRule("V-1", f"SV-1{revision}_rule", "SV-1", revision, "", "", "T", "c", "f", src)


def test_scanner_supplied_text():
    assert source_phrase(None, scanner=True, finding_revision="r1", scan_release="V2R8", references_supplied=True) == "scanner"


def test_filled_from_the_same_revision():
    assert source_phrase(_rule("r1"), scanner=False, finding_revision="r1", scan_release="V2R8",
                         references_supplied=True) == "manual.xml V2R9"


def test_filled_from_a_different_revision_names_the_scanned_release():
    assert source_phrase(_rule("r2"), scanner=False, finding_revision="r1", scan_release="V2R8",
                         references_supplied=True) == "manual.xml V2R9, scanned V2R8"


def test_different_revision_without_a_distinct_scanned_release():
    for scan_release in ("", "V2R9"):
        assert source_phrase(_rule("r2"), scanner=False, finding_revision="r1", scan_release=scan_release,
                             references_supplied=True) == "manual.xml V2R9, revision differs from scan"


def test_finding_without_a_revision_is_not_called_drift():
    assert source_phrase(_rule("r2"), scanner=False, finding_revision="", scan_release="",
                         references_supplied=True) == "manual.xml V2R9"


def test_nothing_filled():
    assert source_phrase(None, scanner=False, finding_revision="r1", scan_release="",
                         references_supplied=True) == "not in supplied references"
    assert source_phrase(None, scanner=False, finding_revision="r1", scan_release="",
                         references_supplied=False) == "no reference supplied"


def test_cell_text():
    assert text_source_cell("scanner", "scanner") == "Check and fix: scanner"
    assert text_source_cell("manual.xml V2R9", "scanner") == "Check: manual.xml V2R9 | Fix: scanner"
```

- [ ] **Step 2: Run — fails with `ModuleNotFoundError`**

- [ ] **Step 3: Implement**

```python
# app/reference/text_source.py
"""The Text Source column: where each row's check and fix text came from."""
from __future__ import annotations

from app.reference.models import ReferenceRule


def source_phrase(
    origin: ReferenceRule | None,
    *,
    scanner: bool,
    finding_revision: str,
    scan_release: str,
    references_supplied: bool,
) -> str:
    """Describe the source of one text field.

    ``scanner`` is True when the scan itself carried the text. ``origin`` is
    the reference rule that filled it, or None when nothing did.
    """
    if scanner:
        return "scanner"
    if origin is None:
        return "not in supplied references" if references_supplied else "no reference supplied"
    label = f"{origin.source.file_name} {origin.source.release}".strip()
    differs = bool(finding_revision) and bool(origin.revision) and origin.revision != finding_revision
    if not differs:
        return label
    if scan_release and scan_release != origin.source.release:
        return f"{label}, scanned {scan_release}"
    return f"{label}, revision differs from scan"


def text_source_cell(check_phrase: str, fix_phrase: str) -> str:
    if check_phrase == fix_phrase:
        return f"Check and fix: {check_phrase}"
    return f"Check: {check_phrase} | Fix: {fix_phrase}"
```

- [ ] **Step 4: Run — passes.** `python -m pytest tests/test_text_source.py -q -p no:cacheprovider`

- [ ] **Step 5: Commit** — `feat(reference): Text Source cell wording`
Files: `app/reference/text_source.py tests/test_text_source.py`

---

### Task 7: Enrichment

**Files:**
- Create: `app/reference/enrich.py`
- Test: `tests/test_enrich.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_enrich.py
from pathlib import Path

from app.parsers.base import Finding
from app.parsers.benchmark_parser import BenchmarkParser
from app.reference.cklb_loader import load_cklb_reference
from app.reference.enrich import EnrichmentReport, enrich_findings
from app.reference.library import ReferenceLibrary

FIX = Path(__file__).parent / "fixtures"
TITLE = "Microsoft Windows 11 STIG SCAP Benchmark"


def _scc_finding(num, revision, fix="scanner fix"):
    """A finding as the matcher produces it from the SCC fixture: fix text, no check text."""
    return Finding(TITLE, f"V-{num}", f"xccdf_mil.disa.stig_rule_SV-{num}{revision}_rule", "CAT II",
                   "Open", "WKSTN-01", "10.0.0.21", "", fix, scan_release="V2R8")


def _library(with_manual=True):
    lib = ReferenceLibrary()
    lib.add_benchmark(BenchmarkParser().parse(FIX / "scc_embedded_results.xml"), "scc_embedded_results.xml", embedded=True)
    if with_manual:
        lib.add_benchmark(BenchmarkParser().parse(FIX / "manual_stig_win11.xml"), "manual_stig_win11.xml", embedded=False)
    return lib


def test_fills_blank_check_text_and_never_overwrites_scanner_text():
    f = _scc_finding(253284, "r958928")
    enrich_findings([f], _library())
    assert f.check_text.startswith("Verify the registry value")
    assert f.fix_text == "scanner fix"                       # untouched
    assert f.stig_id == "WN11-00-000150"                     # blank on the finding, filled from a candidate
    assert f.text_source == "Check: manual_stig_win11.xml V2R9 | Fix: scanner"


def test_different_revision_is_filled_and_counted_as_drift():
    f = _scc_finding(253285, "r958930")
    report = enrich_findings([f], _library())
    assert f.check_text.startswith("Run Get-WindowsOptionalFeature")
    assert f.text_source == "Check: manual_stig_win11.xml V2R9, scanned V2R8 | Fix: scanner"
    assert report.stigs[TITLE].drifted == 1
    assert any("different release" in w and "V2R9" in w and "V2R8" in w for w in report.warnings())


def test_rule_missing_from_the_supplied_reference_is_reported():
    # Two findings so the STIG is only partly unmatched; a fully unmatched STIG
    # gets the "wrong product" wording instead (tested below).
    f = _scc_finding(253286, "r958932")
    report = enrich_findings([_scc_finding(253284, "r958928"), f], _library())
    assert f.check_text == ""
    assert f.text_source == "Check: not in supplied references | Fix: scanner"
    assert report.stigs[TITLE].unmatched == 1
    assert any("not found in any supplied reference" in w and "SV-253286" in w for w in report.warnings())


def test_no_reference_supplied_explains_the_blank_check_text_once():
    findings = [_scc_finding(253284, "r958928"), _scc_finding(253285, "r958930")]
    report = enrich_findings(findings, _library(with_manual=False))
    assert all(f.text_source == "Check: no reference supplied | Fix: scanner" for f in findings)
    warnings = report.warnings()
    assert len(warnings) == 1
    assert "Check text is blank for 2 finding(s)" in warnings[0] and "Manual STIG" in warnings[0]


def test_fully_blank_finding_is_filled_from_a_stem_match_then_re_resolved():
    # As produced when the scan matched no benchmark rule: only server and rule ID are known.
    f = Finding("", "", "xccdf_mil.disa.stig_rule_SV-253285r958930_rule", "", "Open", "h", "i", "", "")
    lib = ReferenceLibrary()
    lib.add_benchmark(BenchmarkParser().parse(FIX / "manual_stig_win11.xml"), "manual_stig_win11.xml", embedded=False)
    enrich_findings([f], lib)
    assert (f.vuln_id, f.stig_id, f.severity) == ("V-253285", "WN11-00-000160", "CAT II")
    assert f.stig_title == "Microsoft Windows 11 Security Technical Implementation Guide"
    assert f.check_text and f.fix_text
    assert f.text_source == "Check and fix: manual_stig_win11.xml V2R9, revision differs from scan"


def test_cklb_reference_fills_a_finding_from_another_scanner():
    f = Finding("Nessus Compliance", "V-254239", "SV-254239r945408_rule", "CAT I", "Open", "h", "i", "", "")
    lib = ReferenceLibrary()
    for source, rules in load_cklb_reference(FIX / "evaluate_stig_checklist.cklb", embedded=False):
        lib.add_rules(source, rules)
    enrich_findings([f], lib)
    assert f.check_text and f.fix_text and f.stig_id == "WN22-00-000010"
    assert f.stig_title == "Nessus Compliance"               # non-blank title is never replaced


def test_wrong_product_reference_says_so():
    findings = [_scc_finding(253284, "r958928")]
    lib = ReferenceLibrary()
    lib.add_benchmark(BenchmarkParser().parse(FIX / "scc_embedded_results.xml"), "scc_embedded_results.xml", embedded=True)
    lib.add_benchmark(BenchmarkParser().parse(FIX / "manual_stig_server2022.xml"), "manual_stig_server2022.xml", embedded=False)
    warnings = enrich_findings(findings, lib).warnings()
    assert any("none of 1 finding(s) matched a supplied reference" in w
               and "Microsoft Windows Server 2022 Security Technical Implementation Guide V2R8" in w for w in warnings)


def test_report_round_trips_through_json():
    report = enrich_findings([_scc_finding(253285, "r958930")], _library())
    again = EnrichmentReport.from_dict(report.to_dict())
    assert again.warnings() == report.warnings()
    assert [s.file_name for s in again.standalone_sources] == ["manual_stig_win11.xml"]
    assert again.source_counts["manual_stig_win11.xml"]["filled_check"] == 1
```

- [ ] **Step 2: Run — fails with `ModuleNotFoundError: app.reference.enrich`**

- [ ] **Step 3: Implement**

```python
# app/reference/enrich.py
"""Fill blank finding fields from the reference library and report what happened.

Runs on actionable findings only, so every count here is a row of the report.
Scanner-supplied values are never overwritten: the finding was evaluated
against the scanned benchmark, and the reference only fills gaps.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field

from app.parsers.base import Finding
from app.reference.library import ReferenceLibrary
from app.reference.models import ReferenceRule, ReferenceSource
from app.reference.normalize import rule_revision, rule_stem
from app.reference.text_source import source_phrase, text_source_cell

_FILL_FIELDS = ("check_text", "fix_text", "severity", "vuln_id", "stig_id", "stig_title")
_NO_TITLE = "(no STIG title)"
_MAX_IDS = 5


@dataclass
class StigCounts:
    findings: int = 0
    filled_check: int = 0
    filled_fix: int = 0
    filled_severity: int = 0
    drifted: int = 0
    unmatched: int = 0
    blank_check_with_fix: int = 0
    unmatched_ids: list[str] = field(default_factory=list)
    drift_pair: str = ""        # most common "reference VxRy, scanned VaRb"


@dataclass
class EnrichmentReport:
    stigs: dict[str, StigCounts] = field(default_factory=dict)
    sources: list[ReferenceSource] = field(default_factory=list)
    # file name -> {"filled_check": n, "filled_fix": n, "drifted": n}
    source_counts: dict[str, dict[str, int]] = field(default_factory=dict)

    @property
    def standalone_sources(self) -> list[ReferenceSource]:
        return [s for s in self.sources if not s.embedded]

    def warnings(self) -> list[str]:
        """Operator-facing lines, one per STIG and kind, only when non-zero."""
        out: list[str] = []
        loaded = "; ".join(f"{s.title} {s.release}".strip() for s in self.standalone_sources)
        for title, c in self.stigs.items():
            if c.drifted:
                pair = f" ({c.drift_pair})" if c.drift_pair else ""
                out.append(
                    f"{title}: {c.drifted} rule(s) took check/fix text from a different "
                    f"release{pair} — see the Text Source column"
                )
            if c.unmatched and c.unmatched == c.findings:
                out.append(
                    f"{title}: none of {c.findings} finding(s) matched a supplied reference "
                    f"(loaded: {loaded}) — wrong product or STIG?"
                )
            elif c.unmatched:
                ids = ", ".join(c.unmatched_ids[:_MAX_IDS]) + ("…" if len(c.unmatched_ids) > _MAX_IDS else "")
                out.append(f"{title}: {c.unmatched} rule(s) not found in any supplied reference: {ids}")
        blank = {t: c.blank_check_with_fix for t, c in self.stigs.items() if c.blank_check_with_fix}
        if blank:
            out.append(
                f"Check text is blank for {sum(blank.values())} finding(s) in {len(blank)} STIG(s): "
                f"{'; '.join(blank)}. SCC results and SCAP Benchmark files carry fix text but no "
                "check text — add the Manual STIG (DISA STIG ZIP or *_Manual-xccdf.xml) as a "
                "reference to fill it."
            )
        return out

    def to_dict(self) -> dict:
        return {
            "stigs": {t: asdict(c) for t, c in self.stigs.items()},
            "sources": [asdict(s) for s in self.sources],
            "source_counts": self.source_counts,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EnrichmentReport":
        return cls(
            stigs={t: StigCounts(**c) for t, c in (data.get("stigs") or {}).items()},
            sources=[ReferenceSource(**s) for s in (data.get("sources") or [])],
            source_counts=dict(data.get("source_counts") or {}),
        )


def _fill(finding: Finding, candidates: list[ReferenceRule], origin: dict[str, ReferenceRule]) -> None:
    for name in _FILL_FIELDS:
        if getattr(finding, name):
            continue
        for rule in candidates:
            value = getattr(rule, name)
            if value:
                setattr(finding, name, value)
                origin[name] = rule
                break


def enrich_findings(findings: list[Finding], library: ReferenceLibrary) -> EnrichmentReport:
    """Fill blanks in place and return the report."""
    report = EnrichmentReport(sources=list(library.sources))
    references_supplied = library.has_standalone
    drift_pairs: dict[str, Counter] = {}

    for f in findings:
        had_check, had_fix = bool(f.check_text), bool(f.fix_text)
        origin: dict[str, ReferenceRule] = {}
        candidates = library.candidates(f)
        _fill(f, candidates, origin)
        if "vuln_id" in origin or "stig_id" in origin:
            # New identifiers can reach rules the first pass could not.
            candidates = library.candidates(f)
            _fill(f, candidates, origin)

        revision = rule_revision(f.rule_id)
        phrases = {
            name: source_phrase(
                origin.get(name), scanner=had, finding_revision=revision,
                scan_release=f.scan_release, references_supplied=references_supplied,
            )
            for name, had in (("check_text", had_check), ("fix_text", had_fix))
        }
        f.text_source = text_source_cell(phrases["check_text"], phrases["fix_text"])

        title = f.stig_title or _NO_TITLE
        counts = report.stigs.setdefault(title, StigCounts())
        counts.findings += 1
        counts.filled_severity += "severity" in origin
        drifted = False
        for name, counter in (("check_text", "filled_check"), ("fix_text", "filled_fix")):
            rule = origin.get(name)
            if rule is None:
                continue
            setattr(counts, counter, getattr(counts, counter) + 1)
            per_source = report.source_counts.setdefault(
                rule.source.file_name, {"filled_check": 0, "filled_fix": 0, "drifted": 0})
            per_source[counter] += 1
            if revision and rule.revision and rule.revision != revision:
                drifted = True
                per_source["drifted"] += 1
                pair = f"reference {rule.source.release}" + (
                    f", scanned {f.scan_release}" if f.scan_release and f.scan_release != rule.source.release else "")
                drift_pairs.setdefault(title, Counter())[pair] += 1
        counts.drifted += drifted

        has_standalone_candidate = any(not c.source.embedded for c in candidates)
        if references_supplied and not has_standalone_candidate:
            counts.unmatched += 1
            counts.unmatched_ids.append(rule_stem(f.rule_id) or f.vuln_id or "(no rule ID)")
        elif not f.check_text and f.fix_text:
            counts.blank_check_with_fix += 1

    for title, pairs in drift_pairs.items():
        report.stigs[title].drift_pair = pairs.most_common(1)[0][0]
    return report
```

- [ ] **Step 4: Run — passes.** `python -m pytest tests/test_enrich.py -q -p no:cacheprovider`

- [ ] **Step 5: Commit** — `feat(reference): enrichment pass that fills blanks, records text source, and reports gaps`
Files: `app/reference/enrich.py tests/test_enrich.py`

---

### Task 8: Matcher records STIG ID and scanned release, and returns its problems

**Files:**
- Modify: `app/processors/matcher.py`
- Test: `tests/test_matcher.py` (append)

- [ ] **Step 1: Write the failing tests** (append)

```python
# tests/test_matcher.py  (append)
from pathlib import Path as _P

from app.parsers.benchmark_parser import BenchmarkParser as _BPm
from app.parsers.xccdf_parser import XCCDFResultsParser as _XP
from app.processors.matcher import MatchIssue, unresolved_issue_warnings

_FIXm = _P(__file__).parent / "fixtures"


class TestNewFindingFieldsAndIssues:
    def test_findings_carry_stig_id_and_scanned_release(self):
        scan = _XP().parse(_FIXm / "scc_embedded_results.xml")
        bm = _BPm().parse(_FIXm / "scc_embedded_results.xml")
        findings = match_results_to_benchmarks([scan], [bm])
        assert {f.stig_id for f in findings} == {"WN11-00-000150", "WN11-00-000160", "WN11-00-000170"}
        assert {f.scan_release for f in findings} == {"V2R8"}

    def test_rule_id_mismatch_is_returned_as_an_issue(self):
        scan = _XP().parse(_FIXm / "evaluate_stig_results.xml")
        manual = _BPm().parse(_FIXm / "manual_stig_server2022.xml")
        issues: list[MatchIssue] = []
        findings = match_results_to_benchmarks([scan], [manual], issues)
        assert len(findings) == 3 and all(f.stig_title for f in findings)
        assert [i.kind for i in issues] == ["rules-not-found"]
        assert len(issues[0].keys) == 3

    def test_no_benchmark_at_all_is_an_issue(self):
        scan = _XP().parse(_FIXm / "evaluate_stig_results.xml")
        issues: list[MatchIssue] = []
        match_results_to_benchmarks([scan], [], issues)
        assert [i.kind for i in issues] == ["no-benchmark"]

    def test_unresolved_no_benchmark_warns_and_resolved_one_does_not(self):
        scan = _XP().parse(_FIXm / "evaluate_stig_results.xml")
        issues: list[MatchIssue] = []
        findings = match_results_to_benchmarks([scan], [], issues)
        warnings = unresolved_issue_warnings(issues, findings, references_supplied=False)
        assert len(warnings) == 1 and "evaluate_stig_results.xml" in warnings[0]
        assert "no matching STIG benchmark" in warnings[0]
        for f in findings:
            f.stig_title = "Filled later"
        assert unresolved_issue_warnings(issues, findings, references_supplied=False) == []

    def test_rules_not_found_is_left_to_the_enrichment_report_when_references_exist(self):
        scan = _XP().parse(_FIXm / "evaluate_stig_results.xml")
        manual = _BPm().parse(_FIXm / "manual_stig_server2022.xml")
        issues: list[MatchIssue] = []
        findings = match_results_to_benchmarks([scan], [manual], issues)
        assert unresolved_issue_warnings(issues, findings, references_supplied=True) == []
        assert len(unresolved_issue_warnings(issues, findings, references_supplied=False)) == 1
```

- [ ] **Step 2: Run — fails** (`ImportError: cannot import name 'MatchIssue'`)

- [ ] **Step 3: Implement in `app/processors/matcher.py`**

Add `from dataclasses import dataclass, field` to the imports, and after `_KEEP_STATUSES`:

```python
@dataclass
class MatchIssue:
    """A matching problem, reported as data so the pipeline can decide whether
    it still matters after reference enrichment has run."""
    kind: str                 # "no-benchmark" | "rules-not-found"
    source_file: str
    benchmark_id: str
    # (server, rule_id) of every actionable finding the issue affects
    keys: set[tuple[str, str]] = field(default_factory=set)
```

Replace `match_results_to_benchmarks` with:

```python
def match_results_to_benchmarks(
    scan_results: list[ScanResult],
    benchmarks: list[Benchmark],
    issues: list[MatchIssue] | None = None,
) -> list[Finding]:
    """Merge scan results with benchmark data to produce Finding objects.

    Only actionable statuses (fail, notchecked, notselected, error, unknown)
    are included in output — all others are discarded here. Matching problems
    are appended to *issues* (when given) rather than only logged: the caller
    reports the ones that reference enrichment could not repair.
    """
    findings: list[Finding] = []

    for scan in scan_results:
        benchmark = _find_benchmark(scan.benchmark_href, scan.benchmark_id, benchmarks)
        stig_title = benchmark.title if benchmark else ""
        scan_release = benchmark.release if benchmark else ""
        actionable: set[tuple[str, str]] = set()
        unmatched: set[tuple[str, str]] = set()

        for rr in scan.rule_results:
            display_status = _STATUS_MAP.get(rr.status)
            if display_status is None:
                # Discard: pass, notapplicable, informational, fixed, etc.
                continue

            rule_def = benchmark.rules.get(rr.rule_id) if benchmark else None
            actionable.add((scan.hostname, rr.rule_id))
            if rule_def is None and benchmark is not None:
                unmatched.add((scan.hostname, rr.rule_id))

            findings.append(
                Finding(
                    stig_title=stig_title,
                    vuln_id=rule_def.vuln_id if rule_def else "",
                    rule_id=rr.rule_id,
                    severity=rule_def.severity if rule_def else "",
                    status=display_status,
                    server=scan.hostname,
                    ip_address=scan.ip_address,
                    check_text=rule_def.check_text if rule_def else "",
                    fix_text=rule_def.fix_text if rule_def else "",
                    stig_id=rule_def.stig_id if rule_def else "",
                    scan_release=scan_release,
                )
            )

        if benchmark is None and actionable:
            log.debug("%s: no benchmark matched (href=%r, id=%r)",
                      scan.source_file, scan.benchmark_href, scan.benchmark_id)
            if issues is not None:
                issues.append(MatchIssue("no-benchmark", scan.source_file, scan.benchmark_id, actionable))
        elif unmatched:
            log.debug("%s: %d rule(s) not found in benchmark '%s'",
                      scan.source_file, len(unmatched), benchmark.benchmark_id)
            if issues is not None:
                issues.append(MatchIssue("rules-not-found", scan.source_file, benchmark.benchmark_id, unmatched))

    return findings


def unresolved_issue_warnings(
    issues: list[MatchIssue],
    findings: list[Finding],
    *,
    references_supplied: bool,
) -> list[str]:
    """Operator warnings for matching problems that enrichment did not repair.

    Called after enrichment. ``rules-not-found`` is skipped when the operator
    supplied references, because the enrichment report then names the same
    rules per STIG.
    """
    by_key = {(f.server, f.rule_id): f for f in findings}
    out: list[str] = []
    for issue in issues:
        affected = [by_key[k] for k in issue.keys if k in by_key]
        if issue.kind == "no-benchmark":
            blank = [f for f in affected if not f.stig_title]
            if blank:
                out.append(
                    f"{issue.source_file}: no matching STIG benchmark — {len(blank)} finding(s) "
                    "have no STIG title, severity, or check/fix text. Add the STIG as a reference."
                )
        elif issue.kind == "rules-not-found" and not references_supplied:
            blank = [f for f in affected if not f.check_text and not f.fix_text]
            if blank:
                out.append(
                    f"{issue.source_file}: {len(blank)} rule(s) not found in benchmark "
                    f"'{issue.benchmark_id}' — check/fix text blank"
                )
    return out
```

- [ ] **Step 4: Run the matcher tests, then the whole suite**

Run: `python -m pytest tests/test_matcher.py -q -p no:cacheprovider` → passed.
Run: `python -m pytest -q -p no:cacheprovider`. A test that asserted the old matcher log warnings (`caplog`) now asserts the `issues` list instead; anything else must still pass.

- [ ] **Step 5: Commit** — `feat(matcher): record STIG ID and scanned release; return matching problems as data`
Files: `app/processors/matcher.py tests/test_matcher.py`

---

### Task 9: CKLB and Nessus parsers populate the new fields

**Files:**
- Modify: `app/parsers/cklb_parser.py`, `app/parsers/nessus_parser.py`
- Test: `tests/test_cklb_parser.py`, `tests/test_nessus_parser.py` (append)

- [ ] **Step 1: Write the failing tests** (append)

```python
# tests/test_cklb_parser.py  (append)
def test_findings_carry_stig_id_and_release():
    from pathlib import Path
    from app.parsers.cklb_parser import CKLBParser
    findings = CKLBParser().parse(Path(__file__).parent / "fixtures" / "evaluate_stig_checklist.cklb")
    first = next(f for f in findings if f.vuln_id == "V-254239")
    assert first.stig_id == "WN22-00-000010"
    assert first.scan_release == "V1R4"
```

```python
# tests/test_nessus_parser.py  (append)
def test_findings_carry_the_stig_id_token():
    from pathlib import Path
    from app.parsers.nessus_parser import NessusComplianceParser
    findings = NessusComplianceParser().parse(Path(__file__).parent / "fixtures" / "nessus_compliance.nessus")
    with_reference = [f for f in findings if f.vuln_id]
    assert with_reference, "fixture should contain DISA-referenced items"
    assert all(f.stig_id for f in with_reference)
```

If the Nessus fixture has DISA items without a `STIG-ID` token, narrow the second assertion to the items whose `cm:compliance-reference` contains `STIG-ID|` (read the fixture first) rather than loosening it to `any`.

- [ ] **Step 2: Run — fails** (`stig_id == ""`)

- [ ] **Step 3: Implement**

`app/parsers/cklb_parser.py`: add `from app.reference.normalize import norm_stig_id, release_label`; inside the `for stig in stigs:` loop, after `stig_title` is computed, add:

```python
            scan_release = release_label(
                str(stig.get("version") or ""), str(stig.get("release_info") or "")
            )
```

and in the `Finding(...)` call add:

```python
                        stig_id=norm_stig_id(str(rule.get("rule_version") or "")),
                        scan_release=scan_release,
```

`app/parsers/nessus_parser.py`: add `from app.reference.normalize import norm_stig_id`; in the `Finding(...)` call add:

```python
                        stig_id=norm_stig_id(tokens.get("STIG-ID", "")),
```

- [ ] **Step 4: Run — passes.** `python -m pytest tests/test_cklb_parser.py tests/test_nessus_parser.py -q -p no:cacheprovider`

- [ ] **Step 5: Commit** — `feat(parsers): CKLB and Nessus findings carry the STIG ID and scanned release`
Files: `app/parsers/cklb_parser.py app/parsers/nessus_parser.py tests/test_cklb_parser.py tests/test_nessus_parser.py`

---

### Task 10: Content-based input routing and reference ZIP members

**Files:**
- Create: `app/core/inputs.py`
- Modify: `app/utils/zip_extract.py`
- Test: `tests/test_inputs.py`, `tests/test_zip_extract.py` (append)

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_inputs.py
import zipfile
from pathlib import Path

from app.core.inputs import classify_inputs, sniff_xml

FIX = Path(__file__).parent / "fixtures"


def test_sniff_xml():
    assert sniff_xml(FIX / "scc_embedded_results.xml") == "results"      # Benchmark root, TestResult nested
    assert sniff_xml(FIX / "evaluate_stig_results.xml") == "results"
    assert sniff_xml(FIX / "manual_stig_win11.xml") == "benchmark"
    assert sniff_xml(FIX / "scap_datastream_win11.xml") == "benchmark"
    assert sniff_xml(FIX / "legacy_checklist.ckl.xml") == "other"


def test_sniff_xml_invalid_is_other(tmp_path):
    bad = tmp_path / "bad.xml"
    bad.write_text("<Benchmark", encoding="utf-8")
    assert sniff_xml(bad) == "other"


def test_a_benchmark_in_the_results_list_is_routed_to_references(tmp_path):
    c = classify_inputs([FIX / "evaluate_stig_results.xml", FIX / "manual_stig_server2022.xml"], [], tmp_path)
    assert [p.name for p in c.xccdf_results] == ["evaluate_stig_results.xml"]
    assert [p.name for p in c.reference_xml] == ["manual_stig_server2022.xml"]


def test_results_in_the_reference_list_are_routed_to_results(tmp_path):
    c = classify_inputs([], [FIX / "scc_embedded_results.xml"], tmp_path)
    assert [p.name for p in c.xccdf_results] == ["scc_embedded_results.xml"]
    assert c.reference_xml == []


def test_cklb_is_results_unless_it_came_through_the_reference_list(tmp_path):
    cklb = FIX / "evaluate_stig_checklist.cklb"
    as_results = classify_inputs([cklb], [], tmp_path)
    assert as_results.self_contained == [cklb] and as_results.reference_cklb == []
    as_reference = classify_inputs([], [cklb], tmp_path)
    assert as_reference.self_contained == [] and as_reference.reference_cklb == [cklb]


def test_nessus_and_unrecognised_xml_keep_their_list(tmp_path):
    c = classify_inputs([FIX / "nessus_compliance.nessus", FIX / "legacy_checklist.ckl.xml"], [], tmp_path)
    assert [p.name for p in c.self_contained] == ["nessus_compliance.nessus"]
    assert [p.name for p in c.xccdf_results] == ["legacy_checklist.ckl.xml"]   # the parser explains the .ckl case


def test_reference_zip_is_expanded_and_typed(tmp_path):
    z = tmp_path / "U_MS_Windows_11_V2R9_STIG.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.write(FIX / "manual_stig_win11.xml", "U_MS_Windows_11_V2R9_Manual_STIG/U_MS_Windows_11_STIG_V2R9_Manual-xccdf.xml")
        zf.write(FIX / "scap_datastream_win11.xml", "U_MS_Windows_11_V2R8_STIG_SCAP_1-3_Benchmark.xml")
        zf.write(FIX / "evaluate_stig_checklist.cklb", "checklist.cklb")
        zf.writestr("readme.txt", "ignored")
    c = classify_inputs([], [z], tmp_path / "x")
    assert sorted(p.name for p in c.reference_xml) == [
        "U_MS_Windows_11_STIG_V2R9_Manual-xccdf.xml", "U_MS_Windows_11_V2R8_STIG_SCAP_1-3_Benchmark.xml"]
    assert [p.name for p in c.reference_cklb] == ["checklist.cklb"]
    assert c.warnings == []


def test_zip_without_reference_content_warns(tmp_path):
    z = tmp_path / "empty.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("readme.txt", "nothing")
    c = classify_inputs([], [z], tmp_path / "x")
    assert len(c.warnings) == 1 and "empty.zip" in c.warnings[0]
```

```python
# tests/test_zip_extract.py  (append)
def test_extracts_scap_datastreams_and_checklists(tmp_path):
    import zipfile
    from app.utils.zip_extract import extract_xccdf_from_zip
    z = tmp_path / "bundle.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("U_X_V1R1_STIG_SCAP_1-3_Benchmark.xml", "<a/>")
        zf.writestr("U_X_STIG_V1R1_Manual-xccdf.xml", "<a/>")
        zf.writestr("list.cklb", "{}")
        zf.writestr("U_X_V1R1_STIG_SCAP_1-2_Benchmark-oval.xml", "<a/>")
        zf.writestr("U_X_V1R1_STIG_SCAP_1-2_Benchmark-cpe-dictionary.xml", "<a/>")
    names = sorted(p.name for p in extract_xccdf_from_zip(z, tmp_path / "out"))
    assert names == ["U_X_STIG_V1R1_Manual-xccdf.xml", "U_X_V1R1_STIG_SCAP_1-3_Benchmark.xml", "list.cklb"]
```

- [ ] **Step 2: Run — fails** (`ModuleNotFoundError: app.core.inputs`; the ZIP test extracts only the `xccdf.xml` member)

- [ ] **Step 3: Extend `app/utils/zip_extract.py`**

Replace the `_XCCDF_SUFFIX` constant with:

```python
# Archive members treated as STIG reference content (case-insensitive suffixes):
# Manual STIG / SCAP 1.2 XCCDF, SCAP 1.3 source datastreams, and checklists.
_REFERENCE_SUFFIXES = ("xccdf.xml", "_benchmark.xml", ".cklb")
```

and in `extract_xccdf_from_zip` replace `if lower.endswith(_XCCDF_SUFFIX):` with `if lower.endswith(_REFERENCE_SUFFIXES):`. In `expand_benchmark_paths` change the warning text to:

```python
            warnings.append(
                f"No STIG reference found in {p.name} (expected a *xccdf.xml, "
                f"*_Benchmark.xml, or .cklb file inside the zip)"
            )
```

Update the module docstring's first line to "Extract STIG reference files from DISA distribution ZIPs." If an existing test pins the old warning sentence, update it to the new one.

- [ ] **Step 4: Create `app/core/inputs.py`**

```python
# app/core/inputs.py
"""Route uploaded files by what they contain, not by which slot they came from.

The GovCloud SPA sends one flat file list, and operators drop a Manual STIG in
the results zone as often as not. Only two cases are re-routed: a benchmark
found among the results becomes a reference, and scan results found among the
references become results. Everything else keeps its list, so the existing
parsers still produce their specific messages (legacy .ckl, invalid XML, …).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from lxml import etree

from app.utils.zip_extract import expand_benchmark_paths

_SELF_CONTAINED_SUFFIXES = (".cklb", ".nessus")


@dataclass
class ClassifiedInputs:
    xccdf_results: list[Path] = field(default_factory=list)
    self_contained: list[Path] = field(default_factory=list)   # .cklb / .nessus results
    reference_xml: list[Path] = field(default_factory=list)
    reference_cklb: list[Path] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def sniff_xml(path: Path) -> str:
    """``"results"`` (has a TestResult), ``"benchmark"`` (a Benchmark and no
    TestResult — Manual STIG, SCAP benchmark or datastream), or ``"other"``."""
    saw_benchmark = False
    try:
        for _event, el in etree.iterparse(
            str(path), events=("start",),
            resolve_entities=False, no_network=True, load_dtd=False, huge_tree=True,
        ):
            if not isinstance(el.tag, str):
                continue
            local = etree.QName(el.tag).localname
            if local == "TestResult":
                return "results"
            if local == "Benchmark":
                saw_benchmark = True
    except (etree.XMLSyntaxError, OSError):
        return "other"
    return "benchmark" if saw_benchmark else "other"


def classify_inputs(
    results_paths: list[Path],
    reference_paths: list[Path],
    extract_dir: Path,
) -> ClassifiedInputs:
    out = ClassifiedInputs()

    references, zip_warnings = expand_benchmark_paths(list(reference_paths), extract_dir)
    out.warnings.extend(zip_warnings)

    for path in results_paths:
        suffix = path.suffix.lower()
        if suffix in _SELF_CONTAINED_SUFFIXES:
            out.self_contained.append(path)
        elif suffix == ".zip":
            expanded, warnings = expand_benchmark_paths([path], extract_dir)
            out.warnings.extend(warnings)
            references.extend(expanded)
        elif sniff_xml(path) == "benchmark":
            out.reference_xml.append(path)
        else:
            out.xccdf_results.append(path)

    for path in references:
        suffix = path.suffix.lower()
        if suffix == ".cklb":
            out.reference_cklb.append(path)
        elif suffix == ".nessus":
            out.self_contained.append(path)
        elif sniff_xml(path) == "results":
            out.xccdf_results.append(path)
        else:
            out.reference_xml.append(path)

    return out
```

- [ ] **Step 5: Run — passes.** `python -m pytest tests/test_inputs.py tests/test_zip_extract.py -q -p no:cacheprovider`

- [ ] **Step 6: Commit** — `feat(inputs): route uploads by content; extract SCAP datastreams and checklists from reference ZIPs`
Files: `app/core/inputs.py app/utils/zip_extract.py tests/test_inputs.py tests/test_zip_extract.py`

---

### Task 11: Pipeline integration (the regression tests go green here)

**Files:**
- Modify: `app/core/pipeline.py`
- Test: `tests/test_reference_pipeline.py` (new), `tests/test_pipeline.py` (update expectations only where they pinned silence)

- [ ] **Step 1: Write the failing regression tests**

```python
# tests/test_reference_pipeline.py
"""End-to-end through parse_stage: the defects in spec §1 must stay fixed."""
from pathlib import Path

from app.core.pipeline import parse_stage

FIX = Path(__file__).parent / "fixtures"


def test_manual_stig_fills_text_for_long_form_scan_ids(tmp_path):
    # Defect 2: a real Manual STIG matched zero rules.
    result = parse_stage([FIX / "evaluate_stig_results.xml"], [FIX / "manual_stig_server2022.xml"], tmp_path)
    f = {x.vuln_id or x.rule_id: x for x in result.findings}
    drifted = f["V-254239"]
    assert drifted.check_text and drifted.fix_text and drifted.severity == "CAT I"
    assert drifted.stig_id == "WN22-00-000010"
    assert drifted.text_source == "Check and fix: manual_stig_server2022.xml V2R8, revision differs from scan"
    same = f["V-254241"]
    assert same.check_text and same.text_source == "Check and fix: manual_stig_server2022.xml V2R8"
    assert all(x.stig_title == "Microsoft Windows Server 2022 Security Technical Implementation Guide"
               for x in result.findings)


def test_unmatched_rules_reach_the_operator(tmp_path):
    # Defect 3: the mismatch was logged, never returned.
    result = parse_stage([FIX / "evaluate_stig_results.xml"], [FIX / "manual_stig_server2022.xml"], tmp_path)
    assert any("not found in any supplied reference" in w and "SV-254243" in w for w in result.warnings)
    assert any("different release" in w for w in result.warnings)


def test_reference_upload_does_not_wipe_scc_data(tmp_path):
    # Defect 4: supplying any benchmark dropped the embedded one.
    alone = parse_stage([FIX / "scc_embedded_results.xml"], [], tmp_path / "a")
    with_ref = parse_stage([FIX / "scc_embedded_results.xml"], [FIX / "manual_stig_win11.xml"], tmp_path / "b")
    for a, b in zip(alone.findings, with_ref.findings):
        assert (b.fix_text, b.severity, b.vuln_id, b.stig_title) == (a.fix_text, a.severity, a.vuln_id, a.stig_title)
        assert a.fix_text and a.severity and a.vuln_id
    filled = [f for f in with_ref.findings if f.check_text]
    assert {f.vuln_id for f in filled} == {"V-253284", "V-253285"}


def test_plain_scc_run_says_why_check_text_is_blank(tmp_path):
    result = parse_stage([FIX / "scc_embedded_results.xml"], [], tmp_path)
    assert all(not f.check_text and f.fix_text for f in result.findings)
    assert all(f.text_source == "Check: no reference supplied | Fix: scanner" for f in result.findings)
    assert [w for w in result.warnings if "Check text is blank for 3 finding(s)" in w]


def test_wrong_slot_still_works(tmp_path):
    # The SPA sends one flat list: a Manual STIG among the results must act as a reference.
    result = parse_stage([FIX / "scc_embedded_results.xml", FIX / "manual_stig_win11.xml"], [], tmp_path)
    assert result.source_file_count == 1
    assert any(f.check_text for f in result.findings)
    assert not any("0 rule results" in w for w in result.warnings)


def test_cklb_reference_fills_xccdf_findings(tmp_path):
    result = parse_stage([FIX / "evaluate_stig_results.xml"], [FIX / "evaluate_stig_checklist.cklb"], tmp_path)
    assert result.source_file_count == 1                      # the checklist is a reference, not a second scan
    assert all(f.check_text and f.fix_text for f in result.findings)


def test_scap_datastream_reference_supplies_fix_text_and_title(tmp_path):
    result = parse_stage([FIX / "scc_embedded_results.xml"], [FIX / "scap_datastream_win11.xml"], tmp_path)
    assert all(f.stig_title for f in result.findings)
    assert any("Check text is blank" in w or "not found in any supplied reference" in w for w in result.warnings)


def test_enrichment_report_and_coverage_are_returned(tmp_path):
    result = parse_stage([FIX / "scc_embedded_results.xml"], [FIX / "manual_stig_win11.xml"], tmp_path)
    assert [s.file_name for s in result.enrichment.standalone_sources] == ["manual_stig_win11.xml"]
    assert {(f.server, f.stig_title) for f in result.findings} <= result.coverage


def test_references_only_is_an_error_that_says_so(tmp_path):
    import pytest
    from app.core.pipeline import PipelineError
    with pytest.raises(PipelineError) as exc:
        parse_stage([FIX / "manual_stig_win11.xml"], [], tmp_path)
    assert "no rule results" in str(exc.value).lower() and "reference" in str(exc.value).lower()
```

- [ ] **Step 2: Run — fails** (`AttributeError: 'ParseResult' object has no attribute 'enrichment'`, blank check text, missing warnings, wiped SCC data)

Run: `python -m pytest tests/test_reference_pipeline.py -q -p no:cacheprovider`

- [ ] **Step 3: Rework `app/core/pipeline.py`**

Imports: remove `from app.utils.zip_extract import expand_benchmark_paths`; add

```python
from app.core.inputs import classify_inputs
from app.processors.matcher import (
    MatchIssue,
    match_results_to_benchmarks,
    scan_coverage,
    unresolved_issue_warnings,
)
from app.reference.cklb_loader import load_cklb_reference
from app.reference.enrich import EnrichmentReport, enrich_findings
from app.reference.library import ReferenceLibrary
```

(replacing the existing matcher import). Add to `ParseResult`:

```python
    # What reference enrichment filled, drifted, and could not find.
    enrichment: EnrichmentReport = field(default_factory=EnrichmentReport)
```

(import `field` from `dataclasses`). Replace the body of `parse_stage` from `warnings: list[str] = []` down to the `return` with the following, and rename the second parameter to `reference_paths` (update the docstring's first paragraph to: "Parse results and references, match, filter to actionable findings, then fill blanks from the reference library. `reference_paths` are operator-supplied STIG references (Manual STIG XML, DISA ZIP, SCAP benchmark, or CKLB); files are routed by content, so a reference among the results still works."):

```python
    warnings: list[str] = []

    # Self-contained result formats parse straight to findings.
    _SELF_CONTAINED = {".cklb": CKLBParser, ".nessus": NessusComplianceParser}
    # Why a self-contained file can parse cleanly yet hold zero rows.
    _ZERO_ROW_HINT = {
        ".cklb": "the checklist has no rules",
        ".nessus": "no Policy Compliance items (a vulnerability scan is not a "
                   "compliance scan)",
    }

    _check()
    inputs = classify_inputs(results_paths, reference_paths, extract_dir)
    warnings.extend(inputs.warnings)
    xccdf_paths = inputs.xccdf_results
    sc_paths = inputs.self_contained

    # Benchmarks feed the matcher (title, severity, embedded fix text) and the
    # reference library (blank-filling). The benchmark embedded in each results
    # file (SCC) is ALWAYS used — supplying a reference must never discard what
    # the scan itself carried — and it is listed FIRST, so a scan matches the
    # benchmark it was actually run against even when an uploaded reference
    # has the same benchmark id.
    library = ReferenceLibrary()
    benchmark_parser = BenchmarkParser()
    reference_benchmarks = []
    for path in inputs.reference_xml:
        _check()
        parsed = benchmark_parser.parse_all(path)
        if not parsed:
            warnings.append(f"Could not parse benchmark: {path.name}")
        for bm in parsed:
            if not bm.rules:
                warnings.append(f"{path.name}: reference contains 0 rules — ignored")
                continue
            reference_benchmarks.append(bm)
            library.add_benchmark(bm, path.name, embedded=False)
    embedded_benchmarks = []
    for path in xccdf_paths:
        _check()
        for bm in benchmark_parser.parse_all(path, warn_if_empty=False):
            if bm.rules:
                embedded_benchmarks.append(bm)
                library.add_benchmark(bm, path.name, embedded=True)
    benchmarks = embedded_benchmarks + reference_benchmarks
    for path in inputs.reference_cklb:
        _check()
        loaded = load_cklb_reference(path, embedded=False)
        if not loaded:
            warnings.append(f"Could not parse reference checklist: {path.name}")
        for source, rules in loaded:
            if not any(r.check_text for r in rules):
                warnings.append(f"{path.name}: 0 of {len(rules)} rules carry check text")
            library.add_rules(source, rules)

    # Per-file progress over the results files — the dominant, multi-minute
    # phase. References parse fast and aren't counted here.
    total_results = len(xccdf_paths) + len(sc_paths)
    done = 0

    results_parser = XCCDFResultsParser()
    scan_results = []
    for path in xccdf_paths:
        _check()
        done += 1
        _progress(f"Parsing {path.name} ({done} of {total_results})…")
        sr = results_parser.parse(path)
        if sr:
            scan_results.append(sr)
        else:
            warnings.append(f"Could not parse results file: {path.name}")

    sc_findings: list[Finding] = []
    sc_file_count = 0
    for path in sc_paths:
        _check()
        done += 1
        _progress(f"Parsing {path.name} ({done} of {total_results})…")
        suffix = path.suffix.lower()
        parsed = _SELF_CONTAINED[suffix]().parse(path)
        if parsed is None:
            warnings.append(f"Could not parse results file: {path.name}")
            continue
        sc_file_count += 1
        sc_findings.extend(parsed)
        if not parsed:
            # Zero rows contribute no coverage pair: like a zero-rule-result
            # XCCDF file this is not a scan, and the operator must be told
            # which file, by name.
            warnings.append(
                f"{path.name}: 0 rule results — not counted as a scan; {_ZERO_ROW_HINT[suffix]}"
            )
        if suffix == ".cklb":
            # A results checklist carries full STIG text, so it can also fill
            # blanks on findings that came from another scanner.
            for source, rules in load_cklb_reference(path, embedded=True):
                library.add_rules(source, rules)

    if not scan_results and sc_file_count == 0:
        if library.sources and not (xccdf_paths or sc_paths):
            raise PipelineError(
                "No rule results were found: the file(s) supplied are STIG "
                "references (benchmarks or checklists used as references), not "
                "scan results. Add the scan results to report on.",
                warnings,
            )
        raise PipelineError("No valid results files could be parsed.", warnings)

    _check()
    # Coverage comes from every parsed row (self-contained formats emit all
    # statuses) plus one pair per XCCDF scan file — captured BEFORE the
    # actionable filter so a clean scan still records what it covered.
    coverage = {(f.server, f.stig_title) for f in sc_findings}
    coverage |= scan_coverage(scan_results, benchmarks)
    # scan_coverage skips a file with no rule results (it is not a scan and
    # must never count as a re-scan); say so per file.
    for sr in scan_results:
        if not sr.rule_results:
            warnings.append(
                f"{sr.source_file}: 0 rule results — not counted as a scan; "
                "if this file is a benchmark, pass it as a reference"
            )

    issues: list[MatchIssue] = []
    findings = match_results_to_benchmarks(scan_results, benchmarks, issues)
    findings.extend(sc_findings)
    findings = filter_findings(findings)

    total_files = len(scan_results) + sc_file_count
    total_rules = sum(len(s.rule_results) for s in scan_results) + len(sc_findings)
    if total_rules == 0:
        # Well-formed files with no rule results at all are a wrong input,
        # never a clean scan — allow_empty does not apply.
        raise PipelineError(
            f"No rule results were found in any of the {total_files} results "
            f"file(s). The files may not be scan results (XCCDF, CKLB, or "
            f".nessus), or may use an unrecognised structure. Check the "
            f"warnings for details.",
            warnings,
        )
    if not findings and not allow_empty:
        raise PipelineError(
            f"Parsed {total_rules} rule result(s) across {total_files} "
            f"file(s), but none had an actionable status (Open / Not Reviewed "
            f"/ Error / Unknown). Either every rule passed, or the results "
            f"were not matched to the supplied STIG benchmarks. Check the "
            f"warnings.",
            warnings,
        )

    # Fill blanks from the library (actionable findings only, so every count
    # is a report row), then report what could not be filled.
    enrichment = enrich_findings(findings, library)
    warnings.extend(
        unresolved_issue_warnings(issues, findings, references_supplied=library.has_standalone)
    )
    warnings.extend(enrichment.warnings())
    # A title filled by enrichment must stay inside the coverage set, or the
    # delta report would treat the finding's own scan as not covering it.
    coverage |= {(f.server, f.stig_title) for f in findings}

    return ParseResult(
        findings=findings,
        warnings=warnings,
        source_file_count=total_files,
        coverage=coverage,
        enrichment=enrichment,
    )
```

- [ ] **Step 4: Run the new tests, then the whole suite**

Run: `python -m pytest tests/test_reference_pipeline.py -q -p no:cacheprovider` → passed.
Run: `python -m pytest -q -p no:cacheprovider`. Expected new failures are tests that pinned the old silence or the old wording, and nothing else:
- a run that now carries the "no matching STIG benchmark" or "Check text is blank" warning where the test expected none;
- `"pass it with --benchmarks"` → `"pass it as a reference"`;
- a test that handed a benchmark in as results and expected the zero-rule-results message.
Update each expectation to the new behaviour. If any other assertion fails, stop and fix the code, not the test.

- [ ] **Step 5: Commit** — `fix(pipeline): references fill blank text for every finding; results always supply their embedded benchmark; mismatches reach the operator`
Files: `app/core/pipeline.py tests/test_reference_pipeline.py` plus each updated test file.

---

### Task 12: Workbook columns and the Reference sources table

**Files:**
- Modify: `app/exporters/excel_exporter.py`, `app/core/pipeline.py` (`export_stage`)
- Test: `tests/test_excel_exporter.py` (append)

- [ ] **Step 1: Write the failing tests** (append)

```python
# tests/test_excel_exporter.py  (append)
class TestReferenceColumnsAndTable:
    def _run(self, tmp_path, references):
        from pathlib import Path
        from openpyxl import load_workbook
        from app.core.pipeline import export_stage, parse_stage
        fix = Path(__file__).parent / "fixtures"
        result = parse_stage([fix / "scc_embedded_results.xml"], [fix / n for n in references], tmp_path / "x")
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
        assert ws.auto_filter.ref == "A1:K1"

    def test_summary_formulas_still_point_at_the_same_columns(self, tmp_path):
        summary = self._run(tmp_path, ["manual_stig_win11.xml"])["Summary"]
        formulas = [c.value for row in summary.iter_rows() for c in row
                    if isinstance(c.value, str) and c.value.startswith("=COUNTIFS")]
        assert formulas and all("$D:$D" in f for f in formulas)          # Severity stays in D
        assert any("$E:$E" in f for f in formulas) and any("$F:$F" in f for f in formulas)

    def test_reference_sources_table_lists_the_supplied_reference(self, tmp_path):
        summary = self._run(tmp_path, ["manual_stig_win11.xml"])["Summary"]
        rows = [[c.value for c in row] for row in summary.iter_rows()]
        start = next(i for i, r in enumerate(rows) if r[0] == "Reference sources")
        assert rows[start + 1][:9] == ["File", "STIG", "Edition", "Release", "Embedded in results",
                                       "Rules loaded", "Check text filled", "Fix text filled",
                                       "From a different release"]
        manual = next(r for r in rows[start + 2:] if r[0] == "manual_stig_win11.xml")
        assert manual[2:9] == ["manual", "V2R9", "no", 3, 2, 0, 1]
        missing = next(r for r in rows if r[0] == "Not found in any supplied reference")
        assert missing[1] == 1

    def test_no_reference_supplied_means_no_table(self, tmp_path):
        summary = self._run(tmp_path, [])["Summary"]
        assert all(row[0].value != "Reference sources" for row in summary.iter_rows())
```

- [ ] **Step 2: Run — fails** (`TypeError: export_stage() got an unexpected keyword argument 'enrichment'`)

- [ ] **Step 3: Implement**

`app/exporters/excel_exporter.py`:

Add `from app.reference.enrich import EnrichmentReport` to the imports. Append two entries to `_FINDINGS_COLS`:

```python
    ("STIG ID",     "stig_id",     18),
    ("Text Source", "text_source", 60),
```

Change `_WRAP_HEADERS` to `{"Check Text", "Fix Text", "Text Source"}`. Change `export` to:

```python
    def export(
        self,
        findings: list[Finding],
        output_path: Path,
        *,
        enrichment: EnrichmentReport | None = None,
    ) -> Path:
        """Write *findings* to *output_path* and return it.

        *enrichment* adds the Reference sources table to the Summary sheet
        when the operator supplied at least one reference. Raises ValueError
        when *findings* is empty.
        """
        if not findings:
            raise ValueError("No findings to export — workbook not generated.")

        wb = Workbook()
        findings_ws = wb.active
        findings_ws.title = "Findings"
        _write_findings_sheet(
            findings_ws, findings, _FINDINGS_COLS, {"Severity": _SEVERITY_FILL}
        )

        summary_ws = wb.create_sheet("Summary")
        self._write_summary(summary_ws, findings, enrichment)

        wb.save(str(output_path))
        log.info("Workbook written to %s", output_path)
        return output_path
```

Change the signature `def _write_summary(self, ws, findings: list[Finding], enrichment: EnrichmentReport | None = None) -> None:` and insert, immediately before the `# ── Footer note` block:

```python
        # ── Table 4: Reference sources ────────────────────────────────
        # Only when the operator supplied a reference: a run without one keeps
        # the historical Summary layout. Literal values, not formulas — this
        # is the audit trail of where filled text came from.
        if enrichment is not None and enrichment.standalone_sources:
            h(ws, row, 1, "Reference sources")
            row += 1
            for ci, lbl in enumerate(
                ["File", "STIG", "Edition", "Release", "Embedded in results", "Rules loaded",
                 "Check text filled", "Fix text filled", "From a different release"], 1,
            ):
                h(ws, row, ci, lbl)
            row += 1
            for src in enrichment.sources:
                counts = enrichment.source_counts.get(src.file_name, {})
                b(ws, row, 1, _sanitize_cell(src.file_name))
                b(ws, row, 2, _sanitize_cell(src.title))
                b(ws, row, 3, src.edition)
                b(ws, row, 4, _sanitize_cell(src.release))
                b(ws, row, 5, "yes" if src.embedded else "no")
                b(ws, row, 6, src.rule_count)
                b(ws, row, 7, counts.get("filled_check", 0))
                b(ws, row, 8, counts.get("filled_fix", 0))
                b(ws, row, 9, counts.get("drifted", 0))
                row += 1
            unmatched = sum(c.unmatched for c in enrichment.stigs.values())
            b(ws, row, 1, "Not found in any supplied reference")
            b(ws, row, 2, unmatched)
            row += 1
            row += 1  # spacer
```

and change the final `_autofit_summary(ws, 6, row)` of `_write_summary` to `_autofit_summary(ws, 9, row)`.

`app/core/pipeline.py`:

```python
def export_stage(
    findings: list[Finding],
    output_path: Path,
    *,
    enrichment: EnrichmentReport | None = None,
) -> None:
    """Write findings to an Excel workbook at ``output_path``."""
    ExcelExporter().export(findings, output_path, enrichment=enrichment)
```

- [ ] **Step 4: Run — passes; then the whole suite**

Run: `python -m pytest tests/test_excel_exporter.py -q -p no:cacheprovider`
Existing tests that pinned nine Findings columns or the `A1:I1` filter range are updated to eleven and `A1:K1`.

- [ ] **Step 5: Commit** — `feat(exporter): STIG ID and Text Source columns; Reference sources table`
Files: `app/exporters/excel_exporter.py app/core/pipeline.py tests/test_excel_exporter.py`

---

### Task 13: Delta carries the new fields

**Files:**
- Modify: `app/processors/delta.py` (`DeltaFinding`, `_tag`), `app/exporters/excel_exporter.py` (`_DELTA_COLS`)
- Test: `tests/test_delta.py`, `tests/test_excel_exporter.py` (append / update the pinned column layout)

- [ ] **Step 1: Write the failing tests** (append)

```python
# tests/test_delta.py  (append)
def test_delta_rows_carry_stig_id_and_text_source():
    from app.parsers.base import Finding
    from app.processors.delta import compute_delta
    f = Finding("T", "V-1", "SV-1r1_rule", "CAT I", "Open", "H", "i", "c", "x",
                stig_id="WN11-00-000150", text_source="Check and fix: scanner")
    cov = {("H", "T")}
    row = compute_delta([f], [f], baseline_coverage=cov, current_coverage=cov).findings[0]
    assert (row.stig_id, row.text_source) == ("WN11-00-000150", "Check and fix: scanner")
```

```python
# tests/test_excel_exporter.py  (append)
def test_delta_sheet_appends_stig_id_and_text_source(tmp_path):
    from openpyxl import load_workbook
    from app.exporters.excel_exporter import ExcelExporter
    from app.parsers.base import Finding
    from app.processors.delta import compute_delta
    f = Finding("T", "V-1", "SV-1r1_rule", "CAT I", "Open", "H", "i", "c", "x",
                stig_id="WN11-00-000150", text_source="Check and fix: scanner")
    cov = {("H", "T")}
    out = tmp_path / "d.xlsx"
    ExcelExporter().export_delta(compute_delta([f], [f], baseline_coverage=cov, current_coverage=cov), out)
    ws = load_workbook(out)["Findings"]
    headers = [c.value for c in ws[1]]
    assert headers[0] == "Delta" and headers[4] == "Severity"            # COUNTIFS columns A and E unchanged
    assert headers[-2:] == ["STIG ID", "Text Source"]
    assert ws.cell(row=2, column=len(headers)).value == "Check and fix: scanner"
```

- [ ] **Step 2: Run — fails** (`AttributeError: 'DeltaFinding' object has no attribute 'stig_id'`)

- [ ] **Step 3: Implement**

`app/processors/delta.py` — in `DeltaFinding`, after `current_status: str` add:

```python
    stig_id: str = ""
    text_source: str = ""
```

and in `_tag(...)` add to the `DeltaFinding(...)` call:

```python
        stig_id=f.stig_id,
        text_source=f.text_source,
```

`app/exporters/excel_exporter.py` — append to `_DELTA_COLS`:

```python
    ("STIG ID",          "stig_id",         18),
    ("Text Source",      "text_source",     60),
```

- [ ] **Step 4: Run — passes; update the test that pins the delta column list to the 13-column layout.**

Run: `python -m pytest tests/test_delta.py tests/test_excel_exporter.py -q -p no:cacheprovider`

- [ ] **Step 5: Commit** — `feat(delta): delta rows carry STIG ID and Text Source`
Files: `app/processors/delta.py app/exporters/excel_exporter.py tests/test_delta.py tests/test_excel_exporter.py`

---

### Task 14: CLI — `--references`

**Files:**
- Modify: `app/cli.py`
- Test: `tests/test_cli.py` (append)

- [ ] **Step 1: Write the failing tests** (append)

```python
# tests/test_cli.py  (append)
class TestReferencesFlag:
    FIX = Path(__file__).parent / "fixtures"

    def _findings_sheet(self, path):
        from openpyxl import load_workbook
        return load_workbook(path)["Findings"]

    def test_references_flag_fills_check_text(self, tmp_path):
        out = tmp_path / "r.xlsx"
        rc = main(["report", "--results", str(self.FIX / "scc_embedded_results.xml"),
                   "--references", str(self.FIX / "manual_stig_win11.xml"), "--output", str(out)])
        assert rc == 0
        ws = self._findings_sheet(out)
        assert ws["H2"].value and ws["K2"].value.startswith("Check: manual_stig_win11.xml V2R9")

    def test_benchmarks_is_still_accepted_as_an_alias(self, tmp_path):
        out = tmp_path / "r.xlsx"
        rc = main(["--results", str(self.FIX / "scc_embedded_results.xml"),
                   "--benchmarks", str(self.FIX / "manual_stig_win11.xml"), "--output", str(out)])
        assert rc == 0 and self._findings_sheet(out)["H2"].value

    def test_reference_directory_is_scanned_recursively(self, tmp_path):
        import shutil
        lib = tmp_path / "stigs" / "windows"
        lib.mkdir(parents=True)
        shutil.copy(self.FIX / "manual_stig_win11.xml", lib / "manual_stig_win11.xml")
        out = tmp_path / "r.xlsx"
        rc = main(["report", "--results", str(self.FIX / "scc_embedded_results.xml"),
                   "--references", str(tmp_path / "stigs"), "--output", str(out)])
        assert rc == 0 and self._findings_sheet(out)["H2"].value

    def test_run_summary_reports_what_was_filled(self, tmp_path, caplog):
        import logging
        caplog.set_level(logging.INFO)
        main(["report", "--results", str(self.FIX / "scc_embedded_results.xml"),
              "--references", str(self.FIX / "manual_stig_win11.xml"), "--output", str(tmp_path / "r.xlsx")])
        assert any("check text filled: 2" in r.getMessage() for r in caplog.records)

    def test_delta_accepts_references(self, tmp_path):
        out = tmp_path / "d.xlsx"
        scc = str(self.FIX / "scc_embedded_results.xml")
        rc = main(["delta", "--baseline", scc, "--current", scc,
                   "--references", str(self.FIX / "manual_stig_win11.xml"), "--output", str(out)])
        assert rc == 0
        headers = [c.value for c in self._findings_sheet(out)[1]]
        assert "Text Source" in headers
```

(`main` and `Path` are already imported at the top of `tests/test_cli.py`; if `Path` is not, add `from pathlib import Path`.)

- [ ] **Step 2: Run — fails** (`unrecognized arguments: --references`)

- [ ] **Step 3: Implement in `app/cli.py`**

- Replace `_BENCHMARK_EXTS = (".xml", ".zip")` with `_REFERENCE_EXTS = (".xml", ".zip", ".cklb")`.
- Give `_resolve_paths` a keyword `recursive: bool = False` and, in the directory branch, use `p.rglob(f"*{ext}") if recursive else p.glob(f"*{ext}")`.
- `_MULTI_VALUE_OPTS = ("--results", "--references", "--benchmarks", "--baseline", "--current")`.
- In both subparsers replace the `--benchmarks` argument with:

```python
    rp.add_argument(          # and the same on dp, with the delta help text below
        "--references", "--benchmarks",
        dest="references",
        nargs="*",
        required=False,
        default=None,
        metavar="PATH",
        help=(
            "STIG references that fill blank check/fix text: Manual STIG XML, "
            "DISA STIG ZIP, SCAP benchmark, or .cklb checklist; a directory is "
            "scanned recursively, so one folder of STIGs works as a library. "
            "SCC results carry fix text only — add the Manual STIG for check "
            "text. (--benchmarks is accepted as an alias.)"
        ),
    )
```

  For `dp` use the same call with help `"STIG references applied to BOTH sets (see report --references)."`.
- In `_run_report` replace the benchmark-path block and the two log lines with:

```python
    reference_paths = (
        _resolve_paths(args.references, extensions=_REFERENCE_EXTS, recursive=True)
        if args.references
        else []
    )

    if not results_paths:
        log.error("No results files found for: %s", args.results)
        return 1

    log.info("Results files:   %d", len(results_paths))
    log.info("Reference files: %d", len(reference_paths))
```

  call `parse_stage(results_paths, reference_paths, extract_dir)`, and after the `Actionable findings` log line add:

```python
        for title, counts in result.enrichment.stigs.items():
            log.info(
                "%s — check text filled: %d, fix text filled: %d, from a different "
                "release: %d, not in a supplied reference: %d",
                title, counts.filled_check, counts.filled_fix, counts.drifted, counts.unmatched,
            )
```

  and export with `export_stage(result.findings, output_path, enrichment=result.enrichment)`.
- In `_run_delta` build `reference_paths` the same way from `args.references`, use it in the `missing` check and the two `parse_stage` calls, and change the log line to `"Baseline files: %d  Current files: %d  Reference files: %d"`.
- Remove the now-wrong "No --benchmarks supplied — XCCDF results will be used as their own benchmark source" info message.

- [ ] **Step 4: Run — passes; then the whole suite** (tests that asserted the removed log lines are updated)

Run: `python -m pytest tests/test_cli.py -q -p no:cacheprovider`

- [ ] **Step 5: Commit** — `feat(cli): --references (alias --benchmarks), recursive reference folders, enrichment summary`
Files: `app/cli.py tests/test_cli.py`

---

### Task 15: Flask UI

**Files:**
- Modify: `app/templates/index.html`, `app/static/app.js`, `app/web.py`
- Test: `tests/test_web.py` (append)

- [ ] **Step 1: Write the failing tests** (append; reuse the module's existing client fixture and its helper that posts files and polls to completion — read the top of `tests/test_web.py` and follow the pattern used by the existing upload test)

```python
# tests/test_web.py  (append)
def test_reference_zone_copy_and_accept_list(client):
    html = client.get("/").get_data(as_text=True)
    assert "STIG References" in html
    assert "Manual STIG ZIPs add check text" in html
    assert 'accept=".xml,.zip,.cklb"' in html
    assert "Not needed when uploading SCC result files" not in html


def test_manual_stig_reference_fills_check_text_through_the_web_flow(client, tmp_path):
    import io, time
    from pathlib import Path
    from openpyxl import load_workbook
    fix = Path(__file__).parent / "fixtures"
    data = {
        "results": (io.BytesIO((fix / "scc_embedded_results.xml").read_bytes()), "scc_embedded_results.xml"),
        "benchmarks": (io.BytesIO((fix / "manual_stig_win11.xml").read_bytes()), "manual_stig_win11.xml"),
    }
    job_id = client.post("/api/process", data=data, content_type="multipart/form-data").get_json()["job_id"]
    for _ in range(100):
        status = client.get(f"/api/status/{job_id}").get_json()
        if status["status"] != "running":
            break
        time.sleep(0.05)
    assert status["status"] == "complete"
    assert any("not found in any supplied reference" in w for w in status["warnings"])
    out = tmp_path / "r.xlsx"
    out.write_bytes(client.get(f"/api/download/{job_id}").data)
    wb = load_workbook(out)
    assert wb["Findings"]["H2"].value                                  # check text filled
    assert any(row[0].value == "Reference sources" for row in wb["Summary"].iter_rows())


def test_cklb_is_accepted_in_the_reference_zone(client):
    import io
    from pathlib import Path
    fix = Path(__file__).parent / "fixtures"
    data = {
        "results": (io.BytesIO((fix / "evaluate_stig_results.xml").read_bytes()), "evaluate_stig_results.xml"),
        "benchmarks": (io.BytesIO((fix / "evaluate_stig_checklist.cklb").read_bytes()), "evaluate_stig_checklist.cklb"),
    }
    resp = client.post("/api/process", data=data, content_type="multipart/form-data")
    assert resp.status_code == 200
```

- [ ] **Step 2: Run — fails** (old copy; no `Reference sources` table because `export_stage` is called without `enrichment`)

- [ ] **Step 3: Implement**

`app/templates/index.html` — in the second upload zone replace the `<h2>`, `<p>` and `<input>` lines with:

```html
              <h2>STIG References <span class="badge-optional">Optional</span></h2>
              <p>Manual STIG ZIPs add check text. Accepts DISA STIG ZIP or Manual XCCDF (.xml), SCAP benchmarks, and STIG Viewer checklists (.cklb). SCC results carry fix text only.</p>
              <button type="button" class="btn btn-secondary" id="benchmarks-browse">Choose Files</button>
              <input type="file" id="benchmarks-input" name="benchmarks" multiple accept=".xml,.zip,.cklb" hidden>
```

and change the comment above the zone to `<!-- Reference drop zone: STIG content that fills blank check/fix text -->`. In the header replace the subtitle sentence with:

```html
      <p class="subtitle">Upload scan results to generate a consolidated findings report. Add the Manual STIG as a reference to include check text &mdash; SCC results carry fix text only.</p>
```

`app/static/app.js` — line 135: change the allowed list to `['.xml', '.zip', '.cklb']`.

`app/web.py` — in `process()`, keep the form field name `benchmarks`; replace the fallback-name line for reference files with:

```python
                lower = f.filename.lower()
                fallback = "reference.cklb" if lower.endswith(".cklb") else (
                    "reference.zip" if lower.endswith(".zip") else "reference.xml")
                safe_name = secure_filename(f.filename) or fallback
```

  In `_run_job` rename the parameter `benchmark_paths` → `reference_paths` (and the call site argument stays positional), and change the export call to:

```python
        export_stage(result.findings, output_path, enrichment=result.enrichment)
```

- [ ] **Step 4: Run — passes; then the whole suite** (tests that asserted the old zone copy are updated)

Run: `python -m pytest tests/test_web.py -q -p no:cacheprovider`

- [ ] **Step 5: Commit** — `feat(web): STIG References zone accepts checklists; workbook carries the reference table`
Files: `app/templates/index.html app/static/app.js app/web.py tests/test_web.py`

---

### Task 16: Async stages and the Lambda API

**Files:**
- Modify: `app/core/stages.py`, `app/lambdas/parser.py`, `app/lambdas/api.py`
- Test: `tests/test_stages.py`, `tests/test_lambda_handlers.py` (append)

- [ ] **Step 1: Write the failing tests** (append; follow each module's existing helpers for building the artifact store and job store and for invoking the API handler — read the first 80 lines of each test file and reuse them. Construct the stores and put the job into the state `run_parse_stage` expects exactly as the existing parse-stage tests in `tests/test_stages.py` do; if the in-memory job store class or the starting status differs from what is written below, use the existing ones and keep the assertions.)

```python
# tests/test_stages.py  (append)
def test_parse_stage_uses_the_reference_hint_and_writes_enrichment_json(tmp_path):
    import json
    from pathlib import Path
    from app.core.artifact_store import LocalArtifactStore
    from app.core.job_store import MemoryJobStore
    from app.core.stages import ENRICHMENT_KEY, run_export_stage, run_parse_stage
    fix = Path(__file__).parent / "fixtures"
    store = LocalArtifactStore(tmp_path / "store")
    jobs = MemoryJobStore()
    job_id = "job-ref"
    jobs.create(job_id, status="pending")
    for name in ("evaluate_stig_results.xml", "evaluate_stig_checklist.cklb"):
        store.put_bytes(f"jobs/{job_id}/input/{name}", (fix / name).read_bytes())

    assert run_parse_stage(
        job_id, ["evaluate_stig_results.xml", "evaluate_stig_checklist.cklb"], store, jobs,
        work_dir=tmp_path / "w", reference_filenames=["evaluate_stig_checklist.cklb"],
    )
    assert jobs.get(job_id)["source_file_count"] == 1           # the checklist was a reference
    report = json.loads(store.get_bytes(ENRICHMENT_KEY.format(job_id=job_id)))
    assert any(s["file_name"] == "evaluate_stig_checklist.cklb" and not s["embedded"] for s in report["sources"])

    assert run_export_stage(job_id, store, jobs, work_dir=tmp_path / "w2")
    from openpyxl import load_workbook
    out = tmp_path / "r.xlsx"
    store.download_to(f"jobs/{job_id}/report.xlsx", out)
    assert any(row[0].value == "Reference sources" for row in load_workbook(out)["Summary"].iter_rows())


def test_export_stage_tolerates_a_job_parsed_before_enrichment_existed(tmp_path):
    from pathlib import Path
    from app.core.artifact_store import LocalArtifactStore
    from app.core.job_store import MemoryJobStore
    from app.core.stages import ENRICHMENT_KEY, run_export_stage, run_parse_stage
    fix = Path(__file__).parent / "fixtures"
    store = LocalArtifactStore(tmp_path / "store")
    jobs = MemoryJobStore()
    jobs.create("old", status="pending")
    store.put_bytes("jobs/old/input/scc_embedded_results.xml", (fix / "scc_embedded_results.xml").read_bytes())
    assert run_parse_stage("old", ["scc_embedded_results.xml"], store, jobs, work_dir=tmp_path / "w")
    (tmp_path / "store" / ENRICHMENT_KEY.format(job_id="old")).unlink()
    assert run_export_stage("old", store, jobs, work_dir=tmp_path / "w2")
```

```python
# tests/test_lambda_handlers.py  (append — use this module's existing event builder and stores)
def test_uploads_accepts_reference_filenames_and_rejects_strangers(api_env):
    # `api_env` stands for whatever fixture this module already uses to call the API handler;
    # use the same call helper as the existing POST /uploads tests.
    ok = _call("POST", "/uploads", {"filenames": ["a.xml", "ref.cklb"], "referenceFilenames": ["ref.cklb"]})
    assert ok["statusCode"] == 201
    job_id = json.loads(ok["body"])["jobId"]
    assert common.job_store().get(job_id)["reference_filenames"] == ["ref.cklb"]

    bad = _call("POST", "/uploads", {"filenames": ["a.xml"], "referenceFilenames": ["other.xml"]})
    assert bad["statusCode"] == 400
    assert "referenceFilenames" in json.loads(bad["body"])["error"]

    not_a_list = _call("POST", "/uploads", {"filenames": ["a.xml"], "referenceFilenames": "a.xml"})
    assert not_a_list["statusCode"] == 400


def test_execution_input_carries_reference_filenames():
    from app.lambdas import api
    payload = json.loads(api._execution_input(
        "j", {"input_filenames": ["a.xml", "r.zip"], "reference_filenames": ["r.zip"]}, False))
    assert payload["referenceFilenames"] == ["r.zip"]
    assert json.loads(api._execution_input("j", {"input_filenames": ["a.xml"]}, False))["referenceFilenames"] == []
```

Adapt `_call` / `api_env` to the helper names this test module really uses; keep the assertions as written.

- [ ] **Step 2: Run — fails** (`ImportError: ENRICHMENT_KEY`; `TypeError: run_parse_stage() got an unexpected keyword argument 'reference_filenames'`; API ignores `referenceFilenames`)

- [ ] **Step 3: Implement**

`app/core/stages.py`:
- add `import json`, `from app.reference.enrich import EnrichmentReport`, and next to `REPORT_KEY`: `ENRICHMENT_KEY = "jobs/{job_id}/enrichment.json"`.
- `run_parse_stage` gains a keyword parameter `reference_filenames: list[str] | None = None` (document it: "names from `input_filenames` the operator supplied as STIG references; routing is by content, this only marks a checklist as reference-only"). Replace `result = parse_stage(local_inputs, [], extract_dir)` with:

```python
        reference_names = set(reference_filenames or [])
        local_references = [p for p in local_inputs if p.name in reference_names]
        local_results = [p for p in local_inputs if p.name not in reference_names]
        result = parse_stage(local_results, local_references, extract_dir)
```

  and, right after the existing `store.put_bytes(FINDINGS_KEY…)`, add:

```python
    store.put_bytes(
        ENRICHMENT_KEY.format(job_id=job_id),
        json.dumps(result.enrichment.to_dict()).encode("utf-8"),
    )
```

- in `run_export_stage`, replace `export_stage(findings, out_path)` with:

```python
        # Jobs parsed by an older build have no enrichment artifact; the
        # workbook then simply omits the Reference sources table.
        enrichment_key = ENRICHMENT_KEY.format(job_id=job_id)
        enrichment = (
            EnrichmentReport.from_dict(json.loads(store.get_bytes(enrichment_key).decode("utf-8")))
            if store.exists(enrichment_key)
            else None
        )
        export_stage(findings, out_path, enrichment=enrichment)
```

`app/lambdas/parser.py` — pass the hint:

```python
        input_store=common.upload_store(),
        reference_filenames=list(event.get("referenceFilenames") or []),
```

`app/lambdas/api.py`:
- in `_execution_input` add `"referenceFilenames": record.get("reference_filenames", []),` to the dict.
- in `_post_uploads`, after the filename-rejection loop add:

```python
    reference_filenames = body.get("referenceFilenames") or []
    if not isinstance(reference_filenames, list) or any(
        str(name) not in {str(n) for n in filenames} for name in reference_filenames
    ):
        return _response(
            400, {"error": "referenceFilenames must be a list of names from 'filenames'."}
        )
```

  (bind `body = _body(event)` at the top of the function and read `filenames` from it), and pass `reference_filenames=[str(n) for n in reference_filenames],` to `common.job_store().create(...)`.

- [ ] **Step 4: Run — passes; then the whole suite**

Run: `python -m pytest tests/test_stages.py tests/test_lambda_handlers.py -q -p no:cacheprovider`

- [ ] **Step 5: Commit** — `feat(async): reference hint through the API and parse stage; enrichment.json feeds the exporter`
Files: `app/core/stages.py app/lambdas/parser.py app/lambdas/api.py tests/test_stages.py tests/test_lambda_handlers.py`

---

### Task 17: SPA

**Files:**
- Modify: `frontend/src/api.ts`, `frontend/src/useJob.ts`, `frontend/src/App.tsx`
- Test: `frontend/src/api.test.ts`, `frontend/src/App.test.tsx` (append)

- [ ] **Step 1: Write the failing tests** (append; use each file's existing fetch mock and render helpers)

```ts
// frontend/src/api.test.ts  (append inside the existing describe)
it('createUploads sends referenceFilenames only when there are some', async () => {
  const fetchMock = mockFetchOnce({ jobId: 'j', uploads: [] });   // this file's existing helper
  await createUploads(['scan.xml', 'stig.zip'], ['stig.zip']);
  expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({
    filenames: ['scan.xml', 'stig.zip'],
    referenceFilenames: ['stig.zip'],
  });

  const second = mockFetchOnce({ jobId: 'j', uploads: [] });
  await createUploads(['scan.xml']);
  expect(JSON.parse(second.mock.calls[0][1].body)).toEqual({ filenames: ['scan.xml'] });
});
```

```tsx
// frontend/src/App.test.tsx  (append)
it('labels the reference zone and tells the operator what it adds', async () => {
  await renderApp();                                               // this file's existing helper
  expect(screen.getByRole('heading', { name: /STIG References/ })).toBeInTheDocument();
  expect(screen.getByText(/Manual STIG ZIPs add check text/)).toBeInTheDocument();
  expect(screen.queryByText(/Not needed when uploading SCC result files/)).toBeNull();
});
```

Add one more test beside the existing "submits the selected files" test in the same style, asserting that after adding `scan.xml` to the results zone and `stig.zip` to the reference zone and pressing Process, `api.createUploads` was called with `(['scan.xml', 'stig.zip'], ['stig.zip'])`.

- [ ] **Step 2: Run — fails**

Run (from `frontend/`): `npx vitest run src/api.test.ts src/App.test.tsx`

- [ ] **Step 3: Implement**

`frontend/src/api.ts`:

```ts
export function createUploads(
  filenames: string[],
  referenceFilenames: string[] = [],
): Promise<UploadsResponse> {
  // referenceFilenames marks which uploads are STIG references. The server routes
  // by content; the hint only makes a checklist a reference instead of a scan.
  const body = referenceFilenames.length > 0 ? { filenames, referenceFilenames } : { filenames };
  return request<UploadsResponse>('/uploads', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}
```

`frontend/src/useJob.ts` — change the `submit` signature to `async (files: File[], ai: boolean, referenceNames: string[] = [])` and the call to:

```ts
        const { jobId, uploads } = await api.createUploads(files.map((f) => f.name), referenceNames);
```

`frontend/src/App.tsx` — replace the second `<UploadZone …>` with:

```tsx
              <UploadZone
                id="benchmarks"
                title="STIG References"
                badge="Optional"
                description="Manual STIG ZIPs add check text. Accepts DISA STIG ZIP or Manual XCCDF (.xml), SCAP benchmarks, and STIG Viewer checklists (.cklb). SCC results carry fix text only."
                accept=".xml,.zip,.cklb"
                limits={config}
                files={benchmarks}
                onChange={setBenchmarks}
              />
```

  the Process button's handler with:

```tsx
                onClick={() => void submit([...results, ...benchmarks], ai, benchmarks.map((f) => f.name))}
```

  and the header subtitle with:

```tsx
        <p className="subtitle">
          Upload scan results to generate a consolidated findings report. Add the
          Manual STIG as a reference to include check text — SCC results carry fix
          text only.
        </p>
```

- [ ] **Step 4: Run — passes; then typecheck, the full frontend suite, and the build**

Run (from `frontend/`): `npx tsc --noEmit -p . && npx vitest run && npm run build`
Tests that asserted the old zone title/description are updated to the new copy.

- [ ] **Step 5: Commit** — `feat(spa): STIG References zone; send the reference hint with uploads`
Files: `frontend/src/api.ts frontend/src/useJob.ts frontend/src/App.tsx frontend/src/api.test.ts frontend/src/App.test.tsx` plus any updated test file.

---

### Task 18: Documentation and the final gate

**Files:**
- Modify: `README.md`, `CODEBASE_INDEX.md`, `frontend/README.md` (only if it describes the upload zones)

- [ ] **Step 1: Update `README.md`**
  - **Supported Scanners** table: SCC row notes → "Result files embed the scanned SCAP benchmark: fix text, severity and V-ID come from the scan. **Check text is not in SCC output — add the Manual STIG as a reference.**"
  - **Output** table: add rows `STIG ID | STIG rule identifier, e.g. WN22-00-000010` and `Text Source | Where the row's check and fix text came from: scanner, the reference file and release, or "no reference supplied"`. Add under the Summary paragraph: "When a reference is supplied the Summary sheet adds a **Reference sources** table: each file, its edition and release, how many rows it filled, and how many came from a different release than the one scanned."
  - New section **STIG references** (replace "STIG Benchmark Files"): what to upload (DISA STIG ZIP or `*_Manual-xccdf.xml` for check text; a `.cklb` made from the Manual STIG works too; SCAP Benchmark ZIPs carry no check text), that blanks are filled and scanner text is never overwritten, the meaning of "revision differs" / "scanned VxRy", that files are routed by content so the wrong zone still works, and the CLI folder-as-library pattern.
  - **CLI** examples and argument table: `--references` (with `--benchmarks` alias), recursive directories.
  - **How It Works**: insert "Route by content", "Load references", and "Enrich" steps.
- [ ] **Step 2: Update `CODEBASE_INDEX.md`** — add `app/reference/*` and `app/core/inputs.py` entries and adjust the pipeline, matcher, exporter, cli, stages and api lines.
- [ ] **Step 3: Run every gate**

```bash
python -m pytest -q -p no:cacheprovider
python -m pip_audit            # only if installed locally; CI runs it regardless
cd frontend && npx tsc --noEmit -p . && npx vitest run && npm run build
```

Expected: all green; Python count is 502 plus the tests added by Tasks 1–16.

- [ ] **Step 4: Commit** — `docs: STIG references, Text Source column, --references`
Files: `README.md CODEBASE_INDEX.md` (+ `frontend/README.md` if changed)

---

## Live verification (run by the orchestrator after Task 18, not committed)

1. A real SCC session (the maintainer's own scan data, verified locally and never committed) alone → every row has fix text, one "Check text is blank for N finding(s) in K STIG(s)" warning, `Text Source` = `Check: no reference supplied | Fix: scanner`.
2. The same session plus the current DISA Manual STIG ZIPs for its STIGs (each download approved first) → every matched row has check text; fix text, severity and V-ID identical to run 1; drift and unmatched counts appear in the warnings and in the Reference sources table; workbook opened and screenshotted.
3. The same through the Flask UI in a real browser: zone copy, warnings on the result card, download opens.
4. `delta` with `--references` on the same session against itself → `Text Source` present, every finding Persisting.

## Self-review record

- **Spec coverage:** §1 defects 1–6 → Tasks 3, 10, 11 (regressions in Task 11), fixtures in Task 1. §4.1 (references, CKLB hint) → Tasks 10, 11, 16, 17. §4.2 → Tasks 2–5. §4.3 (fill, re-resolve, Text Source, drift, unmatched, warnings, matcher issues) → Tasks 6–8, 11. §4.4 → Tasks 3, 8, 9 (`ansible_task`, `fqdn` deferred to PR B as noted). §4.7 columns J/K and Table 4 → Task 12. §4.8 → Tasks 11, 16. §4.9 → Tasks 14–17. §5 rows that belong to PR A (zero-rule reference, wrong-product reference, SCAP-only reference, drift, CKLB without check text, `referenceFilenames` validation) → Tasks 7, 11, 16. Delta update → Task 13.
- **Deferred to PR B/C by design:** YAML/playbook routing, bundle, SHA-256 provenance, `Ansible Task` column, Table 5, OVAL index.
- **Type consistency:** `ReferenceLibrary.add_benchmark(benchmark, file_name, *, embedded)`, `add_rules(source, rules)`, `candidates(finding)`, `has_standalone`; `enrich_findings(findings, library) -> EnrichmentReport` with `.stigs`, `.sources`, `.source_counts`, `.standalone_sources`, `.warnings()`, `.to_dict()/.from_dict()`; `match_results_to_benchmarks(scan_results, benchmarks, issues=None)`; `unresolved_issue_warnings(issues, findings, *, references_supplied)`; `classify_inputs(results_paths, reference_paths, extract_dir) -> ClassifiedInputs(xccdf_results, self_contained, reference_xml, reference_cklb, warnings)`; `parse_stage(results_paths, reference_paths, extract_dir, *, cancel_check, allow_empty, progress_cb)`; `export_stage(findings, output_path, *, enrichment=None)`; `run_parse_stage(..., reference_filenames=None)`; `createUploads(filenames, referenceFilenames = [])`.

## Amendments during execution

Where the code differs from a task's listing above, this section is authoritative.

1. **Task 2, `app/reference/normalize.py`** (commit `40ea81b`, from the spec review of Tasks 1–3):
   - `release_label` accepts ASCII digits only (`[0-9]`), so a crafted `<version>` such as `²` is returned unchanged instead of raising.
   - `_REVISION` is `(?<=[0-9])(r[0-9]+)(?:_rule)?$`: a rule ID without the `_rule` suffix (`SV-254239r945408`, the form STIG Viewer checklists use in `rule_id`) yields stem `SV-254239` and revision `r945408`.
2. **Task 1, `tests/fixtures/scc_embedded_results.xml`**: `start-time`/`end-time` are `2026-01-15T10:00:00` / `2026-01-15T10:01:24` (fully fabricated).
3. **Task 3, `app/parsers/benchmark_parser.py`** (commits `11b7747`, `e9c64e0`): rules are collected by one iterative walk per Benchmark that descends only through `Group` elements (nested groups supported; a rule directly under the Benchmark gets a blank V-ID; rules inside `TestResult` or other wrappers are not read; an inner Benchmark owns its own rules). Duplicate rule IDs keep the last definition and log one bounded, escaped warning. `_findall_local` no longer exists.
4. **Tasks 4–7, `app/reference/`** (commits `aa476fc`, `c23e635`, `666a7d1`, `ec5cc75`):
   - `normalize.release_key("V2R10") -> (2, 10)`; candidate ranking within a key is: same revision, operator-supplied before embedded, source release equal to the finding's `scan_release`, newest release, load order.
   - At most 32 rules are indexed per key value; overflow is recorded once per (file, index) in `ReferenceLibrary.warnings`. **Task 11 must add `library.warnings` to the operator warnings.**
   - A finding is unmatched only when references were supplied, it has no operator-supplied candidate, and it still lacks check or fix text. `StigCounts.needed` counts findings that lacked text before enrichment; the wrong-product line reads "none of N finding(s) that need text matched a supplied reference".
   - `StigCounts.blank_both` and its warning cover titled findings with neither check nor fix text. Untitled ones are reported per results file by the matcher issue in Task 8/11.
   - `StigCounts.unmatched_ids` stores at most 50 IDs.
   - `load_cklb_reference` returns `[]` on `ValueError` and `RecursionError` as well.
   - Tests in later tasks that assert the old wrong-product wording must use the new one.
5. **Tasks 4–7, `app/reference/`** (commits `1b7c363`, `e98cf97`, `499eb9d`, `66c03a0`, `bb9a796`, `cb5955e`, `3a7e241`, `4701501`, from the spec review of Tasks 4–7). The rule: a finding is never filled from a rule that could be a different rule, and the report never says "not found" when the truth is "found but refused".
   - **Lookup.** `ReferenceLibrary.lookup(finding) -> Lookup(matches, ambiguous, ambiguous_by, refused_products, refused_more)`; `matches` is `[(rule, first_key)]` with key one of `rule_id`, `stem`, `vuln_id`, `stig_id`. `candidates(finding)` and `candidates_with_keys(finding)` wrap it.
   - **Guards.** New helpers in `normalize`: `is_disa_stem` (`SV-[0-9]{1,12}`), `is_vuln_id` (`V-[0-9]{1,12}`), `product_key(title)`.
     - Stems are compared only when both are DISA-style; a different DISA stem rejects the candidate. A scanner check name, an SSG rule name or a STIG ID used as a rule ID is not a stem.
     - Only V-ID-shaped group IDs are indexed, looked up or compared. A topic group such as `accounts-session` is never a key.
     - A V-ID that reaches more than one rule identity in the same dialect (DISA stems, or non-DISA rule IDs) lends nothing: V-ID-only candidates are dropped, exact rule-ID and stem hits stay. One DISA rule plus one non-DISA rule under a V-ID is the cross-dialect case and is allowed.
     - A rule reached only by STIG ID must have the same `product_key` as the finding's STIG title. With a blank title it is accepted only when every such rule shares one product; otherwise the lookup is ambiguous.
   - **Text Source phrases added** (Task 18 must document them in the README): `…, matched by STIG ID` appended to a fill; `STIG ID matches several STIGs, not filled`; `V-ID matches several rules, not filled`; `STIG ID found under a different STIG title, not filled`.
   - **`StigCounts` fields added:** `unmatched_rules`, `blank_fix_with_check`, `ambiguous`, `product_refused`, `refused_titles` (at most 5), `refused_more`. `unmatched_ids` holds distinct IDs. Ambiguous and product-refused findings are not counted as unmatched.
   - **Warning lines changed or added:** `"{title}: {n} finding(s) across {m} rule(s) not found in any supplied reference: {ids}"` (the "across" clause is omitted when the payload has no rule count); drift lines say `finding(s)` and omit the parenthetical when the release is blank; `"Fix text is blank for {n} finding(s) in {k} STIG(s): {titles}."`; `"… match more than one rule or STIG and were not filled — …"`; `"… carry a STIG ID found only under a different STIG title ({titles}) and were not filled — …"`. The "loaded:" list shows at most 5 sources.
   - **Severity** `""` or `"Unknown"` is filled from the reference. **Task 8 must emit `""`, not `"Unknown"`, for a rule the scan's own benchmark does not describe.**
   - **Sources.** An embedded benchmark equal to one already loaded (same benchmark ID, release and SHA-256 over its rules' IDs, severities and texts) is not added again; `add_benchmark` and `add_rules` return the source actually held, which may carry another file's name. The 32-per-key cap is counted separately for operator-supplied and embedded rules.
   - **`source_counts`** is keyed by `enrich.source_key(source)` (`file|benchmark_id`), and `drifted` counts findings, not fields. **Task 12's listing uses `source_counts.get(src.file_name)`; it must use `source_counts.get(source_key(src))`.** `from_dict` ignores unknown keys.
   - **CKLB loader** strips XCCDF prefixes from group and rule IDs and logs a STIG entry with no rules.
   - **Carried into later tasks:**
     - Task 8 (matcher): "scanner" means "non-blank before enrichment", so the matcher must take check text, fix text and `scan_release` only from the results file's own embedded benchmark. Text from an operator-supplied reference is added by enrichment alone, or it would be labelled "scanner".
     - Task 9 (Nessus): set `stig_id` whenever the STIG ID doubles as the rule ID. The STIG title feeds the product guard.
     - Task 11 (pipeline): add `library.warnings` to the operator warnings; do not assume one source per results file; tell an unreadable checklist from one with no rules.
     - Task 12 (exporter): one Reference-sources row per entry in `report.sources`. Every warning string carries untrusted titles, file names and rule IDs, so each renderer escapes them (`_sanitize_cell` in the workbook, HTML escaping in the web UI).
   - **Two corrections to the statements above.** (a) A candidate refused by the stem or V-ID guard still reads "not in supplied references"; only product refusals and ambiguity have their own wording. The known case is a pre-2020 scan (old `SV-`/`V-` numbers) against a current reference with the same STIG ID: it is not filled. Task 18 documents this. (b) A V-ID that reaches several rule identities drops only the V-ID-only candidates of the crowded dialect; exact rule-ID and stem hits always stay, and such a finding is not ambiguous.
6. **Tasks 4–7, `app/reference/`** (commits `8500471`, `8de455e`, `ed5e69e`, `baad1c3`, `a4fb559`, `9e2b2ea`, from the code-quality review of Tasks 4–7):
   - **Bounds on uploaded text.** `release_label` returns at most 40 characters for a version it cannot parse; benchmark and checklist titles are clipped to 200 at parse time; `ReferenceSource.__post_init__` clips title, benchmark ID and release; stored IDs and every title shown in a warning are clipped to 120. Helpers `normalize.clip`, `normalize.fold` (ASCII-only upper-casing of IDs) and `normalize.safe_name`.
   - **Checklist loader** takes text from JSON strings only (ints only for the STIG version) and logs one warning per file with the number of values ignored.
   - **An exact rule-ID or stem match is never ambiguous** (V-ID and STIG-ID cases alike). A fill reached only by the V-ID key appends `, matched by V-ID`. A refused reference with no title is shown as `(untitled reference)`.
   - **`EnrichmentReport.from_dict`** never raises on well-formed JSON of the wrong shape; it skips bad entries and coerces field types.
   - **Shape.** `lookup()` is `_gather` → `_drop_crowded_vuln` → `_guard_product`; `Lookup.ambiguous` is a property of `ambiguous_by`; match keys are `MatchKey` (a `StrEnum` with the same string values); `text_source.source_phrase` takes an `Outcome` enum; `make_rule(...)` is the only constructor of a `ReferenceRule` (any new loader must use it); `ReferenceRule.order` and `candidates_with_keys` no longer exist.
7. **Tasks 8 and 11 — each scan is bound to the benchmark embedded in its own results file.** The listings above hand the matcher one global list (`embedded + reference`) and take rule data from the first benchmark whose ID matches. That mislabels operator-supplied text as "scanner" and gives two hosts scanned at different releases the first host's `scan_release`.
   - `ScanResult` gains `embedded_benchmarks: list[Benchmark]` (default empty). `parse_stage` parses the benchmarks embedded in each results file and attaches them to the `ScanResult` parsed from that same path.
   - The matcher resolves `own = _find_benchmark(href, id, scan.embedded_benchmarks)` and `named = own or _find_benchmark(href, id, benchmarks)`. **Rule data (V-ID, severity, check text, fix text, STIG ID) and `scan_release` come from `own` only. `named` supplies the STIG title only.** Everything a reference adds is added by `enrich_findings`, which labels it.
   - `scan_coverage` resolves the title through the same helper, so a coverage pair always equals the `(server, stig_title)` of the findings from that scan.
   - Issues: `no-benchmark` when neither `own` nor `named` exists; `rules-not-found` when `own` exists and lacks the rule. With `named` only, no issue is raised (references were supplied, so the enrichment report names what it could not fill).
   - Existing matcher tests that passed a benchmark and asserted rule text attach that benchmark as the scan's `embedded_benchmarks` instead; the assertions stay as strong.
   - Task 11 also: `warnings.extend(library.warnings)`; `load_cklb_reference` tells "not a readable checklist" from "readable, no rules" and returns the count of ignored non-string values, and `parse_stage` turns each into its own operator warning.
   - Tasks 12 and 14: the Summary table and the CLI summary line show `ambiguous` and `product_refused` beside `unmatched`; a total of "not found: 0" next to rows that say "not filled" is not acceptable.
8. **Tasks 8–11 as built** (commits `0081712` … `9e3152c`, after six spec-review rounds). The rule behind every change: each file or archive member the operator supplied is either used or named in `ParseResult.warnings` with the reason (a log line alone does not count), and no single bad input raises out of `parse_stage`.
   - **Matcher.** `_find_benchmark` and its substring fallback no longer exist. A results file that embeds exactly one benchmark owns it; with several, the one whose `fold(norm_benchmark_id(...))` equals the scan's ID (or href stem when the ID is blank). Operator references name a scan only by that same equality. `MatchIssue` holds the affected `Finding` objects (identity; it must never cross a serialisation boundary) and `keys` is derived. Severity for a rule the scan's own benchmark does not describe is `""`.
   - **Parsers.** The results `CKLBParser` survives hostile JSON, reads text from JSON strings only (`normalize.json_text` / `JsonText`), reports a non-text status as "Unknown", and counts `ignored_values`, `skipped_rules` (blank status) and `malformed_entries`, each reset per file and turned into an operator warning by the pipeline. Parse errors shown to the operator carry no file location or server path (`error_text`); Flask's `_WarningCollector` stores the message only, never a traceback.
   - **Inputs.** `classify_inputs` is the only entry to ZIP handling (`expand_benchmark_paths` is gone; `extract_from_zip` returns an `Extraction`). A ZIP is a folder: each member is routed as the same file would be loose in the ZIP's slot. Members are extracted to generated names; the operator sees `ClassifiedInputs.name_of(path)` — the base name, or `{zip}/{path inside it}` when names collide, ` (2)` when still equal, cut from the left (`clip_left`) when long. Files are de-duplicated by resolved path, then SHA-256. A root-element sniff (at most 64 KiB, charged to the budget) recognises results, benchmarks, legacy `.ckl` (named as unsupported) and ancillary OVAL/CPE/OCIL/stylesheets (silent); a file with no element in its first 64 KiB is named and not parsed. Limits: 200 MB per member (`app/core/uploads.MAX_UPLOAD_BYTES`), 5,000 members and 2 GiB per archive, 20,000 members and 8 GiB per run, nesting depth 2, encrypted archives refused whole; each limit names what was not checked. Other archive formats inside a ZIP are named as not read.
   - **Pipeline.** Reference checklists add a title-only `Benchmark` per STIG so benchmark-less scans are named (`_can_name_a_scan` needs an ID and a title). `load_cklb_reference` returns `ChecklistReference(stigs, readable, ignored_values)`. One fingerprint per results file (`matcher.results_fingerprint`: host, IP, rule key, status of actionable rows); files with equal fingerprints are copies only if both or neither are `.nessus` and every titled host's `product_key` agrees. The copy with the most check/fix text is kept; the others add no rows, coverage or issues, their own STIG text goes into the library after all kept content (so it only fills blanks, labelled with its own name), and each gets `{b}: same scan as {a} (same host and results) — its rows are not repeated`. When files that are not copies report the same rule of one host (rows joined by stem, rule ID or V-ID; an ID-less row by STIG ID only when that names one rule), the host gets `{host}: {k} rule(s) appear in more than one of {n} files (…) — each file's rows are in the report, so totals count those rules more than once` (at most 5 hosts, then "… and m more").
   - **Carry-overs.**
     - Task 12 (exporter): `ParseResult.enrichment` exists; `export_stage` has no `enrichment=` yet. `ReferenceSource.file_name` is a display name of at most 255 characters. Warnings carry untrusted titles and IDs; every renderer escapes.
     - Task 13 (delta): define one host key across formats before matching baseline to current (a short name and an FQDN are two hosts today, with no overlap line). Key coverage and finding matching on `product_key(title)`, not the raw title — one STIG is titled differently by format, and the kept copy's title is the one reported. A benchmark-less XCCDF scan titled only by enrichment adds an extra `(host, "")` coverage pair; it must not mark baseline rows as covered. Baseline and current must be parsed with the same references.
     - Task 14 (CLI): `parse_stage`'s second parameter is `reference_paths`; the INFO line "No --benchmarks supplied — XCCDF results will be used as their own benchmark" no longer describes what happens.
     - Task 15 (Flask): some warnings appear twice (captured log line plus `ParseResult.warnings`). Both zones accept `.zip` and a ZIP is read as a folder in either slot; the zone copy says so. The "Files" count includes a parsed file with 0 rule results and both copies of an all-pass scan; label it "files read" or exclude them.
     - Task 16 (Lambda): `run_parse_stage` passes one flat list; a `.cklb` is a result unless it arrives as a reference, so `referenceFilenames` matters.
     - Task 18 (docs): display names (` (2)`, `{zip}/{path}`, left cut); only XML, `.cklb`, `.nessus` and nested ZIP members are read, other archive formats are named, other extensions are ignored without mention, legacy `.ckl` is unsupported; a file with no XML element in its first 64 KiB is not read; the archive limits above; copies are read once and their text can still fill blanks; files that disagree about one host are all read and totals count those rules once per file; a benchmark-less scan whose ID differs from the Manual's (`Microsoft_Windows_11_STIG` vs `MS_Windows_11_STIG`) is titled only on rows whose rule matched; a pre-2020 renumbered rule is not filled from a current reference; every new operator string from the batch-3 commit messages.
     - Security gate (before PR A goes public): each candidate XML was parsed more than once, and parse cost was not bounded per file (XML or JSON checklists); the archive budgets bound extraction only. Now each file is parsed once and parse cost is bounded per file and per run, see Amendment 11. No per-upload file count on Flask or the Lambda API (the run's parse budgets now bound what such a run parses). Loose files are hashed and sniffed outside the archive budget (bounded by the 200 MB upload cap).
9. **Batch 3 quality fixes and the decisions for Tasks 12–18** (commits `4cec879` … `edbd90a`, code-quality review approved).
   - **Built.** Opening an archive and reading a member never raise (`Exception` caught at both boundaries, reported through `error_text`). `ZipFile` reads the archive through a guard (`zip_extract`) that counts central-directory records once each by offset and refuses more than 100,000 entries or a directory over 16,000,000 bytes before any entry object is built — public API only, no placement arithmetic. `_WarningCollector` keeps only its own worker thread's records, fails closed when a record has no thread id, holds at most 200 lines plus one "… and N more" line, and counts each dropped line once (commits `e969398` and `0a53869` are collector-only and can be cherry-picked to master). Per-row parser log lines: the first 5 per file at WARNING, the rest at DEBUG, all escaped. Flask saves each upload in its own numbered folder, so equal names survive; the Lambda `POST /uploads` refuses duplicate names. Flask removes the extraction dir right after `parse_stage`; the Lambda removes its work dir in a `finally`. Flask and the Lambda show `PipelineError.warnings` on the failure path (Lambda: at most 200 lines). Classification polls for cancellation. `parse_stage` is a short sequence over helpers with a `_Run`; `CKLBParser.parse` returns `ChecklistResult` (frozen dataclass: `findings` plus the three counts); `BaseParser.parse(path, name=...)`; `app/limits.py` holds the size caps; `inputs.sniff_xml` no longer exists.
   - **Task 12 (exporter).** Look up per-source counts with `source_counts.get(source_key(src))`. One Reference-sources row per entry in `enrichment.sources`. Under the table, three total rows, not one: "Not found in any supplied reference" (`unmatched`), "Matches more than one rule or STIG — not filled" (`ambiguous`), "STIG ID found under a different STIG title — not filled" (`product_refused`). Every string from an upload passes `_sanitize_cell`. The listed test values are expectations to verify against the fixtures, not to force.
   - **Task 13 (delta).** As listed (the two new fields), plus tests that pin what batch 3 changed: (a) the same host scanned by SCC (title "…STIG SCAP Benchmark") in the baseline and supplied as a checklist ("Microsoft Windows 11 STIG") in the current run matches as one STIG through the existing edition-neutral `_stig_key`; (b) an extra `(host, "")` coverage pair next to `(host, title)` neither marks baseline rows as covered nor turns a finding "Resolved" or "Not re-scanned" wrongly. Fix the code only if a test shows a wrong result. **Out of PR A:** one host key across formats (a short name and an FQDN are two hosts today) — recorded as a follow-up, not built here.
   - **Task 14 (CLI).** As listed, plus: the results slot also accepts `.zip` (a ZIP is a folder since Amendment 8); `_REFERENCE_EXTS = (".xml", ".zip", ".cklb")` with recursive directory scanning; the per-STIG summary line also prints `ambiguous` and `product_refused` ("…, not in a supplied reference: N, several matches: N, other STIG title: N"); the INFO line about `--benchmarks` is removed.
   - **Task 16 (Lambda) carry-overs.** The success path stores `result.warnings` unbounded in one DynamoDB item (400 KB limit): bound it like the error path. `run_export_stage` leaves its report file in the work dir. Keeping two uploads with the same name needs a new S3 key layout plus an SPA change (today the API refuses the duplicate).
   - **Security gate additions.** No cumulative entry budget across nested ZIPs: the work of reading many nested archives' entry lists is not bounded per run (open, see Amendment 11). The guard's record of seen offsets is bounded by the entry-list size cap.
   - **Follow-ups outside PR A.** Host identity across formats (above). CI does not run ruff; six ruff findings pre-date this branch.
10. **Tasks 12–14 as built** (commits `4a0b6e0` … `32ff563`, after three spec and three quality rounds), and the decisions for Tasks 15–18.
   - **Exporter.** Findings columns J "STIG ID" and K "Text Source" are appended; A–I and every COUNTIFS letter are unchanged. `_sanitize_cell` (every cell, every sheet), in order: characters openpyxl refuses and lone surrogates → U+FFFD; formula-leading characters get an apostrophe; the value is cut to 32,767 UTF-16 units ending `… [truncated by STIG Condenser]`; the underscore of a literal `_xHHHH_` is stored as `_x005F_`. Summary server rows are one per (host, IP) and title rows one per title, compared by per-character upper-casing (Excel's rule); each COUNTIFS criterion is `=` + the `~`-escaped stored cell text, so it matches its own cells by construction. A value COUNTIF would coerce (no letters unless it is a well-formed IP address; TRUE/FALSE; Excel error literals; month-name and year-first dates; AM/PM; exponents) or a criterion over 255 UTF-16 units gets a fixed count computed in one pass, and the footer says so. A "No severity" column (blank or "Unknown") is appended after Total and included in it; a "(no STIG title)" row appears when any finding is untitled; both tables sum to the Findings sheet. The footer always notes that counts were checked against English-language Excel. The Reference-sources table has one row per `enrichment.sources` entry (counts via `source_key`) and three totals: not found, several matches, other STIG title. Cell styles are shared instances (100k findings × 2,000 hosts: about 19 s).
   - **Delta.** Rows carry STIG ID and Text Source. `delta.coverage_gaps(result)` feeds both the warning lines and the workbook's Coverage block: a pair is "cannot be verified as re-scanned" when the other run scanned that host without a STIG title; otherwise "not re-scanned" / "newly scanned"; each line counts the findings it actually tagged. No delta status changed.
   - **CLI.** `--references` (alias `--benchmarks`, `dest="references"`); reference directories are walked recursively and results directories are not; suffixes match in any case; the results slot accepts `.zip`; directory symlinks are followed once (visited by `(st_dev, st_ino)`, by resolved path when `st_ino` is 0), real directories before links; an unreadable directory is warned about (capped); a dangling link is kept so the run reports "Could not read file". Every printed warning and error passes `normalize.escape_controls` (C0, C1, DEL, U+2028/2029, bidi controls); stderr is UTF-8. The per-STIG summary line prints filled, drifted, not found, several matches and other-title counts, at most 50 lines.
   - **Pipeline/inputs.** Loose SCAP support files (OVAL, CPE, OCIL, stylesheets) in either slot are named in one capped line and not counted. A benchmark-less XCCDF scan whose actionable rows were all titled by enrichment covers those titles instead of `(host, "")`.
   - **Task 15 (Flask), in addition to the listing.** Pass `enrichment=result.enrichment` to `export_stage` (Flask still calls it without). Both zones accept `.zip` and a ZIP is read as a folder in either slot: the zone copy and `app.js` allowed lists say so. Stop showing a warning twice (captured log line plus `ParseResult.warnings`). Label the result card's file count as what it is ("files read"), or exclude files the warnings say were not counted. Uploads already live in numbered folders (Amendment 9); keep that.
   - **Task 16 (Lambda), in addition to the listing.** Pass `enrichment` to `export_stage` in `run_export_stage` (via `enrichment.json`, as listed). Bound `result.warnings` on the success path the way the error path is bounded (one DynamoDB item is at most 400 KB). Remove the report file from the work dir after upload. Keep refusing duplicate upload names; keeping both is a follow-up (new S3 key layout plus an SPA change), not PR A.
   - **Task 17 (SPA).** As listed. The worktree has no `frontend/node_modules`; the `style` worktree's `frontend/node_modules` was installed from a byte-identical `package-lock.json`, so link to it (a directory junction) rather than installing anything.
   - **Task 18 (docs).** Everything listed, plus every operator-facing string and behaviour recorded in Amendments 5–10: Text Source phrases; the archive rules and limits; copies and overlaps; display names; the Summary's grouping, fixed counts and footer; the CLI directory rules; that a pre-2020 renumbered rule and a benchmark-less scan whose benchmark ID differs from the Manual's are not filled/titled; the follow-ups. Replace `--benchmarks` in README examples (keep a note that it remains an alias), fix `CODEBASE_INDEX.md`'s Findings column list, and the delta module docstring.
   - **Follow-ups outside PR A (added).** A rule untitled in both runs can never be Resolved (fails toward "Not re-scanned"); consider keying a benchmark-less scan's coverage by its benchmark ID. Duplicate upload names on the Lambda path.
11. **Final fix round before the PR** (commits `572ef46` … `9b1de69`, one per item; README and `CODEBASE_INDEX.md` updated with each).
   - **Text Source and counts agree** (`572ef46`). `enrich._field_outcome` is the one decision per text field; the finding-level reason (`_finding_outcome`) is derived from the outcomes of its blank fields, so a cell and the Summary counts never disagree. New outcome `IN_REFERENCE_NO_TEXT`: a field a supplied reference holds the rule for, without its text, reads `in <file> <release>, which has no check text` (or `fix`), and the finding counts as blank check (or fix) text, not as "not found". A STIG-ID refusal is no longer named in a cell when a supplied rule answered the finding.
   - **Each file is parsed once; parsing is bounded** (`fec6ca2`). Classification parses nothing: the document element (first 64 KiB) settles `TestResult` roots, legacy checklists and support files; otherwise a `TestResult` or `Benchmark` start tag in the bytes (`parse_cost.start_tags`) decides results or benchmark. A file that is not well-formed is routed by its tags and named by the parser that reads it ("Could not parse results file: …" or "Could not parse benchmark: …"); an XML member of a ZIP with neither tag is named as not recognised. The XCCDF results path parses each file once (`benchmark_parser.load_xml`) and hands that tree to the results parser, `detect_scanner` and the embedded-benchmark parser (`tree=`), then drops it. In the same pass that hashes it, each file's parse cost is measured (`app/utils/parse_cost.py`): XML element starts and whether a start tag holds more than `MAX_TAG_ATTRIBUTES = 64` attributes; JSON object and array starts and commas. Caps: `MAX_FILE_ELEMENTS = 4,000,000` per file (real content holds one element per 80–300 bytes, so a full 200 MB upload of it stays under, with room for denser OVAL/ARF content), `MAX_RUN_ELEMENTS = 100,000,000` per run (about the 8 GiB run extraction budget of real content). New warnings: `<file>: too many elements to parse safely — not read`, `<file>: an element has too many attributes to parse safely — not read`, `<file>: not read — the parse limit for one run was reached; any scan results or STIG references in it are missing from this report` (once a file does not fit, every later file is refused too); five files are named per reason per run, then `… and N more …`.
   - **The reference library is bounded** (`6820fda`). A checklist rule entry with no rule ID, V-ID-shaped group ID or STIG ID (`models.indexable`) is never built and is counted in the malformed-entries line; `ReferenceSource.rule_count` counts the rules built. `ReferenceRule`, `ReferenceSource` and `BenchmarkRule` use slots. `ReferenceLibrary` holds at most `MAX_RULES_PER_RUN = 250,000` rules (a library of every DISA STIG holds about 100,000); loaders build no more than `rules_left`, and the first file past the limit is named once: `<file>: the limit of 250,000 STIG reference rules for one run was reached — rules past it, in this file and any later reference, were not loaded; findings they would have filled read "not in supplied references"` (a checklist emptied by the limit is not also called empty). Reference files have their own budget, `MAX_RUN_REFERENCE_BYTES = 2 GiB` per run, charged at classification: `<file>: not read — the limit on STIG reference content for one run was reached; any rules in it are missing from this report`. A reference that names a scan is kept for naming as a title-only `Benchmark`.
   - **A full disk ends extraction as a limit** (`5b140cc`). `OSError` with `ENOSPC` while extracting a member stops the archive as the size limit does ("size limit reached — N more file(s) not checked; …").
   - **The workbook carries the run's warnings** (`dcd60ea`). `export_stage(..., warnings=)` on all three surfaces (CLI and Flask: `ParseResult.warnings`; Lambda: the bounded warnings stored on the job record). The Summary sheet lists them under **Warnings from this run**, each through `_sanitize_cell`, at most 200 then `… and N more warnings not shown`; a run without warnings has no block. The delta workbook's Warnings block uses the same writer (`_write_warnings`), so it is capped too.
   - **Web warnings** (`1b76e8d`). The success path adds `result.warnings` through `_WarningCollector.add_new` (capped, each line once), as the failure path does. Inside one archive, five copies of a file are named (`<b>: identical to <a> — read once`) and the rest counted: `<zip>: … and N more identical to <a> — read once`.
   - **Code kept only for tests removed** (`a6cadf6`). The parsers' `parse()` / `parse_all()` wrappers (and `BenchmarkParser.parse`), `match_results_to_benchmarks`, `scan_coverage`, `ReferenceLibrary.candidates` and `MatchIssue.keys`; `BaseParser` is no longer abstract. Tests use `read()` / `read_all()`, `lookup()`, `match_results_by_scan` and `scan_coverage_pairs`. The log-call guard keeps one forwarding exemption (`RowLog.__call__`) and checks every other call against the detail-line list; the runtime duplicate-reason test is kept because it compares what readers log with what the run reports, which the static check cannot. The private entry-limit pin became a test of the real limits' behaviour.
   - **Wording and display** (`ab3f07c`). Copy-merge line: `<b>: same host and results as <a> — its rows are not repeated`. The CLI writes stdout as UTF-8 too (help text on Windows). `unresolved_issue_warnings` shows the display name as it is (only `escape_controls`, which does not change an escaped name). Severity filled per source (`source_counts[...]["filled_severity"]`) is a new last column of the Reference-sources table, "Severity filled", and in the CLI per-STIG line. Spec D12 and its Text Source table now describe the revision-based behaviour the code has.
   - **Lambda downloads** (`9b1de69`). `ArtifactStore.download_to(..., max_bytes=)` reads at most that many bytes (S3: a ranged GET), removes a partial file and raises `ObjectTooLarge`; `run_parse_stage` caps each input at `MAX_UPLOAD_BYTES` and reports `File too large: '<name>' (max 200 MB each).`, as the size check does. `pyproject.toml` has `urllib3>=2.8.0` (it arrives through botocore).
   - **Open after this round.** Nested ZIPs still have no run-wide budget for reading their entry lists. A results checklist is still read twice (by the parser and, for its STIG text, by the reference loader), each bounded by the per-file cap. The Lambda runtime's own boto3/urllib3 are not governed by `pyproject.toml`.
12. **Pre-scan fixes after the final review** (commits `3e6981a`, `93f1d6b`, `4c16e33`).
   - **Attributes** (`3e6981a`). The crowded-tag check counts attributes as the XML parser reads them: whitespace, a name, `=` (whitespace allowed around it), then a value in double or single quotes, which may hold `>`; a value holding `<` ends the count, as it ends the parse. One possessive regex (no backtracking; each attempt reads one tag and at most `MAX_TAG_ATTRIBUTES + 1` attributes) searches the memory-mapped file, so no tag is split between reads; it is skipped for a file already over the element cap. Every `=` is charged to the per-file and per-run element counts (each attribute has one; one in text is over-counted, never under). Constants unchanged: `MAX_FILE_ELEMENTS = 4,000,000` elements and attributes, `MAX_RUN_ELEMENTS = 100,000,000`, `MAX_TAG_ATTRIBUTES = 64`. Design figures: real content holds one node per 40–95 bytes (the fixtures 37–67, a DISA Manual STIG 56 whole and 93 in its rules), so 200 MB of Manual-STIG rules counts about 2.3 million and peaked near 0.6 GB through `parse_stage`; one parse at the cap peaks near 0.5 GB for flat elements and near 1 GB for elements with many attributes.
   - **Start tags and slot advice** (`93f1d6b`). `start_tags` searches the memory-mapped file and steps over comments, CDATA sections, processing instructions and a DOCTYPE's internal subset; a construct never closed ends the search (the rest of the file is inside it). Every `<` except an end tag's is now charged as a node, so comments, CDATA, instructions and DOCTYPE count toward the caps too. Scan results that came in the reference slot are recorded (`ClassifiedInputs.results_from_references`, `_ResultsFile.as_reference`); such a file with no rule results reads `<file>: supplied as a STIG reference, but it holds a TestResult, so it was read as scan results — 0 rule results, not counted as a scan`, and one from the results slot keeps `… if this file is a benchmark, pass it as a reference`.
   - **Namespace prefixes** (`4c16e33`). A start tag is recognised under a namespace prefix of any length (possessive, so linear), inside a ZIP as loose.
   - **Known limitation.** A DOCTYPE's internal subset is taken to end at the first `]` followed by `>`; an entity value that itself holds `]>` ends it early, and a `TestResult` or `Benchmark` tag written after that point in the subset can route that one file to the wrong list. Its parser still names it if it cannot be read as such.
