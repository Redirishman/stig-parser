# STIG Condenser — Sub-project #4: Bedrock Enrichment (Design Spec)

**Date:** 2026-07-14
**Status:** Draft — pending review, then plan → build
**Parent:** [GovCloud Re-Platform master architecture](2026-07-07-govcloud-replatform-design.md) §4.1
**Depends on:** #2 (enricher Lambda shell, IAM scoped to one model ARN, Bedrock VPC endpoint, Step Functions `Choice` state, SSM killswitch) and #3 (the AI toggle and the `ai` gate display) — **both merged**.
**Blocks:** nothing. This is the last sub-project of the re-platform.

---

## 1. Goal & Non-Goals

**Goal:** Draft **POA&M (Plan of Action & Milestones) entries** from open findings using Bedrock, and deliver them as a clearly-labeled, separately-auditable artifact that **cannot corrupt the deterministic report**.

**Non-goals — deliberately cut (YAGNI):**
- **Finding narratives.** One call per finding is the highest-cost, highest-latency job, and STIG check/fix text is already prescriptive. Low marginal value.
- **Executive summary.** Cheap, but nobody asked for it and it is not what makes accreditation painful.
- **Categorize / dedupe.** **Actively rejected.** It would let an LLM silently *change the deterministic finding set* — the one thing a compliance tool must never permit. If a finding is deduped away by a model and it mattered, the operator has no way to know.

The three cut jobs remain in the master spec if someone later wants them; nothing here forecloses them.

---

## 2. The binding constraint

Master spec §4.1 governs this sub-project, and one line governs everything else:

> **Unlabeled LLM text must never appear in accreditation artifacts.**

Every decision below follows from that. The report this tool produces goes into an accreditation package that a human signs. An LLM sentence that a reader mistakes for scanner output is the worst failure this system can produce — worse than a crash, because a crash is visible.

---

## 3. Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| E1 | **POA&M drafting only.** | Highest real value (it is the paperwork engineers actually hate), and structured enough that output is checkable against the deterministic finding it claims to describe. |
| E2 | **The enricher writes `jobs/{id}/poam.json`; the exporter adds a sheet only if that artifact exists.** | The Findings sheet stays **byte-identical whether AI ran or not** — AI cannot corrupt audit-grade data. `poam.json` is separately auditable: an ISSO can diff exactly what the model said. Stage idempotency (#2 §6) holds: one deterministic key, overwritten on re-run. |
| E3 | **Structured JSON output, and every returned `vuln_id` is verified against the deterministic finding set.** Entries naming a finding that does not exist are **dropped and counted**. | The model may *phrase*; it may not *invent*. This is the single most important rule in the sub-project. A hallucinated Vuln-ID in an accreditation package is a fabricated compliance record. |
| E4 | **Hard cap + batching, and the shortfall is stated on the artifact's face.** | GovCloud Bedrock quotas are low and a large scan can carry thousands of open findings. A POA&M that is silently 200 entries short is worse than no POA&M. |
| E5 | **Ships with no model configured** (`bedrock_model_id = ""` → `ai: disabled-globally`). | The exact GovCloud model ID cannot be confirmed without GovCloud access (master spec §3: *"do not hard-code an assumed ID"*). AI stays off until an operator sets D4 and validates output in a real environment. |
| E6 | **Enrichment failure is non-fatal**, always. | Already wired in #2: the `Choice`-state `Catch` routes to `Export`, not to the error path. A Bedrock outage must never destroy a job whose parse succeeded. |

---

## 4. Architecture

```
Parse ──> Choice(aiEnabled) ──> Enrich ──> Export ──> Done
                    │                         ▲
                    └─────────────────────────┘   (AI off: straight to Export)

findings.json ──> [enricher] ──> poam.json ──> [exporter] ──> report.xlsx
   (deterministic)                (AI, labeled)      (Findings sheet unchanged
                                                      + POA&M sheet iff poam.json)
```

### 4.1 `app/core/poam.py` (new — pure, no boto3)

The domain logic, testable without AWS:

- `select_findings(findings, cap)` → the findings to enrich: **open findings only**, sorted CAT I → II → III, capped. Returns `(selected, over_cap_count)`.
- `build_prompt(batch, prompt_version)` → the prompt text.
- `parse_response(raw, valid_vuln_ids)` → `(entries, dropped)`. **Drops any entry whose `vuln_id` is not in `valid_vuln_ids`.** Raises on malformed JSON.
- `PoamEntry` dataclass: `vuln_id`, `weakness`, `mitigation`, `milestones`, `resources`, `scheduled_completion`.
- `poam_to_json` / `poam_from_json`, mirroring the existing `findings_io` pattern.

Keeping this AWS-free means the hallucination guard — the thing that matters most — is unit-testable with no mocking at all.

### 4.2 `app/lambdas/enricher.py` (replaces the shell)

1. Load `findings.json` from the artifact store.
2. `select_findings(...)` with `AI_MAX_FINDINGS`.
3. Batch into groups of `AI_BATCH_SIZE`; one `InvokeModel` per batch (one call per finding would be slow, expensive, and quota-hostile).
4. Per batch: invoke Bedrock, `parse_response(...)`, accumulate entries and drops.
5. Write `poam.json` (see §5) to the artifact store.
6. Update the job: `ai: done`, plus provenance and counts. On any Bedrock failure: `ai: failed` + `ai_error`, **and return normally** so Export still runs.

Retries: Bedrock throttling (`ThrottlingException`) is retried with backoff inside the handler; the Step Functions `Retry` block already covers transient Lambda faults.

### 4.3 `app/exporters/excel_exporter.py` (extended)

Gains an optional `poam` argument. When present, adds one sheet:

**`POA&M (AI-DRAFTED — REVIEW REQUIRED)`**

- **Row 1 — banner (bold, warning-tinted, merged):**
  `AI-DRAFTED — NOT REVIEWED. Generated by <model_id> (prompt <version>) on <timestamp>. Every entry must be verified by a human before this enters an accreditation package.`
- **Row 2 — coverage, stated plainly:**
  `Drafted entries for N of M open findings. K findings were NOT enriched (over the per-job cap). J entries were discarded as unverifiable.`
- Row 3: headers. Row 4+: entries.

If `poam.json` is absent (AI off, or it failed), the workbook is **exactly what it is today** — no empty sheet, no placeholder. A reader cannot tell the difference between "AI was off" and "this build has no AI", which is correct: the job record is where the gate is reported, and the SPA renders it.

---

## 5. `poam.json` — the auditable artifact

```json
{
  "provenance": {
    "model_id": "<from BEDROCK_MODEL_ID>",
    "prompt_version": "poam-v1",
    "region": "us-gov-west-1",
    "generated_at": "2026-07-14T22:31:00Z"
  },
  "coverage": {
    "open_findings": 412,
    "requested": 200,
    "enriched": 197,
    "dropped_unverifiable": 3,
    "over_cap": 212
  },
  "entries": [
    { "vuln_id": "V-12345", "weakness": "...", "mitigation": "...",
      "milestones": "...", "resources": "...", "scheduled_completion": "..." }
  ]
}
```

`coverage` is the audit trail for E3 and E4: it records exactly how much of the scan the model saw, how much it got right, and how much it never touched.

---

## 6. Alerting on a partial POA&M (four places, not one)

A shortfall is announced everywhere an operator might look. A partial POA&M that only whispers in a JSON file is the failure this design exists to prevent.

1. **Job record** — a warning. The SPA already renders warnings, and (since #3) they **survive onto the success card**, so the alert is still on screen when the report is ready.
2. **The sheet itself** — the row-2 coverage line. The artifact tells the truth standalone, without the app.
3. **`poam.json`** — the `coverage` block, for audit.
4. **CloudWatch** — logged, so an operator can see it without opening the report.

---

## 7. Configuration (all already plumbed by #2)

| Env var | Terraform var | Default | Meaning |
|---|---|---|---|
| `BEDROCK_MODEL_ID` | `bedrock_model_id` | `""` | **Empty = AI off everywhere** (D4). |
| `BEDROCK_REGION` | `bedrock_region` | `us-gov-west-1` | |
| `AI_KILLSWITCH_PARAM` | `ai_killswitch_param` | `""` | SSM killswitch; fails closed. |
| `AI_MAX_FINDINGS` | `ai_max_findings` | `200` | **New.** Per-job enrichment cap. |
| `AI_BATCH_SIZE` | `ai_batch_size` | `20` | **New.** Findings per `InvokeModel` call. |

The two new variables are the only Terraform change: added to `modules/compute` (env) and `envs/example`. **No new IAM** — #2 already scopes `bedrock:InvokeModel` to exactly the one approved model ARN, and to nothing if none is set.

---

## 8. Failure handling

| Failure | Behaviour |
|---|---|
| No model configured | `ai: disabled-globally`. Never reached in normal flow (the API gate stops it first). |
| Killswitch thrown / unreadable | AI off, fails **closed**. Already implemented in #2. |
| Bedrock throttled | Retry with backoff. Exhausted → `ai: failed`, deterministic report still ships. |
| Bedrock error / timeout | `ai: failed` + `ai_error`. Export still runs. |
| Malformed JSON from the model | `ai: failed`. Do **not** attempt to salvage partial text — a half-parsed POA&M is untrustworthy. |
| Model returns an unknown `vuln_id` | Entry **dropped**, counted in `dropped_unverifiable`, surfaced in all four alert channels. |
| Model returns *no* usable entries | `ai: failed` with a clear reason. No empty POA&M sheet. |
| Findings exceed the cap | Enrich the highest-severity `AI_MAX_FINDINGS`; report the shortfall in all four channels (§6). |

---

## 9. Testing

- **`app/core/poam.py` — pure unit tests, no mocks.** The hallucination guard is the centerpiece: a response naming `V-99999` when no such finding exists must be dropped and counted. Selection order (CAT I first), the cap, and JSON round-tripping.
- **`app/lambdas/enricher.py` — Bedrock mocked** via `botocore` Stubber. Adversarial cases: throttle → retry → success; throttle exhausted → `ai: failed` + Export still runs; malformed JSON → `ai: failed`; hallucinated ID → dropped + warning; zero usable entries → `failed`, no sheet.
- **Exporter** — the POA&M sheet exists only when `poam.json` does; the **Findings sheet is byte-identical with and without AI** (assert this explicitly — it is E2's whole point); the banner and coverage rows are present and accurate.
- **No live Bedrock call anywhere in CI.**

---

## 10. What this design does NOT prove

Stated plainly, because it is the biggest limitation of this sub-project:

- **No prompt has ever been run against a real model.** Bedrock is mocked throughout. The tests prove the *plumbing, the guardrails, and the failure paths* are correct; they prove **nothing about the quality of the drafted POA&M text.**
- **The GovCloud model ID is unconfirmed** (master spec §3 forbids hard-coding an assumed one).
- Consequently the feature **ships disabled**. The first operator to set `bedrock_model_id` must review the output themselves before trusting it. `docs/` will say so.
- LLM output is not deterministic. §4.1 requires *"same scan + same request = same report **shape**"* — shape, not bytes. The Findings sheet is byte-stable; POA&M prose may vary between runs. Provenance (model + prompt version) makes each run auditable, not reproducible.

---

## 11. Build order

1. `app/core/poam.py` + pure unit tests (the hallucination guard first — it is the point).
2. `app/lambdas/enricher.py` — real Bedrock call, batching, retry, provenance. Stubber-mocked tests.
3. `app/exporters/excel_exporter.py` — the labeled POA&M sheet; assert the Findings sheet is unchanged.
4. Terraform: `ai_max_findings`, `ai_batch_size` in `modules/compute` + `envs/example`.
5. Docs: README + `infra/README.md` — what is unverified, and that AI ships off.

---

## 12. Definition of Done

- Hallucination guard proven: an entry naming a nonexistent finding is dropped, counted, and surfaced.
- The Findings sheet is **byte-identical** whether or not AI ran (explicitly asserted).
- Every AI cell in the workbook is under an AI-DRAFTED banner naming the model and prompt version.
- A partial POA&M alerts in all four channels (§6).
- Every failure in §8 leaves a complete deterministic report.
- Full Python suite green; no live Bedrock in CI.
- Terraform: fmt/validate/tflint/checkov clean.
- Docs state plainly that the prompt is unvalidated and the feature ships off.
