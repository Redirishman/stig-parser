# Delta coverage fix — implementation plan (2026-09-28)

Spec: `docs/superpowers/specs/2026-07-20-delta-reporting-design.md` §Revision 2 (decisions R2-1 … R2-8).
Branch: `feat/delta-reporting-cli`, worktree `.claude/worktrees/delta-cli`. Baseline: 406 tests green.
Method: TDD. Every step = failing test first, run it, then the smallest code that passes. Commit after each numbered step with a `fix(delta):` / `test(delta):` message. Never edit tests to make wrong behaviour pass.

## 1. Regression tests that fail today (`tests/test_delta.py`, new class `TestCoverageFromScans`)
1. Fully remediated host: baseline HOST-A has 2 findings; current has none for HOST-A but `current_coverage` contains HOST-A's pair → both **Resolved** (today: absent).
2. STIG not re-scanned: baseline has findings for (HOST-A, "Microsoft Edge STIG SCAP Benchmark"); current coverage lacks that pair, host still present via another STIG → those findings **Not re-scanned**, zero Resolved (today: Resolved).
3. Newly scanned STIG: current has findings on a pair absent from baseline coverage → **Newly scanned**, zero New.
4. Host only in current coverage → all **Newly scanned**; host only in baseline coverage → all **Not re-scanned**.
5. Edition-neutral key: pair recorded as "Microsoft Windows 11 STIG SCAP Benchmark" in baseline and "Microsoft Windows 11 Security Technical Implementation Guide" in current is one pair; Nessus "DISA_STIG_MS_Windows_11_v2r8.audit" vs "..._v2r9.audit" is one pair.
6. Pass 2 ignores blank rule_id: baseline V-1, V-2 with blank vuln_id and blank rule_id; current V-1, V-3 → no false Persisting, V-2 Resolved, V-3 New (given coverage).
7. Pass 2 matches on rule stem: `xccdf_mil.disa.stig_rule_SV-1r1_rule` vs `SV-1r2_rule`, blank vuln_ids → Persisting.
8. Sort order uses the normalised host key ("apple" before "Zeta").
9. Warnings: no-overlap, not-re-scanned pairs, newly-scanned pairs each produce an entry in `DeltaResult.warnings`.
Update existing tests that pinned the old behaviour (`test_empty_current_all_not_rescanned`, `test_current_only_host_all_new`, `test_baseline_only_host_not_counted_resolved`, `TestEmptySets`) to the R2 semantics; every existing `compute_delta` call gains explicit coverage (add a test helper `cov(findings)` that builds pairs from findings for the simple cases).

## 2. `app/processors/delta.py`
- Add `_stig_key`, `_rule_stem` (strip `^xccdf_[^_]+_rule_`, strip `r\d+_rule$`), `_pair_key(server, stig_title)`.
- `DeltaResult` gains `not_rescanned_pairs: set[(str, str)]`, `newly_scanned_pairs: set[(str, str)]` (raw spellings, first seen), keeps `common_hosts`, `only_baseline_hosts`, `only_current_hosts` derived from coverage.
- `compute_delta(baseline, current, *, baseline_coverage, current_coverage)` per R2-3/R2-4. `_rule_key` returns None for blank rule_id and uses the stem.
- `DELTA_STATUSES` per R2-5; module constants `_NOT_RESCANNED`, `_NEWLY_SCANNED`.
- Append the R2-6 warnings inside `compute_delta` (move the two CLI-only messages here; keep wording, drop the sentence claiming a clean scan "contributes no hosts").

## 3. `app/core/pipeline.py` (+ `tests/test_pipeline.py`)
- `ParseResult.coverage: set[tuple[str, str]]`. Build it before `filter_findings`: `{(f.server, f.stig_title) for f in sc_findings}` ∪ `scan_coverage(scan_results, benchmarks)`.
- New `scan_coverage()` in `app/processors/matcher.py`: one `(scan.hostname, benchmark.title or "")` per `ScanResult` using `_find_benchmark`. Test: an all-pass XCCDF scan yields a pair and zero findings.
- R2-7: compute `total_rules` first; raise when it is 0 regardless of `allow_empty`; raise the "none actionable" message only when `not allow_empty`. Test: `sample_benchmark.xml` as a results file raises even with `allow_empty=True`.

## 4. `app/exporters/excel_exporter.py` (+ `tests/test_excel_exporter.py`)
- `_DELTA_STATUS_COLOR` gains `"Not re-scanned": "D9D9D9"` (grey) and `"Newly scanned": "DDEBF7"` (light blue); the KeyError-at-import guard stays.
- Coverage block: "Hosts compared", then "Host / STIG pairs not re-scanned" (one row per pair: host in col B, STIG in col C), then "Host / STIG pairs newly scanned". Footer note rewritten: "'Resolved' means a baseline finding is absent from the current scan of the SAME host and STIG. Pairs not re-scanned are listed above and are never counted as resolved."
- Tests: every status in `DELTA_STATUSES` has a Summary row and a fill; pair rows present and sanitised; single-run `export()` output unchanged (existing tests).

## 5. `app/cli.py` (+ `tests/test_cli.py`)
- Pass `baseline_coverage=base_res.coverage`, `current_coverage=curr_res.coverage`.
- Remove the two inline coverage warnings (now in `delta.warnings`); keep draining `delta.warnings` to the log.
- Summary line counts all five statuses. Fix the existing tests that asserted the old messages.
- Optional, last: `_misplaced_subcommand` should skip a value-taking flag's values instead of stopping the scan (minor review finding).

## 6. Docs
- README `delta` section: the five tags and what each means; "Resolved requires the same host and STIG in the current set"; coverage block description.
- `CODEBASE_INDEX.md` delta line if it describes behaviour.

## 7. Done when
- `python -m pytest -q -p no:cacheprovider` green; new tests failed before their step and pass after.
- No `compute_delta` call without explicit coverage anywhere in `app/` or `tests/`.
- Live acceptance (run by the orchestrator on the real May session, not committed): 322 Persisting / 90 Newly scanned / 90 Not re-scanned / 322 Resolved for the four scenarios in the spec.
