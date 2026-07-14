# STIG Condenser — Sub-project #3: React Frontend (Design Spec)

**Date:** 2026-07-14
**Status:** Draft — pending review, then plan → build
**Parent:** [GovCloud Re-Platform master architecture](2026-07-07-govcloud-replatform-design.md) §7
**Depends on:** #2 Terraform IaC ([PR #7](https://github.com/Redirishman/stig-parser/pull/7)) — the private API, the SPA bucket, and the `apigw_s3_proxy` serving path
**Blocks:** nothing. #4 (Bedrock enrichment) consumes the AI toggle this ships, but does not require it.

---

## 1. Goal & Non-Goals

**Goal:** Port the existing Flask/Jinja + vanilla-JS UI to a React SPA that speaks the GovCloud async API, **preserving the design system and the accessibility work verbatim** rather than restyling from scratch.

**Non-goals:**
- Replacing the Flask UI. It stays (see §2).
- The Bedrock prompt logic (#4). This ships the *toggle* and the gate display, not the enrichment.
- A CDN, SSR, or offline mode.
- The `/backend` monorepo rename. `frontend/` is added additively beside `app/` and `infra/`.

---

## 2. Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| F1 | **Keep the Flask UI.** React serves GovCloud; Flask serves local/air-gapped use. | The Flask app is the only zero-infrastructure way to run this tool. Deleting it strands local operators who have no API to point at. Two UIs is a real cost, accepted deliberately. |
| F2 | **The SPA targets the GovCloud API only.** | Abstracting over both the Flask multipart contract and the async presigned contract doubles the client and its test surface to serve a user who does not exist — anyone running Flask already has the Flask UI. |
| F3 | **Port `style.css` nearly as-is**, class names intact. No CSS framework, no CSS-in-JS. | The stylesheet carries an audited token system, 20/20 verified WCAG contrast pairs, focus rings, and a light/dark story. Re-deriving that under a new styling paradigm risks silently regressing it, and the project constraint is explicitly "no CSS framework". |
| F4 | **Thin architecture:** no router, no state library. | The UI is a three-state machine (upload → progress → result) with one job in flight. A router would add a URL contract to a single-page app; a state library would add ceremony around one hook. |
| F5 | **`GET /config` and `POST /jobs/{id}/cancel` are added to the API in PR #7.** | Both are gaps the SPA cannot paper over. See §3. |
| F6 | **AI toggle renders disabled, with the reason,** when AI is unavailable. | Master spec §4.1 requires gate transparency: AI being off is never silent. Hiding the control would leave the operator unaware the capability exists or why it is off. |
| F7 | **`jobId` persists in `localStorage`;** a stored non-terminal job resumes polling on mount. | Replaces the Flask server-session reconnect. Without it, an accidental refresh during a long parse loses sight of a job that is still running and still billing. |

---

## 3. API additions (land in PR #7 before it merges)

These are **not** frontend conveniences; the SPA is incorrect without them.

### 3.1 `GET /config`

```json
{ "aiAvailable": false,
  "aiReason": "disabled-globally",
  "maxUploadBytes": 209715200,
  "allowedExtensions": [".cklb", ".nessus", ".xml", ".zip"] }
```

Two problems it solves:

1. **The AI gate is server-side state.** `bedrock_model_id` and the SSM killswitch are known only to the API. Today the gate is reported *after* a job is submitted — too late to render a disabled toggle with an honest reason (F6). Without `/config` the SPA would have to guess at the gate, which is exactly the silent-failure mode §4.1 forbids.
2. **The upload allow-list would fork.** The SPA validates files client-side for fast feedback. Hardcoding the extension list and size cap in TypeScript creates a second copy that drifts from `app/core/uploads.py` — the precise drift that module was created to prevent. `/config` serves the server's values, so there is one source of truth.

`aiReason` reuses the existing gate vocabulary (`disabled-by-request` | `disabled-globally` | `failed` | `done`).

**Client-side validation is a courtesy, not a control.** The API re-validates every filename server-side; a client check is bypassable by definition and is never the security boundary.

### 3.2 `POST /jobs/{id}/cancel`

Calls `states:StopExecution` and marks the job `cancelled`. Requires adding `states:StopExecution` to the api role (it currently holds only `StartExecution`).

**Race:** the execution can finish between the operator's click and `StopExecution` landing. The endpoint therefore returns the job's *actual* resulting status rather than asserting `cancelled` — the same honesty the Flask UI already practises (`test_cancel_finished_job_reports_final_status`).

Without this endpoint the ported Cancel button would be a dead control, or worse, a client-side lie that stops polling while the job keeps running and billing.

---

## 4. Architecture

```
frontend/
├── index.html
├── package.json
├── vite.config.ts
├── src/
│   ├── main.tsx
│   ├── App.tsx              # 3-state switch: upload | progress | result
│   ├── api.ts               # typed wrappers; the only place a URL appears
│   ├── useJob.ts            # THE async lifecycle. The only stateful module.
│   ├── types.ts
│   ├── components/
│   │   ├── UploadZone.tsx   # used twice: results, benchmarks
│   │   ├── ActivityLog.tsx
│   │   ├── ResultCard.tsx
│   │   ├── WarningsBox.tsx
│   │   └── AiToggle.tsx
│   └── styles/
│       ├── style.css        # ported from app/static/style.css
│       └── fonts/           # PublicSans-*.woff2, OFL.txt
└── tests/
    ├── unit/                # Vitest + RTL
    └── e2e/                 # Playwright vs mocked API
```

**`useJob.ts` carries all the complexity** — upload, submit, poll, cancel, reconnect, terminal states. Everything else is presentational. This is deliberate: the hard part is then testable in isolation, and the components stay trivial enough to review at a glance.

---

## 5. Data flow

1. **Mount** → `GET /config`. Gate + limits in hand before the operator can do anything.
2. **File selection** → validate name/extension/size against `/config`.
3. `POST /uploads {filenames}` → `{jobId, uploads:[{filename, url}]}`. Persist `jobId`.
4. **`PUT` each file directly to S3** via its presigned URL. Bytes never traverse a Lambda — this is what keeps a 200 MB scan clear of the 29-second API Gateway timeout. Per-file progress via `XMLHttpRequest.upload` (`fetch` still cannot report upload progress).
5. `POST /jobs {jobId, ai}` → the Step Functions execution starts.
6. **Poll `GET /jobs/{id}` every 1s** (matching the Flask cadence) → drives the activity log, warnings, and stall detection.
7. On `complete` → `GET /jobs/{id}/result` → presigned GET → download.

`jobId` is cleared on any terminal state (`complete`, `error`, `cancelled`) and on reset.

---

## 6. Failure handling

Each of these is a real path, not a hypothetical:

| Failure | Behaviour |
|---------|-----------|
| **Presigned PUT fails or expires** | Presigned URLs live 15 minutes; a slow 200 MB upload over VPN can outlive one. Report per-file, offer retry. **Never** mark the job started when its bytes are not all there. |
| **Poll fails repeatedly** | Dead-backend notice after N consecutive failures (the existing `app.js` uses 10). |
| **Job stalls** | "Still working — large files can take a few minutes" after ~20s with no change, as today. |
| **`GET /result` → 410** | The report expired via the D5 retention window. Say *that* — not "download failed". |
| **`GET /result` → 409** | Not ready yet; keep polling rather than surfacing an error. |
| **AI gate** | Render the job's `ai` field plainly: `disabled-by-request`, `disabled-globally`, `failed`, `done`. Never silence. |
| **Cancel races completion** | Show the status the API actually returns. |

---

## 7. Accessibility (hard requirement)

Section 508 / WCAG AA is a hard requirement for this audience, and the Flask UI's `/audit` score (18/20) is the **floor**, not the target. Ported wholesale:

- Real `<button>` elements for Choose Files (never a click-handler on a div)
- `:focus-visible` rings; full keyboard operability
- `aria-live` regions; `role="status"` / `role="alert"` / `role="log"`
- `<ul>` file lists; `<dl>` for the findings summary
- `prefers-reduced-motion` block honoured
- 44px minimum touch targets under `pointer: coarse`
- Light + dark via `prefers-color-scheme`

**Verified,** not asserted: `axe-core` assertions in the component tests, plus a keyboard-only Playwright pass.

---

## 8. Testing

- **Vitest + React Testing Library** — `useJob` (state machine, retry, reconnect, terminal states, cancel race) and every component. `useJob` gets the deepest coverage; it holds all the complexity.
- **Playwright e2e against a mocked API** — the full flow: select files → presigned PUT → poll → download. Plus a cancel path, an expired-report path, and a keyboard-only pass.
- **CI** — `npm run build`, `npm test`, `npx playwright test`, and `tsc --noEmit` on any change under `frontend/`. The existing leak scan already covers the new directory.

Mocking the API (rather than standing up the real one) is what the master spec calls for, and it keeps CI free of GovCloud credentials.

---

## 9. Deployment

Vite build → `frontend/dist/` → synced to the `spa_bucket` that PR #7 provisions → served through the API Gateway S3 proxy (D6, `apigw_s3_proxy`).

**The S3 sync is an operator/CD step, not a public-CI step** — the same boundary `terraform apply` sits behind. Public CI builds and tests the bundle; it never holds GovCloud credentials.

The API base URL is injected at build time (`VITE_API_BASE`). It is the *only* environment-specific value in the bundle, and it is a VPC-internal URL — no secret, but it stays out of tracked files per the §5 leak discipline of the #2 spec.

---

## 10. Build order (feeds the plan)

1. **API additions to PR #7**: `GET /config`, `POST /jobs/{id}/cancel`, `states:StopExecution` IAM grant, tests.
2. `frontend/` scaffold: Vite + React + TS, `style.css` + fonts ported, `npm run build` green.
3. `types.ts` + `api.ts` — the typed client.
4. `useJob.ts` — the lifecycle, TDD'd against the mocked client.
5. Components: `UploadZone`, `ActivityLog`, `WarningsBox`, `ResultCard`, `AiToggle`.
6. `App.tsx` — assemble the three states.
7. Playwright e2e + axe passes.
8. CI workflow (`frontend.yml`).
9. `frontend/README.md` — build, test, deploy, and the `VITE_API_BASE` contract.

---

## 11. Definition of Done

- `npm run build`, `npm test`, `tsc --noEmit`, and Playwright e2e all green in CI.
- axe-core reports no violations on any of the three screens.
- Full keyboard-only operation verified (no mouse).
- Light and dark both render correctly; contrast pairs unchanged from the audited stylesheet.
- The AI toggle states its gate reason when unavailable — never silently absent.
- Cancel actually stops the execution (verified against the mocked API; the real `StopExecution` is exercised only on a live apply).
- The Flask UI still passes its existing tests — the port must not regress it.

---

## 12. Open questions

1. **`VITE_API_BASE` at build time vs runtime.** Build-time is simpler and is assumed here, but it means one bundle per environment. A runtime `config.json` fetched from the SPA bucket would allow one bundle everywhere. Deferred until an operator actually runs two environments.
2. **Does the org mandate a Node/npm registry mirror?** An air-gapped build host may not reach npmjs.com. Affects CI and the operator build step, not the design.
3. **Is `apigw_s3_proxy` (D6) actually workable in practice?** It is unproven — nothing has been applied to GovCloud yet. If binary media types bite, the `lambda_served` fallback exists and this SPA is unchanged by the swap.
