# STIG Condenser — AWS GovCloud Re-Platform (Master Architecture)

**Date:** 2026-07-07
**Status:** Approved architecture — pending per-sub-project implementation specs
**Scope:** Master design for re-platforming STIG Condenser to run fully-private on AWS GovCloud, serverless, with an optional AWS Bedrock enrichment stage and a React frontend.

---

## 1. Purpose & Drivers

STIG Condenser parses XCCDF compliance scan results (SCC, OpenSCAP, Nessus SCAP, Evaluate-STIG), cross-references STIG benchmark definitions, and produces a consolidated Excel findings report. Today it is a Flask web app + CLI with a Jinja/vanilla-JS UI and no cloud dependencies and no AI.

Four new hard requirements force a re-platform:

1. **Runs on AWS GovCloud** (partition `aws-us-gov`).
2. **All LLM work goes through AWS Bedrock** (no other model providers).
3. **Frontend is React.**
4. **Backend infrastructure is provisioned/modifiable with Terraform.**

Additional constraints captured during design:

- **Deployment is fully private.** No public endpoint. Access is VPC-internal only via VPN / Direct Connect / PrivateLink. Authentication is handled **upstream** (VPN + org IdP / CAC-PKI); the app trusts the network boundary and may read an identity header.
- **Compute model is Lambda + API Gateway** (occasional-use workload).
- **AI is optional.** Core functionality (deterministic XML→Excel) must work with Bedrock fully disabled or unavailable. AI is a feature-flagged enrichment layer, never a dependency.
- Output feeds accreditation paperwork — correctness and auditability are paramount.

---

## 2. Key Architectural Facts (non-negotiable)

- **API Gateway integration timeout is 29 seconds.** Parsing many findings plus optional (slow) Bedrock calls exceeds this immediately. **Processing MUST be asynchronous** — no synchronous request/response processing path.
- **API Gateway sync payload cap (10 MB) and Lambda sync payload cap (6 MB).** Scan uploads can exceed this. Uploads use **S3 presigned-URL PUT**, never direct POST through the API.
- **Fully private ⇒ no CloudFront** (CloudFront is a public edge service). The React SPA is served from private S3 via an S3 interface VPC endpoint behind the Private API Gateway.
- **Lambda runs inside the VPC** (private subnets, no Internet Gateway, no NAT). All AWS service access is via **VPC endpoints**.
- **Bedrock is reached via an interface VPC endpoint (PrivateLink).** Finding data never leaves the VPC boundary.
- **Bedrock in GovCloud lives in `us-gov-west-1`.** The exact available foundation model ID must be confirmed against `us-gov-west-1` Bedrock at implementation time (do not hard-code an assumed ID).

---

## 3. Target Architecture

Serverless, fully-private, event-driven. The existing deterministic parsing/export logic is reused unchanged and re-wrapped as asynchronous job stages.

### 3.1 Components

| Component | Role |
|---|---|
| **React SPA** | Vite-built static SPA. Hosted in a private S3 bucket, served through an S3 interface VPC endpoint behind the Private API Gateway. Preserves the existing design tokens (colors, layout, light/dark) from the prior design overhaul. |
| **Private REST API Gateway** | Resource policy restricts invocation to the VPC interface endpoint only. Routes below. |
| **API Lambda** | In-VPC. Issues S3 presigned URLs, starts the Step Functions execution, returns/reads job status. |
| **Step Functions state machine** | Orchestrates the async job: `Parse → Choice(AI enabled?) → [Bedrock Enrich] → Export → Done`. Each work stage is its own Lambda. Splitting stages sidesteps the per-Lambda 15-minute limit on large scans. |
| **Stage Lambdas** | `parser`, `enricher` (Bedrock), `exporter`. Thin handlers wrapping the existing `parsers/`, `processors/`, `exporters/` Python modules. |
| **DynamoDB job table** | Lightweight job/status record: `jobId`, `status`, S3 keys, `error`, timestamps, TTL for auto-cleanup. |
| **S3 buckets** | `uploads` (input scans) and `artifacts` (generated Excel + intermediate normalized findings JSON). SSE-KMS with a customer-managed key, block-public, lifecycle expiry. |
| **Bedrock** | Reached via interface VPC endpoint. `bedrock-runtime:InvokeModel` with a foundation model (GovCloud model ID confirmed at impl time). |
| **VPC** | Private subnets, no IGW/NAT. Interface endpoints: `execute-api`, `bedrock-runtime`, `states`, `logs`, `kms`, `sts`. Gateway endpoints: `s3`, `dynamodb`. |
| **IAM** | Least-privilege role per Lambda. All ARNs use the `aws-us-gov` partition. |
| **Observability** | CloudWatch logs + metrics; optional X-Ray tracing; CloudTrail S3 data events for audit. |

### 3.2 API routes

| Method + path | Purpose |
|---|---|
| `POST /uploads` | Returns a presigned S3 PUT URL for a scan file. |
| `POST /jobs` | Body `{ keys: [...], aiEnabled?: bool }`. Writes job row, `StartExecution` on the state machine, returns `jobId`. |
| `GET /jobs/{id}` | Returns job status (`PENDING` / `RUNNING` / `DONE` / `ERROR`) + any warnings. |
| `GET /jobs/{id}/result` | Returns a presigned S3 GET URL for the finished Excel report. |

### 3.3 Data flow

1. User (on VPN) loads the SPA from private S3.
2. SPA calls `POST /uploads`; API Lambda returns a presigned S3 PUT URL.
3. SPA PUTs the scan file(s) directly to the `uploads` bucket.
4. SPA calls `POST /jobs` with the uploaded keys and `aiEnabled`; API Lambda writes a job row and starts the Step Functions execution; returns `jobId`.
5. State machine: **Parse** Lambda reads uploads → normalized findings JSON in S3 → **Choice** on AI flag → optional **Enrich** Lambda (Bedrock) → **Export** Lambda writes Excel to `artifacts` → DynamoDB `status=DONE`.
6. SPA polls `GET /jobs/{id}` until `DONE` or `ERROR`.
7. SPA calls `GET /jobs/{id}/result` → presigned S3 GET → downloads the Excel report.

---

## 4. Optional AI Layer (feature-flagged)

- **Two independent gates:** a per-request `aiEnabled` flag AND a global kill-switch in SSM Parameter Store. AI runs only if both allow it and the Bedrock endpoint is reachable.
- The Step Functions **`Choice` state** is the toggle: when AI is off, the flow routes straight from Parse to Export.
- **Enrichment failure is non-fatal.** Any Bedrock error degrades gracefully to the deterministic core report plus a warning surfaced in job status. The core report is never blocked by AI.
- **AI jobs (all optional):**
  - **Finding narratives** — plain-language explanation / remediation text per open finding.
  - **POA&M drafting** — Plan of Action & Milestones entries (mitigation, milestones, dates) from failed findings.
  - **Scan summary** — executive compliance-posture summary across all findings.
  - **Categorize / dedupe** — semantic clustering and duplicate reconciliation across scanners.
- **Model access:** `bedrock-runtime:InvokeModel` on a foundation model in `us-gov-west-1`, via the Bedrock interface VPC endpoint. Prompt content = finding text; it stays inside the VPC via PrivateLink. Bedrock does not train on invocation data.

### 4.1 Determinism & provenance (hard requirements for #4)

- **Availability never decides silently.** Unavailability may *degrade* a run (deterministic report + loud "AI enrichment unavailable" warning in job status AND in the report itself); it must never silently produce a report that differs from what the user requested. Same scan + same request = same report shape, always.
- **All AI-generated content is labeled.** Any Bedrock-drafted text in the Excel report or POA&M output is explicitly marked as AI-drafted, pending human review. Unlabeled LLM text must never appear in accreditation artifacts.
- **Provenance stamped in job metadata:** model ID, prompt version, `aiRequested`, `aiRan`. Every report is auditable and reproducible.
- **Gate transparency:** the job record states *which* gate blocked AI when it did not run — `ai: disabled-by-request | disabled-globally | failed | done`.
- **Cost/runtime guardrails designed in, not bolted on:** cap on findings enriched per job, batching strategy, summarize-above-threshold fallback. Rate limiting in the enricher — GovCloud Bedrock quotas are low.

---

## 5. Backend Re-Architecture (Sub-project #1 — foundation)

The current `web.py` couples request → parse → export synchronously. The existing domain modules (`app/parsers/`, `app/processors/`, `app/exporters/`, `app/utils/`) are already well-factored and are **reused as-is**.

- Introduce a **job-orchestration boundary**: pure functions that (a) parse an upload set into normalized findings, (b) optionally enrich, (c) export to Excel — each taking/returning S3-addressable artifacts.
- Provide **Lambda handlers** (`backend/handlers/`) that wrap those functions for the parse / enrich / export stages plus the API Lambda.
- **Preserve** the synchronous Flask `web.py` path and the CLI for local development and testing — they call the same core functions. No behavior change to the CLI.
- The async orchestration (Step Functions wiring) lives in infra (#2); the backend exposes stage entrypoints it can call.

---

## 6. Terraform IaC (Sub-project #2)

- Provider pinned to the `aws-us-gov` partition; region `us-gov-west-1` (Bedrock) — confirm East/West split for other services per org standard.
- Modules: `network` (VPC, subnets, endpoints), `storage` (S3 + KMS + lifecycle), `data` (DynamoDB), `compute` (Lambdas, layers), `orchestration` (Step Functions), `api` (Private API GW + resource policy), `iam` (least-priv roles), `observability` (log groups, CloudTrail data events).
- Environments via workspaces or `envs/` dirs. Remote state in an encrypted S3 backend + DynamoDB lock (GovCloud).
- Static analysis in CI: `terraform validate`, `tflint`, `checkov`.
- **Stage idempotency contract:** Step Functions will retry stages. Every stage must be safely re-runnable — artifact writes overwrite (never duplicate/corrupt), job-status updates converge. Make this an explicit requirement in the state-machine design, verified per stage.
- **Public-repo discipline:** this repo is public. Account IDs, VPC/endpoint IDs, and any environment-specific values live only in `*.tfvars` (gitignored; `*.tfvars.example` committed with placeholders). A leak check is part of the #2 review gate.
- **Known cost floor:** interface VPC endpoints bill hourly (~$7–8/mo each). With 6–7 endpoints the environment costs ~$50+/mo at zero usage — the dominant idle cost, exceeding Lambda. Accepted consequence of the fully-private requirement; document in the env README so the first bill isn't a surprise.
- **Known friction — private SPA serving:** serving React assets through Private API GW (S3 proxy) is workable but fiddly (binary media types, no CDN caching, per-request cost/latency). Fallback options if it bites: serve the SPA from the API Lambda, or a small internal ALB. Decide during #2 implementation; #1's abstractions keep either swap cheap.

---

## 7. React Frontend (Sub-project #3)

- Vite SPA. Screens: upload (drag/drop, presigned PUT), AI toggle, job progress/polling, warnings display, result download.
- **Preserve the existing design system** (utilitarian/industrial precision, light + dark via `light-dark()`, WCAG AA / Section 508). Port the current `style.css` tokens into the React app rather than restyling from scratch.
- No external runtime dependencies assumed beyond the React/Vite toolchain; keep the bundle lean.
- Built assets deployed to the private S3 SPA bucket by Terraform/CI.

---

## 8. Security & Accreditation

- **No public ingress.** Private API Gateway resource policy restricts to the VPC interface endpoint; SPA served privately; Lambda in private subnets with no IGW/NAT.
- **Encryption:** SSE-KMS (CMK) at rest on all S3 + DynamoDB; TLS in transit via VPC endpoints.
- **Least privilege:** one IAM role per Lambda, scoped to exact ARNs, `aws-us-gov` partition.
- **Data handling:** Bedrock prompts (finding text) stay in-VPC via PrivateLink; document data-flow for the ATO package. No third-party model providers.
- **Audit:** CloudWatch logs/metrics; CloudTrail S3 data events; job records retained (with TTL) for traceability.
- **CUI handling (explicit):** scan results and derived findings are treated as CUI. State this in the ATO data-flow documentation; apply CUI marking guidance to generated reports where org policy requires it; retention/deletion (S3 lifecycle, DynamoDB TTL) is set per records policy — TTL values are a policy decision, not a convenience default. Confirm marking requirements with the ISSO during #2.
- Run a security review before shipping infra and the Bedrock stage.

---

## 9. Testing Strategy

- **Core logic:** keep the existing pytest suite for parsers/processors/exporters — logic is unchanged.
- **Handlers:** unit tests with `moto` mocking S3 / DynamoDB / Step Functions.
- **Stages:** unit test each state-machine stage independently.
- **Bedrock:** mock `bedrock-runtime`; contract test prompt construction + response parsing; verify graceful degradation on error.
- **Infra:** `terraform validate` + `tflint` + `checkov` in CI.
- **Frontend:** React component tests + Playwright e2e against a mocked API.

---

## 10. Repository Layout (monorepo)

```
/backend    # python: app/ (reused core), handlers/ (lambda entrypoints), tests/
/frontend   # react/vite SPA
/infra      # terraform modules + envs (aws-us-gov)
/docs/superpowers/specs
```

---

## 11. Decomposition & Build Order

Each sub-project gets its own implementation spec → plan → build cycle. This master doc holds the cross-cutting decisions (partition, private boundary, VPC endpoints, async orchestration, AI-optional contract) that bind all four.

1. **#1 Backend async re-architecture** — foundation; everything depends on the async job shape and stage entrypoints.
2. **#2 Terraform IaC** and **#3 React frontend** — parallel, once #1's runtime shape is fixed.
3. **#4 Bedrock enrichment** — last; plugs into the `Choice` state and stage contract.

---

## 12. Open Items (resolve at implementation time)

- Confirm the exact foundation model ID available in `us-gov-west-1` Bedrock.
- Confirm GovCloud region split (West vs East) for non-Bedrock services per org policy.
- Confirm upstream auth mechanism specifics (VPN + IdP / CAC) and whether an identity header is passed to the app.
- Confirm org standards for Terraform state backend and CI runner placement (must reach GovCloud).
