# STIG Condenser — Sub-project #2: Terraform IaC (Implementation Spec)

**Date:** 2026-07-13
**Status:** Draft — pending review, then plan → build
**Parent:** [GovCloud Re-Platform master architecture](2026-07-07-govcloud-replatform-design.md) §6
**Depends on:** #1 Backend async re-architecture (stage entrypoints exist: `app/core/stages.py`, `ArtifactStore`, `JobStore`)
**Blocks:** #3 React frontend (SPA bucket + API), #4 Bedrock enrichment (Choice state + enricher Lambda)

---

## 1. Goal & Non-Goals

**Goal:** Provision the entire GovCloud runtime for STIG Condenser as reviewable, `apply`-able Terraform — VPC, private endpoints, S3+KMS, DynamoDB, Lambdas, Step Functions, Private API Gateway, IAM, observability — parameterized so the **public repo carries zero environment-specific values**.

**Non-goals (this sub-project):**
- Lambda application code beyond thin handlers already delivered by #1 (the async stage functions are reused; #2 packages and wires them).
- React app code (#3) — #2 provisions the empty SPA bucket + serving path and the deploy hook; the bundle is #3's.
- Bedrock prompt logic (#4) — #2 provisions the `bedrock-runtime` VPC endpoint, the enricher Lambda shell, IAM, and the `Choice` state; prompt construction is #4's.

---

## 2. Prerequisite Decisions (org-owned — confirm before `apply`, not before authoring)

These are the master-doc §12 open items. **None block *authoring* the modules** — all become Terraform variables with placeholder values in `*.tfvars.example`. They block a real `apply`, and each is called out at its use site.

| # | Decision | Owner | Terraform surface | Default in example |
|---|---|---|---|---|
| D1 | Region split (West vs East for non-Bedrock services) | Org cloud team | `var.aws_region`, `var.bedrock_region` | `us-gov-west-1` both |
| D2 | Remote state backend (bucket, lock table, KMS key) | Org cloud team | `backend "s3"` block in `envs/*/backend.tf` | placeholders + `.example` |
| D3 | Upstream auth: identity header name, or none | ISSO / network | `var.identity_header` (API GW → Lambda mapping) | `"x-forwarded-user"` |
| D4 | Claude model ID in `us-gov-west-1` Bedrock | Confirm at #4 | `var.bedrock_model_id` | `""` (AI off until set) |
| D5 | CUI marking + retention (S3 lifecycle days, DynamoDB TTL days) | ISSO / records | `var.artifact_retention_days`, `var.job_ttl_days` | conservative placeholders, commented "policy decision" |
| D6 | Private-SPA serving path and exact browser upload origin(s) | This sub-project | `var.spa_serving_mode`, `var.additional_upload_cors_origins` | `"apigw_s3_proxy"`; managed API origin only (see §6) |
| D7 | Approved private client CIDRs and return-route ownership/targets | Org network team | `var.api_client_cidr_blocks`, `var.api_client_route_management`, `var.api_client_routes` | no client or route-owner default |

**Recommendation:** proceed to author all modules against these variables now. Do not hard-code any account ID, VPC ID, or endpoint ID anywhere in committed `.tf`.

---

## 3. Repository Structure

Master §10 specifies a monorepo (`/backend /frontend /infra`). Current reality: everything under `stig-parser/app/`. **Recommendation for #2: additive, not a big-bang move.**

- Add `stig-parser/infra/` now (Terraform is self-contained; no code moves required).
- Defer the `/backend` + `/frontend` rename to when #3 lands (that's when a second top-level app appears and the rename pays for itself).
- The Lambda packaging step references the Python source at its **current** path (`stig-parser/app/`) via a variable (`var.backend_source_dir`) so the eventual rename is a one-line change.

```
stig-parser/infra/
├── README.md                 # cost floor warning, apply order, decision log
├── .gitignore                # *.tfvars, .terraform/, *.tfstate*, plan output
├── versions.tf               # required_providers, aws-us-gov, TF version pin
├── modules/
│   ├── network/              # VPC, subnets, route tables, interface+gateway endpoints, SGs
│   ├── storage/              # S3 uploads+artifacts, CMK, block-public, lifecycle
│   ├── data/                 # DynamoDB job table (+ TTL)
│   ├── compute/              # Lambda functions, layers, packaging, log groups
│   ├── orchestration/        # Step Functions state machine + IAM
│   ├── api/                  # Private REST API GW + resource policy + routes/integrations
│   ├── iam/                  # per-Lambda least-priv roles/policies (aws-us-gov ARNs)
│   └── observability/        # log retention, CloudTrail S3 data events, optional X-Ray
└── envs/
    └── example/              # one env wiring the modules together
        ├── backend.tf.example
        ├── main.tf           # module composition
        ├── variables.tf
        ├── terraform.tfvars.example   # ALL placeholders, committed
        └── outputs.tf
```

---

## 4. Module Contracts

Each module lists its non-obvious inputs, key resources, and outputs consumed downstream. All ARNs constructed with `data.aws_partition.current.partition` (== `aws-us-gov`), never a literal `aws`.

### 4.1 `network`
- **In:** `vpc_cidr`, `az_count`, `private_subnet_cidrs`, `interface_endpoint_services` (list), approved API-client CIDRs and return-route ownership/targets, `enable_x_ray`.
- **Resources:** VPC (no IGW, no NAT); private subnets across AZs; route tables; **interface endpoints** for `execute-api`, client-facing `s3`, `bedrock-runtime`, `states`, `logs`, `kms`, `sts` (+ `monitoring` if X-Ray); **gateway endpoints** for Lambda `s3` and `dynamodb`; Lambda-only runtime endpoint SG; separate execute-api and S3-client SGs allowing TCP/443 only from approved operator networks; optional static client return routes; Lambda SG with gateway prefix-list egress. GovCloud S3 private DNS is unsupported, so presigned URLs use the interface endpoint's Regional endpoint-specific DNS name. VPN/DX/TGW/VGW attachments, reciprocal routes, and execute-api hybrid DNS are organization-managed prerequisites.
- **Out:** `vpc_id`, `private_subnet_ids`, `lambda_sg_id`, execute-api endpoint/SG/DNS outputs, S3 interface and gateway endpoint ids, S3-client SG/DNS outputs, and the Regional S3 presigning endpoint URL.
- **⚠ Cost:** PrivateLink bills per endpoint-hour in each selected AZ plus data processing. Seven required services across two AZs produce 14 billed endpoint-AZ units (+2 for optional monitoring); README must state this and require a current GovCloud estimate.

### 4.2 `storage`
- **In:** `kms_key_arn` (or create CMK here), `artifact_retention_days`, `upload_retention_days`.
- **Resources:** `uploads` + `artifacts` buckets — SSE-KMS (CMK), block-public-access all four flags, versioning, lifecycle expiry (D5), bucket policy denying non-TLS access. The API role's `aws:SourceVpce` conditions enforce the presigned object path without breaking organization-admin access. CMK with rotation.
- **Out:** `uploads_bucket`, `artifacts_bucket`, `kms_key_arn`.

### 4.3 `data`
- **Resources:** DynamoDB `jobs` table — PK `jobId`, on-demand billing, SSE with CMK, TTL attribute `expiresAt` (D5), point-in-time recovery on. Matches the `DynamoJobStore` single-item-per-job shape from #1 (fields JSON-encoded into a `data` attribute).
- **Out:** `job_table_name`, `job_table_arn`.

### 4.4 `compute`
- **In:** `backend_source_dir`, `job_table_name`, bucket names, `kms_key_arn`, `state_machine_arn` and the Regional S3 PrivateLink presigning URL (API Lambda only), subnet/SG ids, `bedrock_model_id`, `bedrock_region`, `identity_header`, `ai_killswitch_param` (SSM).
- **Resources:** five Lambdas — `api`, `parser`, `enricher`, `exporter`, `marker` — each in-VPC, each with its `iam` role. Packaging: `archive_file` zip of `backend_source_dir` + handler shims; a shared **layer** for `lxml`/`openpyxl` (lxml needs the Linux wheel — build note in README; runtime boto3 is not vendored). Per-function log group with retention.
- **Out:** function ARNs (orchestration + api wiring), enricher name.
- **Note:** stage Lambdas call the #1 entrypoints `run_parse_stage` / `run_export_stage` with an `S3ArtifactStore` + `DynamoJobStore`. Confirmed those already exist and are boto3-boundaried.

### 4.5 `orchestration`
- **Resources:** Step Functions **standard** state machine: `Parse → Choice(aiEnabled && killswitch off) → [Enrich] → Export → Done`, with `Catch` → `MarkError` → `Fail` on every stage. Retry policy per stage (transient errors only). Execution role scoped to invoke exactly the four stage functions.
- **§6 idempotency contract (hard req):** each stage is safely re-runnable — artifact writes **overwrite** (deterministic S3 keys from `jobId`, never append/suffix), job-status updates **converge** (last-writer-wins on a single item). Verified per stage in #9.
- **Out:** `state_machine_arn`.

### 4.6 `api`
- **In:** `execute_api_endpoint_id`, stage function ARNs, `identity_header`, `spa_serving_mode`, uploads bucket, and optional exact upload-CORS origins.
- **Resources:** **Private** REST API GW; **resource policy** allowing invoke ONLY via the VPC interface endpoint (deny all else); routes `POST /uploads`, `POST /jobs`, `GET /jobs/{id}`, `GET /jobs/{id}/result` → API Lambda proxy; SPA serving per D6/§6; binary media types if S3-proxy mode; uploads-bucket CORS limited to exact origins, `PUT`, and `Content-Type`. No API key, no public stage.
- **Out:** `api_id`, `invoke_url` (VPC-internal), `spa_bucket` (if applicable), exact upload-CORS origins.

### 4.7 `iam`
- One role per Lambda, least-privilege, exact ARNs, `aws-us-gov`:
  - `api`: `s3:PutObject/GetObject` (presign) on exact bucket prefixes with `aws:SourceVpce` restricted to the client interface endpoint (plus the S3 gateway endpoint for report existence checks), exact DynamoDB item operations on the job table, `states:StartExecution`, `ssm:GetParameter` (killswitch), KMS use.
  - `parser`: read `uploads`, write `artifacts` (findings JSON), Dynamo update, KMS.
  - `enricher`: read/write `artifacts`, `bedrock-runtime:InvokeModel` on `var.bedrock_model_id` only, Dynamo update, KMS. (Empty/`Deny` until D4 set.)
  - `exporter`: read `artifacts` (findings JSON), write `artifacts` (xlsx), Dynamo update, KMS.
  - All: VPC ENI perms + scoped CloudWatch Logs.

### 4.8 `observability`
- Log-group retention (`var.log_retention_days`); CloudTrail trail with **S3 data events** on both buckets (audit); optional X-Ray. CloudWatch alarms: state-machine `ExecutionsFailed`, per-Lambda `Errors`/`Throttles`.

---

## 5. Public-Repo Leak Discipline (hard gate)

- `.gitignore` excludes `*.tfvars` (except `*.tfvars.example`), `*.tfstate*`, `.terraform/`, `*.plan`, `backend.tf` (real) — only `backend.tf.example` committed.
- **No account ID, VPC/subnet/endpoint ID, ARN with a real account, bucket name, or KMS key ID in any committed `.tf`.** All via variables → gitignored tfvars.
- Review gate before merge: `git grep -nE '[0-9]{12}|vpc-[0-9a-f]+|subnet-[0-9a-f]+|vpce-[0-9a-f]+|arn:aws-us-gov:[^$]*[0-9]{12}'` over tracked files must return nothing (documented in `infra/README.md`, wired as a CI step §8).

---

## 6. Private SPA Serving (D6)

Master §6 flags this as known friction. `var.spa_serving_mode` enum, default `apigw_s3_proxy`:
- **`apigw_s3_proxy`** (default): Private API GW `{proxy+}` → S3 via AWS integration; requires `binary_media_types`, no CDN caching, per-request cost. Workable, fiddly.
- **`lambda_served`**: API Lambda returns bundled assets. Simpler routing, couples SPA to the API function.
- **`internal_alb`**: small internal ALB in front of S3/Lambda. More infra, cleaner caching.

Author `apigw_s3_proxy` first; keep the module boundary so a swap is a variable + one module, not a rewrite. Decide for real if the default bites during #3 integration.

---

## 7. State Backend & Environments

- Remote state: encrypted S3 backend + DynamoDB lock, GovCloud (D2). `backend.tf.example` committed with placeholders; real `backend.tf` gitignored (org supplies bucket/table/KMS).
- Environments: `envs/<name>/` dirs (not workspaces) — clearer separation for an ATO'd system; `example/` is the committed template.

---

## 8. CI (extends `.github/workflows/ci.yml` or a new `infra.yml`)

Triggered on `infra/**`:
1. `terraform fmt -check -recursive`
2. `terraform init -backend=false` + `terraform validate` (per module + env)
3. `terraform test` for module-level private-network and upload-CORS contracts
4. `tflint` (aws-us-gov ruleset)
5. `checkov` (fail on HIGH; document any nosec)
6. **Leak scan** (§5 `git grep` guard) — fail on any match.

No `plan`/`apply` in public CI (needs GovCloud creds + private runner — D2/org runner placement).

---

## 9. Testing & Verification

- **Static:** the §8 CI chain is the gate; `checkov` covers encryption/public-access/least-priv baselines.
- **Idempotency (per §4.5 contract):** for each stage, a documented re-run test — invoke twice with the same `jobId`, assert (a) artifact object identical/overwritten not duplicated, (b) job row converges to one consistent state. Runs against `localstack`/`moto` where feasible, else a scripted check in a throwaway env.
- **Handler wiring:** the existing #1 `moto`-mocked stage tests (`test_stages.py`, `test_artifact_store_s3.py`, `test_job_store_dynamo.py`) already cover the code the Lambdas call; #2 adds a packaging smoke test (zip builds, imports resolve on `python3.11` Linux).
- **No live GovCloud `apply` in this repo's CI** — that's an org-runner concern.

---

## 10. Build Order (feeds the plan)

1. `versions.tf`, `.gitignore`, `README` (cost floor + apply order + decision log).
2. `network` → `storage` → `data` (no cross-deps beyond KMS).
3. `iam` + `compute` (compute needs iam + storage + data outputs).
4. `orchestration` (needs compute ARNs) — encode idempotency contract.
5. `api` (needs compute + network endpoint id) — incl. SPA serving mode.
6. `observability`.
7. `envs/example` composition + all `*.example` files.
8. CI `infra.yml` incl. leak scan.
9. Idempotency verification write-up.

---

## 11. Definition of Done

- `terraform validate` + `tflint` + `checkov` (no HIGH) pass on every module and `envs/example`.
- Leak scan clean; no environment-specific value in any tracked file.
- Every §2 decision surfaced as a variable with a placeholder and a use-site comment.
- `infra/README.md` documents: idle cost floor, apply order, each org decision (D1–D6), the CUI/retention note, and the lxml-layer build step.
- Stage idempotency contract documented and verified per stage.
- Security review before any real `apply` (master §8).

---

## 12. Open Questions for Reviewer

1. Repo structure: OK to add `infra/` additively now and defer the `/backend`+`/frontend` monorepo rename to #3? (§3 recommendation.)
2. Any org-mandated Terraform module registry / naming / tagging standard to conform to before authoring?
3. Is a private CI runner with GovCloud reach available, or is `plan`/`apply` strictly operator-run out-of-band? (Sets whether §8 ever gains a plan stage.)
