# STIG Condenser — GovCloud Infrastructure (Terraform)

Provisions the fully-private, serverless GovCloud runtime for STIG Condenser.
This directory is **infrastructure only** — the Python application lives in
`../app/` and is packaged into Lambdas by the `compute` module.

**Design:** [Sub-project #2 spec](../docs/superpowers/specs/2026-07-13-govcloud-terraform-iac-spec.md)
· [Master architecture](../docs/superpowers/specs/2026-07-07-govcloud-replatform-design.md)

> **Status:** all modules authored — `network`, `storage`, `data`, `iam`,
> `compute`, `orchestration`, `api`, `observability`, plus the `envs/example`
> composition. `terraform fmt`, `terraform validate` and `checkov` pass
> (448 passed / 0 failed / 54 skipped, every skip with a written reason).
>
> **Never applied against a real GovCloud account.** `validate` proves the
> configuration is well-formed; it does **not** prove the deployment works. The
> first `apply` is an operator activity, and the items under *Before the first
> apply* below are still open.

---

## ⚠ Idle cost floor — read before provisioning

The **fully-private** requirement forbids NAT and public edge, so every AWS
service is reached through an **interface VPC endpoint**. Interface endpoints
bill **hourly (~$7–8/mo each), regardless of usage**. With the ~6–7 endpoints
this design needs (`execute-api`, `bedrock-runtime`, `states`, `logs`, `kms`,
`sts`, +optional `monitoring`), the environment costs **~$50+/mo at zero
traffic** — the dominant idle cost, exceeding Lambda. This is an accepted
consequence of the private-boundary requirement, documented so the first bill
is not a surprise. Gateway endpoints (`s3`, `dynamodb`) are free.

Smaller ongoing costs, all deliberate: VPC flow logs, CloudTrail S3 data events
(one event per object read/write), and CloudWatch log retention (1 year).

---

## Public-repo discipline (hard rule)

This repository is **public**. No account ID, VPC/subnet/endpoint ID, real ARN,
bucket name, or KMS key ID may appear in any tracked `.tf` file. All such values
are Terraform **variables**, supplied via **gitignored** `*.tfvars` /
`backend.tf`; only `*.example` templates are committed. Before any merge touching
`infra/`, the CI **leak scan** (and the local check below) must return nothing:

```sh
git grep -nEI '[0-9]{12}|vpc-[0-9a-f]{8,}|subnet-[0-9a-f]{8,}|vpce-[0-9a-f]{8,}|arn:aws-us-gov:[^$"]*[0-9]{12}' -- 'infra/**' ':!infra/**/*.example'
```

Rewriting git history does not un-publish a leaked value. The scan runs on
tracked files only, so a developer's real (gitignored) `terraform.tfvars` does
not trip it.

---

## Org decisions required before a real `apply`

Authoring the modules did **not** need these (all are variables with
placeholders); a real `apply` does. See spec §2.

| ID | Decision | Variable | Default |
|----|----------|----------|---------|
| D1 | Region split (West/East) | `aws_region`, `bedrock_region` | both `us-gov-west-1` |
| D2 | Remote state backend (bucket / lock table / KMS) | `envs/*/backend.tf` | placeholders in `backend.tf.example` |
| D3 | Upstream auth identity header (or none) | `identity_header` | `""` (no identity recorded) |
| D4 | Claude model ID in GovCloud Bedrock | `bedrock_model_id` | `""` — **AI is off until set** |
| D5 | CUI retention — S3 lifecycle days, DynamoDB TTL days | `upload_retention_days`, `artifact_retention_days`, `job_ttl_days` | conservative placeholders |
| D6 | Private-SPA serving mode | `spa_serving_mode` | `apigw_s3_proxy` |

**CUI note:** scan results and derived findings are treated as CUI. Retention and
TTL values are a **records-policy decision**, not a convenience default — confirm
with the ISSO. Apply CUI marking to generated reports where org policy requires.

**D4 / AI is off by default and fails closed.** With `bedrock_model_id` empty,
the enricher role receives *no* `bedrock:InvokeModel` permission at all (rather
than a wildcard that would silently become live the day a model is enabled in
the account), and the API reports the gate as `disabled-globally`. If
`ai_killswitch_param` is set, its SSM parameter must read exactly `enabled` for
AI to run; any other value — **or an unreadable parameter** — disables AI.

---

## Apply order

`storage` → `network` → `data` → `iam` → `compute` → `orchestration` → `api` →
`observability`, composed in `envs/example/`. Terraform resolves this from the
dependency graph; the order matters only for reading the code.

(`storage` precedes `network` because the VPC flow-log group is encrypted with
the storage module's CMK.)

```sh
cd envs/example
cp backend.tf.example backend.tf              # fill in (D2) — gitignored
cp terraform.tfvars.example terraform.tfvars  # fill in — gitignored
../../scripts/build-layer.sh python3.12       # see below — must run on Linux
terraform init
terraform plan
```

## Lambda packaging — the dependency layer

`lxml` and `openpyxl` ship **compiled C extensions**. A layer built on Windows or
macOS imports fine locally and then dies at cold start in Lambda with
`No module named 'lxml.etree'`. `scripts/build-layer.sh` therefore builds it in
the AWS Lambda Python image via Docker:

```sh
./scripts/build-layer.sh python3.12   # -> infra/build/deps-layer.zip
```

`boto3` is deliberately **not** vendored into the layer — it is already in the
Lambda runtime, and a pinned copy would shadow it and drift from the service API.

The layer must be built against the same `python_runtime` the functions declare.

---

## Verification status

All gates below were run locally through Docker (none of the tooling is installed
on the dev box). Git Bash mangles container paths, so mounts need
`MSYS_NO_PATHCONV=1`:

```sh
MSYS_NO_PATHCONV=1 docker run --rm -v "/g/path/to/stig-parser/infra:/w" -w /w \
  hashicorp/terraform:1.9.8 fmt -check -recursive
```

| Gate | Status |
|------|--------|
| `terraform fmt -check -recursive` | clean |
| `terraform validate` (8 modules + `envs/example`) | all pass |
| `tflint` (aws ruleset, recursive) | clean — zero findings |
| `checkov` | 448 passed, **0 failed**, 54 skipped |
| Leak scan | clean (verified it catches a planted value) |
| `terraform plan` / `apply` | **never run** — needs GovCloud credentials |

Every `checkov` skip is inline at its resource with a written reason. The
substantive ones:

- **`CKV_AWS_59` (API Gateway authorization `NONE`)** — the endpoint is
  `PRIVATE`, and its resource policy **denies** every request that did not arrive
  through our `execute-api` VPC endpoint. Authentication is upstream of the
  private boundary (D3). A gateway authorizer would be a second, weaker copy of a
  decision already made.
- **`CKV_AWS_116` (no Lambda DLQ)** — a DLQ only applies to *async* invocation.
  Every function here is invoked synchronously (API Gateway, Step Functions), and
  stage failures are caught by the state machine and recorded on the job.
- **`CKV_AWS_145` / `CKV2_AWS_65` (access-log bucket uses AES256 + ACLs)** — S3
  server-access-log delivery cannot write into an SSE-KMS bucket and requires
  ACLs. Only that one bucket; the CUI buckets are SSE-KMS with ACLs disabled.
- **`CKV_AWS_356` / `111` / `109` (wildcard resources)** — the Lambda ENI-attach
  permissions and the mandatory KMS key-policy root statement; neither accepts a
  resource ARN. Every other statement names exact ARNs.
- **X-Ray checks** — off by design: it needs an extra ~$8/mo interface endpoint in
  a VPC with no internet route.

---

## Before the first apply

1. Make decisions **D1–D6** (table above), especially D5 with the ISSO.
2. Build the dependency layer on Linux (`scripts/build-layer.sh`).
3. Wire `alarm_actions` to a real SNS topic — otherwise the alarms evaluate but
   page nobody.
4. Confirm `vpc_cidr` does not overlap anything reachable over the VPN.
5. Security review (master spec §8).
6. Expect the first `apply` to surface things `validate` cannot: IAM propagation
   races, GovCloud service availability, and the SPA-proxy binary-media handling
   (D6 — see spec §6; the fallback modes exist for exactly this reason).

---

## CI

`.github/workflows/infra.yml`, on any change under `infra/`: `terraform fmt
-check`, `validate` (every module + env), `tflint`, `checkov`, and the leak scan.

No `plan`/`apply` in public CI — that needs GovCloud credentials and a private
runner with VPC reach (an open question for the org; spec §12).
