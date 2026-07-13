# STIG Condenser — GovCloud Infrastructure (Terraform)

Provisions the fully-private, serverless GovCloud runtime for STIG Condenser.
This directory is **infrastructure only** — the Python application lives in
`../app/` and is packaged into Lambdas by the `compute` module.

**Design:** [Sub-project #2 spec](../docs/superpowers/specs/2026-07-13-govcloud-terraform-iac-spec.md)
· [Master architecture](../docs/superpowers/specs/2026-07-07-govcloud-replatform-design.md)

> **Status:** scaffolding in progress. `versions.tf`, `.gitignore`, and this
> README are in place; the `modules/` and `envs/` trees are being built per the
> spec's §10 build order. This is not yet `apply`-able.

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

---

## Public-repo discipline (hard rule)

This repository is **public**. No account ID, VPC/subnet/endpoint ID, real ARN,
bucket name, or KMS key ID may appear in any tracked `.tf` file. All such values
are Terraform **variables**, supplied via **gitignored** `*.tfvars` /
`backend.tf`; only `*.example` templates are committed. Before any merge touching
`infra/`, the CI **leak scan** (and the local check below) must return nothing:

```sh
git grep -nE '[0-9]{12}|vpc-[0-9a-f]+|subnet-[0-9a-f]+|vpce-[0-9a-f]+|arn:aws-us-gov:[^ ]*[0-9]{12}' -- 'infra/**' ':!*.example'
```

---

## Org decisions required before a real `apply`

Authoring the modules does **not** need these (all are variables with
placeholders); a real `apply` does. See spec §2.

| ID | Decision | Variable |
|----|----------|----------|
| D1 | Region split (West/East) | `aws_region`, `bedrock_region` |
| D2 | Remote state backend (bucket / lock table / KMS) | `envs/*/backend.tf` |
| D3 | Upstream auth identity header (or none) | `identity_header` |
| D4 | Claude model ID in `us-gov-west-1` Bedrock | `bedrock_model_id` (AI off until set) |
| D5 | CUI retention — S3 lifecycle days, DynamoDB TTL days | `artifact_retention_days`, `job_ttl_days` |
| D6 | Private-SPA serving mode | `spa_serving_mode` |

CUI note: scan results and derived findings are treated as CUI. Retention/TTL
values are a **records-policy decision**, not a convenience default — confirm
with the ISSO. Apply CUI marking to generated reports where org policy requires.

---

## Apply order (spec §10)

`network` → `storage` → `data` → `iam` + `compute` → `orchestration` → `api`
→ `observability`, composed in `envs/example/`.

## Lambda packaging note

The Python source (`../app/`) is zipped into the stage Lambdas via the `compute`
module. `lxml` and `openpyxl` need **Linux (manylinux) wheels** matching the
`python3.11` Lambda runtime — build the shared dependency layer on Linux (or in
a container), not from Windows/macOS wheels, or imports fail at runtime.

## CI

Static analysis only (no `plan`/`apply` in public CI — needs GovCloud creds on a
private runner): `terraform fmt -check`, `validate`, `tflint`, `checkov`
(fail on HIGH), and the leak scan above. See spec §8.
