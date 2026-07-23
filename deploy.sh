#!/usr/bin/env bash
#
# deploy.sh — one-command deploy for stig-parser into a GovCloud environment.
#
#   ./deploy.sh <env> [flags]        e.g.  ./deploy.sh army-dev
#
# Phases (each can be trimmed with a flag):
#   0 guards    account + toolchain + filesystem safety checks
#   1 preflight the gitignored per-env files exist (backend.tf, terraform.tfvars)
#   2 layer     build the Lambda dependency layer (Docker/Linux)   [--skip-layer]
#   3 infra     terraform init/validate/plan -> y/N gate -> apply  [--plan-only]
#   4 spa       build the React bundle and sync it to the SPA bucket  [--skip-spa]
#   5 smoke     invoke the API Lambda's GET /config and check 200
#
# Flags:
#   --plan-only    stop after `terraform plan` (never applies; implies no spa/smoke)
#   --infra-only   run guards + preflight + layer + infra, skip spa + smoke
#   --skip-layer   reuse the existing infra/build/deps-layer.zip
#   --skip-spa     do not build or sync the frontend
#   --yes          skip the interactive apply prompt (also: AUTO_APPROVE=1)
#   -h, --help     show this help
#
# You always run this from the repo root: ./deploy.sh <env>. You never cd into
# the env folder — the script reaches into it for you.
#
# Per-env config is OPTIONAL. With no config, the account guard resolves the
# account and asks you to confirm it. To make the guard silent + strict, copy
# infra/envs/<env>/deploy.env.example to infra/envs/<env>/deploy.env (gitignored):
#   AWS_PROFILE=...  AWS_REGION=...  EXPECTED_ACCOUNT=...
# It sits beside backend.tf/terraform.tfvars because the account is a per-env
# fact (army-dev and a future prod may be different accounts). No account value
# is ever hard-coded here — this repo is public.

set -euo pipefail

# --- pretty logging --------------------------------------------------------
if [[ -t 1 ]]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GRN=$'\033[32m'
  YLW=$'\033[33m'; BLU=$'\033[34m'; RST=$'\033[0m'
else
  BOLD=; DIM=; RED=; GRN=; YLW=; BLU=; RST=
fi
step()  { printf '\n%s==> %s%s\n' "$BOLD$BLU" "$*" "$RST"; }
info()  { printf '    %s\n' "$*"; }
ok()    { printf '    %s✓ %s%s\n' "$GRN" "$*" "$RST"; }
warn()  { printf '    %s! %s%s\n' "$YLW" "$*" "$RST" >&2; }
die()   { printf '\n%s✗ %s%s\n' "$RED$BOLD" "$*" "$RST" >&2; exit 1; }

# --- locate repo root (script lives at the root) ---------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# --- parse args ------------------------------------------------------------
ENV=""
PLAN_ONLY=0; INFRA_ONLY=0; SKIP_LAYER=0; SKIP_SPA=0
AUTO_APPROVE="${AUTO_APPROVE:-0}"

usage() { sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

for arg in "$@"; do
  case "$arg" in
    --plan-only)  PLAN_ONLY=1 ;;
    --infra-only) INFRA_ONLY=1 ;;
    --skip-layer) SKIP_LAYER=1 ;;
    --skip-spa)   SKIP_SPA=1 ;;
    --yes|-y)     AUTO_APPROVE=1 ;;
    -h|--help)    usage 0 ;;
    -*)           die "unknown flag: $arg  (try --help)" ;;
    *)            [[ -z "$ENV" ]] && ENV="$arg" || die "unexpected argument: $arg" ;;
  esac
done
[[ -n "$ENV" ]] || { warn "no environment given"; usage 1; }

ENV_DIR="infra/envs/${ENV}"
[[ -d "$ENV_DIR" ]] || die "no such environment: ${ENV_DIR}"

# ===========================================================================
# Phase 0 — guards
# ===========================================================================
step "Phase 0 · Guards (${ENV})"

# 0a. Never run from a Windows mount under WSL — npm/docker there corrupts
#     Lambda artifacts (a hazard both sibling AIE stacks learned the hard way).
if [[ "$REPO_ROOT" == /mnt/* && "${ALLOW_MNT:-0}" != "1" ]]; then
  die "refusing to run from a Windows mount ($REPO_ROOT).
    Clone into the native WSL filesystem (e.g. ~/stig-parser) and run there.
    Override at your own risk with ALLOW_MNT=1."
fi

# 0b. Optional per-env config (gitignored). Absent is fine — the account guard
#     below just confirms the resolved account instead of hard-checking it.
DEPLOY_ENV_FILE="${ENV_DIR}/deploy.env"
if [[ -f "$DEPLOY_ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$DEPLOY_ENV_FILE"
  ok "loaded ${DEPLOY_ENV_FILE}"
fi
AWS_PROFILE="${AWS_PROFILE:-army-govcloud}"
AWS_REGION="${AWS_REGION:-us-gov-west-1}"
export AWS_PROFILE AWS_REGION AWS_DEFAULT_REGION="$AWS_REGION"

# 0c. Force profile-based auth: stray static/assumed-role keys in the shell
#     (our whole terraform-role saga) silently target the wrong identity.
if [[ -n "${AWS_ACCESS_KEY_ID:-}${AWS_SESSION_TOKEN:-}" ]]; then
  warn "unsetting stray AWS_ACCESS_KEY_ID/SECRET/SESSION_TOKEN so profile '${AWS_PROFILE}' is used"
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
fi

# 0d. Toolchain.
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required but not on PATH${2:+ — $2}"; }
need aws
need terraform
tf_ver="$(terraform version -json 2>/dev/null | sed -n 's/.*"terraform_version": *"\([^"]*\)".*/\1/p' | head -1)"
[[ -n "$tf_ver" ]] || tf_ver="$(terraform version | sed -n '1s/Terraform v//p')"
tf_major="${tf_ver%%.*}"; tf_rest="${tf_ver#*.}"; tf_minor="${tf_rest%%.*}"
if (( tf_major < 1 || (tf_major == 1 && tf_minor < 10) )); then
  die "terraform ${tf_ver} is too old — the S3-native backend lock (use_lockfile) needs >= 1.10."
fi
ok "terraform ${tf_ver}"

# 0e. Account guard — the classic wrong-account tripwire.
info "resolving caller identity for profile '${AWS_PROFILE}'..."
ACCOUNT="$(aws sts get-caller-identity --query Account --output text 2>/dev/null)" \
  || die "could not authenticate with profile '${AWS_PROFILE}'. Check ~/.aws/config, or run 'aws sso login' / refresh MFA."
if [[ -n "${EXPECTED_ACCOUNT:-}" ]]; then
  [[ "$ACCOUNT" == "$EXPECTED_ACCOUNT" ]] \
    || die "WRONG ACCOUNT: profile resolved to ${ACCOUNT}, expected ${EXPECTED_ACCOUNT}."
  ok "account ${ACCOUNT} (matches EXPECTED_ACCOUNT)"
else
  warn "account is ${ACCOUNT} — no EXPECTED_ACCOUNT set to check it against"
  if [[ "$AUTO_APPROVE" != "1" ]]; then
    read -r -p "    Deploy '${ENV}' into account ${ACCOUNT}? [y/N] " ans || true
    [[ "$ans" =~ ^[yY]([eE][sS])?$ ]] || die "aborted."
  fi
fi

# ===========================================================================
# Phase 1 — preflight (the gitignored per-env files that must exist)
# ===========================================================================
step "Phase 1 · Preflight"
missing=0
for f in backend.tf terraform.tfvars; do
  if [[ -f "${ENV_DIR}/${f}" ]]; then ok "${ENV_DIR}/${f}"; else
    warn "missing ${ENV_DIR}/${f} (gitignored — copy from ${f}.example and fill in)"; missing=1
  fi
done
(( missing == 0 )) || die "create the files above, then re-run."

# Read a value out of terraform.tfvars:  tfvar <key>
tfvar() { sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*\"\{0,1\}\([^\"]*\)\"\{0,1\}.*/\1/p" "${ENV_DIR}/terraform.tfvars" | head -1; }

# ===========================================================================
# Phase 2 — dependency layer
# ===========================================================================
LAYER_ZIP="infra/build/deps-layer.zip"
if (( SKIP_LAYER )); then
  step "Phase 2 · Layer (skipped)"
  [[ -f "$LAYER_ZIP" ]] || die "--skip-layer but ${LAYER_ZIP} does not exist. Build it once without the flag."
  ok "reusing existing ${LAYER_ZIP}"
else
  step "Phase 2 · Dependency layer"
  need docker "the layer must be built on Linux; install Docker or pass --skip-layer if the zip is current"
  runtime="$(tfvar python_runtime)"; runtime="${runtime:-python3.12}"
  info "building ${LAYER_ZIP} for ${runtime} (Docker)..."
  ./infra/scripts/build-layer.sh "$runtime"
  ok "layer built"
fi

# ===========================================================================
# Phase 3 — infrastructure
# ===========================================================================
step "Phase 3 · Terraform (${ENV})"
tf() { terraform -chdir="$ENV_DIR" "$@"; }

info "init..."; tf init -input=false >/dev/null && ok "backend initialized"
info "validate..."; tf validate >/dev/null && ok "configuration valid"

info "plan..."
set +e
tf plan -input=false -out=deploy.tfplan -detailed-exitcode
plan_rc=$?
set -e
case "$plan_rc" in
  0) ok "no changes — infrastructure already matches"; APPLIED_NOTHING=1 ;;
  2) info "changes pending (see plan above)"; APPLIED_NOTHING=0 ;;
  *) die "terraform plan failed (exit ${plan_rc})." ;;
esac

if (( PLAN_ONLY )); then
  step "Done (--plan-only)"; info "reviewed the plan; nothing applied."; exit 0
fi

if [[ "${APPLIED_NOTHING:-0}" == "0" ]]; then
  if [[ "$AUTO_APPROVE" != "1" ]]; then
    printf '\n'
    read -r -p "    ${BOLD}Apply this plan to ${ENV} (${ACCOUNT})? [y/N]${RST} " ans || true
    [[ "$ans" =~ ^[yY]([eE][sS])?$ ]] || { rm -f "${ENV_DIR}/deploy.tfplan"; die "aborted — nothing applied."; }
  fi
  info "applying..."
  tf apply -input=false deploy.tfplan || die "apply failed. Existing resources are unchanged; fix and re-run."
  ok "apply complete"
fi
rm -f "${ENV_DIR}/deploy.tfplan"

# --- AI killswitch parameter (created once; never overwritten) --------------
killswitch="$(tfvar ai_killswitch_param)"
if [[ -n "$killswitch" ]]; then
  if aws ssm get-parameter --name "$killswitch" >/dev/null 2>&1; then
    cur="$(aws ssm get-parameter --name "$killswitch" --query Parameter.Value --output text)"
    ok "killswitch ${killswitch} exists (value: ${cur})"
    [[ "$cur" == "enabled" ]] || warn "killswitch is not 'enabled' — AI stays OFF until it reads exactly 'enabled'"
  else
    aws ssm put-parameter --name "$killswitch" --type String --value enabled \
      --description "stig-parser AI killswitch: exactly 'enabled' turns AI on; anything else fails closed" >/dev/null
    ok "created killswitch ${killswitch} = enabled"
  fi
fi

if (( INFRA_ONLY )); then
  step "Done (--infra-only)"; exit 0
fi

# ===========================================================================
# Phase 4 — SPA build + sync
# ===========================================================================
spa_bucket="$(tf output -raw spa_bucket 2>/dev/null || true)"
if (( SKIP_SPA )); then
  step "Phase 4 · SPA (skipped)"
elif [[ -z "$spa_bucket" || "$spa_bucket" == "null" ]]; then
  step "Phase 4 · SPA (not applicable)"
  info "spa_bucket output is empty — spa_serving_mode is not apigw_s3_proxy; nothing to sync."
else
  step "Phase 4 · SPA bundle"
  need node; need npm
  api_url="$(tf output -raw api_invoke_url)"
  info "building frontend (VITE_API_BASE=${api_url})..."
  ( cd frontend && npm ci --no-audit --no-fund >/dev/null 2>&1 && VITE_API_BASE="$api_url" npm run build >/dev/null )
  [[ -d frontend/dist && -f frontend/dist/index.html ]] || die "frontend build produced no dist/index.html."
  ok "bundle built"
  info "syncing dist/ -> s3://${spa_bucket}/ ..."
  aws s3 sync frontend/dist/ "s3://${spa_bucket}/" --delete >/dev/null
  ok "SPA published to ${spa_bucket}"
fi

# ===========================================================================
# Phase 5 — smoke test (in-VPC-blind: invoke the Lambda directly)
# ===========================================================================
step "Phase 5 · Smoke test"
# name_prefix is derivable from a guaranteed output (…-uploads).
uploads="$(tf output -raw uploads_bucket 2>/dev/null || true)"
if [[ -z "$uploads" ]]; then
  warn "no uploads_bucket output — skipping smoke test"
else
  api_fn="${uploads%-uploads}-api"
  tmp="$(mktemp -t stig-smoke.XXXXXX)"
  event='{"httpMethod":"GET","resource":"/config","path":"/config","headers":{},"body":null,"isBase64Encoded":false,"requestContext":{"identity":{}}}'
  info "invoking ${api_fn} (GET /config)..."
  if aws lambda invoke --function-name "$api_fn" \
       --payload "$event" --cli-binary-format raw-in-base64-out \
       "$tmp" >/dev/null 2>&1 && grep -q '"statusCode": *200' "$tmp"; then
    ok "API healthy — $(sed -n 's/.*"body": *"\(.*\)".*/\1/p' "$tmp" | head -c 80)"
  else
    warn "smoke test did not return 200. Payload:"; sed 's/^/      /' "$tmp" >&2
    rm -f "$tmp"; die "deploy applied but the API smoke test failed — investigate before trusting this environment."
  fi
  rm -f "$tmp"
fi

step "${GRN}Deploy complete — ${ENV}${RST}"
info "API (private):  $(tf output -raw api_invoke_url 2>/dev/null || echo n/a)"
info "SPA bucket:     ${spa_bucket:-n/a}"
info "State machine:  $(tf output -raw state_machine_arn 2>/dev/null || echo n/a)"
