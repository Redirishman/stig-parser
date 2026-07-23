# The four Lambdas — api, parser, enricher, exporter — all in-VPC, each with its
# own least-privilege role from the iam module. Spec §4.4.

locals {
  # Per-function shape. The API function is the odd one out: it is synchronous
  # behind API Gateway's 29s cap and does no parsing, so it gets a fraction of
  # the memory and none of the long timeout.
  functions = {
    api = {
      handler = "app.lambdas.api.handler"
      memory  = var.api_memory_mb
      timeout = var.api_timeout_seconds
    }
    parser = {
      handler = "app.lambdas.parser.handler"
      memory  = var.stage_memory_mb
      timeout = var.stage_timeout_seconds
    }
    enricher = {
      handler = "app.lambdas.enricher.handler"
      memory  = var.stage_memory_mb
      timeout = var.stage_timeout_seconds
    }
    exporter = {
      handler = "app.lambdas.exporter.handler"
      memory  = var.stage_memory_mb
      timeout = var.stage_timeout_seconds
    }
    # Catch target. One DynamoDB write, so it needs neither the parsing memory
    # nor the long timeout — and it must stay cheap enough to succeed when the
    # thing it is reporting on is an out-of-memory kill.
    marker = {
      handler = "app.lambdas.mark_error.handler"
      memory  = 256
      timeout = 30
    }
  }

  base_env = merge(
    {
      UPLOADS_BUCKET   = var.uploads_bucket
      ARTIFACTS_BUCKET = var.artifacts_bucket
      JOB_TABLE        = var.job_table_name
      BEDROCK_MODEL_ID = var.bedrock_model_id
      BEDROCK_REGION   = var.bedrock_region
      # AWS_REGION is reserved — the Lambda runtime sets it; setting it here is
      # rejected at create time.
    },
    var.job_ttl_days == null ? {} : { JOB_TTL_DAYS = tostring(var.job_ttl_days) },
    var.ai_killswitch_param == "" ? {} : { AI_KILLSWITCH_PARAM = var.ai_killswitch_param },
    var.identity_header == "" ? {} : { IDENTITY_HEADER = var.identity_header },
  )

  # Only the API function starts executions; the stages have no business
  # knowing the state machine ARN or the browser-facing S3 endpoint hostname.
  function_env = {
    for name, _ in local.functions :
    name => name == "api" ? merge(local.base_env, {
      STATE_MACHINE_ARN       = var.state_machine_arn
      S3_PRESIGN_ENDPOINT_URL = var.s3_presign_endpoint_url
    }) : local.base_env
  }
}

check "presign_endpoint_is_api_only" {
  assert {
    condition = alltrue([
      for name, environment in local.function_env :
      contains(keys(environment), "S3_PRESIGN_ENDPOINT_URL") == (name == "api")
    ])
    error_message = "S3_PRESIGN_ENDPOINT_URL must be present on the API Lambda and absent from every pipeline-stage Lambda."
  }
}

# ---------------------------------------------------------------------------
# Packaging
# ---------------------------------------------------------------------------

# One zip of the application source, shared by all four functions — they differ
# only by handler. Excludes everything that is not importable app code: test
# fixtures are megabytes of sample scans, and the web assets belong to the Flask
# UI (#3 replaces them with the React SPA).
data "archive_file" "source" {
  type        = "zip"
  source_dir  = var.backend_source_dir
  output_path = "${path.module}/.build/${var.name_prefix}-source.zip"

  excludes = [
    "tests",
    "docs",
    "infra",
    "tmp",
    ".git",
    ".github",
    # The React SPA is deployed separately (built + synced to S3); it and its
    # node_modules have no place in a Python Lambda and, because node_modules
    # holds platform-specific binaries, they make the source hash differ per
    # machine — the churn that made every plan noisy.
    "frontend",
    ".pytest_cache",
    ".claude",
    # Root-level ops files: not part of the Lambda runtime, and the playbook
    # carries account-specific detail that must not ride into the function zip.
    "deploy.sh",
    "GOVCLOUD-PLAYBOOK.md",
    "app/static",
    "app/templates",
    "__pycache__",
    "app/__pycache__",
    "app/core/__pycache__",
    "app/parsers/__pycache__",
    "app/processors/__pycache__",
    "app/exporters/__pycache__",
    "app/utils/__pycache__",
    "app/lambdas/__pycache__",
  ]
}

# lxml and openpyxl ship compiled wheels and cannot be zipped from a developer's
# machine unless that machine is Linux on the target Python. Built out-of-band by
# infra/scripts/build-layer.sh; see infra/README.md.
resource "aws_lambda_layer_version" "deps" {
  layer_name          = "${var.name_prefix}-deps"
  filename            = var.dependency_layer_zip
  source_code_hash    = filebase64sha256(var.dependency_layer_zip)
  compatible_runtimes = [var.python_runtime]
  description         = "lxml + openpyxl for ${var.name_prefix}."
}

# ---------------------------------------------------------------------------
# Log groups
# ---------------------------------------------------------------------------

# Created explicitly (not implicitly by first invocation) so retention and CMK
# encryption apply from the very first log line — an implicitly-created group
# defaults to never-expire and AWS-managed keys, which is a CUI problem.
resource "aws_cloudwatch_log_group" "this" {
  for_each = local.functions

  name              = "/aws/lambda/${var.name_prefix}-${each.key}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn

  tags = merge(var.tags, { Name = "${var.name_prefix}-${each.key}" })
}

# ---------------------------------------------------------------------------
# Functions
# ---------------------------------------------------------------------------

resource "aws_lambda_function" "this" {
  #checkov:skip=CKV_AWS_116:A DLQ only applies to ASYNC invocation. Every function here is invoked synchronously — by API Gateway or by Step Functions — and a failed stage is already captured by the state machine's Catch, which routes to the marker function and records the failure on the job.
  #checkov:skip=CKV_AWS_50:X-Ray is off by design (it needs an extra ~$8/mo interface endpoint). var.enable_x_ray in the network module turns it on.
  #checkov:skip=CKV_AWS_272:Code signing requires an org-owned signing profile; there is no CI signer for this repo yet. Flagged for the org to decide.
  for_each = local.functions

  function_name = "${var.name_prefix}-${each.key}"
  role          = var.role_arns[each.key]
  handler       = each.value.handler
  runtime       = var.python_runtime
  memory_size   = each.value.memory
  timeout       = each.value.timeout
  layers        = [aws_lambda_layer_version.deps.arn]

  # Bounds the blast radius of a runaway client: without a cap, a submit loop
  # would scale out until it exhausted the account's concurrency and throttled
  # every other Lambda in the account.
  reserved_concurrent_executions = var.reserved_concurrency

  filename         = data.archive_file.source.output_path
  source_code_hash = data.archive_file.source.output_base64sha256

  ephemeral_storage {
    size = var.ephemeral_storage_mb
  }

  # No public egress exists in this VPC — every AWS call leaves through a VPC
  # endpoint (see the network module).
  vpc_config {
    subnet_ids         = var.subnet_ids
    security_group_ids = [var.security_group_id]
  }

  kms_key_arn = var.kms_key_arn

  environment {
    variables = local.function_env[each.key]
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-${each.key}" })

  # Terraform would otherwise race the implicit log group Lambda creates on
  # first invoke, and lose the retention/CMK settings above.
  depends_on = [aws_cloudwatch_log_group.this]
}
