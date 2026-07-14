# One execution role per Lambda, least-privilege. Spec §4.7.
#
# Every ARN is built from data.aws_partition.current.partition (== "aws-us-gov"
# here) — a literal "aws" would silently produce a policy that matches nothing
# in GovCloud, granting less than intended and failing at runtime.

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  partition  = data.aws_partition.current.partition
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name

  # `marker` is the Catch target: it only touches the job table (no S3, no
  # Bedrock), so it gets the narrowest policy of the five.
  functions = ["api", "parser", "enricher", "exporter", "marker"]

  log_group_arn = "arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/${var.name_prefix}-*"

  # Empty model id (D4 unmade) => no Bedrock statement at all, rather than a
  # wildcard "any model" grant that would quietly become live the day a model
  # is enabled in the account.
  bedrock_model_arn = var.bedrock_model_id == "" ? null : "arn:${local.partition}:bedrock:${var.bedrock_region}::foundation-model/${var.bedrock_model_id}"

  # StopExecution acts on an execution ARN, which is a different resource type
  # from the state machine ARN:
  #   arn:<p>:states:<r>:<a>:stateMachine:<name>
  #   arn:<p>:states:<r>:<a>:execution:<name>:<execution-name>
  # Executions are named for the job id, so the wildcard covers exactly this
  # state machine's executions and nothing else.
  execution_arn_pattern = "${replace(var.state_machine_arn, ":stateMachine:", ":execution:")}:*"
}

# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "this" {
  for_each = toset(local.functions)

  name               = "${var.name_prefix}-${each.value}"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = merge(var.tags, { Name = "${var.name_prefix}-${each.value}" })
}

# ---------------------------------------------------------------------------
# Shared: VPC ENI management + scoped CloudWatch Logs
# ---------------------------------------------------------------------------

# The EC2 network-interface calls that let an in-VPC Lambda attach an ENI do not
# support resource-level permissions — "*" is what the service requires.
#
data "aws_iam_policy_document" "shared" {
  #checkov:skip=CKV_AWS_356:ec2:*NetworkInterface* does not accept a resource ARN; AWS requires "*" for the Lambda VPC-attach permissions. Every other statement in this module names exact ARNs.
  #checkov:skip=CKV_AWS_111:Same — these are the ENI lifecycle calls Lambda itself makes, not a broad write grant on account resources.
  statement {
    sid    = "ManageLambdaEni"
    effect = "Allow"
    actions = [
      "ec2:CreateNetworkInterface",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DeleteNetworkInterface",
      "ec2:AssignPrivateIpAddresses",
      "ec2:UnassignPrivateIpAddresses",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "WriteOwnLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [local.log_group_arn, "${local.log_group_arn}:*"]
  }
}

resource "aws_iam_policy" "shared" {
  name   = "${var.name_prefix}-lambda-shared"
  policy = data.aws_iam_policy_document.shared.json
  tags   = var.tags
}

resource "aws_iam_role_policy_attachment" "shared" {
  for_each = aws_iam_role.this

  role       = each.value.name
  policy_arn = aws_iam_policy.shared.arn
}

# ---------------------------------------------------------------------------
# KMS: every bucket and table access needs the CMK
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "kms" {
  statement {
    sid    = "UseCmk"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]
    resources = [var.kms_key_arn]
  }
}

resource "aws_iam_policy" "kms" {
  name   = "${var.name_prefix}-lambda-kms"
  policy = data.aws_iam_policy_document.kms.json
  tags   = var.tags
}

resource "aws_iam_role_policy_attachment" "kms" {
  for_each = aws_iam_role.this

  role       = each.value.name
  policy_arn = aws_iam_policy.kms.arn
}

# ---------------------------------------------------------------------------
# api: presign both buckets, own the job table, start the state machine
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "api" {
  # Presigning is a local signing operation, but the url only works if the role
  # itself holds the permission it presigns.
  statement {
    sid       = "PresignUploads"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${var.uploads_bucket_arn}/jobs/*"]
  }

  statement {
    sid       = "PresignReports"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${var.artifacts_bucket_arn}/jobs/*"]
  }

  statement {
    sid       = "JobRecords"
    effect    = "Allow"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem"]
    resources = [var.job_table_arn]
  }

  statement {
    sid       = "StartPipeline"
    effect    = "Allow"
    actions   = ["states:StartExecution"]
    resources = [var.state_machine_arn]
  }

  # Cancel. StopExecution is granted on the state machine's EXECUTIONS, not on
  # the state machine itself — a common way to get this wrong is to reuse the
  # StartExecution resource above, which produces a policy that never matches
  # and an AccessDenied the first time an operator clicks Cancel.
  statement {
    sid       = "CancelPipeline"
    effect    = "Allow"
    actions   = ["states:StopExecution"]
    resources = [local.execution_arn_pattern]
  }

  dynamic "statement" {
    for_each = var.ai_killswitch_param_arn == "" ? [] : [1]
    content {
      sid       = "ReadAiKillswitch"
      effect    = "Allow"
      actions   = ["ssm:GetParameter"]
      resources = [var.ai_killswitch_param_arn]
    }
  }
}

# ---------------------------------------------------------------------------
# parser: read uploads, write findings, update the job
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "parser" {
  statement {
    sid       = "ReadUploads"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${var.uploads_bucket_arn}/jobs/*"]
  }

  statement {
    sid       = "WriteFindings"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${var.artifacts_bucket_arn}/jobs/*"]
  }

  statement {
    sid       = "JobRecords"
    effect    = "Allow"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem"]
    resources = [var.job_table_arn]
  }
}

# ---------------------------------------------------------------------------
# enricher: artifacts round-trip + exactly one Bedrock model (if D4 is made)
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "enricher" {
  statement {
    sid       = "ReadWriteArtifacts"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${var.artifacts_bucket_arn}/jobs/*"]
  }

  statement {
    sid       = "JobRecords"
    effect    = "Allow"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem"]
    resources = [var.job_table_arn]
  }

  # Scoped to the one approved model ARN, never "*": an unreviewed model must
  # not become invokable just because it exists in the account.
  dynamic "statement" {
    for_each = local.bedrock_model_arn == null ? [] : [1]
    content {
      sid       = "InvokeApprovedModelOnly"
      effect    = "Allow"
      actions   = ["bedrock:InvokeModel"]
      resources = [local.bedrock_model_arn]
    }
  }
}

# ---------------------------------------------------------------------------
# exporter: read findings, write the workbook, update the job
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "exporter" {
  statement {
    sid       = "ReadWriteArtifacts"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${var.artifacts_bucket_arn}/jobs/*"]
  }

  statement {
    sid       = "JobRecords"
    effect    = "Allow"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem"]
    resources = [var.job_table_arn]
  }
}

# ---------------------------------------------------------------------------
# marker: the Catch target — job table only
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "marker" {
  statement {
    sid       = "JobRecords"
    effect    = "Allow"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem"]
    resources = [var.job_table_arn]
  }
}

# ---------------------------------------------------------------------------
# Attach the per-function policies
# ---------------------------------------------------------------------------

locals {
  policies = {
    api      = data.aws_iam_policy_document.api.json
    parser   = data.aws_iam_policy_document.parser.json
    enricher = data.aws_iam_policy_document.enricher.json
    exporter = data.aws_iam_policy_document.exporter.json
    marker   = data.aws_iam_policy_document.marker.json
  }
}

resource "aws_iam_policy" "function" {
  for_each = local.policies

  name   = "${var.name_prefix}-${each.key}-policy"
  policy = each.value
  tags   = var.tags
}

resource "aws_iam_role_policy_attachment" "function" {
  for_each = local.policies

  role       = aws_iam_role.this[each.key].name
  policy_arn = aws_iam_policy.function[each.key].arn
}
