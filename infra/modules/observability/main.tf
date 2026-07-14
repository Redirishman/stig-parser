# Audit trail + the alarms that matter. Spec §4.8.
#
# The alarms are deliberately few. A private, occasional-use compliance tool has
# one question worth paging on: did an operator's job fail? Everything else is
# console-inspectable after the fact.

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  trail_name = "${var.name_prefix}-trail"
}

# ---------------------------------------------------------------------------
# CloudTrail — object-level access to the CUI buckets
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "trail" {
  #checkov:skip=CKV_AWS_18:CloudTrail records its own delivery; server access logs on the trail bucket would be a circular audit of the audit.
  #checkov:skip=CKV_AWS_144:GovCloud CUI stays in-region — replication would copy the audit trail out of the ATO boundary.
  #checkov:skip=CKV2_AWS_62:Nothing consumes S3 events on the trail bucket.
  count = var.enable_cloudtrail ? 1 : 0

  bucket        = "${var.name_prefix}-trail"
  force_destroy = false # an audit trail must not vanish with a terraform destroy

  tags = merge(var.tags, { Name = local.trail_name })
}

resource "aws_s3_bucket_public_access_block" "trail" {
  count = var.enable_cloudtrail ? 1 : 0

  bucket                  = aws_s3_bucket.trail[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  count = var.enable_cloudtrail ? 1 : 0

  bucket = aws_s3_bucket.trail[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
  }
}

resource "aws_s3_bucket_versioning" "trail" {
  count = var.enable_cloudtrail ? 1 : 0

  bucket = aws_s3_bucket.trail[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  count = var.enable_cloudtrail ? 1 : 0

  bucket = aws_s3_bucket.trail[0].id

  rule {
    id     = "expire-trail-objects"
    status = "Enabled"
    filter {}

    expiration {
      days = var.trail_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = var.trail_retention_days
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "trail_bucket" {
  count = var.enable_cloudtrail ? 1 : 0

  statement {
    sid       = "AWSCloudTrailAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail[0].arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }

  statement {
    sid       = "AWSCloudTrailWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail[0].arn}/AWSLogs/${local.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.trail[0].arn, "${aws_s3_bucket.trail[0].arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  count = var.enable_cloudtrail ? 1 : 0

  bucket = aws_s3_bucket.trail[0].id
  policy = data.aws_iam_policy_document.trail_bucket[0].json
}

# CloudTrail delivers into CloudWatch Logs as well as S3, so the trail can be
# alarmed on and searched without waiting for an S3 object to land.
resource "aws_cloudwatch_log_group" "trail" {
  count = var.enable_cloudtrail ? 1 : 0

  name              = "/aws/cloudtrail/${var.name_prefix}"
  retention_in_days = var.trail_log_group_retention_days
  kms_key_id        = var.kms_key_arn

  tags = merge(var.tags, { Name = local.trail_name })
}

data "aws_iam_policy_document" "trail_cw_assume" {
  count = var.enable_cloudtrail ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "trail_cw" {
  count = var.enable_cloudtrail ? 1 : 0

  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.trail[0].arn}:*"]
  }
}

resource "aws_iam_role" "trail_cw" {
  count = var.enable_cloudtrail ? 1 : 0

  name               = "${var.name_prefix}-trail-cw"
  assume_role_policy = data.aws_iam_policy_document.trail_cw_assume[0].json
  tags               = var.tags
}

resource "aws_iam_role_policy" "trail_cw" {
  count = var.enable_cloudtrail ? 1 : 0

  name   = "${var.name_prefix}-trail-cw"
  role   = aws_iam_role.trail_cw[0].id
  policy = data.aws_iam_policy_document.trail_cw[0].json
}

resource "aws_cloudtrail" "this" {
  #checkov:skip=CKV_AWS_252:Alarms notify via var.alarm_actions (an org-owned SNS topic). A second SNS topic wired directly to the trail would double-notify.
  count = var.enable_cloudtrail ? 1 : 0

  name           = local.trail_name
  s3_bucket_name = aws_s3_bucket.trail[0].id
  kms_key_id     = var.kms_key_arn

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.trail[0].arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.trail_cw[0].arn

  enable_log_file_validation    = true
  include_global_service_events = true

  # Multi-region: activity in a region we do not deploy to is exactly the kind of
  # thing an audit trail exists to catch. The cost is negligible — a trail only
  # bills on events, and there are none in the other regions.
  is_multi_region_trail = true

  # Object-level events on the CUI buckets — who read whose scan results, and
  # when. Management events alone would not record that.
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = [for arn in var.data_event_bucket_arns : "${arn}/"]
    }
  }

  depends_on = [aws_s3_bucket_policy.trail]

  tags = merge(var.tags, { Name = local.trail_name })
}

# ---------------------------------------------------------------------------
# Alarms
# ---------------------------------------------------------------------------

# The one that matters: an operator's job died.
resource "aws_cloudwatch_metric_alarm" "executions_failed" {
  alarm_name          = "${var.name_prefix}-executions-failed"
  alarm_description   = "A STIG Condenser pipeline execution failed. The job record carries the operator-facing reason."
  namespace           = "AWS/States"
  metric_name         = "ExecutionsFailed"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching" # no executions is normal for an occasional-use tool

  dimensions = {
    StateMachineArn = var.state_machine_arn
  }

  alarm_actions = var.alarm_actions
  tags          = var.tags
}

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  for_each = var.lambda_function_names

  alarm_name          = "${var.name_prefix}-${each.key}-errors"
  alarm_description   = "Unhandled errors in the ${each.key} function."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = each.value
  }

  alarm_actions = var.alarm_actions
  tags          = var.tags
}

resource "aws_cloudwatch_metric_alarm" "lambda_throttles" {
  for_each = var.lambda_function_names

  alarm_name          = "${var.name_prefix}-${each.key}-throttles"
  alarm_description   = "The ${each.key} function is being throttled — jobs will stall."
  namespace           = "AWS/Lambda"
  metric_name         = "Throttles"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = each.value
  }

  alarm_actions = var.alarm_actions
  tags          = var.tags
}
