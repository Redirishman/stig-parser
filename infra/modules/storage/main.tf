# S3 buckets (uploads + artifacts) and the customer-managed KMS key that
# encrypts them (and, via the data module, DynamoDB). Block-public, versioned,
# TLS-only, lifecycle-expired. Spec §4.2.

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}

locals {
  # Per-bucket lifecycle expiry (CUI records policy, D5).
  buckets = {
    uploads   = var.upload_retention_days
    artifacts = var.artifact_retention_days
  }
}

# ---------------------------------------------------------------------------
# Customer-managed KMS key
# ---------------------------------------------------------------------------

data "aws_region" "current" {}

# An explicit key policy. Without one the CMK gets the default "root account has
# full access" policy, which grants every principal in the account that IAM
# allows — far broader than a CUI key should be. This scopes use to the account's
# own IAM (so the Lambda role policies remain the real gate) and to the AWS
# services that must encrypt on our behalf.
data "aws_iam_policy_document" "cmk" {
  #checkov:skip=CKV_AWS_356:The kms:* on "*" is the mandatory root statement of a KMS key policy — a key policy without it becomes unmanageable (AWS cannot even delete it). "*" here means "this key", not "all keys".
  #checkov:skip=CKV_AWS_111:Same root statement. Actual key USE is gated by the per-Lambda IAM policies in the iam module, which name the CMK ARN exactly.
  #checkov:skip=CKV_AWS_109:Same root statement — it is what allows IAM to administer the key at all.
  statement {
    sid       = "EnableIamUserPermissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  # CloudWatch Logs encrypts log groups with this key and must be able to
  # describe it; without this statement, log-group creation fails outright.
  statement {
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${data.aws_region.current.name}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:*"]
    }
  }

  statement {
    sid    = "AllowCloudTrail"
    effect = "Allow"
    actions = [
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    # Confused-deputy guard: tie the grant to this account's own trail so a
    # CloudTrail in another account cannot request a data key from this CMK
    # (mirrors the AllowCloudWatchLogs statement's scoping above).
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_kms_key" "this" {
  description             = "${var.name_prefix} CMK for S3 + DynamoDB (CUI at rest)."
  deletion_window_in_days = var.kms_deletion_window_days
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.cmk.json

  tags = merge(var.tags, { Name = "${var.name_prefix}-cmk" })
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.name_prefix}"
  target_key_id = aws_kms_key.this.key_id
}

# ---------------------------------------------------------------------------
# Buckets
# ---------------------------------------------------------------------------

# Server access logs for the CUI buckets. CloudTrail data events (observability
# module) record the API-level story; these are the S3-side record. The log
# bucket cannot log to itself, hence the separate bucket.
#
resource "aws_s3_bucket" "access_logs" {
  #checkov:skip=CKV_AWS_145:S3 log delivery cannot write into an SSE-KMS bucket — AES256 is the only encryption the mechanism supports. These logs hold object keys, not scan contents.
  #checkov:skip=CKV_AWS_18:This IS the access-log bucket — self-logging is a loop.
  #checkov:skip=CKV_AWS_144:GovCloud CUI stays in-region; cross-region replication would copy it out of the ATO boundary.
  #checkov:skip=CKV2_AWS_62:Nothing consumes S3 events here; the pipeline is driven by Step Functions.
  bucket = "${var.name_prefix}-access-logs"
  tags   = merge(var.tags, { Name = "${var.name_prefix}-access-logs" })
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 server access logging cannot deliver into an SSE-KMS bucket; SSE-S3 is the
# only option the log-delivery mechanism supports. The logs carry object keys
# (job ids and filenames), not scan contents.
resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    id     = "expire-access-logs"
    status = "Enabled"
    filter {}

    expiration {
      days = var.access_log_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = var.access_log_retention_days
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# The log-delivery group writes here; ACLs are otherwise disabled account-wide by
# BucketOwnerEnforced, which log delivery does not support — so this one bucket
# keeps ObjectWriter ownership.
resource "aws_s3_bucket_ownership_controls" "access_logs" {
  #checkov:skip=CKV2_AWS_65:S3 server-access-log delivery writes with an ACL and does not support BucketOwnerEnforced. This is the one bucket that must keep ACLs; every other bucket disables them.
  bucket = aws_s3_bucket.access_logs.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

data "aws_iam_policy_document" "access_logs" {
  statement {
    sid       = "AllowS3LogDelivery"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.access_logs.arn}/*"]
    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.access_logs.arn, "${aws_s3_bucket.access_logs.arn}/*"]
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

resource "aws_s3_bucket_policy" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  policy = data.aws_iam_policy_document.access_logs.json
}

resource "aws_s3_bucket" "this" {
  #checkov:skip=CKV_AWS_144:GovCloud CUI stays in-region; cross-region replication would copy it out of the ATO boundary.
  #checkov:skip=CKV2_AWS_62:Nothing consumes S3 events here; the pipeline is driven by Step Functions.
  for_each = local.buckets

  bucket = "${var.name_prefix}-${each.key}"
  tags   = merge(var.tags, { Name = "${var.name_prefix}-${each.key}" })
}

resource "aws_s3_bucket_logging" "this" {
  for_each = aws_s3_bucket.this

  bucket        = each.value.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "s3/${each.key}/"
}

resource "aws_s3_bucket_public_access_block" "this" {
  for_each = aws_s3_bucket.this

  bucket                  = each.value.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "this" {
  for_each = aws_s3_bucket.this

  bucket = each.value.id
  rule {
    object_ownership = "BucketOwnerEnforced" # disables ACLs entirely
  }
}

resource "aws_s3_bucket_versioning" "this" {
  for_each = aws_s3_bucket.this

  bucket = each.value.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  for_each = aws_s3_bucket.this

  bucket = each.value.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.this.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  for_each = local.buckets

  bucket = aws_s3_bucket.this[each.key].id

  rule {
    id     = "expire-objects"
    status = "Enabled"

    filter {} # all objects

    expiration {
      days = each.value
    }

    # Versioning is on; clear noncurrent versions on the same clock.
    noncurrent_version_expiration {
      noncurrent_days = each.value
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Deny any non-TLS request. (Public access is already blocked above.)
data "aws_iam_policy_document" "tls_only" {
  for_each = aws_s3_bucket.this

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [each.value.arn, "${each.value.arn}/*"]

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

resource "aws_s3_bucket_policy" "tls_only" {
  for_each = aws_s3_bucket.this

  bucket = each.value.id
  policy = data.aws_iam_policy_document.tls_only[each.key].json
}
