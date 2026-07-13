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

resource "aws_kms_key" "this" {
  description             = "${var.name_prefix} CMK for S3 + DynamoDB (CUI at rest)."
  deletion_window_in_days = var.kms_deletion_window_days
  enable_key_rotation     = true

  tags = merge(var.tags, { Name = "${var.name_prefix}-cmk" })
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.name_prefix}"
  target_key_id = aws_kms_key.this.key_id
}

# ---------------------------------------------------------------------------
# Buckets
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "this" {
  for_each = local.buckets

  bucket = "${var.name_prefix}-${each.key}"
  tags   = merge(var.tags, { Name = "${var.name_prefix}-${each.key}" })
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
