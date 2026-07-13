# DynamoDB job/status table. One item per jobId; the #1 DynamoJobStore encodes
# all fields into a single JSON `data` attribute, so only the partition key and
# the TTL attribute are modeled here. Spec §4.3.

resource "aws_dynamodb_table" "jobs" {
  name         = "${var.name_prefix}-jobs"
  billing_mode = "PAY_PER_REQUEST" # occasional-use workload; no capacity to plan
  hash_key     = "jobId"

  attribute {
    name = "jobId"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  ttl {
    enabled        = var.ttl_enabled
    attribute_name = "expiresAt"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-jobs" })
}
