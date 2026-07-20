# DynamoDB job/status table. One item per job; the #1 DynamoJobStore encodes
# all user-facing fields into one JSON `data` attribute and guards mutations
# with a top-level numeric `version`. DynamoDB only requires the partition key
# in the declared schema; `expiresAt` is configured below for TTL. Spec §4.3.
#
# The key name `job_id` and the TTL attribute `expiresAt` are a contract with
# app/core/job_store.py:DynamoJobStore — changing either here breaks every
# read at runtime. The store writes `expiresAt` only when JOB_TTL_DAYS is set
# in the Lambda environment (see modules/compute); with TTL enabled here and
# that variable unset, rows would never expire.

resource "aws_dynamodb_table" "jobs" {
  name         = "${var.name_prefix}-jobs"
  billing_mode = "PAY_PER_REQUEST" # occasional-use workload; no capacity to plan
  hash_key     = "job_id"

  attribute {
    name = "job_id"
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
