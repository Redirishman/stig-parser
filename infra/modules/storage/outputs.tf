output "uploads_bucket" {
  description = "Name of the uploads bucket."
  value       = aws_s3_bucket.this["uploads"].bucket
}

output "uploads_bucket_arn" {
  description = "ARN of the uploads bucket."
  value       = aws_s3_bucket.this["uploads"].arn
}

output "artifacts_bucket" {
  description = "Name of the artifacts bucket."
  value       = aws_s3_bucket.this["artifacts"].bucket
}

output "artifacts_bucket_arn" {
  description = "ARN of the artifacts bucket."
  value       = aws_s3_bucket.this["artifacts"].arn
}

output "kms_key_arn" {
  description = "CMK ARN — reused by the data module for DynamoDB SSE and by Lambda roles."
  value       = aws_kms_key.this.arn
}

output "kms_key_id" {
  description = "CMK key id."
  value       = aws_kms_key.this.key_id
}
