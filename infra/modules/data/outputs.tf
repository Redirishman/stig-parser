output "job_table_name" {
  description = "DynamoDB job table name (passed to Lambdas as JOB_TABLE)."
  value       = aws_dynamodb_table.jobs.name
}

output "job_table_arn" {
  description = "DynamoDB job table ARN (scoped into Lambda IAM policies)."
  value       = aws_dynamodb_table.jobs.arn
}
