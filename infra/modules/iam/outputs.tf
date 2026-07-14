output "role_arns" {
  description = "Map of function short name (api|parser|enricher|exporter) -> execution role ARN."
  value       = { for k, v in aws_iam_role.this : k => v.arn }
}

output "role_names" {
  description = "Map of function short name -> execution role name."
  value       = { for k, v in aws_iam_role.this : k => v.name }
}
