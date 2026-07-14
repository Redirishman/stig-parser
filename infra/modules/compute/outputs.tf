output "function_arns" {
  description = "Map of function short name (api|parser|enricher|exporter) -> function ARN."
  value       = { for k, v in aws_lambda_function.this : k => v.arn }
}

output "function_names" {
  description = "Map of function short name -> function name."
  value       = { for k, v in aws_lambda_function.this : k => v.function_name }
}

output "api_function_arn" {
  description = "ARN of the API function (the API Gateway integration target)."
  value       = aws_lambda_function.this["api"].arn
}

output "api_function_name" {
  description = "Name of the API function (needed for the lambda:InvokeFunction permission)."
  value       = aws_lambda_function.this["api"].function_name
}

output "log_group_names" {
  description = "Map of function short name -> CloudWatch log group name."
  value       = { for k, v in aws_cloudwatch_log_group.this : k => v.name }
}
