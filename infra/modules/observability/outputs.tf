output "trail_bucket" {
  description = "CloudTrail log bucket name (null when enable_cloudtrail is false)."
  value       = var.enable_cloudtrail ? aws_s3_bucket.trail[0].bucket : null
}

output "trail_arn" {
  description = "CloudTrail trail ARN (null when enable_cloudtrail is false)."
  value       = var.enable_cloudtrail ? aws_cloudtrail.this[0].arn : null
}

output "alarm_names" {
  description = "Every alarm this module created."
  value = concat(
    [aws_cloudwatch_metric_alarm.executions_failed.alarm_name],
    [for a in aws_cloudwatch_metric_alarm.lambda_errors : a.alarm_name],
    [for a in aws_cloudwatch_metric_alarm.lambda_throttles : a.alarm_name],
  )
}
