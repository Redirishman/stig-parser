output "state_machine_arn" {
  description = "ARN of the pipeline state machine (the API function starts executions on it)."
  value       = aws_sfn_state_machine.this.arn
}

output "state_machine_name" {
  description = "Name of the state machine (used by the observability alarms)."
  value       = aws_sfn_state_machine.this.name
}

output "log_group_name" {
  description = "Execution log group name."
  value       = aws_cloudwatch_log_group.states.name
}
