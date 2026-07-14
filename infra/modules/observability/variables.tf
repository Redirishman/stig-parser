variable "name_prefix" {
  description = "Prefix for the trail, alarms and log groups."
  type        = string
}

variable "kms_key_arn" {
  description = "CMK for the trail's log bucket."
  type        = string
}

variable "data_event_bucket_arns" {
  description = "Bucket ARNs whose object-level reads and writes are recorded (uploads + artifacts — the CUI ones)."
  type        = list(string)
}

variable "lambda_function_names" {
  description = "Map of function short name -> function name, for per-function alarms."
  type        = map(string)
}

variable "state_machine_arn" {
  description = "State machine ARN, for the ExecutionsFailed alarm."
  type        = string
}

variable "alarm_actions" {
  description = <<-EOT
    SNS topic ARNs notified when an alarm fires. Empty means the alarms still
    evaluate and show in the console but nobody is paged — fine for a first
    apply, not for production. The topic is org-owned, so it is an input rather
    than something this module invents.
  EOT
  type        = list(string)
  default     = []
}

variable "trail_retention_days" {
  description = "Lifecycle expiry for CloudTrail objects."
  type        = number
  default     = 365
}

variable "trail_log_group_retention_days" {
  description = "Retention for the CloudTrail CloudWatch log group (the S3 copy is the system of record; this one exists to be alarmed on and searched)."
  type        = number
  default     = 365
}

variable "enable_cloudtrail" {
  description = "Provision the CloudTrail trail. Off only if the org already runs an account-wide trail that covers these buckets — double-recording S3 data events is expensive and buys nothing."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
