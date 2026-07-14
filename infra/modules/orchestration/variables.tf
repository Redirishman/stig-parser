variable "name_prefix" {
  description = "Prefix for the state machine and its role."
  type        = string
}

variable "function_arns" {
  description = "Map of function short name (parser|enricher|exporter|marker) -> ARN, from the compute module."
  type        = map(string)
}

variable "log_retention_days" {
  description = "Retention for the state machine's execution log group."
  type        = number
  default     = 365
}

variable "kms_key_arn" {
  description = "CMK for the execution log group."
  type        = string
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
