variable "name_prefix" {
  description = "Prefix for the table name."
  type        = string
}

variable "kms_key_arn" {
  description = "CMK ARN from the storage module for table encryption at rest."
  type        = string
}

variable "ttl_enabled" {
  description = "Enable DynamoDB TTL on the expiresAt attribute (CUI retention, D5)."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
