variable "name_prefix" {
  description = "Prefix for bucket names and the KMS alias. Must yield globally-unique bucket names — the environment supplies uniqueness (e.g. an account-scoped suffix); never hard-code a real bucket name in tracked .tf."
  type        = string
}

variable "upload_retention_days" {
  description = "Lifecycle expiry for uploaded scan files. CUI records-policy decision (D5), not a convenience default."
  type        = number
}

variable "artifact_retention_days" {
  description = "Lifecycle expiry for generated reports + intermediate findings JSON (D5)."
  type        = number
}

variable "kms_deletion_window_days" {
  description = "Waiting period before the CMK is deleted after a destroy."
  type        = number
  default     = 30
}

variable "access_log_retention_days" {
  description = "Lifecycle expiry for S3 server access logs. These record who touched which object key, so they usually outlive the objects themselves."
  type        = number
  default     = 365
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
