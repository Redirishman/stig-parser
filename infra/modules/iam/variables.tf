variable "name_prefix" {
  description = "Prefix for role and policy names."
  type        = string
}

variable "uploads_bucket_arn" {
  description = "ARN of the uploads bucket (raw operator scan files)."
  type        = string
}

variable "artifacts_bucket_arn" {
  description = "ARN of the artifacts bucket (findings.json, report.xlsx)."
  type        = string
}

variable "api_s3_client_endpoint_id" {
  description = "S3 interface endpoint id required for browser use of API-generated presigned URLs."
  type        = string
  nullable    = false

  validation {
    condition     = startswith(var.api_s3_client_endpoint_id, "vpce-")
    error_message = "api_s3_client_endpoint_id must be a VPC endpoint id beginning with vpce-."
  }
}

variable "api_s3_gateway_endpoint_id" {
  description = "S3 gateway endpoint id used by the API Lambda for object existence checks."
  type        = string
  nullable    = false

  validation {
    condition     = startswith(var.api_s3_gateway_endpoint_id, "vpce-")
    error_message = "api_s3_gateway_endpoint_id must be a VPC endpoint id beginning with vpce-."
  }
}

variable "job_table_arn" {
  description = "ARN of the DynamoDB job table."
  type        = string
}

variable "kms_key_arn" {
  description = "CMK ARN — every S3/DynamoDB read and write needs Encrypt/Decrypt on it."
  type        = string
}

variable "state_machine_arn" {
  description = <<-EOT
    ARN of the Step Functions state machine the API role may start. Passed in
    rather than derived: the orchestration module needs the role ARNs, so the
    ARN is constructed in the env composition to break the cycle.
  EOT
  type        = string
}

variable "bedrock_model_id" {
  description = <<-EOT
    Bedrock model id the enricher may invoke (D4). Empty (the default) means no
    model is approved yet, and the enricher role gets NO bedrock permission at
    all — AI is off until an org decision fills this in.
  EOT
  type        = string
  default     = ""
}

variable "bedrock_region" {
  description = "Region hosting Bedrock (D1) — the model ARN is built in this region, which may differ from the region the rest of the stack runs in."
  type        = string
}

variable "ai_killswitch_param_arn" {
  description = "ARN of the SSM parameter holding the AI killswitch. Empty disables the ssm:GetParameter grant."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
