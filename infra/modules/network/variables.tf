variable "name_prefix" {
  description = "Prefix for all resource names in this environment (e.g. stig-condenser-prod)."
  type        = string
}

variable "aws_region" {
  description = "GovCloud region for interface endpoint service names (D1)."
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
}

variable "private_subnet_cidrs" {
  description = "CIDRs for the private subnets, one per AZ. Length sets AZ count."
  type        = list(string)
}

variable "interface_endpoint_services" {
  description = <<-EOT
    Short service names for interface VPC endpoints (without the
    com.amazonaws.<region> prefix). Each bills ~$7-8/mo — see infra/README.md.
  EOT
  type        = list(string)
  default     = ["execute-api", "bedrock-runtime", "states", "logs", "kms", "sts"]
}

variable "enable_monitoring_endpoint" {
  description = "Add the 'monitoring' interface endpoint (needed for X-Ray)."
  type        = bool
  default     = false
}

variable "enable_flow_logs" {
  description = "Record VPC flow logs. On by default: this VPC has no route to the internet, so any traffic to an unexpected destination is worth having a record of."
  type        = bool
  default     = true
}

variable "flow_log_retention_days" {
  description = "Retention for the flow-log group."
  type        = number
  default     = 365
}

variable "kms_key_arn" {
  description = "CMK for the flow-log group. Required when enable_flow_logs is true."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
