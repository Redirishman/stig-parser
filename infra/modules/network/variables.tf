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

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
