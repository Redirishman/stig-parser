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

variable "api_client_cidr_blocks" {
  description = <<-EOT
    IPv4 CIDRs allowed to reach the private execute-api endpoint on TCP/443.
    These must be the source addresses the endpoint ENIs actually observe after
    traffic crosses the organization-managed VPN, Direct Connect, or VPC path.
  EOT
  type        = set(string)
  nullable    = false

  validation {
    condition     = length(var.api_client_cidr_blocks) > 0
    error_message = "api_client_cidr_blocks must contain at least one approved client CIDR."
  }

  validation {
    condition = alltrue([
      for cidr in var.api_client_cidr_blocks :
      try(cidrnetmask(cidr) != "0.0.0.0", false)
    ])
    error_message = "api_client_cidr_blocks must contain valid IPv4 CIDRs and must not include 0.0.0.0/0."
  }
}

variable "api_client_route_management" {
  description = <<-EOT
    Who owns the private-subnet return routes for api_client_cidr_blocks:

      module   - this module creates one aws_route per entry in api_client_routes.
      external - an organization-managed network stack or an existing local/
                 propagated route owns every return route.

    VPN, Direct Connect, transit-gateway attachments, reciprocal routes, and
    hybrid DNS remain organization-managed in both modes.
  EOT
  type        = string
  nullable    = false

  validation {
    condition     = contains(["module", "external"], var.api_client_route_management)
    error_message = "api_client_route_management must be either module or external."
  }
}

variable "api_client_routes" {
  description = <<-EOT
    Static return routes for approved API clients when
    api_client_route_management is module. Each destination must match one
    api_client_cidr_blocks entry and name exactly one pre-existing, attached
    next hop. Attachments and reciprocal routing are owned by the network team.
  EOT
  type = map(object({
    destination_cidr_block     = string
    transit_gateway_id         = optional(string)
    virtual_private_gateway_id = optional(string)
    vpc_peering_connection_id  = optional(string)
  }))
  default  = {}
  nullable = false

  validation {
    condition = alltrue([
      for route in values(var.api_client_routes) :
      try(cidrnetmask(route.destination_cidr_block) != "0.0.0.0", false)
    ])
    error_message = "Every api_client_routes destination must be a valid IPv4 CIDR and must not be 0.0.0.0/0."
  }

  validation {
    condition = length(distinct([
      for route in values(var.api_client_routes) : route.destination_cidr_block
    ])) == length(var.api_client_routes)
    error_message = "api_client_routes must not contain duplicate destination CIDRs."
  }

  validation {
    condition = alltrue([
      for route in values(var.api_client_routes) : length([
        for target in [
          route.transit_gateway_id,
          route.virtual_private_gateway_id,
          route.vpc_peering_connection_id,
        ] : target if target != null && target != ""
      ]) == 1
    ])
    error_message = "Each api_client_routes entry must set exactly one transit_gateway_id, virtual_private_gateway_id, or vpc_peering_connection_id."
  }

  validation {
    condition = alltrue([
      for route in values(var.api_client_routes) :
      (route.transit_gateway_id == null || try(startswith(route.transit_gateway_id, "tgw-"), false)) &&
      (route.virtual_private_gateway_id == null || try(startswith(route.virtual_private_gateway_id, "vgw-"), false)) &&
      (route.vpc_peering_connection_id == null || try(startswith(route.vpc_peering_connection_id, "pcx-"), false))
    ])
    error_message = "Route target IDs must use the expected tgw-, vgw-, or pcx- prefix."
  }
}

variable "s3_client_uploads_bucket_arn" {
  description = "Uploads bucket ARN. The client S3 interface endpoint policy permits only s3:PutObject beneath its jobs/ prefix."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^arn:[^:]+:s3:::[^/*]+$", var.s3_client_uploads_bucket_arn))
    error_message = "s3_client_uploads_bucket_arn must be an S3 bucket ARN without an object suffix or wildcard."
  }
}

variable "s3_client_artifacts_bucket_arn" {
  description = "Artifacts bucket ARN. The client S3 interface endpoint policy permits only s3:GetObject beneath its jobs/ prefix."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^arn:[^:]+:s3:::[^/*]+$", var.s3_client_artifacts_bucket_arn))
    error_message = "s3_client_artifacts_bucket_arn must be an S3 bucket ARN without an object suffix or wildcard."
  }
}

variable "interface_endpoint_services" {
  description = <<-EOT
    Short service names for interface VPC endpoints (without the
    com.amazonaws.<region> prefix). The execute-api endpoint is always created
    separately with its client-facing security group. Interface endpoints bill
    per endpoint-hour in every selected AZ — see infra/README.md.
  EOT
  type        = list(string)
  # ssm is required whenever ai_killswitch_param is set: the API and enricher
  # read the killswitch parameter at request time, and without an endpoint the
  # call hangs to the 29s function timeout in this zero-egress VPC.
  default     = ["bedrock-runtime", "states", "logs", "kms", "sts", "ssm"]

  validation {
    condition     = !contains(var.interface_endpoint_services, "execute-api")
    error_message = "execute-api is created separately and must not be included in interface_endpoint_services."
  }
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
