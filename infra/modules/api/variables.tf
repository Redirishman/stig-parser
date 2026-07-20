variable "name_prefix" {
  description = "Prefix for the API and its supporting resources."
  type        = string
}

variable "execute_api_endpoint_id" {
  description = <<-EOT
    The execute-api interface endpoint id. The API's resource policy allows
    invocation ONLY through this VPCE — it is the control that makes a "private"
    API actually private. A Private API without this condition is reachable from
    any VPC endpoint in any account that can guess its id.
  EOT
  type        = string
}

variable "api_function_arn" {
  description = "ARN of the API Lambda (proxy integration target)."
  type        = string
}

variable "api_function_name" {
  description = "Name of the API Lambda (for the lambda:InvokeFunction permission)."
  type        = string
}

variable "stage_name" {
  description = "API Gateway stage name."
  type        = string
  default     = "v1"
}

variable "spa_serving_mode" {
  description = <<-EOT
    How the React SPA (#3) is served inside the private VPC (D6):

      apigw_s3_proxy - API Gateway proxies GETs to a private S3 bucket. Default.
                       No CDN, per-request cost, needs binary_media_types.
      lambda_served  - the API function returns the bundled assets. Simpler
                       routing; couples the SPA to the API function.
      none           - serve the SPA elsewhere (e.g. an internal ALB the org
                       already runs). This module provisions no SPA path.
  EOT
  type        = string
  default     = "apigw_s3_proxy"

  validation {
    condition     = contains(["apigw_s3_proxy", "lambda_served", "none"], var.spa_serving_mode)
    error_message = "spa_serving_mode must be one of: apigw_s3_proxy, lambda_served, none."
  }
}

variable "uploads_bucket_name" {
  description = "Uploads bucket whose browser PUT path needs exact-origin CORS."
  type        = string
  nullable    = false
}

variable "additional_upload_cors_origins" {
  description = <<-EOT
    Additional exact HTTPS browser origins allowed to PUT to the uploads
    bucket. Managed SPA modes automatically include the API Gateway origin.
    Mode `none` must supply at least one origin and must place API calls behind
    the same-origin internal facade; this module does not add cross-origin API
    Gateway routes or response headers.
  EOT
  type        = set(string)
  default     = []
  nullable    = false

  validation {
    condition = alltrue([
      for origin in var.additional_upload_cors_origins :
      can(regex("^https://[^/:@?#*\\s]+(:[0-9]{1,5})?$", origin))
    ])
    error_message = "Each additional upload CORS origin must be an exact HTTPS origin (scheme and host, optional port), with no wildcard, credentials, path, query, fragment, or trailing slash."
  }
}

variable "kms_key_arn" {
  description = "CMK for the SPA bucket (apigw_s3_proxy mode) and the access-log group."
  type        = string
}

variable "log_retention_days" {
  description = "Retention for the API access-log group."
  type        = number
  default     = 365
}

variable "throttling_rate_limit" {
  description = "Steady-state request rate for the stage. This is a private, low-volume, human-driven API; the cap exists to bound a runaway client, not to shape traffic."
  type        = number
  default     = 50
}

variable "throttling_burst_limit" {
  description = "Burst capacity for the stage."
  type        = number
  default     = 100
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
