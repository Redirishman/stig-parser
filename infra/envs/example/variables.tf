# Every org decision (D1-D6, spec §2) surfaces here as a variable. None of them
# have values in tracked files — see terraform.tfvars.example.

variable "name_prefix" {
  description = "Prefix for every resource name. Must make the S3 bucket names globally unique (e.g. stig-condenser-prod-<account-suffix>)."
  type        = string
}

variable "aws_region" {
  description = "GovCloud region for the stack (D1)."
  type        = string
  default     = "us-gov-west-1"
}

# --- Network -----------------------------------------------------------------

variable "vpc_cidr" {
  description = "CIDR for the VPC. Must not overlap anything reachable over the VPN."
  type        = string
}

variable "private_subnet_cidrs" {
  description = "One private subnet CIDR per AZ (two AZs minimum for Lambda availability)."
  type        = list(string)
}

# --- Retention (D5: CUI records policy — confirm with the ISSO) --------------

variable "upload_retention_days" {
  description = "Days before raw uploaded scan files are deleted. A records-retention decision, not a convenience default."
  type        = number
}

variable "artifact_retention_days" {
  description = "Days before generated findings JSON and xlsx reports are deleted."
  type        = number
}

variable "job_ttl_days" {
  description = "Days before a job record expires from DynamoDB. Null means job records never expire — deliberate choice required."
  type        = number
  default     = null
}

variable "trail_retention_days" {
  description = "Days before CloudTrail audit objects expire. Usually the longest of the three."
  type        = number
  default     = 365
}

# --- Compute -----------------------------------------------------------------

variable "backend_source_dir" {
  description = "Path to the directory containing `app/` (the repo root today; `/backend` after the #3 rename)."
  type        = string
  default     = "../../.."
}

variable "dependency_layer_zip" {
  description = "Path to the lxml+openpyxl layer zip built by infra/scripts/build-layer.sh. Must be built on Linux for python_runtime."
  type        = string
}

variable "python_runtime" {
  description = "Lambda Python runtime. Must match what the dependency layer was built against."
  type        = string
  default     = "python3.12"
}

# --- AI (D4: off until a model is approved) -----------------------------------

variable "bedrock_model_id" {
  description = <<-EOT
    Bedrock model id (D4). Empty — the default — means AI is off everywhere: the
    enricher role gets no bedrock permission and the API reports the gate as
    `disabled-globally`. Filling this in is what turns enrichment on, and it is
    an ATO-relevant change.
  EOT
  type        = string
  default     = ""
}

variable "bedrock_region" {
  description = "Region hosting Bedrock (D1). May differ from aws_region."
  type        = string
  default     = "us-gov-west-1"
}

variable "ai_killswitch_param" {
  description = "SSM parameter name holding the AI killswitch (e.g. /stig-condenser/ai-enabled). Value 'enabled' turns AI on; anything else — or an unreadable parameter — turns it off. Empty disables the killswitch check entirely."
  type        = string
  default     = ""
}

# --- Auth (D3) ---------------------------------------------------------------

variable "identity_header" {
  description = "Header carrying the upstream-authenticated user, recorded on jobs for audit (D3). Empty records no identity. NOT a trust boundary."
  type        = string
  default     = ""
}

# --- SPA (D6) ----------------------------------------------------------------

variable "spa_serving_mode" {
  description = "How the React SPA is served privately: apigw_s3_proxy | lambda_served | none (D6)."
  type        = string
  default     = "apigw_s3_proxy"
}

# --- Observability -----------------------------------------------------------

variable "log_retention_days" {
  description = "CloudWatch log retention across Lambdas, Step Functions and API Gateway."
  type        = number
  default     = 365
}

variable "enable_cloudtrail" {
  description = "Provision a CloudTrail trail for S3 data events. Turn off ONLY if an account-wide trail already covers these buckets."
  type        = bool
  default     = true
}

variable "enable_flow_logs" {
  description = "Record VPC flow logs. Turn off ONLY if the org captures flow logs centrally."
  type        = bool
  default     = true
}

variable "flow_log_retention_days" {
  description = "Retention for the VPC flow-log group."
  type        = number
  default     = 365
}

variable "lambda_reserved_concurrency" {
  description = "Per-function concurrency cap. Bounds a runaway client and protects the job table from a stampede; -1 means unreserved."
  type        = number
  default     = 10
}

variable "alarm_actions" {
  description = "SNS topic ARNs notified on alarm. Empty means alarms fire into the void — acceptable for a first apply, not for production."
  type        = list(string)
  default     = []
}

# --- Tagging -----------------------------------------------------------------

variable "tags" {
  description = "Tags applied to every resource. The org's tagging standard (data classification, system owner, ATO boundary) goes here."
  type        = map(string)
  default     = {}
}
