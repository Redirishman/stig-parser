variable "name_prefix" {
  description = "Prefix for function and log-group names."
  type        = string
}

variable "backend_source_dir" {
  description = <<-EOT
    Path to the Python package root that gets zipped into every function (the
    directory *containing* `app/`). Referenced as a variable so the eventual
    /backend monorepo rename (deferred to #3) is a one-line change here.
  EOT
  type        = string
}

variable "dependency_layer_zip" {
  description = <<-EOT
    Path to a prebuilt Lambda layer zip holding lxml + openpyxl (boto3 is in the
    runtime already). These ship compiled wheels, so the layer MUST be built on
    Linux for the target runtime — see infra/scripts/build-layer.sh. There is no
    default: a function without this layer imports lxml and dies at cold start,
    and that failure is far cheaper to hit here than in GovCloud.
  EOT
  type        = string
}

variable "python_runtime" {
  description = "Lambda runtime. Must match the interpreter the dependency layer was built against."
  type        = string
  default     = "python3.12"
}

variable "uploads_bucket" {
  description = "Uploads bucket name (env: UPLOADS_BUCKET)."
  type        = string
}

variable "artifacts_bucket" {
  description = "Artifacts bucket name (env: ARTIFACTS_BUCKET)."
  type        = string
}

variable "job_table_name" {
  description = "DynamoDB job table name (env: JOB_TABLE)."
  type        = string
}

variable "job_ttl_days" {
  description = <<-EOT
    Days before a job record expires via DynamoDB TTL (D5, CUI retention).
    DynamoJobStore only writes the `expiresAt` attribute when this is set — with
    TTL enabled on the table and this null, nothing ever expires.
  EOT
  type        = number
  default     = null
}

variable "state_machine_arn" {
  description = "State machine the API function starts (env: STATE_MACHINE_ARN)."
  type        = string
}

variable "role_arns" {
  description = "Map of function short name -> execution role ARN, from the iam module."
  type        = map(string)
}

variable "subnet_ids" {
  description = "Private subnets for Lambda ENIs."
  type        = list(string)
}

variable "security_group_id" {
  description = "Lambda security group id."
  type        = string
}

variable "kms_key_arn" {
  description = "CMK for environment-variable and log-group encryption."
  type        = string
}

variable "bedrock_model_id" {
  description = "Bedrock model id (D4). Empty keeps AI off — the API gate reports `disabled-globally`."
  type        = string
  default     = ""
}

variable "bedrock_region" {
  description = "Region hosting Bedrock (D1)."
  type        = string
}

variable "ai_killswitch_param" {
  description = "SSM parameter name holding the AI killswitch ('enabled' = on; anything else, or an unreadable parameter, = off)."
  type        = string
  default     = ""
}

variable "identity_header" {
  description = <<-EOT
    Header carrying the upstream-authenticated user (D3), recorded on the job for
    audit. NOT a trust boundary — the API never makes an authorization decision
    from it; auth is enforced upstream of the private endpoint.
  EOT
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "CloudWatch log retention for every function. Compliance systems are usually held to a year."
  type        = number
  default     = 365
}

variable "reserved_concurrency" {
  description = "Per-function concurrency cap. -1 leaves the function unreserved (it may then consume the whole account's concurrency)."
  type        = number
  default     = 10
}

variable "ephemeral_storage_mb" {
  description = <<-EOT
    Size of /tmp. The stages download uploads, unzip DISA benchmark bundles and
    write an xlsx there; the 512 MB default is not enough for the 200 MB per-file
    upload cap, and overflowing /tmp surfaces as an opaque OSError mid-parse.
  EOT
  type        = number
  default     = 4096
}

variable "stage_memory_mb" {
  description = "Memory for the parser/enricher/exporter functions. Lambda scales CPU with memory, and lxml parsing is CPU-bound."
  type        = number
  default     = 3008
}

variable "stage_timeout_seconds" {
  description = "Timeout for the parser/enricher/exporter functions (Step Functions has no 29s cap; a large multi-file scan is slow)."
  type        = number
  default     = 900
}

variable "api_memory_mb" {
  description = "Memory for the API function. It only presigns and reads DynamoDB — no parsing."
  type        = number
  default     = 512
}

variable "api_timeout_seconds" {
  description = "Timeout for the API function. API Gateway hard-caps the request at 29s, so a longer value here cannot help."
  type        = number
  default     = 29
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
