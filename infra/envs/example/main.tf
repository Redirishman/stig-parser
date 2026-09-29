# Example environment: wires every module together. Copy this directory to
# envs/<your-env>/, supply a real terraform.tfvars and backend.tf, then apply.
#
# NOTHING environment-specific belongs in this file — no account id, no VPC id,
# no bucket name. Everything arrives through variables (spec §5).

terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40.0, < 6.0.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4.0, < 3.0.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = var.tags
  }
}

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}

locals {
  # Dependency cycle break: the iam module must grant states:StartExecution on
  # the state machine, but the orchestration module that creates it needs the
  # Lambda ARNs, which need the roles. The name is ours to choose, so the ARN is
  # predictable — construct it rather than reference it.
  #
  # It must match aws_sfn_state_machine.this.name in modules/orchestration
  # (== var.name_prefix).
  state_machine_arn = "arn:${data.aws_partition.current.partition}:states:${var.aws_region}:${data.aws_caller_identity.current.account_id}:stateMachine:${var.name_prefix}"

  ai_killswitch_param_arn = var.ai_killswitch_param == "" ? "" : "arn:${data.aws_partition.current.partition}:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter${var.ai_killswitch_param}"
}

module "storage" {
  source = "../../modules/storage"

  name_prefix             = var.name_prefix
  upload_retention_days   = var.upload_retention_days
  artifact_retention_days = var.artifact_retention_days
  tags                    = var.tags
}

# After storage: the flow-log group is encrypted with the storage module's CMK.
module "network" {
  source = "../../modules/network"

  name_prefix                    = var.name_prefix
  aws_region                     = var.aws_region
  vpc_cidr                       = var.vpc_cidr
  private_subnet_cidrs           = var.private_subnet_cidrs
  api_client_cidr_blocks         = var.api_client_cidr_blocks
  api_client_route_management    = var.api_client_route_management
  api_client_routes              = var.api_client_routes
  s3_client_uploads_bucket_arn   = module.storage.uploads_bucket_arn
  s3_client_artifacts_bucket_arn = module.storage.artifacts_bucket_arn
  kms_key_arn                    = module.storage.kms_key_arn
  enable_flow_logs               = var.enable_flow_logs
  flow_log_retention_days        = var.flow_log_retention_days
  tags                           = var.tags
}

module "data" {
  source = "../../modules/data"

  name_prefix = var.name_prefix
  kms_key_arn = module.storage.kms_key_arn
  tags        = var.tags
}

module "iam" {
  source = "../../modules/iam"

  name_prefix                = var.name_prefix
  uploads_bucket_arn         = module.storage.uploads_bucket_arn
  artifacts_bucket_arn       = module.storage.artifacts_bucket_arn
  api_s3_client_endpoint_id  = module.network.s3_client_endpoint_id
  api_s3_gateway_endpoint_id = module.network.s3_gateway_endpoint_id
  job_table_arn              = module.data.job_table_arn
  kms_key_arn                = module.storage.kms_key_arn
  state_machine_arn          = local.state_machine_arn
  bedrock_model_id           = var.bedrock_model_id
  bedrock_region             = var.bedrock_region
  ai_killswitch_param_arn    = local.ai_killswitch_param_arn
  tags                       = var.tags
}

module "compute" {
  source = "../../modules/compute"

  name_prefix          = var.name_prefix
  backend_source_dir   = var.backend_source_dir
  dependency_layer_zip = var.dependency_layer_zip
  python_runtime       = var.python_runtime

  uploads_bucket          = module.storage.uploads_bucket
  artifacts_bucket        = module.storage.artifacts_bucket
  s3_presign_endpoint_url = module.network.s3_client_endpoint_url
  job_table_name          = module.data.job_table_name
  job_ttl_days            = var.job_ttl_days
  state_machine_arn       = local.state_machine_arn
  role_arns               = module.iam.role_arns

  subnet_ids        = module.network.private_subnet_ids
  security_group_id = module.network.lambda_security_group_id
  kms_key_arn       = module.storage.kms_key_arn

  bedrock_model_id     = var.bedrock_model_id
  bedrock_region       = var.bedrock_region
  ai_killswitch_param  = var.ai_killswitch_param
  identity_header      = var.identity_header
  log_retention_days   = var.log_retention_days
  reserved_concurrency = var.lambda_reserved_concurrency

  tags = var.tags
}

module "orchestration" {
  source = "../../modules/orchestration"

  name_prefix        = var.name_prefix
  function_arns      = module.compute.function_arns
  kms_key_arn        = module.storage.kms_key_arn
  log_retention_days = var.log_retention_days
  tags               = var.tags
}

module "api" {
  source = "../../modules/api"

  name_prefix                    = var.name_prefix
  execute_api_endpoint_id        = module.network.execute_api_endpoint_id
  api_function_arn               = module.compute.api_function_arn
  api_function_name              = module.compute.api_function_name
  spa_serving_mode               = var.spa_serving_mode
  uploads_bucket_name            = module.storage.uploads_bucket
  additional_upload_cors_origins = var.additional_upload_cors_origins
  kms_key_arn                    = module.storage.kms_key_arn
  log_retention_days             = var.log_retention_days
  tags                           = var.tags
}

module "observability" {
  source = "../../modules/observability"

  name_prefix       = var.name_prefix
  kms_key_arn       = module.storage.kms_key_arn
  enable_cloudtrail = var.enable_cloudtrail

  data_event_bucket_arns = [
    module.storage.uploads_bucket_arn,
    module.storage.artifacts_bucket_arn,
  ]

  lambda_function_names = module.compute.function_names
  state_machine_arn     = module.orchestration.state_machine_arn
  alarm_actions         = var.alarm_actions
  trail_retention_days  = var.trail_retention_days

  tags = var.tags
}

# The constructed ARN above is load-bearing: if it ever drifts from the real
# one, the API function's states:StartExecution grant silently stops matching
# and every job submission fails with AccessDenied at runtime. Fail the apply
# instead.
resource "terraform_data" "state_machine_arn_matches" {
  lifecycle {
    precondition {
      condition     = module.orchestration.state_machine_arn == local.state_machine_arn
      error_message = "Constructed state machine ARN does not match the created one — the IAM grant would not match. Check that modules/orchestration names the state machine var.name_prefix."
    }
  }
}
