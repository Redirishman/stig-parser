output "api_invoke_url" {
  description = "VPC-internal API url. Reachable only from inside the VPC via the execute-api endpoint."
  value       = module.api.invoke_url
}

output "spa_bucket" {
  description = "Bucket the React bundle (#3) is uploaded to. Null unless spa_serving_mode is apigw_s3_proxy."
  value       = module.api.spa_bucket
}

output "uploads_bucket" {
  description = "Raw scan-file upload bucket."
  value       = module.storage.uploads_bucket
}

output "artifacts_bucket" {
  description = "Generated findings/report bucket."
  value       = module.storage.artifacts_bucket
}

output "job_table_name" {
  description = "DynamoDB job table."
  value       = module.data.job_table_name
}

output "state_machine_arn" {
  description = "Pipeline state machine."
  value       = module.orchestration.state_machine_arn
}

output "vpc_id" {
  description = "VPC hosting the runtime."
  value       = module.network.vpc_id
}
