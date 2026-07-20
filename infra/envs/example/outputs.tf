output "api_invoke_url" {
  description = "Private API URL. Reachability requires an approved client CIDR, an attached network path with reciprocal routing, and private DNS forwarding."
  value       = module.api.invoke_url
}

output "execute_api_endpoint_dns_entries" {
  description = "Endpoint DNS records supplied to the network/DNS team when configuring hybrid resolution."
  value       = module.network.execute_api_endpoint_dns_entries
}

output "execute_api_security_group_id" {
  description = "Dedicated endpoint SG that admits only approved API client CIDRs on TCP/443."
  value       = module.network.execute_api_security_group_id
}

output "s3_client_endpoint_dns_entries" {
  description = "Endpoint-specific S3 DNS records for private browser upload and report-download troubleshooting."
  value       = module.network.s3_client_endpoint_dns_entries
}

output "s3_client_security_group_id" {
  description = "Dedicated S3 interface-endpoint SG that admits approved client CIDRs on TCP/443."
  value       = module.network.s3_client_security_group_id
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
