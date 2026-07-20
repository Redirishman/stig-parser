output "api_id" {
  description = "REST API id."
  value       = aws_api_gateway_rest_api.this.id
}

output "invoke_url" {
  description = <<-EOT
    VPC-internal invoke url. Resolvable only from inside the VPC, through the
    execute-api interface endpoint — it is not reachable from the internet.
  EOT
  value       = aws_api_gateway_stage.this.invoke_url
}

output "stage_name" {
  description = "Deployed stage name."
  value       = aws_api_gateway_stage.this.stage_name
}

output "spa_bucket" {
  description = "SPA asset bucket (apigw_s3_proxy mode only; null otherwise). #3 uploads the React bundle here."
  value       = local.serve_spa_from_s3 ? aws_s3_bucket.spa[0].bucket : null
}

output "upload_cors_allowed_origins" {
  description = "Exact browser origins configured on the uploads bucket for presigned PUT requests."
  value       = local.upload_cors_allowed_origins
}
