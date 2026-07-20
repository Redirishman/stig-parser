output "vpc_id" {
  description = "VPC id."
  value       = aws_vpc.this.id
}

output "private_subnet_ids" {
  description = "Private subnet ids for Lambda placement."
  value       = aws_subnet.private[*].id
}

output "lambda_security_group_id" {
  description = "Security group id to attach to in-VPC Lambdas."
  value       = aws_security_group.lambda.id
}

output "private_route_table_id" {
  description = "Private route table id (gateway endpoints attach here)."
  value       = aws_route_table.private.id
}

output "execute_api_endpoint_id" {
  description = "Interface endpoint id for execute-api — the Private API GW resource policy restricts invocation to this VPCE."
  value       = aws_vpc_endpoint.execute_api.id
}

output "execute_api_security_group_id" {
  description = "Dedicated execute-api endpoint security group for approved client CIDRs."
  value       = aws_security_group.execute_api_vpce.id
}

output "execute_api_endpoint_dns_entries" {
  description = "Execute-api endpoint DNS entries for the network/DNS team. Hybrid clients still require organization-managed conditional forwarding."
  value       = aws_vpc_endpoint.execute_api.dns_entry
}

output "s3_gateway_endpoint_id" {
  description = "Gateway endpoint id used by Lambda S3 calls and allowed by the API role's network condition."
  value       = aws_vpc_endpoint.gateway["s3"].id
}

output "s3_client_endpoint_id" {
  description = "S3 interface endpoint id used by browser presigned PUT and GET requests."
  value       = aws_vpc_endpoint.s3_client.id
}

output "s3_client_security_group_id" {
  description = "Dedicated S3 client endpoint security group for approved client CIDRs."
  value       = aws_security_group.s3_client_vpce.id
}

output "s3_client_endpoint_dns_entries" {
  description = "All endpoint-specific S3 DNS entries, including Regional and zonal records."
  value       = aws_vpc_endpoint.s3_client.dns_entry
}

output "s3_client_endpoint_url" {
  description = "GovCloud-safe Regional S3 PrivateLink URL used only to generate browser presigned URLs."
  value       = local.s3_client_endpoint_url

  precondition {
    condition     = length(local.s3_client_regional_dns_names) == 1 && startswith(local.s3_client_endpoint_url, "https://bucket.") && !strcontains(local.s3_client_endpoint_url, "*")
    error_message = "The S3 interface endpoint must expose exactly one Regional DNS name that can be converted to a https://bucket.<endpoint> URL."
  }
}

output "interface_endpoint_ids" {
  description = "Map of service short name -> interface endpoint id."
  value = merge(
    { for k, v in aws_vpc_endpoint.interface : k => v.id },
    {
      "execute-api" = aws_vpc_endpoint.execute_api.id
      "s3-client"   = aws_vpc_endpoint.s3_client.id
    },
  )
}
