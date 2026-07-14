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
  value       = try(aws_vpc_endpoint.interface["execute-api"].id, null)
}

output "interface_endpoint_ids" {
  description = "Map of service short name -> interface endpoint id."
  value       = { for k, v in aws_vpc_endpoint.interface : k => v.id }
}
