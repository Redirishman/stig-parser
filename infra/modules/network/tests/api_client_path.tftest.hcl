mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = {
      names = ["us-gov-west-1a", "us-gov-west-1b"]
    }
  }

  mock_resource "aws_vpc_endpoint" {
    defaults = {
      dns_entry = [
        {
          dns_name       = "*.vpce-test.s3.us-gov-west-1.vpce.amazonaws.com"
          hosted_zone_id = "test-regional-zone"
        },
        {
          dns_name       = "*.vpce-test-us-gov-west-1a.s3.us-gov-west-1.vpce.amazonaws.com"
          hosted_zone_id = "test-zonal-zone-a"
        },
        {
          dns_name       = "*.vpce-test-us-gov-west-1b.s3.us-gov-west-1.vpce.amazonaws.com"
          hosted_zone_id = "test-zonal-zone-b"
        },
      ]
      prefix_list_id = "pl-test"
    }
  }
}

variables {
  name_prefix          = "stig-condenser-test"
  aws_region           = "us-gov-west-1"
  vpc_cidr             = "10.0.0.0/16"
  private_subnet_cidrs = ["10.0.1.0/24", "10.0.2.0/24"]

  api_client_cidr_blocks      = ["10.100.0.0/16"]
  api_client_route_management = "module"
  api_client_routes = {
    operator_vpn = {
      destination_cidr_block = "10.100.0.0/16"
      transit_gateway_id     = "tgw-0123456789abcdef0"
    }
  }

  s3_client_uploads_bucket_arn   = "arn:aws-us-gov:s3:::test-uploads"
  s3_client_artifacts_bucket_arn = "arn:aws-us-gov:s3:::test-artifacts"

  enable_flow_logs = false
}

run "isolates_execute_api_and_builds_return_route" {
  command = apply

  assert {
    condition     = aws_vpc_endpoint.execute_api.security_group_ids == toset([aws_security_group.execute_api_vpce.id])
    error_message = "execute-api must use its dedicated client security group."
  }

  assert {
    condition     = !contains(keys(aws_vpc_endpoint.interface), "execute-api")
    error_message = "execute-api must not share the Lambda-only runtime endpoint group."
  }

  assert {
    condition = (
      aws_vpc_security_group_ingress_rule.execute_api_client["10.100.0.0/16"].cidr_ipv4 == "10.100.0.0/16" &&
      aws_vpc_security_group_ingress_rule.execute_api_client["10.100.0.0/16"].from_port == 443 &&
      aws_vpc_security_group_ingress_rule.execute_api_client["10.100.0.0/16"].to_port == 443 &&
      aws_vpc_security_group_ingress_rule.execute_api_client["10.100.0.0/16"].ip_protocol == "tcp"
    )
    error_message = "The API endpoint must admit only the configured client CIDR on TCP/443."
  }

  assert {
    condition = (
      aws_route.api_client["operator_vpn"].destination_cidr_block == "10.100.0.0/16" &&
      aws_route.api_client["operator_vpn"].transit_gateway_id == "tgw-0123456789abcdef0"
    )
    error_message = "Module-managed routing must create the exact configured return route."
  }

  assert {
    condition = (
      aws_vpc_endpoint.s3_client.vpc_endpoint_type == "Interface" &&
      aws_vpc_endpoint.s3_client.service_name == "com.amazonaws.us-gov-west-1.s3" &&
      aws_vpc_endpoint.s3_client.private_dns_enabled == false &&
      aws_vpc_endpoint.s3_client.security_group_ids == toset([aws_security_group.s3_client_vpce.id])
    )
    error_message = "Browser S3 traffic must use a dedicated interface endpoint with GovCloud-compatible private DNS disabled."
  }

  assert {
    condition = (
      aws_vpc_security_group_ingress_rule.s3_client["10.100.0.0/16"].cidr_ipv4 == "10.100.0.0/16" &&
      aws_vpc_security_group_ingress_rule.s3_client["10.100.0.0/16"].from_port == 443 &&
      aws_vpc_security_group_ingress_rule.s3_client["10.100.0.0/16"].to_port == 443 &&
      aws_vpc_security_group_ingress_rule.s3_client["10.100.0.0/16"].ip_protocol == "tcp"
    )
    error_message = "The S3 client endpoint must admit only the configured client CIDR on TCP/443."
  }

  assert {
    condition = (
      aws_vpc_endpoint.gateway["s3"].vpc_endpoint_type == "Gateway" &&
      contains(one(aws_security_group.lambda.egress).prefix_list_ids, aws_vpc_endpoint.gateway["s3"].prefix_list_id) &&
      contains(one(aws_security_group.lambda.egress).prefix_list_ids, aws_vpc_endpoint.gateway["dynamodb"].prefix_list_id)
    )
    error_message = "Lambda must retain the free S3 gateway path and be allowed to reach both gateway-endpoint prefix lists."
  }

  assert {
    condition = (
      output.s3_client_endpoint_url == "https://bucket.vpce-test.s3.us-gov-west-1.vpce.amazonaws.com" &&
      !strcontains(output.s3_client_endpoint_url, "*") &&
      !strcontains(output.s3_client_endpoint_url, "-us-gov-west-1a.s3.")
    )
    error_message = "Presigned URLs must use the wildcard-free Regional S3 interface endpoint hostname, not a zonal record."
  }

  assert {
    condition = (
      length(jsondecode(aws_vpc_endpoint.s3_client.policy).Statement) == 2 &&
      toset(flatten([
        for statement in jsondecode(aws_vpc_endpoint.s3_client.policy).Statement : [statement.Action]
      ])) == toset(["s3:PutObject", "s3:GetObject"]) &&
      toset(flatten([
        for statement in jsondecode(aws_vpc_endpoint.s3_client.policy).Statement : [statement.Resource]
        ])) == toset([
        "arn:aws-us-gov:s3:::test-uploads/jobs/*",
        "arn:aws-us-gov:s3:::test-artifacts/jobs/*",
      ])
    )
    error_message = "The S3 client endpoint policy must expose only presigned uploads and report downloads beneath jobs/."
  }
}

run "rejects_world_client_cidr" {
  command = plan

  variables {
    api_client_cidr_blocks      = ["0.0.0.0/0"]
    api_client_route_management = "external"
    api_client_routes           = {}
  }

  expect_failures = [var.api_client_cidr_blocks]
}

run "rejects_multiple_route_targets" {
  command = plan

  variables {
    api_client_routes = {
      operator_vpn = {
        destination_cidr_block     = "10.100.0.0/16"
        transit_gateway_id         = "tgw-0123456789abcdef0"
        virtual_private_gateway_id = "vgw-0123456789abcdef0"
      }
    }
  }

  expect_failures = [var.api_client_routes]
}

run "rejects_route_and_client_cidr_mismatch" {
  command = plan

  variables {
    api_client_routes = {
      wrong_network = {
        destination_cidr_block = "10.200.0.0/16"
        transit_gateway_id     = "tgw-0123456789abcdef0"
      }
    }
  }

  expect_failures = [aws_security_group.execute_api_vpce]
}
