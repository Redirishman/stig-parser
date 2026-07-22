# Private VPC for the STIG Condenser runtime: private subnets only, no Internet
# Gateway and no NAT. Every AWS service is reached through a VPC endpoint.
# Spec §4.1.

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  az_names = slice(
    data.aws_availability_zones.available.names,
    0,
    length(var.private_subnet_cidrs),
  )

  interface_services = concat(
    var.interface_endpoint_services,
    var.enable_monitoring_endpoint ? ["monitoring"] : [],
  )

  # GovCloud does not support private DNS for S3 interface endpoints. AWS
  # returns one Regional wildcard name plus one zonal name per subnet; browser
  # presigned URLs must use the Regional endpoint-specific name. `bucket` is a
  # literal S3 PrivateLink access label, not the actual bucket name; path-style
  # addressing appends the real bucket below it.
  s3_client_regional_dns_names = [
    for entry in aws_vpc_endpoint.s3_client.dns_entry : entry.dns_name
    if length(regexall("-${var.aws_region}[a-z]\\.s3\\.", entry.dns_name)) == 0
  ]
  s3_client_regional_dns_name = one(local.s3_client_regional_dns_names)
  s3_client_endpoint_host = startswith(local.s3_client_regional_dns_name, "*.") ? (
    "bucket.${trimprefix(local.s3_client_regional_dns_name, "*.")}"
    ) : (
    startswith(local.s3_client_regional_dns_name, "bucket.") ?
    local.s3_client_regional_dns_name :
    "bucket.${local.s3_client_regional_dns_name}"
  )
  s3_client_endpoint_url = "https://${local.s3_client_endpoint_host}"
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true # required for private_dns_enabled interface endpoints

  tags = merge(var.tags, { Name = "${var.name_prefix}-vpc" })
}

# Every VPC ships a default security group that allows all traffic between any
# ENI attached to it. Nothing here uses it, but an ENI created later without an
# explicit SG lands in it — so it is emptied rather than left as a latent hole.
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id

  # No ingress, no egress blocks == deny all.

  tags = merge(var.tags, { Name = "${var.name_prefix}-default-DO-NOT-USE" })
}

# ---------------------------------------------------------------------------
# Flow logs
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "flow" {
  count = var.enable_flow_logs ? 1 : 0

  name              = "/aws/vpc/${var.name_prefix}"
  retention_in_days = var.flow_log_retention_days
  kms_key_id        = var.kms_key_arn

  tags = merge(var.tags, { Name = "${var.name_prefix}-flow-logs" })
}

data "aws_iam_policy_document" "flow_assume" {
  count = var.enable_flow_logs ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "flow" {
  count = var.enable_flow_logs ? 1 : 0

  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
    ]
    resources = ["${aws_cloudwatch_log_group.flow[0].arn}:*"]
  }
}

resource "aws_iam_role" "flow" {
  count = var.enable_flow_logs ? 1 : 0

  name               = "${var.name_prefix}-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.flow_assume[0].json
  tags               = var.tags
}

resource "aws_iam_role_policy" "flow" {
  count = var.enable_flow_logs ? 1 : 0

  name   = "${var.name_prefix}-flow-logs"
  role   = aws_iam_role.flow[0].id
  policy = data.aws_iam_policy_document.flow[0].json
}

# ALL traffic, not just rejects: in a VPC with no internet route, an *accepted*
# connection to somewhere unexpected is the interesting event.
resource "aws_flow_log" "this" {
  count = var.enable_flow_logs ? 1 : 0

  vpc_id                   = aws_vpc.this.id
  traffic_type             = "ALL"
  iam_role_arn             = aws_iam_role.flow[0].arn
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow[0].arn
  max_aggregation_interval = 60

  tags = merge(var.tags, { Name = "${var.name_prefix}-flow-logs" })
}

resource "aws_subnet" "private" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = local.az_names[count.index]

  # No public IPs: these subnets have no route to the internet.
  map_public_ip_on_launch = false

  tags = merge(var.tags, { Name = "${var.name_prefix}-private-${local.az_names[count.index]}" })
}

# Single private route table. No 0.0.0.0/0 route — there is no IGW/NAT. Gateway
# endpoints (S3, DynamoDB) inject their prefix-list routes here.
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${var.name_prefix}-private-rt" })
}

resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# The VPN / Direct Connect / peering attachment itself is organization-owned.
# When requested, this stack owns only the return routes from its private
# subnets to already-attached next hops. "external" is an explicit assertion
# that another stack (or an existing local/propagated route) owns them.
resource "aws_route" "api_client" {
  for_each = var.api_client_route_management == "module" ? var.api_client_routes : {}

  route_table_id            = aws_route_table.private.id
  destination_cidr_block    = each.value.destination_cidr_block
  transit_gateway_id        = each.value.transit_gateway_id
  gateway_id                = each.value.virtual_private_gateway_id
  vpc_peering_connection_id = each.value.vpc_peering_connection_id
}

# ---------------------------------------------------------------------------
# Security groups
# ---------------------------------------------------------------------------

# Lambda ENIs. Egress-only; ingress is never needed (Lambda is not a target).
resource "aws_security_group" "lambda" {
  #checkov:skip=CKV2_AWS_5:Attached to the Lambda ENIs by the compute module (vpc_config.security_group_ids). checkov cannot see the attachment across a module boundary.
  name_prefix = "${var.name_prefix}-lambda-"
  # EC2 rejects GroupDescription characters beyond ASCII — plain hyphens only.
  description = "STIG Condenser Lambda ENIs - egress to VPC endpoints only."
  vpc_id      = aws_vpc.this.id

  egress {
    description = "HTTPS to interface endpoints plus S3 and DynamoDB gateway-endpoint prefix lists."
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    prefix_list_ids = [
      aws_vpc_endpoint.gateway["s3"].prefix_list_id,
      aws_vpc_endpoint.gateway["dynamodb"].prefix_list_id,
    ]
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-lambda-sg" })

  lifecycle {
    create_before_destroy = true
  }
}

# Runtime service endpoint ENIs. Accept 443 only from the Lambda SG. The
# operator-facing execute-api endpoint has a separate SG below so approved
# client networks do not gain access to KMS, STS, Bedrock, or other endpoints.
resource "aws_security_group" "vpce" {
  name_prefix = "${var.name_prefix}-vpce-"
  # EC2 rejects GroupDescription characters beyond ASCII — plain hyphens only.
  description = "Interface VPC endpoints - 443 from Lambda SG only."
  vpc_id      = aws_vpc.this.id

  ingress {
    description     = "HTTPS from Lambda ENIs."
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.lambda.id]
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-vpce-sg" })

  lifecycle {
    create_before_destroy = true
  }
}

# Private API endpoint ENIs. The SG is deliberately separate from runtime
# endpoints and has no egress rules: security groups are stateful, so response
# traffic for an allowed HTTPS connection is still permitted.
resource "aws_security_group" "execute_api_vpce" {
  name_prefix = "${var.name_prefix}-execute-api-vpce-"
  description = "Private execute-api endpoint - HTTPS from approved client networks."
  vpc_id      = aws_vpc.this.id

  tags = merge(var.tags, { Name = "${var.name_prefix}-execute-api-vpce-sg" })

  lifecycle {
    create_before_destroy = true

    precondition {
      condition = var.api_client_route_management == "module" ? (
        length(var.api_client_routes) > 0 &&
        toset([for route in values(var.api_client_routes) : route.destination_cidr_block]) == var.api_client_cidr_blocks
        ) : (
        length(var.api_client_routes) == 0
      )
      error_message = "module route management requires exactly one api_client_routes destination per approved client CIDR; external route management requires api_client_routes to be empty."
    }
  }
}

resource "aws_vpc_security_group_ingress_rule" "execute_api_client" {
  for_each = var.api_client_cidr_blocks

  security_group_id = aws_security_group.execute_api_vpce.id
  description       = "HTTPS from an approved private API client network."
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = each.value

  tags = merge(var.tags, { Name = "${var.name_prefix}-execute-api-${replace(each.value, "/", "-")}" })
}

# Browser uploads and report downloads use presigned S3 URLs. A separate SG
# keeps that client path isolated from execute-api and from Lambda-only service
# endpoints even though it admits the same approved source CIDRs on HTTPS.
resource "aws_security_group" "s3_client_vpce" {
  name_prefix = "${var.name_prefix}-s3-client-vpce-"
  description = "S3 client interface endpoint - HTTPS from approved client networks."
  vpc_id      = aws_vpc.this.id

  tags = merge(var.tags, { Name = "${var.name_prefix}-s3-client-vpce-sg" })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "s3_client" {
  for_each = var.api_client_cidr_blocks

  security_group_id = aws_security_group.s3_client_vpce.id
  description       = "HTTPS from an approved presigned-URL client network."
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = each.value

  tags = merge(var.tags, { Name = "${var.name_prefix}-s3-client-${replace(each.value, "/", "-")}" })
}

# ---------------------------------------------------------------------------
# VPC endpoints
# ---------------------------------------------------------------------------

# Interface endpoints (PrivateLink) — one per service, billed hourly.
resource "aws_vpc_endpoint" "interface" {
  for_each = toset(local.interface_services)

  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.aws_region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpce.id]
  private_dns_enabled = true

  tags = merge(var.tags, { Name = "${var.name_prefix}-vpce-${each.value}" })
}

# Kept outside the runtime endpoint loop so its SG can admit approved operator
# networks without exposing every other AWS service endpoint to those clients.
resource "aws_vpc_endpoint" "execute_api" {
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.aws_region}.execute-api"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.execute_api_vpce.id]
  private_dns_enabled = true

  tags = merge(var.tags, { Name = "${var.name_prefix}-vpce-execute-api" })
}

# Preserve existing deployments when execute-api moves out of the shared loop.
moved {
  from = aws_vpc_endpoint.interface["execute-api"]
  to   = aws_vpc_endpoint.execute_api
}

# Gateway endpoints (free) — S3 and DynamoDB, wired into the private route table.
resource "aws_vpc_endpoint" "gateway" {
  for_each = toset(["s3", "dynamodb"])

  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.aws_region}.${each.value}"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = merge(var.tags, { Name = "${var.name_prefix}-vpce-${each.value}" })
}

# Paid PrivateLink path for browsers arriving over VPN / Direct Connect.
# GovCloud does not support S3 interface-endpoint private DNS, so browser URLs
# use the endpoint-specific Regional DNS name exported below. Lambda's default
# Regional S3 name continues to use the free gateway endpoint above.
resource "aws_vpc_endpoint" "s3_client" {
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.s3_client_vpce.id]
  private_dns_enabled = false
  ip_address_type     = "ipv4"
  # Limit the endpoint to the two browser operations. Principal "*" is
  # intentional: an endpoint policy is only a maximum and grants nothing by
  # itself, while anonymous browser OPTIONS preflight must still reach S3's CORS
  # evaluator. The API role's signature authorizes the subsequent PUT or GET.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "UploadScanResults"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:PutObject"]
        Resource  = ["${var.s3_client_uploads_bucket_arn}/jobs/*"]
      },
      {
        Sid       = "DownloadGeneratedReports"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:GetObject"]
        Resource  = ["${var.s3_client_artifacts_bucket_arn}/jobs/*"]
      },
    ]
  })

  tags = merge(var.tags, { Name = "${var.name_prefix}-vpce-s3-client" })
}
