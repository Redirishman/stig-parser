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
    description = "HTTPS to interface VPC endpoints and gateway-endpoint prefixes."
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-lambda-sg" })

  lifecycle {
    create_before_destroy = true
  }
}

# Interface-endpoint ENIs. Accept 443 only from the Lambda SG.
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

# Gateway endpoints (free) — S3 and DynamoDB, wired into the private route table.
resource "aws_vpc_endpoint" "gateway" {
  for_each = toset(["s3", "dynamodb"])

  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.aws_region}.${each.value}"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = merge(var.tags, { Name = "${var.name_prefix}-vpce-${each.value}" })
}
