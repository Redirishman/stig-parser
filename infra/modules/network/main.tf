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
  name_prefix = "${var.name_prefix}-lambda-"
  description = "STIG Condenser Lambda ENIs — egress to VPC endpoints only."
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
  description = "Interface VPC endpoints — 443 from Lambda SG only."
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
