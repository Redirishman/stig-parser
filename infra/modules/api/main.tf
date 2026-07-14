# Private REST API Gateway. Spec §4.6.
#
# There is no public endpoint, no API key and no authorizer here: auth is
# enforced upstream (VPN + the org's identity layer), and the deployment is
# reachable only from inside the VPC. The single control that enforces that is
# the resource policy below — a PRIVATE endpoint type alone does NOT restrict
# which VPC endpoint may reach it.

data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  partition         = data.aws_partition.current.partition
  region            = data.aws_region.current.name
  serve_spa_from_s3 = var.spa_serving_mode == "apigw_s3_proxy"
}

# ---------------------------------------------------------------------------
# The API
# ---------------------------------------------------------------------------

resource "aws_api_gateway_rest_api" "this" {
  #checkov:skip=CKV_AWS_237:create_before_destroy belongs on the deployment, which is the resource that is actually replaced on every routing change. Recreating the REST API itself would change its id and break the VPC endpoint association.
  name        = var.name_prefix
  description = "STIG Condenser private API."

  endpoint_configuration {
    types            = ["PRIVATE"]
    vpc_endpoint_ids = [var.execute_api_endpoint_id]
  }

  # S3-proxied SPA assets (fonts, the woff2 files, favicon) and the generated
  # xlsx are binary; without this API Gateway would corrupt them into text.
  binary_media_types = local.serve_spa_from_s3 ? ["*/*"] : []

  tags = merge(var.tags, { Name = var.name_prefix })
}

# Deny anything that did not arrive through our execute-api VPC endpoint. The
# explicit Deny matters: an Allow-only policy still leaves the API reachable
# from other VPC endpoints that resolve the same private DNS name.
data "aws_iam_policy_document" "resource_policy" {
  statement {
    sid       = "AllowInvokeFromOurVpceOnly"
    effect    = "Allow"
    actions   = ["execute-api:Invoke"]
    resources = ["execute-api:/*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceVpce"
      values   = [var.execute_api_endpoint_id]
    }
  }

  statement {
    sid       = "DenyInvokeFromAnywhereElse"
    effect    = "Deny"
    actions   = ["execute-api:Invoke"]
    resources = ["execute-api:/*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEquals"
      variable = "aws:SourceVpce"
      values   = [var.execute_api_endpoint_id]
    }
  }
}

resource "aws_api_gateway_rest_api_policy" "this" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  policy      = data.aws_iam_policy_document.resource_policy.json
}

# ---------------------------------------------------------------------------
# Routes -> API Lambda (proxy integration)
# ---------------------------------------------------------------------------

resource "aws_api_gateway_resource" "uploads" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  parent_id   = aws_api_gateway_rest_api.this.root_resource_id
  path_part   = "uploads"
}

resource "aws_api_gateway_resource" "jobs" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  parent_id   = aws_api_gateway_rest_api.this.root_resource_id
  path_part   = "jobs"
}

resource "aws_api_gateway_resource" "job" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  parent_id   = aws_api_gateway_resource.jobs.id
  path_part   = "{job_id}"
}

resource "aws_api_gateway_resource" "job_result" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  parent_id   = aws_api_gateway_resource.job.id
  path_part   = "result"
}

locals {
  # The api handler dispatches on (httpMethod, resource), so these keys must stay
  # in step with app/lambdas/api.py.
  routes = {
    post_uploads = { resource_id = aws_api_gateway_resource.uploads.id, method = "POST" }
    post_jobs    = { resource_id = aws_api_gateway_resource.jobs.id, method = "POST" }
    get_job      = { resource_id = aws_api_gateway_resource.job.id, method = "GET" }
    get_result   = { resource_id = aws_api_gateway_resource.job_result.id, method = "GET" }
  }
}

resource "aws_api_gateway_method" "this" {
  #checkov:skip=CKV_AWS_59:There is no "open access" here. The endpoint is PRIVATE and the resource policy above DENIES every request that did not arrive through our execute-api VPC endpoint. Authentication happens upstream of the private endpoint (VPN + the org's identity layer, D3); an API Gateway authorizer would be a second, weaker copy of a decision already made.
  #checkov:skip=CKV2_AWS_53:Request bodies are validated in the handler (app/lambdas/api.py enforces the shared upload allow-list). A JSON-schema validator at the gateway would duplicate that and drift from it.
  for_each = local.routes

  rest_api_id = aws_api_gateway_rest_api.this.id
  resource_id = each.value.resource_id
  http_method = each.value.method

  authorization = "NONE"
}

resource "aws_api_gateway_integration" "this" {
  for_each = local.routes

  rest_api_id = aws_api_gateway_rest_api.this.id
  resource_id = each.value.resource_id
  http_method = aws_api_gateway_method.this[each.key].http_method

  type                    = "AWS_PROXY"
  integration_http_method = "POST" # always POST for Lambda proxy, regardless of the route's method
  uri                     = "arn:${local.partition}:apigateway:${local.region}:lambda:path/2015-03-31/functions/${var.api_function_arn}/invocations"
}

resource "aws_lambda_permission" "api" {
  statement_id  = "AllowInvokeFromApiGateway"
  action        = "lambda:InvokeFunction"
  function_name = var.api_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.this.execution_arn}/*/*"
}

# ---------------------------------------------------------------------------
# SPA (D6) — apigw_s3_proxy mode
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "spa" {
  #checkov:skip=CKV_AWS_18:Access logging belongs on the CUI buckets. This one holds the public-by-nature SPA bundle (JS/CSS/fonts) — every operator fetches all of it on every page load, so an access log records nothing worth keeping.
  #checkov:skip=CKV_AWS_144:GovCloud stays in-region; the bundle is rebuilt by CI anyway.
  #checkov:skip=CKV2_AWS_62:Nothing consumes S3 events on the SPA bucket.
  #checkov:skip=CKV2_AWS_61:The SPA bundle is not time-expiring content — it is replaced wholesale on each deploy, and versioning bounds the history.
  count = local.serve_spa_from_s3 ? 1 : 0

  bucket = "${var.name_prefix}-spa"
  tags   = merge(var.tags, { Name = "${var.name_prefix}-spa" })
}

resource "aws_s3_bucket_public_access_block" "spa" {
  count = local.serve_spa_from_s3 ? 1 : 0

  bucket                  = aws_s3_bucket.spa[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "spa" {
  count = local.serve_spa_from_s3 ? 1 : 0

  bucket = aws_s3_bucket.spa[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "spa" {
  count = local.serve_spa_from_s3 ? 1 : 0

  bucket = aws_s3_bucket.spa[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

# API Gateway reads the bucket under this role — the browser never talks to S3
# for SPA assets, so the bucket stays fully private.
data "aws_iam_policy_document" "spa_assume" {
  count = local.serve_spa_from_s3 ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["apigateway.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "spa_read" {
  count = local.serve_spa_from_s3 ? 1 : 0

  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.spa[0].arn}/*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [var.kms_key_arn]
  }
}

resource "aws_iam_role" "spa" {
  count = local.serve_spa_from_s3 ? 1 : 0

  name               = "${var.name_prefix}-spa-read"
  assume_role_policy = data.aws_iam_policy_document.spa_assume[0].json
  tags               = var.tags
}

resource "aws_iam_role_policy" "spa" {
  count = local.serve_spa_from_s3 ? 1 : 0

  name   = "${var.name_prefix}-spa-read"
  role   = aws_iam_role.spa[0].id
  policy = data.aws_iam_policy_document.spa_read[0].json
}

resource "aws_api_gateway_resource" "spa_proxy" {
  count = local.serve_spa_from_s3 ? 1 : 0

  rest_api_id = aws_api_gateway_rest_api.this.id
  parent_id   = aws_api_gateway_rest_api.this.root_resource_id
  path_part   = "{proxy+}"
}

resource "aws_api_gateway_method" "spa_proxy" {
  #checkov:skip=CKV_AWS_59:Serves the static SPA bundle (JS/CSS/fonts) from a private bucket. The API is PRIVATE and its resource policy denies any request not arriving through our VPC endpoint; auth is upstream (D3).
  #checkov:skip=CKV2_AWS_53:A GET for a static asset by path has no request body to validate.
  count = local.serve_spa_from_s3 ? 1 : 0

  rest_api_id   = aws_api_gateway_rest_api.this.id
  resource_id   = aws_api_gateway_resource.spa_proxy[0].id
  http_method   = "GET"
  authorization = "NONE"

  request_parameters = {
    "method.request.path.proxy" = true
  }
}

resource "aws_api_gateway_integration" "spa_proxy" {
  count = local.serve_spa_from_s3 ? 1 : 0

  rest_api_id = aws_api_gateway_rest_api.this.id
  resource_id = aws_api_gateway_resource.spa_proxy[0].id
  http_method = aws_api_gateway_method.spa_proxy[0].http_method

  type                    = "AWS"
  integration_http_method = "GET"
  uri                     = "arn:${local.partition}:apigateway:${local.region}:s3:path/${aws_s3_bucket.spa[0].bucket}/{proxy}"
  credentials             = aws_iam_role.spa[0].arn

  request_parameters = {
    "integration.request.path.proxy" = "method.request.path.proxy"
  }
}

resource "aws_api_gateway_method_response" "spa_proxy" {
  count = local.serve_spa_from_s3 ? 1 : 0

  rest_api_id = aws_api_gateway_rest_api.this.id
  resource_id = aws_api_gateway_resource.spa_proxy[0].id
  http_method = aws_api_gateway_method.spa_proxy[0].http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Content-Type" = true
  }
}

resource "aws_api_gateway_integration_response" "spa_proxy" {
  count = local.serve_spa_from_s3 ? 1 : 0

  rest_api_id = aws_api_gateway_rest_api.this.id
  resource_id = aws_api_gateway_resource.spa_proxy[0].id
  http_method = aws_api_gateway_method.spa_proxy[0].http_method
  status_code = aws_api_gateway_method_response.spa_proxy[0].status_code

  response_parameters = {
    "method.response.header.Content-Type" = "integration.response.header.Content-Type"
  }

  depends_on = [aws_api_gateway_integration.spa_proxy]
}

# ---------------------------------------------------------------------------
# Deployment + stage
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "access" {
  name              = "/aws/apigateway/${var.name_prefix}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn

  tags = merge(var.tags, { Name = "${var.name_prefix}-api-access" })
}

resource "aws_api_gateway_deployment" "this" {
  rest_api_id = aws_api_gateway_rest_api.this.id

  # Redeploy whenever the routing surface changes. Without this the API keeps
  # serving the previous definition after an apply that looked successful.
  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_rest_api.this.body,
      aws_api_gateway_rest_api_policy.this.policy,
      [for k, m in aws_api_gateway_method.this : m.id],
      [for k, i in aws_api_gateway_integration.this : i.id],
      local.serve_spa_from_s3 ? aws_api_gateway_integration.spa_proxy[0].id : "",
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    aws_api_gateway_integration.this,
    aws_api_gateway_integration.spa_proxy,
  ]
}

resource "aws_api_gateway_stage" "this" {
  #checkov:skip=CKV2_AWS_51:Client-certificate auth is for the gateway proving its identity to a BACKEND. The backend here is Lambda, invoked over the AWS API with SigV4 — there is no origin to present a certificate to.
  #checkov:skip=CKV_AWS_120:Response caching is off deliberately. Job status is polled and must be fresh, and caching would put CUI in a gateway-managed cache.
  #checkov:skip=CKV_AWS_73:X-Ray is off by design — see the compute module.
  #checkov:skip=CKV_AWS_237:create_before_destroy is set on the deployment, which is the resource that actually gets replaced.
  rest_api_id   = aws_api_gateway_rest_api.this.id
  deployment_id = aws_api_gateway_deployment.this.id
  stage_name    = var.stage_name

  xray_tracing_enabled = false

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.access.arn
    # No request body, no query strings: this API carries CUI filenames, and an
    # access log is not an appropriate place for them.
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      resourcePath   = "$context.resourcePath"
      status         = "$context.status"
      responseLength = "$context.responseLength"
      integrationErr = "$context.integration.error"
    })
  }

  tags = merge(var.tags, { Name = var.name_prefix })
}

resource "aws_api_gateway_method_settings" "this" {
  #checkov:skip=CKV_AWS_225:Caching is off deliberately — job status must be fresh, and a gateway cache would hold CUI.
  rest_api_id = aws_api_gateway_rest_api.this.id
  stage_name  = aws_api_gateway_stage.this.stage_name
  method_path = "*/*"

  settings {
    throttling_rate_limit  = var.throttling_rate_limit
    throttling_burst_limit = var.throttling_burst_limit
    logging_level          = "ERROR"
    # Request/response bodies would land CUI in CloudWatch.
    data_trace_enabled = false
    metrics_enabled    = true
  }
}
