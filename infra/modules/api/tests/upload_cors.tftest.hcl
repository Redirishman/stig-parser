mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = {
      partition = "aws-us-gov"
    }
  }

  mock_data "aws_region" {
    defaults = {
      name = "us-gov-west-1"
    }
  }

  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }

  mock_resource "aws_api_gateway_stage" {
    defaults = {
      invoke_url = "https://api-test.execute-api.us-gov-west-1.amazonaws.com/v1"
    }
  }

  mock_resource "aws_api_gateway_rest_api" {
    defaults = {
      execution_arn = "arn:aws-us-gov:execute-api:us-gov-west-1:aws:api-test"
    }
  }

  mock_resource "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws-us-gov:logs:us-gov-west-1:aws:log-group:test"
    }
  }
}

variables {
  name_prefix             = "stig-condenser-test"
  execute_api_endpoint_id = "vpce-api-test"
  api_function_arn        = "arn:aws-us-gov:lambda:us-gov-west-1:test:function:api-test"
  api_function_name       = "api-test"
  uploads_bucket_name     = "test-uploads"
  kms_key_arn             = "arn:aws-us-gov:kms:us-gov-west-1:test:key/test"
}

run "managed_spa_gets_narrow_upload_cors" {
  command = apply

  assert {
    condition     = aws_s3_bucket_cors_configuration.uploads.bucket == "test-uploads"
    error_message = "CORS must be attached to the uploads bucket."
  }

  assert {
    condition     = length(aws_s3_bucket_cors_configuration.uploads.cors_rule) == 1
    error_message = "The uploads bucket must have exactly one CORS rule."
  }

  assert {
    condition     = one(aws_s3_bucket_cors_configuration.uploads.cors_rule).allowed_methods == toset(["PUT"])
    error_message = "Upload CORS must allow only PUT."
  }

  assert {
    condition     = one(aws_s3_bucket_cors_configuration.uploads.cors_rule).allowed_headers == toset(["Content-Type"])
    error_message = "Upload CORS must allow only the browser-synthesized Content-Type header."
  }

  assert {
    condition     = one(aws_s3_bucket_cors_configuration.uploads.cors_rule).allowed_origins == toset(["https://api-test.execute-api.us-gov-west-1.amazonaws.com"])
    error_message = "The managed SPA origin must be exact and must omit the API stage path."
  }

  assert {
    condition     = try(length(one(aws_s3_bucket_cors_configuration.uploads.cors_rule).expose_headers), 0) == 0
    error_message = "Upload CORS must not expose unused response headers."
  }

  assert {
    condition     = one(aws_s3_bucket_cors_configuration.uploads.cors_rule).max_age_seconds == 300
    error_message = "Upload preflight responses must use the bounded 300-second cache period."
  }
}

run "unions_an_additional_exact_origin" {
  command = apply

  variables {
    additional_upload_cors_origins = ["https://stig.internal.example"]
  }

  assert {
    condition = one(aws_s3_bucket_cors_configuration.uploads.cors_rule).allowed_origins == toset([
      "https://api-test.execute-api.us-gov-west-1.amazonaws.com",
      "https://stig.internal.example",
    ])
    error_message = "An explicitly approved exact origin must be unioned with the managed SPA origin."
  }
}

run "external_spa_uses_only_its_explicit_origin" {
  command = apply

  variables {
    spa_serving_mode               = "none"
    additional_upload_cors_origins = ["https://stig.internal.example"]
  }

  assert {
    condition     = one(aws_s3_bucket_cors_configuration.uploads.cors_rule).allowed_origins == toset(["https://stig.internal.example"])
    error_message = "An externally served same-origin facade must not inherit the API Gateway hostname as an upload origin."
  }
}

run "rejects_wildcard_origin" {
  command = plan

  variables {
    additional_upload_cors_origins = ["https://*.internal.example"]
  }

  expect_failures = [var.additional_upload_cors_origins]
}

run "rejects_origin_with_path" {
  command = plan

  variables {
    additional_upload_cors_origins = ["https://stig.internal.example/app"]
  }

  expect_failures = [var.additional_upload_cors_origins]
}

run "rejects_non_https_origin" {
  command = plan

  variables {
    additional_upload_cors_origins = ["http://stig.internal.example"]
  }

  expect_failures = [var.additional_upload_cors_origins]
}

run "external_spa_requires_an_explicit_origin" {
  command = plan

  variables {
    spa_serving_mode               = "none"
    additional_upload_cors_origins = []
  }

  expect_failures = [aws_s3_bucket_cors_configuration.uploads]
}
