mock_provider "aws" {
  mock_resource "aws_lambda_layer_version" {
    defaults = {
      arn = "arn:aws-us-gov:lambda:us-gov-west-1:aws:layer:test:1"
    }
  }
}

mock_provider "archive" {
  mock_data "archive_file" {
    defaults = {
      output_path         = "/tmp/source.zip"
      output_base64sha256 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    }
  }
}

variables {
  name_prefix          = "stig-condenser-test"
  backend_source_dir   = "."
  dependency_layer_zip = "tests/dependency-layer.fixture"

  uploads_bucket          = "test-uploads"
  artifacts_bucket        = "test-artifacts"
  s3_presign_endpoint_url = "https://bucket.vpce-test.s3.us-gov-west-1.vpce.amazonaws.com"
  job_table_name          = "test-jobs"
  state_machine_arn       = "arn:aws-us-gov:states:us-gov-west-1:aws:stateMachine:test"
  role_arns = {
    api      = "arn:aws-us-gov:iam::aws:role/test-api"
    parser   = "arn:aws-us-gov:iam::aws:role/test-parser"
    enricher = "arn:aws-us-gov:iam::aws:role/test-enricher"
    exporter = "arn:aws-us-gov:iam::aws:role/test-exporter"
    marker   = "arn:aws-us-gov:iam::aws:role/test-marker"
  }

  subnet_ids        = ["subnet-test-a", "subnet-test-b"]
  security_group_id = "sg-test"
  kms_key_arn       = "arn:aws-us-gov:kms:us-gov-west-1:aws:key/test"
  bedrock_region    = "us-gov-west-1"
}

run "private_presign_endpoint_is_api_only" {
  command = apply

  assert {
    condition = aws_lambda_function.this["api"].environment[0].variables["S3_PRESIGN_ENDPOINT_URL"] == (
      "https://bucket.vpce-test.s3.us-gov-west-1.vpce.amazonaws.com"
    )
    error_message = "The API Lambda must receive the Regional S3 PrivateLink signing endpoint."
  }

  assert {
    condition = alltrue([
      for name, function in aws_lambda_function.this :
      !contains(keys(function.environment[0].variables), "S3_PRESIGN_ENDPOINT_URL")
      if name != "api"
    ])
    error_message = "Pipeline-stage Lambdas must not receive the browser-facing S3 signing endpoint."
  }
}
