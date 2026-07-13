# Terraform + provider version pins for the STIG Condenser GovCloud infra.
# Partition is aws-us-gov; the region comes from var.aws_region (default
# us-gov-west-1). The provider block itself lives per-environment in
# envs/<name>/main.tf so each env can target its own region/credentials.
#
# Spec: docs/superpowers/specs/2026-07-13-govcloud-terraform-iac-spec.md

terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40.0, < 6.0.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4.0, < 3.0.0"
    }
  }
}

# All ARNs in this codebase are built from this partition data source
# (== "aws-us-gov" in GovCloud) — never a hard-coded "aws" literal.
data "aws_partition" "current" {}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}
