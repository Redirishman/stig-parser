# Pinned to the same provider range the environments use. Without this a
# standalone `terraform validate` of this module resolves the newest provider
# available, which is not the one that will apply the module — CI would then be
# validating against a different provider than production runs on.

terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40.0, < 6.0.0"
    }
  }
}
