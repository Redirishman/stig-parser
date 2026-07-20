#!/usr/bin/env bash
# Bootstrap the Terraform state backend for this project — run ONCE per account.
#
# Terraform cannot create its own backend bucket, so this creates it out-of-band:
#   - S3 bucket, versioned (protects state history), SSE-S3 encrypted,
#     all public access blocked.
#   - State locking is S3-native (`use_lockfile = true` in the env's backend.tf,
#     Terraform >= 1.10) — deliberately no DynamoDB lock table.
#
# Safe to re-run: every step is idempotent.
# Contains no account-specific values (public repo) — bucket name + region only.
#
# Usage:  AWS_PROFILE=<profile> ./bootstrap-state-backend.sh [bucket] [region]
set -euo pipefail

BUCKET="${1:-stig-parser-terraform-state}"
REGION="${2:-us-gov-west-1}"

if aws s3api head-bucket --bucket "${BUCKET}" 2>/dev/null; then
  echo "==> bucket s3://${BUCKET} already exists — reapplying settings only"
else
  echo "==> creating s3://${BUCKET} in ${REGION}"
  aws s3api create-bucket \
    --bucket "${BUCKET}" \
    --region "${REGION}" \
    --create-bucket-configuration "LocationConstraint=${REGION}"
fi

echo "==> enabling versioning"
aws s3api put-bucket-versioning --bucket "${BUCKET}" --region "${REGION}" \
  --versioning-configuration Status=Enabled

echo "==> enabling default encryption (SSE-S3)"
aws s3api put-bucket-encryption --bucket "${BUCKET}" --region "${REGION}" \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"},"BucketKeyEnabled":true}]}'

echo "==> blocking all public access"
aws s3api put-public-access-block --bucket "${BUCKET}" --region "${REGION}" \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

echo "Done. Point envs/<env>/backend.tf at bucket ${BUCKET} with use_lockfile = true."
