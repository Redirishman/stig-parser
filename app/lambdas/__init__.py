"""AWS Lambda handler shims for the GovCloud deployment (sub-project #2).

These are thin: they translate a Lambda event into a call to the AWS-agnostic
stage entrypoints in :mod:`app.core.stages` and translate the result back. All
AWS wiring (bucket names, table name, region) arrives through the environment,
set by the Terraform ``compute`` module.

Nothing outside this package and the ``*Store`` implementations may import
boto3 — the parsers, processors and exporters stay cloud-free so the CLI and
the Flask app keep working unchanged.
"""
