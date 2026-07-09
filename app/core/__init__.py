"""Core pipeline, serialization, and storage/job abstractions.

This package is AWS-agnostic except for the concrete ``S3ArtifactStore`` and
``DynamoJobStore`` implementations, which are the only modules permitted to
import boto3.
"""
