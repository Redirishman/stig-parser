# tests/test_core_import.py
"""Smoke test: the core package and its AWS deps are importable."""


def test_core_package_imports():
    import app.core  # noqa: F401


def test_boto3_available():
    import boto3  # noqa: F401


def test_moto_available():
    import moto  # noqa: F401
