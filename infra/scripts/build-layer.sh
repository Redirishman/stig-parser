#!/usr/bin/env bash
# Build the Lambda dependency layer (lxml + openpyxl).
#
# These ship compiled C extensions, so the layer must be built against Linux and
# the exact Python the functions run. Building it on macOS or Windows produces a
# zip that imports fine locally and dies at cold start in Lambda with
# "No module named 'lxml.etree'" — hence Docker rather than a bare `pip install`.
#
# boto3 is already in the Lambda runtime and is deliberately NOT vendored here:
# a stale pinned copy would shadow the runtime's and drift from the service APIs.
#
# Usage:  ./build-layer.sh [runtime]        e.g. ./build-layer.sh python3.12
# Output: infra/build/deps-layer.zip  -> point var.dependency_layer_zip at it.

set -euo pipefail

RUNTIME="${1:-python3.12}"
PY_VERSION="${RUNTIME#python}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../.." && pwd)"
BUILD_DIR="${REPO_ROOT}/infra/build"
OUT="${BUILD_DIR}/deps-layer.zip"

# Keep these in lockstep with the floors in pyproject.toml — the security floors
# there (PYSEC advisories) are not optional just because this is a layer.
DEPS=(
  "lxml>=6.1.0,<7.0"
  "openpyxl>=3.1,<4.0"
)

command -v docker >/dev/null 2>&1 || {
  echo "docker is required: the layer must be built on Linux for ${RUNTIME}." >&2
  exit 1
}

rm -rf "${BUILD_DIR}/python" "${OUT}"
mkdir -p "${BUILD_DIR}/python"

# The layer's import root must be exactly `python/` at the zip root — Lambda
# appends that path to sys.path and nothing else.
docker run --rm \
  --entrypoint /bin/sh \
  -v "${BUILD_DIR}:/out" \
  "public.ecr.aws/lambda/python:${PY_VERSION}" \
  -c "pip install --no-cache-dir --only-binary=:all: ${DEPS[*]@Q} -t /out/python"

(cd "${BUILD_DIR}" && zip -qr "${OUT}" python)
rm -rf "${BUILD_DIR}/python"

echo "Built ${OUT} for ${RUNTIME}."
echo "Set dependency_layer_zip = \"\${path.root}/../build/deps-layer.zip\" (or an absolute path)."
