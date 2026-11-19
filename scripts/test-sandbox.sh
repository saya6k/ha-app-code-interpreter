#!/bin/sh
# Run sandbox.py integration tests against the local Docker daemon.
# The test runner (not the sandbox) gets docker.sock; the sandbox gets no mounts.
# Usage: scripts/test-sandbox.sh [sandbox-image]
# Set SANDBOX_TEST_NO_CGROUP_LIMITS=1 on hosts without a memory/cpu cgroup
# controller (the linux-test VM); CI runs with full limits.
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
image=${1:-python:3.13-slim}
docker pull -q python:3.13-slim >/dev/null
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$repo/code-interpreter/rootfs/opt:/src:ro" \
  -e SANDBOX_TEST_IMAGE="$image" \
  -e SANDBOX_TEST_NO_CGROUP_LIMITS="${SANDBOX_TEST_NO_CGROUP_LIMITS:-0}" \
  -e PYTHONDONTWRITEBYTECODE=1 \
  -w /src python:3.13-slim \
  sh -c 'pip install -q --root-user-action=ignore pytest docker==7.1.0 \
    && python -m pytest -q -p no:cacheprovider mcp-server/tests/test_sandbox_docker.py'
