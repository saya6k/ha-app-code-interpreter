#!/bin/sh
# Sandbox integration tests inside the app image (local docker, CI). Runs the
# container as Supervisor does (seccomp=unconfined, default capabilities;
# extra docker run options from $DOCKER_RUN_EXTRA)
# with the source tree mounted read-only. --init stands in for s6 as PID 1,
# which reaps the inner bwrap after its parent is killed.
#   scripts/test-sandbox.sh [image] [pytest args...]
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
image=${1:-app-code-interpreter:dev}
[ $# -gt 0 ] && shift
# shellcheck disable=SC2086 # DOCKER_RUN_EXTRA is a list of options
docker run --rm --init --security-opt seccomp=unconfined ${DOCKER_RUN_EXTRA:-} \
  -e PYTHONDONTWRITEBYTECODE=1 \
  -v "$repo/code-interpreter/rootfs/opt:/src:ro" \
  --entrypoint /bin/sh "$image" -c '
set -eu
/opt/venv/bin/pip install -q --disable-pip-version-check pytest >/dev/null
cd /src && exec /opt/venv/bin/python3 -m pytest -q -p no:cacheprovider mcp-server/tests/test_sandbox_bwrap.py "$@"
' sh "$@"
