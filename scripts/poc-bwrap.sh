#!/bin/sh
# Local run of poc/bwrap-probe on a Docker host (linux-test). Mimics Supervisor:
# seccomp=unconfined, default capabilities. Local hosts usually lack AppArmor,
# so the AppArmor question is only answered on real HAOS.
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
docker build -q -t bwrap-probe:dev "$repo/poc/bwrap-probe" >/dev/null
echo "### seccomp=unconfined (as Supervisor runs apps)"
docker run --rm --security-opt seccomp=unconfined bwrap-probe:dev
echo "### Docker default seccomp (comparison)"
docker run --rm bwrap-probe:dev || true
