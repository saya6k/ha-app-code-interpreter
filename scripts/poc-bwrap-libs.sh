#!/bin/sh
# Local run of poc/bwrap-libs-probe on a Docker host (linux-test), mimicking
# Supervisor (seccomp=unconfined). Section C (host OOM) stays off here:
# linux-test cannot apply container memory caps, so it would hit the VM itself.
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
docker build -q -t bwrap-libs-probe:dev "$repo/poc/bwrap-libs-probe" >/dev/null
docker run --rm --security-opt seccomp=unconfined bwrap-libs-probe:dev
