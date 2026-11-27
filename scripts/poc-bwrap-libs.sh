#!/bin/sh
# Local run of poc/bwrap-libs-probe with docker (on the Mac: socktainer),
# mimicking Supervisor (seccomp=unconfined). Section C (host OOM) stays off
# here: it was written for linux-test, which could not apply container memory
# caps. Under socktainer -m sizes the container's own VM; not re-tested.
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
docker build -q -t bwrap-libs-probe:dev "$repo/poc/bwrap-libs-probe" >/dev/null
docker run --rm --security-opt seccomp=unconfined bwrap-libs-probe:dev
