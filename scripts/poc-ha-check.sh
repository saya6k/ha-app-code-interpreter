#!/bin/sh
# Local run of the assembled ha-check app on a Docker host (linux-test),
# mimicking Supervisor (seccomp=unconfined, init: true). No AppArmor here.
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
sh "$repo/scripts/assemble-ha-check.sh" >/dev/null
docker build -q -t ci-check:dev "$repo/poc/ha-check/.build" >/dev/null
docker run --rm --init --security-opt seccomp=unconfined ci-check:dev
