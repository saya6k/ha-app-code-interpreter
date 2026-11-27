#!/bin/sh
# Local run of the assembled node-probe app on a Docker host, mimicking
# Supervisor: seccomp=unconfined, init: true. No AppArmor and no Supervisor
# here, so section B is skipped. Exits with the probe's code.
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
sh "$repo/scripts/assemble-node-probe.sh" >/dev/null
docker build -q -t node-probe:dev "$repo/poc/node-probe/.build" >/dev/null
docker run --rm --init --security-opt seccomp=unconfined node-probe:dev
