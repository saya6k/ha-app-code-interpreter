#!/bin/sh
# Local run of the assembled ha-check app on a Docker host (linux-test),
# mimicking Supervisor: seccomp=unconfined, init: true, /share and /data
# mounted like the real app. No AppArmor here. Exits with the check's code.
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
sh "$repo/scripts/assemble-ha-check.sh" >/dev/null
docker build -q -t ci-check:dev "$repo/poc/ha-check/.build" >/dev/null
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/share" "$tmp/data"
echo '{}' > "$tmp/data/options.json"
docker run --rm --init --security-opt seccomp=unconfined \
  -e SUPERVISOR_TOKEN=local-test-token \
  -v "$tmp/share:/share" -v "$tmp/data:/data" ci-check:dev
