#!/bin/sh
# Smoke test of the app image (linux-test, CI): s6 boots the MCP server, a
# real MCP client drives the tools, then idle expiry and shutdown cleanup.
# Runs the container as Supervisor does (seccomp=unconfined).
#   scripts/smoke.sh [image] [idle-wait-seconds, default 150; 0 = skip]
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
image=${1:-app-code-interpreter:dev}
idle_wait=${2:-150}
name=ci-smoke-$$
tmp=$(mktemp -d)
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$tmp"; }
trap cleanup EXIT
mkdir -p "$tmp/data" "$tmp/share"
printf 'kwh\n1\n2\n3\n' > "$tmp/share/energy.csv"
printf '{"idle_timeout_minutes": 1, "max_sessions": 3, "memory_limit_mb": 1024, "network_allowlist": []}\n' \
  > "$tmp/data/options.json"

docker run -d --name "$name" --security-opt seccomp=unconfined \
  -v "$tmp/data:/data" -v "$tmp/share:/share" \
  -v "$repo/scripts/smoke_client.py:/smoke_client.py:ro" "$image" >/dev/null

i=0
until docker logs "$name" 2>&1 | grep -q "Uvicorn running"; do
  i=$((i + 1))
  if [ "$i" -gt 120 ]; then echo "FAIL | server did not start"; docker logs "$name"; exit 1; fi
  sleep 0.5
done
if docker logs "$name" 2>&1 | grep -q "self-check ok"; then
  echo "PASS | sandbox self-check at startup"
else
  echo "FAIL | sandbox self-check at startup"; docker logs "$name"; exit 1
fi

rc=0
docker exec "$name" /opt/venv/bin/python3 /smoke_client.py "$idle_wait" || rc=1

docker stop -t 20 "$name" >/dev/null
if docker logs "$name" 2>&1 | grep -q "all sessions closed"; then
  echo "PASS | shutdown closes sessions"
else
  echo "FAIL | shutdown closes sessions"; docker logs "$name" 2>&1 | tail -20; rc=1
fi
exit "$rc"
