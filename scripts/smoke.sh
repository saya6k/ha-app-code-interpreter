#!/bin/sh
# Smoke test of the app image (linux-test, CI): s6 boots the MCP server and a
# real MCP client drives the tools — default options first (incl. idle expiry
# and shutdown cleanup), then with a network allowlist.
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
rc=0

phase() { # options-json client-args...
  docker rm -f "$name" >/dev/null 2>&1 || true
  rm -rf "$tmp/data" "$tmp/share"
  mkdir -p "$tmp/data" "$tmp/share"
  printf 'kwh\n1\n2\n3\n' > "$tmp/share/energy.csv"
  printf '%s\n' "$1" > "$tmp/data/options.json"
  shift
  docker run -d --name "$name" --security-opt seccomp=unconfined \
    -v "$tmp/data:/data" -v "$tmp/share:/share" \
    -v "$repo/scripts/smoke_client.py:/smoke_client.py:ro" "$image" >/dev/null
  i=0
  until docker logs "$name" 2>&1 | grep -q "Uvicorn running"; do
    i=$((i + 1))
    if [ "$i" -gt 120 ]; then echo "FAIL | server did not start"; docker logs "$name"; rc=1; return; fi
    sleep 0.5
  done
  if docker logs "$name" 2>&1 | grep -q "self-check ok"; then
    echo "PASS | sandbox self-check at startup"
  else
    echo "FAIL | sandbox self-check at startup"; docker logs "$name"; rc=1; return
  fi
  docker exec "$name" /opt/venv/bin/python3 /smoke_client.py "$@" || rc=1
  docker stop -t 20 "$name" >/dev/null
  if docker logs "$name" 2>&1 | grep -q "all sessions closed"; then
    echo "PASS | shutdown closes sessions"
  else
    echo "FAIL | shutdown closes sessions"; docker logs "$name" 2>&1 | tail -20; rc=1
  fi
}

echo "## default options"
phase '{"idle_timeout_minutes": 1, "max_sessions": 3, "memory_limit_mb": 1024, "network_allowlist": []}' "$idle_wait"
echo "## network_allowlist: pypi.org, *.pythonhosted.org"
phase '{"idle_timeout_minutes": 20, "network_allowlist": ["pypi.org", "*.pythonhosted.org"]}' 0 allowlist
exit "$rc"
