#!/bin/sh
# Smoke test of the app image (linux-test, CI): s6 boots the MCP server and a
# real MCP client drives the tools. Phases: default options (incl. idle
# expiry and shutdown cleanup), network allowlist, and lifecycle (SIGKILL +
# restart leaves nothing behind; a normal stop closes every session).
# Runs the container as Supervisor does (seccomp=unconfined). Extra docker run
# options (e.g. an AppArmor profile in CI) come from $DOCKER_RUN_EXTRA.
#   scripts/smoke.sh [image] [idle-wait-seconds, default 150; 0 = skip]
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
image=${1:-app-code-interpreter:dev}
idle_wait=${2:-150}
name=ci-smoke-$$
tmp=$(mktemp -d)
# The container writes /data as root; the caller may not be able to remove it.
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$tmp" 2>/dev/null || true; }
trap cleanup EXIT
rc=0

fail() { echo "FAIL | $1"; rc=1; }

wait_ready() {
  i=0
  until [ "$(docker logs "$name" 2>&1 | grep -c "Uvicorn running")" -ge "$1" ]; do
    i=$((i + 1))
    if [ "$i" -gt 120 ]; then fail "server did not start"; docker logs "$name" 2>&1 | tail -20; return 1; fi
    sleep 0.5
  done
  if [ "$(docker logs "$name" 2>&1 | grep -c "self-check ok")" -ge "$1" ]; then
    echo "PASS | sandbox self-check at startup"
  else
    fail "sandbox self-check at startup"; docker logs "$name" 2>&1 | tail -20; return 1
  fi
  i=0
  until docker logs "$name" 2>&1 | grep -q "skipping discovery announce"; do
    i=$((i + 1))
    if [ "$i" -gt 20 ]; then fail "discovery oneshot ran (no Supervisor -> skip)"; return 1; fi
    sleep 0.5
  done
  echo "PASS | discovery oneshot ran (no Supervisor -> skip)"
}

phase_no=0
start_app() { # options-json
  docker rm -f "$name" >/dev/null 2>&1 || true
  phase_no=$((phase_no + 1))
  dir="$tmp/phase$phase_no"  # fresh per phase: never reuse root-owned files
  mkdir -p "$dir/data" "$dir/share"
  printf 'kwh\n1\n2\n3\n' > "$dir/share/energy.csv"
  printf '%s\n' "$1" > "$dir/data/options.json"
  # shellcheck disable=SC2086 # DOCKER_RUN_EXTRA is a list of options
  docker run -d --name "$name" --security-opt seccomp=unconfined ${DOCKER_RUN_EXTRA:-} \
    -v "$dir/data:/data" -v "$dir/share:/share" \
    -v "$repo/scripts/smoke_client.py:/smoke_client.py:ro" "$image" >/dev/null
  wait_ready 1
}

client() { docker exec "$name" /opt/venv/bin/python3 /smoke_client.py "$@" || rc=1; }

stop_app() {
  docker stop -t 20 "$name" >/dev/null
  if docker logs "$name" 2>&1 | grep -q "all sessions closed"; then
    echo "PASS | shutdown closes sessions"
  else
    fail "shutdown closes sessions"; docker logs "$name" 2>&1 | tail -20
  fi
}

echo "## default options"
if start_app '{"idle_timeout_minutes": 1, "max_sessions": 3, "memory_limit_mb": 2048, "network_allowlist": []}'; then
  client "$idle_wait"
  stop_app
fi

echo "## network_allowlist: pypi.org, *.pythonhosted.org"
if start_app '{"idle_timeout_minutes": 20, "network_allowlist": ["pypi.org", "*.pythonhosted.org"]}'; then
  client 0 allowlist
  stop_app
fi

echo "## lifecycle"
if start_app '{"idle_timeout_minutes": 20, "max_sessions": 3}'; then
  client 0 open2
  docker kill -s KILL "$name" >/dev/null
  docker start "$name" >/dev/null
  if wait_ready 2; then
    client 0 after_kill
    client 0 open2
    stop_app
    n=$(cat "$dir"/data/audit/audit-*.jsonl | grep '"session.destroy"' | grep -c '"reason": "shutdown"' || true)
    if [ "$n" -ge 2 ]; then echo "PASS | normal stop audits session.destroy (shutdown) x$n"; else fail "shutdown destroy audit ($n)"; fi
  fi
fi
exit "$rc"
