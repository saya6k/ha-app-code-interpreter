#!/bin/sh
# Assemble poc/ha-check with the current app sources (Supervisor builds a
# local app from its own folder only).
#   scripts/assemble-ha-check.sh [dest]   (default: poc/ha-check/.build)
# dest must not exist yet, or must be a previous assembly (it is replaced).
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
dest=${1:-$repo/poc/ha-check/.build}
opt=$repo/code-interpreter/rootfs/opt
if [ -e "$dest" ]; then
  if ! grep -qs '^slug: ci_check$' "$dest/config.yaml" || [ ! -f "$dest/check.py" ]; then
    echo "refusing to replace $dest: not a previous ha-check assembly" >&2
    exit 1
  fi
  rm -rf "$dest"
fi
mkdir -p "$dest/mcp-server" "$dest/ci/repl"
cp "$repo"/poc/ha-check/config.yaml "$repo"/poc/ha-check/Dockerfile "$repo"/poc/ha-check/check.py "$dest/"
cp "$repo/code-interpreter/apparmor.txt" "$dest/"
cp "$opt"/mcp-server/*.py "$dest/mcp-server/"
cp "$opt/ci/launch.py" "$dest/ci/"
cp "$opt"/ci/repl/*.py "$dest/ci/repl/"
echo "assembled: $dest"
