#!/bin/sh
# Assemble poc/node-probe with the current app sources (Supervisor builds a
# local app from its own folder only).
#   scripts/assemble-node-probe.sh [dest]   (default: poc/node-probe/.build)
# dest must not exist yet, or must be a previous assembly (it is replaced).
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
dest=${1:-$repo/poc/node-probe/.build}
opt=$repo/code-interpreter/rootfs/opt
if [ -e "$dest" ]; then
  if ! grep -qs '^slug: node_probe$' "$dest/config.yaml" || [ ! -f "$dest/probe.py" ]; then
    echo "refusing to replace $dest: not a previous node-probe assembly" >&2
    exit 1
  fi
  rm -rf "$dest"
fi
mkdir -p "$dest/mcp-server" "$dest/ci/repl/vendor"
cp "$repo"/poc/node-probe/config.yaml "$repo"/poc/node-probe/Dockerfile "$repo"/poc/node-probe/probe.py "$dest/"
cp -R "$repo/poc/node-probe/js" "$dest/js"
cp "$repo/code-interpreter/apparmor.txt" "$dest/"
cp "$opt"/mcp-server/*.py "$dest/mcp-server/"
cp "$opt"/ci/*.py "$dest/ci/"
cp "$opt"/ci/repl/*.py "$opt"/ci/repl/*.mjs "$dest/ci/repl/"
cp "$opt"/ci/repl/vendor/* "$dest/ci/repl/vendor/"
echo "assembled: $dest"
