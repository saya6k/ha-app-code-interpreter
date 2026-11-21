#!/bin/sh
# Sandbox entrypoint: (re)start the REPL server whenever it exits, so a
# kernel restart keeps the container and its files but drops the variables.
dir=$(dirname "$0")
while :; do
  python3 -u "$dir/server.py"
  sleep 0.2
done
