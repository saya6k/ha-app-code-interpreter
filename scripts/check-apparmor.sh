#!/bin/sh
# Parse-only check of code-interpreter/apparmor.txt with AppArmor 3.x (HAOS ships 3.1.x).
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
docker run --rm -v "$repo/code-interpreter/apparmor.txt:/p.txt:ro" debian:bookworm sh -c \
  'apt-get -qq update >/dev/null && apt-get -qq install -y apparmor >/dev/null 2>&1 && apparmor_parser --version | head -1 && apparmor_parser -Q -K /p.txt && echo "PASS apparmor.txt parses"'
