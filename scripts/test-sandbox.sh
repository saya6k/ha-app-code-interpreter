#!/bin/sh
# Sandbox checks against the app image on a Docker host (linux-test, CI).
# Runs the image as Supervisor does (seccomp=unconfined, default caps).
#   scripts/test-sandbox.sh [image]
set -eu
image=${1:-app-code-interpreter:dev}
docker run --rm --security-opt seccomp=unconfined --entrypoint /bin/sh "$image" -c '
set -eu
uid=60000
mkdir -p /tmp/sbx-work && chown "$uid:$uid" /tmp/sbx-work
su_exec() { setpriv --reuid "$uid" --regid "$uid" --clear-groups "$@" 2>/dev/null \
  || python3 -c "import os,sys; os.setgroups([]); os.setgid($uid); os.setuid($uid); os.execvp(sys.argv[1], sys.argv[1:])" "$@"; }
su_exec bwrap --unshare-all --unshare-user --die-with-parent \
  --uid 65534 --gid 65534 --cap-drop ALL --clearenv \
  --setenv PATH /opt/venv/bin:/usr/bin:/bin --setenv HOME /tmp --setenv MPLBACKEND Agg \
  --ro-bind /opt/sandbox-root / --dev /dev --tmpfs /tmp --bind /tmp/sbx-work /sandbox --chdir /sandbox \
  python3 -c "
import numpy, pandas, matplotlib.pyplot as plt, os, socket, subprocess
assert os.path.exists(\"/opt/ci/repl/server.py\"), \"ci code missing\"
assert not os.path.exists(\"/opt/mcp-server\"), \"app rootfs leaked\"
assert [n for _, n in socket.if_nameindex()] == [\"lo\"]
r = subprocess.run([\"python3\", \"-c\", \"import os; os.unshare(os.CLONE_NEWUSER)\"], capture_output=True)
print(\"INFO nested userns:\", \"blocked\" if r.returncode else \"allowed (seccomp filter pending, R4)\")
plt.plot([1, 2]); plt.savefig(\"/sandbox/p.png\")
print(\"PASS sandbox rootfs: imports, ci code, no app rootfs, lo only, /sandbox rw\")
"
ls -l /tmp/sbx-work/p.png >/dev/null && echo "PASS file visible to app"
'
