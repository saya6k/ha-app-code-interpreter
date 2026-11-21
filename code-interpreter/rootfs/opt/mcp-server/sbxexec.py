"""Apply sandbox process limits, drop to the session uid, exec the command.

    python3 -I -S sbxexec.py '<json spec>' <argv...>

Runs as its own single-threaded process: doing this in a preexec_fn of the
threaded asyncio app is unsafe. Any failure exits 126 before the command
runs (fail-closed).
"""

import json
import os
import resource
import sys


def main() -> None:
    spec = json.loads(sys.argv[1])
    argv = sys.argv[2:]
    uid = spec["uid"]
    # Raising oom_score_adj needs no privilege; do it first anyway.
    with open("/proc/self/oom_score_adj", "w") as f:
        f.write(str(spec["oom_score_adj"]))
    os.nice(spec["nice"])
    for name, value in spec["rlimits"].items():
        resource.setrlimit(getattr(resource, "RLIMIT_" + name), (value, value))
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)
    try:
        os.setuid(0)
    except PermissionError:
        pass
    else:
        raise RuntimeError("privileges were not dropped")
    os.execvp(argv[0], argv)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"sbxexec: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(126)
