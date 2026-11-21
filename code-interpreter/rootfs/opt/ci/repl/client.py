"""REPL client: send one cell (stdin) to the server, enforce the timeout (stdlib only).

Prints one JSON object: stdout, stderr, result, error, truncated, kernel_restarted.
On timeout: SIGINT the server; if it does not answer within REPL_GRACE_S,
SIGKILL it and wait for init.sh to start a fresh one (variables are lost).
"""

import argparse
import json
import os
import signal
import socket
import sys
import time

from proto import recv, send

SOCK = os.environ.get("REPL_SOCK", "/tmp/repl.sock")
GRACE_S = float(os.environ.get("REPL_GRACE_S", "5"))
RESTART_WAIT_S = 15


def connect(wait_s: float = 10) -> socket.socket:
    deadline = time.monotonic() + wait_s
    while True:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.connect(SOCK)
            return s
        except OSError:
            s.close()
            if time.monotonic() > deadline:
                raise
            time.sleep(0.05)


def ping() -> int:
    with connect() as s:
        s.settimeout(5)
        send(s, {"op": "ping"})
        return recv(s)["pid"]


def wait_restart(old_pid: int) -> None:
    deadline = time.monotonic() + RESTART_WAIT_S
    while True:
        try:
            if ping() != old_pid:
                return
        except OSError:
            pass
        if time.monotonic() > deadline:
            raise RuntimeError("REPL server did not restart")
        time.sleep(0.1)


def run(req: dict, timeout_s: float) -> dict:
    pid = ping()
    with connect() as s:
        send(s, req)
        try:
            s.settimeout(timeout_s)
            return recv(s)
        except TimeoutError:
            pass
        except ConnectionError:  # server died mid-cell (crash, OOM kill, os._exit)
            wait_restart(pid)
            return {"error": "KernelDied", "kernel_restarted": True}
        os.kill(pid, signal.SIGINT)
        try:
            s.settimeout(GRACE_S)
            resp = recv(s)
            resp["error"] = "TimeoutError"
            return resp
        except (TimeoutError, ConnectionError):
            pass
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    wait_restart(pid)
    return {"error": "TimeoutError", "kernel_restarted": True}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=float, default=60)
    ap.add_argument("--reset", action="store_true")
    args = ap.parse_args()
    req = {"op": "reset"} if args.reset else {"op": "exec", "code": sys.stdin.read()}
    out = {
        "stdout": "",
        "stderr": "",
        "result": None,
        "error": None,
        "truncated": False,
        "kernel_restarted": False,
    }
    out.update(run(req, args.timeout))
    print(json.dumps(out))


if __name__ == "__main__":
    main()
