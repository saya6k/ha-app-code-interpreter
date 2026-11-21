"""Sandbox entrypoint and agent (stdlib only).

    python3 /opt/ci/launch.py <argv...>

The sandbox network namespace has only loopback. When the app bound a proxy
socket into /run/ci (non-empty allowlist), a thread forwards
127.0.0.1:3128 to it, so HTTP(S)_PROXY clients reach the app's CONNECT
proxy. Without the socket nothing listens and every connection fails.

With $CI_AGENT_FD (a SOCK_SEQPACKET socket from the app) this process stays
for the sandbox's lifetime and supervises the REPL in argv:
    {"op": "restart"} + 2 fds  kill every other sandbox process (kill(-1)
                               spares only init and this agent), then start
                               argv again on the new REPL channels
    {"op": "ping"}
Restarting inside the sandbox keeps its tmpfs /sandbox, so files survive.
When the app closes the agent channel, the agent ends the sandbox.
Without $CI_AGENT_FD it just runs argv and returns its exit code.
"""

import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time

PROXY_SOCK = os.environ.get("CI_PROXY_SOCK", "/run/ci/proxy.sock")
PROXY_PORT = int(os.environ.get("CI_PROXY_PORT", "3128"))
REPL_ENV = ("REPL_FD", "REPL_CTL_FD")


def _pump(src: socket.socket, dst: socket.socket) -> None:
    try:
        while data := src.recv(65536):
            dst.sendall(data)
    except OSError:
        pass
    try:
        dst.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def _relay(client: socket.socket) -> None:
    with client:
        try:
            upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            upstream.connect(PROXY_SOCK)
        except OSError:
            return
        with upstream:
            back = threading.Thread(target=_pump, args=(upstream, client), daemon=True)
            back.start()
            _pump(client, upstream)
            back.join()


def _serve(listener: socket.socket) -> None:
    # Must survive transient limits (EMFILE under RLIMIT_NOFILE, no thread
    # under RLIMIT_NPROC): if this loop dies, egress is gone for the session.
    while True:
        try:
            client, _ = listener.accept()
        except OSError:
            time.sleep(0.1)
            continue
        try:
            threading.Thread(target=_relay, args=(client,), daemon=True).start()
        except RuntimeError:
            client.close()


def _start(argv: list[str], fds: list[int]) -> subprocess.Popen:
    """Run argv with the REPL channel fds; keep no copy of them here, so the
    app sees EOF the moment the REPL dies."""
    env = dict(os.environ, **{k: str(fd) for k, fd in zip(REPL_ENV, fds)})
    for fd in fds:
        os.set_inheritable(fd, True)
    try:
        return subprocess.Popen(argv, env=env, close_fds=False, start_new_session=True)
    finally:
        for fd in fds:
            os.close(fd)


def _kill_others(child: subprocess.Popen) -> None:
    """Inside the sandbox's pid namespace, kill(-1) reaches every leftover
    process of the session (only init and this agent are spared). Anywhere
    else it would hit all of the user's processes, so then only the child's
    process group is killed."""
    try:
        if os.environ.get("CI_IN_SANDBOX") == "1":
            os.kill(-1, signal.SIGKILL)
        else:
            os.killpg(child.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _agent(argv: list[str], agent: socket.socket) -> int:
    child = _start(argv, [int(os.environ[k]) for k in REPL_ENV])
    while True:
        try:
            data, fds, _, _ = socket.recv_fds(agent, 4096, 2)
        except OSError:
            data, fds = b"", []
        if not data:  # app closed the channel: the session is over
            _kill_others(child)
            return 0
        try:
            req = json.loads(data)
        except ValueError:
            req = {}
        if req.get("op") == "restart" and len(fds) == 2:
            _kill_others(child)
            child.wait()
            child = _start(argv, fds)
            reply = {"ok": True}
        else:
            for fd in fds:
                os.close(fd)
            reply = {"ok": req.get("op") == "ping"}
        agent.send(json.dumps(reply).encode())


def main(argv: list[str]) -> int:
    if os.path.exists(PROXY_SOCK):
        listener = socket.create_server(("127.0.0.1", PROXY_PORT))
        threading.Thread(target=_serve, args=(listener,), daemon=True).start()
    if "CI_AGENT_FD" in os.environ:
        agent = socket.socket(fileno=int(os.environ["CI_AGENT_FD"]))
        os.set_inheritable(agent.fileno(), False)  # never hand it to the REPL
        return _agent(argv, agent)
    code = subprocess.call(argv, close_fds=False)
    return 128 - code if code < 0 else code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
