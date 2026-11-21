"""launch.py — real local processes, no bwrap."""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import pytest

LAUNCH = Path(__file__).resolve().parents[1] / "launch.py"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def tmp():
    d = Path(tempfile.mkdtemp(prefix="launch-", dir="/tmp"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


def echo_server(path: Path) -> socket.socket:
    """Unix-socket stand-in for the app's proxy: echoes until the peer half-closes."""
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(str(path))
    srv.listen()

    def handle(c):
        with c:
            while data := c.recv(65536):
                c.sendall(data.upper())

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return srv


def launch(tmp: Path, port: int, code: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, CI_PROXY_SOCK=str(tmp / "proxy.sock"), CI_PROXY_PORT=str(port))
    return subprocess.run(
        [sys.executable, str(LAUNCH), sys.executable, "-c", code],
        env=env, capture_output=True, text=True, timeout=30,
    )


CLIENT = """
import socket, sys
s = socket.create_connection(("127.0.0.1", {port}), timeout=5)
s.sendall(b"hello " * 20000)
s.shutdown(socket.SHUT_WR)
buf = b""
while chunk := s.recv(65536):
    buf += chunk
print(len(buf), buf[:6].decode())
"""


def test_forwards_loopback_to_proxy_socket_both_ways(tmp):
    srv = echo_server(tmp / "proxy.sock")
    port = free_port()
    try:
        p = launch(tmp, port, CLIENT.format(port=port))
    finally:
        srv.close()
    assert p.returncode == 0, p.stderr
    assert p.stdout.split() == ["120000", "HELLO"]


def test_no_forwarder_without_proxy_socket(tmp):
    port = free_port()
    p = launch(tmp, port, CLIENT.format(port=port))
    assert p.returncode != 0
    assert "ConnectionRefusedError" in p.stderr


def test_child_exit_code_is_passed_through(tmp):
    assert launch(tmp, free_port(), "import sys; sys.exit(7)").returncode == 7


def test_child_killed_by_signal_maps_to_128_plus_signal(tmp):
    p = launch(tmp, free_port(), "import os, signal; os.kill(os.getpid(), signal.SIGKILL)")
    assert p.returncode == 128 + 9


def test_forwarder_survives_running_out_of_fds(tmp):
    """EMFILE in accept() must not end the forwarder for the session."""
    srv = echo_server(tmp / "proxy.sock")
    port = free_port()
    code = f"""
import socket, time
held = []
for _ in range(40):  # each relay costs launch.py 2 fds; its NOFILE is 24
    try:
        held.append(socket.create_connection(("127.0.0.1", {port}), timeout=1))
    except OSError:
        break
time.sleep(0.5)
for s in held:
    s.close()
time.sleep(0.5)
s = socket.create_connection(("127.0.0.1", {port}), timeout=5)
s.sendall(b"ok"); s.shutdown(socket.SHUT_WR)
print(s.recv(10).decode())
"""
    env = dict(os.environ, CI_PROXY_SOCK=str(tmp / "proxy.sock"), CI_PROXY_PORT=str(port))
    import resource

    def limit():
        resource.setrlimit(resource.RLIMIT_NOFILE, (24, 24))

    try:
        p = subprocess.run([sys.executable, str(LAUNCH), sys.executable, "-c", code],
                           env=env, capture_output=True, text=True, timeout=30, preexec_fn=limit)
    finally:
        srv.close()
    assert p.returncode == 0, p.stderr
    assert p.stdout.strip() == "OK"


# ---- agent mode (one sandbox per session, REPL restarts inside it) ---------

REPL_DIR = Path(__file__).resolve().parents[1] / "repl"
sys.path.insert(0, str(REPL_DIR))
from proto import recv, send  # noqa: E402


def pairs():
    a_repl, c_repl = socket.socketpair()
    a_ctl, c_ctl = socket.socketpair()
    return (a_repl, a_ctl), (c_repl, c_ctl)


def call(sock, req):
    sock.settimeout(10)
    send(sock, req)
    return recv(sock)


linux_only = pytest.mark.skipif(sys.platform != "linux", reason="AF_UNIX SOCK_SEQPACKET is Linux-only")


@pytest.fixture
def agent():
    assert "CI_IN_SANDBOX" not in os.environ  # kill(-1) must never run here
    (a_repl, a_ctl), (c_repl, c_ctl) = pairs()
    a_agent, c_agent = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    fds = (c_repl.fileno(), c_ctl.fileno(), c_agent.fileno())
    env = dict(os.environ, REPL_FD=str(fds[0]), REPL_CTL_FD=str(fds[1]), CI_AGENT_FD=str(fds[2]),
               CI_PROXY_SOCK="/nonexistent")
    p = subprocess.Popen([sys.executable, str(LAUNCH), sys.executable, str(REPL_DIR / "server.py")],
                         env=env, pass_fds=fds)
    for s in (c_repl, c_ctl, c_agent):
        s.close()
    yield p, a_agent, a_repl
    a_agent.close()
    p.wait(10)


def restart(a_agent):
    (n_repl, n_ctl), (c_repl, c_ctl) = pairs()
    socket.send_fds(a_agent, [b'{"op": "restart"}'], [c_repl.fileno(), c_ctl.fileno()])
    c_repl.close()
    c_ctl.close()
    a_agent.settimeout(10)
    return json.loads(a_agent.recv(4096)), n_repl, n_ctl  # keep n_ctl open: EOF ends the REPL


@linux_only
def test_agent_restarts_repl_on_new_channels_and_old_one_closes(agent):
    p, a_agent, a_repl = agent
    assert call(a_repl, {"op": "exec", "code": "x = 1", "id": 1})["id"] == 1
    reply, n_repl, n_ctl = restart(a_agent)
    assert reply == {"ok": True}
    a_repl.settimeout(5)
    assert a_repl.recv(1) == b""  # old REPL is gone and nobody holds its channel
    assert call(n_repl, {"op": "exec", "code": "x", "id": 2})["error"] == "NameError"


@linux_only
def test_agent_ping_and_unknown_op(agent):
    _, a_agent, _ = agent
    a_agent.settimeout(5)
    a_agent.send(b'{"op": "ping"}')
    assert json.loads(a_agent.recv(4096)) == {"ok": True}
    a_agent.send(b'{"op": "nope"}')
    assert json.loads(a_agent.recv(4096)) == {"ok": False}


@linux_only
def test_closing_the_agent_channel_ends_agent_and_repl(agent):
    p, a_agent, a_repl = agent
    a_agent.close()
    assert p.wait(10) == 0
    a_repl.settimeout(5)
    assert a_repl.recv(1) == b""
