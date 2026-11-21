"""launch.py — real local processes, no bwrap."""

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
