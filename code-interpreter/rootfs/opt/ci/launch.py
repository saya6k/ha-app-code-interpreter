"""Sandbox entrypoint (stdlib only): optional proxy forwarder, then the command.

    python3 /opt/ci/launch.py <argv...>

The sandbox network namespace has only loopback. When the app bound a proxy
socket into /run/ci (non-empty allowlist), a thread forwards
127.0.0.1:3128 to it, so HTTP(S)_PROXY clients reach the app's CONNECT
proxy. Without the socket nothing listens and every connection fails.
"""

import os
import socket
import subprocess
import sys
import threading
import time

PROXY_SOCK = os.environ.get("CI_PROXY_SOCK", "/run/ci/proxy.sock")
PROXY_PORT = int(os.environ.get("CI_PROXY_PORT", "3128"))


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


def main(argv: list[str]) -> int:
    if os.path.exists(PROXY_SOCK):
        listener = socket.create_server(("127.0.0.1", PROXY_PORT))
        threading.Thread(target=_serve, args=(listener,), daemon=True).start()
    code = subprocess.call(argv, close_fds=False)  # REPL channels are inherited fds
    return 128 - code if code < 0 else code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
