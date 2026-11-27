"""The image's CMD: forward Home Assistant's stdin to the MCP server (stdlib only).

Under s6-overlay only the main program receives the container's stdin pipe
(hassio.app_stdin input, one JSON object per line). Each line goes to the
server's Unix socket (see stdin.py). This process must outlive EOF: when the
main program exits, s6 stops the container.
"""

import os
import signal
import socket
import sys
import time

SOCKET = os.environ.get("CI_STDIN_SOCK", "/run/code-interpreter/stdin.sock")
CONNECT_TRIES = 120  # the server may still be starting (its self-check runs first)


def forward(line: bytes) -> bool:
    for _ in range(CONNECT_TRIES):
        try:
            with socket.socket(socket.AF_UNIX) as s:
                s.connect(SOCKET)
                s.sendall(line if line.endswith(b"\n") else line + b"\n")
            return True
        except OSError:
            time.sleep(0.5)
    return False


def main() -> None:
    for line in sys.stdin.buffer:
        if line.strip() and not forward(line):
            print("[stdin] MCP server unreachable: input dropped", flush=True)
    if os.environ.get("CI_STDIN_EXIT_AT_EOF"):  # tests
        return
    while True:
        signal.pause()


if __name__ == "__main__":
    main()
