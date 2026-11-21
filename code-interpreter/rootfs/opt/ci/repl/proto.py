"""Length-prefixed JSON framing shared by the REPL server and client (stdlib only)."""

import json
import struct


def send(sock, obj) -> None:
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


def _exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return buf


def recv(sock):
    (n,) = struct.unpack(">I", _exact(sock, 4))
    return json.loads(_exact(sock, n))
