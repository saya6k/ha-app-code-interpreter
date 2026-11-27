"""Control channel helper for the Node REPL (stdlib only).

    python3 -I -S ctl.py     (control socket on fd 3, started by server.mjs)

Node cannot read the control channel while a cell runs a synchronous loop, so
this process owns it and answers {"op": "interrupt"} by sending its parent
(the REPL) SIGINT. It dies with the REPL.
"""

import ctypes
import os
import signal
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from proto import recv, send  # noqa: E402

PR_SET_PDEATHSIG = 1


def main() -> None:
    parent = os.getppid()
    try:
        ctypes.CDLL(None, use_errno=True).prctl(PR_SET_PDEATHSIG, signal.SIGKILL)
    except (AttributeError, OSError):
        pass  # not Linux (local tests): EOF on the channel still ends us
    if os.getppid() != parent:
        return  # the REPL died before prctl took effect
    conn = socket.socket(fileno=3)
    while True:
        try:
            req = recv(conn)
        except (OSError, ValueError):
            return  # app side closed: the session is gone
        sent = False
        if req.get("op") == "interrupt":
            try:
                os.kill(parent, signal.SIGINT)
                sent = True
            except ProcessLookupError:
                return
        try:
            send(conn, {"interrupted": sent})
        except OSError:
            return


if __name__ == "__main__":
    main()
