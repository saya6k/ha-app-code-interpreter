"""Stateful Python REPL server for the sandbox (stdlib only).

Serves requests one at a time on an inherited socket (fd in $REPL_FD) and
keeps a single globals dict across requests. The app creates the socketpairs
and passes one end through bubblewrap, so no socket file exists that sandbox
code could replace. SIGINT interrupts running user code (KeyboardInterrupt)
and is ignored while idle. The app cannot signal this process by pid (it lives
in the sandbox's pid namespace), so an "interrupt" request on the control
channel ($REPL_CTL_FD) makes the server send SIGINT to itself.
"""

import ast
import builtins
import io
import linecache
import os
import signal
import socket
import sys
import threading
import traceback

from proto import recv, send

OUT_LIMIT = 16000
RESULT_LIMIT = 4000

_executing = False


class Capped(io.TextIOBase):
    """Text sink that keeps only the first `limit` characters."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.parts: list[str] = []
        self.size = 0
        self.truncated = False

    def writable(self) -> bool:
        return True

    def write(self, s: str) -> int:
        room = self.limit - self.size
        if len(s) > room:
            self.truncated = True
        kept = s[: max(room, 0)]
        if kept:
            self.parts.append(kept)
            self.size += len(kept)
        return len(s)

    def getvalue(self) -> str:
        return "".join(self.parts)


def _on_sigint(signum, frame):
    if _executing:
        raise KeyboardInterrupt


def new_globals() -> dict:
    return {"__name__": "__main__", "__builtins__": builtins}


def _run_cell(code: str, g: dict, filename: str):
    """exec all statements; eval and return the last one if it is an expression."""
    linecache.cache[filename] = (len(code), None, code.splitlines(True), filename)
    tree = ast.parse(code, filename)
    last = None
    if tree.body and isinstance(tree.body[-1], ast.Expr):
        last = ast.Expression(tree.body.pop().value)
    exec(compile(tree, filename, "exec"), g)
    if last is not None:
        return eval(compile(last, filename, "eval"), g)
    return None


def _format_exc(exc: BaseException) -> str:
    te = traceback.TracebackException.from_exception(exc)
    te.stack = traceback.StackSummary.from_list(
        [f for f in te.stack if f.filename != __file__]
    )
    return "".join(te.format())


def execute(code: str, g: dict, cell: int) -> dict:
    global _executing
    out, err = Capped(OUT_LIMIT), Capped(OUT_LIMIT)
    result = None
    error = None
    truncated = False
    signal.signal(signal.SIGINT, _on_sigint)  # user code may have replaced it
    saved = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        _executing = True
        value = _run_cell(code, g, f"<cell-{cell}>")
        if value is not None:
            result = repr(value)
            if len(result) > RESULT_LIMIT:
                result, truncated = result[:RESULT_LIMIT], True
    except KeyboardInterrupt:
        error = "KeyboardInterrupt"
    except BaseException as exc:  # incl. SystemExit — never let user code end the server
        error = type(exc).__name__
        err.write(_format_exc(exc))
    finally:
        _executing = False
        sys.stdout, sys.stderr = saved
    return {
        "stdout": out.getvalue(),
        "stderr": err.getvalue(),
        "result": result,
        "error": error,
        "truncated": truncated or out.truncated or err.truncated,
    }


def _channel(env: str) -> socket.socket:
    sock = socket.socket(fileno=int(os.environ[env]))
    os.set_inheritable(sock.fileno(), False)  # keep it from user subprocesses
    return sock


def _serve_ctl(conn: socket.socket) -> None:
    """Control channel, served on its own thread while a cell runs."""
    while True:
        try:
            req = recv(conn)
        except (OSError, ValueError):
            os._exit(0)  # app side closed: the session is gone
        interrupted = req.get("op") == "interrupt" and _executing
        if interrupted:
            os.kill(os.getpid(), signal.SIGINT)
        try:
            send(conn, {"interrupted": interrupted})
        except OSError:
            os._exit(0)


def main() -> None:
    signal.signal(signal.SIGINT, _on_sigint)
    conn = _channel("REPL_FD")
    ctl = _channel("REPL_CTL_FD")
    threading.Thread(target=_serve_ctl, args=(ctl,), daemon=True).start()

    g = new_globals()
    cell = 0
    while True:
        try:
            req = recv(conn)
        except (OSError, ValueError):
            return  # app side closed: the session is gone
        op = req.get("op")
        if op == "ping":
            resp = {"pid": os.getpid()}
        elif op == "reset":
            g.clear()
            g.update(new_globals())
            resp = {"error": None}
        else:
            cell += 1
            resp = execute(req.get("code", ""), g, cell)
        try:
            send(conn, resp)
        except OSError:
            return


if __name__ == "__main__":
    main()
