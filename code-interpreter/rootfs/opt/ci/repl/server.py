"""Stateful Python REPL server for the sandbox (stdlib only).

Serves one request at a time on a Unix socket and keeps a single globals dict
across requests. SIGINT interrupts running user code (KeyboardInterrupt) and
is ignored while idle. The app cannot signal this process by pid (it lives in
the sandbox's pid namespace), so an "interrupt" request on the control socket
makes the server send SIGINT to itself.
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

SOCK = os.environ.get("REPL_SOCK", "/run/ci/repl.sock")
CTL_SOCK = os.environ.get("REPL_CTL", "/run/ci/ctl.sock")
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


def _listen(path: str) -> socket.socket:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(4)
    return srv


def _serve_ctl(srv: socket.socket) -> None:
    """Control channel, served on its own thread while a cell runs."""
    while True:
        conn, _ = srv.accept()
        with conn:
            try:
                req = recv(conn)
                interrupted = req.get("op") == "interrupt" and _executing
                if interrupted:
                    os.kill(os.getpid(), signal.SIGINT)
                send(conn, {"interrupted": interrupted})
            except (OSError, ValueError):
                pass


def main() -> None:
    signal.signal(signal.SIGINT, _on_sigint)
    ctl = _listen(CTL_SOCK)
    threading.Thread(target=_serve_ctl, args=(ctl,), daemon=True).start()
    srv = _listen(SOCK)  # bound last: its presence means the server is ready

    g = new_globals()
    cell = 0
    while True:
        conn, _ = srv.accept()
        with conn:
            try:
                req = recv(conn)
            except (OSError, ValueError):
                continue
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
                pass


if __name__ == "__main__":
    main()
