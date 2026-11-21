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
import subprocess
import sys
import threading
import time
import traceback

from proto import recv, send

OUT_LIMIT = 16000
SANDBOX_DIR = os.environ.get("CI_SANDBOX_DIR", "/sandbox")
READER_GRACE_S = 2.0  # total, for both output readers after the command ends
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


def _read_capped(stream, limit: int, out: list) -> None:
    """Append into out = [bytearray, truncated] as data arrives, so whatever
    was read is kept even if a detached grandchild never closes the pipe."""
    while chunk := stream.read1(65536):
        room = limit - len(out[0])
        if room > 0:
            out[0] += chunk[:room]
        if len(chunk) > room:
            out[1] = True


def run_command(command: str, timeout_s: float) -> dict:
    """sh -c in /sandbox, capped output; timeout or interrupt kills its group."""
    global _executing
    proc = subprocess.Popen(
        ["/bin/sh", "-c", command],
        cwd=SANDBOX_DIR if os.path.isdir(SANDBOX_DIR) else None,  # whatever chdir user code did
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    outs = [[bytearray(), False], [bytearray(), False]]
    readers = [
        threading.Thread(target=_read_capped, args=(s, OUT_LIMIT, o), daemon=True)
        for s, o in zip((proc.stdout, proc.stderr), outs)
    ]
    for t in readers:
        t.start()
    error = None
    signal.signal(signal.SIGINT, _on_sigint)
    try:
        _executing = True
        try:
            proc.wait(timeout_s)
        except subprocess.TimeoutExpired:
            error = "TimeoutError"
    except KeyboardInterrupt:
        error = "KeyboardInterrupt"
    finally:
        _executing = False
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        deadline = time.monotonic() + READER_GRACE_S  # a detached grandchild may hold the pipes
        for t in readers:
            t.join(max(0, deadline - time.monotonic()))
    rc = proc.returncode
    return {
        "stdout": outs[0][0].decode(errors="replace"),
        "stderr": outs[1][0].decode(errors="replace"),
        "exit_code": None if error else (128 - rc if rc < 0 else rc),
        "error": error,
        "truncated": outs[0][1] or outs[1][1],
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
        elif op == "command":
            resp = run_command(req.get("command", ""), float(req.get("timeout_s", 60)))
        else:
            cell += 1
            resp = execute(req.get("code", ""), g, cell)
        # Echo the id: after a cancelled request the app skips stale replies.
        resp["id"] = req.get("id")
        try:
            send(conn, resp)
        except OSError:
            return


if __name__ == "__main__":
    main()
