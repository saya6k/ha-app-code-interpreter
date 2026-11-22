"""File operations the agent (launch.py) performs inside the sandbox (stdlib only).

Paths are logical sandbox paths: "/sandbox/x" or "x" (relative to /sandbox).
Everything resolves inside /sandbox; symlinks are resolved first, so a link
cannot reach the read-only rootfs or /tmp. Contents travel over a pipe fd the
app passes along with the request, so large files need no chunking.
"""

import json
import os
import stat
import tempfile

LOGICAL = "/sandbox"
ROOT = os.environ.get("CI_FILES_ROOT", LOGICAL)  # tests point this elsewhere
LIST_CAP = 1000
# One SOCK_SEQPACKET message must fit the socket send buffer (~208 KB by
# default); a reply that does not would kill the agent and the sandbox.
REPLY_BYTES = 128 * 1024
CHUNK = 65536


class Violation(ValueError):
    """A policy refusal; its kind travels in the reply as "violation"."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


def resolve(path: str) -> str:
    if path == LOGICAL or path.startswith(LOGICAL + "/"):
        path = ROOT + path[len(LOGICAL):]
    elif not os.path.isabs(path):
        path = os.path.join(ROOT, path)
    real = os.path.realpath(path)
    root = os.path.realpath(ROOT)
    if real != root and not real.startswith(root + "/"):
        raise Violation("traversal", f"{path!r} is outside /sandbox")
    return real


def logical(real: str) -> str:
    rel = os.path.relpath(real, os.path.realpath(ROOT))
    return LOGICAL if rel == "." else f"{LOGICAL}/{rel}"


def _kind(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISLNK(mode):
        return "link"
    return "other"


def _entry(real: str) -> dict | None:
    try:
        st = os.lstat(real)
    except OSError:  # vanished since listdir, or unreadable: skip it
        return None
    return {"path": logical(real), "type": _kind(st.st_mode), "size": st.st_size, "mtime": st.st_mtime}


def _names(base: str, recursive: bool, skip_dot: bool):
    if not recursive:
        try:
            yield from (os.path.join(base, n) for n in sorted(os.listdir(base)))
        except OSError:
            pass
        return
    for d, dirs, names in os.walk(base):  # unreadable dirs are skipped by os.walk
        if skip_dot:
            dirs[:] = [x for x in dirs if not x.startswith(".")]
            names = [x for x in names if not x.startswith(".")]
        dirs.sort()
        yield from (os.path.join(d, n) for n in sorted(dirs + names))


def list_entries(path: str, recursive: bool, skip_dot: bool = False) -> dict:
    base = resolve(path)
    if not os.path.isdir(base):
        entry = _entry(base)
        return {"entries": [entry] if entry else [], "truncated": False}
    out, size = [], 100
    for real in _names(base, recursive, skip_dot):
        entry = _entry(real)
        if entry is None:
            continue
        size += len(json.dumps(entry)) + 2
        if len(out) >= LIST_CAP or size > REPLY_BYTES:
            return {"entries": out, "truncated": True}
        out.append(entry)
    return {"entries": out, "truncated": False}


def read(path: str, limit: int, fd: int) -> dict:
    """Stream up to `limit` bytes into fd; report the full size."""
    try:
        real = resolve(path)
        # O_NONBLOCK: opening a FIFO without a writer must not block the agent.
        src = os.open(real, os.O_RDONLY | os.O_NONBLOCK)
        st = os.fstat(src)
        if not stat.S_ISREG(st.st_mode):
            os.close(src)
            raise ValueError(f"{path!r} is not a regular file")
        with os.fdopen(src, "rb") as f:
            size = st.st_size
            sent = 0
            while sent < limit and (chunk := f.read(min(CHUNK, limit - sent))):
                _write_all(fd, chunk)
                sent += len(chunk)
        return {"ok": True, "size": size, "sent": sent}
    finally:
        os.close(fd)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def write(path: str, max_bytes: int, fd: int) -> dict:
    """Read fd to EOF into path (parents created). Written to a temp file and
    renamed over the target only on success, so a failure (over max_bytes,
    ENOSPC, permissions) leaves any existing file untouched."""
    tmp = None
    try:
        real = resolve(path)
        try:
            st = os.lstat(real)
        except FileNotFoundError:
            st = None
        if st is not None and not stat.S_ISREG(st.st_mode):
            raise ValueError(f"{path!r} exists and is not a regular file")
        os.makedirs(os.path.dirname(real), exist_ok=True)
        out_fd, tmp = tempfile.mkstemp(dir=os.path.dirname(real), prefix=".ci-write-")
        size = 0
        with os.fdopen(out_fd, "wb") as out:
            while chunk := os.read(fd, CHUNK):
                size += len(chunk)
                if size > max_bytes:
                    raise Violation("size", f"file exceeds {max_bytes} bytes")
                out.write(chunk)
        os.chmod(tmp, 0o644)
        os.replace(tmp, real)
        tmp = None
        return {"ok": True, "size": size, "path": logical(real)}
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        os.close(fd)


def handle(req: dict, fds: list[int]) -> dict:
    """Agent dispatch for list/read/write. Never raises; closes fds it got."""
    try:
        op = req.get("op")
        if op == "list":
            for fd in fds:
                os.close(fd)
            fds = []
            return {"ok": True, **list_entries(req.get("path", LOGICAL), bool(req.get("recursive")),
                                               bool(req.get("skip_dot")))}
        if op in ("read", "write") and len(fds) == 1:
            fd, fds = fds[0], []
            if op == "read":
                return read(req["path"], int(req["limit"]), fd)
            return write(req["path"], int(req["max_bytes"]), fd)
        return {"ok": False, "error": f"bad request {op!r}"}
    except Violation as e:
        return {"ok": False, "error": f"ValueError: {e}", "violation": e.kind}
    except (OSError, ValueError, KeyError) as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    finally:
        for fd in fds:
            os.close(fd)
