"""File operations the agent (launch.py) performs inside the sandbox (stdlib only).

Paths are logical sandbox paths: "/sandbox/x" or "x" (relative to /sandbox).
Everything resolves inside /sandbox; symlinks are resolved first, so a link
cannot reach the read-only rootfs or /tmp. Contents travel over a pipe fd the
app passes along with the request, so large files need no chunking.
"""

import os
import stat

LOGICAL = "/sandbox"
ROOT = os.environ.get("CI_FILES_ROOT", LOGICAL)  # tests point this elsewhere
LIST_CAP = 1000
CHUNK = 65536


def resolve(path: str) -> str:
    if path == LOGICAL or path.startswith(LOGICAL + "/"):
        path = ROOT + path[len(LOGICAL):]
    elif not os.path.isabs(path):
        path = os.path.join(ROOT, path)
    real = os.path.realpath(path)
    root = os.path.realpath(ROOT)
    if real != root and not real.startswith(root + "/"):
        raise ValueError(f"{path!r} is outside /sandbox")
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


def _entry(real: str) -> dict:
    st = os.lstat(real)
    return {"path": logical(real), "type": _kind(st.st_mode), "size": st.st_size, "mtime": st.st_mtime}


def list_entries(path: str, recursive: bool) -> dict:
    base = resolve(path)
    if not os.path.isdir(base):
        return {"entries": [_entry(base)], "truncated": False}
    out = []
    if recursive:
        for d, dirs, names in os.walk(base):
            dirs.sort()
            for n in sorted(dirs + names):
                out.append(_entry(os.path.join(d, n)))
                if len(out) >= LIST_CAP:
                    return {"entries": out, "truncated": True}
    else:
        for n in sorted(os.listdir(base))[: LIST_CAP + 1]:
            out.append(_entry(os.path.join(base, n)))
    return {"entries": out[:LIST_CAP], "truncated": len(out) > LIST_CAP}


def read(path: str, limit: int, fd: int) -> dict:
    """Stream up to `limit` bytes into fd; report the full size."""
    try:
        real = resolve(path)
        with open(real, "rb") as f:
            size = os.fstat(f.fileno()).st_size
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                raise ValueError(f"{path!r} is not a regular file")
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
    """Read fd to EOF into path (parents created). Over max_bytes: nothing kept."""
    real = None
    try:
        real = resolve(path)
        if os.path.isdir(real):
            raise ValueError(f"{path!r} is a directory")
        os.makedirs(os.path.dirname(real), exist_ok=True)
        size = 0
        with open(real, "wb") as out:
            while chunk := os.read(fd, CHUNK):
                size += len(chunk)
                if size > max_bytes:
                    raise ValueError(f"file exceeds {max_bytes} bytes")
                out.write(chunk)
        return {"ok": True, "size": size, "path": logical(real)}
    except BaseException:
        if real and os.path.isfile(real):
            os.unlink(real)
        raise
    finally:
        os.close(fd)


def handle(req: dict, fds: list[int]) -> dict:
    """Agent dispatch for list/read/write. Never raises; closes fds it got."""
    try:
        op = req.get("op")
        if op == "list":
            for fd in fds:
                os.close(fd)
            fds = []
            return {"ok": True, **list_entries(req.get("path", LOGICAL), bool(req.get("recursive")))}
        if op in ("read", "write") and len(fds) == 1:
            fd, fds = fds[0], []
            if op == "read":
                return read(req["path"], int(req["limit"]), fd)
            return write(req["path"], int(req["max_bytes"]), fd)
        return {"ok": False, "error": f"bad request {op!r}"}
    except (OSError, ValueError, KeyError) as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    finally:
        for fd in fds:
            os.close(fd)
