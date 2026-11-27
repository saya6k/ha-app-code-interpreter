"""/share access for import and export (SPEC §3.6).

The app writes into /share as root, so every path from a tool call is checked
here: reads must resolve (symlinks included) to a regular file inside /share,
and exports go to <export_dir>/<sid>/<basename>, created with O_EXCL and
O_NOFOLLOW so no existing file or planted link is ever written through.
"""

from __future__ import annotations

import os
from pathlib import Path

SHARE = Path("/share")
MAX_SUFFIX = 1000


class ShareError(ValueError):
    """`violation` is the policy kind ("traversal", "size") for the audit log, or None."""

    def __init__(self, message: str, violation: str | None = None) -> None:
        super().__init__(message)
        self.violation = violation


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def resolve_share(p: str, root: Path = SHARE) -> Path:
    rel = p
    if rel == str(SHARE) or rel.startswith(str(SHARE) + "/"):
        rel = rel[len(str(SHARE)):]
    rel = rel.lstrip("/")
    if not rel:
        raise ShareError("share_path is empty")
    real_root = root.resolve()
    # Containment first: a path aiming outside /share is a traversal attempt
    # whether or not its target exists.
    if not _inside((real_root / rel).resolve(), real_root):
        raise ShareError(f"/share/{rel} points outside /share", "traversal")
    try:
        path = (real_root / rel).resolve(strict=True)
    except (OSError, RuntimeError):
        raise ShareError(f"/share/{rel} does not exist") from None
    if not _inside(path, real_root):
        raise ShareError(f"/share/{rel} points outside /share", "traversal")
    if not path.is_file():
        raise ShareError(f"/share/{rel} is not a regular file")
    return path


LIST_CAP = 1000


def list_share(p: str = "", root: Path = SHARE) -> dict:
    """Names, types and sizes in a /share directory (not recursive). Entries
    whose target resolves outside /share are left out."""
    real_root = root.resolve()
    rel = p[len(str(SHARE)):] if p == str(SHARE) or p.startswith(str(SHARE) + "/") else p
    rel = rel.strip("/")
    if not _inside((real_root / rel).resolve(), real_root):
        raise ShareError(f"/share/{rel} points outside /share", "traversal")
    path = (real_root / rel).resolve()
    if not path.is_dir():
        raise ShareError(f"/share/{rel} is not a directory")
    entries = []
    truncated = False
    for e in sorted(os.scandir(path), key=lambda e: e.name):
        target = Path(e.path).resolve()
        if not _inside(target, real_root):
            continue
        if len(entries) == LIST_CAP:
            truncated = True
            break
        kind = "dir" if target.is_dir() else "file" if target.is_file() else "other"
        entry = {"name": e.name, "type": kind}
        if kind == "file":
            entry["size"] = target.stat().st_size
        entries.append(entry)
    return {"path": "/share" + (f"/{rel}" if rel else ""), "entries": entries, "truncated": truncated}


def read_share(p: str, max_bytes: int, root: Path = SHARE) -> bytes:
    path = resolve_share(p, root)
    size = path.stat().st_size
    if size > max_bytes:
        raise ShareError(f"/share/{p.lstrip('/')} is larger than {max_bytes} bytes ({size})", "size")
    data = path.read_bytes()
    if len(data) > max_bytes:  # grew while we looked
        raise ShareError(f"/share/{p.lstrip('/')} is larger than {max_bytes} bytes", "size")
    return data


def _candidates(name: str):
    stem, dot, ext = name.rpartition(".")
    if not stem:  # no extension, or a dotfile like ".env"
        stem, dot, ext = name, "", ""
    yield name
    for i in range(1, MAX_SUFFIX):
        yield f"{stem}-{i}{dot}{ext}"


def export(data: bytes, name: str, export_dir: Path, sid: str, root: Path = SHARE) -> Path:
    base = Path(name).name
    if base in ("", ".", ".."):
        raise ShareError(f"cannot export {name!r}: no file name")
    real_root = root.resolve()
    export_dir = Path(export_dir)
    if not _inside(export_dir.resolve(), real_root):
        raise ShareError(f"export_dir {export_dir} is outside /share", "traversal")
    export_dir.mkdir(parents=True, exist_ok=True)
    session_dir = export_dir / sid
    try:
        session_dir.mkdir()
    except FileExistsError:
        pass
    # Open the directory itself without following a link, then create files
    # relative to that fd: swapping the path for a symlink afterwards no
    # longer redirects the write.
    try:
        dfd = os.open(session_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise ShareError(f"{session_dir} is a symlink or not a directory") from None
    try:
        if not _inside(session_dir.resolve(), real_root):
            raise ShareError(f"{session_dir} points outside /share", "traversal")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        for candidate in _candidates(base):
            try:
                fd = os.open(candidate, flags, 0o644, dir_fd=dfd)
            except FileExistsError:
                continue
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            return session_dir / candidate
        raise ShareError(f"too many files named {base!r} in {session_dir}")
    finally:
        os.close(dfd)
