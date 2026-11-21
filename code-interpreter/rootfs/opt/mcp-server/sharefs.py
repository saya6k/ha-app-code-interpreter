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
    pass


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
        raise ShareError(f"/share/{rel} points outside /share")
    try:
        path = (real_root / rel).resolve(strict=True)
    except (OSError, RuntimeError):
        raise ShareError(f"/share/{rel} does not exist") from None
    if not _inside(path, real_root):
        raise ShareError(f"/share/{rel} points outside /share")
    if not path.is_file():
        raise ShareError(f"/share/{rel} is not a regular file")
    return path


def read_share(p: str, max_bytes: int, root: Path = SHARE) -> bytes:
    path = resolve_share(p, root)
    size = path.stat().st_size
    if size > max_bytes:
        raise ShareError(f"/share/{p.lstrip('/')} is larger than {max_bytes} bytes ({size})")
    data = path.read_bytes()
    if len(data) > max_bytes:  # grew while we looked
        raise ShareError(f"/share/{p.lstrip('/')} is larger than {max_bytes} bytes")
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
        raise ShareError(f"export_dir {export_dir} is outside /share")
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
            raise ShareError(f"{session_dir} points outside /share")
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
