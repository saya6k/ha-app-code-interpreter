"""Docker resources for one sandbox: create, exec, file transfer, destroy, reconcile.

Only resources labeled with this app's owner label are ever touched.
"""

from __future__ import annotations

import asyncio
import io
import logging
import posixpath
import tarfile
from pathlib import Path

import docker.errors

from policy import SANDBOX_UID, SandboxPolicy, container_kwargs, volume_specs

log = logging.getLogger("mcp-server")

LABEL_OWNER = "io.hass.code-interpreter.owner"
LABEL_SESSION = "io.hass.code-interpreter.session"
REPL_DIR = Path(__file__).resolve().parent.parent / "repl"
REPL_FILES = ("proto.py", "server.py", "client.py", "init.sh")
SANDBOX_ROOT = "/sandbox"


def make_tar(files: dict[str, tuple[bytes, int]], uid: int) -> bytes:
    """Build a tar from {relative path: (data, mode)}, in insertion order."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, (data, mode) in files.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.uid, info.gid = len(data), mode, uid, uid
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def first_file(blob: bytes) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(blob)) as tf:
        for member in tf:
            if member.isfile():
                return tf.extractfile(member).read()
    raise FileNotFoundError("no regular file in archive")


def repl_tar(repl_dir: Path = REPL_DIR) -> bytes:
    files = {name: ((repl_dir / name).read_bytes(), 0o644) for name in REPL_FILES}
    files[".ready"] = (b"", 0o644)  # last: the entrypoint starts on this marker
    return make_tar(files, uid=0)


def resolve_image(client, ref: str) -> str:
    """Image ID (sha256:…) — Supervisor ignores sha256 refs when flagging unknown images."""
    try:
        return client.images.get(ref).id
    except docker.errors.ImageNotFound:
        return client.images.pull(ref).id


class Sandbox:
    def __init__(self, client, sid: str, volumes: list[str]) -> None:
        self.client = client
        self.sid = sid
        self.volumes = volumes
        self.container_id: str | None = None

    def _container(self):
        return self.client.containers.get(self.container_id)

    async def exec(self, cmd: list[str], environment: dict | None = None) -> tuple[int, str, str]:
        def run():
            res = self._container().exec_run(cmd, demux=True, environment=environment)
            out, err = res.output
            return (
                res.exit_code,
                (out or b"").decode(errors="replace"),
                (err or b"").decode(errors="replace"),
            )

        return await asyncio.to_thread(run)

    async def put_file(self, path: str, data: bytes, mode: int = 0o644) -> None:
        """Write a file under /sandbox, creating parent dirs owned by the sandbox user."""
        path = posixpath.normpath(path)
        if not path.startswith(SANDBOX_ROOT + "/"):
            raise ValueError(f"path must be under {SANDBOX_ROOT}: {path}")
        rel = path[len(SANDBOX_ROOT) + 1 :]
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            parts = rel.split("/")
            for i in range(1, len(parts)):
                d = tarfile.TarInfo("/".join(parts[:i]))
                d.type, d.mode, d.uid, d.gid = tarfile.DIRTYPE, 0o755, SANDBOX_UID, SANDBOX_UID
                tf.addfile(d)
            f = tarfile.TarInfo(rel)
            f.size, f.mode, f.uid, f.gid = len(data), mode, SANDBOX_UID, SANDBOX_UID
            tf.addfile(f, io.BytesIO(data))
        blob = buf.getvalue()
        await asyncio.to_thread(lambda: self._container().put_archive(SANDBOX_ROOT, blob))

    async def get_file(self, path: str) -> bytes:
        def run():
            bits, _ = self._container().get_archive(path)
            return first_file(b"".join(bits))

        return await asyncio.to_thread(run)

    async def destroy(self) -> None:
        def run():
            if self.container_id:
                try:
                    self._container().remove(force=True)
                except docker.errors.NotFound:
                    pass
            for name in self.volumes:
                try:
                    self.client.volumes.get(name).remove(force=True)
                except docker.errors.NotFound:
                    pass

        await asyncio.to_thread(run)


async def create_sandbox(
    client, policy: SandboxPolicy, *, image: str, owner: str, sid: str
) -> Sandbox:
    labels = {LABEL_OWNER: owner, LABEL_SESSION: sid}
    specs = volume_specs(policy, sid, labels)
    sb = Sandbox(client, sid, [s["name"] for s in specs])

    def run():
        image_id = resolve_image(client, image)
        for spec in specs:
            client.volumes.create(**spec)
        c = client.containers.create(
            **container_kwargs(
                policy, image_id=image_id, name=f"ci-sbx-{sid}", sid=sid, labels=labels
            )
        )
        sb.container_id = c.id
        c.start()
        c.put_archive("/opt/repl", repl_tar())

    try:
        await asyncio.to_thread(run)
    except BaseException:
        await sb.destroy()  # no half-built sandboxes
        raise
    return sb


async def reconcile(client, owner: str) -> dict[str, int]:
    """Remove every container and volume carrying this owner label."""

    def run():
        flt = {"label": f"{LABEL_OWNER}={owner}"}
        n_c = n_v = 0
        for c in client.containers.list(all=True, filters=flt):
            try:
                c.remove(force=True)
                n_c += 1
            except docker.errors.NotFound:
                pass
        for v in client.volumes.list(filters=flt):
            try:
                v.remove(force=True)
                n_v += 1
            except docker.errors.NotFound:
                pass
        return {"containers": n_c, "volumes": n_v}

    return await asyncio.to_thread(run)
