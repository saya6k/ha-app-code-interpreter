"""App-side client for the sandbox REPL server (SPEC §3.2).

Talks to repl.sock / ctl.sock in a session's run directory, which bubblewrap
binds into the sandbox at /run/ci. Framing matches ci/repl/proto.py.
Restarting a dead or stuck REPL is the sandbox layer's job: this client only
reports restart_required.
"""

from __future__ import annotations

import asyncio
import json
import struct
from pathlib import Path

GRACE_S = 5.0


class SandboxNotReady(RuntimeError):
    """The REPL did not come up — the caller must not run code (fail-closed)."""


async def _send(writer: asyncio.StreamWriter, obj: dict) -> None:
    data = json.dumps(obj).encode()
    writer.write(struct.pack(">I", len(data)) + data)
    await writer.drain()


async def _recv(reader: asyncio.StreamReader) -> dict:
    (n,) = struct.unpack(">I", await reader.readexactly(4))
    return json.loads(await reader.readexactly(n))


def _blank() -> dict:
    return {
        "stdout": "",
        "stderr": "",
        "result": None,
        "error": None,
        "truncated": False,
        "restart_required": False,
    }


class ReplClient:
    def __init__(self, run_dir: Path, grace_s: float = GRACE_S) -> None:
        self.sock = str(run_dir / "repl.sock")
        self.ctl = str(run_dir / "ctl.sock")
        self.grace_s = grace_s

    async def _request(self, path: str, req: dict, timeout_s: float) -> dict:
        reader, writer = await asyncio.open_unix_connection(path)
        try:
            await _send(writer, req)
            return await asyncio.wait_for(_recv(reader), timeout_s)
        finally:
            writer.close()

    async def wait_ready(self, timeout_s: float) -> None:
        deadline = asyncio.get_running_loop().time() + timeout_s
        while True:
            try:
                await self._request(self.sock, {"op": "ping"}, timeout_s=2)
                return
            except (OSError, asyncio.IncompleteReadError, TimeoutError):
                if asyncio.get_running_loop().time() > deadline:
                    raise SandboxNotReady(f"REPL not ready after {timeout_s}s") from None
                await asyncio.sleep(0.05)

    async def interrupt(self) -> bool:
        """Ask the server to SIGINT itself. True if a cell was running."""
        try:
            resp = await self._request(self.ctl, {"op": "interrupt"}, timeout_s=2)
        except (OSError, asyncio.IncompleteReadError, TimeoutError):
            return False
        return bool(resp.get("interrupted"))

    async def reset(self) -> dict:
        out = _blank()
        out.update(await self._request(self.sock, {"op": "reset"}, timeout_s=10))
        return out

    async def run(self, code: str, timeout_s: float) -> dict:
        out = _blank()
        try:
            reader, writer = await asyncio.open_unix_connection(self.sock)
        except OSError:
            out.update(error="KernelDied", restart_required=True)
            return out
        try:
            await _send(writer, {"op": "exec", "code": code})
            try:
                out.update(await asyncio.wait_for(_recv(reader), timeout_s))
                return out
            except TimeoutError:
                pass
            except (asyncio.IncompleteReadError, ConnectionError):
                # Server died mid-cell: crash, OOM kill, os._exit.
                out.update(error="KernelDied", restart_required=True)
                return out
            await self.interrupt()
            try:
                out.update(await asyncio.wait_for(_recv(reader), self.grace_s))
                out["error"] = "TimeoutError"
            except (TimeoutError, asyncio.IncompleteReadError, ConnectionError):
                out.update(error="TimeoutError", restart_required=True)
            return out
        finally:
            writer.close()
