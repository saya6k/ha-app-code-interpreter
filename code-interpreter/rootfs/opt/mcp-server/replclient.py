"""App-side client for the sandbox REPL server (SPEC §3.2).

The app creates two socketpairs per REPL start and passes one end of each
into the sandbox (fds named by $REPL_FD / $REPL_CTL_FD). No socket file is
involved, so sandbox code cannot redirect the app to another socket.
Framing matches ci/repl/proto.py. Restarting a dead or stuck REPL is the
sandbox layer's job: this client only reports restart_required.
"""

from __future__ import annotations

import asyncio
import json
import socket
import struct

GRACE_S = 5.0
# Sandbox code can write to its end of the channel directly; never let a
# forged length header make the app allocate without bound. Legit replies are
# capped at 2 x 16000 chars of output plus a 4000-char result.
MAX_MSG = 1 << 20


class SandboxNotReady(RuntimeError):
    """The REPL did not come up — the caller must not run code (fail-closed)."""


class ChannelBroken(ConnectionError):
    """Peer closed, or sent something that is not a valid reply."""


def socketpairs() -> tuple[tuple[socket.socket, socket.socket], tuple[socket.socket, socket.socket]]:
    """(app_repl, app_ctl), (child_repl, child_ctl). Child ends are inheritable."""
    app_repl, child_repl = socket.socketpair()
    app_ctl, child_ctl = socket.socketpair()
    for s in (child_repl, child_ctl):
        s.set_inheritable(True)
    return (app_repl, app_ctl), (child_repl, child_ctl)


class _Channel:
    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None

    async def _open(self) -> None:
        if self.reader is None:
            self.reader, self.writer = await asyncio.open_unix_connection(sock=self.sock)

    async def send(self, obj: dict) -> None:
        await self._open()
        data = json.dumps(obj).encode()
        self.writer.write(struct.pack(">I", len(data)) + data)
        await self.writer.drain()

    async def recv(self) -> dict:
        await self._open()
        try:
            (n,) = struct.unpack(">I", await self.reader.readexactly(4))
            if n > MAX_MSG:
                raise ChannelBroken(f"reply of {n} bytes exceeds {MAX_MSG}")
            msg = json.loads(await self.reader.readexactly(n))
        except (asyncio.IncompleteReadError, ValueError, OSError) as e:
            raise ChannelBroken(str(e)) from None
        if not isinstance(msg, dict):
            raise ChannelBroken("reply is not an object")
        return msg

    def close(self) -> None:
        if self.writer is not None:
            self.writer.close()
        else:
            self.sock.close()


_REPLY_KEYS = ("stdout", "stderr", "result", "error", "truncated")


def _merge(out: dict, reply: dict) -> dict:
    """Take only the reply fields the app knows; the sandbox controls the rest."""
    for k in _REPLY_KEYS:
        if k in reply:
            out[k] = reply[k]
    return out


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
    def __init__(self, repl: socket.socket, ctl: socket.socket, grace_s: float = GRACE_S) -> None:
        self._repl = _Channel(repl)
        self._ctl = _Channel(ctl)
        self.grace_s = grace_s

    def close(self) -> None:
        self._repl.close()
        self._ctl.close()

    async def wait_ready(self, timeout_s: float) -> None:
        try:
            await self._repl.send({"op": "ping"})
            await asyncio.wait_for(self._repl.recv(), timeout_s)
        except (ConnectionError, TimeoutError) as e:
            raise SandboxNotReady(f"REPL not ready: {e or 'timeout'}") from None

    async def interrupt(self) -> bool:
        """Ask the server to SIGINT itself. True if a cell was running."""
        try:
            await self._ctl.send({"op": "interrupt"})
            resp = await asyncio.wait_for(self._ctl.recv(), 2)
        except (ConnectionError, TimeoutError):
            return False
        return bool(resp.get("interrupted"))

    async def reset(self) -> dict:
        out = _blank()
        try:
            await self._repl.send({"op": "reset"})
            _merge(out, await asyncio.wait_for(self._repl.recv(), 10))
        except (ConnectionError, TimeoutError):
            out.update(error="KernelDied", restart_required=True)
        return out

    async def run(self, code: str, timeout_s: float) -> dict:
        out = _blank()
        try:
            await self._repl.send({"op": "exec", "code": code})
            try:
                _merge(out, await asyncio.wait_for(self._repl.recv(), timeout_s))
                return out
            except TimeoutError:
                pass
            await self.interrupt()
            try:
                _merge(out, await asyncio.wait_for(self._repl.recv(), self.grace_s))
                out["error"] = "TimeoutError"
                return out
            except TimeoutError:
                out.update(error="TimeoutError", restart_required=True)
                return out
        except ConnectionError:
            # Server died mid-cell (crash, OOM kill, os._exit) or broke the protocol.
            out.update(error="KernelDied", restart_required=True)
            return out
