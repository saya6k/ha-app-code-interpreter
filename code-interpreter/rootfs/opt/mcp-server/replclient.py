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


_CODE_KEYS = ("stdout", "stderr", "result", "error", "truncated")
_COMMAND_KEYS = ("stdout", "stderr", "exit_code", "error", "truncated")


def _merge(out: dict, reply: dict, keys: tuple[str, ...]) -> dict:
    """Take only the reply fields the app knows; the sandbox controls the rest."""
    for k in keys:
        if k in reply:
            out[k] = reply[k]
    return out


def _blank(command: bool = False) -> dict:
    out = {"stdout": "", "stderr": "", "error": None, "truncated": False, "restart_required": False}
    out.update({"exit_code": None} if command else {"result": None})
    return out


class ReplClient:
    def __init__(self, repl: socket.socket, ctl: socket.socket, grace_s: float = GRACE_S) -> None:
        self._repl = _Channel(repl)
        self._ctl = _Channel(ctl)
        self.grace_s = grace_s
        self._next_id = 0

    def close(self) -> None:
        self._repl.close()
        self._ctl.close()

    async def _send(self, req: dict) -> int:
        self._next_id += 1
        await self._repl.send({**req, "id": self._next_id})
        return self._next_id

    async def _reply(self, rid: int, timeout_s: float) -> dict:
        """Next reply for request `rid`; replies to abandoned requests are skipped."""
        async def matching():
            while (msg := await self._repl.recv()).get("id") != rid:
                pass
            return msg

        return await asyncio.wait_for(matching(), timeout_s)

    async def wait_ready(self, timeout_s: float) -> None:
        try:
            await self._reply(await self._send({"op": "ping"}), timeout_s)
        except (ConnectionError, TimeoutError) as e:
            raise SandboxNotReady(f"REPL not ready: {e or 'timeout'}") from None

    async def interrupt(self) -> bool:
        """Ask the server to SIGINT itself. True if a cell or command was running."""
        try:
            await self._ctl.send({"op": "interrupt"})
            resp = await asyncio.wait_for(self._ctl.recv(), 2)
        except (ConnectionError, TimeoutError):
            return False
        return bool(resp.get("interrupted"))

    async def reset(self) -> dict:
        out = _blank()
        try:
            _merge(out, await self._reply(await self._send({"op": "reset"}), 10), _CODE_KEYS)
        except (ConnectionError, TimeoutError):
            out.update(error="KernelDied", restart_required=True)
        return out

    async def _bounded(self, req: dict, timeout_s: float, out: dict, keys: tuple[str, ...]) -> dict:
        """Send, wait timeout_s, then interrupt and wait grace_s, then give up."""
        try:
            rid = await self._send(req)
            try:
                return _merge(out, await self._reply(rid, timeout_s), keys)
            except TimeoutError:
                pass
            await self.interrupt()
            try:
                _merge(out, await self._reply(rid, self.grace_s), keys)
                out["error"] = "TimeoutError"
            except TimeoutError:
                out.update(error="TimeoutError", restart_required=True)
            return out
        except ConnectionError:
            # Server died mid-request (crash, OOM kill, os._exit) or broke the protocol.
            out.update(error="KernelDied", restart_required=True)
            return out
        except asyncio.CancelledError:
            # Caller gave up: stop the work in the sandbox so the next request
            # does not queue behind it. Its late reply is skipped by id.
            await asyncio.shield(self.interrupt())
            raise

    async def run(self, code: str, timeout_s: float) -> dict:
        return await self._bounded({"op": "exec", "code": code}, timeout_s, _blank(), _CODE_KEYS)

    async def command(self, command: str, timeout_s: float) -> dict:
        """The server enforces timeout_s itself; the client allows a little more."""
        req = {"op": "command", "command": command, "timeout_s": timeout_s}
        return await self._bounded(req, timeout_s + 2, _blank(command=True), _COMMAND_KEYS)
