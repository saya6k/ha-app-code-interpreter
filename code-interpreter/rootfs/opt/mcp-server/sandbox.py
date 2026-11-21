"""One session's bubblewrap sandbox: REPL lifecycle, commands, teardown (SPEC §3.2-3.4).

Layout under base_dir/<sid>/ (app-only, not mounted whole into the sandbox):
    work/   session uid, 0700  -> /sandbox (rw)
    proxy/  root, 0755         -> /run/ci  (ro; proxy.sock when allowlisted)

Fail-closed: if bwrap or the REPL does not come up, create() raises and
nothing runs. There is no code path that executes outside bubblewrap.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import signal
from pathlib import Path

from policy import SANDBOX_ROOT, SandboxPolicy, bwrap_argv, exec_prefix, sandbox_env
from replclient import ReplClient, SandboxNotReady, socketpairs
from seccomp import compile_filter

BASE_DIR = Path("/var/cache/code-interpreter")
PY = "/opt/venv/bin/python3"
LAUNCH = [PY, "/opt/ci/launch.py"]
REPL = [PY, "-u", "/opt/ci/repl/server.py"]
OUT_LIMIT = 16000
STDERR_TAIL = 4096
READY_TIMEOUT_S = 30.0


class SandboxError(RuntimeError):
    pass


async def _read_capped(stream: asyncio.StreamReader, limit: int) -> tuple[bytes, bool]:
    buf, truncated = bytearray(), False
    while chunk := await stream.read(65536):
        room = limit - len(buf)
        if room > 0:
            buf += chunk[:room]
        if len(chunk) > room:
            truncated = True
    return bytes(buf), truncated


def _exit_code(rc: int) -> int:
    return 128 - rc if rc < 0 else rc


class Sandbox:
    def __init__(
        self,
        sid: str,
        uid: int,
        policy: SandboxPolicy,
        *,
        base_dir: Path = BASE_DIR,
        root: Path = SANDBOX_ROOT,
        bwrap: str = "bwrap",
        ready_timeout_s: float = READY_TIMEOUT_S,
    ) -> None:
        self.sid = sid
        self.uid = uid
        self.policy = policy
        self.base_dir = base_dir
        self.dir = base_dir / sid
        self.work = self.dir / "work"
        self.proxy_dir = self.dir / "proxy"
        self.root = root
        self.bwrap = bwrap
        self.ready_timeout_s = ready_timeout_s
        self._repl: asyncio.subprocess.Process | None = None
        self._client: ReplClient | None = None
        self._stderr_tail = bytearray()
        self._commands: set[asyncio.subprocess.Process] = set()

    @classmethod
    async def create(cls, sid: str, uid: int, policy: SandboxPolicy, **kw) -> Sandbox:
        sbx = cls(sid, uid, policy, **kw)
        try:
            await asyncio.to_thread(sbx._prepare_dirs)
            await sbx._start_repl()
        except BaseException:
            await sbx.destroy()
            raise
        return sbx

    def _prepare_dirs(self) -> None:
        # bwrap runs as the session uid and must traverse to work/ and proxy/.
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.base_dir.chmod(0o711)
        self.dir.mkdir(mode=0o711)
        self.dir.chmod(0o711)
        self.work.mkdir(mode=0o700)
        os.chown(self.work, self.uid, self.uid)
        self.proxy_dir.mkdir(mode=0o755)

    async def _spawn(self, cmd: list[str], env_extra: dict[str, str], keep_fds: tuple[int, ...], **io):
        env = sandbox_env(self.policy) | env_extra
        r, w = os.pipe()
        try:
            os.write(w, compile_filter())
            os.close(w)
            argv = exec_prefix(self.policy, self.uid) + bwrap_argv(
                self.policy,
                work=self.work,
                proxy_dir=self.proxy_dir,
                seccomp_fd=r,
                env=env,
                root=self.root,
                bwrap=self.bwrap,
            ) + LAUNCH + cmd
            return await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.DEVNULL,
                pass_fds=(r, *keep_fds),
                start_new_session=True,
                **io,
            )
        finally:
            os.close(r)

    async def _drain_stderr(self, stream: asyncio.StreamReader) -> None:
        while chunk := await stream.read(65536):
            self._stderr_tail += chunk
            del self._stderr_tail[:-STDERR_TAIL]

    async def _start_repl(self) -> None:
        (app_repl, app_ctl), (child_repl, child_ctl) = socketpairs()
        try:
            self._repl = await self._spawn(
                REPL,
                {"REPL_FD": str(child_repl.fileno()), "REPL_CTL_FD": str(child_ctl.fileno())},
                (child_repl.fileno(), child_ctl.fileno()),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
        finally:
            child_repl.close()
            child_ctl.close()
        asyncio.get_running_loop().create_task(self._drain_stderr(self._repl.stderr))
        self._client = ReplClient(app_repl, app_ctl)
        try:
            await self._client.wait_ready(self.ready_timeout_s)
        except SandboxNotReady as e:
            await self._stop_repl()
            await asyncio.sleep(0.1)  # let the stderr drain catch the last words
            tail = self._stderr_tail.decode(errors="replace").strip()
            raise SandboxError(f"sandbox did not start: {e}: {tail}") from None

    async def _kill(self, proc: asyncio.subprocess.Process) -> None:
        # The outer bwrap leads the process group; --die-with-parent then takes
        # down the sandbox's pid namespace with it.
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signal.SIGKILL)
        await proc.wait()

    async def _stop_repl(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None
        if self._repl is not None:
            await self._kill(self._repl)
            self._repl = None

    async def run_code(self, code: str, timeout_s: float, reset: bool = False) -> dict:
        if self._client is None:
            raise SandboxError("sandbox is not running")
        if reset:
            r = await self._client.reset()
            if r["restart_required"]:
                await self._restart()
        r = await self._client.run(code, timeout_s)
        restarted = r.pop("restart_required")
        if restarted:
            await self._restart()
        r["kernel_restarted"] = restarted
        return r

    async def _restart(self) -> None:
        await self._stop_repl()
        await self._start_repl()

    async def run_command(self, command: str, timeout_s: float) -> dict:
        proc = await self._spawn(
            ["/bin/sh", "-c", command],
            {},
            (),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._commands.add(proc)
        readers = asyncio.gather(
            _read_capped(proc.stdout, OUT_LIMIT), _read_capped(proc.stderr, OUT_LIMIT)
        )
        error = None
        try:
            await asyncio.wait_for(proc.wait(), timeout_s)
        except TimeoutError:
            error = "TimeoutError"
            await self._kill(proc)
        finally:
            self._commands.discard(proc)
        (out, out_trunc), (err, err_trunc) = await readers
        return {
            "stdout": out.decode(errors="replace"),
            "stderr": err.decode(errors="replace"),
            "exit_code": None if error else _exit_code(proc.returncode),
            "error": error,
            "truncated": out_trunc or err_trunc,
        }

    async def destroy(self) -> None:
        await self._stop_repl()
        for proc in list(self._commands):
            await self._kill(proc)
        await asyncio.to_thread(shutil.rmtree, self.dir, True)
