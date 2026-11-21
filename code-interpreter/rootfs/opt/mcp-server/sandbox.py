"""One session's bubblewrap sandbox: REPL lifecycle, commands, teardown (SPEC §3.2-3.4).

One bwrap per session. Inside it, launch.py (the agent) supervises the REPL;
commands run through the REPL, so code, commands, /sandbox, /tmp and HOME
all live in the same namespaces. /sandbox and /tmp are size-capped tmpfs:
nothing a session writes lands on the HA data disk. Restarting a stuck or
dead REPL happens inside the sandbox and keeps the files.

On the app's disk only base_dir/<sid>/proxy/ exists (root, 0755, bound
read-only at /run/ci; proxy.sock when allowlisted).

Fail-closed: if bwrap or the REPL does not come up, create() raises and
nothing runs. There is no code path that executes outside bubblewrap.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import signal
import socket
from pathlib import Path
from typing import Callable

import egress
from policy import SANDBOX_ROOT, SandboxPolicy, bwrap_argv, exec_prefix, sandbox_env
from replclient import ReplClient, SandboxNotReady, socketpairs
from seccomp import compile_filter

BASE_DIR = Path("/var/cache/code-interpreter")
PY = "/opt/venv/bin/python3"
SANDBOX_CMD = [PY, "/opt/ci/launch.py", PY, "-u", "/opt/ci/repl/server.py"]
STDERR_TAIL = 4096
READY_TIMEOUT_S = 30.0
AGENT_TIMEOUT_S = 10.0


class SandboxError(RuntimeError):
    pass


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
        on_net_event: Callable[[dict], None] | None = None,
    ) -> None:
        self.sid = sid
        self.uid = uid
        self.policy = policy
        self.base_dir = base_dir
        self.dir = base_dir / sid
        self.proxy_dir = self.dir / "proxy"
        self.root = root
        self.bwrap = bwrap
        self.ready_timeout_s = ready_timeout_s
        self._proc: asyncio.subprocess.Process | None = None
        self._agent: socket.socket | None = None
        self._agent_lock = asyncio.Lock()
        self._client: ReplClient | None = None
        self._stderr_tail = bytearray()
        self._on_net_event = on_net_event
        self._proxy: asyncio.Server | None = None
        # Set first thing in destroy(): no REPL may start after it.
        self._closed = False

    @classmethod
    async def create(cls, sid: str, uid: int, policy: SandboxPolicy, **kw) -> Sandbox:
        sbx = cls(sid, uid, policy, **kw)
        try:
            await asyncio.to_thread(sbx._prepare_dirs)
            await sbx._start_proxy()
            await sbx._start()
        except BaseException:
            await sbx.destroy()
            raise
        return sbx

    def _prepare_dirs(self) -> None:
        # bwrap runs as the session uid and must traverse to proxy/.
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.base_dir.chmod(0o711)
        self.dir.mkdir(mode=0o711)
        self.dir.chmod(0o711)
        self.proxy_dir.mkdir(mode=0o755)

    async def _start_proxy(self) -> None:
        """Only with an allowlist: no socket means no way out of the sandbox."""
        if not self.policy.allowlist:
            return

        def log(entry: dict) -> None:
            if self._on_net_event:
                self._on_net_event({"session_id": self.sid, **entry})

        self._proxy = await egress.serve_unix(
            str(self.proxy_dir / "proxy.sock"),
            egress.parse_allowlist(list(self.policy.allowlist)),
            log=log,
            owner=self.uid,
        )

    async def _drain_stderr(self, stream: asyncio.StreamReader) -> None:
        while chunk := await stream.read(65536):
            self._stderr_tail += chunk
            del self._stderr_tail[:-STDERR_TAIL]

    def _failure(self, what: str) -> SandboxError:
        tail = self._stderr_tail.decode(errors="replace").strip()
        return SandboxError(f"{what}: {tail}" if tail else what)

    async def _start(self) -> None:
        """Spawn the session's one bwrap: agent + first REPL."""
        (app_repl, app_ctl), (child_repl, child_ctl) = socketpairs()
        app_agent, child_agent = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        children = (child_repl, child_ctl, child_agent)
        for s in children:
            s.set_inheritable(True)
        r, w = os.pipe()
        try:
            try:
                os.write(w, compile_filter())
            finally:
                os.close(w)
            env = sandbox_env(self.policy) | {
                "REPL_FD": str(child_repl.fileno()),
                "REPL_CTL_FD": str(child_ctl.fileno()),
                "CI_AGENT_FD": str(child_agent.fileno()),
            }
            argv = exec_prefix(self.policy, self.uid) + bwrap_argv(
                self.policy, proxy_dir=self.proxy_dir, seccomp_fd=r, env=env,
                root=self.root, bwrap=self.bwrap,
            ) + SANDBOX_CMD
            self._proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
                pass_fds=(r, *(s.fileno() for s in children)),
                start_new_session=True,
            )
        except BaseException:
            for s in (app_repl, app_ctl, app_agent):
                s.close()
            raise
        finally:
            os.close(r)
            for s in children:
                s.close()
        self._agent = app_agent
        asyncio.get_running_loop().create_task(self._drain_stderr(self._proc.stderr))
        await self._attach(ReplClient(app_repl, app_ctl), "sandbox did not start")

    async def _attach(self, client: ReplClient, what: str) -> None:
        self._client = client
        try:
            await client.wait_ready(self.ready_timeout_s)
        except SandboxNotReady as e:
            await asyncio.sleep(0.1)  # let the stderr drain catch the last words
            raise self._failure(f"{what}: {e}") from None

    def _agent_call(self, req: dict, fds: list[int]) -> dict:
        """Blocking request on the SOCK_SEQPACKET agent channel (run in a thread)."""
        self._agent.settimeout(AGENT_TIMEOUT_S)
        socket.send_fds(self._agent, [json.dumps(req).encode()], fds)
        data = self._agent.recv(4096)
        if not data:
            raise ConnectionError("agent closed")
        return json.loads(data)

    async def _restart_repl(self) -> None:
        """Fresh REPL in the same sandbox: variables go, files stay."""
        if self._closed or self._agent is None:
            raise SandboxError("sandbox is closed")
        if self._client is not None:
            self._client.close()
            self._client = None
        (app_repl, app_ctl), (child_repl, child_ctl) = socketpairs()
        try:
            async with self._agent_lock:
                reply = await asyncio.to_thread(
                    self._agent_call, {"op": "restart"}, [child_repl.fileno(), child_ctl.fileno()]
                )
        except (OSError, ValueError) as e:
            app_repl.close()
            app_ctl.close()
            raise self._failure(f"sandbox is gone, its files are lost ({e})") from None
        finally:
            child_repl.close()
            child_ctl.close()
        if not reply.get("ok"):
            app_repl.close()
            app_ctl.close()
            raise self._failure("sandbox refused the REPL restart")
        await self._attach(ReplClient(app_repl, app_ctl), "REPL did not restart")

    async def _with_restart(self, call) -> dict:
        if self._client is None:
            raise SandboxError("sandbox is not running")
        r = await call(self._client)
        restarted = r.pop("restart_required")
        if restarted and not self._closed:
            await self._restart_repl()
        r["kernel_restarted"] = restarted
        return r

    async def run_code(self, code: str, timeout_s: float, reset: bool = False) -> dict:
        if reset:
            await self._with_restart(lambda c: c.reset())
        return await self._with_restart(lambda c: c.run(code, timeout_s))

    async def run_command(self, command: str, timeout_s: float) -> dict:
        return await self._with_restart(lambda c: c.command(command, timeout_s))

    async def destroy(self) -> None:
        self._closed = True
        if self._client is not None:
            self._client.close()
            self._client = None
        if self._agent is not None:
            self._agent.close()
            self._agent = None
        if self._proc is not None:
            # The outer bwrap leads the process group; --die-with-parent then
            # takes down the sandbox's pid namespace (and its tmpfs) with it.
            # Never signal a pid asyncio has already reaped: it may be reused.
            if self._proc.returncode is None:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.killpg(self._proc.pid, signal.SIGKILL)
            await self._proc.wait()
            self._proc = None
        if self._proxy is not None:
            await egress.close(self._proxy)
            self._proxy = None
        await asyncio.to_thread(shutil.rmtree, self.dir, True)
