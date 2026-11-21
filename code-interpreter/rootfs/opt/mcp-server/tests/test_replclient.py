"""ReplClient against the real REPL server — local processes, no bwrap.

The fixture plays the sandbox layer's part: it starts the server and, when
the client reports restart_required, kills and starts a fresh one.
"""

import asyncio
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from replclient import ReplClient, SandboxNotReady

SERVER = Path(__file__).resolve().parents[2] / "ci" / "repl" / "server.py"


class Repl:
    def __init__(self) -> None:
        # Short dir: AF_UNIX paths are capped at 104 bytes on macOS.
        self.dir = Path(tempfile.mkdtemp(prefix="repl-", dir="/tmp"))
        self.client = ReplClient(self.dir, grace_s=1)
        self.proc: subprocess.Popen | None = None
        self.start()

    def start(self) -> None:
        env = dict(
            os.environ,
            REPL_SOCK=str(self.dir / "repl.sock"),
            REPL_CTL=str(self.dir / "ctl.sock"),
        )
        self.proc = subprocess.Popen(
            [sys.executable, str(SERVER)], env=env, start_new_session=True
        )
        asyncio.run(self.client.wait_ready(timeout_s=10))

    def kill(self) -> None:
        if self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGKILL)
        self.proc.wait()

    def __call__(self, code: str, timeout: float = 10) -> dict:
        r = asyncio.run(self.client.run(code, timeout_s=timeout))
        if r.get("restart_required"):
            self.kill()
            self.start()
        return r

    def reset(self) -> dict:
        return asyncio.run(self.client.reset())

    def close(self) -> None:
        self.kill()
        shutil.rmtree(self.dir, ignore_errors=True)


@pytest.fixture
def repl():
    r = Repl()
    yield r
    r.close()


def test_variables_persist_between_calls(repl):
    assert repl("x = 1")["error"] is None
    r = repl("print(x)")
    assert r["stdout"] == "1\n"
    assert r["restart_required"] is False


def test_last_expression_is_returned_as_repr(repl):
    assert repl("1 + 1")["result"] == "2"
    assert repl("'a'")["result"] == "'a'"


def test_no_result_when_last_statement_is_not_an_expression(repl):
    assert repl("y = 2")["result"] is None
    assert repl("None")["result"] is None


def test_exception_reports_name_and_traceback_and_keeps_state(repl):
    repl("z = 5")
    r = repl("1 / 0")
    assert r["error"] == "ZeroDivisionError"
    assert "ZeroDivisionError" in r["stderr"]
    assert "server.py" not in r["stderr"]
    assert repl("z")["result"] == "5"


def test_stderr_is_captured_separately(repl):
    r = repl("import sys; print('out'); print('err', file=sys.stderr)")
    assert r["stdout"] == "out\n"
    assert r["stderr"] == "err\n"


def test_timeout_interrupts_via_control_socket_and_keeps_variables(repl):
    repl("keep = 42")
    pid = repl.proc.pid
    r = repl("while True: pass", timeout=1)
    assert r["error"] == "TimeoutError"
    assert r["restart_required"] is False
    assert repl.proc.pid == pid
    assert repl("keep")["result"] == "42"


def test_sigint_ignoring_code_requires_restart(repl):
    repl("lost = 1")
    r = repl(
        "import signal\nsignal.signal(signal.SIGINT, signal.SIG_IGN)\nwhile True: pass",
        timeout=1,
    )
    assert r["error"] == "TimeoutError"
    assert r["restart_required"] is True
    assert repl("lost")["error"] == "NameError"


def test_server_death_requires_restart(repl):
    r = repl("import os; os._exit(1)")
    assert r["error"] == "KernelDied"
    assert r["restart_required"] is True
    assert repl("1")["result"] == "1"


def test_reset_clears_globals(repl):
    repl("gone = 1")
    assert repl.reset()["error"] is None
    assert repl("gone")["error"] == "NameError"


def test_stdout_is_truncated(repl):
    r = repl("print('a' * 20000)")
    assert len(r["stdout"]) == 16000
    assert r["truncated"] is True


def test_result_repr_is_capped(repl):
    r = repl("'b' * 10000")
    assert len(r["result"]) == 4000
    assert r["truncated"] is True


def test_sys_exit_does_not_kill_server(repl):
    pid = repl.proc.pid
    assert repl("import sys; sys.exit(3)")["error"] == "SystemExit"
    assert repl.proc.pid == pid
    assert repl("2")["result"] == "2"


def test_interrupt_while_idle_is_ignored(repl):
    repl("still = 'here'")
    assert asyncio.run(repl.client.interrupt()) is False
    assert repl("still")["result"] == "'here'"


def test_wait_ready_fails_closed_when_no_server():
    d = Path(tempfile.mkdtemp(prefix="repl-", dir="/tmp"))
    try:
        with pytest.raises(SandboxNotReady):
            asyncio.run(ReplClient(d).wait_ready(timeout_s=0.3))
    finally:
        shutil.rmtree(d, ignore_errors=True)
