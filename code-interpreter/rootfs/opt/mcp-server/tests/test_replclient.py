"""ReplClient against the real REPL server — local processes, no bwrap.

The fixture plays the sandbox layer's part: it starts the server and, when
the client reports restart_required, kills and starts a fresh one.
"""

import asyncio
import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

import replclient
from replclient import MAX_MSG, ReplClient, SandboxNotReady, socketpairs

SERVER = Path(__file__).resolve().parents[2] / "ci" / "repl" / "server.py"


class Repl:
    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.proc: subprocess.Popen | None = None
        self.client: ReplClient | None = None
        self.start()

    def start(self) -> None:
        (app_repl, app_ctl), (child_repl, child_ctl) = socketpairs()
        self.sandbox_dir = tempfile.mkdtemp(prefix="sbx-")
        env = dict(
            os.environ,
            REPL_FD=str(child_repl.fileno()),
            REPL_CTL_FD=str(child_ctl.fileno()),
            CI_SANDBOX_DIR=self.sandbox_dir,
        )
        self.proc = subprocess.Popen(
            [sys.executable, str(SERVER)],
            env=env,
            pass_fds=(child_repl.fileno(), child_ctl.fileno()),
            start_new_session=True,
        )
        child_repl.close()
        child_ctl.close()
        self.client = ReplClient(app_repl, app_ctl, grace_s=1)
        self.do(self.client.wait_ready(timeout_s=10))

    def do(self, coro):
        return self.loop.run_until_complete(coro)

    def kill(self) -> None:
        self.client.close()
        try:
            os.killpg(self.proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass  # already exited on EOF (macOS reports EPERM for a dead group)
        self.proc.wait()

    def __call__(self, code: str, timeout: float = 10) -> dict:
        r = self.do(self.client.run(code, timeout_s=timeout))
        if r.get("restart_required"):
            self.kill()
            self.start()
        return r

    def reset(self) -> dict:
        return self.do(self.client.reset())

    def close(self) -> None:
        self.kill()
        self.loop.close()


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
    assert repl.do(repl.client.interrupt()) is False
    assert repl("still")["result"] == "'here'"


def test_wait_ready_fails_closed_when_peer_is_gone():
    (app_repl, app_ctl), (child_repl, child_ctl) = socketpairs()
    child_repl.close()
    child_ctl.close()
    client = ReplClient(app_repl, app_ctl)
    with pytest.raises(SandboxNotReady):
        asyncio.run(client.wait_ready(timeout_s=1))


def test_wait_ready_times_out_when_peer_is_silent():
    (app_repl, app_ctl), child = socketpairs()
    client = ReplClient(app_repl, app_ctl)
    with pytest.raises(SandboxNotReady):
        asyncio.run(client.wait_ready(timeout_s=0.3))
    for s in child:
        s.close()


def test_forged_oversized_reply_is_rejected_as_kernel_death(repl):
    code = (
        "import os, struct\n"
        "os.write(int(os.environ['REPL_FD']), struct.pack('>I', %d))\n"
        "import time; time.sleep(5)" % (MAX_MSG + 1)
    )
    r = repl(code)
    assert r["error"] == "KernelDied"
    assert r["restart_required"] is True


def test_forged_reply_without_the_request_id_is_ignored(repl):
    code = (
        "import os, json, struct\n"
        "b = json.dumps({'stdout': 'forged', 'result': '1'}).encode()\n"
        "os.write(int(os.environ['REPL_FD']), struct.pack('>I', len(b)) + b)\n"
        "'real'"
    )
    r = repl(code)
    assert r["result"] == "'real'" and r["stdout"] == ""


def test_merge_keeps_only_known_fields():
    out = replclient._merge({"error": None}, {"stdout": "x", "restart_required": False, "evil": 1},
                            replclient._CODE_KEYS)
    assert out == {"error": None, "stdout": "x"}


def test_command_runs_with_exit_code_and_stderr(repl):
    r = repl.do(repl.client.command("echo out; echo err >&2; exit 4", timeout_s=10))
    assert (r["stdout"], r["stderr"], r["exit_code"], r["error"]) == ("out\n", "err\n", 4, None)
    assert "result" not in r


def test_command_timeout_kills_its_process_group(repl):
    r = repl.do(repl.client.command("sleep 30 & sleep 30", timeout_s=1))
    assert r["error"] == "TimeoutError" and r["exit_code"] is None and not r["restart_required"]
    assert repl("1")["result"] == "1"


def test_command_output_is_capped(repl):
    r = repl.do(repl.client.command("yes | head -c 100000", timeout_s=10))
    assert len(r["stdout"]) == 16000 and r["truncated"] is True


def test_cancelled_request_does_not_leak_its_reply_into_the_next(repl):
    async def go():
        task = asyncio.ensure_future(repl.client.run("import time; time.sleep(1); 'late'", timeout_s=30))
        await asyncio.sleep(0.2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return await repl.client.run("'next'", timeout_s=10)

    assert repl.do(go())["result"] == "'next'"


def test_command_runs_in_sandbox_dir_even_after_chdir(repl):
    repl("import os; os.chdir('/')")
    r = repl.do(repl.client.command("pwd", timeout_s=10))
    assert os.path.realpath(r["stdout"].strip()) == os.path.realpath(repl.sandbox_dir)


def test_command_with_detached_grandchild_is_not_a_timeout(repl):
    # The grandchild keeps the pipes open; the command itself exits at once.
    r = repl.do(repl.client.command("(sleep 30 &) ; echo done", timeout_s=2))
    assert r["error"] is None and r["exit_code"] == 0 and r["stdout"].startswith("done")


def test_command_spawn_failure_is_an_error_not_a_dead_kernel(repl):
    """EAGAIN from fork under RLIMIT_NPROC must not take the variables with it."""
    repl("keep = 7")
    repl("import subprocess\n"
         "def _no_fork(*a, **k):\n"
         "    raise BlockingIOError(11, 'Resource temporarily unavailable')\n"
         "subprocess.Popen = _no_fork")
    r = repl.do(repl.client.command("true", timeout_s=10))
    assert r["error"] == "BlockingIOError" and r["exit_code"] is None
    assert not r["restart_required"]
    assert repl("keep")["result"] == "7"


def test_command_reader_thread_failure_is_an_error_not_a_dead_kernel(repl):
    repl("keep = 7")
    repl("import threading\n"
         "def _no_thread(self):\n"
         "    raise RuntimeError(\"can't start new thread\")\n"
         "threading.Thread.start = _no_thread")
    r = repl.do(repl.client.command("sleep 30", timeout_s=10))
    assert r["error"] == "RuntimeError" and r["exit_code"] is None
    assert not r["restart_required"]
    assert repl("keep")["result"] == "7"


def test_interrupt_while_formatting_a_traceback_keeps_the_server(repl):
    """SIGINT landing in the except handler (the timeout racing a failing cell)."""
    repl("keep = 7")
    r = repl("import os, signal, time, traceback\n"
             "_orig = traceback.TracebackException.from_exception\n"
             "def _slow(*a, **k):\n"
             "    os.kill(os.getpid(), signal.SIGINT)\n"
             "    time.sleep(0.2)\n"
             "    return _orig(*a, **k)\n"
             "traceback.TracebackException.from_exception = _slow\n"
             "raise ValueError('boom')")
    assert r["error"] == "ValueError" and not r["restart_required"]
    assert repl("keep")["result"] == "7"
