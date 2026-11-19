"""REPL server/client tests — real local processes, no Docker."""

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

REPL_DIR = Path(__file__).resolve().parent.parent


@pytest.fixture
def repl():
    # Short dir: AF_UNIX paths are capped at 104 bytes on macOS.
    tmp_path = Path(tempfile.mkdtemp(prefix="repl-", dir="/tmp"))
    env = dict(
        os.environ,
        REPL_SOCK=str(tmp_path / "repl.sock"),
        REPL_PID=str(tmp_path / "repl.pid"),
        REPL_GRACE_S="1",
    )
    proc = subprocess.Popen(
        ["sh", str(REPL_DIR / "init.sh")], env=env, start_new_session=True
    )
    deadline = time.time() + 10
    while not (tmp_path / "repl.sock").exists():
        assert time.time() < deadline, "REPL server did not start"
        time.sleep(0.05)

    def run(code: str, timeout: float = 10, reset: bool = False) -> dict:
        args = [sys.executable, str(REPL_DIR / "client.py"), "--timeout", str(timeout)]
        if reset:
            args.append("--reset")
        out = subprocess.run(
            args, input=code, capture_output=True, text=True, env=env, timeout=60
        )
        assert out.returncode == 0, out.stderr
        return json.loads(out.stdout)

    run.pid = lambda: int((tmp_path / "repl.pid").read_text())
    yield run
    os.killpg(proc.pid, signal.SIGKILL)
    proc.wait()
    shutil.rmtree(tmp_path, ignore_errors=True)


def test_variables_persist_between_calls(repl):
    assert repl("x = 1")["error"] is None
    r = repl("print(x)")
    assert r["stdout"] == "1\n"
    assert r["kernel_restarted"] is False


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


def test_timeout_interrupts_and_keeps_variables(repl):
    repl("keep = 42")
    pid = repl.pid()
    r = repl("while True: pass", timeout=1)
    assert r["error"] == "TimeoutError"
    assert r["kernel_restarted"] is False
    assert repl.pid() == pid
    assert repl("keep")["result"] == "42"


def test_sigint_ignoring_code_restarts_kernel(repl):
    repl("lost = 1")
    pid = repl.pid()
    r = repl(
        "import signal\nsignal.signal(signal.SIGINT, signal.SIG_IGN)\nwhile True: pass",
        timeout=1,
    )
    assert r["error"] == "TimeoutError"
    assert r["kernel_restarted"] is True
    assert repl.pid() != pid
    assert repl("lost")["error"] == "NameError"


def test_server_crash_is_reported_as_restart(repl):
    r = repl("import os; os._exit(1)")
    assert r["kernel_restarted"] is True
    assert repl("1")["result"] == "1"


def test_reset_clears_globals(repl):
    repl("gone = 1")
    r = repl("", reset=True)
    assert r["error"] is None
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
    pid = repl.pid()
    assert repl("import sys; sys.exit(3)")["error"] == "SystemExit"
    assert repl.pid() == pid
    assert repl("2")["result"] == "2"


def test_idle_sigint_is_ignored(repl):
    repl("still = 'here'")
    pid = repl.pid()
    os.kill(pid, signal.SIGINT)
    time.sleep(0.2)
    r = repl("still")
    assert r["result"] == "'here'"
    assert repl.pid() == pid
