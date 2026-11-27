"""ReplClient against the real Node REPL server — local processes, no bwrap.

The fixture plays the sandbox layer's part: it starts the server and, when
the client reports restart_required, kills and starts a fresh one. Needs
Node 22+ ($CI_NODE or node on PATH); skipped otherwise.
"""

import asyncio
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

import replclient
from replclient import MAX_MSG, ReplClient, SandboxNotReady, socketpairs

SERVER = Path(__file__).resolve().parents[2] / "ci" / "repl" / "server.mjs"


def find_node() -> str | None:
    node = os.environ.get("CI_NODE") or shutil.which("node")
    if not node:
        return None
    out = subprocess.run([node, "--version"], capture_output=True, text=True).stdout
    m = re.match(r"v(\d+)\.", out)
    return node if m and int(m.group(1)) >= 22 else None


NODE = find_node()
needs_node = pytest.mark.skipif(NODE is None, reason="needs Node 22+ (CI_NODE or node on PATH)")


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
            CI_PYTHON=sys.executable,
        )
        self.proc = subprocess.Popen(
            [NODE, "--disable-warning=ExperimentalWarning", str(SERVER)],
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
            os.killpg(self.proc.pid, signal.SIGKILL)  # the REPL and its ctl helper
        except (ProcessLookupError, PermissionError):
            pass  # already exited on EOF (macOS reports EPERM for a dead group)
        self.proc.wait()

    def __call__(self, code: str, timeout: float = 10) -> dict:
        r = self.do(self.client.run(code, timeout_s=timeout))
        if r.get("restart_required"):
            self.kill()
            self.start()
        return r

    def close(self) -> None:
        self.kill()
        self.loop.close()


@pytest.fixture
def repl():
    if NODE is None:
        pytest.skip("needs Node 22+ (CI_NODE or node on PATH)")
    r = Repl()
    yield r
    r.close()


def test_variables_persist_between_calls(repl):
    assert repl("const x = 1")["error"] is None
    r = repl("console.log(x)")
    assert r["stdout"] == "1\n"
    assert r["restart_required"] is False


def test_last_expression_is_returned(repl):
    assert repl("1 + 1")["result"] == "2"
    assert repl("'a'")["result"] == "a"  # strings as they are
    assert repl("({a: [1, 2]})")["result"] == '{"a":[1,2]}'
    assert repl("new Map([[1, 2]])")["result"] == "Map(1) { 1 => 2 }"


def test_no_result_when_last_statement_is_not_an_expression(repl):
    assert repl("let y = 2")["result"] is None
    assert repl("undefined")["result"] is None
    assert repl("null")["result"] == "null"


def test_top_level_await_and_awaited_result(repl):
    assert repl("await new Promise((r) => setTimeout(() => r(5), 50))")["result"] == "5"
    assert repl("Promise.resolve('later')")["result"] == "later"


def test_exception_reports_name_and_stack_and_keeps_state(repl):
    repl("const z = 5")
    r = repl("null.x")
    assert r["error"] == "TypeError"
    assert "TypeError" in r["stderr"] and "<cell-" in r["stderr"]
    assert "server.mjs" not in r["stderr"] and "transform.mjs" not in r["stderr"]
    assert repl("z")["result"] == "5"


def test_syntax_error_is_reported(repl):
    r = repl("const = 1")
    assert r["error"] == "SyntaxError" and "(1:6)" in r["stderr"]


def test_stderr_is_captured_separately(repl):
    r = repl("console.log('out'); console.error('err')")
    assert r["stdout"] == "out\n"
    assert r["stderr"] == "err\n"


def test_timeout_interrupts_a_sync_loop_and_keeps_variables(repl):
    repl("const keep = 42")
    pid = repl.proc.pid
    r = repl("while (true) {}", timeout=1)
    assert r["error"] == "TimeoutError"
    assert r["restart_required"] is False
    assert repl.proc.pid == pid
    assert repl("keep")["result"] == "42"


def test_timeout_ends_a_cell_waiting_on_a_promise(repl):
    repl("const keep = 'x'")
    r = repl("await new Promise(() => {})", timeout=1)
    assert r["error"] == "TimeoutError" and r["restart_required"] is False
    assert repl("keep")["result"] == "x"


def test_loop_after_await_requires_restart(repl):
    repl("const lost = 1")
    r = repl("await null; while (true) {}", timeout=1)
    assert r["error"] == "TimeoutError"
    assert r["restart_required"] is True
    assert repl("lost")["error"] == "ReferenceError"


def test_server_death_requires_restart(repl):
    r = repl("process.kill(process.pid, 'SIGKILL')")
    assert r["error"] == "KernelDied"
    assert r["restart_required"] is True
    assert repl("1")["result"] == "1"


def test_stdout_is_truncated(repl):
    r = repl("console.log('a'.repeat(20000))")
    assert len(r["stdout"]) == 16000
    assert r["truncated"] is True


def test_result_is_capped(repl):
    r = repl("'b'.repeat(10000)")
    assert len(r["result"]) == 4000
    assert r["truncated"] is True


def test_process_exit_does_not_kill_server(repl):
    pid = repl.proc.pid
    assert repl("process.exit(3)")["error"] == "SystemExit"
    assert repl.proc.pid == pid
    assert repl("2")["result"] == "2"


def test_interrupt_while_idle_is_harmless(repl):
    repl("const still = 'here'")
    repl.do(repl.client.interrupt())
    assert repl("still")["result"] == "here"


def test_error_from_abandoned_async_work_is_reported_with_the_next_cell(repl):
    repl("setTimeout(() => { throw new RangeError('later') }, 10); 1")
    repl.do(asyncio.sleep(0.2))
    r = repl("2")
    assert r["result"] == "2" and "RangeError: later" in r["stderr"]


def test_require_reaches_node_builtins(repl):
    assert repl("require('node:path').join('a', 'b')")["result"] == "a/b"


def test_shell_result_shows_exit_and_output(repl):
    assert repl("await $`echo hi`")["result"] == '{"exitCode":0,"stdout":"hi\\n","stderr":""}'


def test_promises_in_a_returned_object_are_awaited(repl):
    r = repl("({a: $`echo a`.text(), b: Promise.resolve(2), c: 3})")
    assert r["result"] == '{"a":"a\\n","b":2,"c":3}'


def test_failing_command_is_a_shell_error(repl):
    r = repl("await $`exit 5`")
    assert r["error"] == "ShellError" and "exit code 5" in r["stderr"]


def test_log_writes_to_stdout(repl):
    assert repl("log('a', 1, {b: 2})")["stdout"] == "a 1 { b: 2 }\n"


class FakeCalls:
    def __init__(self) -> None:
        self.seen, self.refused, self.inflight, self.peak = [], [], 0, 0

    async def call(self, op, args):
        self.seen.append((op, args))
        self.inflight += 1
        self.peak = max(self.peak, self.inflight)
        try:
            await asyncio.sleep(0.05)
            if op == "share.import" and args.get("share_path") == "bad":
                raise replclient.RpcError("ShareError", "points outside /share")
            return {"op": op, "args": args}
        finally:
            self.inflight -= 1

    def rejected(self, reason):
        self.refused.append(reason)


def run_with(repl, code, calls, timeout=10):
    return repl.do(repl.client.run(code, timeout_s=timeout, rpc=calls))


def test_share_calls_reach_the_app_and_return_values(repl):
    calls = FakeCalls()
    r = run_with(repl, "await share.list('sub')", calls)
    assert r["result"] == '{"op":"share.list","args":{"path":"sub"}}'
    r = run_with(repl, "(await share.import('a.csv', 'b.csv')).args", calls)
    assert r["result"] == '{"share_path":"a.csv","dest":"b.csv"}'


def test_app_errors_reach_the_cell_with_their_name(repl):
    r = run_with(repl, "await share.import('bad').catch((e) => e.name + ': ' + e.message)", FakeCalls())
    assert r["result"] == "ShareError: points outside /share"


def test_calls_run_at_most_four_at_a_time(repl):
    calls = FakeCalls()
    r = run_with(repl, "(await Promise.all(Array.from({length: 10}, (_, i) => share.list(String(i))))).length", calls)
    assert r["result"] == "10" and calls.peak == 4


def test_call_tagged_with_another_request_is_refused(repl):
    calls = FakeCalls()
    code = (
        "const b = Buffer.from(JSON.stringify({rpc: {id: 99, cell: 12345, op: 'share.list', args: {}}}));\n"
        "const h = Buffer.alloc(4); h.writeUInt32BE(b.length);\n"
        "require('fs').writeSync(Number(process.env.REPL_FD), Buffer.concat([h, b]));\n"
        "await sleep(200); 'done'"
    )
    r = run_with(repl, code, calls)
    assert r["result"] == "done" and calls.seen == [] and calls.refused == ["call from another request"]


def test_ha_proxy_maps_domain_and_tool_to_a_call(repl):
    calls = FakeCalls()
    r = run_with(repl, "(await ha.intent.HassTurnOff({name: 'Kitchen'})).args", calls)
    assert r["result"] == '{"api":"assist","name":"intent__HassTurnOff","args":{"name":"Kitchen"}}'
    r = run_with(repl, "[(await ha.tools()).op, (await ha.call('x__y')).args.name]", calls)
    assert r["result"] == '["ha.list","x__y"]'


def test_ha_admin_exists_only_in_an_admins_cell(repl):
    calls = FakeCalls()
    r = repl.do(repl.client.run("typeof ha.admin", timeout_s=10, rpc=calls))
    assert r["result"] == "undefined"
    r = repl.do(repl.client.run("(await ha.admin.trace.get_trace({})).args.api", timeout_s=10, rpc=calls,
                                ctx={"admin": True}))
    assert r["result"] == "homeassistant"
    assert repl.do(repl.client.run("typeof ha.admin", timeout_s=10, rpc=calls))["result"] == "undefined"


def test_ha_namespaces_are_not_thenables(repl):
    assert repl("const d = await ha.intent; typeof d.HassTurnOn")["result"] == "function"


def test_calls_without_a_handler_are_refused(repl):
    r = repl("await share.list().catch((e) => e.name)")
    assert r["result"] == "RpcRejected"


def test_timeout_kills_running_shell_commands(repl):
    marker = os.path.join(repl.sandbox_dir, "marker")
    r = repl("await $`sleep 2; touch marker`", timeout=0.5)
    assert r["error"] == "TimeoutError" and r["restart_required"] is False
    repl.do(asyncio.sleep(2.5))
    assert not os.path.exists(marker)
    assert repl("await $`echo ok`.text()")["result"] == "ok\n"


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
        "const head = Buffer.alloc(4); head.writeUInt32BE(%d);\n"
        "require('fs').writeSync(Number(process.env.REPL_FD), head);\n"
        "await new Promise((r) => setTimeout(r, 5000))" % (MAX_MSG + 1)
    )
    r = repl(code)
    assert r["error"] == "KernelDied"
    assert r["restart_required"] is True


def test_forged_reply_without_the_request_id_is_ignored(repl):
    code = (
        "const b = Buffer.from(JSON.stringify({stdout: 'forged', result: '1'}));\n"
        "const h = Buffer.alloc(4); h.writeUInt32BE(b.length);\n"
        "require('fs').writeSync(Number(process.env.REPL_FD), Buffer.concat([h, b]));\n"
        "'real'"
    )
    r = repl(code)
    assert r["result"] == "real" and r["stdout"] == ""


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


def test_command_killed_by_signal_maps_to_128_plus_signal(repl):
    r = repl.do(repl.client.command("kill -TERM $$", timeout_s=10))
    assert r["exit_code"] == 128 + signal.SIGTERM and r["error"] is None


def test_cancelled_request_does_not_leak_its_reply_into_the_next(repl):
    async def go():
        task = asyncio.ensure_future(repl.client.run(
            "await new Promise((r) => setTimeout(r, 1000)); 'late'", timeout_s=30))
        await asyncio.sleep(0.2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return await repl.client.run("'next'", timeout_s=10)

    assert repl.do(go())["result"] == "next"


def test_command_runs_in_sandbox_dir_even_after_chdir(repl):
    repl("process.chdir('/')")
    r = repl.do(repl.client.command("pwd", timeout_s=10))
    assert os.path.realpath(r["stdout"].strip()) == os.path.realpath(repl.sandbox_dir)


def test_command_with_detached_grandchild_is_not_a_timeout(repl):
    # The grandchild keeps the pipes open; the command itself exits at once.
    r = repl.do(repl.client.command("(sleep 30 &) ; echo done", timeout_s=2))
    assert r["error"] is None and r["exit_code"] == 0 and r["stdout"].startswith("done")
