import asyncio
import json

import pytest

import service
from policy import SandboxPolicy
from sandbox import SandboxError


class FakeSandbox:
    def __init__(self, sid, uid, policy):
        self.sid, self.uid, self.policy = sid, uid, policy
        self.vars = {}
        self.destroyed = False

    async def run_code(self, code, timeout_s, reset=False):
        self.last_timeout = timeout_s
        if reset:
            self.vars.clear()
        if code.startswith("set "):
            k, v = code[4:].split("=")
            self.vars[k] = v
            return {"stdout": "", "stderr": "", "result": None, "error": None,
                    "truncated": False, "kernel_restarted": False}
        result = "2" if code == "1 + 1" else self.vars.get(code)
        return {"stdout": "", "stderr": "", "result": result, "error": None,
                "truncated": False, "kernel_restarted": False}

    async def run_command(self, command, timeout_s):
        return {"stdout": command, "stderr": "", "exit_code": 0, "error": None, "truncated": False}

    async def destroy(self):
        self.destroyed = True


def make(tmp_path, options=None, create=None):
    opts = tmp_path / "options.json"
    opts.write_text(json.dumps(options or {}))
    created = []

    async def default_create(sid, uid, policy, **kw):
        s = FakeSandbox(sid, uid, policy)
        created.append(s)
        return s

    svc = service.Service(service.load_options(opts), create_sandbox=create or default_create,
                          base_dir=tmp_path / "cache")
    return svc, created


def run(coro):
    return asyncio.run(coro)


def test_options_defaults_and_allowlist_cleanup(tmp_path):
    p = tmp_path / "o.json"
    p.write_text(json.dumps({"network_allowlist": ["pypi.org", "", "  ", "*.pythonhosted.org"],
                             "memory_limit_mb": 2048}))
    o = service.load_options(p)
    assert o.idle_timeout_minutes == 20 and o.max_sessions == 3
    assert o.policy == SandboxPolicy(memory_mb=2048, allowlist=("pypi.org", "*.pythonhosted.org"))


def test_missing_options_file_uses_defaults(tmp_path):
    o = service.load_options(tmp_path / "absent.json")
    assert o.policy == SandboxPolicy() and o.max_sessions == 3


def test_run_code_creates_session_and_keeps_state(tmp_path):
    async def go():
        svc, created = make(tmp_path)
        r1 = await svc.run_code("set a=1")
        r2 = await svc.run_code("a", session_id=r1["session_id"])
        assert r2["result"] == "1" and r2["session_id"] == r1["session_id"]
        assert len(created) == 1 and created[0].uid == 60000

    run(go())


def test_unknown_session_is_an_error_with_hint_and_creates_nothing(tmp_path):
    async def go():
        svc, created = make(tmp_path)
        r = await svc.run_code("1", session_id="deadbeefdeadbeef")
        assert r["error"] == "session_not_found" and "without session_id" in r["hint"]
        assert created == []

    run(go())


def test_sandbox_failure_is_reported_not_raised(tmp_path):
    async def broken(sid, uid, policy, **kw):
        raise SandboxError("bwrap: Operation not permitted")

    async def go():
        svc, _ = make(tmp_path, create=broken)
        r = await svc.run_code("1")
        assert r["error"] == "sandbox_unavailable" and "Operation not permitted" in r["detail"]
        assert "session_id" not in r

    run(go())


def test_timeout_is_clamped(tmp_path):
    async def go():
        svc, created = make(tmp_path)
        await svc.run_code("1", timeout_s=10_000)
        assert created[0].last_timeout == service.MAX_TIMEOUT_S
        await svc.run_code("1", timeout_s=0)
        assert created[1].last_timeout == 1

    run(go())


def test_run_command_list_and_close(tmp_path):
    async def go():
        svc, created = make(tmp_path)
        r = await svc.run_command("echo hi")
        sid = r["session_id"]
        assert r["stdout"] == "echo hi"
        listed = svc.list_sessions()
        assert [s["session_id"] for s in listed["sessions"]] == [sid]
        assert 0 < listed["sessions"][0]["expires_in_s"] <= 20 * 60
        assert (await svc.close_session(sid)) == {"closed": sid}
        assert created[0].destroyed
        assert (await svc.close_session(sid))["error"] == "session_not_found"

    run(go())


def test_startup_clears_leftover_session_dirs(tmp_path):
    cache = tmp_path / "cache"
    (cache / "old" / "work").mkdir(parents=True)
    (cache / "old" / "work" / "f").write_text("x")
    svc, _ = make(tmp_path)
    svc.clear_leftovers()
    assert cache.is_dir() and list(cache.iterdir()) == []


def test_shutdown_destroys_all_sessions(tmp_path):
    async def go():
        svc, created = make(tmp_path)
        await svc.run_code("1")
        await svc.run_code("1")
        await svc.shutdown()
        assert all(s.destroyed for s in created)
        assert svc.list_sessions()["sessions"] == []

    run(go())


def test_self_check_reports_ok_and_failure(tmp_path):
    async def go():
        svc, created = make(tmp_path)
        assert (await svc.self_check()) is None
        assert created[0].uid == service.SELF_CHECK_UID and created[0].destroyed

        async def broken(sid, uid, policy, **kw):
            raise SandboxError("no userns")

        svc2, _ = make(tmp_path, create=broken)
        assert "no userns" in await svc2.self_check()

    run(go())
