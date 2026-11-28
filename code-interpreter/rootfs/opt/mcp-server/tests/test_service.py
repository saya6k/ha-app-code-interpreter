import asyncio
import dataclasses
import json

import pytest

from pathlib import Path

import hab
import hamcp
import replclient
import service
from skills import SkillError, SkillReviewer, SkillStore
from skills import find as skills_find
from audit import Audit
from policy import SandboxPolicy
from sandbox import FileOpError, SandboxError


class FakeSandbox:
    def __init__(self, sid, uid, policy):
        self.sid, self.uid, self.policy = sid, uid, policy
        self.vars = {}
        self.files = {}
        self.destroyed = False

    async def run_code(self, code, timeout_s, reset=False, rpc=None, ctx=None):
        self.last_ctx = ctx
        self.last_timeout = timeout_s
        if code.startswith("call "):  # call <op> <json args>: what the cell's share.* would send
            op, args = code[5:].split(" ", 1)
            try:
                result = json.dumps(await rpc.call(op, json.loads(args)))
                error = None
            except replclient.RpcError as e:
                result, error = None, f"{e.name}: {e}"
            return {"logs": "", "result": result, "error": error, "message": None,
                    "truncated": False, "kernel_restarted": False}
        if reset:
            self.vars.clear()
        if code.startswith("touch "):
            for name in code[6:].split():
                self.files["/sandbox/" + name] = b"x"
            code = "set _=1"
        if code.startswith("set "):
            k, v = code[4:].split("=")
            self.vars[k] = v
            return {"logs": "", "result": None, "error": None, "message": None,
                    "truncated": False, "kernel_restarted": False}
        result = "2" if code == "1 + 1" else self.vars.get(code)
        return {"logs": "", "result": result, "error": None, "message": None,
                "truncated": False, "kernel_restarted": False}

    async def list_files(self, path="/sandbox", recursive=False, skip_dot=False):
        if getattr(self, "list_fails", False):
            raise FileOpError("PermissionError: listing failed")
        entries = [{"path": p, "type": "file", "size": len(d), "mtime": 0} for p, d in sorted(self.files.items())]
        return {"entries": entries, "truncated": False}

    async def read_file(self, path, limit):
        if path not in self.files:
            raise FileOpError(f"{path} missing")
        d = self.files[path]
        return d[:limit], len(d)

    async def write_file(self, path, data, max_bytes):
        if len(data) > max_bytes:
            raise FileOpError("too large")
        p = path if path.startswith("/sandbox/") else "/sandbox/" + path
        self.files[p] = data
        return {"path": p, "size": len(data)}

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

    share = tmp_path / "share"
    share.mkdir(exist_ok=True)
    o = service.load_options(opts)
    o = dataclasses.replace(o, export_dir=share / "code-interpreter")
    svc = service.Service(o, create_sandbox=create or default_create,
                          base_dir=tmp_path / "cache", share_root=share, audit=Audit(tmp_path / "audit"))
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


def test_list_and_close(tmp_path):
    async def go():
        svc, created = make(tmp_path)
        sid = (await svc.run_code("1 + 1"))["session_id"]
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


def test_invalid_allowlist_entry_is_dropped_and_logged(tmp_path, caplog):
    p = tmp_path / "o.json"
    p.write_text(json.dumps({"network_allowlist": ["https://pypi.org", "pypi.org"]}))
    with caplog.at_level("ERROR"):
        o = service.load_options(p)
    assert o.policy.allowlist == ("pypi.org",)
    assert "https://pypi.org" in caplog.text


def test_export_dir_outside_share_falls_back(tmp_path, caplog):
    p = tmp_path / "o.json"
    p.write_text(json.dumps({"export_dir": "/config/out"}))
    with caplog.at_level("ERROR"):
        assert service.load_options(p).export_dir == Path("/share/code-interpreter")
    assert "/config/out" in caplog.text
    p.write_text(json.dumps({"export_dir": "/share/../etc"}))
    assert service.load_options(p).export_dir == Path("/share/code-interpreter")
    p.write_text(json.dumps({"export_dir": "/share/results"}))
    assert service.load_options(p).export_dir == Path("/share/results")


def test_run_code_reports_new_and_changed_files_but_not_dotfiles(tmp_path):
    async def go():
        svc, created = make(tmp_path)
        r = await svc.run_code("touch a.csv .cache/x b.png")
        assert r["new_files"] == ["/sandbox/a.csv", "/sandbox/b.png"]
        r = await svc.run_code("set q=1", session_id=r["session_id"])
        assert r["new_files"] == []

    run(go())


def test_import_export_round_trip_through_a_cell(tmp_path):
    svc, created = make(tmp_path)
    (tmp_path / "share" / "energy.csv").write_text("kwh\n1\n2\n")
    sid = asyncio.run(svc.run_code("1 + 1"))["session_id"]
    r = json.loads(call(svc, sid, "share.import", share_path="energy.csv")["result"])
    assert r == {"path": "/sandbox/energy.csv", "size": 8}
    assert created[0].files["/sandbox/energy.csv"] == b"kwh\n1\n2\n"
    created[0].files["/sandbox/out.txt"] = b"result"
    r = json.loads(call(svc, sid, "share.export", path="/sandbox/out.txt")["result"])
    exported = Path(r["share_path"])
    assert exported == tmp_path / "share" / "code-interpreter" / sid / "out.txt"
    assert exported.read_text() == "result"






def events(tmp_path):
    out = []
    for f in sorted((tmp_path / "audit").glob("audit-*.jsonl")):
        out += [json.loads(x) for x in f.read_text().splitlines()]
    return out


def test_audit_session_lifecycle_and_code_without_output(tmp_path):
    async def go():
        svc, _ = make(tmp_path)
        r = await svc.run_code("set a=secret-output")
        await svc.close_session(r["session_id"])
        return r["session_id"]

    sid = run(go())
    ev = events(tmp_path)
    assert [e["event"] for e in ev] == ["session.create", "code.exec", "session.destroy"]
    assert all(e["session_id"] == sid for e in ev)
    code_ev = ev[1]["detail"]
    assert code_ev["code"] == "set a=secret-output" and len(code_ev["sha256"]) == 64
    assert {"ms", "logs_chars", "kernel_restarted", "timeout"} <= code_ev.keys()
    assert "logs" not in code_ev and "result" not in code_ev  # output is never stored
    assert ev[2]["detail"]["reason"] == "close"


def test_audit_file_events_and_traversal_violation(tmp_path):
    svc, created = make(tmp_path)
    (tmp_path / "share" / "in.csv").write_text("1")
    sid = asyncio.run(svc.run_code("1 + 1"))["session_id"]
    call(svc, sid, "share.import", share_path="in.csv")
    created[0].files["/sandbox/o.txt"] = b"data"
    call(svc, sid, "share.export", path="/sandbox/o.txt")
    call(svc, sid, "share.import", share_path="../etc/passwd")
    ev = events(tmp_path)
    kinds = [(e["event"], e["outcome"]) for e in ev]
    assert ("file.import", "ok") in kinds and ("file.export", "ok") in kinds
    assert ("file.import", "error") in kinds
    viol = [e for e in ev if e["event"] == "policy.violation"]
    assert viol and viol[0]["detail"]["kind"] == "traversal"
    exp = next(e for e in ev if e["event"] == "file.export")
    assert exp["detail"]["share_path"].endswith("/o.txt") and len(exp["detail"]["sha256"]) == 64


def test_audit_net_events_attribute_session_and_flag_denials(tmp_path):
    svc, _ = make(tmp_path)
    svc._net_event({"session_id": "s1", "host": "pypi.org", "port": 443, "allowed": True,
                    "bytes_up": 10, "bytes_down": 99, "duration_ms": 5})
    svc._net_event({"session_id": "s1", "host": "example.com", "port": 443, "allowed": False,
                    "reason": "not-allowlisted", "bytes_up": 0, "bytes_down": 0, "duration_ms": 1})
    ev = events(tmp_path)
    assert [(e["event"], e["outcome"]) for e in ev] == [
        ("net.connect", "allowed"), ("net.connect", "denied"), ("policy.violation", "denied")]
    assert ev[0]["session_id"] == "s1" and ev[0]["detail"]["bytes_down"] == 99
    assert ev[2]["detail"] == {"kind": "egress", "host": "example.com", "port": 443, "reason": "not-allowlisted"}


def test_listing_failure_does_not_cost_run_code_its_result(tmp_path):
    async def go():
        svc, created = make(tmp_path)
        r = await svc.run_code("set a=1")
        created[0].list_fails = True
        r = await svc.run_code("a", session_id=r["session_id"])
        assert (r["result"], r["new_files"], r["error"]) == ("1", [], None)

    run(go())


def test_default_timeout_stays_under_home_assistants_30_s_cap(tmp_path):
    async def go():
        svc, created = make(tmp_path)
        await svc.run_code("1")
        assert created[0].last_timeout == service.DEFAULT_TIMEOUT_S < 30

    run(go())


def test_policy_words_in_a_file_name_are_no_violation(tmp_path):
    """Violations come from the refusing code, never from matching message text."""
    svc, created = make(tmp_path)
    sid = asyncio.run(svc.run_code("1 + 1"))["session_id"]
    r = call(svc, sid, "share.export", path="/sandbox/outside_temps larger than.csv")
    assert r["error"].startswith("FileOpError: ")

    async def refused(path, limit):
        raise FileOpError("ValueError: '../x' is outside /sandbox", "traversal")

    created[0].read_file = refused
    call(svc, sid, "share.export", path="../x")
    viol = [e for e in events(tmp_path) if e["event"] == "policy.violation"]
    assert [(v["detail"]["kind"], v["detail"]["during"]) for v in viol] == [("traversal", "file.export")]


def test_size_refusals_are_size_violations(tmp_path):
    svc, created = make(tmp_path, options={"max_file_mb": 1})
    (tmp_path / "share" / "big.bin").write_bytes(b"x" * (service.MIB + 1))
    sid = asyncio.run(svc.run_code("1 + 1"))["session_id"]
    assert call(svc, sid, "share.import", share_path="big.bin")["error"].startswith("ShareError: ")
    created[0].files["/sandbox/big.txt"] = b"x" * (service.MIB + 1)
    assert call(svc, sid, "share.export", path="/sandbox/big.txt")["error"].startswith("FileOpError: ")
    kinds = [e["detail"]["kind"] for e in events(tmp_path) if e["event"] == "policy.violation"]
    assert kinds == ["size", "size"]


def test_sandbox_failure_after_a_concurrent_close_keeps_the_real_error(tmp_path):
    async def go():
        svc, created = make(tmp_path)
        sid = (await svc.run_code("1 + 1"))["session_id"]

        async def closed_meanwhile(*args, **kwargs):
            await svc.close_session(sid)  # e.g. the Ingress Close button
            raise SandboxError("sandbox is closed")

        created[0].run_code = closed_meanwhile
        r = await svc.run_code("1", session_id=sid)
        assert r["error"] == "sandbox_unavailable" and "closed" in r["detail"]

    run(go())


def test_self_check_fails_closed_when_cleanup_or_run_fails(tmp_path):
    async def go():
        async def leaky(sid, uid, policy, **kw):
            s = FakeSandbox(sid, uid, policy)

            async def destroy():
                raise SandboxError("1 process(es) of uid 59999 still alive after destroy")

            s.destroy = destroy
            return s

        svc, _ = make(tmp_path, create=leaky)
        assert "still alive" in await svc.self_check()

        async def dead(sid, uid, policy, **kw):
            s = FakeSandbox(sid, uid, policy)

            async def run_code(code, timeout_s, reset=False):
                raise SandboxError("REPL did not restart")

            s.run_code = run_code
            return s

        svc2, _ = make(tmp_path, create=dead)
        assert "did not restart" in await svc2.self_check()

    run(go())


def call(svc, sid, op, **args):
    return asyncio.run(svc.run_code(f"call {op} {json.dumps(args)}", session_id=sid))


def test_cell_share_list_import_and_export(tmp_path):
    svc, _ = make(tmp_path)
    (tmp_path / "share" / "energy.csv").write_text("kwh\n1\n")
    sid = asyncio.run(svc.run_code("1 + 1"))["session_id"]
    listed = json.loads(call(svc, sid, "share.list")["result"])
    assert {"name": "energy.csv", "type": "file", "size": 6} in listed["entries"]
    r = call(svc, sid, "share.import", share_path="energy.csv", dest="in.csv")
    assert json.loads(r["result"]) == {"path": "/sandbox/in.csv", "size": 6}
    r = call(svc, sid, "share.export", path="/sandbox/in.csv")
    out = json.loads(r["result"])
    assert out["share_path"].endswith(f"/code-interpreter/{sid}/in.csv")
    assert {"share.list", "file.import", "file.export"} <= {e["event"] for e in events(tmp_path)}


def test_cell_share_errors_reach_the_cell_and_the_audit(tmp_path):
    svc, _ = make(tmp_path)
    sid = asyncio.run(svc.run_code("1 + 1"))["session_id"]
    r = call(svc, sid, "share.import", share_path="../etc/passwd")
    assert r["error"].startswith("ShareError: ") and "outside /share" in r["error"]
    r = call(svc, sid, "share.list", path="..")
    assert r["error"].startswith("ShareError: ")
    r = call(svc, sid, "nope.op")
    assert r["error"] == "RpcRejected: unknown call 'nope.op'"
    kinds = [e["detail"].get("kind") for e in events(tmp_path) if e["event"] == "policy.violation"]
    assert kinds.count("traversal") == 2 and "rpc" in kinds


class FakeHA:
    def __init__(self, admins=("alice",)):
        self.admins = set(admins)
        self.calls = []
        self.users = {"alice": "Alice", "bob": "Bob"}

    def known_users(self):
        return dict(self.users)

    async def find_user(self, who):
        found = [uid for uid, name in self.users.items() if who.casefold() in (uid, name.casefold())]
        if len(found) != 1:
            raise LookupError(f"no active Home Assistant user {who!r}")
        return found[0]

    async def is_admin(self, user_id):
        return user_id in self.admins

    async def mcp_servers(self):
        return [{"entry_id": "M1", "title": "Memory", "state": "loaded"},
                {"entry_id": "S1", "title": "Secrets", "state": "loaded"}]

    async def tools(self, api):
        if api == "mcp-M1":
            return [{"name": "memory__search", "read_only": True, "destructive": False, "description": "find", "input_schema": {}}]
        if api == "mcp-S1":
            return [{"name": "secrets__read", "read_only": True, "destructive": False, "description": "", "input_schema": {}}]
        if api == "assist":
            return [{"name": "intent__HassTurnOff", "read_only": False, "destructive": True, "description": "", "input_schema": {}}]
        return [{"name": "trace__get_trace", "read_only": True, "destructive": False, "description": "", "input_schema": {}},
                {"name": "homeassistant__call_action", "read_only": False, "destructive": True, "description": "", "input_schema": {}}]

    def pool(self):
        return self

    async def close(self):
        pass

    async def call(self, api, name, args, timeout_s):
        self.calls.append((api, name, args))
        if name == "intent__HassTurnOff" and args.get("name") == "boom":
            raise hamcp.HaToolError("no such device")
        return {"ok": True}


def make_ha(tmp_path, **kw):
    svc, created = make(tmp_path)
    svc.ha = FakeHA(**kw)
    return svc, created


def ha_call(svc, sid, user, **args):
    return asyncio.run(svc.run_code(f"call ha.call {json.dumps(args)}", session_id=sid, user_id=user))


def test_ha_call_assist_and_audit(tmp_path):
    svc, created = make_ha(tmp_path)
    sid = asyncio.run(svc.run_code("1 + 1", user_id="bob"))["session_id"]
    assert created[0].last_ctx == {"admin": False, "plugins": False}
    r = ha_call(svc, sid, "bob", api="assist", name="intent__HassTurnOff", args={"name": "Kitchen"})
    assert json.loads(r["result"]) == {"ok": True}
    r = ha_call(svc, sid, "bob", api="assist", name="intent__HassTurnOff", args={"name": "boom"})
    assert r["error"] == "HaToolError: no such device"
    r = ha_call(svc, sid, "bob", api="assist", name="nope__x")
    assert r["error"].startswith("UnknownTool: ")
    ev = [e for e in events(tmp_path) if e["event"] == "ha.call"]
    assert [e["outcome"] for e in ev] == ["ok", "error"]
    assert ev[0]["detail"]["tool"] == "intent__HassTurnOff" and ev[0]["detail"]["user_id"] == "bob"
    assert ev[0]["detail"]["args"] == '{"name": "Kitchen"}'


def test_ha_admin_is_for_admins_and_read_only_tools(tmp_path):
    svc, created = make_ha(tmp_path)
    sid = asyncio.run(svc.run_code("1 + 1", user_id="alice"))["session_id"]
    assert created[0].last_ctx == {"admin": True, "plugins": False}
    listed = json.loads(asyncio.run(svc.run_code('call ha.list {"api": "homeassistant"}', session_id=sid, user_id="alice"))["result"])
    assert [t["name"] for t in listed] == ["trace__get_trace"]
    assert json.loads(ha_call(svc, sid, "alice", api="homeassistant", name="trace__get_trace")["result"]) == {"ok": True}
    r = ha_call(svc, sid, "alice", api="homeassistant", name="homeassistant__call_action", args={"action": "homeassistant.restart"})
    assert r["error"].startswith("NotAllowed: ")
    other = asyncio.run(svc.run_code("1 + 1", user_id="bob"))["session_id"]
    r = ha_call(svc, other, "bob", api="homeassistant", name="trace__get_trace")
    assert r["error"].startswith("AdminOnly: ")
    r = ha_call(svc, other, "bob", api="everything", name="x")
    assert r["error"].startswith("RpcRejected: ")
    assert ("homeassistant", "homeassistant__call_action", {"action": "homeassistant.restart"}) not in svc.ha.calls
    kinds = [e["detail"]["kind"] for e in events(tmp_path) if e["event"] == "policy.violation"]
    assert kinds.count("admin") == 2 and "rpc" in kinds


def test_ha_calls_per_run_are_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(service, "HA_CALLS_PER_CELL", 2)
    svc, _ = make_ha(tmp_path)
    sid = asyncio.run(svc.run_code("1 + 1"))["session_id"]

    async def three():
        calls = service._CellCalls(svc, svc.manager._sessions[sid].sandbox, None, deadline=1e12)
        out = []
        for _ in range(3):
            try:
                out.append(await calls.call("ha.call", {"api": "assist", "name": "intent__HassTurnOff", "args": {}}))
            except replclient.RpcError as e:
                out.append(e.name)
        return out

    assert asyncio.run(three()) == [{"ok": True}, {"ok": True}, "RateLimited"]


def test_sessions_belong_to_their_user(tmp_path):
    svc, _ = make_ha(tmp_path)
    sid = asyncio.run(svc.run_code("set x=1", user_id="alice"))["session_id"]
    assert asyncio.run(svc.run_code("x", session_id=sid, user_id="bob"))["error"] == "session_not_found"
    assert asyncio.run(svc.run_code("x", session_id=sid))["error"] == "session_not_found"
    assert asyncio.run(svc.run_code("x", session_id=sid, user_id="alice"))["result"] == "1"
    assert [s["session_id"] for s in svc.list_sessions(user_id="alice")["sessions"]] == [sid]
    assert svc.list_sessions(user_id="bob")["sessions"] == []
    assert asyncio.run(svc.close_session(sid, user_id="bob"))["error"] == "session_not_found"


def test_run_code_while_the_users_ha_call_is_in_flight_is_refused(tmp_path):
    svc, _ = make_ha(tmp_path)
    svc._ha_inflight["alice"] = 1
    assert asyncio.run(svc.run_code("1 + 1", user_id="alice"))["error"] == "nested_call"
    assert asyncio.run(svc.run_code("1 + 1", user_id="bob"))["result"] == "2"
    assert any(e["detail"].get("kind") == "nested" for e in events(tmp_path) if e["event"] == "policy.violation")


class FakeHab:
    def __init__(self):
        self.calls = []

    async def check(self, argv):
        if argv[:2] == ["automation", "update"]:
            raise hab.HabRefused("'hab automation update' changes Home Assistant (write); add a hab_allow rule")
        return " ".join(argv[:2]), "read"

    async def call(self, argv, stdin, timeout_s):
        self.calls.append((argv, stdin))
        return {"success": True, "data": {"id": argv[-1]}, "exit_code": 0}


def test_hab_is_for_admins_checked_and_audited(tmp_path):
    svc, _ = make_ha(tmp_path)
    svc.hab = FakeHab()
    sid = asyncio.run(svc.run_code("1 + 1", user_id="alice"))["session_id"]
    r = asyncio.run(svc.run_code('call ha.hab {"argv": ["automation", "get", "night"], "stdin": "x"}', session_id=sid, user_id="alice"))
    assert json.loads(r["result"])["data"] == {"id": "night"} and svc.hab.calls == [(["automation", "get", "night"], "x")]
    r = asyncio.run(svc.run_code('call ha.hab {"argv": ["automation", "update", "night"]}', session_id=sid, user_id="alice"))
    assert r["error"].startswith("NotAllowed: ") and "hab_allow" in r["error"]
    other = asyncio.run(svc.run_code("1 + 1", user_id="bob"))["session_id"]
    r = asyncio.run(svc.run_code('call ha.hab {"argv": ["automation", "get", "night"]}', session_id=other, user_id="bob"))
    assert r["error"].startswith("AdminOnly: ")
    ev = events(tmp_path)
    habs = [e for e in ev if e["event"] == "ha.hab"]
    assert len(habs) == 1 and habs[0]["detail"]["command"] == "automation get" and habs[0]["detail"]["stdin_chars"] == 1
    kinds = [e["detail"]["kind"] for e in ev if e["event"] == "policy.violation"]
    assert "hab" in kinds and "admin" in kinds


def test_hab_rules_come_from_the_options(tmp_path):
    opts = tmp_path / "o.json"
    opts.write_text(json.dumps({"hab_allow": ["automation *", " ", None], "hab_deny": ["automation delete *"]}))
    o = service.load_options(opts)
    assert o.hab_rules == hab.Rules(allow=("automation *",), deny=("automation delete *",))


def test_a_user_without_session_id_continues_their_latest_session(tmp_path):
    svc, created = make_ha(tmp_path)
    first = asyncio.run(svc.run_code("set x=1", user_id="alice"))
    assert "resumed" not in first
    r = asyncio.run(svc.run_code("x", user_id="alice"))
    assert r["session_id"] == first["session_id"] and r["result"] == "1" and r["resumed"] is True
    other = asyncio.run(svc.run_code("x", user_id="bob"))
    assert other["session_id"] != first["session_id"] and other["result"] is None
    anon1 = asyncio.run(svc.run_code("set y=2"))
    anon2 = asyncio.run(svc.run_code("y"))
    assert anon1["session_id"] != anon2["session_id"] and anon2["result"] is None and "resumed" not in anon2


def test_resuming_a_session_closed_meanwhile_starts_a_new_one(tmp_path):
    svc, _ = make_ha(tmp_path)
    sid = asyncio.run(svc.run_code("set x=1", user_id="alice"))["session_id"]
    real_latest = svc.manager.latest
    svc.manager.latest = lambda owner: "0000000000000000"  # a session that is already gone
    r = asyncio.run(svc.run_code("x", user_id="alice"))
    svc.manager.latest = real_latest
    assert r["session_id"] not in (sid, "0000000000000000") and r["error"] is None and "resumed" not in r


class FakeAITask(FakeHA):
    def __init__(self, answer):
        super().__init__()
        self.answer = answer
        self.asked = []

    async def generate_data(self, task_name, instructions, structure, entity_id=None, timeout_s=120):
        self.asked.append((instructions, entity_id))
        return self.answer


SKILL_CODE = "const on = (await ha.homeassistant.GetLiveContext());\nconst names = [];\nawait Promise.all(names.map((n) => ha.intent.HassTurnOff({ name: n })));"


def skill_service(tmp_path, answer, **opts):
    svc, created = make(tmp_path, {"skill_workflow": True, **opts})
    svc.ha = FakeAITask(answer)
    svc.skills = SkillStore(tmp_path / "skills")
    svc.reviewer = SkillReviewer(svc.skills, svc.ha, svc.audit, enabled=svc.options.skill_workflow,
                                 entity_id=svc.options.skill_ai_task_entity)
    return svc, created


def finish(svc, sid):
    async def go():
        await svc.close_session(sid, everyone=True)
        await svc.reviewer.wait()

    asyncio.run(go())


def test_a_finished_session_can_save_a_skill(tmp_path):
    answer = {"save": True, "name": "lights_off_except", "description": "d", "params": "{ except }",
              "code": "async ({ except: room }) => room", "reason": "repeatable"}
    svc, _ = skill_service(tmp_path, answer, skill_ai_task_entity="ai_task.claude_ai_task")
    sid = asyncio.run(svc.run_code("set " + "a=1", user_id="alice"))["session_id"]
    asyncio.run(svc.run_code(SKILL_CODE, session_id=sid, user_id="alice"))
    finish(svc, sid)
    (instructions, entity), = svc.ha.asked
    assert entity == "ai_task.claude_ai_task" and "GetLiveContext" in instructions and "set a=1" not in instructions
    assert "when to use it" in instructions
    skill = svc.skills.get("alice", "lights_off_except")
    assert skill["code"] == "async ({ except: room }) => room" and skill["source"]["session_id"] == sid
    (ev,) = [e for e in events(tmp_path) if e["event"] == "skill.saved"]
    assert ev["detail"]["via"] == "review" and ev["detail"]["ai_task_entity"] == "ai_task.claude_ai_task"


def test_no_review_when_off_anonymous_trivial_or_declined(tmp_path):
    svc, _ = skill_service(tmp_path, {"save": False, "reason": "one-off"}, skill_workflow=False)
    sid = asyncio.run(svc.run_code(SKILL_CODE, user_id="alice"))["session_id"]
    finish(svc, sid)
    assert svc.ha.asked == []
    (tmp_path / "b").mkdir()
    svc, _ = skill_service(tmp_path / "b", {"save": False, "reason": "one-off"})
    anon = asyncio.run(svc.run_code(SKILL_CODE))["session_id"]
    finish(svc, anon)
    short = asyncio.run(svc.run_code("1 + 1", user_id="alice"))["session_id"]
    finish(svc, short)
    assert svc.ha.asked == []
    sid = asyncio.run(svc.run_code(SKILL_CODE, user_id="alice"))["session_id"]
    finish(svc, sid)
    assert len(svc.ha.asked) == 1 and svc.skills.list("alice") == []
    assert any(e["event"] == "skill.review" and e["detail"]["saved"] is False for e in events(tmp_path / "b"))


def test_cells_use_only_their_users_skills(tmp_path):
    svc, _ = skill_service(tmp_path, {})
    svc.skills.save("alice", "greet", "code", "says hi", "async () => 1", "{}")
    sid = asyncio.run(svc.run_code("1 + 1", user_id="alice"))["session_id"]
    listed = json.loads(asyncio.run(svc.run_code("call skills.list {}", session_id=sid, user_id="alice"))["result"])
    assert listed == [{"name": "greet", "kind": "code", "description": "says hi", "params": "{}"}]
    r = asyncio.run(svc.run_code('call skills.get {"name": "greet"}', session_id=sid, user_id="alice"))
    assert json.loads(r["result"]) == {"code": "async () => 1"}
    other = asyncio.run(svc.run_code("1 + 1", user_id="bob"))["session_id"]
    r = asyncio.run(svc.run_code('call skills.get {"name": "greet"}', session_id=other, user_id="bob"))
    assert r["error"].startswith("UnknownSkill: ")


def test_a_new_conversations_first_result_lists_the_skills_recent_first(tmp_path):
    svc, _ = skill_service(tmp_path, {})
    svc.skills.save("alice", "alpha", "code", "first one", "async () => 1")
    svc.skills.save("alice", "beta", "guide", "how to answer", "be brief")
    first = asyncio.run(svc.run_code("1", user_id="alice"))
    assert first["skills"] == [{"name": "alpha", "kind": "code", "description": "first one"},
                               {"name": "beta", "kind": "guide", "description": "how to answer"}]
    assert "skills_more" not in first
    asyncio.run(svc.run_code('call skills.get {"name": "beta"}', session_id=first["session_id"], user_id="alice"))
    assert "skills" not in asyncio.run(svc.run_code("1", user_id="alice"))  # same conversation: said already
    for s in svc.manager.list():
        s.last_used -= 301  # Home Assistant's conversation has expired: the next call starts a new one
    later = asyncio.run(svc.run_code("1", user_id="alice"))
    assert later["resumed"] and [s["name"] for s in later["skills"]] == ["beta", "alpha"]  # beta ran last
    assert "skills" not in asyncio.run(svc.run_code("1", user_id="bob"))
    assert "skills" not in asyncio.run(svc.run_code("1"))


def test_the_listing_is_capped_and_the_rest_counted(tmp_path):
    svc, _ = skill_service(tmp_path, {})
    for i in range(33):
        svc.skills.save("alice", f"s{i:02}", "code", "d", "async () => 1")
    r = asyncio.run(svc.run_code("1", user_id="alice"))
    assert len(r["skills"]) == 30 and r["skills_more"] == 3


def test_skills_find_ranks_by_the_requests_words(tmp_path):
    svc, _ = skill_service(tmp_path, {})
    svc.skills.save("alice", "todays_outfit", "code", "오늘 날씨에 맞는 코디를 추천", "async () => 1")
    svc.skills.save("alice", "lights_off_except", "code", "Turn off every light except one room", "async () => 1")
    svc.skills.save("alice", "water_plants", "code", "Start the garden irrigation", "async () => 1")
    sid = asyncio.run(svc.run_code("1", user_id="alice"))["session_id"]

    def find(text):
        r = asyncio.run(svc.run_code(f"call skills.find {json.dumps({'text': text})}", session_id=sid, user_id="alice"))
        return r.get("error") or [s["name"] for s in json.loads(r["result"])]

    assert find("오늘 코디 추천해 줘") == ["todays_outfit"]
    assert find("turn the lights off but not the bedroom") == ["lights_off_except"]  # not "the garden"
    assert find("start watering the garden") == ["water_plants"]
    assert find("zzz") == []
    assert find("  ").startswith("TypeError: ")
    other = asyncio.run(svc.run_code("1", user_id="bob"))["session_id"]
    r = asyncio.run(svc.run_code('call skills.find {"text": "코디"}', session_id=other, user_id="bob"))
    assert json.loads(r["result"]) == []


def test_skills_find_weighs_the_name_over_the_description():
    skills = [
        {"name": "garden_report", "description": "what the sensors say"},
        {"name": "sensor_summary", "description": "the garden's sensors"},
    ]
    assert [s["name"] for s in skills_find(skills, "garden")] == ["garden_report", "sensor_summary"]


def test_a_skill_still_runs_when_its_use_cannot_be_recorded(tmp_path, monkeypatch):
    svc, _ = skill_service(tmp_path, {})
    svc.skills.save("alice", "greet", "code", "d", "async () => 1")
    sid = asyncio.run(svc.run_code("1", user_id="alice"))["session_id"]
    monkeypatch.setattr(svc.skills, "_write", lambda *a: (_ for _ in ()).throw(OSError("disk full")))
    r = asyncio.run(svc.run_code('call skills.get {"name": "greet"}', session_id=sid, user_id="alice"))
    assert json.loads(r["result"]) == {"code": "async () => 1"}


def test_a_guide_is_in_force_at_once_and_the_user_edits_and_deletes_it(tmp_path):
    svc, _ = skill_service(tmp_path, {})
    sid = asyncio.run(svc.run_code("1", user_id="alice"))["session_id"]

    def cell(op, args):
        r = asyncio.run(svc.run_code(f"call {op} {json.dumps(args, ensure_ascii=False)}", session_id=sid, user_id="alice"))
        return r.get("error") or json.loads(r["result"])

    saved = cell("skills.save", {"name": "outfit_notes", "description": "코디 추천 규칙", "guide": "비 오면 우산을 챙기라고 말해."})
    assert saved["saved"] == "outfit_notes"
    assert cell("skills.get", {"name": "outfit_notes"}) == {"guide": "비 오면 우산을 챙기라고 말해."}  # no approval
    (entry,) = cell("skills.find", {"text": "코디 추천해 줘"})
    assert (entry["name"], entry["kind"]) == ("outfit_notes", "guide")
    cell("skills.save", {"name": "outfit_notes", "description": "코디 추천 규칙", "guide": "우산과 겉옷을 챙기라고 말해."})
    assert cell("skills.get", {"name": "outfit_notes"}) == {"guide": "우산과 겉옷을 챙기라고 말해."}
    assert cell("skills.delete", {"name": "outfit_notes"}) == {"deleted": "outfit_notes"}
    assert cell("skills.get", {"name": "outfit_notes"}).startswith("UnknownSkill: ")
    assert [e["detail"]["name"] for e in events(tmp_path) if e["event"] in ("skill.saved", "skill.deleted")] == [
        "outfit_notes"] * 3


def test_the_agent_saves_replaces_and_deletes_any_of_the_users_skills(tmp_path):
    svc, _ = skill_service(tmp_path, {})
    sid = asyncio.run(svc.run_code("1", user_id="alice"))["session_id"]

    def cell(op, args):
        r = asyncio.run(svc.run_code(f"call {op} {json.dumps(args)}", session_id=sid, user_id="alice"))
        return r.get("error") or json.loads(r["result"])

    saved = cell("skills.save", {"name": "greet", "description": "says hi", "code": "async () => 1", "params": "{}"})
    assert saved["saved"] == "greet" and cell("skills.get", {"name": "greet"}) == {"code": "async () => 1"}
    cell("skills.save", {"name": "greet", "description": "how to greet", "guide": "wave"})  # replaced, any kind
    assert cell("skills.get", {"name": "greet"}) == {"guide": "wave"}
    assert cell("skills.delete", {"name": "greet"}) == {"deleted": "greet"}
    assert cell("skills.save", {"name": "x", "description": "d", "code": "a", "guide": "b"}).startswith("TypeError: ")
    assert cell("skills.save", {"name": "x", "description": "d"}).startswith("TypeError: ")
    assert cell("skills.save", {"name": "x", "description": "d", "guide": 3}).startswith("TypeError: ")
    assert cell("skills.save", {"name": "x", "guide": "b"}).startswith("SkillError: ")  # no description
    assert cell("skills.save", {"name": "list", "description": "d", "guide": "b"}).startswith("SkillError: ")
    assert cell("skills.delete", {"name": "nope"}).startswith("SkillError: ")
    saved = [e["detail"] for e in events(tmp_path) if e["event"] == "skill.saved"]
    assert [(d["kind"], d["via"]) for d in saved] == [("code", "agent"), ("guide", "agent")]
    other = asyncio.run(svc.run_code("1"))["session_id"]
    r = asyncio.run(svc.run_code('call skills.save {"name": "n3", "description": "d", "guide": "x"}', session_id=other))
    assert r["error"].startswith("NoUser: ")


def test_a_failed_review_is_audited_not_lost(tmp_path):
    svc, _ = skill_service(tmp_path, {})

    async def down(*a, **kw):
        raise hamcp.HaUnavailable("ai_task.generate_data: ConnectError: refused")

    svc.ha.generate_data = down
    sid = asyncio.run(svc.run_code(SKILL_CODE, user_id="alice"))["session_id"]
    finish(svc, sid)
    (e,) = [e for e in events(tmp_path) if e["event"] == "skill.review"]
    assert e["outcome"] == "error" and e["detail"]["error"] == "HaUnavailable"


def test_nothing_is_remembered_while_the_workflow_is_off(tmp_path):
    svc, _ = skill_service(tmp_path, {}, skill_workflow=False)
    asyncio.run(svc.run_code(SKILL_CODE, user_id="alice"))
    assert svc.reviewer._history == {}


def request(svc, line):
    async def go():
        svc.handle_stdin(line)
        await svc.reviewer.wait()

    asyncio.run(go())


def test_a_skill_request_from_stdin_is_saved_for_that_user(tmp_path):
    answer = {"save": True, "name": "lights_off_except", "description": "d", "params": "{ except }",
              "code": "async ({ except: room }) => room", "reason": "asked"}
    svc, _ = skill_service(tmp_path, answer)
    request(svc, json.dumps({"type": "skill.request", "user": "Bob", "request": "거실 빼고 불 끄기"}))
    ((instructions, _),) = svc.ha.asked
    assert "거실 빼고 불 끄기" in instructions and "intent__HassTurnOff" in instructions
    assert "trace__get_trace" not in instructions  # bob is not an administrator
    skill = svc.skills.get("bob", "lights_off_except")
    assert skill["code"] == "async ({ except: room }) => room" and skill["source"]["request"] == "거실 빼고 불 끄기"
    ev = [e for e in events(tmp_path) if e["event"] in ("skill.requested", "skill.saved")]
    assert [e["event"] for e in ev] == ["skill.requested", "skill.saved"] and ev[0]["detail"]["user_id"] == "bob"
    assert ev[1]["detail"]["via"] == "request"


def test_an_administrators_request_lists_the_read_only_admin_tools(tmp_path):
    svc, _ = skill_service(tmp_path, {"save": False, "reason": "cannot"})
    request(svc, json.dumps({"type": "skill.request", "user": "alice", "request": "trace report"}))
    ((instructions, _),) = svc.ha.asked
    assert "admin.trace__get_trace" in instructions and "call_action" not in instructions
    assert svc.skills.list("alice") == []


def test_skill_requests_are_refused_when_off_unknown_or_malformed(tmp_path):
    svc, _ = skill_service(tmp_path, {}, skill_workflow=False)
    request(svc, json.dumps({"type": "skill.request", "user": "bob", "request": "x"}))
    (tmp_path / "b").mkdir()
    on, _ = skill_service(tmp_path / "b", {})
    request(on, json.dumps({"type": "skill.request", "user": "nobody", "request": "x"}))
    request(on, json.dumps({"type": "skill.request", "user": "", "request": "x"}))
    request(on, "not json")
    request(on, json.dumps({"type": "something.else"}))
    assert svc.ha.asked == [] and on.ha.asked == []
    (off,) = [e for e in events(tmp_path) if e["event"] == "skill.requested"]
    assert off["outcome"] == "denied" and off["detail"]["reason"] == "skill_workflow is off"
    ev = [(e["event"], e["outcome"]) for e in events(tmp_path / "b") if e["event"] in ("skill.requested", "stdin")]
    assert ev == [("skill.requested", "error"), ("skill.requested", "error"), ("stdin", "error"), ("stdin", "error")]


def plugin_service(tmp_path):
    svc, created = make(tmp_path, {"plugins": [{"name": "memory", "access": "all"}, {"name": "Secrets", "access": "admin"},
                                               {"name": "bad", "access": "everyone"}, {"access": "all"}]})
    svc.ha = FakeHA()
    svc.plugins.ha = svc.ha
    return svc, created


def test_plugin_options_drop_invalid_entries(tmp_path):
    svc, _ = plugin_service(tmp_path)
    assert [(p.name, p.access) for p in svc.options.plugins] == [("memory", "all"), ("Secrets", "admin")]


def test_plugins_by_access_and_audited(tmp_path):
    svc, created = plugin_service(tmp_path)
    bob = asyncio.run(svc.run_code("1 + 1", user_id="bob"))["session_id"]
    assert created[0].last_ctx == {"admin": False, "plugins": True}
    listed = json.loads(asyncio.run(svc.run_code("call plugins.list {}", session_id=bob, user_id="bob"))["result"])
    assert [(t["name"], t["plugin"]) for t in listed] == [("memory__search", "memory")]
    r = asyncio.run(svc.run_code('call plugins.call {"name": "memory__search", "args": {"q": "x"}}', session_id=bob, user_id="bob"))
    assert json.loads(r["result"]) == {"ok": True} and svc.ha.calls[-1] == ("mcp-M1", "memory__search", {"q": "x"})
    # an admin-only plugin's tool sent straight over RPC by someone else
    r = asyncio.run(svc.run_code('call plugins.call {"name": "secrets__read"}', session_id=bob, user_id="bob"))
    assert r["error"].startswith("UnknownTool: ")
    alice = asyncio.run(svc.run_code("1 + 1", user_id="alice"))["session_id"]
    r = asyncio.run(svc.run_code('call plugins.call {"name": "secrets__read"}', session_id=alice, user_id="alice"))
    assert json.loads(r["result"]) == {"ok": True} and svc.ha.calls[-1][0] == "mcp-S1"
    ev = [e for e in events(tmp_path) if e["event"] == "plugin.call"]
    assert [(e["detail"]["plugin"], e["detail"]["tool"], e["detail"]["user_id"]) for e in ev] == [
        ("memory", "memory__search", "bob"), ("Secrets", "secrets__read", "alice")]


def test_find_returns_the_matching_tools_the_caller_may_use(tmp_path):
    svc, _ = plugin_service(tmp_path)
    bob = asyncio.run(svc.run_code("1 + 1", user_id="bob"))["session_id"]

    def found(op, args):
        r = asyncio.run(svc.run_code(f"call {op} {json.dumps(args)}", session_id=bob, user_id="bob"))
        return r.get("error") or [t["name"] for t in json.loads(r["result"])]

    assert found("ha.list", {"api": "assist", "query": "turn off the kitchen"}) == ["intent__HassTurnOff"]
    assert found("plugins.list", {"query": "search memory"}) == ["memory__search"]
    assert found("plugins.list", {"query": "read secrets"}) == []  # admin-only plugin: not even found
    assert found("ha.list", {"api": "assist", "query": " "}).startswith("TypeError: ")
    assert found("plugins.list", {"query": "select:memory__search,secrets__read"}) == ["memory__search"]


def test_tool_listings_are_brief_and_find_gives_the_schema(tmp_path):
    svc, _ = plugin_service(tmp_path)
    bob = asyncio.run(svc.run_code("1 + 1", user_id="bob"))["session_id"]

    def result(op, args):
        return json.loads(asyncio.run(svc.run_code(f"call {op} {json.dumps(args)}", session_id=bob, user_id="bob"))["result"])

    assert result("ha.list", {"api": "assist"}) == [{"name": "intent__HassTurnOff", "description": ""}]
    assert result("plugins.list", {}) == [{"name": "memory__search", "description": "find", "plugin": "memory"}]
    (full,) = result("plugins.list", {"query": "select:memory__search"})
    assert full["input_schema"] == {} and full["read_only"] is True


def test_admin_tools_keep_some_of_an_all_servers_tools_for_administrators(tmp_path):
    svc, _ = make(tmp_path, {"plugins": [{"name": "memory", "access": "all", "admin_tools": " save_*, memory__search ,"}]})
    svc.ha = FakeHA()
    svc.plugins.ha = svc.ha
    assert svc.options.plugins[0].admin_tools == ("save_*", "memory__search")
    bob = asyncio.run(svc.run_code("1 + 1", user_id="bob"))["session_id"]
    assert json.loads(asyncio.run(svc.run_code("call plugins.list {}", session_id=bob, user_id="bob"))["result"]) == []
    r = asyncio.run(svc.run_code('call plugins.call {"name": "memory__search"}', session_id=bob, user_id="bob"))
    assert r["error"].startswith("UnknownTool: ") and svc.ha.calls == []
    alice = asyncio.run(svc.run_code("1 + 1", user_id="alice"))["session_id"]
    r = asyncio.run(svc.run_code('call plugins.call {"name": "memory__search"}', session_id=alice, user_id="alice"))
    assert json.loads(r["result"]) == {"ok": True}


def test_admin_tools_match_with_or_without_the_server_prefix():
    from plugins import Plugin
    p = Plugin("memory", "all", admin_tools=("save_*", "memory__wipe"))
    assert p.admin_only("memory__save_note") and p.admin_only("memory__wipe")
    assert not p.admin_only("memory__search") and not p.admin_only("other__wipe")
    assert Plugin("x", "admin").admin_only("x__anything")


def test_no_plugins_without_a_user(tmp_path):
    svc, created = plugin_service(tmp_path)
    sid = asyncio.run(svc.run_code("1 + 1"))["session_id"]
    assert created[0].last_ctx == {"admin": False, "plugins": False}
    r = asyncio.run(svc.run_code('call plugins.call {"name": "memory__search"}', session_id=sid))
    assert r["error"].startswith("NoUser: ")


def test_a_request_offers_the_users_plugin_tools(tmp_path):
    svc, _ = plugin_service(tmp_path)
    svc.ha = FakeAITask({"save": False, "reason": "no"})
    svc.plugins.ha = svc.ha
    svc.reviewer = SkillReviewer(svc.skills, svc.ha, svc.audit, enabled=True, entity_id=None, plugins=svc.plugins)
    request(svc, json.dumps({"type": "skill.request", "user": "bob", "request": "remember"}))
    ((instructions, _),) = svc.ha.asked
    assert "plugin.memory__search" in instructions and "secrets__read" not in instructions


def test_plugin_options_take_an_api_id_but_never_the_ha_apis(tmp_path):
    svc, _ = make(tmp_path, {"plugins": [{"name": "Wardrowbe", "access": "admin", "api": "wardrowbe__W9"},
                                         {"name": "sneaky", "access": "all", "api": "homeassistant"},
                                         {"name": "path", "access": "all", "api": "../x"}]})
    assert [(p.name, p.api) for p in svc.options.plugins] == [("Wardrowbe", "wardrowbe__W9")]


def ask(svc, sid, user, text="today's outfit"):
    return asyncio.run(svc.run_code(f"call skills.request {json.dumps({'request': text})}", session_id=sid, user_id=user))


def test_a_skill_asked_for_in_a_conversation_is_saved_for_the_speaker(tmp_path):
    answer = {"save": True, "name": "todays_outfit", "description": "d", "params": "{}",
              "code": "async () => plugins.wardrowbe.suggest_outfit({})", "reason": "asked"}
    svc, _ = skill_service(tmp_path, answer)
    sid = asyncio.run(svc.run_code("1 + 1", user_id="bob"))["session_id"]
    r = ask(svc, sid, "bob")
    assert json.loads(r["result"])["requested"] is True
    asyncio.run(svc.reviewer.wait())
    ((instructions, _),) = svc.ha.asked
    assert "today's outfit" in instructions
    skill = svc.skills.get("bob", "todays_outfit")
    assert skill["source"]["request"] == "today's outfit" and skill["source"]["session_id"] == sid
    assert skill["code"] == "async () => plugins.wardrowbe.suggest_outfit({})"  # in force at once
    (ev,) = [e for e in events(tmp_path) if e["event"] == "skill.requested"]
    assert ev["session_id"] == sid and ev["detail"]["via"] == "conversation" and ev["detail"]["user_id"] == "bob"


def test_a_skill_request_sees_the_users_skills_with_their_kind(tmp_path):
    svc, _ = skill_service(tmp_path, {"save": False, "reason": "no"})
    svc.skills.save("bob", "outfit_rules", "guide", "코디 규칙", "우산을 챙기라고 말해.")
    sid = asyncio.run(svc.run_code("1 + 1", user_id="bob"))["session_id"]
    ask(svc, sid, "bob")
    asyncio.run(svc.reviewer.wait())
    ((instructions, _),) = svc.ha.asked
    assert '{"name": "outfit_rules", "kind": "guide", "description": "코디 규칙"}' in instructions
    assert "우산" not in instructions  # a guide's text stays with the agent it was written for


def test_skill_requests_need_a_user_the_workflow_and_one_at_a_time(tmp_path):
    svc, _ = skill_service(tmp_path, {"save": False, "reason": "no"})
    anon = asyncio.run(svc.run_code("1 + 1"))["session_id"]
    assert ask(svc, anon, None)["error"].startswith("NoUser: ")
    sid = asyncio.run(svc.run_code("1 + 1", user_id="bob"))["session_id"]
    assert ask(svc, sid, "bob", "  ")["error"].startswith("TypeError: ")
    svc.reviewer._writing.add("bob")  # a request of bob's is being written
    assert ask(svc, sid, "bob")["error"].startswith("SkillError: ")
    svc.reviewer._writing.clear()
    (tmp_path / "off").mkdir()
    off, _ = skill_service(tmp_path / "off", {}, skill_workflow=False)
    osid = asyncio.run(off.run_code("1 + 1", user_id="bob"))["session_id"]
    assert ask(off, osid, "bob")["error"].startswith("SkillsOff: ")
    assert off.ha.asked == []


def test_a_finished_or_failed_request_frees_the_users_turn(tmp_path):
    svc, _ = skill_service(tmp_path, {"save": False, "reason": "no"})
    sid = asyncio.run(svc.run_code("1 + 1", user_id="bob"))["session_id"]
    assert ask(svc, sid, "bob")["error"] is None
    asyncio.run(svc.reviewer.wait())
    assert ask(svc, sid, "bob")["error"] is None  # the first one is done

    async def down(*a, **kw):
        raise hamcp.HaUnavailable("ai_task.generate_data: ConnectError: refused")

    asyncio.run(svc.reviewer.wait())
    svc.ha.generate_data = down
    assert ask(svc, sid, "bob")["error"] is None
    asyncio.run(svc.reviewer.wait())
    assert svc.reviewer._writing == set()
    assert ask(svc, sid, "bob")["error"] is None  # a failed one too


def test_a_stdin_request_does_not_free_a_conversation_requests_turn(tmp_path):
    svc, _ = skill_service(tmp_path, {"save": False, "reason": "no"})
    gate = asyncio.Event()
    real = svc.ha.generate_data

    async def slow_for_the_conversation(task_name, instructions, *a, **kw):
        if instructions.endswith("Request:\nslow"):
            await gate.wait()
        return await real(task_name, instructions, *a, **kw)

    svc.ha.generate_data = slow_for_the_conversation

    async def go():
        sid = (await svc.run_code("1 + 1", user_id="bob"))["session_id"]
        first = await svc.run_code('call skills.request {"request": "slow"}', session_id=sid, user_id="bob")
        svc.handle_stdin(json.dumps({"type": "skill.request", "user": "bob", "request": "quick"}))  # finishes at once
        for _ in range(20):
            await asyncio.sleep(0)
        second = await svc.run_code('call skills.request {"request": "c"}', session_id=sid, user_id="bob")
        gate.set()
        await svc.reviewer.wait()
        return first, second

    first, second = asyncio.run(go())
    assert first["error"] is None and second["error"].startswith("SkillError: ")


def test_skill_requests_count_toward_the_runs_call_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(service, "HA_CALLS_PER_CELL", 0)
    svc, _ = skill_service(tmp_path, {"save": False, "reason": "no"})
    sid = asyncio.run(svc.run_code("1 + 1", user_id="bob"))["session_id"]
    assert ask(svc, sid, "bob")["error"].startswith("RateLimited: ")
