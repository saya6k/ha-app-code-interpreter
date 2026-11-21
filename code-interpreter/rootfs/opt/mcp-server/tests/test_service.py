import asyncio
import dataclasses
import json

import pytest
from pathlib import Path

import service
from audit import Audit
from policy import SandboxPolicy
from sandbox import FileOpError, SandboxError


class FakeSandbox:
    def __init__(self, sid, uid, policy):
        self.sid, self.uid, self.policy = sid, uid, policy
        self.vars = {}
        self.files = {}
        self.destroyed = False

    async def run_code(self, code, timeout_s, reset=False):
        self.last_timeout = timeout_s
        if reset:
            self.vars.clear()
        if code.startswith("touch "):
            for name in code[6:].split():
                self.files["/sandbox/" + name] = b"x"
            code = "set _=1"
        if code.startswith("set "):
            k, v = code[4:].split("=")
            self.vars[k] = v
            return {"stdout": "", "stderr": "", "result": None, "error": None,
                    "truncated": False, "kernel_restarted": False}
        result = "2" if code == "1 + 1" else self.vars.get(code)
        return {"stdout": "", "stderr": "", "result": result, "error": None,
                "truncated": False, "kernel_restarted": False}

    async def list_files(self, path="/sandbox", recursive=False):
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


def test_import_read_write_export_round_trip(tmp_path):
    async def go():
        svc, created = make(tmp_path)
        (tmp_path / "share" / "energy.csv").write_text("kwh\n1\n2\n")
        r = await svc.import_from_share("energy.csv")
        sid = r["session_id"]
        assert r["path"] == "/sandbox/energy.csv" and r["size"] == 8
        r = await svc.read_file(sid, "/sandbox/energy.csv")
        assert r["content"] == "kwh\n1\n2\n" and r["truncated"] is False
        await svc.write_file(sid, "out.txt", "result")
        r = await svc.export_to_share(sid, "/sandbox/out.txt")
        exported = Path(r["share_path"])
        assert exported == tmp_path / "share" / "code-interpreter" / sid / "out.txt"
        assert exported.read_text() == "result"

    run(go())


def test_import_refuses_paths_outside_share(tmp_path):
    async def go():
        svc, _ = make(tmp_path)
        (tmp_path / "secret").write_text("x")
        r = await svc.import_from_share("../secret")
        assert r["error"] == "share_error" and "outside /share" in r["detail"]

    run(go())


def test_read_file_binary_and_missing(tmp_path):
    async def go():
        svc, created = make(tmp_path)
        r = await svc.run_code("1")
        sid = r["session_id"]
        created[0].files["/sandbox/p.png"] = b"\x89PNG\x00\x01"
        r = await svc.read_file(sid, "/sandbox/p.png")
        assert r["binary"] is True and r["mime"] == "image/png" and "content" not in r
        r = await svc.read_file(sid, "/sandbox/none.txt")
        assert r["error"] == "file_error"

    run(go())


def test_read_file_truncates_long_text_and_handles_cut_multibyte():
    data = ("가" * 20000).encode()  # 3 bytes each
    r = service._text_or_binary("/sandbox/k.txt", data[:64000], len(data))
    assert r["truncated"] is True and len(r["content"]) == 16000 and set(r["content"]) == {"가"}


def test_write_file_over_limit(tmp_path):
    async def go():
        svc, _ = make(tmp_path, {"max_file_mb": 1})
        r = await svc.run_code("1")
        r = await svc.write_file(r["session_id"], "big.txt", "x" * (2 << 20))
        assert r["error"] == "file_error" and "max_file_mb" in r["detail"]

    run(go())


def events(tmp_path):
    out = []
    for f in sorted((tmp_path / "audit").glob("audit-*.jsonl")):
        out += [json.loads(x) for x in f.read_text().splitlines()]
    return out


def test_audit_session_lifecycle_and_code_without_output(tmp_path):
    async def go():
        svc, _ = make(tmp_path)
        r = await svc.run_code("set a=secret-output")
        await svc.run_command("echo hi", session_id=r["session_id"])
        await svc.close_session(r["session_id"])
        return r["session_id"]

    sid = run(go())
    ev = events(tmp_path)
    assert [e["event"] for e in ev] == ["session.create", "code.exec", "command.exec", "session.destroy"]
    assert all(e["session_id"] == sid for e in ev)
    code_ev = ev[1]["detail"]
    assert code_ev["code"] == "set a=secret-output" and len(code_ev["sha256"]) == 64
    assert {"ms", "stdout_chars", "stderr_chars", "kernel_restarted", "timeout"} <= code_ev.keys()
    assert "stdout" not in code_ev and "result" not in code_ev  # output is never stored
    assert ev[2]["detail"]["command"] == "echo hi" and ev[2]["detail"]["exit_code"] == 0
    assert ev[3]["detail"]["reason"] == "close"


def test_audit_file_events_and_traversal_violation(tmp_path):
    async def go():
        svc, _ = make(tmp_path)
        (tmp_path / "share" / "in.csv").write_text("1")
        r = await svc.import_from_share("in.csv")
        sid = r["session_id"]
        await svc.write_file(sid, "o.txt", "data")
        await svc.export_to_share(sid, "/sandbox/o.txt")
        await svc.import_from_share("../etc/passwd", session_id=sid)

    run(go())
    ev = events(tmp_path)
    kinds = [(e["event"], e["outcome"]) for e in ev]
    assert ("file.import", "ok") in kinds and ("file.write", "ok") in kinds and ("file.export", "ok") in kinds
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
