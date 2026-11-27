"""Ingress UI HTTP layer (needs Starlette + httpx: runs in CI and the app image)."""

import asyncio
import json

import pytest

pytest.importorskip("starlette")
pytest.importorskip("httpx")

from starlette.testclient import TestClient  # noqa: E402

import web  # noqa: E402
from audit import Audit  # noqa: E402
from policy import SandboxPolicy  # noqa: E402
from service import Options  # noqa: E402
from sessions import SessionNotFound  # noqa: E402
from skills import SkillStore  # noqa: E402


class FakeHA:
    def known_users(self):
        return {"u1": "Alice"}


class FakeReviewer:
    def __init__(self):
        self.dismissed = []

    async def dismiss(self, user, name):
        self.dismissed.append((user, name))


class FakeService:
    def __init__(self, audit, skills_dir):
        self.options = Options(policy=SandboxPolicy(allowlist=("pypi.org",)), skill_workflow=True)
        self.audit = audit
        self.ha = FakeHA()
        self.reviewer = FakeReviewer()
        self.skills = SkillStore(skills_dir)
        self.skills.propose("u1", "greet", "says hi", "{}", "async () => ha.intent.HassTurnOn({})", {},
                            uses={"ha": ["intent__HassTurnOff"]})
        self.open = {"abc": {"session_id": "abc", "created": 1.0, "last_used": 2.0, "expires_in_s": 90}}

    def list_sessions(self, everyone=False):
        assert everyone  # the panel shows every user's sessions
        return {"sessions": list(self.open.values())}

    async def close_session(self, sid, everyone=False):
        assert everyone
        if self.open.pop(sid, None) is None:
            return {"error": "session_not_found", "hint": "gone"}
        return {"closed": sid}


@pytest.fixture
def env(tmp_path):
    audit = Audit(tmp_path)
    audit.record("session.create", "abc", uid=60000)
    audit.record("code.exec", "abc", code="<img src=x onerror=alert(1)>", ms=3)
    svc = FakeService(audit, tmp_path / "skills")
    app = web.build_app(svc, tmp_path, allowed_clients={"testclient"})
    return TestClient(app), svc, tmp_path


def test_index_is_served_without_caching(env):
    client, _, _ = env
    r = client.get("/")
    assert r.status_code == 200 and "Code Interpreter" in r.text
    assert r.headers["cache-control"] == "no-store"


def test_live_sessions_and_settings(env):
    client, _, _ = env
    body = client.get("/api/sessions").json()
    assert [s["session_id"] for s in body["sessions"]] == ["abc"]
    assert body["settings"]["network_allowlist"] == ["pypi.org"]
    assert body["settings"]["memory_limit_mb"] == 2048


def test_audit_endpoints(env):
    client, _, _ = env
    days = client.get("/api/audit/days").json()["days"]
    assert len(days) == 1
    sessions = client.get(f"/api/audit/sessions?day={days[0]}").json()["sessions"]
    assert sessions[0]["session_id"] == "abc" and sessions[0]["code_runs"] == 1
    events = client.get(f"/api/audit/events?day={days[0]}&session_id=abc&event=code.exec").json()
    # Raw, unescaped in JSON: the UI must (and does) render it with textContent.
    assert events["events"][0]["detail"]["code"] == "<img src=x onerror=alert(1)>"


def test_bad_day_is_400(env):
    client, _, _ = env
    assert client.get("/api/audit/events?day=../../etc").status_code == 400
    assert client.get("/api/audit/sessions?day=").status_code == 400


def test_close_requires_the_ui_header_and_is_audited_with_the_user(env):
    client, svc, d = env
    assert client.post("/api/sessions/abc/close").status_code == 403
    assert "abc" in svc.open
    r = client.post("/api/sessions/abc/close",
                    headers={"X-Requested-With": "code-interpreter-ui", "X-Remote-User-Name": "admin"})
    assert r.status_code == 200 and r.json() == {"closed": "abc"}
    r = client.post("/api/sessions/abc/close", headers={"X-Requested-With": "code-interpreter-ui"})
    assert r.status_code == 404
    lines = [json.loads(x) for f in d.glob("audit-*.jsonl") for x in f.read_text().splitlines()]
    ui = [x for x in lines if x["event"] == "ui.close_session"]
    assert ui[0]["detail"] == {"user": "admin", "result": "closed"} and ui[1]["outcome"] == "error"


def test_requests_from_other_hosts_are_refused(tmp_path):
    app = web.build_app(FakeService(Audit(tmp_path), tmp_path / "skills"), tmp_path)  # default allowlist: ingress + loopback
    client = TestClient(app)  # client host is "testclient"
    assert client.get("/").status_code == 403
    assert client.get("/api/sessions").status_code == 403


def test_ui_never_injects_html():
    html = web.UI_FILE.read_text()
    assert "innerHTML" not in html and "insertAdjacentHTML" not in html and "document.write" not in html


def test_skills_are_listed_and_need_the_ui_header_to_approve(env):
    client, svc, _ = env
    body = client.get("/api/skills").json()
    assert body["workflow"] is True
    (k,) = body["skills"]
    assert (k["user"], k["name"], k["active"], k["pending"]["code"]) == ("Alice", "greet", None, "async () => ha.intent.HassTurnOn({})")
    assert k["check"] == {"pending": {"undeclared": ["intent__HassTurnOn"], "dynamic": []}}
    assert client.post("/api/skills/u1/greet/approve").status_code == 403
    r = client.post("/api/skills/u1/greet/approve", headers={"X-Requested-With": "code-interpreter-ui",
                                                              "X-Remote-User-Name": "admin"})
    assert r.status_code == 200 and svc.skills.get("u1", "greet")["active"]["approved_by"] == "admin"
    assert svc.reviewer.dismissed == [("u1", "greet")]  # the approval notification is done
    assert client.post("/api/skills/u1/greet/approve", headers={"X-Requested-With": "code-interpreter-ui"}).status_code == 400
    assert client.post("/api/skills/u1/greet/explode", headers={"X-Requested-With": "code-interpreter-ui"}).status_code == 404
    assert client.post("/api/skills/..%2Fx/greet/delete", headers={"X-Requested-With": "code-interpreter-ui"}).status_code in (400, 404)


def test_skill_code_is_only_inserted_as_text():
    html = web.UI_FILE.read_text()
    start = html.index("async function loadSkills")
    assert "innerHTML" not in html[start:html.index("async function loadLive")]
