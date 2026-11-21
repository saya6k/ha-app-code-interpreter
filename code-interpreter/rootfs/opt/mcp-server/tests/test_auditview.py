import json

import pytest

import auditview


def write(d, day, events):
    with open(d / f"audit-{day}.jsonl", "a") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


def ev(t, event, sid, outcome="ok", **detail):
    return {"time": t, "event": event, "session_id": sid, "outcome": outcome, "detail": detail}


@pytest.fixture
def audit_dir(tmp_path):
    write(tmp_path, "20261121", [
        ev("2026-11-21T10:00:00Z", "session.create", "a", uid=60000),
        ev("2026-11-21T10:00:01Z", "code.exec", "a", code="1+1", ms=5),
        ev("2026-11-21T10:00:02Z", "code.exec", "a", "error", code="1/0", error="ZeroDivisionError"),
        ev("2026-11-21T10:00:03Z", "net.connect", "a", "allowed", host="pypi.org"),
        ev("2026-11-21T10:00:04Z", "net.connect", "a", "denied", host="example.com"),
        ev("2026-11-21T10:00:04Z", "policy.violation", "a", "denied", kind="egress"),
        ev("2026-11-21T10:05:00Z", "session.destroy", "a", reason="idle", lifetime_s=300),
        ev("2026-11-21T11:00:00Z", "session.create", "b", uid=60001),
        ev("2026-11-21T11:00:01Z", "file.import", "b", share_path="x.csv"),
    ])
    write(tmp_path, "20261122", [ev("2026-11-22T09:00:00Z", "session.create", "c")])
    (tmp_path / "notes.txt").write_text("ignored")
    (tmp_path / "audit-20261123.jsonl").write_text('{"time": "x", "event": "e"\nnot json\n')
    return tmp_path


def test_days_are_listed_newest_first(audit_dir):
    assert auditview.days(audit_dir) == ["20261123", "20261122", "20261121"]


def test_days_of_missing_dir_is_empty(tmp_path):
    assert auditview.days(tmp_path / "absent") == []


def test_sessions_summary_for_a_day(audit_dir):
    s = {x["session_id"]: x for x in auditview.sessions(audit_dir, "20261121")}
    assert list(s) == ["b", "a"]  # newest activity first
    a = s["a"]
    assert (a["started"], a["ended"], a["end_reason"]) == ("2026-11-21T10:00:00Z", "2026-11-21T10:05:00Z", "idle")
    assert (a["code_runs"], a["errors"], a["net_allowed"], a["net_denied"], a["violations"]) == (2, 1, 1, 1, 1)
    assert s["b"]["ended"] is None and s["b"]["events"] == 2


def test_events_filter_by_session_and_type_newest_first(audit_dir):
    got = auditview.events(audit_dir, "20261121", session_id="a", event="code.exec")
    assert [e["detail"]["code"] for e in got["events"]] == ["1/0", "1+1"]
    assert got["total"] == 2 and got["truncated"] is False


def test_events_limit_marks_truncation(audit_dir):
    got = auditview.events(audit_dir, "20261121", limit=3)
    assert len(got["events"]) == 3 and got["total"] == 9 and got["truncated"] is True
    assert got["events"][0]["event"] == "file.import"


def test_corrupt_lines_are_skipped_not_fatal(audit_dir):
    assert auditview.events(audit_dir, "20261123")["events"] == []


@pytest.mark.parametrize("day", ["../etc", "2026112", "abcdefgh", "20261121/../x", ""])
def test_day_must_be_eight_digits(audit_dir, day):
    with pytest.raises(ValueError):
        auditview.events(audit_dir, day)
