import json
import os
import time

import audit as audit_mod
from audit import Audit


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


def lines(d):
    out = []
    for f in sorted(d.glob("audit-*.jsonl")):
        out += [json.loads(x) for x in f.read_text().splitlines()]
    return out


def test_record_appends_one_json_line_per_event_with_common_fields(tmp_path):
    a = Audit(tmp_path, retention_days=30, clock=Clock(1795267200.0))  # 2026-11-21 13:20 UTC
    a.record("session.create", "s1", uid=60000)
    a.record("code.exec", "s1", outcome="error", ms=12)
    got = lines(tmp_path)
    assert [g["event"] for g in got] == ["session.create", "code.exec"]
    assert got[1] == {"time": "2026-11-21T13:20:00Z", "event": "code.exec", "session_id": "s1",
                      "outcome": "error", "detail": {"ms": 12}}
    assert (tmp_path / "audit-20261121.jsonl").exists()


def test_files_roll_over_by_utc_day(tmp_path):
    clock = Clock(1795267200.0)
    a = Audit(tmp_path, retention_days=30, clock=clock)
    a.record("x", None)
    clock.t += 86400
    a.record("y", None)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["audit-20261121.jsonl", "audit-20261122.jsonl"]


def test_prune_deletes_files_older_than_retention_only(tmp_path):
    now = 1795267200.0
    for name, age_days in (("audit-20261001.jsonl", 51), ("audit-20261101.jsonl", 20), ("other.txt", 99)):
        p = tmp_path / name
        p.write_text("{}\n")
        os.utime(p, (now - age_days * 86400,) * 2)
    Audit(tmp_path, retention_days=30, clock=Clock(now)).prune()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["audit-20261101.jsonl", "other.txt"]


def test_code_detail_caps_source_and_hashes_it():
    d = audit_mod.code_detail("x" * 70000)
    assert len(d["code"]) == audit_mod.CODE_CAP and d["code_truncated"] is True
    assert len(d["sha256"]) == 64
    assert audit_mod.code_detail("1+1")["code_truncated"] is False


def test_write_failure_is_logged_not_raised(tmp_path, caplog):
    blocker = tmp_path / "audit"
    blocker.write_text("not a dir")
    a = Audit(blocker, retention_days=30)
    with caplog.at_level("ERROR"):
        a.record("x", None)  # must not break the tool call
    assert "audit" in caplog.text


def test_summary_line_goes_to_the_app_log(tmp_path, caplog):
    a = Audit(tmp_path, retention_days=30)
    with caplog.at_level("INFO"):
        a.record("code.exec", "abc", ms=132)
    assert "[audit] code.exec sid=abc ok" in caplog.text
    assert time  # keep import used
