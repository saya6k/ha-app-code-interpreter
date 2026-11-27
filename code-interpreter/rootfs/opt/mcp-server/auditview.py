"""Read-only queries over the JSONL audit log, for the Ingress UI (no MCP deps)."""

from __future__ import annotations

import json
import re
from pathlib import Path

DAY_RE = re.compile(r"^\d{8}$")
FILE_RE = re.compile(r"^audit-(\d{8})\.jsonl$")
DEFAULT_LIMIT = 500


def days(directory: Path) -> list[str]:
    """Days with an audit file, newest first (YYYYMMDD)."""
    if not directory.is_dir():
        return []
    found = [m.group(1) for p in directory.iterdir() if (m := FILE_RE.match(p.name))]
    return sorted(found, reverse=True)


def _load(directory: Path, day: str) -> list[dict]:
    if not DAY_RE.match(day):
        raise ValueError(f"invalid day {day!r}: expected YYYYMMDD")
    path = directory / f"audit-{day}.jsonl"
    out: list[dict] = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue  # a torn last line (crash mid-write) must not hide the rest
                if isinstance(entry, dict) and "event" in entry:
                    out.append(entry)
    except FileNotFoundError:
        pass
    return out


def sessions(directory: Path, day: str) -> list[dict]:
    """Per-session summary for one day, most recently active first."""
    summary: dict[str, dict] = {}
    for e in _load(directory, day):
        sid = e.get("session_id")
        if not sid:
            continue
        s = summary.setdefault(sid, {
            "session_id": sid, "started": None, "ended": None, "end_reason": None,
            "last": None, "events": 0, "code_runs": 0, "commands": 0, "ha_calls": 0, "errors": 0,
            "files": 0, "net_allowed": 0, "net_denied": 0, "violations": 0,
        })
        s["events"] += 1
        s["last"] = e.get("time")
        kind, outcome = e["event"], e.get("outcome")
        if kind == "session.create":
            s["started"] = e.get("time")
        elif kind == "session.destroy":
            s["ended"] = e.get("time")
            s["end_reason"] = (e.get("detail") or {}).get("reason")
        elif kind == "code.exec":
            s["code_runs"] += 1
        elif kind == "command.exec":  # before 0.5.0
            s["commands"] += 1
        elif kind == "ha.call":
            s["ha_calls"] += 1
        elif kind.startswith("file."):
            s["files"] += 1
        elif kind == "net.connect":
            s["net_allowed" if outcome == "allowed" else "net_denied"] += 1
        elif kind == "policy.violation":
            s["violations"] += 1
        if outcome == "error":
            s["errors"] += 1
    return sorted(summary.values(), key=lambda s: s["last"] or "", reverse=True)


def events(
    directory: Path,
    day: str,
    *,
    session_id: str | None = None,
    event: str | None = None,
    limit: int = DEFAULT_LIMIT,
) -> dict:
    """Matching events for one day, newest first, at most `limit`."""
    matched = [
        e for e in _load(directory, day)
        if (session_id is None or e.get("session_id") == session_id)
        and (event is None or e["event"] == event)
    ]
    matched.reverse()
    return {"events": matched[:limit], "total": len(matched), "truncated": len(matched) > limit}
