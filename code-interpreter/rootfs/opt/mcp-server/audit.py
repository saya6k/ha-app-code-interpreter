"""JSONL audit log (SPEC §3.7).

One file per UTC day under /data/audit (app-private, in HA backups), one JSON
object per line: time, event, session_id, outcome, detail. Execution output
is never stored, only its size. The app log gets a one-line summary.
A failing write is logged and swallowed: auditing must not break a tool call.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

log = logging.getLogger("mcp-server")

AUDIT_DIR = Path("/data/audit")
CODE_CAP = 64 * 1024


def code_detail(source: str, key: str = "code") -> dict:
    """Source text (capped) plus its hash; `key` names it (code / command)."""
    data = source.encode()
    return {
        key: data[:CODE_CAP].decode(errors="ignore"),
        f"{key}_truncated": len(data) > CODE_CAP,
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Audit:
    def __init__(self, directory: Path = AUDIT_DIR, retention_days: int = 30,
                 clock: Callable[[], float] = time.time) -> None:
        self.dir = Path(directory)
        self.retention_days = retention_days
        self._clock = clock

    def record(self, event: str, session_id: str | None, outcome: str = "ok", **detail) -> None:
        now = datetime.fromtimestamp(self._clock(), timezone.utc)
        entry = {
            "time": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event": event,
            "session_id": session_id,
            "outcome": outcome,
            "detail": detail,
        }
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            with open(self.dir / f"audit-{now:%Y%m%d}.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError as e:
            log.error("[audit] write failed (%s): %s", event, e)
        extra = f" {detail['ms']}ms" if "ms" in detail else ""
        log.info("[audit] %s sid=%s %s%s", event, session_id or "-", outcome, extra)

    def prune(self) -> None:
        cutoff = self._clock() - self.retention_days * 86400
        for p in self.dir.glob("audit-*.jsonl"):
            try:
                if p.stat().st_mtime < cutoff:
                    p.unlink()
            except OSError as e:
                log.error("[audit] prune failed for %s: %s", p.name, e)
