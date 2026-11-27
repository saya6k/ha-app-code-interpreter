"""Per-user skills: reusable functions proposed from finished sessions, used
only after an administrator approves them (SPEC-code-mode §3.11).

One JSON file per skill under /data/skills/<user_id>/<name>.json, holding
the approved version ("active") and a proposal waiting for review
("pending"), so a new proposal never replaces code that is in use until
someone approves it.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

ROOT = Path("/data/skills")
NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
USER_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
CODE_CAP = 8192
TEXT_CAP = 500
PER_USER_CAP = 50


class SkillError(ValueError):
    pass


class SkillStore:
    def __init__(self, root: Path = ROOT) -> None:
        self.root = root

    def _dir(self, user: str) -> Path:
        if not USER_RE.match(user or ""):
            raise SkillError("unknown user")
        return self.root / user

    def _path(self, user: str, name: str) -> Path:
        if not NAME_RE.match(name or ""):
            raise SkillError(f"invalid skill name {name!r}: lowercase letters, digits and _")
        return self._dir(user) / f"{name}.json"

    def _read(self, path: Path) -> dict | None:
        try:
            return json.loads(path.read_text())
        except (OSError, ValueError):
            return None

    def _write(self, path: Path, data: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1))
        os.replace(tmp, path)  # never a half-written skill

    def users(self) -> list[str]:
        return sorted(p.name for p in self.root.iterdir() if p.is_dir()) if self.root.is_dir() else []

    def list(self, user: str) -> list[dict]:
        d = self._dir(user)
        if not d.is_dir():
            return []
        out = []
        for p in sorted(d.glob("*.json")):
            if (s := self._read(p)) is not None:
                out.append(s)
        return out

    def get(self, user: str, name: str) -> dict | None:
        return self._read(self._path(user, name))

    def propose(self, user: str, name: str, description: str, params: str, code: str, source: dict) -> dict:
        path = self._path(user, name)
        if not code or len(code) > CODE_CAP:
            raise SkillError(f"code must be 1..{CODE_CAP} characters")
        existing = self._read(path)
        if existing is None and len(self.list(user)) >= PER_USER_CAP:
            raise SkillError(f"{PER_USER_CAP} skills already; delete some first")
        skill = existing or {"name": name, "active": None, "pending": None}
        skill["pending"] = {
            "description": description[:TEXT_CAP], "params": params[:TEXT_CAP], "code": code,
            "proposed": time.time(), "source": source,
        }
        self._write(path, skill)
        return skill

    def approve(self, user: str, name: str, by: str | None) -> dict:
        path = self._path(user, name)
        skill = self._read(path)
        if not skill or not skill.get("pending"):
            raise SkillError("nothing to approve")
        skill["active"] = {**skill["pending"], "approved": time.time(), "approved_by": by}
        skill["pending"] = None
        self._write(path, skill)
        return skill

    def reject(self, user: str, name: str) -> dict:
        path = self._path(user, name)
        skill = self._read(path)
        if not skill or not skill.get("pending"):
            raise SkillError("nothing to reject")
        skill["pending"] = None
        if skill.get("active"):
            self._write(path, skill)
        else:
            path.unlink(missing_ok=True)
        return skill

    def delete(self, user: str, name: str) -> None:
        path = self._path(user, name)
        if not path.exists():
            raise SkillError("no such skill")
        path.unlink()
