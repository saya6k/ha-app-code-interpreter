"""ha.admin.hab(): Home Assistant Builder (hab) for administrators' cells
(SPEC-code-mode §3.10).

Permissions follow Claude Code's Code Mode in its `dontAsk` mode, the mode
for runs nobody can approve: every hab call is checked on its own; commands
hab marks `read` run; `write` and `destructive` ones run only if an allow
rule (option hab_allow) matches; deny rules (hab_deny) win over allow rules;
and a fixed set of commands no rule can allow, like the actions Claude Code
never auto-approves. hab runs here in the app, with the Supervisor token;
the sandbox only sends the arguments.
"""

from __future__ import annotations

import asyncio
import fnmatch
import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field

HAB = "/usr/local/bin/hab"
OUTPUT_CAP = 256 << 10

# No rule can allow these: they reach past Home Assistant's configuration
# (accounts, apps, backups, the host, firmware), run actions directly
# (call_action's reach), or ask the conversation agent again (recursion).
NEVER = (
    "action call", "app", "application-credential", "assist", "auth", "automation run", "backup",
    "esphome", "event fire", "host", "integration", "marketplace", "mount", "network", "scene activate",
    "script run", "system", "thread", "update", "user",
)
# Flags that would read the app's files or point hab at other credentials.
REFUSED_FLAGS = ("-f", "--file", "--url", "--access-token", "--token", "--config", "--refresh-token")


class HabRefused(PermissionError):
    """`kind` is the audit's policy.violation kind."""

    def __init__(self, message: str, kind: str = "hab") -> None:
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class Rules:
    allow: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()


def _matches(rule: str, words: list[str]) -> bool:
    """A rule is the command as typed, with * for any rest: "automation update *"."""
    return fnmatch.fnmatchcase(" ".join(words), rule.strip())


@dataclass
class Hab:
    rules: Rules = field(default_factory=Rules)
    binary: str = HAB
    token: str = field(default_factory=lambda: os.environ.get("SUPERVISOR_TOKEN", ""))
    _index: dict[str, str] | None = None

    async def _run(self, argv: list[str], stdin: str | None, timeout_s: float) -> tuple[int, bytes]:
        home = tempfile.mkdtemp(prefix="hab-")  # no stored credentials, no state between calls
        try:
            proc = await asyncio.create_subprocess_exec(
                self.binary, "--json", "--skip-update-check", "--config", home, *argv,
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                env={"PATH": "/usr/bin:/bin", "HOME": home, "SUPERVISOR_TOKEN": self.token,
                     "HAB_SKIP_UPDATE_CHECK": "1"},
            )
            try:
                out, _ = await asyncio.wait_for(proc.communicate((stdin or "").encode()), timeout_s)
            except TimeoutError:
                proc.kill()
                await proc.wait()
                raise
            return proc.returncode, out
        finally:
            shutil.rmtree(home, ignore_errors=True)

    async def index(self) -> dict[str, str]:
        """Command path ("automation update") -> side effect, from hab itself."""
        if self._index is None:
            found: dict[str, str] = {}
            offset = 0
            while True:
                _, out = await self._run(["schema", "--index", "--limit", "500", "--offset", str(offset)], None, 30)
                commands = json.loads(out)["data"]["commands"]
                found.update({c["path"].removeprefix("hab ").strip(): c["side_effect"] for c in commands})
                if len(commands) < 500:
                    break
                offset += 500
            self._index = found
        return self._index

    async def check(self, argv: list[str]) -> tuple[str, str]:
        """(command path, side effect) if this call may run, else HabRefused."""
        if not argv or not all(isinstance(a, str) for a in argv):
            raise HabRefused("hab takes a list of strings, e.g. ['automation', 'get', 'night_lights']", "rpc")
        for a in argv:
            if a.split("=", 1)[0] in REFUSED_FLAGS:
                raise HabRefused(f"{a.split('=', 1)[0]} is not available here (pass data with -d or stdin)")
        words = [a for a in argv if not a.startswith("-")]
        index = await self.index()
        path = next((" ".join(words[:n]) for n in range(len(words), 0, -1) if " ".join(words[:n]) in index), None)
        if path is None:
            raise HabRefused(f"unknown hab command: {' '.join(words[:3])}")
        if any(path == g or path.startswith(g + " ") for g in NEVER):
            raise HabRefused(f"'hab {path}' is never available here")
        effect = index[path]
        if any(_matches(r, argv) for r in self.rules.deny):
            raise HabRefused(f"'hab {path}' is denied by hab_deny")
        if effect != "read" and not any(_matches(r, argv) for r in self.rules.allow):
            raise HabRefused(f"'hab {path}' changes Home Assistant ({effect}); add a hab_allow rule "
                             f"such as \"{path} *\" to the app's options to allow it")
        return path, effect

    async def call(self, argv: list[str], stdin: str | None, timeout_s: float) -> dict:
        code, out = await self._run(argv, stdin, timeout_s)
        text = out[:OUTPUT_CAP].decode(errors="replace")
        try:
            envelope = json.loads(text)
        except ValueError:
            envelope = {"success": code == 0, "output": text, "truncated": len(out) > OUTPUT_CAP}
        envelope.setdefault("exit_code", code)
        return envelope
