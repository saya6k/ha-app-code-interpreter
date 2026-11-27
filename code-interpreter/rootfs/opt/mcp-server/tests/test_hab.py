import asyncio
import json
import os
import stat
import sys
import textwrap

import pytest

from hab import Hab, HabRefused, Rules

INDEX = {
    "automation get": "read", "automation update": "write", "automation delete": "destructive",
    "automation run": "write", "script create": "write", "dashboard patch": "write",
    "backup restore": "destructive", "action call": "write", "template render": "read", "schema": "read",
}


@pytest.fixture
def fake(tmp_path):
    """A stand-in hab: answers the schema index, echoes other calls as an envelope."""
    log = tmp_path / "calls.jsonl"
    script = tmp_path / "hab"
    script.write_text(textwrap.dedent(f"""\
        #!{sys.executable}
        import json, os, sys
        argv = sys.argv[1:]
        with open({str(log)!r}, "a") as f:
            f.write(json.dumps({{"argv": argv, "home": os.environ.get("HOME"), "token": os.environ.get("SUPERVISOR_TOKEN"),
                                "env": sorted(os.environ), "stdin": sys.stdin.read()}}) + "\\n")
        rest = [a for a in argv if a not in ("--json", "--skip-update-check")]
        if "--config" in rest:
            i = rest.index("--config"); del rest[i:i + 2]
        if rest[:2] == ["schema", "--index"]:
            print(json.dumps({{"data": {{"commands": [{{"path": "hab " + p, "side_effect": e}} for p, e in {INDEX!r}.items()]}}}}))
        elif rest[:1] == ["boom"]:
            print("not json"); sys.exit(3)
        else:
            print(json.dumps({{"success": True, "data": rest}}))
    """))
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script, log


def make(fake, allow=(), deny=()):
    return Hab(Rules(allow=allow, deny=deny), binary=str(fake[0]), token="tok")


def check(h, argv):
    return asyncio.run(h.check(argv))


def test_reads_run_and_writes_need_an_allow_rule(fake):
    h = make(fake)
    assert check(h, ["automation", "get", "night"]) == ("automation get", "read")
    with pytest.raises(HabRefused, match="add a hab_allow rule"):
        check(h, ["automation", "update", "night", "-d", "{}"])
    h = make(fake, allow=("automation update *",))
    assert check(h, ["automation", "update", "night", "-d", "{}"]) == ("automation update", "write")
    with pytest.raises(HabRefused, match="hab_allow"):
        check(h, ["script", "create", "x"])


def test_deny_wins_over_allow(fake):
    h = make(fake, allow=("automation *",), deny=("automation update night*",))
    with pytest.raises(HabRefused, match="hab_deny"):
        check(h, ["automation", "update", "night", "-d", "{}"])
    assert check(h, ["automation", "update", "day", "-d", "{}"])[0] == "automation update"


@pytest.mark.parametrize("argv", [["backup", "restore", "x"], ["action", "call", "light.turn_on"],
                                  ["automation", "run", "night"]])
def test_some_commands_no_rule_can_allow(fake, argv):
    with pytest.raises(HabRefused, match="never available"):
        check(make(fake, allow=("*",)), argv)


@pytest.mark.parametrize("flag", ["-f", "--file=/data/options.json", "--url", "--access-token", "--config"])
def test_flags_that_reach_app_files_or_other_credentials_are_refused(fake, flag):
    with pytest.raises(HabRefused, match="not available here"):
        check(make(fake, allow=("*",)), ["automation", "update", "x", flag, "v"])


@pytest.mark.parametrize("argv", [[], ["nope", "thing"], "automation get x", [1, 2]])
def test_unknown_or_malformed_calls_are_refused(fake, argv):
    with pytest.raises(HabRefused):
        check(make(fake), argv)


def test_call_runs_with_a_fresh_home_the_token_and_nothing_else(fake):
    h = make(fake)
    out = asyncio.run(h.call(["template", "render"], "{{ 1 + 1 }}", 10))
    assert out["success"] is True and out["data"] == ["template", "render"] and out["exit_code"] == 0
    rec = [json.loads(x) for x in fake[1].read_text().splitlines()][-1]
    assert rec["argv"][:4] == ["--json", "--skip-update-check", "--config", rec["home"]]
    assert rec["token"] == "tok" and rec["stdin"] == "{{ 1 + 1 }}"
    assert set(rec["env"]) <= {"PATH", "HOME", "SUPERVISOR_TOKEN", "HAB_SKIP_UPDATE_CHECK", "LC_CTYPE", "__CF_USER_TEXT_ENCODING"}
    assert not os.path.exists(rec["home"])  # removed after the call


def test_non_json_output_is_returned_as_text(fake):
    out = asyncio.run(make(fake).call(["boom"], None, 10))
    assert out == {"success": False, "output": "not json\n", "truncated": False, "exit_code": 3}
