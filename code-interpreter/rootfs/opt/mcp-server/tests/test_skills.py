import json

import pytest

from skills import CODE_CAP, SkillError, SkillStore, manifest_check, parse_uses

CODE = "async ({ room }) => room"


def test_propose_approve_and_a_new_proposal_does_not_replace_the_active_code(tmp_path):
    st = SkillStore(tmp_path)
    st.propose("u1", "lights_off", "turn lights off", "{room}", CODE, {"session_id": "s"})
    assert st.get("u1", "lights_off")["active"] is None
    st.approve("u1", "lights_off", "admin")
    st.propose("u1", "lights_off", "v2", "{room}", "async () => 2", {})
    s = st.get("u1", "lights_off")
    assert s["active"]["code"] == CODE and s["active"]["approved_by"] == "admin"
    assert s["pending"]["code"] == "async () => 2"
    st.reject("u1", "lights_off")
    assert st.get("u1", "lights_off")["pending"] is None and st.get("u1", "lights_off")["active"]["code"] == CODE


def test_rejecting_a_never_approved_skill_removes_it(tmp_path):
    st = SkillStore(tmp_path)
    st.propose("u1", "x", "", "", CODE, {})
    st.reject("u1", "x")
    assert st.get("u1", "x") is None and st.list("u1") == []


def test_skills_are_per_user(tmp_path):
    st = SkillStore(tmp_path)
    st.propose("u1", "a", "", "", CODE, {})
    assert st.list("u2") == [] and st.get("u2", "a") is None and st.users() == ["u1"]


@pytest.mark.parametrize("name", ["", "Bad", "1x", "../x", "a" * 41, "a-b", "list"])
def test_invalid_names_are_refused(tmp_path, name):
    with pytest.raises(SkillError):
        SkillStore(tmp_path).propose("u1", name, "", "", CODE, {})


@pytest.mark.parametrize("user", ["", "../etc", "a/b"])
def test_invalid_users_are_refused(tmp_path, user):
    with pytest.raises(SkillError):
        SkillStore(tmp_path).propose(user, "a", "", "", CODE, {})


def test_code_size_and_approving_nothing(tmp_path):
    st = SkillStore(tmp_path)
    with pytest.raises(SkillError):
        st.propose("u1", "a", "", "", "x" * (CODE_CAP + 1), {})
    with pytest.raises(SkillError):
        st.approve("u1", "missing", None)


def test_files_are_json_with_both_versions(tmp_path):
    st = SkillStore(tmp_path)
    st.propose("u1", "a", "d", "p", CODE, {"session_id": "s"})
    data = json.loads((tmp_path / "u1" / "a.json").read_text())
    assert set(data) == {"name", "active", "pending"} and data["pending"]["source"] == {"session_id": "s"}


def test_uses_are_normalized_from_json_or_objects():
    assert parse_uses('{"ha": ["b", "a", "a", 3], "hab": "x"}') == {"ha": ["a", "b"], "hab": [], "plugins": []}
    assert parse_uses("not json") == parse_uses(None) == {"ha": [], "hab": [], "plugins": []}


def test_propose_stores_the_manifest(tmp_path):
    st = SkillStore(tmp_path)
    st.propose("u1", "a", "", "", CODE, {}, uses={"ha": ["intent__HassTurnOff"]})
    assert st.get("u1", "a")["pending"]["uses"] == {"ha": ["intent__HassTurnOff"], "hab": [], "plugins": []}


CHECKED = """async ({ room }) => {
  const { entities } = await ha.homeassistant.GetLiveContext();
  await ha.intent.HassTurnOff({ name: room });
  await ha.call("light__HassLightSet", { name: room });
  await ha.admin.history.get_history({});
  await ha.admin.call('trace__get_trace', {});
  await ha.admin.hab(["automation", "get", room]);
  await ha.admin.hab(["script", "set", "x"]);
  const tools = await ha.tools();
}"""


def test_manifest_check_lists_undeclared_calls():
    uses = {"ha": ["homeassistant__GetLiveContext", "intent__HassTurnOff", "admin.history__get_history"],
            "hab": ["automation get"]}
    assert manifest_check(CHECKED, uses) == {
        "undeclared": ["admin.trace__get_trace", "light__HassLightSet", "hab script set x"], "dynamic": []}
    full = {"ha": uses["ha"] + ["admin.trace__get_trace", "light__HassLightSet"], "hab": ["automation get", "script"]}
    assert manifest_check(CHECKED, full) == {"undeclared": [], "dynamic": []}


def test_manifest_check_reads_optional_chaining():
    code = ("async () => { await ha.admin?.history.get_history({}); await ha?.intent.HassTurnOff({}); "
            "await ha.admin?.call('trace__get_trace'); await ha.admin?.hab(['automation', 'list']); }")
    assert manifest_check(code, {}) == {"undeclared": ["admin.history__get_history", "admin.trace__get_trace",
                                                       "intent__HassTurnOff", "hab automation list"], "dynamic": []}


def test_manifest_check_flags_calls_it_cannot_read():
    code = "async ({ tool, argv }) => { await ha.call(tool, {}); await ha.admin.hab(argv); await ha.admin.hab([argv[0]]); }"
    assert manifest_check(code, {}) == {"undeclared": [], "dynamic": ["ha.admin.hab", "ha.call"]}
    # a prefix that is not a whole word does not cover a command
    assert manifest_check('ha.admin.hab(["automations", "list"])', {"hab": ["automation"]})["undeclared"] == [
        "hab automations list"]
