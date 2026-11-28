import json

import pytest

from skills import CODE_CAP, SkillError, SkillStore, calls_in, tool_summary

CODE = "async ({ room }) => room"


def test_a_saved_skill_is_in_force_and_a_save_replaces_it(tmp_path):
    st = SkillStore(tmp_path)
    st.save("u1", "lights_off", "code", "turn lights off", CODE, "{room}", {"session_id": "s"})
    assert st.get("u1", "lights_off")["code"] == CODE
    st.touch("u1", "lights_off")
    st.save("u1", "lights_off", "guide", "how to turn lights off", "Ask which room first.")
    s = st.get("u1", "lights_off")
    assert (s["kind"], s["guide"], "code" in s) == ("guide", "Ask which room first.", False)
    assert s["used"]  # replacing keeps when it last ran
    st.delete("u1", "lights_off")
    assert st.get("u1", "lights_off") is None
    with pytest.raises(SkillError):
        st.delete("u1", "lights_off")


def test_skills_are_per_user(tmp_path):
    st = SkillStore(tmp_path)
    st.save("u1", "a", "code", "d", CODE)
    assert st.list("u2") == [] and st.get("u2", "a") is None and st.users() == ["u1"]


@pytest.mark.parametrize("name", ["", "Bad", "1x", "../x", "a" * 41, "a-b", "list", "request", "find", "save", "delete"])
def test_invalid_names_are_refused(tmp_path, name):
    with pytest.raises(SkillError):
        SkillStore(tmp_path).save("u1", name, "code", "d", CODE)


@pytest.mark.parametrize("user", ["", "../etc", "a/b"])
def test_invalid_users_are_refused(tmp_path, user):
    with pytest.raises(SkillError):
        SkillStore(tmp_path).save(user, "a", "code", "d", CODE)


@pytest.mark.parametrize("kind, body, description", [
    ("code", "x" * (CODE_CAP + 1), "d"), ("code", "", "d"), ("guide", CODE, "  "), ("macro", CODE, "d")])
def test_size_description_and_kind_are_checked(tmp_path, kind, body, description):
    with pytest.raises(SkillError):
        SkillStore(tmp_path).save("u1", "a", kind, description, body)


def test_files_written_while_skills_waited_for_approval_still_load(tmp_path):
    (tmp_path / "u1").mkdir()
    (tmp_path / "u1" / "old.json").write_text(json.dumps({"name": "old", "active": None, "used": 5, "pending": {
        "description": "d", "params": "{}", "code": CODE, "uses": {}, "proposed": 1.0, "source": {"session_id": "s"}}}))
    (tmp_path / "u1" / "note.json").write_text(json.dumps({"name": "note", "kind": "guide", "pending": None,
                                                           "active": {"description": "g", "guide": "be brief"}}))
    st = SkillStore(tmp_path)
    assert st.get("u1", "old") == {"name": "old", "kind": "code", "description": "d", "params": "{}", "code": CODE,
                                   "saved": 1.0, "source": {"session_id": "s"}, "used": 5}
    assert st.get("u1", "note")["guide"] == "be brief"


def test_an_approval_era_update_replaces_the_version_it_waited_beside(tmp_path):
    (tmp_path / "u1").mkdir()
    (tmp_path / "u1" / "a.json").write_text(json.dumps({"name": "a", "active": {"description": "v1", "code": "async () => 1"},
                                                        "pending": {"description": "v2", "code": "async () => 2"}}))
    skill = SkillStore(tmp_path).get("u1", "a")
    assert (skill["description"], skill["code"]) == ("v2", "async () => 2")


def test_the_listing_is_recent_first_capped_and_counts_the_rest(tmp_path):
    st = SkillStore(tmp_path)
    for name in ("alpha", "beta", "gamma"):
        st.save("u1", name, "code", f"{name} " + "x" * 200, CODE)
    st.touch("u1", "gamma")
    listed, more = st.listing("u1", cap=2)
    assert [s["name"] for s in listed] == ["gamma", "alpha"] and more == 1
    assert listed[0]["kind"] == "code" and len(listed[0]["description"]) == 120


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


def test_calls_in_lists_what_the_code_visibly_calls():
    assert calls_in(CHECKED) == {"calls": ["admin.history__get_history", "admin.trace__get_trace",
                                           "homeassistant__GetLiveContext", "intent__HassTurnOff", "light__HassLightSet",
                                           "hab automation get", "hab script set x"], "dynamic": []}


def test_calls_in_reads_optional_chaining():
    code = ("async () => { await ha.admin?.history.get_history({}); await ha?.intent.HassTurnOff({}); "
            "await ha.admin?.call('trace__get_trace'); await ha.admin?.hab(['automation', 'list']); }")
    assert calls_in(code) == {"calls": ["admin.history__get_history", "admin.trace__get_trace",
                                        "intent__HassTurnOff", "hab automation list"], "dynamic": []}


def test_calls_in_flags_calls_it_cannot_read():
    code = "async ({ tool, argv }) => { await ha.call(tool, {}); await ha.admin.hab(argv); await ha.admin.hab([argv[0]]); }"
    assert calls_in(code) == {"calls": [], "dynamic": ["ha.admin.hab", "ha.call"]}


def test_calls_in_covers_plugin_tools():
    code = ('async () => { await plugins.memory.search({}); await plugins["multi-service-mcp"].find_places({}); '
            'await plugins.call("memory__save", {}); const t = await plugins.tools(); }')
    assert calls_in(code) == {"calls": ["plugin memory__save", "plugin memory__search",
                                        "plugin multi-service-mcp__find_places"], "dynamic": []}
    assert calls_in("plugins.call(name, {})")["dynamic"] == ["plugins.call"]
    # optional chaining, as the tool description writes plugins?.<server>.<tool>
    chained = 'await plugins?.memory.search({}); await plugins?.["multi-service-mcp"]?.find_places({}); plugins?.call("x__y")'
    assert calls_in(chained)["calls"] == [
        "plugin memory__search", "plugin multi-service-mcp__find_places", "plugin x__y"]


SUGGEST = {"name": "wardrowbe__suggest_outfit", "description": "Generate a new outfit.\nMore.", "input_schema": {
    "type": "object", "required": ["occasion"], "properties": {
        "occasion": {"type": "string", "enum": ["casual", "work"]},
        "temperature_unit": {"type": "string", "enum": ["celsius", "fahrenheit"]},
        "temperature": {"type": "number", "minimum": -60},
        "domain": {"type": "array", "items": {"type": "string", "enum": ["light"]}},
        "percentage": {"allOf": [{"type": "integer"}, {"type": "number"}]},
        "volume_step": {"anyOf": [{"type": "string", "enum": ["down", "up"]}, {"type": "integer"}]},
        "is_volume_muted": {"description": "no type"}}}}


def test_tool_summaries_give_types_allowed_values_and_required_args():
    s = tool_summary(SUGGEST, "plugin.")
    assert s["name"] == "plugin.wardrowbe__suggest_outfit" and s["description"] == "Generate a new outfit."
    assert s["args"] == {"domain": "array of one of light", "is_volume_muted": "any", "occasion": "one of casual|work",
                         "percentage": "integer or number", "temperature": "number",
                         "temperature_unit": "one of celsius|fahrenheit", "volume_step": "one of down|up or integer"}
    assert s["required"] == ["occasion"]
