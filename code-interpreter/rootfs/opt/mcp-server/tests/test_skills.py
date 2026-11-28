import json

import pytest

from skills import GUIDE_CAP, SkillError, SkillStore, calls_in, tool_summary

GUIDE = "When asked for an outfit, call plugins.wardrowbe.suggest_outfit({}) and mention the chance of rain."
CODE = "async ({ room }) => room"


def test_a_saved_skill_is_in_force_and_a_save_replaces_it(tmp_path):
    st = SkillStore(tmp_path)
    st.save("u1", "outfit", "suggest an outfit", GUIDE, {"session_id": "s"})
    assert st.get("u1", "outfit")["guide"] == GUIDE
    st.touch("u1", "outfit")
    st.save("u1", "outfit", "suggest an outfit", "Ask about the occasion first.")
    s = st.get("u1", "outfit")
    assert s["guide"] == "Ask about the occasion first." and s["used"]  # replacing keeps when it last ran
    st.delete("u1", "outfit")
    assert st.get("u1", "outfit") is None
    with pytest.raises(SkillError):
        st.delete("u1", "outfit")


def test_skills_are_per_user(tmp_path):
    st = SkillStore(tmp_path)
    st.save("u1", "a", "d", GUIDE)
    assert st.list("u2") == [] and st.get("u2", "a") is None and st.users() == ["u1"]


@pytest.mark.parametrize("name", ["", "Bad", "1x", "../x", "a" * 41, "a-b", "list", "request", "find", "save", "delete"])
def test_invalid_names_are_refused(tmp_path, name):
    with pytest.raises(SkillError):
        SkillStore(tmp_path).save("u1", name, "d", GUIDE)


@pytest.mark.parametrize("user", ["", "../etc", "a/b"])
def test_invalid_users_are_refused(tmp_path, user):
    with pytest.raises(SkillError):
        SkillStore(tmp_path).save(user, "a", "d", GUIDE)


@pytest.mark.parametrize("guide, description", [("x" * (GUIDE_CAP + 1), "d"), ("  ", "d"), (GUIDE, "  ")])
def test_size_and_description_are_checked(tmp_path, guide, description):
    with pytest.raises(SkillError):
        SkillStore(tmp_path).save("u1", "a", description, guide)


def test_routines_from_before_become_guides_that_say_how_to_run_them(tmp_path):
    (tmp_path / "u1").mkdir()
    (tmp_path / "u1" / "old.json").write_text(json.dumps({"name": "old", "active": None, "used": 5, "pending": {
        "description": "d", "params": "{ room }", "code": CODE, "uses": {}, "proposed": 1.0, "source": {"session_id": "s"}}}))
    (tmp_path / "u1" / "flat.json").write_text(json.dumps({"name": "flat", "kind": "code", "description": "f",
                                                           "params": "", "code": CODE, "saved": 2.0}))
    (tmp_path / "u1" / "note.json").write_text(json.dumps({"name": "note", "kind": "guide", "pending": None,
                                                           "active": {"description": "g", "guide": "be brief"}}))
    st = SkillStore(tmp_path)
    old = st.get("u1", "old")
    assert old == {"name": "old", "description": "d", "guide": old["guide"], "saved": 1.0, "source": {"session_id": "s"},
                   "used": 5}
    assert "{ room }" in old["guide"] and f"const routine = {CODE};" in old["guide"]
    assert CODE in st.get("u1", "flat")["guide"] and st.get("u1", "note")["guide"] == "be brief"


def test_an_approval_era_update_replaces_the_version_it_waited_beside(tmp_path):
    (tmp_path / "u1").mkdir()
    (tmp_path / "u1" / "a.json").write_text(json.dumps({"name": "a", "active": {"description": "v1", "guide": "one"},
                                                        "pending": {"description": "v2", "guide": "two"}}))
    skill = SkillStore(tmp_path).get("u1", "a")
    assert (skill["description"], skill["guide"]) == ("v2", "two")


def test_the_listing_is_recent_first_capped_and_counts_the_rest(tmp_path):
    st = SkillStore(tmp_path)
    for name in ("alpha", "beta", "gamma"):
        st.save("u1", name, f"{name} " + "x" * 200, GUIDE)
    st.touch("u1", "gamma")
    listed, more = st.listing("u1", cap=2)
    assert [s["name"] for s in listed] == ["gamma", "alpha"] and more == 1
    assert set(listed[0]) == {"name", "description"} and len(listed[0]["description"]) == 120


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
