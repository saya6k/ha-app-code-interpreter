from rank import grams, rank


def names(items, text, cap=8):
    return [i["name"] for i in rank(items, text, lambda i: i["name"], lambda i: i.get("description"), cap)]


def test_camel_and_snake_case_names_split_into_words():
    assert {"hass", "turn", "off"} <= grams("intent__HassTurnOff")
    assert {"suggest", "outfit"} <= grams("wardrowbe__suggest_outfit")


def test_korean_particles_english_plurals_and_stopwords():
    assert "코디" in grams("코디를") and "light" in grams("lights")
    assert not grams("the of and")


def test_ranks_by_name_then_description_and_drops_stray_matches():
    tools = [
        {"name": "intent__HassTurnOff", "description": "Turns off a device or entity"},
        {"name": "intent__HassTurnOn", "description": "Turns on a device or entity"},
        {"name": "intent__HassLightSet", "description": "Sets the brightness of a light"},
    ]
    assert names(tools, "turn off the kitchen light")[0] == "intent__HassTurnOff"
    assert names(tools, "brightness") == ["intent__HassLightSet"]
    assert names(tools, "zzz") == [] and names(tools, "turn", cap=1) == ["intent__HassTurnOff"]
