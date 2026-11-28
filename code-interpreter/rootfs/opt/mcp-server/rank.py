"""Ranking by shared words, for skills.find() and the tool lists' find():
no tokenizer, no model (a home server has neither to spare)."""

from __future__ import annotations

import re

STOPWORDS = frozenset("a an and are as at be but by for from in is it of on or the to with".split())


def grams(text: str) -> set[str]:
    """What a request and an item can share: Korean words as character
    bigrams ("코디를" meets "코디"), other words whole and by their first five
    letters ("lights" meets "light"). English bigrams would make every
    description match ("th", "in"). snake_case and camelCase split into
    words (HassTurnOff is "hass turn off")."""
    text = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", text.replace("_", " "))
    out = set()
    for word in re.findall(r"\w+", text.casefold()):
        if word in STOPWORDS:
            continue
        out.add(word)
        if re.search("[가-힣]", word):
            out.update(word[i:i + 2] for i in range(len(word) - 1))
        else:
            out.add(word[:5])
    return out


def rank(items: list, text: str, name, description, cap: int) -> list:
    """The items that share the most of the request's words with their name
    (counted twice) and description, best first. One that scores under half
    the best shares only a stray word."""
    query = grams(text)
    scored = []
    for i, item in enumerate(items):
        score = 2 * len(query & grams(name(item))) + len(query & grams(description(item) or ""))
        if score:
            scored.append((-score, name(item), i))
    if not scored:
        return []
    best = -min(scored)[0]
    return [items[i] for score, _, i in sorted(scored)[:cap] if -score * 2 >= best]
