"""Tenant text as valid interchange text.

A JSON ``\\ud800`` escape decodes to a lone UTF-16 surrogate: a Python ``str`` that cannot be encoded as UTF-8, hashed
as text or stored in the evidence index. Tenant text is made valid once, where it enters the run bundle (the offline
sample, each collector's payload, the raw, chunk and export records): every lone surrogate becomes U+FFFD, the Unicode
replacement character, and the rest of the value is unchanged. A high and a low surrogate side by side are one valid
character and are joined into it, not replaced. A repaired dictionary key never overwrites another entry: when its
repaired name is taken it gets a ``~2``, ``~3`` suffix.
"""
from __future__ import annotations

import re
from typing import Any

REPLACEMENT = "�"
_SURROGATE = re.compile("[\ud800-\udfff]")
_PAIR_OR_LONE = re.compile("([\ud800-\udbff][\udc00-\udfff])|[\ud800-\udfff]")


def valid_text(value: Any) -> tuple[Any, int]:
    """``value`` with each lone surrogate in its strings and keys replaced by U+FFFD, and how many were replaced.

    JSON-shaped values only (dicts, lists, tuples, strings, scalars). An unchanged container is returned as itself.
    """
    count = 0

    def fix(text: str) -> str:
        nonlocal count
        if _SURROGATE.search(text) is None:
            return text

        def one(match: re.Match[str]) -> str:
            nonlocal count
            pair = match.group(1)
            if pair:
                return chr(0x10000 + ((ord(pair[0]) - 0xD800) << 10) + (ord(pair[1]) - 0xDC00))
            count += 1
            return REPLACEMENT
        return _PAIR_OR_LONE.sub(one, text)

    def walk(item: Any) -> Any:
        if isinstance(item, str):
            return fix(item)
        if isinstance(item, dict):
            changed = False
            out = {}
            # A key that needs no repair keeps its name. A repaired key that would land on a name already taken (a
            # clean key, or another repaired key) gets the first free "~2", "~3" suffix, so no entry is overwritten.
            taken = {key for key in item if not (isinstance(key, str) and _SURROGATE.search(key))}
            for key, child in item.items():
                new_key = key
                if isinstance(key, str) and _SURROGATE.search(key):
                    new_key = base = fix(key)
                    suffix = 2
                    while new_key in taken:
                        new_key = f"{base}~{suffix}"
                        suffix += 1
                    taken.add(new_key)
                new_child = walk(child)
                changed = changed or new_key is not key or new_child is not child
                out[new_key] = new_child
            return out if changed else item
        if isinstance(item, (list, tuple)):
            children = [walk(child) for child in item]
            if all(new is old for new, old in zip(children, item, strict=True)):
                return item
            return children if isinstance(item, list) else tuple(children)
        return item

    return walk(value), count


def lone_surrogate_note(count: int) -> str:
    """The plain-words data-quality note for ``count`` replaced characters."""
    noun = "character" if count == 1 else "characters"
    return (f"{count} invalid {noun} in tenant text (lone UTF-16 surrogates) replaced with the Unicode replacement "
            "character U+FFFD before the evidence was saved; the rest of each value is unchanged.")
