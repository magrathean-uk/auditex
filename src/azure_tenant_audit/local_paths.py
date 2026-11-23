"""Absolute local paths never reach a run bundle: one normaliser applied where bundle files are written.

Every JSON, JSONL and log file the writer produces, and every text value of the SQLite evidence index, passes through
``LocalPathScrubber``. An absolute path of the operator's machine becomes:

- a path inside the run folder: run-relative (``raw/users.json``), the run folder itself its name;
- a path under the user's home: ``~`` plus the rest (``~/audits/waivers.json``);
- any other local path: its file or executable name only (``pwsh``, ``client.json``).

A path is recognised by a prefix the machine itself names (the run folder and the folder it sits in, the home, the
working and temporary folders, the Python install and library folders, and each absolute path on the command line),
POSIX or Windows style. Tenant evidence carries absolute paths of its own (Graph endpoints such as ``/users``,
Intune and Defender path settings), so a path is never rewritten for its shape alone. Console output to the operator
is not passed through here and may still name a path.
"""

from __future__ import annotations

import os
import re
import site
import sys
import sysconfig
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

_RUN, _HOME, _OTHER = "run", "home", "other"
_SEPARATORS = "/\\"
# A character that can continue a path name: a prefix followed by one is a different folder (/tmp vs /tmpfoo), and a
# prefix preceded by one is part of a longer path (/x/tmp is not /tmp).
_NAME_CHARS = r"A-Za-z0-9_.\-~"
# Where a path written in running text ends; a path that is the whole value, a flag's value or quoted may hold spaces.
_TEXT_END = re.compile(r"[\s'\"`,;()\[\]{}<>|]")
_VALUE_END = re.compile(r"[\n\r\t'\"`]|: ")
_FLAG_VALUE = re.compile(r"^-{1,2}[A-Za-z0-9][A-Za-z0-9_-]*=$")
_TRAILING = ".,:;"


def _variants(path: str | os.PathLike[str] | None) -> set[str]:
    if not path:
        return set()
    text = os.fspath(path)
    out = {text.rstrip(_SEPARATORS) or text}
    try:
        out.add(os.path.realpath(text).rstrip(_SEPARATORS))
    except (OSError, ValueError):
        pass
    for item in list(out):
        if "\\" in item:
            out.add(item.replace("\\", "/"))
    return {item for item in out if _is_absolute(item) and not _is_root(item)}


def _is_absolute(text: str) -> bool:
    return text.startswith("/") or bool(re.match(r"^[A-Za-z]:[\\/]", text)) or text.startswith("\\\\")


def _is_root(text: str) -> bool:
    return text in ("", "/", "\\", "\\\\") or bool(re.fullmatch(r"[A-Za-z]:[\\/]?", text))


def _depth(text: str) -> int:
    return len([part for part in re.split(r"[\\/]", text) if part and not re.fullmatch(r"[A-Za-z]:", part)])


def _interpreter_folders() -> set[str]:
    """Python's install and library folders (a library error names a file there); too-shallow ones (``/usr``) skipped."""
    found: set[str] = set()
    paths = sysconfig.get_paths()
    for key in ("stdlib", "platstdlib", "purelib", "platlib"):
        found |= _variants(paths.get(key))
    for item in (sys.prefix, sys.exec_prefix):
        found |= _variants(item)
    try:
        found |= {item for folder in site.getsitepackages() for item in _variants(folder)}
    except AttributeError:  # pragma: no cover - a virtualenv's old site module
        pass
    found |= _variants(site.getusersitepackages())
    found |= _variants(Path(__file__).resolve().parents[1])
    return {item for item in found if _depth(item) >= 3}


def _argv_paths(argv: Iterable[str]) -> set[str]:
    found: set[str] = set()
    for item in argv:
        if not isinstance(item, str):
            continue
        value = item.partition("=")[2] if item.startswith("-") and "=" in item else item
        if _is_absolute(value):
            found |= _variants(value)
    return found


class LocalPathScrubber:
    """Rewrite the operator's absolute local paths in a value bound for a run bundle (see the module docstring)."""

    def __init__(
        self,
        run_dir: str | os.PathLike[str],
        *,
        home: str | os.PathLike[str] | None = None,
        others: Iterable[str | os.PathLike[str]] | None = None,
        argv: Iterable[str] | None = None,
    ) -> None:
        run_text = os.fspath(run_dir)
        if not _is_absolute(run_text):
            run_text = os.path.abspath(run_text)
        self.run_name = re.split(r"[\\/]", run_text.rstrip(_SEPARATORS))[-1]
        self._run = _variants(run_text)
        home_text = os.fspath(home) if home is not None else os.path.expanduser("~")
        self._home = _variants(home_text) if _depth(home_text) >= 1 else set()
        if others is None:
            other: set[str] = set()
            other |= _variants(os.path.dirname(run_text.rstrip(_SEPARATORS)))
            try:
                other |= _variants(os.getcwd())
            except OSError:
                pass
            other |= _variants(tempfile.gettempdir())
            other |= _interpreter_folders()
        else:
            other = {item for value in others for item in _variants(value)}
        other |= _argv_paths(sys.argv if argv is None else argv)
        prefixes = sorted(self._run | self._home | other, key=len, reverse=True)
        self._pattern = (
            re.compile(
                rf"(?<![{_NAME_CHARS}/\\])(?:{'|'.join(re.escape(item) for item in prefixes)})(?![{_NAME_CHARS}])"
            )
            if prefixes
            else None
        )

    def __call__(self, value: Any) -> Any:
        return self.scrub(value)

    def scrub(self, value: Any) -> Any:
        """``value`` with every local path rewritten; strings in lists, tuples and mapping keys and values included."""
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            changed = False
            out: dict[Any, Any] = {}
            for key, item in value.items():
                new_key = self.text(key) if isinstance(key, str) else key
                new_item = self.scrub(item)
                changed = changed or new_key is not key or new_item is not item
                out[new_key] = new_item
            return out if changed else value
        if isinstance(value, (list, tuple)):
            items = [self.scrub(item) for item in value]
            if all(new is old for new, old in zip(items, value, strict=True)):
                return value
            return items if isinstance(value, list) else tuple(items)
        return value

    def text(self, value: str) -> str:
        if self._pattern is None or ("/" not in value and "\\" not in value):
            return value
        parts: list[str] = []
        position = 0
        for match in self._pattern.finditer(value):
            start = match.start()
            if start < position:
                continue
            end = self._token_end(value, start, match.end())
            token = value[start:end]
            trailing = ""
            if not self._is_value(value, start):
                while token and token[-1] in _TRAILING and len(token) > match.end() - start:
                    trailing = token[-1] + trailing
                    token = token[:-1]
            parts.append(value[position:start])
            parts.append(self._render(token) + trailing)
            position = end
        if not parts:
            return value
        parts.append(value[position:])
        return "".join(parts)

    @staticmethod
    def _is_value(value: str, start: int) -> bool:
        """The path opens the string, a ``--flag=`` value or a quotation, so it ends only where the value does."""
        return start == 0 or bool(_FLAG_VALUE.match(value[:start])) or value[start - 1] in "'\"`"

    def _token_end(self, value: str, start: int, prefix_end: int) -> int:
        if start > 0 and value[start - 1] in "'\"`":
            close = value.find(value[start - 1], prefix_end)
            return len(value) if close < 0 else close
        ender = _VALUE_END if self._is_value(value, start) else _TEXT_END
        found = ender.search(value, prefix_end)
        return len(value) if found is None else found.start()

    def _render(self, token: str) -> str:
        for prefix in sorted(self._run, key=len, reverse=True):
            rest = _rest(token, prefix)
            if rest is not None:
                return rest.replace("\\", "/") if rest else self.run_name
        for prefix in sorted(self._home, key=len, reverse=True):
            rest = _rest(token, prefix)
            if rest is not None:
                return "~/" + rest.replace("\\", "/") if rest else "~"
        name = re.split(r"[\\/]", token.rstrip(_SEPARATORS))[-1]
        return name or "<local-path>"


def _rest(token: str, prefix: str) -> str | None:
    if token == prefix:
        return ""
    if token.startswith(prefix) and token[len(prefix)] in _SEPARATORS:
        return token[len(prefix):].lstrip(_SEPARATORS)
    return None


def path_names(value: Any) -> Any:
    """``value`` with every string that is a whole absolute path reduced to its last name (``/srv/lab/run-1`` -> ``run-1``).

    For metadata that holds no tenant text, such as an offline sample's fixture provenance, where a path from another
    machine (a lab seed run) is not one this machine's ``LocalPathScrubber`` can recognise.
    """
    if isinstance(value, str):
        if _is_absolute(value) and not _is_root(value):
            return re.split(r"[\\/]", value.rstrip(_SEPARATORS))[-1]
        return value
    if isinstance(value, dict):
        return {key: path_names(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [path_names(item) for item in value]
    return value
