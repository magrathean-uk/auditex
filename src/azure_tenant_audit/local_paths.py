"""Absolute local paths never reach a run bundle: one normaliser applied where bundle files are written.

Every JSON, JSONL and log file the writer produces, and every text value of the SQLite evidence index, passes through
``LocalPathScrubber``. It knows a fixed set of local folders, collected once per run, and replaces only those folders
where a string starts with one (as an exact prefix followed by a path separator or the end of the name):

- the run folder: removed, so a path inside it is run-relative (``raw/users.json``); the folder alone is its name;
- the home folder: ``~`` (``~/audits/waivers.json``);
- each absolute path on the command line (an input file, ``--out``): its last name (``client.json``);
- the folder holding the run folder, the working and temporary folders, the folder of the PowerShell executable and of
  each command-line path, and Python's install and library folders: removed, so a file directly inside one keeps its
  name (``pwsh``) and anything deeper keeps the rest of its path as written.

Each folder is matched as written, resolved, with ``/`` for ``\\``, and in its JSON-escaped (and doubly escaped) form,
so a Windows path quoted inside an error message is found too. A folder only one level below the root (``/tmp``,
``/srv``, a home of ``/root``) is not used, apart from the run folder itself: tenant evidence uses such paths (an
organisational unit ``/tmp/Archive``) and a path below one names no person or workstation.

Every other string is left exactly as written. Tenant evidence carries absolute paths of its own (Graph endpoints
such as ``/users``, organisational units such as ``/Sales/London``, URL queries, policy text), so nothing is rewritten
for its shape alone. Console output to the operator is not passed through here and may still name a path. Log rows a
resumed run folder already held from an older version are left as they were written.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import site
import sys
import sysconfig
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

_SEPARATORS = "/\\"
# A character that can continue a path name: a prefix followed by one is a different folder (/tmp vs /tmpfoo), and a
# prefix preceded by one (or by a separator) is part of a longer path (/x/tmp is not /tmp).
_NAME_CHARS = r"A-Za-z0-9_.\-~"
# Replacement kinds, in the order that wins when two kinds name the same folder.
_RUN, _HOME, _NAMED, _OTHER = 0, 1, 2, 3


def _escaped(text: str) -> str:
    return json.dumps(text, ensure_ascii=False)[1:-1]


def _variants(path: str | os.PathLike[str] | None) -> set[str]:
    """``path`` as written, resolved and with ``/`` separators: the forms a run can write it in."""
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


def _last_name(text: str) -> str:
    return re.split(r"[\\/]", text.rstrip(_SEPARATORS))[-1]


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


def _argv_paths(argv: Iterable[str]) -> list[str]:
    found: list[str] = []
    for item in argv:
        if not isinstance(item, str):
            continue
        value = item.partition("=")[2] if item.startswith("-") and "=" in item else item
        if _is_absolute(value) and not _is_root(value):
            found.append(value)
    return found


def _parent(text: str) -> str:
    stripped = text.rstrip(_SEPARATORS)
    cut = max(stripped.rfind("/"), stripped.rfind("\\"))
    return stripped[:cut] if cut > 0 else ""


class LocalPathScrubber:
    """Replace this run's known local folders in a value bound for a run bundle (see the module docstring)."""

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
        self.run_name = _last_name(run_text)
        # Folder form -> (kind, the name a named path renders as).
        self._known: dict[str, tuple[int, str]] = {}
        self._add(_RUN, run_text, deep_only=False)
        self._add(_HOME, os.fspath(home) if home is not None else os.path.expanduser("~"))
        folders: list[str] = []
        if others is None:
            folders.append(_parent(run_text))
            try:
                folders.append(os.getcwd())
            except OSError:
                pass
            folders.append(tempfile.gettempdir())
            pwsh = shutil.which("pwsh")
            if pwsh:
                folders.append(os.path.dirname(pwsh))
            folders.extend(_interpreter_folders())
        else:
            folders.extend(os.fspath(item) for item in others)
        for path in _argv_paths(sys.argv if argv is None else argv):
            self._add(_NAMED, path)
            folders.append(_parent(path))
        for folder in folders:
            self._add(_OTHER, folder)
        forms = sorted(self._known, key=len, reverse=True)
        self._pattern = (
            re.compile(
                rf"(?<![{_NAME_CHARS}/\\])(?P<prefix>{'|'.join(re.escape(item) for item in forms)})"
                rf"(?:(?P<sep>[\\/]+)|(?![{_NAME_CHARS}]))"
            )
            if forms
            else None
        )

    def _add(self, kind: int, path: str, *, deep_only: bool = True) -> None:
        if not path or (deep_only and _depth(path) < 2):
            return
        name = _last_name(path)
        for form in _variants(path):
            for written in (form, _escaped(form), _escaped(_escaped(form))):
                held = self._known.get(written)
                if held is None or kind < held[0]:
                    self._known[written] = (kind, name)

    def __call__(self, value: Any) -> Any:
        return self.scrub(value)

    def scrub(self, value: Any) -> Any:
        """``value`` with every known local folder replaced; strings in lists, tuples and mapping keys included."""
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
        return self._pattern.sub(self._render, value)

    def _render(self, match: re.Match[str]) -> str:
        kind, name = self._known[match.group("prefix")]
        inside = match.group("sep") is not None
        if kind == _RUN:
            return "" if inside else self.run_name
        if kind == _HOME:
            return "~/" if inside else "~"
        if kind == _NAMED:
            return f"{name}/" if inside else name
        return "" if inside else "<local-path>"


def path_names(value: Any) -> Any:
    """``value`` with every string that is a whole absolute path reduced to its last name (``/srv/lab/run-1`` -> ``run-1``).

    For metadata that holds no tenant text, such as an offline sample's fixture provenance, where a path from another
    machine (a lab seed run) is not one this machine's ``LocalPathScrubber`` can recognise.
    """
    if isinstance(value, str):
        if _is_absolute(value) and not _is_root(value):
            return _last_name(value)
        return value
    if isinstance(value, dict):
        return {key: path_names(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [path_names(item) for item in value]
    return value


# An absolute path written in running text: it starts at a word boundary (not inside a URL or a longer path) and ends
# at white space or a quotation mark.
_PATH_IN_TEXT = re.compile(r"(?<![\w.~:/\\-])(?:[A-Za-z]:[\\/]|/)[^\s'\"`]+")


def path_names_in_text(text: str) -> str:
    """``text`` with every absolute path in it reduced to its last name.

    Only for a local diagnostic that holds no tenant text (a PowerShell module lookup on the operator's machine): it
    rewrites by shape, which tenant evidence must never be.
    """

    def name(match: re.Match[str]) -> str:
        token = match.group(0)
        stripped = token.rstrip(".,;:)]")
        return (_last_name(stripped) or stripped) + token[len(stripped):]

    return _PATH_IN_TEXT.sub(name, text)
