"""Bind run arguments and admit parsed CLI paths for one invocation."""
from __future__ import annotations

import argparse
from functools import wraps
import os
import stat
import sys
from typing import Any

from .guarded_io import UnsafeRunFileError, guard_session, open_pinned_binary
from .secret_hygiene import collect_sensitive_argv_values

_INPUT_FLAGS = frozenset({
    "--assessment", "--break-glass-accounts", "--cases", "--config", "--env", "--input",
    "--manifest", "--permission-hints", "--responses", "--sample", "--sensitive-users",
    "--training-overrides", "--waiver-file",
})
_RUN_FLAGS = frozenset({"--run-dir", "--resume-from", "--baseline", "--current", "--compare"})
_OUTPUT_FLAGS = frozenset({"--out", "--output", "--output-dir"})
_PATH_FLAGS = _INPUT_FLAGS | _RUN_FLAGS | _OUTPUT_FLAGS | {"--expect-manifest-sha256"}


def guarded_cli(function):
    """Keep identities pinned for the invocation and print only a fixed refusal."""
    @wraps(function)
    def wrapped(*args, **kwargs):
        message = None
        try:
            with guard_session():
                return function(*args, **kwargs)
        except UnsafeRunFileError as exc:
            message = str(exc)
        if message is not None:
            print(message, file=sys.stderr)
            return 2
        return 2
    return wrapped


def _all_actions(parser: argparse.ArgumentParser) -> list[argparse.Action]:
    actions: list[argparse.Action] = []
    for action in parser._actions:
        actions.append(action)
        if isinstance(action, argparse._SubParsersAction):
            for child in action.choices.values():
                actions.extend(_all_actions(child))
    return actions


def _arguments(parser: argparse.ArgumentParser, argv: list[str]) -> tuple[list[str], set[str]]:
    options = {option for action in _all_actions(parser) for option in action.option_strings}
    result: list[str] = []
    explicit: set[str] = set()
    index = 0
    while index < len(argv):
        arg = argv[index]
        flag = arg.partition("=")[0]
        if flag in _PATH_FLAGS:
            explicit.add(flag)
            if "=" not in arg and index + 1 < len(argv):
                value = argv[index + 1]
                next_flag = value.partition("=")[0]
                if value.startswith("-") and next_flag not in options:
                    result.append(arg + "=" + value)
                    index += 2
                    continue
        result.append(arg)
        index += 1
    return result, explicit


def _values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, str) and item]
    return []


def _bind(context, path: str, field: str) -> None:
    failed = False
    try:
        context.bind_run(path)
    except UnsafeRunFileError:
        failed = True
    if failed:
        raise UnsafeRunFileError(field) from None


def _pin(context, path: str, field: str) -> None:
    try:
        with open_pinned_binary(path, field=field, context=context):
            pass
    except FileNotFoundError:
        # Preserve the caller's ordinary missing-file handling; unsafe is never optional.
        return


def admit_sensitive_env(context, explicit: str | None) -> None:
    selected = explicit if explicit is not None else os.environ.get("AUDITEX_SENSITIVE_USERS_FILE")
    if selected:
        _pin(context, selected, "sensitive-users")


def _admit_destination(context, path: str, field: str) -> None:
    parent = None
    descriptor = None
    failed = False
    try:
        with context._lock:
            context.discover_run(path)
            parent, name = context._parent(path)
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            info = os.fstat(descriptor)
            if field in {"out", "output-dir"}:
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                    raise UnsafeRunFileError(field)
            else:
                context._check_file(info, field, None)
    except FileNotFoundError:
        pass
    except (OSError, ValueError, TypeError):
        failed = True
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent is not None:
            os.close(parent)
    if failed:
        raise UnsafeRunFileError(field) from None


def parse_guarded(parser: argparse.ArgumentParser, argv: list[str]) -> argparse.Namespace:
    normalized, explicit = _arguments(parser, list(argv))
    sensitive_values = collect_sensitive_argv_values(normalized)
    class _SafeParseFailure(Exception):
        def __init__(self, current: argparse.ArgumentParser, message: str) -> None:
            self.parser = current
            self.message = message

    if sensitive_values:
        # argparse can echo unknown or invalid values before returning control.
        # Keep its usage/help while replacing the diagnostic on every subparser.
        def sanitise_errors(current: argparse.ArgumentParser) -> None:
            def safe_error(message: str) -> None:
                reason = ("unrecognized arguments: ***redacted***" if message.startswith("unrecognized arguments:")
                          else "invalid arguments")
                raise _SafeParseFailure(current, reason) from None

            current.error = safe_error
            for action in current._actions:
                if isinstance(action, argparse._SubParsersAction):
                    for child in action.choices.values():
                        sanitise_errors(child)

        sanitise_errors(parser)
    failure = None
    try:
        args, unknown = parser.parse_known_args(normalized)
        if unknown:
            if sensitive_values:
                parser.error("unrecognized arguments: ***redacted***")
            else:
                parser.error("unrecognized arguments: " + " ".join(unknown))
    except _SafeParseFailure as exc:
        failure = exc.parser, exc.message
    if failure is not None:
        failed_parser, reason = failure
        failed_parser.print_usage(sys.stderr)
        failed_parser.exit(2, f"{failed_parser.prog}: error: {reason}\n")
    actions = _all_actions(parser)
    with guard_session() as context:
        for action in actions:
            flags = set(action.option_strings)
            selected = flags & explicit & _RUN_FLAGS
            if selected:
                field = sorted(selected)[0][2:]
                for path in _values(getattr(args, action.dest, None)):
                    _bind(context, path, field)
        for action in actions:
            if "--expect-manifest-sha256" in action.option_strings and "--expect-manifest-sha256" in explicit:
                for item in _values(getattr(args, action.dest, None)):
                    if "=" in item:
                        _bind(context, item.rsplit("=", 1)[0], "expect-manifest-sha256")
        # Explicit positional run roots are known before any file arguments are read.
        for action in actions:
            if not action.option_strings and action.dest in {"run_dir", "run_a", "run_b"}:
                for path in _values(getattr(args, action.dest, None)):
                    _bind(context, path, "run-dir")
        for action in actions:
            selected = set(action.option_strings) & explicit & _OUTPUT_FLAGS
            if selected:
                field = sorted(selected)[0][2:]
                for path in _values(getattr(args, action.dest, None)):
                    _admit_destination(context, path, field)
        for action in actions:
            if "--sensitive-users" in action.option_strings:
                admit_sensitive_env(context, getattr(args, action.dest, None))
                break
        for action in actions:
            selected = set(action.option_strings) & explicit & _INPUT_FLAGS
            if not selected:
                continue
            flag = sorted(selected)[0]
            for value in _values(getattr(args, action.dest, None)):
                if flag == "--break-glass-accounts":
                    if not value.startswith("@"):
                        continue
                    value = value[1:]
                _pin(context, value, flag[2:])
    return args
