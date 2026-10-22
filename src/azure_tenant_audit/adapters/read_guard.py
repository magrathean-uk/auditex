"""Read-only command guard shared by the m365 CLI, PowerShell and Microsoft365DSC adapters.

Every adapter calls :func:`check_command` before it starts a process, so a string that is not on
the read allowlist never reaches ``subprocess``. The check is a syntactic allowlist, not a
PowerShell parser: it fails closed on anything it cannot classify. The authoritative read-only
boundary is still the read-only role and scopes granted to the auditor; this guard stops a
mistyped or injected write verb from being tried at all and makes the refusal visible in the
audit log.

Allowed:

* ``m365``: the last command word is ``list``, ``get`` or ``status``, or the command is an
  ``outlook report <name>`` usage report. The executable must be ``m365``.
* PowerShell: every command at a command position is ``Get-*``, one of a small set of
  read-shaping pipeline cmdlets (``Select-Object``, ``Where-Object``, ``Sort-Object``,
  ``Measure-Object``, ``ConvertTo-Json`` and so on) or ``Search-UnifiedAuditLog``. Comments,
  backtick escapes, redirection, here-strings, static member access (``::``), the call operator
  on anything but a script block, subexpressions inside double-quoted strings, and method calls
  other than a few string helpers are refused, because each can hide or run another command.
* Microsoft365DSC: the PowerShell rules plus ``Export-M365DSCConfiguration``, the one export
  cmdlet that reads the tenant (it writes only local files).

Both languages are checked as plain ASCII: any non-ASCII character or control character other
than tab, line feed and carriage return is refused, because the CLI and PowerShell parsers treat
Unicode quotes, dashes and line breaks differently from this check. ``\r`` ends a statement
like ``\n``. The m365 check also parses the options: after the command words every token must be
a known option, or the value of a known value option, so the CLI parser cannot read a later bare
word (or ``--``) as part of the command.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import PurePath

from ..secret_hygiene import redact_text


M365_READ_VERBS = frozenset({"list", "get", "status"})
M365_REPORT_PREFIX = ("outlook", "report")
# Options the shipped read commands use. Anything else after the command words is refused, so a token
# the m365 parser would read as part of the command can never hide behind an option.
M365_VALUE_OPTIONS = frozenset({"--output", "-o", "--period", "--top"})
M365_FLAG_OPTIONS = frozenset({"--help", "-h", "--verbose", "--debug"})

POWERSHELL_READ_VERB = "get"
POWERSHELL_READ_COMMANDS = frozenset(
    {
        "select-object",
        "where-object",
        "sort-object",
        "measure-object",
        "convertto-json",
        "convertfrom-json",
        "out-null",
        "format-list",
        "format-table",
        "search-unifiedauditlog",
    }
)
DSC_READ_COMMANDS = frozenset({"export-m365dscconfiguration"})
POWERSHELL_LANGUAGE_WORDS = frozenset({"if", "elseif", "else", "foreach"})
POWERSHELL_READ_METHODS = frozenset(
    {"tostring", "tolower", "toupper", "trim", "contains", "startswith", "endswith"}
)

ADAPTER_KINDS = ("m365_cli", "powershell_graph", "m365dsc")
REFUSED_ERROR_CLASS = "command_refused"


_MAX_REASON_LENGTH = 160


class CommandRefused(ValueError):
    """The command is not on the read allowlist; nothing was executed.

    The reason is written to the audit log and shown to callers, and it can quote a word from the
    refused command, so it is redacted and clipped first.
    """

    def __init__(self, reason: str, *, adapter: str) -> None:
        safe = redact_text(reason)
        if len(safe) > _MAX_REASON_LENGTH:
            safe = safe[: _MAX_REASON_LENGTH - 3] + "..."
        super().__init__(safe)
        self.reason = safe
        self.adapter = adapter


class VettedCommand(str):
    """A PowerShell script an adapter has already checked and then wrapped.

    The Microsoft365DSC adapter checks the caller's command, then wraps it in a module-version
    guard (``Import-Module``/``Invoke-Expression``) that the read allowlist would refuse. The
    wrapper marks the wrapped text with this type so ``PowerShellGraphAdapter.run`` does not
    check it a second time; ``vetted_text`` is what the audit log records instead.
    """

    vetted_text: str
    source_adapter: str
    command_words: tuple[str, ...]

    def __new__(
        cls,
        value: str,
        *,
        vetted_text: str,
        source_adapter: str,
        command_words: tuple[str, ...] = (),
    ) -> "VettedCommand":
        item = super().__new__(cls, value)
        item.vetted_text = vetted_text
        item.source_adapter = source_adapter
        item.command_words = tuple(command_words)
        return item


@dataclass(frozen=True)
class CommandClass:
    """What the guard made of one command string."""

    adapter: str
    read_only: bool
    words: tuple[str, ...]
    reason: str | None = None

    @property
    def family(self) -> str:
        return " ".join(self.words)


@dataclass(frozen=True)
class _Token:
    kind: str  # "op", "word", "string" or "var"
    text: str
    start: int
    end: int


_VAR = re.compile(
    r"\$(?:\{[^}\n]*\}|(?:env|global|script|local|using):[A-Za-z_]\w*|[A-Za-z_]\w*|[?$^])"
)
_SPLAT = re.compile(r"@[A-Za-z_]\w*")
_WORD = re.compile(r"[^\s|;{}()\[\],=&<>'\"$@`#]+")
_NOUN = re.compile(r"[a-z][a-z0-9]*")
_NUMBER = re.compile(r"\d+(?:\.\d+)?")
_M365_WORD = re.compile(r"[A-Za-z][A-Za-z0-9-]*")
_DYNAMIC_MEMBER_FOLLOWERS = frozenset("'\"$([{@")
_SEPARATORS = frozenset({"|", ";", "\n", "{", "}", "(", "$(", "@(", "&&", "||", "&", "="})


def _require_plain_text(command: str, adapter: str) -> None:
    """Refuse non-ASCII and control characters (other than tab, LF and CR) anywhere in a command."""
    for character in command:
        code = ord(character)
        if code > 126 or (code < 32 and character not in "\t\n\r"):
            raise CommandRefused(f"character U+{code:04X} is not allowed in a command", adapter=adapter)


def _tokenize(script: str, adapter: str) -> list[_Token]:
    tokens: list[_Token] = []
    i = 0
    n = len(script)

    def refuse(reason: str) -> None:
        raise CommandRefused(reason, adapter=adapter)

    def add(kind: str, text: str, start: int, end: int) -> None:
        tokens.append(_Token(kind, text, start, end))

    while i < n:
        ch = script[i]
        if ch in " \t":
            i += 1
        elif ch in "\r\n":
            add("op", "\n", i, i + 1)  # PowerShell ends a statement at CR as well as LF
            i += 1
        elif ch == "#":
            refuse("comments are not allowed")
        elif ch == "`":
            refuse("backtick escapes are not allowed")
        elif ch in "<>":
            refuse("redirection and block comments are not allowed")
        elif ch in "'\"":
            end = _string_end(script, i, adapter)
            body = script[i + 1 : end]
            if ch == '"' and ("$(" in body or "`" in body):
                refuse("subexpressions and escapes inside double-quoted strings are not allowed")
            add("string", script[i : end + 1], i, end + 1)
            i = end + 1
        elif ch == "@":
            following = script[i + 1 : i + 2]
            if following in ("'", '"'):
                refuse("here-strings are not allowed")
            if following in ("(", "{"):
                add("op", "@" + following, i, i + 2)
                i += 2
                continue
            match = _SPLAT.match(script, i)
            if match is None:
                refuse("unsupported @ syntax")
            add("var", match.group(0), i, match.end())
            i = match.end()
        elif ch == "$":
            if script[i + 1 : i + 2] == "(":
                add("op", "$(", i, i + 2)
                i += 2
                continue
            match = _VAR.match(script, i)
            if match is None:
                refuse("unsupported variable syntax")
            add("var", match.group(0), i, match.end())
            i = match.end()
        elif ch == "&":
            if script[i + 1 : i + 2] == "&":
                add("op", "&&", i, i + 2)
                i += 2
                continue
            rest = script[i + 1 :].lstrip(" \t")
            if not rest.startswith("{"):
                refuse("the call operator may only run a script block")
            add("op", "&", i, i + 1)
            i += 1
        elif ch == "|":
            if script[i + 1 : i + 2] == "|":
                add("op", "||", i, i + 2)
                i += 2
            else:
                add("op", "|", i, i + 1)
                i += 1
        elif ch in ";{}()[],=":
            add("op", ch, i, i + 1)
            i += 1
        else:
            match = _WORD.match(script, i)
            if match is None:  # pragma: no cover - the character classes above are exhaustive
                refuse(f"unsupported character {ch!r}")
            word = match.group(0)
            if "::" in word:
                refuse("static member access is not allowed")
            if word.endswith(".") and script[match.end() : match.end() + 1] in _DYNAMIC_MEMBER_FOLLOWERS and match.end() < n:
                refuse("dynamic member access is not allowed")
            add("word", word, i, match.end())
            i = match.end()
    return tokens


def _string_end(script: str, start: int, adapter: str) -> int:
    quote = script[start]
    i = start + 1
    n = len(script)
    while i < n:
        if script[i] == quote:
            if script[i + 1 : i + 2] == quote:  # doubled quote is an escaped quote
                i += 2
                continue
            return i
        i += 1
    raise CommandRefused("unterminated string", adapter=adapter)


def _allowed_word(word: str, extra: frozenset[str]) -> bool:
    lowered = word.lower()
    if _NUMBER.fullmatch(lowered):
        return True  # a bare number is an expression, not a command
    if lowered in POWERSHELL_LANGUAGE_WORDS or lowered in POWERSHELL_READ_COMMANDS or lowered in extra:
        return True
    verb, separator, noun = lowered.partition("-")
    return bool(separator) and verb == POWERSHELL_READ_VERB and _NOUN.fullmatch(noun) is not None


def _command_words(script: str, adapter: str, extra: frozenset[str]) -> list[str]:
    """Words at a command position; raises CommandRefused for the first one that is not a read."""
    tokens = _tokenize(script, adapter)
    commands: list[str] = []
    for index, token in enumerate(tokens):
        previous = tokens[index - 1] if index else None
        following = tokens[index + 1] if index + 1 < len(tokens) else None
        if token.kind == "op" and token.text == "(" and previous is not None:
            # A method call is a word containing "." glued to "("; only a few string helpers are reads.
            if previous.kind == "word" and "." in previous.text and previous.end == token.start:
                method = previous.text.rsplit(".", 1)[1].lower()
                if method not in POWERSHELL_READ_METHODS:
                    raise CommandRefused(f"method call .{method or '()'} is not a read", adapter=adapter)
        if token.kind != "word":
            continue
        at_command = previous is None or (previous.kind == "op" and previous.text in _SEPARATORS)
        if not at_command:
            continue
        if following is not None and following.kind == "op" and following.text == "=":
            continue  # a hashtable key or an assignment target, not a command
        if not _allowed_word(token.text, extra):
            raise CommandRefused(f"{token.text} is not on the read allowlist", adapter=adapter)
        if token.text.lower() not in POWERSHELL_LANGUAGE_WORDS:
            commands.append(token.text)
    return commands


def check_powershell_command(script: str, *, adapter: str = "powershell_graph") -> tuple[str, ...]:
    """Cmdlets used by a read-only PowerShell script, or CommandRefused."""
    _require_plain_text(script, adapter)
    if not script.strip():
        raise CommandRefused("command is empty", adapter=adapter)
    extra = DSC_READ_COMMANDS if adapter == "m365dsc" else frozenset()
    return tuple(_command_words(script, adapter, extra))


def _m365_argv(command: str | list[str], adapter: str) -> list[str]:
    if isinstance(command, str):
        _require_plain_text(command, adapter)
        try:
            argv = shlex.split(command)
        except ValueError as exc:
            raise CommandRefused(f"command could not be parsed: {exc}", adapter=adapter) from exc
    else:
        argv = [str(item) for item in command]
        _require_plain_text(" ".join(argv), adapter)
    if not argv:
        raise CommandRefused("command is empty", adapter=adapter)
    if PurePath(argv[0]).name != "m365":
        raise CommandRefused("the executable is not m365", adapter=adapter)
    return argv


def _m365_split(argv: list[str]) -> tuple[list[str], list[str]]:
    """Command words (the leading tokens before the first option) and the tokens after them."""
    words: list[str] = []
    for item in argv[1:]:
        if item.startswith("-"):
            break
        words.append(item)
    return words, argv[1 + len(words) :]


def _check_m365_options(options: list[str], adapter: str) -> None:
    """Every token after the command words must be a known option or the value of a known value option.

    The m365 parser resolves the command from the bare words it finds, wherever they sit, so a stray
    word after an option (or after ``--``) could extend ``spo list`` into ``spo list remove``.
    """
    index = 0
    while index < len(options):
        token = options[index]
        if token == "--" or not token.startswith("-"):
            raise CommandRefused(f"unexpected token {token!r} after the command words", adapter=adapter)
        name, equals, value = token.partition("=")
        if name in M365_FLAG_OPTIONS:
            if equals:
                raise CommandRefused(f"option {name} takes no value", adapter=adapter)
            index += 1
        elif name in M365_VALUE_OPTIONS:
            if equals:
                if not value:
                    raise CommandRefused(f"option {name} needs a value", adapter=adapter)
                index += 1
            else:
                following = options[index + 1] if index + 1 < len(options) else ""
                if not following or following.startswith("-"):
                    raise CommandRefused(f"option {name} needs a value", adapter=adapter)
                index += 2
        else:
            raise CommandRefused(f"option {name} is not allowed", adapter=adapter)


def m365_command_words(command: str | list[str]) -> list[str]:
    """Command words of an m365 call without judging them; empty when the text is not an m365 call."""
    try:
        return _m365_split(_m365_argv(command, "m365_cli"))[0]
    except CommandRefused:
        return []


def check_m365_command(command: str | list[str], *, adapter: str = "m365_cli") -> tuple[str, ...]:
    """Command words of a read-only m365 CLI call, or CommandRefused."""
    words, options = _m365_split(_m365_argv(command, adapter))
    if not words:
        raise CommandRefused("no m365 command was given", adapter=adapter)
    for word in words:
        if not _M365_WORD.fullmatch(word):
            raise CommandRefused(f"command word {word!r} is not a plain word", adapter=adapter)
    _check_m365_options(options, adapter)
    lowered = tuple(word.lower() for word in words)
    if lowered[-1] in M365_READ_VERBS:
        return tuple(words)
    if len(lowered) >= 3 and lowered[:2] == M365_REPORT_PREFIX:
        return tuple(words)
    raise CommandRefused(f"m365 {' '.join(words)} does not end in list, get or status", adapter=adapter)


def check_command(adapter: str, command: str | list[str]) -> tuple[str, ...]:
    """Refuse ``command`` unless it is a read for ``adapter``; return its command words."""
    if adapter == "m365_cli":
        return check_m365_command(command, adapter=adapter)
    if adapter in {"powershell_graph", "m365dsc"}:
        if not isinstance(command, str):
            raise CommandRefused("a PowerShell command must be a string", adapter=adapter)
        return check_powershell_command(command, adapter=adapter)
    raise CommandRefused(f"unknown adapter {adapter!r}", adapter=str(adapter))


def words_are_read(adapter: str, words: list[str] | tuple[str, ...]) -> bool:
    """Whether logged command words are reads, judged by the same rules the adapters enforce.

    The API ledger calls this on the words an adapter recorded, so a log written by a build that
    did not enforce the allowlist is still classified correctly.
    """
    if not words:
        return False
    lowered = tuple(str(word).lower() for word in words)
    if adapter == "m365_cli":
        return lowered[-1] in M365_READ_VERBS or (len(lowered) >= 3 and lowered[:2] == M365_REPORT_PREFIX)
    if adapter in {"powershell_graph", "m365dsc"}:
        extra = DSC_READ_COMMANDS if adapter == "m365dsc" else frozenset()
        return all(_allowed_word(str(word), extra) for word in words)
    return False


def classify_command(adapter: str, command: str | list[str]) -> CommandClass:
    """Classify a logged command with the same rules the adapters enforce."""
    try:
        words = check_command(adapter, command)
    except CommandRefused as exc:
        return CommandClass(adapter=adapter, read_only=False, words=(), reason=exc.reason)
    return CommandClass(adapter=adapter, read_only=True, words=words)


def refusal_response(command: str, exc: CommandRefused) -> dict[str, str]:
    """Adapter result for a refused command; ``command`` is the already-redacted text."""
    return {
        "error": f"command_refused:{exc.reason}",
        "error_class": REFUSED_ERROR_CLASS,
        "command": command,
        "refusal_reason": exc.reason,
    }
