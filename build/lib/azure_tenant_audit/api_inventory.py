from __future__ import annotations

import copy
import json
import re
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlparse

from .adapters.read_guard import CommandRefused, check_m365_command, m365_command_words, words_are_read


SCHEMA_VERSION = "2026-10-22"
_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
API_INVENTORY_ARTIFACT = "api-inventory.json"
LEDGER_SOURCE = "audit-log.jsonl"
# Longest list of refused or out-of-declaration calls written into the ledger; counts stay exact.
_MAX_LISTED = 100


def _rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, Mapping)]


def _text(value: Any, fallback: str = "") -> str:
    rendered = str(value or "").strip()
    return rendered if rendered else fallback


def _method(row: Mapping[str, Any]) -> str:
    explicit = _text(row.get("method") or row.get("http_method")).upper()
    if explicit:
        return explicit
    row_type = _text(row.get("type")).lower()
    endpoint = _text(row.get("endpoint") or row.get("path") or row.get("name"))
    if row_type in {"command", "adapter", "powershell", "m365_cli"}:
        return "COMMAND"
    if endpoint.startswith(("Get-", "Export-", "Search-")):
        return "COMMAND"
    return "GET"


def _access_mode(method: str) -> str:
    if method in _MUTATING_METHODS:
        return "write"
    if method == "COMMAND":
        return "read_command"
    return "read"


def _data_class(*, platform: str, collector: str, endpoint: str, name: str) -> str:
    haystack = f"{platform} {collector} {endpoint} {name}".lower()
    if any(token in haystack for token in ("gmail", "mailbox", "message", "exchange")):
        return "mail_metadata_and_settings"
    if any(token in haystack for token in ("drive", "onedrive", "sharepoint", "site")):
        return "file_metadata_and_sharing"
    if any(token in haystack for token in ("audit", "signin", "signins", "reports", "activities", "alert")):
        return "audit_and_security_events"
    if any(token in haystack for token in ("device", "intune", "chrome", "mobile")):
        return "device_inventory_and_policy"
    if any(token in haystack for token in ("policy", "settings", "conditionalaccess", "authmethods")):
        return "configuration_policy"
    if any(token in haystack for token in ("user", "group", "directory", "role", "domain")):
        return "directory_identity"
    return "tenant_metadata"


def _api_version(row: Mapping[str, Any], endpoint: str) -> str | None:
    explicit = _text(row.get("api_version"))
    if explicit:
        return explicit
    if endpoint.startswith("https://graph.microsoft.com/beta"):
        return "beta"
    if endpoint.startswith("https://graph.microsoft.com/v1.0"):
        return "v1.0"
    if _text(row.get("type")).lower() == "graph" and endpoint.startswith("/"):
        return "v1.0"
    return None


def _capability_index(capability_rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for row in capability_rows:
        collector = _text(row.get("collector"))
        if collector:
            indexed[collector] = row
    return indexed


def _observed_call(
    *,
    platform: str,
    capabilities: Mapping[str, dict[str, Any]],
    row: Mapping[str, Any],
    index: int,
) -> tuple[str, dict[str, Any]]:
    collector = _text(row.get("collector"), "unknown")
    name = _text(row.get("name") or row.get("operation"), f"call-{index}")
    endpoint = _text(row.get("endpoint") or row.get("path") or name, name)
    method = _method(row)
    access_mode = _access_mode(method)
    content_reads = bool(row.get("content_reads") or row.get("body_reads") or row.get("file_content_reads"))
    write_actions = bool(row.get("write_actions") or access_mode == "write")
    capability = capabilities.get(collector, {})
    return collector, {
        "id": f"{collector}:{name}:{index}",
        "source": "observed",
        "platform": platform,
        "collector": collector,
        "name": name,
        "endpoint": endpoint,
        "method": method,
        "api_version": _api_version(row, endpoint),
        "access_mode": access_mode,
        "status": row.get("status"),
        "item_count": int(row.get("item_count") or 0),
        "duration_ms": row.get("duration_ms"),
        "data_class": _data_class(platform=platform, collector=collector, endpoint=endpoint, name=name),
        "content_reads": content_reads,
        "write_actions": write_actions,
        "required_permissions": list(capability.get("required_permissions") or []),
        "missing_permissions": list(capability.get("missing_permissions") or []),
        "error_class": row.get("error_class"),
        **_command_fields(row),
    }


def _command_fields(row: Mapping[str, Any]) -> dict[str, Any]:
    """The command text a collector recorded for a command row, so the observed ledger can compare against it."""
    command = _text(row.get("command"))
    if not command:
        return {}
    variants = row.get("command_variants")
    return {
        "command": command,
        "command_variants": [str(item) for item in variants] if isinstance(variants, list) else [],
    }


@dataclass
class ApiInventoryRecorder:
    platform: str
    capability_rows: list[dict[str, Any]]
    _observed_calls: list[dict[str, Any]] = field(default_factory=list)
    _observed_counts: Counter[str] = field(default_factory=Counter)
    _mutating_calls: list[dict[str, Any]] = field(default_factory=list)
    _content_calls: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.platform = self.platform or "m365"
        self._capabilities = _capability_index(self.capability_rows)

    def record(self, row: Mapping[str, Any]) -> dict[str, Any]:
        collector, call = _observed_call(
            platform=self.platform,
            capabilities=self._capabilities,
            row=row,
            index=len(self._observed_calls) + 1,
        )
        self._observed_calls.append(call)
        self._observed_counts[collector] += 1
        if call["write_actions"]:
            self._mutating_calls.append({"id": call["id"], "method": call["method"], "endpoint": call["endpoint"]})
        if call["content_reads"]:
            self._content_calls.append({"id": call["id"], "endpoint": call["endpoint"]})
        return call

    def record_many(self, rows: list[dict[str, Any]]) -> None:
        for row in _rows(rows):
            if row.get("type") == "derived":
                continue
            self.record(row)

    def observed_calls(self) -> list[dict[str, Any]]:
        return list(self._observed_calls)

    def observed_counts(self) -> Counter[str]:
        return Counter(self._observed_counts)

    def mutating_calls(self) -> list[dict[str, Any]]:
        return list(self._mutating_calls)

    def content_calls(self) -> list[dict[str, Any]]:
        return list(self._content_calls)


def _collector_plan(
    *,
    selected_collectors: list[str],
    capability_rows: list[dict[str, Any]],
    collector_catalog: Mapping[str, Mapping[str, Any]] | None,
    observed_counts: Counter[str],
) -> list[dict[str, Any]]:
    capabilities = _capability_index(capability_rows)
    catalog = dict(collector_catalog or {})
    rows: list[dict[str, Any]] = []
    for collector in selected_collectors:
        capability = capabilities.get(collector, {})
        metadata = dict(catalog.get(collector) or {})
        rows.append(
            {
                "collector": collector,
                "description": metadata.get("description", ""),
                "status": capability.get("status"),
                "reason": capability.get("reason"),
                "required_permissions": list(capability.get("required_permissions") or []),
                "observed_permissions": list(capability.get("observed_permissions") or []),
                "missing_permissions": list(capability.get("missing_permissions") or []),
                "observed_call_count": observed_counts.get(collector, 0),
                "minimum_role_hints": list(metadata.get("minimum_role_hints") or []),
                "tool_requirements": list(metadata.get("tool_requirements") or []),
                "optional_commands": list(metadata.get("optional_commands") or []),
            }
        )
    return rows


# --------------------------------------------------------------------------------------------
# Observed ledger: facts read back from the run's own audit log, not declarations.
#
# GraphClient._request and the command adapters write graph.request.* and command.* events for
# every call they make (and for every call they refuse). The ledger below is built from those
# events, so "read-only" and "no content read" are statements about what was sent, and the
# declared ledger (the collectors' coverage rows) is only the expected set to compare against.
# --------------------------------------------------------------------------------------------

_GUID = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
_OPAQUE_ID = re.compile(r"^[0-9A-Za-z_=\-]{24,}$")
# Graph resource names are letters-only camelCase (``deviceCompliancePolicies``); an opaque identifier almost
# always carries a digit or base64 punctuation. A long letters-only segment is therefore a name, and templating
# it would merge sibling endpoints and blind the outside-declared check.
_OPAQUE_ID_MARKS = re.compile(r"[0-9_=\-]")
_CONTENT_PATHS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"(?:^|/)messages(?:/|$)",  # mail and chat message bodies
        r"(?:^|/)attachments(?:/|$)",
        r"/\$value$",
        r"/content$",  # driveItem and OneNote page content
        # calendar event bodies, whichever way the calendar is reached (default, by id, or inside a group)
        r"^/(?:users/\{id\}|me|groups/\{id\})/(?:calendar/|calendars/\{id\}/|calendarGroups/\{id\}/calendars/\{id\}/)?(?:events|calendarView)(?:/|$)",
        r"(?:^|/)onenote(?:/|$)",
        r"^/search/query$",
        r"(?:^|/)(?:threads|conversations|posts)(?:/|$)",  # group conversation posts
        r"(?:^|/)getAllMessages(?:\(|/|$)",  # tenant-wide chat messages
        r"(?:^|/)lists/\{id\}/items(?:/|$)",  # SharePoint list item fields
        r"(?:^|/)todo/lists/\{id\}/tasks(?:/|$)",  # To Do task titles and bodies
    )
)
# Microsoft service-health posts, not user content.
_CONTENT_EXEMPT_PREFIXES = ("/admin/serviceAnnouncement",)
_CONTENT_SELECT_FIELDS = frozenset({"body", "bodypreview", "uniquebody", "content"})
# ``$expand`` names a related collection to inline; these carry user content.
_CONTENT_EXPAND_FIELDS = frozenset(
    {"body", "uniquebody", "content", "messages", "attachments", "events", "posts", "threads", "conversations", "items"}
)
_EXPAND_NAME = re.compile(r"[A-Za-z_]+")
_CMDLET = re.compile(r"^[A-Za-z]+-[A-Za-z0-9]+$")


def _is_identifier(segment: str) -> bool:
    """Whether a path segment is an object identifier rather than a resource name."""
    if _GUID.match(segment) or "@" in segment or segment.isdigit():
        return True
    return bool(_OPAQUE_ID.match(segment) and _OPAQUE_ID_MARKS.search(segment))


def endpoint_template(url: str, *, default_version: str | None = "v1.0") -> tuple[str, str | None]:
    """Path of a Graph URL with the version prefix, host and query removed and ids replaced by ``{id}``.

    Returns ``(template, api_version)``. Function-call segments such as
    ``getMailboxUsageDetail(period='D30')`` keep their name and drop the arguments.
    """
    parsed = urlparse(url)
    path = parsed.path if parsed.scheme else url.split("?", 1)[0]
    segments = [item for item in path.split("/") if item]
    version = default_version
    if segments and segments[0] in {"v1.0", "beta"}:
        version = segments[0]
        segments = segments[1:]
    parts: list[str] = []
    for segment in segments:
        segment = unquote(segment)
        name, paren, _ = segment.partition("(")
        if paren:
            parts.append(f"{name}(...)")
        elif _is_identifier(segment):
            parts.append("{id}")
        else:
            parts.append(segment)
    return "/" + "/".join(parts), version


def _is_batch_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.path in {"/v1.0/$batch", "/beta/$batch"}


def _content_reason(template: str, params: Any) -> str | None:
    if not template.startswith(_CONTENT_EXEMPT_PREFIXES):
        for pattern in _CONTENT_PATHS:
            if pattern.search(template):
                return f"endpoint reads content ({pattern.pattern})"
    if isinstance(params, Mapping):
        selected = str(params.get("$select") or "")
        fields = {item.strip().lower() for item in selected.split(",") if item.strip()}
        if fields & _CONTENT_SELECT_FIELDS:
            return "$select requests a body field"
        expanded = {name.lower() for name in _EXPAND_NAME.findall(str(params.get("$expand") or ""))}
        if expanded & _CONTENT_EXPAND_FIELDS:
            return "$expand requests content"
    return None


def _request_params(url: str, params: Any) -> dict[str, Any]:
    """The query a request carried: its logged parameters plus any query string left inside the URL.

    A next-page link or a ``$batch`` inner URL carries ``$select`` and ``$expand`` in the URL itself, so a
    body request inside it must be judged the same as one passed as a parameter.
    """
    merged: dict[str, Any] = dict(params) if isinstance(params, Mapping) else {}
    for key, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
        if key in {"$select", "$expand"} and merged.get(key):
            merged[key] = f"{merged[key]},{value}"
        else:
            merged.setdefault(key, value)
    return merged


class AuditEvents(list):
    """Events of one audit log, plus what could not be read: the ledger reports both.

    A line that is not a JSON object, or a log that cannot be opened, is not silently dropped: an
    event that was not read could have been a write, so the ledger cannot call the run read-only.
    """

    readable: bool = True
    malformed_lines: int = 0

    def __init__(self, rows: Iterable[dict[str, Any]] = (), *, readable: bool = True, malformed_lines: int = 0) -> None:
        super().__init__(rows)
        self.readable = readable
        self.malformed_lines = malformed_lines


def read_audit_events(path: str | Path) -> AuditEvents:
    """Events of an ``audit-log.jsonl`` file, with the count of malformed lines and whether it was readable."""
    events = AuditEvents()
    try:
        handle = Path(path).open(encoding="utf-8")
    except OSError:
        events.readable = False
        return events
    with handle:
        try:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except ValueError:
                    events.malformed_lines += 1
                    continue
                if isinstance(row, dict):
                    events.append(row)
                else:
                    events.malformed_lines += 1
        except (OSError, UnicodeDecodeError):
            events.readable = False
    return events


def _adapter_for(details: Mapping[str, Any]) -> str:
    adapter = _text(details.get("adapter"))
    if adapter:
        return adapter
    executable = Path(_text(details.get("executable"))).name.lower()
    return {"pwsh": "powershell_graph", "m365": "m365_cli"}.get(executable, executable or "unknown")


def _logged_words(adapter: str, command: str) -> list[str]:
    """Command words recovered from logged text, for events from a build that did not record them."""
    if adapter == "m365_cli":
        try:
            return list(check_m365_command(command, adapter=adapter))
        except CommandRefused:
            return m365_command_words(command) or ["unparsed"]
    return [item.strip("'\"") for item in command.split() if _CMDLET.match(item.strip("'\""))] or ["unparsed"]


def _text_words_are_read(adapter: str, words: list[str], command_text: str) -> bool:
    """Cross-check the words an adapter recorded against the command text it logged.

    Text and words come from the same adapter call, so they must agree. m365: the words before the
    first option must equal the recorded words. PowerShell: the logged text is quoted by the log
    redaction, so it is scanned for cmdlet-shaped tokens; every one must be on the read allowlist
    and every recorded word must appear in the text.
    """
    if not command_text:
        return True  # an event without text (older log): the recorded words stand alone
    if adapter == "m365_cli":
        return [item.lower() for item in m365_command_words(command_text)] == [item.lower() for item in words]
    if adapter in {"powershell_graph", "m365dsc"}:
        found = [item.strip("'\"") for item in re.split(r"[\s,|;(){}\[\]=]+", command_text)]
        cmdlets = [item for item in found if _CMDLET.match(item)]
        if not words_are_read(adapter, cmdlets):
            return False
        return {item.lower() for item in words} <= {item.lower() for item in cmdlets}
    return True


def _family(adapter: str, words: list[str]) -> str:
    if adapter == "m365_cli":
        return " ".join(words).lower()
    return words[0].lower() if words else ""


def _declared_command_families(declared_calls: Iterable[Mapping[str, Any]]) -> set[tuple[str, str]]:
    families: set[tuple[str, str]] = set()
    for call in declared_calls:
        texts = [_text(call.get("command")), *[_text(item) for item in call.get("command_variants") or []]]
        for text in texts:
            if not text:
                continue
            adapter = "m365_cli" if text.startswith("m365") else "powershell_graph"
            if adapter == "m365_cli":
                try:
                    words = list(check_m365_command(text, adapter=adapter))
                except CommandRefused:
                    continue
            else:
                words = _logged_words(adapter, text)
            families.add((adapter, _family(adapter, words)))
            if adapter == "powershell_graph":
                families.add(("m365dsc", _family("m365dsc", words)))
    return families


def _declared_graph_templates(declared_calls: Iterable[Mapping[str, Any]]) -> set[str]:
    templates: set[str] = set()
    for call in declared_calls:
        endpoint = _text(call.get("endpoint"))
        if _text(call.get("method")).upper() == "COMMAND" or not endpoint.startswith(("/", "http")):
            continue
        templates.add(endpoint_template(endpoint)[0])
    return templates


def _sorted_entries(entries: Mapping[Any, dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for key in sorted(entries, key=lambda item: tuple(str(part) for part in item)):
        entry = dict(entries[key])
        entry["statuses"] = {name: entry["statuses"][name] for name in sorted(entry["statuses"])}
        rows.append(entry)
    return rows


def observe_audit_events(
    events: Iterable[Mapping[str, Any]],
    *,
    platform: str = "m365",
    declared_calls: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Summarise graph.request.* and command.* audit events into the observed ledger.

    Only transport and command events are counted, so the result does not change when later
    events (completion, validation) are appended to the same log.
    """
    events_source = events
    declared = [dict(call) for call in declared_calls if isinstance(call, Mapping)]
    graph: dict[tuple[str, str, str | None], dict[str, Any]] = {}
    graph_pending: dict[tuple[str, str, Any], list[dict[str, Any]]] = {}
    methods_seen: set[str] = set()
    data_methods: set[str] = set()
    attempts = batch_posts = batch_inner = unverified_batches = 0
    graph_writes: list[dict[str, Any]] = []
    graph_content: dict[tuple[str, str], dict[str, Any]] = {}
    graph_refused: list[dict[str, Any]] = []
    # Redirect hops the client followed (host and path only; the query of a download URL is a credential).
    graph_redirects: dict[tuple[str, str, str], dict[str, Any]] = {}
    redirects_refused = 0
    commands: dict[tuple[str, str], dict[str, Any]] = {}
    command_pending: dict[str, list[dict[str, Any]]] = {}
    command_writes: dict[tuple[str, str], dict[str, Any]] = {}
    command_refused: list[dict[str, Any]] = []
    auth: Counter[str] = Counter()

    def record_graph(method: str, template: str, version: str | None, params: Any) -> dict[str, Any]:
        if method != "UNVERIFIED":
            data_methods.add(method)
        entry = graph.setdefault(
            (method, template, version),
            {"method": method, "endpoint": template, "api_version": version, "count": 0, "statuses": Counter()},
        )
        entry["count"] += 1
        reason = _content_reason(template, params)
        if reason:
            graph_content.setdefault((method, template), {"method": method, "endpoint": template, "reason": reason})
        return entry

    replayed_from: str | None = None
    replayed = False
    events_seen = 0
    for event in events:
        if not isinstance(event, Mapping):
            continue
        events_seen += 1
        name = event.get("event")
        details = event.get("details") if isinstance(event.get("details"), Mapping) else {}
        if name == "run.started" and _text(details.get("mode")) == "offline":
            # An offline run replays a saved sample: it has no transport, so its log cannot observe anything.
            replayed = True
            replayed_from = Path(_text(details.get("sample"))).name or replayed_from
        elif name == "graph.request.started":
            method = _text(details.get("method")).upper()
            url = _text(details.get("url"))
            attempts += 1
            methods_seen.add(method)
            if method == "POST" and _is_batch_url(url):
                batch_posts += 1
                _, version = endpoint_template(url)
                batch = details.get("batch")
                inner_urls = batch.get("urls") if isinstance(batch, Mapping) else None
                inner_methods = (
                    {_text(item).upper() for item in batch.get("methods") or []}
                    if isinstance(batch, Mapping) and isinstance(batch.get("methods"), list)
                    else set()
                )
                # A batch counts as GET-only only when its inner calls and their methods were both recorded,
                # agree in number, and the only method recorded is GET. Anything less is unverified.
                recorded = (
                    isinstance(inner_urls, list)
                    and bool(inner_urls)
                    and bool(inner_methods)
                    and batch.get("size") == len(inner_urls)
                )
                if not recorded:
                    unverified_batches += 1
                    for inner_url in inner_urls if isinstance(inner_urls, list) else []:
                        batch_inner += 1
                        inner_template, _ = endpoint_template(_text(inner_url), default_version=version)
                        record_graph("UNVERIFIED", inner_template, version, _request_params(_text(inner_url), None))
                    continue
                for inner_url in inner_urls:
                    batch_inner += 1
                    inner_template, _ = endpoint_template(_text(inner_url), default_version=version)
                    record_graph("GET", inner_template, version, _request_params(_text(inner_url), None))
                for inner_method in sorted(inner_methods - {"GET"}):
                    graph_writes.append({"method": inner_method, "endpoint": "/$batch", "via": "$batch"})
                continue
            template, version = endpoint_template(url)
            entry = record_graph(method, template, version, _request_params(url, details.get("params")))
            graph_pending.setdefault((method, url, details.get("attempt")), []).append(entry)
            if method != "GET":
                graph_writes.append({"method": method, "endpoint": template})
        elif name == "graph.request.completed":
            key = (_text(details.get("method")).upper(), _text(details.get("url")), details.get("attempt"))
            waiting = graph_pending.get(key)
            if waiting:
                waiting.pop(0)["statuses"][str(details.get("status"))] += 1
        elif name == "graph.request.refused":
            template, _ = endpoint_template(_text(details.get("url")))
            graph_refused.append(
                {"method": _text(details.get("method")).upper(), "endpoint": template, "reason": _text(details.get("reason"))}
            )
        elif name == "graph.request.redirect":
            origin, _ = endpoint_template(_text(details.get("from_path")))
            hop = graph_redirects.setdefault(
                (origin, _text(details.get("host")), _text(details.get("path"))),
                {"from": origin, "host": _text(details.get("host")), "path": _text(details.get("path")), "count": 0},
            )
            hop["count"] += 1
        elif name == "graph.request.redirect_refused":
            redirects_refused += 1
        elif name in {"graph.token.requested", "graph.token.interactive"}:
            auth["token_requests"] += 1
        elif name == "graph.token.succeeded":
            auth["token_succeeded"] += 1
        elif name == "graph.token.failed":
            auth["token_failed"] += 1
        elif name == "command.started":
            adapter = _adapter_for(details)
            command_text = _text(details.get("command"))
            words = details.get("command_words")
            if not isinstance(words, list) or not words:
                words = _logged_words(adapter, command_text)
            words = [str(item) for item in words]
            read_only = words_are_read(adapter, words) and _text_words_are_read(adapter, words, command_text)
            display = " ".join(words)
            entry = commands.setdefault(
                (adapter, display),
                {
                    "adapter": adapter,
                    "command": display,
                    "family": _family(adapter, words),
                    "read_only": read_only,
                    "count": 0,
                    "statuses": Counter(),
                },
            )
            entry["count"] += 1
            command_pending.setdefault(command_text, []).append(entry)
            if not read_only:
                command_writes.setdefault((adapter, display), {"adapter": adapter, "command": display})
        elif name == "command.completed":
            waiting = command_pending.get(_text(details.get("command")))
            if waiting:
                waiting.pop(0)["statuses"][_text(details.get("status")) or f"rc={details.get('return_code')}"] += 1
        elif name == "command.failed":
            # A command that timed out or raised never completed: its pending call ends as ``failed`` instead of
            # staying without a status.
            waiting = command_pending.get(_text(details.get("command")))
            if waiting:
                waiting.pop(0)["statuses"]["failed"] += 1
        elif name == "command.refused":
            command_refused.append(
                {
                    "adapter": _text(details.get("adapter")),
                    "command": _text(details.get("command")),
                    "reason": _text(details.get("reason")),
                }
            )

    instrumented = platform != "google_workspace"
    log_readable = bool(getattr(events_source, "readable", True))
    malformed_lines = int(getattr(events_source, "malformed_lines", 0))
    outside_graph: list[dict[str, Any]] = []
    outside_commands: list[dict[str, Any]] = []
    declared_templates = _declared_graph_templates(declared)
    if declared_templates:
        outside_graph = [
            {"method": row["method"], "endpoint": row["endpoint"], "api_version": row["api_version"]}
            for row in _sorted_entries(graph)
            if row["endpoint"] not in declared_templates
        ]
    declared_families = _declared_command_families(declared)
    if declared_families:
        outside_commands = [
            {"adapter": row["adapter"], "command": row["command"]}
            for row in _sorted_entries(commands)
            if (row["adapter"], row["family"]) not in declared_families
        ]
    basis = "offline_replay" if replayed else ("transport_audit_log" if instrumented else "not_instrumented")
    # A log with no event at all (not even the run's own start and finish), next to calls the run declared, observed
    # nothing: it was emptied or never written, so it cannot support "read only" on an observed basis, whatever it says
    # about writes. A run that declared no call has nothing to observe.
    silent_log = basis == "transport_audit_log" and events_seen == 0 and bool(declared)
    return {
        "source": LEDGER_SOURCE,
        "basis": basis,
        **({"replay": {"source_file": replayed_from, "tenant_contact": False}} if replayed else {}),
        "instrumentation": {"graph": instrumented, "commands": instrumented, "google_api": False},
        "log": {"readable": log_readable, "malformed_lines": malformed_lines, **({"empty": True} if silent_log else {})},
        "graph": {
            "request_attempts": attempts,
            "methods_seen": sorted(methods_seen),
            "data_methods_seen": sorted(data_methods),
            "batch_requests": batch_posts,
            "batch_inner_requests": batch_inner,
            "unverified_batch_requests": unverified_batches,
            "endpoints": _sorted_entries(graph),
            "write_calls": graph_writes,
            "content_read_calls": [graph_content[key] for key in sorted(graph_content)],
            "refused": graph_refused[:_MAX_LISTED],
            "refused_count": len(graph_refused),
            "redirects": [graph_redirects[key] for key in sorted(graph_redirects)][:_MAX_LISTED],
            "redirects_refused": redirects_refused,
        },
        "commands": {
            "executed": _sorted_entries(commands),
            "write_calls": [command_writes[key] for key in sorted(command_writes)],
            "refused": command_refused[:_MAX_LISTED],
            "refused_count": len(command_refused),
        },
        "auth": {key: auth[key] for key in sorted(auth)},
        "outside_declared": {
            "graph": outside_graph[:_MAX_LISTED],
            "commands": outside_commands[:_MAX_LISTED],
            "count": len(outside_graph) + len(outside_commands),
        },
    }


def _apply_ledger(inventory: dict[str, Any], ledger: dict[str, Any]) -> dict[str, Any]:
    """Fold the observed ledger into an inventory's safety flags and counts; the flags can only get stricter."""
    graph = ledger["graph"]
    commands = ledger["commands"]
    write_calls = [*graph["write_calls"], *commands["write_calls"]]
    content_calls = list(graph["content_read_calls"])
    safety = dict(inventory.get("safety") or {})
    counts = dict(inventory.get("counts") or {})
    safety["observation_basis"] = (
        ledger["basis"] if ledger["basis"] in {"transport_audit_log", "offline_replay"} else "coverage_ledger_only"
    )
    replay = ledger.get("replay")
    if isinstance(replay, Mapping):
        safety["replay_source"] = replay.get("source_file")
    safety["observed_methods"] = list(graph["data_methods_seen"])
    safety["observed_write_calls"] = write_calls
    safety["observed_content_read_calls"] = content_calls
    safety["refused_calls"] = int(graph["refused_count"]) + int(commands["refused_count"])
    safety["observed_outside_declared"] = int(ledger["outside_declared"]["count"])
    log = ledger.get("log") or {}
    log_complete = (
        bool(log.get("readable", True)) and int(log.get("malformed_lines", 0)) == 0 and not log.get("empty")
    )
    safety["observed_log_complete"] = log_complete and graph["unverified_batch_requests"] == 0
    safety["malformed_log_lines"] = int(log.get("malformed_lines", 0))
    # A refused call is a call that tried something that is not a read: nothing reached the tenant (write_actions
    # stays as observed), but the run was not read-only. So is a run whose log cannot be fully read.
    safety["read_only"] = (
        bool(safety.get("read_only", True))
        and not write_calls
        and safety["refused_calls"] == 0
        and safety["observed_log_complete"]
    )
    safety["write_actions"] = bool(safety.get("write_actions")) or bool(write_calls)
    safety["no_content_reads"] = bool(safety.get("no_content_reads", True)) and not content_calls
    safety["content_reads"] = bool(safety.get("content_reads")) or bool(content_calls)
    counts["observed_graph_requests"] = graph["request_attempts"]
    counts["observed_graph_endpoints"] = len(graph["endpoints"])
    counts["observed_commands"] = sum(int(row["count"]) for row in commands["executed"])
    counts["refused_calls"] = safety["refused_calls"]
    counts["observed_outside_declared"] = safety["observed_outside_declared"]
    result = dict(inventory)
    result["safety"] = safety
    result["counts"] = counts
    result["observed_ledger"] = ledger
    return result


def with_observed_ledger(
    inventory: Mapping[str, Any],
    events: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Copy of ``inventory`` with the observed ledger built from ``events`` and the safety flags re-derived."""
    base = copy.deepcopy(dict(inventory))
    ledger = observe_audit_events(
        events,
        platform=_text(base.get("platform"), "m365"),
        declared_calls=_rows(base.get("observed_calls")),
    )
    return _apply_ledger(base, ledger)


def build_api_call_inventory(
    *,
    platform: str,
    selected_collectors: list[str],
    capability_rows: list[dict[str, Any]],
    coverage_rows: list[dict[str, Any]],
    data_handling: Mapping[str, Any] | None,
    collector_catalog: Mapping[str, Mapping[str, Any]] | None = None,
    audit_events: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build the API ledger.

    ``observed_calls`` and ``declared_collectors`` are the declared side (collector coverage rows
    and scope catalog). Pass ``audit_events`` (the run's audit-log events) to add the observed
    ledger and derive the safety flags from what was actually sent; ``AuditWriter`` does this for
    every ``api-inventory.json`` it writes, so a bundle cannot carry the declared view alone.
    """
    provider = platform or "m365"
    data_handling_payload = dict(data_handling or {})
    recorder = ApiInventoryRecorder(platform=provider, capability_rows=capability_rows)
    recorder.record_many(coverage_rows)
    observed_calls = recorder.observed_calls()
    observed_counts = recorder.observed_counts()
    mutating_calls = recorder.mutating_calls()
    content_calls = recorder.content_calls()

    data_content = bool(data_handling_payload.get("content_reads"))
    data_write = bool(data_handling_payload.get("write_actions"))
    read_only = bool(data_handling_payload.get("read_only", True)) and not data_write and not mutating_calls
    no_content_reads = not data_content and not content_calls
    inventory = {
        "schema_version": SCHEMA_VERSION,
        "platform": provider,
        "plane": data_handling_payload.get("plane"),
        "declared_collectors": _collector_plan(
            selected_collectors=selected_collectors,
            capability_rows=capability_rows,
            collector_catalog=collector_catalog,
            observed_counts=observed_counts,
        ),
        "observed_calls": observed_calls,
        "counts": {
            "declared_collectors": len(selected_collectors),
            "observed_calls": len(observed_calls),
            "mutating_calls": len(mutating_calls),
            "content_read_calls": len(content_calls),
            "beta_calls": sum(1 for call in observed_calls if call.get("api_version") == "beta"),
        },
        "safety": {
            "read_only": read_only,
            "no_content_reads": no_content_reads,
            "write_actions": data_write or bool(mutating_calls),
            "content_reads": data_content or bool(content_calls),
            "mutating_calls": mutating_calls,
            "content_read_calls": content_calls,
            "scope_risk": data_handling_payload.get("scope_risk"),
            "write_capable_scopes": list(data_handling_payload.get("write_capable_scopes") or []),
            "observation_basis": "coverage_ledger_only",
        },
    }
    if audit_events is None:
        return inventory
    return _apply_ledger(
        inventory,
        observe_audit_events(audit_events, platform=provider, declared_calls=observed_calls),
    )
