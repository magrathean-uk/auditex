"""Static proof of the three read boundaries: content reads, commands and Google calls.

* Content: the ``api_inventory`` content classifier runs over every endpoint in
  ``configs/collector-definitions.json`` and every endpoint literal under ``collectors/`` and ``adapters/``.
* Commands: every executable command site (a string that reaches a process or runner call, traced through
  the source) in ``src/`` and every command field in ``configs/`` is split into trusted
  wrapper operations (a closed table keyed by file and purpose) and audited commands, which must be on the
  ``api_inventory`` read allow-list. Every m365 CLI command the collectors can issue passes the read guard.
* Google: every API method called under ``src/auditex/google_workspace/`` is a read, and every requested
  scope is read-only, metadata-only or a write-capable scope in the closed accepted-exception table (DEC-010),
  with its blast radius, used only for list and get calls.

Text a user or administrator wrote that a settings read still receives (inventory section G) is pinned in
``_TEXT_EXPOSURES`` with its disposition; the discarded rows are proved discarded here.
"""
from __future__ import annotations

import ast
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from azure_tenant_audit import api_inventory
from azure_tenant_audit.adapters import read_guard
from azure_tenant_audit.adapters.m365dsc import COMPATIBILITY_SCRIPT, MINIMUM_MODULE_VERSION, M365DSCAdapter
from azure_tenant_audit.adapters.powershell_graph import PowerShellGraphAdapter
from azure_tenant_audit.adapters.read_guard import CommandRefused, VettedCommand
from azure_tenant_audit.data_minimisation import (
    AUTO_REPLY_TEXT_FIELDS,
    GMAIL_FILTER_TEXT_FIELDS,
    RULE_CONDITION_WORD_FIELDS,
    SEND_AS_TEXT_FIELDS,
    VACATION_TEXT_FIELDS,
    minimise_gmail_settings,
    minimise_mailbox_settings,
    minimise_user_text,
)
from azure_tenant_audit.scope_catalog import GOOGLE_SCOPE_NOTES

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
ENGINE = SRC / "azure_tenant_audit"
CONFIGS = REPO_ROOT / "configs"
COLLECTOR_DEFINITIONS = CONFIGS / "collector-definitions.json"
GOOGLE_DIR = SRC / "auditex" / "google_workspace"

WRAPPER_VERBS = ("Import-Module", "Connect-ExchangeOnline", "Invoke-Expression")

# Closed: the only executable sites allowed to carry a wrapper operation, and which ones.
_TRUSTED_WRAPPER_SITES: dict[tuple[str, str], tuple[frozenset[str], str]] = {
    ("src/azure_tenant_audit/adapters/powershell_graph.py", "PowerShellGraphAdapter._session_prelude"): (
        frozenset({"Import-Module", "Connect-ExchangeOnline"}),
        "Exchange Online connect preamble, prepended after the caller's script passed the guard",
    ),
    ("src/azure_tenant_audit/adapters/m365dsc.py", "M365DSCAdapter.run"): (
        frozenset({"Import-Module", "Invoke-Expression"}),
        "Microsoft365DSC module-version guard, passed on as a VettedCommand",
    ),
    ("src/azure_tenant_audit/probe.py", "_probe_toolchain_statuses"): (
        frozenset({"Import-Module"}),
        "Exchange module availability probe (Get-Command only, no tenant call)",
    ),
}
# Closed: operator-run local setup that never reaches an audit runner (adapter or probe). Its commands are
# neither wrapper operations nor tenant reads; the site is pinned so a second one cannot appear unseen.
_LOCAL_SETUP_SITES: dict[tuple[str, str], tuple[frozenset[str], str]] = {
    ("src/auditex/auth.py", "ensure_exchange_online_module"): (
        frozenset({"Install-Module"}),
        "operator-run ExchangeOnlineManagement install from the guided setup; local PSGallery download",
    ),
}

# Closed: requests whose endpoint or parameters the source scan cannot resolve, each with why that is safe.
# A new unresolved request fails the scan until it is resolved or reviewed into this table.
_GENERIC_GRAPH_RUNNER = (
    "generic Graph plumbing: endpoint and params come from collector spec dicts, each judged by the "
    "endpoint/params dict rule; the query adds only $top"
)
_UNRESOLVED_REQUESTS: dict[tuple[str, str], str] = {
    ("src/azure_tenant_audit/collectors/base.py", "run_graph_endpoints"): _GENERIC_GRAPH_RUNNER,
    ("src/azure_tenant_audit/collectors/base.py", "_bounded_pages"): _GENERIC_GRAPH_RUNNER,
    ("src/azure_tenant_audit/collectors/base.py", "_validated_collection"): _GENERIC_GRAPH_RUNNER,
    ("src/azure_tenant_audit/collectors/_endpoint_reads.py", "_read_one"): (
        "endpoint is the caller's object path; params are only {'$top': top}, judged here"
    ),
}

# Closed: runner calls whose input is not fully visible in the source, each with why that is safe. The literal
# parts that do resolve are still command sites; a new unresolved runner call fails until reviewed in here.
_RUNTIME_ARGV = "argv adds a runtime value (executable path, tenant id, volume); its script text is literal and scanned"
_CALLER_ARGV = "generic local CLI runner; argv is built by callers in other modules or by the operator's own setup"
_ADAPTER_ENTRY = "adapter entry point: the caller's command passes read_guard.check_command first"
_UNRESOLVED_RUNNER_INPUTS: dict[tuple[str, str], str] = {
    ("src/auditex/auth.py", "_json_command"): _CALLER_ARGV,
    ("src/auditex/auth.py", "_product_auth_runtime"): _CALLER_ARGV,
    ("src/auditex/auth.py", "_pwsh_exchange_module_status"): _RUNTIME_ARGV,
    ("src/auditex/auth.py", "ensure_exchange_online_module"): _RUNTIME_ARGV,
    ("src/auditex/auth_runtime.py", "_default_exchange_module_status"): _RUNTIME_ARGV,
    ("src/auditex/auth_runtime.py", "_default_json_command"): _CALLER_ARGV,
    ("src/auditex/auth_runtime.py", "_default_run_json_command"): _CALLER_ARGV,
    ("src/auditex/auth_runtime.py", "_default_run_returncode"): _CALLER_ARGV,
    ("src/auditex/bootstrap.py", "_run_json_command"): _CALLER_ARGV,
    ("src/auditex/bootstrap.py", "run_setup"): _CALLER_ARGV,
    ("src/auditex/command_runner.py", "run_cli_command"): _CALLER_ARGV,
    ("src/auditex/guided.py", "_ensure_m365_login"): _RUNTIME_ARGV,
    ("src/auditex/guided.py", "_run_azure_login"): _RUNTIME_ARGV,
    ("src/azure_tenant_audit/adapters/m365_cli.py", "M365CLIAdapter.run"): _ADAPTER_ENTRY,
    ("src/azure_tenant_audit/adapters/m365dsc.py", "M365DSCAdapter.run"): _ADAPTER_ENTRY,
    ("src/azure_tenant_audit/adapters/powershell_graph.py", "PowerShellGraphAdapter.run"): _ADAPTER_ENTRY,
    ("src/azure_tenant_audit/adapters/powershell_graph.py", "_run_bounded"): _ADAPTER_ENTRY,
    ("src/azure_tenant_audit/auth_runtime.py", "acquire_azure_cli_access_token"): _RUNTIME_ARGV,
    ("src/azure_tenant_audit/evidence_db.py", "_encrypted_internal_storage"): _RUNTIME_ARGV,
    ("src/azure_tenant_audit/probe.py", "_subprocess_probe"): _CALLER_ARGV,
    ("src/azure_tenant_audit/response.py", "run_response"): (
        "lab-only response actions behind AUDITEX_ENABLE_RESPONSE; the RESPONSE_ACTIONS templates are scanned"
    ),
}

# PowerShell approved verbs (plus ForEach/Tee) used to recognise a cmdlet name inside a string.
_POWERSHELL_VERBS = frozenset(
    """add approve assert backup block build checkpoint clear close compare complete compress confirm connect
    convert convertfrom convertto copy debug deny deploy disable disconnect dismount edit enable enter exit expand
    export find foreach format get grant group hide import initialize install invoke join limit lock measure merge
    mount move new open optimize out ping pop protect publish push read receive redo register remove rename repair
    request reset resize resolve restart restore resume revoke save search select send set show skip sort split
    start step stop submit suspend switch sync tee test trace unblock undo uninstall unlock unprotect unpublish
    unregister update use wait watch where write""".split()
)
_CMDLET = re.compile(r"^[A-Za-z]+-[A-Za-z][A-Za-z0-9]*$")
_GOOGLE_READ_METHOD = re.compile(r"^(?:list|get)(?:[A-Z][A-Za-z]*|_next)?$")
_GOOGLE_SCOPE_PREFIX = "https://www.googleapis.com/auth/"

# Closed: write-capable Google scopes accepted as documented exceptions (DEC-010, approved by G). None has a
# read-only form. Each row names the blast radius if a mutating call were ever made under the scope, why it is
# kept, and the exact calls the provider makes under it; the tests prove every one is a list or get. A requested
# scope that is neither read-only, metadata-only nor in this table fails.
_ACCEPTED_WRITE_CAPABLE_SCOPES: dict[str, dict[str, Any]] = {
    "https://www.googleapis.com/auth/admin.directory.user.security": {
        "blast_radius": "revoke users' OAuth tokens, app-specific passwords and backup codes; sign users out",
        "reason": "2SV and third-party token posture; tokens.list has no read-only scope",
        "calls": frozenset({"tokens.list"}),
    },
    "https://www.googleapis.com/auth/apps.alerts": {
        "blast_radius": "delete or undelete Alert Center alerts, add feedback, change alert notification settings",
        "reason": "Alert Center coverage; the API has a single read/write scope",
        "calls": frozenset({"alerts.list"}),
    },
    "https://www.googleapis.com/auth/gmail.settings.basic": {
        "blast_radius": "change users' filters, IMAP/POP, vacation responder, send-as and language settings",
        "reason": "Gmail settings coverage; the read-only alternative gmail.readonly reads message content",
        "calls": frozenset({
            "getAutoForwarding", "filters.list", "forwardingAddresses.list", "sendAs.list", "getImap", "getPop",
            "getVacation", "delegates.list",
        }),
    },
    "https://www.googleapis.com/auth/apps.groups.settings": {
        "blast_radius": "change any group's join, post, membership-visibility, external-member and moderation settings",
        "reason": "group-settings coverage; the Groups Settings API has a single read/write scope",
        "calls": frozenset({"groups.get"}),
    },
}
# Dropped by M01-T11: every Gmail settings read the collector makes accepts gmail.settings.basic (Gmail API
# reference, users.settings.* get and list methods). It is not an accepted exception and no source may request it.
_RETIRED_SCOPE = "https://www.googleapis.com/auth/gmail.settings.sharing"
_METADATA_ONLY_SCOPE = re.compile(r"\.metadata(?:\.readonly)?$")

# Section G of the M01-T02 transport inventory: reads that receive user- or admin-written text.
# disposition: removed at request level (a `fields` mask never asks for it), discarded (stripped after receipt, proved below),
# accepted (kept as the value a rule judges), removed_at_request (no longer requested; proved below),
# follow_up (retained today; removal at request level or a post-receipt discard is a separate task).
_TEXT_EXPOSURES: tuple[dict[str, Any], ...] = (
    {"id": "G1", "file": "src/auditex/google_workspace/client.py", "needle": "settings.getVacation(",
     "fields": VACATION_TEXT_FIELDS, "disposition": "removed at request level"},
    {"id": "G2", "file": "src/auditex/google_workspace/client.py", "needle": "settings.sendAs().list(",
     "fields": SEND_AS_TEXT_FIELDS, "disposition": "removed at request level"},
    {"id": "G3", "file": "src/azure_tenant_audit/collectors/mailbox_forwarding.py", "needle": "/mailboxSettings\"",
     "fields": AUTO_REPLY_TEXT_FIELDS, "disposition": "discarded"},
    {"id": "G4", "file": "src/azure_tenant_audit/collectors/mailbox_forwarding.py",
     "needle": "/mailFolders/inbox/messageRules\"", "fields": RULE_CONDITION_WORD_FIELDS, "disposition": "discarded"},
    {"id": "G5", "file": "src/auditex/google_workspace/client.py", "needle": "settings.filters().list(",
     "fields": GMAIL_FILTER_TEXT_FIELDS, "disposition": "removed at request level"},
    {"id": "G6", "file": "configs/collector-definitions.json", "needle": "Get-TransportRule | Select-Object",
     "fields": ("ApplyHtmlDisclaimerText",), "disposition": "removed_at_request"},
    {"id": "G6", "file": "src/azure_tenant_audit/collectors/exchange_policy.py", "needle": "Get-TransportRule | Select-Object",
     "fields": ("ApplyHtmlDisclaimerText",), "disposition": "removed_at_request"},
    {"id": "G7", "file": "src/azure_tenant_audit/collectors/exchange_policy.py", "needle": "PrependSubject",
     "fields": ("PrependSubject",), "disposition": "accepted"},
    {"id": "G8", "file": "src/auditex/google_workspace/client.py",
     "needle": "fields=ALERT_FIELDS",
     "fields": ("data.messages[].messageBodySnippet", "data.messages[].subjectText"),
     "disposition": "removed_at_request"},
    {"id": "G9", "file": "src/auditex/google_workspace/client.py",
     "needle": "fields=GROUP_SETTING_FIELDS",
     "fields": ("customFooterText", "defaultMessageDenyNotificationText"),
     "disposition": "removed_at_request"},
    {"id": "G10", "file": "src/azure_tenant_audit/collectors/intune.py",
     "needle": "\"endpoint\": \"/deviceManagement/deviceConfigurations\",\n                \"params\": {},",
     "fields": ("payload",), "disposition": "discarded"},  # discarded after receipt by minimise_device_configurations
    {"id": "G10", "file": "src/azure_tenant_audit/collectors/intune_depth.py",
     "needle": "\"endpoint\": \"/deviceManagement/deviceConfigurations\",\n                    \"params\": {},",
     "fields": ("payload",), "disposition": "discarded"},  # discarded after receipt by minimise_device_configurations
)


# ---------------------------------------------------------------------------------------------------------
# Source walking
# ---------------------------------------------------------------------------------------------------------


def _relative(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def _python_files(*roots: Path) -> list[Path]:
    return sorted(path for root in roots for path in root.rglob("*.py"))


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}


def _docstring_nodes(tree: ast.AST) -> set[ast.AST]:
    """String constants that are statements of their own: docstrings and bare string expressions."""
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr) and isinstance(node.value, (ast.Constant, ast.JoinedStr))
    }


def _module_constants(tree: ast.Module) -> dict[str, str]:
    constants: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            rendered = _render(node.value, constants, placeholder="{id}")
            if rendered is not None:
                constants[node.targets[0].id] = rendered
    return constants


def _render(node: ast.AST, constants: dict[str, str], *, placeholder: str) -> str | None:
    """Text of a string expression, with each runtime value replaced by ``placeholder``."""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.JoinedStr):
        return "".join(
            str(part.value) if isinstance(part, ast.Constant) else placeholder for part in node.values
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _render(node.left, constants, placeholder=placeholder)
        right = _render(node.right, constants, placeholder=placeholder)
        if left is None and right is None:
            return None
        return (placeholder if left is None else left) + (placeholder if right is None else right)
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    return None


def _qualname(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str:
    names: list[str] = []
    current = parents.get(node)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.append(current.name)
        current = parents.get(current)
    return ".".join(reversed(names)) or "<module>"


def _string_expressions(path: Path, *, placeholder: str) -> Iterator[tuple[str, int, str]]:
    """``(qualname, line, text)`` of every outermost non-docstring string expression in a module."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    parents = _parents(tree)
    skipped = _docstring_nodes(tree)
    constants = _module_constants(tree)
    seen: set[ast.AST] = set()
    for node in ast.walk(tree):
        if node in seen or node in skipped:
            seen.update(ast.walk(node))
            continue
        if not isinstance(node, (ast.Constant, ast.JoinedStr, ast.BinOp)):
            continue
        text = _render(node, constants, placeholder=placeholder)
        if text is None:
            continue
        seen.update(ast.walk(node))
        yield _qualname(node, parents), node.lineno, text


# ---------------------------------------------------------------------------------------------------------
# Value resolution: what a name, attribute, call or container in a module can hold
# ---------------------------------------------------------------------------------------------------------

_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp,
                ast.GeneratorExp)
_FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)
# Calls whose value is (one of) their positional arguments: URL builders, conversions, the vetted-command wrapper.
_TRANSPARENT_CALLS = frozenset({"graph_url", "str", "list", "tuple", "sorted", "VettedCommand"})
# String methods whose result is built from the receiver (and, for join and format, the arguments).
_STRING_METHODS = frozenset({"strip", "lstrip", "rstrip", "lower", "upper", "replace", "format", "join", "removeprefix",
                             "removesuffix"})
_MAX_DEPTH = 16


class _Module:
    """One parsed module with its bindings, functions, calls and imports, for backward value resolution."""

    def __init__(self, source: str, label: str, dotted: str | None = None) -> None:
        self.tree = ast.parse(source)
        self.label = label
        self.dotted = dotted
        self.parents = _parents(self.tree)
        self.docstrings = _docstring_nodes(self.tree)
        self.constants = _module_constants(self.tree)
        # (scope, name) -> [(expr, path)]; a path applies "item" (an element of an iterable) and tuple indexes.
        self.bindings: dict[tuple[ast.AST | None, str], list[tuple[ast.AST, tuple[Any, ...]]]] = {}
        self.attributes: dict[str, list[tuple[ast.AST, tuple[Any, ...]]]] = {}  # class and ``self.x`` attributes
        self.functions: dict[str, list[ast.AST]] = {}
        self.calls: dict[str, list[ast.Call]] = {}
        self.imports: dict[str, tuple[str, str]] = {}
        self.module_aliases: dict[str, str] = {}  # ``import subprocess as sp`` -> {"sp": "subprocess"}
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        self.module_aliases[alias.asname] = alias.name
                    else:
                        head = alias.name.split(".", 1)[0]
                        self.module_aliases[head] = head
            if isinstance(node, _FUNCTION_NODES):
                self.functions.setdefault(node.name, []).append(node)
            elif isinstance(node, ast.Call) and (name := _callee_name(node)):
                self.calls.setdefault(name, []).append(node)
                func = node.func
                if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and node.args:
                    # ``rows.append(x)`` and ``rows.extend(xs)`` add to what ``rows`` holds.
                    if name in {"append", "insert"}:
                        self._bind(node, func.value, ast.List(elts=[node.args[-1]], ctx=ast.Load()), ())
                    elif name == "extend":
                        self._bind(node, func.value, node.args[0], ())
            elif isinstance(node, ast.ImportFrom):
                base = self._import_base(node)
                for alias in node.names:
                    if base is not None:
                        self.imports[alias.asname or alias.name] = (base, alias.name)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    self._bind(node, target, node.value, ())
            elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and node.value is not None:
                self._bind(node, node.target, node.value, ())
            elif isinstance(node, ast.NamedExpr):
                self._bind(node, node.target, node.value, ())
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                self._bind(node, node.target, node.iter, ("item",))
            elif isinstance(node, ast.comprehension):
                self._bind(node, node.target, node.iter, ("item",))

    def _import_base(self, node: ast.ImportFrom) -> str | None:
        if not node.level:
            return node.module
        if self.dotted is None:
            return None
        package = self.dotted.split(".")[: -node.level]
        return ".".join([*package, *([node.module] if node.module else [])])

    def scope_of(self, node: ast.AST) -> ast.AST | None:
        current = self.parents.get(node)
        while current is not None and not isinstance(current, _SCOPE_NODES):
            current = self.parents.get(current)
        return current

    def _in_class_body(self, node: ast.AST) -> bool:
        current = self.parents.get(node)
        while current is not None and not isinstance(current, (*_SCOPE_NODES, ast.ClassDef)):
            current = self.parents.get(current)
        return isinstance(current, ast.ClassDef)

    def _bind(self, owner: ast.AST, target: ast.AST, value: ast.AST, path: tuple[Any, ...]) -> None:
        if isinstance(target, (ast.Tuple, ast.List)):
            if not path and isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == len(target.elts):
                for item_target, item_value in zip(target.elts, value.elts):
                    self._bind(owner, item_target, item_value, ())
                return
            for index, item_target in enumerate(target.elts):
                self._bind(owner, item_target, value, (*path, index))
            return
        if isinstance(target, ast.Starred):
            self._bind(owner, target.value, value, (*path, "rest"))
        elif isinstance(target, ast.Name):
            if self._in_class_body(owner):
                self.attributes.setdefault(target.id, []).append((value, path))
                return
            # A comprehension's targets belong to the comprehension; anything else to its enclosing scope.
            scope = self.parents.get(owner) if isinstance(owner, ast.comprehension) else self.scope_of(owner)
            self.bindings.setdefault((scope, target.id), []).append((value, path))
        elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id in {"self", "cls"}:
            self.attributes.setdefault(target.attr, []).append((value, path))


def _callee_name(call: ast.Call) -> str | None:
    func = call.func
    return func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None


_MODULE_CACHE: dict[str, _Module | None] = {}


def _load_module(dotted: str) -> _Module | None:
    if dotted not in _MODULE_CACHE:
        base = SRC.joinpath(*dotted.split("."))
        path = next((p for p in (base.with_suffix(".py"), base / "__init__.py") if p.is_file()), None)
        _MODULE_CACHE[dotted] = (
            None if path is None else _Module(path.read_text(encoding="utf-8"), _relative(path), dotted)
        )
    return _MODULE_CACHE[dotted]


_IMPORTERS: dict[tuple[str, str], list[tuple[_Module, ast.Call]]] = {}


def _importer_calls(dotted: str, name: str) -> list[tuple[_Module, ast.Call]]:
    """Calls of module-level function ``dotted.name`` in every source module that imports it by name."""
    if not _IMPORTERS:
        for path in _python_files(SRC):
            module = _module_for(path)
            for alias, (target, imported) in module.imports.items():
                for call in module.calls.get(alias, []):
                    if isinstance(call.func, ast.Name):
                        _IMPORTERS.setdefault((target, imported), []).append((module, call))
        _IMPORTERS.setdefault(("", ""), [])  # built
    return _IMPORTERS.get((dotted, name), [])


def _module_for(path: Path) -> _Module:
    module = _load_module(".".join(path.relative_to(SRC).with_suffix("").parts).removesuffix(".__init__"))
    assert module is not None, path
    return module


Value = tuple[_Module, ast.AST]


class _Resolver:
    """Backward resolution of an expression to the literal values it can hold.

    ``values`` returns ``(terminals, complete)``: terminals are literal nodes (strings, f-strings, ``+`` joins,
    containers, other constants) with their module; ``complete`` is False when some path ended at a value the
    module cannot show (a runtime input, a parameter with no caller in the module, an unknown call). Every
    caller treats an incomplete resolution as unresolved and fails closed on it.
    """

    def __init__(self) -> None:
        self._memo: dict[tuple[_Module, ast.AST], tuple[list[Value], bool]] = {}  # keys hold the objects
        self._active: set[tuple[_Module, ast.AST]] = set()
        self._cycles = 0

    def values(self, module: _Module, expr: ast.AST, depth: int = 0) -> tuple[list[Value], bool]:
        """Memoised per expression. A re-entered expression (a binding cycle) adds nothing new on that path;
        a result computed across a cycle or at the depth limit is not memoised, so it cannot be reused short."""
        if not isinstance(expr, (ast.Name, ast.Attribute, ast.Subscript, ast.Call)):
            return self._values(module, expr, depth)
        key = (module, expr)
        if key in self._memo:
            return self._memo[key]
        if key in self._active:
            self._cycles += 1
            return [], True
        if depth > _MAX_DEPTH:
            self._cycles += 1
            return [], False
        self._active.add(key)
        before = self._cycles
        try:
            result = self._values(module, expr, depth)
        finally:
            self._active.discard(key)
        if self._cycles == before:
            unique = list({(id(owner), id(node)): (owner, node) for owner, node in result[0]}.values())
            result = (unique, result[1])
            self._memo[key] = result
        return result

    def _values(self, module: _Module, expr: ast.AST, depth: int) -> tuple[list[Value], bool]:
        if depth > _MAX_DEPTH:
            return [], False
        if isinstance(expr, (ast.Constant, ast.JoinedStr, ast.Dict, ast.List, ast.Tuple, ast.Set)):
            return [(module, expr)], True
        if isinstance(expr, ast.BinOp):
            return [(module, expr)], True
        if isinstance(expr, ast.Name):
            return self._name(module, expr, depth)
        if isinstance(expr, ast.Attribute):
            if isinstance(expr.value, ast.Name) and (
                expr.value.id in {"self", "cls"} or any(
                    isinstance(node, ast.ClassDef) and node.name == expr.value.id for node in module.tree.body
                )
            ):
                return self._bound(module, module.attributes.get(expr.attr, []), depth)
            # ``action.commands`` on an object built elsewhere: what the module passes as ``commands=`` to any
            # constructor, or binds as that attribute. Never complete: the object may come from outside.
            passed = [kw.value for calls in module.calls.values() for call in calls for kw in call.keywords
                      if kw.arg == expr.attr]
            found, _ = self._union(module, passed, depth)
            attributes, _ = self._bound(module, module.attributes.get(expr.attr, []), depth)
            return found + attributes, False
        if isinstance(expr, ast.Subscript):
            return self._subscript(module, expr, depth)
        if isinstance(expr, ast.Call):
            return self._call(module, expr, depth)
        if isinstance(expr, ast.IfExp):
            return self._union(module, (expr.body, expr.orelse), depth)
        if isinstance(expr, ast.BoolOp):
            return self._union(module, expr.values, depth)
        if isinstance(expr, (ast.NamedExpr, ast.Starred, ast.Await)):
            return self.values(module, expr.value, depth + 1)
        if isinstance(expr, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return [(module, ast.List(elts=[expr.elt], ctx=ast.Load()))], True
        return [], False

    def _union(self, module: _Module, exprs: Any, depth: int) -> tuple[list[Value], bool]:
        found: list[Value] = []
        complete = True
        for item in exprs:
            values, ok = self.values(module, item, depth + 1)
            found.extend(values)
            complete &= ok
        return found, complete

    def _bound(self, module: _Module, bound: list[tuple[ast.AST, tuple[Any, ...]]], depth: int) -> tuple[list[Value], bool]:
        if not bound:
            return [], False
        found: list[Value] = []
        complete = True
        for expr, path in bound:
            expr, path = _unzip(expr, path)
            values, ok = self.values(module, expr, depth + 1)
            for step in path:
                values, step_ok = self._step(values, step, depth)
                ok &= step_ok
            found.extend(values)
            complete &= ok
        return found, complete

    def _step(self, values: list[Value], step: Any, depth: int) -> tuple[list[Value], bool]:
        found: list[Value] = []
        complete = True
        for module, node in values:
            if step == "rest":
                found.append((module, node))
            elif step == "item":
                if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
                    for element in node.elts:
                        items, ok = self.values(module, element, depth + 1)
                        if isinstance(element, ast.Starred):
                            items, ok = self._step(items, "item", depth + 1)
                        found.extend(items)
                        complete &= ok
                elif isinstance(node, ast.Dict):
                    keys, ok = self._union(module, [key for key in node.keys if key is not None], depth)
                    found.extend(keys)
                    complete &= ok and None not in node.keys
                else:
                    complete = False
            elif step == "values" and isinstance(node, ast.Dict):
                items, ok = self._union(module, node.values, depth)
                found.extend(items)
                complete &= ok and None not in node.keys
            elif isinstance(node, (ast.List, ast.Tuple)) and isinstance(step, int):
                if any(isinstance(element, ast.Starred) for element in node.elts) or step >= len(node.elts):
                    complete = False
                    continue
                items, ok = self.values(module, node.elts[step], depth + 1)
                found.extend(items)
                complete &= ok
            else:
                complete = False
        return found, complete

    def _name(self, module: _Module, expr: ast.Name, depth: int) -> tuple[list[Value], bool]:
        scope = module.scope_of(expr)
        while True:
            bound = module.bindings.get((scope, expr.id), [])
            parameter = isinstance(scope, (*_FUNCTION_NODES, ast.Lambda)) and expr.id in _parameter_names(scope)
            if bound or parameter:
                found, complete = self._bound(module, bound, depth) if bound else ([], True)
                if parameter:
                    values, ok = self._arguments(module, scope, expr.id, depth)
                    found += values
                    complete &= ok
                return found, complete
            if scope is None:
                break
            scope = module.scope_of(scope)
        if expr.id in module.imports:
            target, name = module.imports[expr.id]
            other = _load_module(target)
            if other is not None:
                return self._bound(other, other.bindings.get((None, name), []), depth)
        return [], False

    def _arguments(self, module: _Module, function: ast.AST, name: str, depth: int) -> tuple[list[Value], bool]:
        """Values passed for parameter ``name`` at every call of ``function`` in the same module."""
        if isinstance(function, ast.Lambda) or function.args.vararg or function.args.kwarg:
            return [], False
        positional = [arg.arg for arg in (*function.args.posonlyargs, *function.args.args)]
        method = bool(positional) and positional[0] in {"self", "cls"} and isinstance(
            module.parents.get(function), ast.ClassDef
        )
        defaults = dict(zip(reversed(positional), reversed(function.args.defaults)))
        defaults.update({arg.arg: value for arg, value in zip(function.args.kwonlyargs, function.args.kw_defaults) if value})
        calls = [(module, call) for call in module.calls.get(function.name, [])]
        if isinstance(module.parents.get(function), ast.Module) and module.dotted:
            calls += _importer_calls(module.dotted, function.name)
        if not calls:
            return [], False
        found: list[Value] = []
        complete = True
        for caller, call in calls:
            offset = 1 if method and isinstance(call.func, ast.Attribute) else 0
            if any(isinstance(arg, ast.Starred) for arg in call.args) or any(kw.arg is None for kw in call.keywords):
                complete = False
                continue
            supplied = next((kw.value for kw in call.keywords if kw.arg == name), None)
            if supplied is None and name in positional and 0 <= positional.index(name) - offset < len(call.args):
                supplied = call.args[positional.index(name) - offset]
            supplied = supplied if supplied is not None else defaults.get(name)
            if supplied is None:
                complete = False
                continue
            values, ok = self.values(caller, supplied, depth + 1)
            found.extend(values)
            complete &= ok
        return found, complete

    def _subscript(self, module: _Module, expr: ast.Subscript, depth: int) -> tuple[list[Value], bool]:
        containers, complete = self.values(module, expr.value, depth + 1)
        key = expr.slice.value if isinstance(expr.slice, ast.Constant) else None
        found: list[Value] = []
        for owner, node in containers:
            if isinstance(node, ast.Dict):
                chosen = [v for k, v in zip(node.keys, node.values) if key is None or (isinstance(k, ast.Constant) and k.value == key)]
                complete &= key is None or None not in node.keys
            elif isinstance(node, (ast.List, ast.Tuple)) and not any(isinstance(e, ast.Starred) for e in node.elts):
                chosen = [node.elts[key]] if isinstance(key, int) and -len(node.elts) <= key < len(node.elts) else node.elts
            else:
                complete = False
                continue
            values, ok = self._union(owner, chosen, depth)
            found.extend(values)
            complete &= ok
        return found, complete

    def _call(self, module: _Module, call: ast.Call, depth: int) -> tuple[list[Value], bool]:
        name = _callee_name(call)
        if isinstance(call.func, ast.Attribute) and name == "get" and call.args:
            # ``mapping.get("key", default)``: the key's value in each dict the receiver can be, plus the default.
            key = ast.Subscript(value=call.func.value, slice=call.args[0], ctx=ast.Load())
            found, complete = self._subscript(module, key, depth)
            if len(call.args) > 1:
                values, ok = self.values(module, call.args[1], depth + 1)
                found += values
                complete &= ok
            return found, complete
        if isinstance(call.func, ast.Attribute) and name in _STRING_METHODS:
            parts = [call.func.value, *call.args, *(kw.value for kw in call.keywords)]
            if name == "join" and call.args:
                found, complete = self.values(module, call.func.value, depth + 1)
                items, ok = self.values(module, call.args[0], depth + 1)
                items, step_ok = self._step(items, "item", depth)
                return found + items, complete and ok and step_ok
            return self._union(module, parts, depth)
        if name in _TRANSPARENT_CALLS:
            return self._union(module, call.args, depth)
        if name in module.functions:
            return self._returns(module, module.functions[name], depth)
        if isinstance(call.func, ast.Name) and name in module.imports:
            target, imported = module.imports[name]
            other = _load_module(target)
            if other is not None and imported in other.functions:
                return self._returns(other, other.functions[imported], depth)
        return [], False

    def _returns(self, module: _Module, functions: list[ast.AST], depth: int) -> tuple[list[Value], bool]:
        returns = [
            node.value
            for function in functions
            for node in ast.walk(function)
            if isinstance(node, ast.Return) and node.value is not None and module.scope_of(node) is function
        ]
        return self._union(module, returns, depth) if returns else ([], False)


def _unzip(expr: ast.AST, path: tuple[Any, ...]) -> tuple[ast.AST, tuple[Any, ...]]:
    """``for a, b in zip(xs, ys)``, ``enumerate(xs)`` and ``mapping.items()``: the source of one unpacked name."""
    if len(path) < 2 or path[0] != "item" or not isinstance(path[1], int) or not isinstance(expr, ast.Call):
        return expr, path
    index, rest = path[1], path[2:]
    name = _callee_name(expr)
    if isinstance(expr.func, ast.Name) and name == "zip" and index < len(expr.args):
        return expr.args[index], ("item", *rest)
    if isinstance(expr.func, ast.Name) and name == "enumerate" and expr.args:
        return (ast.Constant(value=0), ()) if index == 0 else (expr.args[0], ("item", *rest))
    if isinstance(expr.func, ast.Attribute) and name == "items" and not expr.args:
        return expr.func.value, ("item" if index == 0 else "values", *rest)
    return expr, path


def _parameter_names(function: ast.AST) -> set[str]:
    args = function.args
    return {arg.arg for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)}


_RESOLVER = _Resolver()


# ---------------------------------------------------------------------------------------------------------
# Content reads
# ---------------------------------------------------------------------------------------------------------


def _looks_like_endpoint(text: str) -> bool:
    if " " in text or "\n" in text:
        return False
    return bool(re.match(r"^(?:/(?:[A-Za-z$]|\{id\})|https://)", text))


_CONTENT_PARAM_KEYS = ("$select", "$expand")
_UNRESOLVED_ENDPOINT = "/unresolved-endpoint"  # judged on its parameters alone; no content path matches it

Read = tuple[str, int, str, dict[str, str]]


def _resolved_strings(module: _Module, expr: ast.AST) -> tuple[list[str], bool]:
    values, complete = _RESOLVER.values(module, expr)
    texts: list[str] = []
    for owner, node in values:
        text = _render(node, owner.constants, placeholder="{id}")
        if text is None:
            complete = complete and isinstance(node, ast.Constant)  # a number, None or bool carries no query text
            continue
        texts.append(text)
    return texts, complete


def _resolved_params(module: _Module, expr: ast.AST | None, depth: int = 0) -> tuple[dict[str, str], bool]:
    """The query ``expr`` can carry: every dict it can be, merged, each key's alternatives joined by commas.

    Complete only when every dict, every ``**`` merge and every ``$select``/``$expand`` value is visible.
    """
    if expr is None:
        return {}, True
    values, complete = _RESOLVER.values(module, expr)
    merged: dict[str, list[str]] = {}
    for owner, node in values:
        if isinstance(node, ast.Constant) and node.value is None:
            continue
        if not isinstance(node, ast.Dict) or depth > _MAX_DEPTH:
            complete = False
            continue
        for key, value in zip(node.keys, node.values):
            if key is None:
                inner, ok = _resolved_params(owner, value, depth + 1)
                complete &= ok
                for name, text in inner.items():
                    merged.setdefault(name, []).append(text)
            elif isinstance(key, ast.Constant) and isinstance(key.value, str):
                texts, ok = _resolved_strings(owner, value)
                complete &= ok or key.value not in _CONTENT_PARAM_KEYS
                merged.setdefault(key.value, []).extend(texts)
            else:
                complete = False
    return {name: ",".join(text for text in texts if text) for name, texts in merged.items()}, complete


def _endpoint_text(module: _Module, node: ast.AST) -> str | None:
    text = _render(node, module.constants, placeholder="{id}")
    if text is None:
        return None
    if text.startswith("{id}/"):
        text = text[len("{id}") :]  # a root constant (GRAPH_ROOT and the like) joined to a path
    return text if _looks_like_endpoint(text) else None


def _request_associations(module: _Module) -> Iterator[tuple[ast.AST, list[ast.AST], ast.AST | None]]:
    """``(site, endpoint candidates, params)`` of every request: a ``params=`` call or an endpoint/params dict."""
    for node in ast.walk(module.tree):
        if isinstance(node, ast.Dict):
            entries = {
                key.value: value
                for key, value in zip(node.keys, node.values)
                if isinstance(key, ast.Constant) and isinstance(key.value, str)
            }
            if "endpoint" in entries and "params" in entries:
                yield node, [entries["endpoint"]], entries["params"]
        elif isinstance(node, ast.Call):
            params = next((kw.value for kw in node.keywords if kw.arg == "params"), None)
            if params is not None:
                candidates = [*node.args, *(kw.value for kw in node.keywords if kw.arg not in {"params", None})]
                yield node, candidates, params


def _endpoints_in(module: _Module) -> tuple[list[Read], list[tuple[str, str, int, dict[str, str]]]]:
    """Every endpoint read of a module, and every request whose endpoint or parameters stay unresolved.

    Each endpoint literal is judged bare. Each request is judged again with the parameters it is sent with, by
    resolving the endpoint and ``params`` arguments through local bindings, module constants, imports and the
    arguments at every call of the enclosing function. A request either resolves completely or is returned as
    unresolved, with whatever parameters were visible, so a lost association cannot pass silently.
    """
    reads: list[Read] = []
    skipped = module.docstrings
    seen: set[ast.AST] = set()
    for node in ast.walk(module.tree):
        if node in seen or node in skipped:
            seen.update(ast.walk(node))
            continue
        if not isinstance(node, (ast.Constant, ast.JoinedStr, ast.BinOp)):
            continue
        if _render(node, module.constants, placeholder="{id}") is None:
            continue
        seen.update(ast.walk(node))
        if (url := _endpoint_text(module, node)) is not None:
            reads.append((module.label, node.lineno, url, {}))
    unresolved: list[tuple[str, str, int, dict[str, str]]] = []
    for site, candidates, params_expr in _request_associations(module):
        params, params_complete = _resolved_params(module, params_expr)
        endpoints: list[tuple[_Module, ast.AST]] = []
        endpoint_complete = False
        for candidate in candidates:
            values, complete = _RESOLVER.values(module, candidate)
            found = [(owner, node) for owner, node in values if _endpoint_text(owner, node) is not None]
            if found:
                endpoints.extend(found)
                endpoint_complete = complete if not endpoint_complete else endpoint_complete and complete
        for owner, node in endpoints:
            reads.append((module.label, site.lineno, str(_endpoint_text(owner, node)), params))
        if not (endpoints and endpoint_complete and params_complete):
            unresolved.append((module.label, _qualname(site, module.parents), site.lineno, params))
    return reads, unresolved


def _config_endpoints() -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []

    def walk(value: Any, where: str) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                walk(item, f"{where}.{key}")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, f"{where}[{index}]")
        elif isinstance(value, str) and _looks_like_endpoint(value):
            found.append((where, value))

    walk(json.loads(COLLECTOR_DEFINITIONS.read_text(encoding="utf-8")), "collector-definitions")
    return found


def _content_reason(url: str, params: dict[str, str]) -> str | None:
    template, _ = api_inventory.endpoint_template(url)
    return api_inventory._content_reason(template, api_inventory._request_params(url, params))


def test_classifier_flags_the_content_shapes_it_must_refuse() -> None:
    """The classifier the scan relies on still recognises message, mail, file and attachment content."""
    for url, params in (
        ("/users/{id}/messages", {}),
        ("/users/{id}/mailFolders/inbox/messages/{id}/attachments", {}),
        ("/drives/{id}/items/{id}/content", {}),
        ("/users/{id}/messages/{id}/$value", {}),
        ("/teams/{id}/channels/{id}/messages", {}),
        ("/users/{id}/mailFolders", {"$expand": "messages"}),
        ("/users/{id}/events", {"$select": "subject,body"}),
        ("https://graph.microsoft.com/beta/users/{id}/messages?$select=subject", {}),
    ):
        assert _content_reason(url, params), url
    assert _content_reason("/admin/serviceAnnouncement/messages", {}) is None


def _engine_endpoint_scan() -> tuple[list[Read], list[tuple[str, str, int, dict[str, str]]]]:
    reads: list[Read] = []
    unresolved: list[tuple[str, str, int, dict[str, str]]] = []
    for path in _python_files(ENGINE / "collectors", ENGINE / "adapters"):
        found, open_requests = _endpoints_in(_module_for(path))
        reads += found
        unresolved += open_requests
    return reads, unresolved


def test_no_collector_or_adapter_endpoint_reads_content() -> None:
    endpoints, unresolved = _engine_endpoint_scan()
    templates = {api_inventory.endpoint_template(url)[0] for _, _, url, _ in endpoints}
    # The scan must see the reads it is meant to judge, so an extraction failure cannot pass as a clean result.
    assert len(endpoints) > 100
    assert {"/deviceManagement/deviceConfigurations", "/users/{id}/mailboxSettings", "/users"} <= templates
    assert sum(1 for *_, params in endpoints if params) > 40  # parameters reach the endpoints they are sent with

    violations = [
        f"{file}:{line} {url} {params}: {reason}"
        for file, line, url, params in endpoints
        if (reason := _content_reason(url, params))
    ]
    # An unresolved request is still judged on the parameters that are visible.
    violations += [
        f"{file}:{line} {qualname} {params}: {reason}"
        for file, qualname, line, params in unresolved
        if (reason := _content_reason(_UNRESOLVED_ENDPOINT, params))
    ]
    assert violations == []


def test_unresolved_requests_are_exactly_the_reviewed_ones() -> None:
    _, unresolved = _engine_endpoint_scan()
    assert {(file, qualname) for file, qualname, _, _ in unresolved} == set(_UNRESOLVED_REQUESTS)


def _synthetic(source: str) -> _Module:
    return _Module(source, "synthetic.py")


def _synthetic_reasons(source: str) -> tuple[list[str], list[str]]:
    reads, unresolved = _endpoints_in(_synthetic(source))
    judged = [f"{url}: {reason}" for _, _, url, params in reads if (reason := _content_reason(url, params))]
    return judged, [qualname for _, qualname, _, _ in unresolved]


@pytest.mark.parametrize(
    "source",
    [
        # The review's case: the endpoint is bound to a name, the content query sits on the call.
        'def read(client):\n    endpoint = "/users"\n    return client.get_json(endpoint, params={"$expand": "messages"})\n',
        # The endpoint is not the first argument.
        'def read(self, client):\n    return self._fetch(client, "/users", params={"$expand": "messages"})\n',
        # The parameters are bound to a name, merged with ``**`` or chosen by a condition.
        'def read(client):\n    query = {"$select": "subject,body"}\n    return client.get_all("/users/{x}/events", params=query)\n',
        'BASE = {"$expand": "messages"}\ndef read(client):\n    return client.get_all("/users", params={"$top": "5", **BASE})\n',
        'def read(client, flag):\n    return client.get_all("/users", params={"$expand": "messages"} if flag else {})\n',
        # Both arrive as arguments of the enclosing function, from a caller in the same module.
        'def fetch(client, path, params):\n    return client.get_all(path, params=params)\n'
        'def run(client):\n    return fetch(client, "/users", {"$expand": "messages"})\n',
        # A loop over a list of specs.
        'SPECS = [{"path": "/users", "params": {"$expand": "messages"}}]\n'
        'def run(client):\n    for spec in SPECS:\n        client.get_all(spec["path"], params=spec["params"])\n',
    ],
)
def test_content_query_bound_away_from_the_call_is_still_judged(source: str) -> None:
    judged, unresolved = _synthetic_reasons(source)
    assert judged and unresolved == [], (judged, unresolved)


def test_an_unresolved_request_is_reported_not_passed() -> None:
    _, unresolved = _synthetic_reasons(
        'def run(client, spec):\n    return client.get_all(spec["endpoint"], params=spec.get("params"))\n'
    )
    assert unresolved == ["run"]
    judged, unresolved = _synthetic_reasons('def run(client):\n    return client.get_all("/users", params=build())\n')
    assert unresolved == ["run"]
    # A visible content query on an unresolved endpoint is still refused.
    reads, open_requests = _endpoints_in(_synthetic('def run(client, path):\n    client.get_all(path, params={"$expand": "messages"})\n'))
    assert [_content_reason(_UNRESOLVED_ENDPOINT, params) for *_, params in open_requests] == ["$expand requests content"]


def test_graph_request_methods_take_params_by_keyword() -> None:
    """The scan reads ``params=``; a positional query would bypass it."""
    positional = []
    for path in _python_files(ENGINE):
        for node in ast.walk(_module_for(path).tree):
            if isinstance(node, ast.Call) and _callee_name(node) in {"get_json", "get_all", "iter_pages", "iter_items"}:
                if isinstance(node.func, ast.Attribute) and len(node.args) > 1:
                    positional.append(f"{_relative(path)}:{node.lineno}")
    assert positional == []


def test_no_collector_definition_endpoint_reads_content() -> None:
    violations = [
        f"{where} {url}: {reason}" for where, url in _config_endpoints() if (reason := _content_reason(url, {}))
    ]
    assert violations == []


# ---------------------------------------------------------------------------------------------------------
# PowerShell command sites
# ---------------------------------------------------------------------------------------------------------


# A process launch hands its argv to the OS; ``<adapter>.run`` hands a command to a PowerShell or CLI runner.
_PROCESS_CALLS = frozenset({"run", "Popen", "check_output", "check_call", "call", "getoutput", "getstatusoutput"})
# ``.run`` receivers that are not runners: a collector run takes a context, never command text.
_NON_RUNNER_RECEIVERS = frozenset({"collector", "collector_runner", "runner", "asyncio"})
_CMDLET_ANY_CASE = re.compile(r"(?<![\w.$-])([A-Za-z]+)-([A-Za-z][A-Za-z0-9]*)(?![\w-])")

CommandSite = tuple[str, str, int, str]


def _origin(module: _Module, expr: ast.AST, depth: int = 0) -> str | None:
    """Dotted origin of a callee through ``import x as y``, ``from x import y as z`` and plain assignments
    (``launch = sp.run``), or None when it does not come from an import."""
    if depth > _MAX_DEPTH:
        return None
    if isinstance(expr, ast.Attribute):
        base = _origin(module, expr.value, depth + 1)
        return f"{base}.{expr.attr}" if base else None
    if not isinstance(expr, ast.Name):
        return None
    if expr.id in module.module_aliases:
        return module.module_aliases[expr.id]
    if expr.id in module.imports:
        base, name = module.imports[expr.id]
        return f"{base}.{name}"
    for (_, name), bound in module.bindings.items():
        if name != expr.id:
            continue
        for value, path in bound:
            if not path and isinstance(value, (ast.Name, ast.Attribute)):
                found = _origin(module, value, depth + 1)
                if found is not None:
                    return found
    return None


def _runner_inputs(module: _Module) -> Iterator[tuple[ast.Call, ast.AST]]:
    """``(call, input)`` of every call that runs a process or hands a command to a runner.

    A process launch is recognised by where its callee comes from, not how it is spelt: ``sp.Popen`` after
    ``import subprocess as sp``, ``launch`` after ``from subprocess import run as launch`` or ``launch = sp.run``.
    """
    for node in ast.walk(module.tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = _callee_name(node)
        receiver = func.value if isinstance(func, ast.Attribute) else None
        receiver_name = (
            receiver.id if isinstance(receiver, ast.Name) else receiver.attr if isinstance(receiver, ast.Attribute) else None
        )
        origin = _origin(module, func)
        if origin is not None and origin.startswith("subprocess."):
            is_runner = origin.removeprefix("subprocess.") in _PROCESS_CALLS
        elif receiver is None:
            is_runner = False
        else:
            is_runner = name == "run" and receiver_name not in _NON_RUNNER_RECEIVERS
        if not is_runner:
            continue
        given = node.args[0] if node.args else next(
            (kw.value for kw in node.keywords if kw.arg in {"args", "command", "script"}), None
        )
        if given is not None:
            yield node, given


def _executable_strings(
    module: _Module, expr: ast.AST, visited: set[int] | None = None, depth: int = 0
) -> tuple[list[Value], bool]:
    """Every string that can become part of ``expr``: the literals, their f-string fields and ``+`` operands,
    and the elements of the lists (argv) and dicts it can be."""
    visited = set() if visited is None else visited
    if depth > _MAX_DEPTH:
        return [], False
    values, complete = _RESOLVER.values(module, expr)
    found: list[Value] = []

    def expand(owner: _Module, child: ast.AST) -> None:
        nonlocal complete
        inner, ok = _executable_strings(owner, child, visited, depth + 1)
        found.extend(inner)
        complete &= ok

    for owner, node in values:
        if id(node) in visited:
            continue
        visited.add(id(node))
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                found.append((owner, node))
        elif isinstance(node, ast.JoinedStr):
            found.append((owner, node))
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    expand(owner, part.value)
        elif isinstance(node, ast.BinOp):
            if _render(node, owner.constants, placeholder="x") is not None:
                found.append((owner, node))
            for side in (node.left, node.right):
                if not isinstance(side, ast.Constant):
                    expand(owner, side)
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for element in node.elts:
                expand(owner, element.value if isinstance(element, ast.Starred) else element)
        elif isinstance(node, ast.Dict):
            for value in node.values:
                expand(owner, value)
    return found, complete


def _command_sites_in(module: _Module) -> tuple[list[CommandSite], list[tuple[str, str, int]]]:
    """Executable command sites reachable from the module's runner calls, and the runner calls whose input is
    not fully visible in the source (it arrives from another module, a config file or an operator).

    A site is a string literal that can flow into a runner: through local and module bindings, imports, class
    attributes, function returns, the arguments at every call of the enclosing function, f-string fields,
    ``+`` joins, ``str.join`` and argv lists. A string that never reaches a runner (a docstring, a comment, help
    or documentation text) is not a site, whatever it says.
    """
    sites: dict[tuple[str, int], CommandSite] = {}
    unresolved: list[tuple[str, str, int]] = []
    for call, given in _runner_inputs(module):
        strings, complete = _executable_strings(module, given)
        for owner, node in strings:
            text = _render(node, owner.constants, placeholder="x")
            if text is not None and node not in owner.docstrings:
                sites[(owner.label, id(node))] = (owner.label, _qualname(node, owner.parents), node.lineno, text)
        if not complete:
            unresolved.append((module.label, _qualname(call, module.parents), call.lineno))
    return list(sites.values()), unresolved


def _command_names(script: str) -> list[str]:
    """Cmdlet names at a command position, by the read guard's own tokenizer, in any letter case.

    PowerShell is case-insensitive, so ``import-module`` is ``Import-Module``. A string the tokenizer refuses
    falls back to every ``verb-noun`` word with a PowerShell verb, in any case.
    """
    try:
        tokens = read_guard._tokenize(script, "scan")
    except CommandRefused:
        return [
            f"{verb}-{noun}" for verb, noun in _CMDLET_ANY_CASE.findall(script) if verb.lower() in _POWERSHELL_VERBS
        ]
    names: list[str] = []
    for index, token in enumerate(tokens):
        if token.kind != "word" or not _CMDLET.match(token.text):
            continue
        previous = tokens[index - 1] if index else None
        following = tokens[index + 1] if index + 1 < len(tokens) else None
        at_command = previous is None or (previous.kind == "op" and previous.text in read_guard._SEPARATORS)
        if not at_command or (following is not None and following.kind == "op" and following.text == "="):
            continue
        if token.text.split("-", 1)[0].lower() in _POWERSHELL_VERBS:  # ``ms-graph`` in an argv is not a cmdlet
            names.append(token.text)
    return names


def _source_command_sites() -> list[CommandSite]:
    sites: dict[tuple[str, int, str], CommandSite] = {}
    for path in _python_files(SRC):
        for site in _command_sites_in(_module_for(path))[0]:
            sites[(site[0], site[2], site[3])] = site
    return sorted(sites.values())


def _unresolved_runner_inputs() -> set[tuple[str, str]]:
    return {
        (file, qualname) for path in _python_files(SRC) for file, qualname, _ in _command_sites_in(_module_for(path))[1]
    }


def _config_command_sites() -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []

    def walk(value: Any, where: str, under_command: bool) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                walk(item, f"{where}.{key}", under_command or key in {"command", "commands", "command_variants"})
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, f"{where}[{index}]", under_command)
        elif isinstance(value, str) and under_command:
            found.append((where, value))

    for path in sorted(CONFIGS.glob("*.json")):
        walk(json.loads(path.read_text(encoding="utf-8")), path.name, False)
    return found


def _audited_violation(name: str) -> bool:
    """Not on the read allow-list of any PowerShell adapter (the DSC export is a read only for the DSC adapter)."""
    return not any(api_inventory.words_are_read(adapter, [name]) for adapter in ("powershell_graph", "m365dsc"))


def test_docstrings_and_comments_are_not_command_sites() -> None:
    sites = _source_command_sites()
    read_guard_lines = {line for file, _, line, _ in sites if file == "src/azure_tenant_audit/adapters/read_guard.py"}
    # read_guard.py:95 names Import-Module and Invoke-Expression in a docstring; it is not an executable site.
    assert 95 not in read_guard_lines
    assert not any("Import-Module" in text for file, _, _, text in sites if file.endswith("read_guard.py"))


def _command_violations(sites: list[CommandSite]) -> tuple[list[str], dict[tuple[str, str], set[str]]]:
    """Wrapper verbs outside the trusted table and audited commands off the read allow-list, in any case."""
    found: dict[tuple[str, str], set[str]] = {}
    violations: list[str] = []
    for file, qualname, line, text in sites:
        for name in _command_names(text):
            canonical = next((verb for verb in WRAPPER_VERBS if verb.lower() == name.lower()), None)
            key = (file, qualname)
            if canonical is not None:
                allowed = _TRUSTED_WRAPPER_SITES.get(key, (frozenset(), ""))[0]
                if canonical not in allowed:
                    violations.append(f"{file}:{line} {qualname}: wrapper {name} outside the trusted table")
                found.setdefault(key, set()).add(canonical)
                continue
            setup = _LOCAL_SETUP_SITES.get(key, (frozenset(), ""))[0]
            local = next((verb for verb in setup if verb.lower() == name.lower()), None)
            if local is not None:
                found.setdefault(key, set()).add(local)
                continue
            if _audited_violation(name):
                violations.append(f"{file}:{line} {qualname}: {name} is not on the read allow-list")
    return violations, found


def test_wrapper_operations_appear_only_at_trusted_sites() -> None:
    sites = _source_command_sites()
    assert len(sites) > 30  # the runner trace reaches the collectors' commands, not only the adapters
    violations, found = _command_violations(sites)
    assert violations == []
    # The tables are exact: every trusted entry is still in use with exactly the operations it names.
    assert {key: frozenset(value) for key, value in found.items()} == {
        key: value[0] for key, value in {**_TRUSTED_WRAPPER_SITES, **_LOCAL_SETUP_SITES}.items()
    }


def test_unresolved_runner_inputs_are_exactly_the_reviewed_ones() -> None:
    assert _unresolved_runner_inputs() == set(_UNRESOLVED_RUNNER_INPUTS)


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        # Lower case is still PowerShell: a lone wrapper verb in an argv reaches a process.
        ('import subprocess\ndef setup():\n'
         '    subprocess.run(["pwsh", "-Command", "import-module ExchangeOnlineManagement"], check=False)\n',
         "wrapper import-module outside the trusted table"),
        # Through a module constant, a helper's return value and an adapter.
        ('SCRIPT = "get-organizationconfig | set-organizationconfig -AuditDisabled $true"\n'
         'def script():\n    return SCRIPT\n'
         'def collect(adapter):\n    return adapter.run(script())\n',
         "set-organizationconfig is not on the read allow-list"),
        # Through a class attribute list unpacked in a loop, and an f-string field.
        ('class C:\n    commands = [("a", "Remove-Mailbox x")]\n'
         '    def run_all(self, adapter):\n        for name, command in self.commands:\n'
         '            adapter.run(f"{command} -Confirm:$false")\n',
         "Remove-Mailbox is not on the read allow-list"),
        # Aliased process launches: a renamed function, a renamed module and an assigned alias.
        ('from subprocess import run as launch\ndef f():\n    launch(["pwsh", "-Command", "Set-Mailbox x"])\n',
         "Set-Mailbox is not on the read allow-list"),
        ('import subprocess as sp\ndef f():\n    sp.Popen(["pwsh", "-Command", "Set-Mailbox x"])\n',
         "Set-Mailbox is not on the read allow-list"),
        ('import subprocess as sp\nlaunch = sp.check_output\n'
         'def f():\n    launch(["pwsh", "-Command", "Remove-Mailbox x"])\n',
         "Remove-Mailbox is not on the read allow-list"),
    ],
)
def test_executable_command_text_is_found_in_any_case(source: str, expected: str) -> None:
    sites, _ = _command_sites_in(_synthetic(source))
    violations, _ = _command_violations(sites)
    assert any(expected in item for item in violations), violations


@pytest.mark.parametrize(
    "source",
    [
        'from subprocess import run as launch\ndef f(argv):\n    launch(argv)\n',
        'import subprocess as sp\ndef f(argv):\n    sp.Popen(argv)\n',
        'import subprocess as sp\ndef f(argv):\n    sp.run(args=argv)\n',
    ],
)
def test_aliased_process_launch_with_unseen_input_is_reported(source: str) -> None:
    _, unresolved = _command_sites_in(_synthetic(source))
    assert [qualname for _, qualname, _ in unresolved] == ["f"]


def test_documentation_text_is_not_a_command_site() -> None:
    source = (
        'HELP = "Run Import-Module ExchangeOnlineManagement, then Connect-ExchangeOnline."\n'
        'TABLE = {"organizationConfig": "Get-OrganizationConfig | Set-OrganizationConfig"}\n'
        'def usage():\n'
        '    """Import-Module ExchangeOnlineManagement; Invoke-Expression x"""\n'
        '    # Connect-ExchangeOnline -UserPrincipalName admin\n'
        '    return HELP\n'
        'def missing_module(stderr):\n'
        '    return "import-module" in stderr.lower()\n'
        'def probe(adapter):\n'
        '    return adapter.run("Get-OrganizationConfig")\n'
    )
    sites, unresolved = _command_sites_in(_synthetic(source))
    assert [text for *_, text in sites] == ["Get-OrganizationConfig"]
    assert unresolved == []
    assert _command_violations(sites)[0] == []


def test_local_setup_install_is_not_reachable_from_an_audit_runner() -> None:
    callers = {
        _relative(path)
        for path in _python_files(SRC)
        if "ensure_exchange_online_module" in path.read_text(encoding="utf-8")
    }
    assert callers == {"src/auditex/auth.py", "src/auditex/guided.py"}


def test_config_command_fields_are_reads() -> None:
    sites = _config_command_sites()
    assert len(sites) > 50
    violations: list[str] = []
    for where, command in sites:
        if command.startswith("m365"):
            try:
                read_guard.check_command("m365_cli", command)
            except CommandRefused as exc:
                violations.append(f"{where}: {exc.reason}")
            continue
        names = _command_names(command)
        if not names:
            violations.append(f"{where}: no command found in {command!r}")
        violations.extend(f"{where}: {name} is not on the read allow-list" for name in names if _audited_violation(name))
        try:
            read_guard.check_command("powershell_graph", command)
        except CommandRefused as exc:
            violations.append(f"{where}: {exc.reason}")
    assert violations == []


def test_read_allow_list_gains_no_wrapper_verb_and_the_guard_refuses_each() -> None:
    for verb in WRAPPER_VERBS:
        for adapter in ("powershell_graph", "m365dsc"):
            assert not api_inventory.words_are_read(adapter, [verb])
            with pytest.raises(CommandRefused):
                read_guard.check_command(adapter, f"{verb} ExchangeOnlineManagement")
            with pytest.raises(CommandRefused):
                read_guard.check_command(adapter, f"Get-OrganizationConfig | {verb} 'x'")


def test_vetted_command_is_built_only_by_the_dsc_adapter() -> None:
    builders = set()
    for path in _python_files(SRC):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", None)) == "VettedCommand":
                builders.add(_relative(path))
    assert builders == {"src/azure_tenant_audit/adapters/m365dsc.py"}


def test_dsc_module_guard_reaches_powershell_run_as_vetted_command(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_run(self: PowerShellGraphAdapter, command: str, log_event: Any = None, **_: Any) -> dict[str, Any]:
        calls.append(command)
        if command == COMPATIBILITY_SCRIPT:
            return {"value": [{"module_version": MINIMUM_MODULE_VERSION, "powershell_version": "7.4.0"}]}
        return {"value": []}

    monkeypatch.setattr(PowerShellGraphAdapter, "run", fake_run)
    caller = "Export-M365DSCConfiguration -Components @('AADGroup') -Path 'out'"
    response = M365DSCAdapter().run(caller)

    assert "error" not in response
    assert calls[0] == COMPATIBILITY_SCRIPT
    read_guard.check_command("powershell_graph", calls[0])  # the probe is an ordinary guarded read
    wrapped = calls[1]
    assert isinstance(wrapped, VettedCommand)
    assert wrapped.vetted_text == caller
    assert wrapped.command_words == read_guard.check_command("m365dsc", wrapped.vetted_text)
    assert [name for name in _command_names(str(wrapped)) if name.lower() in {v.lower() for v in WRAPPER_VERBS}] == [
        "Import-Module",
        "Invoke-Expression",
    ]
    with pytest.raises(CommandRefused):
        read_guard.check_command("m365dsc", str(wrapped))

    # A caller command that is not a read never reaches PowerShell, wrapped or not.
    calls.clear()
    refused = M365DSCAdapter().run("Set-OrganizationConfig -AuditDisabled $true")
    assert refused["error_class"] == read_guard.REFUSED_ERROR_CLASS
    assert calls == []


# ---------------------------------------------------------------------------------------------------------
# Microsoft 365 CLI commands
# ---------------------------------------------------------------------------------------------------------


def _m365_commands() -> list[tuple[str, str]]:
    commands = [(where, text) for where, text in _config_command_sites() if text.startswith("m365")]
    for path in _python_files(ENGINE / "collectors"):
        for qualname, line, text in _string_expressions(path, placeholder="x"):
            if text.startswith("m365 "):
                commands.append((f"{_relative(path)}:{line} {qualname}", text))
    return commands


def test_every_collector_m365_command_passes_the_guard_and_a_write_verb_is_refused() -> None:
    commands = _m365_commands()
    assert len(commands) > 20
    for where, command in commands:
        words = read_guard.check_command("m365_cli", command)
        assert api_inventory.words_are_read("m365_cli", list(words)), where
        argv = command.split()
        # argv[0] is m365, so argv[len(words)] is the last command word; a usage report swaps its ``report`` word.
        target = 2 if tuple(word.lower() for word in words[:2]) == read_guard.M365_REPORT_PREFIX else len(words)
        for verb in ("remove", "set", "add"):
            written = [*argv[:target], verb, *argv[target + 1 :]]
            with pytest.raises(CommandRefused):
                read_guard.check_command("m365_cli", written)
            assert not api_inventory.words_are_read("m365_cli", written[1 : len(words) + 1]), where


# ---------------------------------------------------------------------------------------------------------
# Google API calls and scopes
# ---------------------------------------------------------------------------------------------------------


_GOOGLE_SERVICE_BUILDERS = frozenset({"_service", "_subject_service", "build"})
# ``googleapiclient.http.HttpRequest`` members: touching one marks the object as a request, never a resource.
_HTTP_REQUEST_MEMBERS = frozenset(
    {"execute", "next_chunk", "add_response_callback", "to_json", "from_json", "null_postproc", "uri", "method",
     "body", "headers", "methodId", "http", "postproc", "resumable", "response_callbacks", "body_size",
     "resumable_uri", "resumable_progress"}
)


def _google_api_calls() -> list[tuple[str, int, str, ast.Call]]:
    """``(file, line, "resource.chain.method", call)`` for every Google API method call in the provider."""
    return [
        call
        for path in _python_files(GOOGLE_DIR)
        for call in _google_calls_in(path.read_text(encoding="utf-8"), _relative(path))
    ]


def _google_calls_in(source: str, label: str) -> list[tuple[str, int, str, ast.Call]]:
    """Every API method call of one module, whether executed inline or built first and executed later.

    A call on a service (``_service``/``_subject_service``/``build``, inline or bound to a name) is a resource
    accessor only when its result is used as a handle: a method that is not an ``HttpRequest`` member is called
    on it, inline or through the name it is bound to, and no ``HttpRequest`` member (``execute``, ``uri``,
    ``body``, ``to_json`` ...) is touched on it anywhere. Every other call is a request and is recorded, whether it
    is executed inline, bound to a name and executed later, inspected, passed on or returned; a name used both
    ways counts as a request.
    """
    tree = ast.parse(source)
    parents = _parents(tree)
    request_uses: set[str] = set()
    method_uses: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.attr in _HTTP_REQUEST_MEMBERS:
                request_uses.add(node.value.id)
            elif isinstance(parents.get(node), ast.Call) and parents[node].func is node:
                method_uses.add(node.value.id)
    handle_uses = method_uses - request_uses
    handles: set[str] = set()

    def api_chain(node: ast.AST) -> list[str] | None:
        """The API part of a call chain (after the service it starts from), or None if it is not an API call."""
        chain = _call_chain(node) if isinstance(node, ast.Call) else []
        builder = max((index for index, name in enumerate(chain) if name in _GOOGLE_SERVICE_BUILDERS), default=None)
        if builder is not None:
            return chain[builder + 1 :]
        if chain and chain[0] in handles:
            return chain[1:]
        return None

    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if not (isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if len(targets) != 1 or not isinstance(targets[0], ast.Name) or targets[0].id in handles:
                continue
            value = node.value
            if (
                isinstance(value, ast.Call)
                and getattr(value.func, "id", None) == "getattr"
                and value.args
                and isinstance(value.args[0], ast.Name)
                and value.args[0].id in handles
            ):
                is_handle = True  # ``policies = getattr(service, "policies", None)``
            elif isinstance(value, ast.Name):
                is_handle = value.id in handles
            else:
                chain = api_chain(value)
                # A service itself, or a resource accessor bound to a name that is then used as a handle.
                is_handle = chain == [] or (bool(chain) and targets[0].id in handle_uses and chain[-1] != "execute")
            if is_handle:
                handles.add(targets[0].id)
                changed = True

    found: list[tuple[str, int, str, ast.Call]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        chain = api_chain(node)
        if not chain or chain[-1] == "execute":
            continue
        parent = parents.get(node)
        if (
            isinstance(parent, ast.Attribute)
            and parent.attr not in _HTTP_REQUEST_MEMBERS
            and isinstance(parents.get(parent), ast.Call)
            and parents[parent].func is parent
        ):
            continue  # an inline resource accessor: another API method is called on its result
        if isinstance(parent, (ast.Assign, ast.AnnAssign)):
            targets = parent.targets if isinstance(parent, ast.Assign) else [parent.target]
            if len(targets) == 1 and isinstance(targets[0], ast.Name) and targets[0].id in handles:
                continue  # a bound resource handle (``settings = service.users().settings()``)
        found.append((label, node.lineno, ".".join(chain), node))
    return found


def _call_chain(node: ast.Call) -> list[str]:
    names: list[str] = []
    current: ast.AST = node
    while isinstance(current, (ast.Call, ast.Attribute)):
        if isinstance(current, ast.Attribute):
            names.append(current.attr)
            current = current.value
        else:
            current = current.func
    if not isinstance(current, ast.Name):
        return []
    names.append(current.id)
    return list(reversed(names))


def test_every_google_api_call_is_a_read_method() -> None:
    calls = _google_api_calls()
    methods = {chain for _, _, chain, _ in calls}
    assert methods == {
        "users.list", "groups.list", "orgunits.list", "domains.list", "roles.list", "roleAssignments.list",
        "members.list", "users.aliases.list", "tokens.list", "activities.list", "alerts.list",
        "getAutoForwarding", "filters.list", "forwardingAddresses.list", "sendAs.list", "getImap", "getPop",
        "getVacation", "delegates.list", "files.list", "drives.list", "groups.get", "resources.calendars.list",
        "calendarList.list", "acl.list", "list", "mobiledevices.list", "chromeosdevices.list",
    }
    violations = [
        f"{file}:{line} {chain}" for file, line, chain, _ in calls if not _GOOGLE_READ_METHOD.match(chain.rsplit(".", 1)[-1])
    ]
    assert violations == []


@pytest.mark.parametrize(
    "source",
    [
        # A request built, bound to a name and executed later.
        'def f(self):\n    service = self._service("admin", "directory_v1")\n'
        '    request = service.users().delete(userKey="victim")\n    request.execute()\n',
        # Inline from the service builder, as a method and as a plain function.
        'def f(self):\n    self._service("admin", "directory_v1").users().delete(userKey="victim").execute()\n',
        'def f():\n    _service("admin", "directory_v1").users().delete(userKey="victim").execute()\n',
        'def f(creds):\n    build("admin", "directory_v1", credentials=creds).users().delete(userKey="v").execute()\n',
        # Through a bound resource handle, and a request handed to a helper rather than executed here.
        'def f(self):\n    users = self._service("admin", "directory_v1").users()\n'
        '    return run(users.delete(userKey="victim"))\n',
        # A request whose properties are inspected before or instead of executing it.
        'def f(self):\n    service = self._service("admin", "directory_v1")\n'
        '    request = service.users().delete(userKey="victim")\n    log(request.uri)\n    request.execute()\n',
        'def f(self):\n    service = self._service("admin", "directory_v1")\n'
        '    request = service.users().delete(userKey="victim")\n    return request.to_json()\n',
        'def f(self):\n    service = self._service("admin", "directory_v1")\n'
        '    request = service.users().delete(userKey="victim")\n'
        '    request.add_response_callback(print)\n    return request.headers\n',
        'def f(self):\n    return self._service("admin", "directory_v1").users().delete(userKey="victim").uri\n',
    ],
)
def test_google_write_calls_are_found_in_every_form(source: str) -> None:
    calls = _google_calls_in(source, "synthetic.py")
    # A chain through a bound handle starts at the handle (``delete``), as in the provider (``getImap``).
    assert [chain.rsplit(".", 1)[-1] for _, _, chain, _ in calls] == ["delete"]
    assert not _GOOGLE_READ_METHOD.match("delete")


def test_google_read_requests_and_handles_are_told_apart() -> None:
    source = (
        'def f(self):\n    service = self._service("admin", "directory_v1")\n'
        '    settings = service.users().settings()\n'
        '    request = service.users().list(customer="my_customer")\n'
        '    while request is not None:\n        response = request.execute()\n'
        '        request = service.users().list_next(request, response)\n'
        '    return settings.getImap(userId="me").execute()\n'
    )
    chains = sorted(chain for _, _, chain, _ in _google_calls_in(source, "synthetic.py"))
    assert chains == ["getImap", "users.list", "users.list_next"]
    assert all(_GOOGLE_READ_METHOD.match(chain.rsplit(".", 1)[-1]) for chain in chains)


def test_google_provider_has_no_media_export_or_batch_path() -> None:
    forbidden = {"get_media", "export", "export_media", "new_batch_http_request", "MediaIoBaseDownload", "watch"}
    hits = []
    for path in _python_files(GOOGLE_DIR):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            name = getattr(node, "attr", None) if isinstance(node, ast.Attribute) else getattr(node, "id", None)
            if name in forbidden:
                hits.append(f"{_relative(path)}:{node.lineno} {name}")
    assert hits == []


def test_drive_reads_ask_only_for_metadata_fields() -> None:
    drive = [call for _, _, chain, call in _google_api_calls() if chain in {"files.list", "drives.list"}]
    assert len(drive) == 2
    for call in drive:
        assert any(keyword.arg == "fields" for keyword in call.keywords)


def _requested_scopes() -> dict[str, set[str]]:
    scopes: dict[str, set[str]] = {}
    for path in _python_files(GOOGLE_DIR):
        for _, line, text in _string_expressions(path, placeholder="x"):
            if text.startswith(_GOOGLE_SCOPE_PREFIX):
                scopes.setdefault(text, set()).add(f"{_relative(path)}:{line}")
    return scopes


def _scope_is_read_only(scope: str) -> bool:
    return scope.endswith(".readonly") or bool(_METADATA_ONLY_SCOPE.search(scope))


def _scope_violations(scopes: set[str]) -> list[str]:
    """Requested scopes that are neither read-only, metadata-only nor an accepted write-capable exception."""
    return sorted(
        scope for scope in scopes if not _scope_is_read_only(scope) and scope not in _ACCEPTED_WRITE_CAPABLE_SCOPES
    )


def test_requested_google_scopes_are_read_only_metadata_only_or_accepted() -> None:
    assert _scope_violations(set(_requested_scopes())) == []


def test_gmail_settings_sharing_is_no_longer_requested() -> None:
    assert _RETIRED_SCOPE not in _requested_scopes(), f"{_RETIRED_SCOPE} is write-capable and unneeded"
    for path in (REPO_ROOT / "src").rglob("*.py"):
        if path.name == "findings.py":  # the high-risk term list still flags an operator-granted scope
            continue
        assert _RETIRED_SCOPE not in path.read_text(encoding="utf-8"), path


def test_every_gmail_settings_call_is_covered_by_the_basic_scope() -> None:
    # Gmail API reference, users.settings.{getAutoForwarding,getImap,getPop,getVacation,filters.list,
    # forwardingAddresses.list,sendAs.list,delegates.list}: each lists gmail.settings.basic among its scopes.
    from auditex.google_workspace import auth as google_auth

    assert google_auth.GMAIL_SETTINGS_SCOPES == ("https://www.googleapis.com/auth/gmail.settings.basic",)


def test_an_unlisted_write_capable_scope_fails_the_rule() -> None:
    for scope in (
        "https://www.googleapis.com/auth/admin.directory.user",
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/drive",
        _RETIRED_SCOPE,
    ):
        assert _scope_violations({scope}) == [scope]
    assert _scope_violations({"https://www.googleapis.com/auth/gmail.metadata"}) == []
    assert _scope_violations({"https://www.googleapis.com/auth/drive.metadata.readonly"}) == []
    assert _scope_violations(set(_ACCEPTED_WRITE_CAPABLE_SCOPES)) == []


def test_google_scope_rule_and_exception_table_hold() -> None:
    from auditex.google_workspace import auth as google_auth
    from auditex.google_workspace.run import REGISTRY

    scopes = _requested_scopes()
    declared = set(google_auth.DEFAULT_GOOGLE_SCOPES) | set(google_auth.GMAIL_SETTINGS_SCOPES)
    declared |= set(google_auth.ISOLATED_GOOGLE_SCOPES)
    for name in REGISTRY:
        declared |= set(getattr(REGISTRY.get(name), "required_scopes", ()))
    assert declared <= set(scopes)  # the literal scan sees every scope the provider can request

    # The rule itself: a write-capable scope fails, read-only and metadata-only scopes pass.
    assert not _scope_is_read_only("https://www.googleapis.com/auth/admin.directory.user")
    assert not _scope_is_read_only("https://www.googleapis.com/auth/gmail.modify")
    assert _scope_is_read_only("https://www.googleapis.com/auth/gmail.metadata")
    assert _scope_is_read_only("https://www.googleapis.com/auth/drive.metadata.readonly")

    # The exception table is exact: still requested, really write-capable, documented, and never the pending one.
    calls = {chain for _, _, chain, _ in _google_api_calls()}
    assert _RETIRED_SCOPE not in _ACCEPTED_WRITE_CAPABLE_SCOPES
    for scope, row in _ACCEPTED_WRITE_CAPABLE_SCOPES.items():
        assert scope in scopes, f"{scope} is no longer requested; remove it from the exception table"
        assert not _scope_is_read_only(scope)
        assert (GOOGLE_SCOPE_NOTES.get(scope) or {}).get("risk") == "write_capable"
        assert row["blast_radius"] and row["reason"]
        # Used only for list and get: each named call is made by the provider and is a read method.
        assert row["calls"] <= calls, row["calls"] - calls
        assert all(_GOOGLE_READ_METHOD.match(chain.rsplit(".", 1)[-1]) for chain in row["calls"])


# ---------------------------------------------------------------------------------------------------------
# Section G: user- and admin-written text a settings read receives
# ---------------------------------------------------------------------------------------------------------


def _gmail_call_line(needle: str) -> str:
    source = (REPO_ROOT / "src/auditex/google_workspace/client.py").read_text(encoding="utf-8")
    return next(line for line in source.splitlines() if needle in line)


@pytest.mark.parametrize("row", _TEXT_EXPOSURES, ids=lambda row: f"{row['id']}-{Path(row['file']).name}")
def test_text_exposure_table_matches_the_source(row: dict[str, Any]) -> None:
    """A row whose read changed (removed at request level, or moved) must be re-decided, not left stale."""
    assert row["disposition"] in {"removed at request level", "discarded", "accepted", "follow_up", "removed_at_request"}
    assert row["needle"] in (REPO_ROOT / row["file"]).read_text(encoding="utf-8")
    if row["disposition"] == "removed at request level":
        assert "fields=GMAIL_" in row["needle"] or "fields=GMAIL_" in _gmail_call_line(row["needle"])


def test_removed_at_request_fields_are_absent_from_shipped_command_text() -> None:
    for row in _TEXT_EXPOSURES:
        if row["disposition"] != "removed_at_request":
            continue
        text = (REPO_ROOT / row["file"]).read_text(encoding="utf-8")
        for field in row["fields"]:
            assert field not in text, f"{row['id']}: {field} still in {row['file']}"


def test_discarded_gmail_text_never_leaves_the_collector() -> None:
    marker = "OWNER-WRITTEN-TEXT"
    payload = {
        "userEmail": "user@example.test",
        "vacation": {"enableAutoReply": True, **{field: marker for field in VACATION_TEXT_FIELDS}},
        "sendAs": [{"sendAsEmail": "user@example.test", **{field: marker for field in SEND_AS_TEXT_FIELDS}}],
        "filters": [
            {"id": "f1", "action": {"forward": "out@example.test"},
             "criteria": {"from": "a@example.test", **{field: marker for field in GMAIL_FILTER_TEXT_FIELDS}}}
        ],
    }
    collected = minimise_gmail_settings(payload)
    assert marker not in json.dumps(collected["vacation"]) + json.dumps(collected["sendAs"])
    written = minimise_user_text(collected)  # the bundle writer applies this to every raw payload
    assert marker not in json.dumps(written)
    assert written["vacation"]["enableAutoReply"] is True
    assert written["filters"][0]["criteria"]["from"] == "a@example.test"


def test_discarded_graph_mailbox_text_never_leaves_the_collector() -> None:
    marker = "OWNER-WRITTEN-TEXT"
    settings = {"automaticRepliesSetting": {"status": "alwaysEnabled", **{f: marker for f in AUTO_REPLY_TEXT_FIELDS}}}
    collected = minimise_mailbox_settings(settings)
    assert marker not in json.dumps(collected)
    assert collected["automaticRepliesSetting"]["status"] == "alwaysEnabled"
    rule = {
        "id": "r1",
        "conditions": {"fromAddresses": [{"emailAddress": {"address": "a@example.test"}}],
                       **{field: [marker] for field in RULE_CONDITION_WORD_FIELDS}},
        "actions": {"forwardTo": [{"emailAddress": {"address": "out@example.test"}}]},
    }
    written = minimise_user_text({"value": [rule], "settings": settings})
    assert marker not in json.dumps(written)
    assert written["value"][0]["conditions"]["fromAddresses"] == rule["conditions"]["fromAddresses"]


# ---------------------------------------------------------------------------------------------------------
# G8, G9: Google text fields removed at request level (M01-T09)
# ---------------------------------------------------------------------------------------------------------


def _masked(rows: list[dict[str, Any]], mask: str) -> list[dict[str, Any]]:
    inner = mask.split("alerts(", 1)[1].rstrip(")").split(",")
    return [{k: v for k, v in row.items() if k in inner} for row in rows]


def test_alert_mask_drops_message_text_and_keeps_normalised_fields() -> None:
    from types import SimpleNamespace

    from auditex.google_workspace.client import ALERT_FIELDS, GoogleWorkspaceClient

    marker = "MESSAGE-SNIPPET-SENTINEL"
    alert = {"alertId": "a1", "type": "Suspicious login", "createTime": "2026-01-01T00:00:00Z",
             "metadata": {"severity": "HIGH", "status": "NOT_STARTED"},
             "data": {"messages": [{"messageBodySnippet": marker, "subjectText": marker}]}}
    seen: dict[str, Any] = {}

    class _Req:
        def execute(self) -> dict[str, Any]:
            return {"alerts": _masked([alert], seen["fields"])}

    def _list(**kwargs: Any) -> _Req:
        seen.update(kwargs)
        return _Req()

    client = GoogleWorkspaceClient(credentials=None)
    client._services[("alertcenter", "v1beta1")] = SimpleNamespace(alerts=lambda: SimpleNamespace(list=_list))
    rows = client.list_alerts()
    assert seen["fields"] == ALERT_FIELDS
    assert marker not in json.dumps(rows)
    for kept in ("alertId", "type", "createTime", "metadata"):
        assert kept in rows[0]

    from auditex.google_workspace.collectors import GoogleAlertCenterCollector

    result = GoogleAlertCenterCollector().run({"client": client})
    stored = json.dumps(result.payload, default=str)
    assert marker not in stored
    stored_alert = result.payload["alerts"]["value"][0]
    assert stored_alert["metadata"] == {"severity": "HIGH", "status": "NOT_STARTED"}
    assert "data" not in stored_alert


def test_group_settings_fields_cover_every_setting_the_normaliser_reads() -> None:
    from types import SimpleNamespace

    from auditex.google_workspace.client import GROUP_SETTING_FIELDS, GoogleWorkspaceClient

    source = (REPO_ROOT / "src/auditex/google_workspace/normalize.py").read_text(encoding="utf-8")
    block = source.split('"google_groups_settings.groupSettings"', 1)[1].split("for item in _values", 1)[0]
    read = set(re.findall(r'item\.get\("(\w+)"\)', block))
    assert len(read) == 7
    requested = set(GROUP_SETTING_FIELDS.split(","))
    assert read == requested
    assert not requested & {"customFooterText", "defaultMessageDenyNotificationText"}

    seen: dict[str, Any] = {}

    def _get(**kwargs: Any) -> Any:
        seen.update(kwargs)
        return SimpleNamespace(execute=lambda: {"email": kwargs["groupUniqueId"]})

    client = GoogleWorkspaceClient(credentials=None)
    client._services[("groupssettings", "v1")] = SimpleNamespace(groups=lambda: SimpleNamespace(get=_get))
    client.get_group_settings("g@example.test")
    assert seen["fields"] == GROUP_SETTING_FIELDS
