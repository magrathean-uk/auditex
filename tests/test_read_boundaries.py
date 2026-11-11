"""Static proof of the three read boundaries: content reads, commands and Google calls.

* Content: the ``api_inventory`` content classifier runs over every endpoint in
  ``configs/collector-definitions.json`` and every endpoint literal under ``collectors/`` and ``adapters/``.
* Commands: every executable command site (a string that reaches a process or runner call, traced through
  the source) in ``src/`` and every command field in ``configs/`` is split into trusted
  wrapper operations (a closed table keyed by file and purpose) and audited commands, which must be on the
  ``api_inventory`` read allow-list. Every m365 CLI command the collectors can issue passes the read guard.
  Process launches are found by import origin, in ``subprocess`` and outside it (``os``, ``pty``, ``asyncio``),
  through every binding of an alias, a re-export by another source module, ``getattr``, an import or
  ``sys.modules`` by literal name, and a ``**mapping`` of options; a launcher the scan cannot follow (kept in a
  container, attribute or parameter, reached by a computed name, code run from text) is in a closed reviewed
  table (DEC-011 L1, L2).
* Google: every API method called under ``src/auditex/google_workspace/`` is a read, and every requested
  scope is read-only, metadata-only or a write-capable scope in the closed accepted-exception table (DEC-010),
  with its blast radius, used only for list and get calls. Handles are resolved per Python scope, ``getattr``
  with a literal name is followed, and a service or handle that leaves the traced names fails (DEC-011 L3, L4).

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
from azure_tenant_audit.adapters.m365dsc import (
    COMPATIBILITY_SCRIPT,
    MINIMUM_MODULE_VERSION,
    M365DSCAdapter,
)
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
_LITERAL_FSTRINGS = (
    "command text is f-strings over literals only: cmdlet names and Select-Object property tuples "
    "(exchange_defender_commands._listing) and a numeric row limit (MAILBOX_FORWARDING_COMMAND); every literal "
    "part and field value is scanned as a site of its own"
)
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
    ("src/azure_tenant_audit/collectors/exchange_policy.py", "ExchangePolicyCollector.run"): _LITERAL_FSTRINGS,
    ("src/azure_tenant_audit/collectors/exchange_policy.py", "_run_anti_phish"): _LITERAL_FSTRINGS,
    ("src/azure_tenant_audit/collectors/purview.py", "PurviewCollector._run_command"): (
        "commands are the literal command_collectors variants, each scanned; the variant list is also handed inside "
        "a payload to the export-summary hook, which only writes it as JSON (AuditWriter.write_export_summary)"
    ),
    ("src/azure_tenant_audit/evidence_db.py", "_encrypted_internal_storage"): _RUNTIME_ARGV,
    ("src/azure_tenant_audit/probe.py", "_subprocess_probe"): _CALLER_ARGV,
    ("src/azure_tenant_audit/response.py", "run_response"): (
        "lab-only response actions behind AUDITEX_ENABLE_RESPONSE; the RESPONSE_ACTIONS templates are scanned"
    ),
}

# Closed: sites where a launcher or the module that holds one is reached in a way the scan cannot follow (a
# dynamic import or attribute, or a launcher kept in a container, attribute or parameter), each with why that is
# safe. A new one fails the scan until it is made a direct call or reviewed into this table (DEC-011 L2).
_UNTRACEABLE_LAUNCHES: dict[tuple[str, str], str] = {
    ("src/azure_tenant_audit/value_rules/__init__.py", "_registry"): (
        "imports each value_rules submodule found by pkgutil under this package and reads only its KINDS dict"
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
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


def _evaluated_outside(scope: ast.AST, child: ast.AST, grandchild: ast.AST | None) -> bool:
    """True when ``child`` (the child of ``scope`` on the way down to a node) is evaluated in the enclosing scope:
    a function's defaults, annotations, return annotation and decorators, a lambda's defaults, a class's bases,
    keywords and decorators, and a comprehension's first iterable."""
    if isinstance(scope, _FUNCTION_NODES):
        return child is scope.args or child is scope.returns or any(child is item for item in scope.decorator_list)
    if isinstance(scope, ast.Lambda):
        return child is scope.args
    if isinstance(scope, ast.ClassDef):
        return any(child is item for item in (*scope.bases, *scope.keywords, *scope.decorator_list))
    if isinstance(scope, _COMPREHENSIONS):
        return child is scope.generators[0] and grandchild is scope.generators[0].iter
    return False


def _enclosing(node: ast.AST, parents: dict[ast.AST, ast.AST], kinds: tuple[type, ...]) -> ast.AST | None:
    """The innermost ``kinds`` node whose scope evaluates ``node``, or None for the module."""
    grandchild, child, current = None, node, parents.get(node)
    while current is not None:
        if isinstance(current, kinds) and not _evaluated_outside(current, child, grandchild):
            return current
        grandchild, child, current = child, current, parents.get(current)
    return None
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
        self.by_name: dict[str, list[tuple[ast.AST, tuple[Any, ...]]]] = {}  # every non-class binding, any scope
        # name -> [(scope, dotted origin)] for every import statement that binds it, in any scope; unlike
        # ``imports`` and ``module_aliases`` a later import of the same name does not hide an earlier one.
        self.import_origins: dict[str, list[tuple[ast.AST | None, str]]] = {}
        self._mutated: tuple[set[tuple[ast.AST | None, str]], set[str]] | None = None
        self._grown: set[int] = set()  # values bound by ``append``/``insert``/``extend``, not a binding of the name
        # (function or class, name) -> ast.Global or ast.Nonlocal: where that body's bindings of the name land.
        self.declared: dict[tuple[ast.AST, str], type] = {}
        self._own_names: dict[ast.AST | None, set[str]] | None = None
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.Global, ast.Nonlocal)):
                block = _enclosing(node, self.parents, (*_FUNCTION_NODES, ast.ClassDef))
                if block is not None:  # a module-level ``global`` changes nothing
                    self.declared.update({(block, name): type(node) for name in node.names})
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        self.module_aliases[alias.asname] = alias.name
                    else:
                        head = alias.name.split(".", 1)[0]
                        self.module_aliases[head] = head
                    bound = alias.asname or alias.name.split(".", 1)[0]
                    origin = alias.name if alias.asname else bound
                    self.import_origins.setdefault(bound, []).append((self._import_scope(node, alias, bound), origin))
            if isinstance(node, (*_FUNCTION_NODES, ast.ClassDef, ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
                self._declared_binding(node, node.name, node)
            elif isinstance(node, ast.MatchMapping):
                self._declared_binding(node, node.rest, node)
            elif isinstance(node, ast.withitem) and node.optional_vars is not None:
                for target in ast.walk(node.optional_vars):
                    if isinstance(target, ast.Name):
                        self._declared_binding(node, target.id, node)
            if isinstance(node, _FUNCTION_NODES):
                self.functions.setdefault(node.name, []).append(node)
            elif isinstance(node, ast.Call) and (name := _callee_name(node)):
                self.calls.setdefault(name, []).append(node)
                func = node.func
                if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and node.args:
                    # ``rows.append(x)`` and ``rows.extend(xs)`` add to what ``rows`` holds.
                    if name in {"append", "insert"}:
                        grown = ast.List(elts=[node.args[-1]], ctx=ast.Load())
                        self._grown.add(id(grown))
                        self._bind(node, func.value, grown, ())
                    elif name == "extend":
                        self._grown.add(id(node.args[0]))
                        self._bind(node, func.value, node.args[0], ())
            elif isinstance(node, ast.ImportFrom):
                base = self._import_base(node)
                for alias in node.names:
                    if base is not None:
                        self.imports[alias.asname or alias.name] = (base, alias.name)
                        if alias.name != "*":
                            self.import_origins.setdefault(alias.asname or alias.name, []).append(
                                (self._import_scope(node, alias, alias.asname or alias.name), f"{base}.{alias.name}")
                            )
                    elif alias.name != "*":
                        self._import_scope(node, alias, alias.asname or alias.name)
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
        """The function, lambda or comprehension whose scope evaluates ``node`` (a default value or decorator
        belongs to the enclosing one), or None for the module."""
        return _enclosing(node, self.parents, _SCOPE_NODES)

    def _in_class_body(self, node: ast.AST) -> bool:
        return isinstance(_enclosing(node, self.parents, (*_SCOPE_NODES, ast.ClassDef)), ast.ClassDef)

    def _redirect(self, block: ast.AST | None, name: str) -> tuple[bool, ast.AST | None]:
        """``(True, scope)`` when ``block`` (a function or class body) declares ``name`` ``global`` (the module,
        None) or ``nonlocal`` (the nearest enclosing function that binds it), else ``(False, block)``."""
        kind = self.declared.get((block, name)) if block is not None else None
        if kind is ast.Global:
            return True, None
        if kind is ast.Nonlocal:
            outer = block
            while (outer := _enclosing(outer, self.parents, _FUNCTION_NODES)) is not None:
                if self.declared.get((outer, name)) is ast.Global:
                    return True, None
                if (outer, name) not in self.declared and name in self.own_names(outer):
                    return True, outer
            return True, None
        return False, block

    def _declared(self, node: ast.AST, name: str) -> tuple[bool, ast.AST | None]:
        """Where a binding of ``name`` made at ``node`` lands if the body it is in declares the name ``global`` or
        ``nonlocal``; a walrus in a comprehension binds in the body around the comprehension (PEP 572)."""
        block = _enclosing(node, self.parents, (*_SCOPE_NODES, ast.ClassDef))
        if isinstance(node, ast.NamedExpr):
            while isinstance(block, _COMPREHENSIONS):
                block = _enclosing(block, self.parents, (*_SCOPE_NODES, ast.ClassDef))
        return self._redirect(block, name)

    def _declared_binding(self, node: ast.AST, name: str | None, value: ast.AST) -> None:
        """A binding the scan does not model as a value (a ``def``, ``class``, ``with`` or ``except`` target, a
        ``match`` capture, an import) joins the binding union of the scope a ``global`` or ``nonlocal``
        declaration sends it to; ``value`` stands for it there (``_Resolver`` follows an imported name and
        counts any other as unresolved)."""
        if name is None:
            return
        declared, scope = self._declared(node, name)
        if declared:
            self.bindings.setdefault((scope, name), []).append((value, ()))
            self.by_name.setdefault(name, []).append((value, ()))

    def _import_scope(self, node: ast.AST, alias: ast.alias, name: str) -> ast.AST | None:
        declared, scope = self._declared(node, name)
        if declared:
            self._declared_binding(node, name, alias)
            return scope
        return self.scope_of(node)

    def own_names(self, block: ast.AST | None) -> set[str]:
        """Every name ``block`` (a function, lambda, comprehension or class, None for the module) binds itself, in
        any form, parameters included, whatever it declares."""
        if self._own_names is None:
            self._own_names = {}
            kinds = (*_SCOPE_NODES, ast.ClassDef)
            for node in ast.walk(self.tree):
                if isinstance(node, ast.arg):
                    self._own_names.setdefault(self.parents[self.parents[node]], set()).add(node.arg)
                    continue
                if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
                    names = [node.id]
                    walrus = self.parents.get(node)
                    where = walrus if isinstance(walrus, ast.NamedExpr) and walrus.target is node else node
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    names, where = [(a.asname or a.name).split(".", 1)[0] for a in node.names if a.name != "*"], node
                elif isinstance(node, (*_FUNCTION_NODES, ast.ClassDef, ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
                    names, where = [node.name] if node.name else [], node
                elif isinstance(node, ast.MatchMapping):
                    names, where = [node.rest] if node.rest else [], node
                else:
                    continue
                block_of = _enclosing(where, self.parents, kinds)
                if isinstance(where, ast.NamedExpr):
                    while isinstance(block_of, _COMPREHENSIONS):
                        block_of = _enclosing(block_of, self.parents, kinds)
                self._own_names.setdefault(block_of, set()).update(names)
        return self._own_names.get(block, set())

    def lookup(self, node: ast.AST, name: str) -> Iterator[ast.AST | None]:
        """The scopes whose bindings a use of ``name`` at ``node`` reads, innermost first, ending at the module
        (None). A ``global`` declaration in the function or class body around the use, or in a function on the
        way out, goes to the module; a ``nonlocal`` one to the function that binds the name."""
        declared, scope = self._redirect(_enclosing(node, self.parents, (*_SCOPE_NODES, ast.ClassDef)), name)
        if not declared:
            scope = self.scope_of(node)
        while True:
            yield scope
            if scope is None:
                return
            declared, outer = self._redirect(self.scope_of(scope), name)
            scope = outer if declared else self.scope_of(scope)

    def at_module_level(self, function: ast.AST) -> bool:
        """``function`` is bound at module scope (importable): defined there, or declared ``global``."""
        return isinstance(self.parents.get(function), ast.Module) or self._declared(function, function.name) == (True, None)

    def _bind(self, owner: ast.AST, target: ast.AST, value: ast.AST, path: tuple[Any, ...]) -> None:
        if isinstance(target, (ast.Tuple, ast.List)):
            if not path and isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == len(target.elts):
                for item_target, item_value in zip(target.elts, value.elts, strict=False):
                    self._bind(owner, item_target, item_value, ())
                return
            for index, item_target in enumerate(target.elts):
                self._bind(owner, item_target, value, (*path, index))
            return
        if isinstance(target, ast.Starred):
            self._bind(owner, target.value, value, (*path, "rest"))
        elif isinstance(target, ast.Name):
            # A ``global`` or ``nonlocal`` declaration sends the binding to the module or an enclosing function.
            declared, scope = self._declared(owner, target.id)
            if not declared and self._in_class_body(owner):
                self.attributes.setdefault(target.id, []).append((value, path))
                return
            if not declared:
                # A comprehension's targets belong to the comprehension; anything else to its enclosing scope.
                scope = self.parents.get(owner) if isinstance(owner, ast.comprehension) else self.scope_of(owner)
            self.bindings.setdefault((scope, target.id), []).append((value, path))
            self.by_name.setdefault(target.id, []).append((value, path))
        elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id in {"self", "cls"}:
            self.attributes.setdefault(target.attr, []).append((value, path))

    def binding_scope(self, node: ast.AST, name: str) -> ast.AST | None:
        """The scope whose binding of ``name`` a use at ``node`` reads (the same walk as ``_Resolver._name``);
        None for the module, an import or an unbound name."""
        for scope in self.lookup(node, name):
            if scope is None:
                break
            if any(id(value) not in self._grown for value, _ in self.bindings.get((scope, name), [])) or (
                isinstance(scope, (*_FUNCTION_NODES, ast.Lambda)) and name in _parameter_names(scope)
            ):
                return scope
        return None

    def mutations(self) -> tuple[set[tuple[ast.AST | None, str]], set[str]]:
        """``(names, attributes)`` whose value may change after it is bound: names as ``(binding scope, name)``,
        ``self``/class attributes by name. A change is a subscript or attribute assigned or deleted through it, an
        augmented assignment, ``del``, a mutating method called on it (``update``, ``append``, ``__setitem__`` ...),
        or the value handed to a call that may keep or change it.

        The mark spreads back to what shares the changed object: a plain alias (``b = a``), the container an
        element came from (``b = a[0]``, ``for b in a``), either branch, and what a function of this module
        returns. A change inside the object (``a[0].append(x)``, a call that may do anything) also reaches the
        names a literal container holds (``a = [b]``). A value that resolves only to strings, bytes, numbers or
        None cannot be changed through another name and is not marked when it is passed or aliased."""
        if self._mutated is not None:
            return self._mutated
        names: set[tuple[ast.AST | None, str]] = set()
        attributes: set[str] = set()
        deep: set[tuple[str, Any]] = set()  # changed inside, not only at the top
        self._mutated = (names, attributes)  # partial while computing: a re-entry from a callee sees what is known
        classes = {node.name for node in self.tree.body if isinstance(node, ast.ClassDef)}
        held: dict[int, bool] = {}

        def key(expr: ast.AST) -> tuple[str, Any] | None:
            root = _root(expr, classes)
            if root is None:
                return None
            if isinstance(root, str):
                return ("attribute", root)
            return ("name", (self.binding_scope(root, root.id), root.id))

        def levels(expr: ast.AST) -> int:
            """Subscripts and attributes between ``expr`` and what ``key`` names."""
            count = 0
            while isinstance(expr, (ast.Subscript, ast.Attribute, ast.Starred)):
                if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name) and (
                    expr.value.id in {"self", "cls"} or expr.value.id in classes
                ):
                    return count
                count += not isinstance(expr, ast.Starred)
                expr = expr.value
            return count

        def mutable(expr: ast.AST) -> bool:
            """``expr`` may hold a container: what it resolves to is not all strings, bytes, numbers and None."""
            if id(expr) not in held:
                values, complete = _MUTABILITY.values(self, expr)
                held[id(expr)] = not complete or not all(_immutable(node) for _, node in values)
            return held[id(expr)]

        def mark(expr: ast.AST, inside: bool, *, only_mutable: bool = False) -> None:
            found = key(expr)
            if found is None or (only_mutable and not mutable(expr)):
                return
            (attributes if found[0] == "attribute" else names).add(found[1])
            if inside or levels(expr):
                deep.add(found)

        # What each change reaches: ``(object changed, inside it)``.
        changes: list[tuple[ast.AST, bool]] = []
        calls: list[ast.Call] = []
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.Subscript, ast.Attribute)) and isinstance(node.ctx, (ast.Store, ast.Del)):
                if not (isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store)
                        and isinstance(node.value, ast.Name) and node.value.id in {"self", "cls"}):
                    changes.append((node.value if levels(node) else node, False))  # ``self.x = v`` alone binds ``x``
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Del):
                changes.append((node, False))
            elif isinstance(node, ast.AugAssign):
                changes.append((node.target, False))
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr in _MUTATING_METHODS:
                    changes.append((node.func.value, False))
                if node.args or node.keywords:
                    calls.append(node)

        # Calls that may keep or change a container passed to them: all but a read-only builtin or formatter, a
        # launch (judged on what it is given) and a source function, of this module or imported by name, whose
        # parameters stay unchanged in its own module.
        handed: list[tuple[_Module, list[ast.AST] | None, list[ast.AST]]] = []
        for call in calls:
            callee = _callee_name(call)
            receiver = call.func.value if isinstance(call.func, ast.Attribute) else None
            if callee in _READ_ONLY_CALLS or callee in _LOOP_LAUNCHERS or (
                callee == "run" and not (isinstance(receiver, ast.Name) and receiver.id in _NON_RUNNER_RECEIVERS)
            ):
                continue
            if any(_is_launcher(origin) for origin in _origins(self, call.func)):
                continue
            own = isinstance(call.func, ast.Name) or (isinstance(receiver, ast.Name) and receiver.id in {"self", "cls"})
            owner, local = self, self.functions.get(callee) if own else None
            if local is None and isinstance(call.func, ast.Name) and callee in self.imports:
                target, imported = self.imports[callee]
                other = _load_module(target)
                if other is not None and imported in other.functions:
                    owner, local = other, other.functions[imported]
            handed.append((owner, local, [*call.args, *(kw.value for kw in call.keywords)]))

        def keeps_parameters(owner: _Module, functions: list[ast.AST]) -> bool:
            changed = names if owner is self else owner.mutations()[0]
            return not any(
                function.args.vararg or function.args.kwarg
                or any((function, parameter) in changed for parameter in _parameter_names(function) - {"self", "cls"})
                for function in functions
            )

        def spread(value: ast.AST, inside: bool, seen: set[int]) -> None:
            """Mark what ``value`` shares with a name bound to it that was changed (``inside``: changed within)."""
            if isinstance(value, ast.Name):
                mark(value, inside, only_mutable=True)
            elif isinstance(value, (ast.Attribute, ast.Subscript, ast.Starred)):
                if key(value) is not None:
                    mark(value, True, only_mutable=True)  # an element or attribute of it changed
                else:
                    spread(value.value, True, seen)  # ``shared()[0]``, ``(a or b).x``
            elif isinstance(value, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
                if inside:
                    for part in value.values if isinstance(value, ast.Dict) else value.elts:
                        spread(part, True, seen)
            elif isinstance(value, ast.IfExp):
                spread(value.body, inside, seen)
                spread(value.orelse, inside, seen)
            elif isinstance(value, ast.BoolOp):
                for part in value.values:
                    spread(part, inside, seen)
            elif isinstance(value, (ast.NamedExpr, ast.Await)):
                spread(value.value, inside, seen)
            elif isinstance(value, ast.Call) and (callee := _callee_name(value)) in self.functions:
                for function in self.functions[callee]:
                    if id(function) not in seen:
                        seen.add(id(function))
                        for ret in ast.walk(function):
                            if isinstance(ret, ast.Return) and ret.value is not None:
                                spread(ret.value, inside, seen)

        def defaults(function: ast.AST) -> dict[str, ast.AST]:
            positional = [arg.arg for arg in (*function.args.posonlyargs, *function.args.args)]
            found = dict(zip(reversed(positional), reversed(function.args.defaults), strict=False))
            found.update({
                arg.arg: value for arg, value in zip(function.args.kwonlyargs, function.args.kw_defaults, strict=False) if value
            })
            return found

        for changed, inside in changes:
            if key(changed) is not None:
                mark(changed, inside or bool(levels(changed)))
            else:
                spread(changed, inside, set())  # ``(alias := ARGV).append(x)``, ``(a or b)[0] = x``, ``shared().pop()``
        while True:
            size = len(names) + len(attributes) + len(deep)
            for scope, name in list(names):
                inside = ("name", (scope, name)) in deep
                for value, path in self.bindings.get((scope, name), []):
                    spread(value, bool(path) or inside, set())
                if isinstance(scope, (*_FUNCTION_NODES, ast.Lambda)) and name in defaults(scope):
                    spread(defaults(scope)[name], inside, set())  # ``def f(argv=ARGV)`` changing ``argv``
            for attribute in list(attributes):
                for value, path in self.attributes.get(attribute, []):
                    spread(value, bool(path) or ("attribute", attribute) in deep, set())
            for owner, local, given in handed:
                if not (local and keeps_parameters(owner, local)):
                    for argument in given:
                        spread(argument, True, set())
            if len(names) + len(attributes) + len(deep) == size:
                return self._mutated


# Methods that change the container they are called on.
_MUTATING_METHODS = frozenset({
    "update", "setdefault", "pop", "popitem", "append", "extend", "insert", "clear", "remove", "sort", "reverse",
    "add", "discard", "difference_update", "intersection_update", "symmetric_difference_update", "__setitem__",
    "__delitem__", "__iadd__", "__ior__", "__imul__",
})
# Calls that read an argument without keeping or changing it.
_READ_ONLY_CALLS = frozenset({
    "len", "str", "repr", "print", "list", "tuple", "sorted", "set", "frozenset", "dict", "any", "all", "isinstance",
    "bool", "int", "float", "enumerate", "zip", "iter", "reversed", "min", "max", "sum", "hash", "id", "type", "join",
    "dumps", "quote", "format", "debug", "info", "warning", "error", "exception", "critical",
    "graph_url", "VettedCommand",
})


def _root(expr: ast.AST, classes: set[str]) -> ast.Name | str | None:
    """What a change through ``expr`` changes: the name node for ``n``, ``n[k]``, ``n.a`` or ``*n``; the attribute
    name for ``self.a``, ``cls.a`` or ``C.a`` of a class in the module, and what hangs off them."""
    while isinstance(expr, (ast.Subscript, ast.Attribute, ast.Starred)):
        if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name) and (
            expr.value.id in {"self", "cls"} or expr.value.id in classes
        ):
            return expr.attr
        expr = expr.value
    return expr if isinstance(expr, ast.Name) and expr.id not in {"self", "cls"} else None


def _immutable(value: ast.AST) -> bool:
    """A literal that no later change can reach: a string, bytes, number or None, an f-string or a ``+`` join."""
    return isinstance(value, (ast.Constant, ast.JoinedStr, ast.BinOp))


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

    A ``strict`` resolver (the one for launches) also counts as unresolved a name or ``self`` attribute whose value
    may change after it is bound (``_Module.mutations``) and a string built by a method (``join``, ``format``,
    ``replace`` ...): only ``lower``, ``upper`` and a bare ``strip`` keep the text a scan of the parts would see.
    """

    def __init__(self, *, strict: bool = False, budget: int | None = None) -> None:
        self.strict = strict
        self.budget = budget  # steps per top-level query; past it a value is unresolved (and not memoised)
        self._spent = 0
        self._memo: dict[tuple[_Module, ast.AST], tuple[list[Value], bool]] = {}  # keys hold the objects
        self._active: set[tuple[_Module, ast.AST]] = set()
        self._cycles = 0

    def values(self, module: _Module, expr: ast.AST, depth: int = 0) -> tuple[list[Value], bool]:
        """Memoised per expression. A re-entered expression (a binding cycle) adds nothing new on that path;
        a result computed across a cycle or at the depth limit is not memoised, so it cannot be reused short."""
        if self.budget is not None:
            self._spent = 0 if depth == 0 else self._spent + 1
            if self._spent > self.budget:
                self._cycles += 1
                return [], False
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
                found, complete = self._bound(module, module.attributes.get(expr.attr, []), depth)
                return found, complete and not (self.strict and expr.attr in module.mutations()[1])
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
        if isinstance(expr, ast.alias):
            # ``from base import name`` sent to another scope by a declaration: what ``base`` binds ``name`` to.
            statement = module.parents.get(expr)
            base = module._import_base(statement) if isinstance(statement, ast.ImportFrom) else None
            other = _load_module(base) if base else None
            if other is None:
                return [], False
            found, complete = self._bound(other, other.bindings.get((None, expr.name), []), depth)
            return found, complete and not (self.strict and (None, expr.name) in other.mutations()[0])
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
        grown: list[tuple[ast.AST, tuple[Any, ...]]] = []  # ``x.append(v)`` in a scope that does not bind ``x``
        for scope in module.lookup(expr, expr.id):
            bound = module.bindings.get((scope, expr.id), [])
            parameter = isinstance(scope, (*_FUNCTION_NODES, ast.Lambda)) and expr.id in _parameter_names(scope)
            if not parameter and all(id(value) in module._grown for value, _ in bound):
                grown += bound
                bound = []
            if bound or parameter:
                bound = bound + grown
                found, complete = self._bound(module, bound, depth) if bound else ([], True)
                if parameter:
                    values, ok = self._arguments(module, scope, expr.id, depth)
                    found += values
                    complete &= ok
                return found, complete and not (self.strict and (scope, expr.id) in module.mutations()[0])
        if expr.id in module.imports:
            target, name = module.imports[expr.id]
            other = _load_module(target)
            if other is not None:
                found, complete = self._bound(other, other.bindings.get((None, name), []), depth)
                found += self._bound(module, grown, depth)[0]
                mutated = self.strict and ((None, name) in other.mutations()[0] or (None, expr.id) in module.mutations()[0])
                return found, complete and not mutated
        return (self._bound(module, grown, depth)[0] if grown else []), False

    def _arguments(self, module: _Module, function: ast.AST, name: str, depth: int) -> tuple[list[Value], bool]:
        """Values passed for parameter ``name`` at every call of ``function`` in the same module."""
        if isinstance(function, ast.Lambda) or function.args.vararg or function.args.kwarg:
            return [], False
        positional = [arg.arg for arg in (*function.args.posonlyargs, *function.args.args)]
        method = bool(positional) and positional[0] in {"self", "cls"} and isinstance(
            module.parents.get(function), ast.ClassDef
        )
        defaults = dict(zip(reversed(positional), reversed(function.args.defaults), strict=False))
        defaults.update({arg.arg: value for arg, value in zip(function.args.kwonlyargs, function.args.kw_defaults, strict=False) if value})
        calls = [(module, call) for call in module.calls.get(function.name, [])]
        if module.at_module_level(function) and module.dotted:
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
                chosen = [v for k, v in zip(node.keys, node.values, strict=False) if key is None or (isinstance(k, ast.Constant) and k.value == key)]
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
            if self.strict and not (name in {"lower", "upper"} or (name == "strip" and not call.args)):
                found, _ = self._union(module, [call.func.value, *call.args, *(kw.value for kw in call.keywords)], depth)
                return found, False  # the parts are still scanned; the text they make is not known
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
# Launch inputs, importer names and standard input: a value counts only when the scan proves it literal.
_STRICT = _Resolver(strict=True)
# Whether a value handed to a call may be a container: bounded, so a deep or cyclic trace counts as one.
_MUTABILITY = _Resolver(budget=400)


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
        for key, value in zip(node.keys, node.values, strict=False):
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
                for key, value in zip(node.keys, node.values, strict=False)
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
# A host's script flag: ``-Command`` and every abbreviation PowerShell accepts (``-c``, ``-Com``), ``bash -c``,
# ``cmd /c``.
_HOST_SCRIPT_FLAG = re.compile(r"^(?:-c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?|/c)$", re.IGNORECASE)

CommandSite = tuple[str, str, int, str]


def _literal_argument(call: ast.Call, index: int) -> str | None:
    if len(call.args) > index and isinstance(call.args[index], ast.Constant) and isinstance(call.args[index].value, str):
        return call.args[index].value
    return None


def _is_getattr(node: ast.AST | None) -> bool:
    return (
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr" and len(node.args) >= 2
    )


def _module_name_argument(call: ast.Call) -> ast.AST | None:
    """The module-name argument of ``importlib.import_module``, ``__import__`` or ``importlib.__import__``, given
    by position or as ``name=``; None when the call has arguments the scan does not model (``*args``,
    ``**options``, an unknown keyword, or a relative import through ``package=`` or a non-zero ``level``)."""
    if any(isinstance(arg, ast.Starred) for arg in call.args) or any(kw.arg is None for kw in call.keywords):
        return None
    keywords = {kw.arg: kw.value for kw in call.keywords}
    if set(keywords) - {"name", "package", "globals", "locals", "fromlist", "level"}:
        return None
    level = call.args[4] if len(call.args) > 4 else keywords.get("level")
    if level is not None and not (isinstance(level, ast.Constant) and level.value == 0):
        return None
    given = call.args[0] if call.args else keywords.get("name")
    if isinstance(given, ast.Constant) and isinstance(given.value, str) and given.value.startswith("."):
        return None
    return given


def _literal_module_name(call: ast.Call) -> str | None:
    given = _module_name_argument(call)
    return given.value if isinstance(given, ast.Constant) and isinstance(given.value, str) else None


# Builtins that reach a module, an attribute, a namespace or code by a name or text the source may compute.
_DYNAMIC_BUILTINS = frozenset({"getattr", "__import__", "eval", "exec", "compile", "globals", "locals", "vars"})
# Callables that import a module by a name given as a string.
_IMPORTERS_BY_NAME = frozenset({"importlib.import_module", "importlib.__import__", "builtins.__import__"})
# Callables that load or run a module by a path, a spec or a ``module:attribute`` text; none is followed, each is
# reported wherever it appears.
_MODULE_LOADERS = frozenset({
    "pkgutil.resolve_name", "runpy.run_module", "runpy.run_path", "importlib.reload",
    "importlib.util.module_from_spec", "importlib.machinery.SourceFileLoader", "zipimport.zipimporter",
})
_ORIGIN_NODES = (ast.Name, ast.Attribute, ast.Call, ast.Subscript)
# ``os`` re-exports the platform module; ``posix.system`` is ``os.system``.
_OS_PLATFORM_MODULES = frozenset({"posix", "nt"})


def _canonical(origin: str, depth: int, active: frozenset[tuple[int, str]]) -> set[str]:
    """``origin`` with a platform module read as ``os`` and a name re-exported by a source module followed to
    what that module binds it to at module level (``from helpers import launch`` where ``helpers`` has
    ``launch = subprocess.run`` or ``from subprocess import run as launch``)."""
    head, _, rest = origin.partition(".")
    if head in _OS_PLATFORM_MODULES:
        origin = f"os.{rest}" if rest else "os"
    parts = origin.split(".")
    for cut in range(len(parts) - 1, 0, -1):
        other = _load_module(".".join(parts[:cut]))
        if other is None:
            continue
        name, tail = parts[cut], ".".join(parts[cut + 1 :])
        key = (id(other), name)
        if key in active or depth > _MAX_DEPTH:
            return set()
        found: set[str] = set()
        for scope, imported in other.import_origins.get(name, []):
            if scope is None:
                found |= _canonical(imported, depth + 1, active | {key})
        for value, path in other.bindings.get((None, name), []):
            if not path and isinstance(value, _ORIGIN_NODES):
                found |= _origins(other, value, depth + 1, active | {key})
        if not found:
            return {origin}
        return {item for base in found for item in _canonical(f"{base}.{tail}" if tail else base, depth + 1, active)}
    return {origin}


def _origins(
    module: _Module, expr: ast.AST, depth: int = 0, active: frozenset[tuple[int, str]] = frozenset()
) -> set[str]:
    """Every dotted origin an expression can have through ``import x as y``, ``from x import y as z``, plain
    assignments (``launch = sp.run``), ``getattr(x, "name")``, ``importlib.import_module("x")``, ``__import__("x")``
    and ``sys.modules["x"]`` with a literal name, and names re-exported by another source module.

    Every binding of a name counts, in any scope and whatever order they come in: ``launch = json.loads`` then
    ``launch = getattr(subprocess, "Popen")`` gives both origins, and a later import of a name does not hide an
    earlier one. An unbound name that is a dynamic builtin (``getattr``, ``__import__``, ``eval`` ...) has origin
    ``builtins.<name>``. Empty when nothing comes from an import."""
    if depth > _MAX_DEPTH:
        return set()
    if isinstance(expr, ast.Attribute):
        bases = _origins(module, expr.value, depth + 1, active)
        return {item for base in bases for item in _canonical(f"{base}.{expr.attr}", depth + 1, active)}
    if isinstance(expr, ast.Subscript):
        key = expr.slice.value if isinstance(expr.slice, ast.Constant) else None
        if isinstance(key, str) and "sys.modules" in _origins(module, expr.value, depth + 1, active):
            return _canonical(key, depth + 1, active)
        return set()
    if isinstance(expr, ast.Call):
        if _is_getattr(expr) and (attribute := _literal_argument(expr, 1)) is not None:
            bases = _origins(module, expr.args[0], depth + 1, active)
            return {item for base in bases for item in _canonical(f"{base}.{attribute}", depth + 1, active)}
        callee = _origins(module, expr.func, depth + 1, active)
        if "sys.modules.get" in callee and (imported := _literal_argument(expr, 0)) is not None:
            return _canonical(imported, depth + 1, active)
        if not callee & _IMPORTERS_BY_NAME or (imported := _literal_module_name(expr)) is None:
            return set()
        found = _canonical(imported, depth + 1, active) if "importlib.import_module" in callee else set()
        if callee & {"importlib.__import__", "builtins.__import__"}:
            found |= _canonical(imported.split(".", 1)[0], depth + 1, active)
        return found
    if not isinstance(expr, ast.Name):
        return set()
    key = (id(module), expr.id)
    if key in active:
        return set()
    active = active | {key}
    found: set[str] = set()
    for _, imported in module.import_origins.get(expr.id, []):
        found |= _canonical(imported, depth + 1, active)
    bound = module.by_name.get(expr.id, [])
    for value, path in bound:
        if not path and isinstance(value, _ORIGIN_NODES):
            found |= _origins(module, value, depth + 1, active)
    if not found and not bound and expr.id in _DYNAMIC_BUILTINS and expr.id not in module.functions:
        found.add(f"builtins.{expr.id}")
    return found


def _launcher_table() -> dict[str, tuple[int, int | None]]:
    """Process launchers outside ``subprocess`` (DEC-011 L1) by import origin, with the slice of positional
    arguments that carry the program, argv or shell text (a spawn mode or an environment mapping is skipped)."""
    table: dict[str, tuple[int, int | None]] = {
        "os.system": (0, 1), "os.popen": (0, 1), "os.startfile": (0, None), "os.posix_spawn": (0, 2),
        "os.posix_spawnp": (0, 2), "pty.spawn": (0, 1),
    }
    for prefix in ("asyncio.", "asyncio.subprocess."):
        table[f"{prefix}create_subprocess_exec"] = (0, None)
        table[f"{prefix}create_subprocess_shell"] = (0, 1)
    for family, start in (("exec", 0), ("spawn", 1)):
        for suffix in ("l", "lp", "le", "lpe", "v", "vp", "ve", "vpe"):
            if suffix.startswith("l"):
                table[f"os.{family}{suffix}"] = (start, -1 if suffix.endswith("e") else None)
            else:
                table[f"os.{family}{suffix}"] = (start, start + 2)
    return table


_OS_LAUNCHERS = _launcher_table()
# Event-loop launchers, matched by method name because the loop is a runtime object.
_LOOP_LAUNCHERS: dict[str, tuple[int, int | None]] = {"subprocess_exec": (1, None), "subprocess_shell": (1, 2)}
# Keywords of a launch that carry no program, argv, script or standard-input text. Every other keyword, a ``**``
# mapping's other keys and an unknown keyword included, is scanned, so text the scan cannot see leaves it unresolved.
_LAUNCH_OPTIONS = frozenset({
    "check", "capture_output", "text", "universal_newlines", "timeout", "env", "cwd", "stdin", "stdout", "stderr",
    "shell", "encoding", "errors", "bufsize", "close_fds", "pass_fds", "start_new_session", "process_group",
    "creationflags", "startupinfo", "restore_signals", "preexec_fn", "user", "group", "extra_groups", "umask",
    "pipesize", "limit", "file_actions", "setpgroup", "resetids", "setsid", "setsigmask", "setsigdef", "scheduler",
})
# Keywords of an adapter's ``run`` other than its command: the event logger, the Exchange session the adapter's own
# trusted prelude connects with, and a response transform. Pinned to the adapters' signatures by a test.
_RUNNER_OPTIONS = frozenset({"log_event", "session", "response_transform"})
# Modules whose attributes include a launcher: reached dynamically or passed on as a value, they hide the launch.
_LAUNCHER_MODULES = frozenset({"subprocess", "os", "pty", "asyncio", "asyncio.subprocess"})


def _is_launcher(origin: str | None) -> bool:
    if origin is None:
        return False
    if origin.startswith("subprocess."):
        return origin.removeprefix("subprocess.") in _PROCESS_CALLS
    return origin in _OS_LAUNCHERS


def _unpacked(module: _Module, expr: ast.AST, options: frozenset[str] = _LAUNCH_OPTIONS) -> list[Value]:
    """What a ``**mapping`` at a launch can give a keyword other than a launch option: the values under every other
    key in each literal dict the mapping resolves to (``m365_subprocess_kwargs`` gives only ``env``). A mapping
    that the strict resolver cannot prove literal (changed after it is bound, built by a call, keys not literal)
    is scanned whole, so what it cannot show leaves the launch unresolved."""
    values, complete = _STRICT.values(module, expr)
    literal = complete and values and all(
        isinstance(node, ast.Dict)
        and all(isinstance(key, ast.Constant) and isinstance(key.value, str) for key in node.keys)
        for _, node in values
    )
    if not literal:
        return [(module, expr)]
    return [
        (owner, value)
        for owner, node in values
        for key, value in zip(node.keys, node.values, strict=False)
        if key.value not in options
    ]


def _runner_inputs(module: _Module) -> Iterator[tuple[ast.Call, _Module, ast.AST]]:
    """``(call, module, input)`` of every call that runs a process or hands a command to a runner; the module is
    where the input expression stands (a ``**mapping`` may resolve to a dict in another module).

    A process launch is recognised by where its callee comes from, not how it is spelt: ``sp.Popen`` after
    ``import subprocess as sp``, ``launch`` after ``from subprocess import run as launch`` or ``launch = sp.run``,
    ``getattr(subprocess, "run")`` and ``importlib.import_module("subprocess").Popen``. Launchers outside
    ``subprocess`` (``os.system``, ``os.popen``, ``os.exec*``, ``os.spawn*``, ``os.posix_spawn``, ``pty.spawn``,
    ``asyncio.create_subprocess_*`` and an event loop's ``subprocess_exec``/``subprocess_shell``) hand on every
    argument that carries program, argv or shell text. Every keyword but a known launch option (``_LAUNCH_OPTIONS``,
    or ``_RUNNER_OPTIONS`` for an adapter's ``run``) is input too, ``input=`` (standard input) and unknown keywords
    included, and a ``**mapping`` adds what it holds under any other key.
    """
    for node in ast.walk(module.tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if _is_getattr(func) and (attribute := _literal_argument(func, 1)) is not None:
            name, receiver = attribute, func.args[0]  # ``getattr(loop, "subprocess_shell")(...)``
        else:
            name, receiver = _callee_name(node), func.value if isinstance(func, ast.Attribute) else None
        receiver_name = (
            receiver.id if isinstance(receiver, ast.Name) else receiver.attr if isinstance(receiver, ast.Attribute) else None
        )
        origins = _origins(module, func)
        # ``**options`` can carry any keyword, the program or script text included.
        unpacked = [item for kw in node.keywords if kw.arg is None for item in _unpacked(module, kw.value)]
        foreign = [(owner, expr) for owner, expr in unpacked if owner is not module]
        local = [expr for owner, expr in unpacked if owner is module]
        launchers = sorted({_OS_LAUNCHERS[origin] for origin in origins if origin in _OS_LAUNCHERS}, key=str)
        if not launchers and receiver is not None and name in _LOOP_LAUNCHERS:
            launchers = [_LOOP_LAUNCHERS[name]]
        for start, end in launchers:
            # A starred argument shifts the positions, so every argument is then scanned.
            args = node.args if any(isinstance(arg, ast.Starred) for arg in node.args) else node.args[start:end]
            parts = [*args, *(kw.value for kw in node.keywords if kw.arg is not None and kw.arg not in _LAUNCH_OPTIONS),
                     *local]
            if parts:
                yield node, module, ast.List(elts=parts, ctx=ast.Load())
        if launchers:
            for owner, expr in foreign:
                yield node, owner, expr
            continue
        process = [origin for origin in origins if origin.startswith("subprocess.")]
        if process:
            is_runner = any(origin.removeprefix("subprocess.") in _PROCESS_CALLS for origin in process)
        elif receiver is None:
            is_runner = False
        else:
            is_runner = name == "run" and receiver_name not in _NON_RUNNER_RECEIVERS
        if not is_runner:
            continue
        options = _LAUNCH_OPTIONS if process else _RUNNER_OPTIONS
        if not process:
            unpacked = [item for kw in node.keywords if kw.arg is None for item in _unpacked(module, kw.value, options)]
            foreign = [(owner, expr) for owner, expr in unpacked if owner is not module]
            local = [expr for owner, expr in unpacked if owner is module]
        given = node.args[0] if node.args else next(
            (kw.value for kw in node.keywords if kw.arg in {"args", "command", "script"}), None
        )
        # Every other keyword but a launch option is scanned: ``input=`` is standard input (a script for
        # ``pwsh -Command -``), ``executable=`` the program, and a keyword the scan does not know may carry either.
        # A process's later positional arguments (``executable`` is the third) are scanned too.
        extra = [
            *(node.args[1:] if process else []),
            *(kw.value for kw in node.keywords if kw.arg is not None and kw.arg not in options and kw.value is not given),
        ]
        parts = [part for part in (given, *extra, *local) if part is not None]
        if len(parts) == 1:
            yield node, module, parts[0]
        elif parts:
            yield node, module, ast.List(elts=parts, ctx=ast.Load())
        for owner, expr in foreign:
            yield node, owner, expr


def _executable_strings(
    module: _Module, expr: ast.AST, visited: set[int] | None = None, depth: int = 0
) -> tuple[list[Value], bool]:
    """Every string that can become part of ``expr``: the literals, their f-string fields and ``+`` operands,
    and the elements of the lists (argv) and dicts it can be.

    Complete only when the strict resolver proves every value literal. A bytes literal (standard input given as
    ``b"..."``), an f-string with a field and a ``+`` or ``%`` join of anything but two literals are unresolved:
    their parts are still scanned, but the text they make is not known."""
    visited = set() if visited is None else visited
    if depth > _MAX_DEPTH:
        return [], False
    values, complete = _STRICT.values(module, expr)
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
            if isinstance(node.value, (str, bytes)):
                found.append((owner, node))
                complete &= isinstance(node.value, str)
        elif isinstance(node, ast.JoinedStr):
            found.append((owner, node))
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    complete = False
                    expand(owner, part.value)
        elif isinstance(node, ast.BinOp):
            if _render(node, owner.constants, placeholder="x") is not None:
                found.append((owner, node))
            complete &= isinstance(node.op, ast.Add)
            for side in (node.left, node.right):
                if not (isinstance(side, ast.Constant) and isinstance(side.value, str)):
                    complete = False
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
    for call, owner_module, given in _runner_inputs(module):
        strings, complete = _executable_strings(owner_module, given)
        for owner, node in strings:
            text = _render(node, owner.constants, placeholder="x")
            if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
                text = node.value.decode("utf-8", "replace")  # standard input as bytes: scanned, still unresolved
            if text is not None and node not in owner.docstrings:
                sites[(owner.label, id(node))] = (owner.label, _qualname(node, owner.parents), node.lineno, text)
        entry = (module.label, _qualname(call, module.parents), call.lineno)
        if not complete and entry not in unresolved:
            unresolved.append(entry)
    return list(sites.values()), unresolved


def _untraceable_launches(module: _Module) -> list[tuple[str, str, int, str]]:
    """``(file, qualname, line, why)`` of every place a launch could happen that ``_runner_inputs`` cannot see.

    A launcher (``subprocess.run``, ``os.system`` ...) may only be called, or bound to a plain name that is then
    called (``_origins`` follows every binding of the alias). A launcher module may only have an attribute read,
    by name or by ``getattr`` with a literal name, or be bound to a plain name. Anything else hides the launch: a
    launcher put in a dict, list, class or ``self`` attribute, passed as an argument or default, returned or
    wrapped; a module passed on; ``getattr`` of a launcher module with a computed name; ``import_module``,
    ``__import__`` or ``sys.modules`` with a computed name; an importer or a dynamic builtin (``getattr``,
    ``__import__``, ``eval`` ...) used as a value; code run from text (``eval``, ``exec``, ``compile``); a
    namespace read (``globals()``, ``locals()``, ``vars()``) in a module that binds a launcher; any star import.
    Each is reported, so the scan fails closed on it.
    """
    found: list[tuple[str, str, int, str]] = []
    holds_launcher: list[bool] = []

    def report(node: ast.AST, why: str) -> None:
        found.append((module.label, _qualname(node, module.parents), node.lineno, why))

    def plain_alias(parent: ast.AST | None, node: ast.AST) -> bool:
        if isinstance(parent, ast.Assign) and parent.value is node and len(parent.targets) == 1:
            target = parent.targets[0]
        elif isinstance(parent, ast.AnnAssign) and parent.value is node:
            target = parent.target
        else:
            return False
        return isinstance(target, ast.Name) and not module._in_class_body(parent)

    def binds_a_launcher() -> bool:
        if not holds_launcher:
            names = {*module.import_origins, *module.by_name}
            holds_launcher.append(any(
                _is_launcher(origin) or origin in _LAUNCHER_MODULES
                for name in names for origin in _origins(module, ast.Name(id=name, ctx=ast.Load()))
            ))
        return holds_launcher[0]

    def literal_module_read(node: ast.AST, parent: ast.AST | None) -> bool:
        """``sys.modules["x"]`` or ``sys.modules.get("x")``: resolved by ``_origins``."""
        if isinstance(parent, ast.Subscript) and parent.value is node:
            return isinstance(parent.slice, ast.Constant) and isinstance(parent.slice.value, str)
        outer = module.parents.get(parent) if parent is not None else None
        return (
            isinstance(parent, ast.Attribute) and parent.attr == "get" and isinstance(outer, ast.Call)
            and outer.func is parent and _literal_argument(outer, 0) is not None
        )

    for node in ast.walk(module.tree):
        parent = module.parents.get(node)
        if isinstance(node, ast.ImportFrom):
            if any(alias.name == "*" for alias in node.names):
                report(node, f"star import from {module._import_base(node) or '.' * node.level + (node.module or '')}")
            continue
        called = isinstance(parent, ast.Call) and parent.func is node
        if isinstance(node, ast.Call):
            callee = _origins(module, node.func)
            if callee & _IMPORTERS_BY_NAME and _literal_module_name(node) is None:
                # The name, by position or ``name=``, traced by the strict resolver to literals (a module constant
                # looped over) is judged; a computed or changed name, or arguments the scan does not model
                # (``*args``, ``**options``, a relative import), is reported.
                given = _module_name_argument(node)
                values, complete = _STRICT.values(module, given) if given is not None else ([], False)
                names = {value.value for _, value in values if isinstance(value, ast.Constant)}
                if not complete or len(names) != len(values) or not all(isinstance(name, str) for name in names):
                    report(node, "import of a computed module name")
                elif names & _LAUNCHER_MODULES:
                    report(node, f"import of {sorted(names & _LAUNCHER_MODULES)[0]} through a name")
            if _is_getattr(node) and _literal_argument(node, 1) is None and _origins(module, node.args[0]) & _LAUNCHER_MODULES:
                report(node, "getattr of a launcher module with a computed name")
            if _is_getattr(node) and _literal_argument(node, 1) in _LOOP_LAUNCHERS and not called:
                report(node, f"event-loop {_literal_argument(node, 1)} used as a value")
            if callee & _MODULE_LOADERS:
                report(node, f"module loaded by {sorted(callee & _MODULE_LOADERS)[0]}")
            if callee & {"builtins.eval", "builtins.exec", "builtins.compile"}:
                report(node, f"code run from text by {sorted(callee)[0].removeprefix('builtins.')}")
            if callee & {"builtins.globals", "builtins.locals", "builtins.vars"} and not node.args and binds_a_launcher():
                report(node, f"namespace read through {sorted(callee)[0].removeprefix('builtins.')}()")
        if isinstance(node, ast.Attribute) and node.attr in _LOOP_LAUNCHERS:
            if not called:
                report(node, f"event-loop {node.attr} used as a value")
            continue
        if not isinstance(node, (ast.Name, ast.Attribute, ast.Call)):
            continue
        if isinstance(node, (ast.Name, ast.Attribute)) and not isinstance(node.ctx, ast.Load):
            replaced = sorted(origin for origin in _origins(module, node) if _is_launcher(origin))
            if isinstance(node, ast.Attribute) and replaced:
                report(node, f"{replaced[0]} replaced")
            continue
        origins = _origins(module, node)
        launchers = sorted(origin for origin in origins if _is_launcher(origin))
        dynamic = sorted(origins & (_IMPORTERS_BY_NAME | _MODULE_LOADERS | {f"builtins.{name}" for name in _DYNAMIC_BUILTINS}))
        modules = sorted(origins & _LAUNCHER_MODULES)
        if launchers or dynamic:
            if not called and not plain_alias(parent, node):
                report(node, f"{(launchers or dynamic)[0]} used as a value")
        elif "sys.modules" in origins:
            if not literal_module_read(node, parent):
                report(node, "sys.modules read other than by a literal name")
        elif modules:
            if isinstance(parent, ast.Attribute) and parent.value is node and not parent.attr.startswith("__"):
                continue  # an attribute read by name: its origin is judged on the attribute itself
            if _is_getattr(parent) and parent.args[0] is node:
                continue  # judged on the getattr call: a literal name resolves, a computed one is reported above
            if isinstance(parent, ast.Call) and isinstance(parent.func, ast.Name) and parent.func.id == "hasattr":
                continue  # ``hasattr(os, "O_NOFOLLOW")`` only tests that the attribute exists
            if not plain_alias(parent, node):
                report(node, f"module {modules[0]} used as a value")
    return found


def _command_names(script: str) -> list[str]:
    """Cmdlet names at a command position, by the read guard's own tokenizer, in any letter case.

    PowerShell is case-insensitive, so ``import-module`` is ``Import-Module``. A string the tokenizer refuses
    falls back to every ``verb-noun`` word with a PowerShell verb, in any case. In a shell command line (the text
    ``os.system`` or ``create_subprocess_shell`` takes), what follows a host's script flag (``pwsh -Command``,
    ``-c``, ``bash -c``, ``cmd /c``) is a script of its own and is scanned as one.
    """
    try:
        tokens = read_guard._tokenize(script, "scan")
    except CommandRefused:
        return [
            f"{verb}-{noun}" for verb, noun in _CMDLET_ANY_CASE.findall(script) if verb.lower() in _POWERSHELL_VERBS
        ]
    names: list[str] = []
    for index, token in enumerate(tokens):
        following = tokens[index + 1] if index + 1 < len(tokens) else None
        if token.kind == "word" and _HOST_SCRIPT_FLAG.match(token.text):
            if following is not None and following.kind == "string":
                names += _command_names(following.text[1:-1])
                continue
            # Unquoted, the rest of the line is the script; scanning it as one covers every remaining token.
            names += _command_names(script[token.end :])
            break
        if token.kind != "word" or not _CMDLET.match(token.text):
            continue
        previous = tokens[index - 1] if index else None
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


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        # DEC-011 L1: launchers outside ``subprocess``, shell text and argv forms, under any import spelling.
        ('import os\ndef f():\n    os.system("pwsh -NoProfile -Command Set-Mailbox x")\n',
         "Set-Mailbox is not on the read allow-list"),
        ('import os\ndef f():\n    return os.popen("pwsh -c \'Remove-Mailbox x\'").read()\n',
         "Remove-Mailbox is not on the read allow-list"),
        ('from os import system as sh\ndef f():\n    sh("bash -c \\"pwsh -Command import-module X\\"")\n',
         "wrapper import-module outside the trusted table"),
        ('from os import execvp\ndef f():\n    execvp("pwsh", ["pwsh", "-Command", "Set-Mailbox x"])\n',
         "Set-Mailbox is not on the read allow-list"),
        ('import os\ndef f():\n    os.execle("/usr/bin/pwsh", "pwsh", "-Command", "Set-Mailbox x", {})\n',
         "Set-Mailbox is not on the read allow-list"),
        ('import os\ndef f():\n    os.spawnlp(os.P_WAIT, "pwsh", "pwsh", "-Command", "Remove-Mailbox x")\n',
         "Remove-Mailbox is not on the read allow-list"),
        ('import os\nARGV = ["pwsh", "-Command", "Set-Mailbox x"]\ndef f():\n    os.spawnv(os.P_NOWAIT, "pwsh", ARGV)\n',
         "Set-Mailbox is not on the read allow-list"),
        ('import os\ndef f():\n    os.posix_spawn("/usr/bin/pwsh", ["pwsh", "-Command", "Set-Mailbox x"], {})\n',
         "Set-Mailbox is not on the read allow-list"),
        ('import pty\ndef f():\n    pty.spawn(["pwsh", "-Command", "Set-Mailbox x"])\n',
         "Set-Mailbox is not on the read allow-list"),
        ('import asyncio\nasync def f():\n    await asyncio.create_subprocess_exec("pwsh", "-Command", "Set-Mailbox x")\n',
         "Set-Mailbox is not on the read allow-list"),
        ('from asyncio import create_subprocess_shell\nasync def f():\n'
         '    await create_subprocess_shell("pwsh -Command Remove-Mailbox x")\n',
         "Remove-Mailbox is not on the read allow-list"),
        ('import asyncio\nasync def f():\n    loop = asyncio.get_running_loop()\n'
         '    await loop.subprocess_exec(object, "pwsh", "-Command", "Set-Mailbox x")\n',
         "Set-Mailbox is not on the read allow-list"),
        # DEC-011 L2: a launcher reached through getattr or an import by literal name is resolved.
        ('import subprocess\ndef f():\n    getattr(subprocess, "Popen")(["pwsh", "-Command", "Set-Mailbox x"])\n',
         "Set-Mailbox is not on the read allow-list"),
        ('import importlib\ndef f():\n    importlib.import_module("subprocess").check_output(["pwsh", "-Command", "Set-Mailbox x"])\n',
         "Set-Mailbox is not on the read allow-list"),
        ('def f():\n    sp = __import__("subprocess")\n    sp.call(["pwsh", "-Command", "Remove-Mailbox x"])\n',
         "Remove-Mailbox is not on the read allow-list"),
        ('import os\ndef f():\n    launch = getattr(os, "system")\n    launch("pwsh -Command Set-Mailbox x")\n',
         "Set-Mailbox is not on the read allow-list"),
    ],
)
def test_launches_outside_plain_subprocess_calls_are_found(source: str, expected: str) -> None:
    sites, unresolved = _command_sites_in(_synthetic(source))
    violations, _ = _command_violations(sites)
    assert any(expected in item for item in violations), (violations, unresolved)


@pytest.mark.parametrize(
    "source",
    [
        'import os\ndef f(command):\n    os.system(command)\n',
        'import os\ndef f(argv):\n    os.execvp("pwsh", argv)\n',
        'import asyncio\nasync def f(argv):\n    await asyncio.create_subprocess_exec(*argv)\n',
        'import pty\ndef f(argv):\n    pty.spawn(argv=argv)\n',
    ],
)
def test_non_subprocess_launch_with_unseen_input_is_reported(source: str) -> None:
    _, unresolved = _command_sites_in(_synthetic(source))
    assert [qualname for _, qualname, _ in unresolved] == ["f"]


def test_shell_script_flags_open_a_script_of_their_own() -> None:
    assert _command_names("pwsh -NoProfile -Command Get-Mailbox; Set-Mailbox x") == ["Get-Mailbox", "Set-Mailbox"]
    assert _command_names("pwsh -c 'Remove-Mailbox x'") == ["Remove-Mailbox"]
    assert _command_names('cmd /c "pwsh -Com Set-Mailbox x"') == ["Set-Mailbox"]
    # A flag with no script after it, or an argv element of its own, adds nothing.
    assert _command_names("-Command") == []
    assert _command_names("az login -c") == []


def test_untraceable_launches_are_exactly_the_reviewed_ones() -> None:
    found = {
        (file, qualname) for path in _python_files(SRC) for file, qualname, _, _ in _untraceable_launches(_module_for(path))
    }
    assert found == set(_UNTRACEABLE_LAUNCHES)


@pytest.mark.parametrize(
    ("source", "why"),
    [
        # DEC-011 L2: a launcher in a dict, a list, a class attribute or a self attribute.
        ('import subprocess\nLAUNCH = {"go": subprocess.run}\ndef f():\n    LAUNCH["go"](["pwsh", "-Command", "Set-Mailbox x"])\n',
         "subprocess.run used as a value"),
        ('import subprocess as sp\nLAUNCHERS = [sp.Popen]\ndef f():\n    LAUNCHERS[0](["pwsh"])\n',
         "subprocess.Popen used as a value"),
        ('import os\nclass R:\n    launch = os.system\n    def go(self):\n        self.launch("pwsh -Command Set-Mailbox x")\n',
         "os.system used as a value"),
        ('from subprocess import check_output\nclass R:\n    def __init__(self):\n        self.launch = check_output\n',
         "subprocess.check_output used as a value"),
        # Passed in as a parameter, as a default, wrapped or returned.
        ('import subprocess\ndef go(launch, argv):\n    return launch(argv)\n'
         'def main():\n    return go(subprocess.run, ["pwsh", "-Command", "Set-Mailbox x"])\n',
         "subprocess.run used as a value"),
        ('import subprocess\ndef go(argv, launch=subprocess.run):\n    return launch(argv)\n',
         "subprocess.run used as a value"),
        ('import functools, subprocess\nquiet = functools.partial(subprocess.run, check=False)\n',
         "subprocess.run used as a value"),
        ('import pty\ndef launcher():\n    return pty.spawn\n', "pty.spawn used as a value"),
        ('import subprocess\ndef launcher():\n    return getattr(subprocess, "run")\n', "subprocess.run used as a value"),
        ('async def f(loop, launch):\n    return launch(loop.subprocess_shell)\n', "event-loop subprocess_shell used as a value"),
        # A launcher module passed on, read with a computed name, imported by a computed name or star-imported.
        ('import subprocess\ndef f(runner):\n    return runner(subprocess)\n', "module subprocess used as a value"),
        ('import subprocess\ndef f(name, argv):\n    return getattr(subprocess, name)(argv)\n',
         "getattr of a launcher module with a computed name"),
        ('import os\ndef f(name):\n    return os.__dict__[name]\n', "module os used as a value"),
        ('import importlib\ndef f(name):\n    return importlib.import_module(name).run(["pwsh"])\n',
         "import of a computed module name"),
        ('MODULES = ("json", "subprocess")\ndef f():\n    for name in MODULES:\n        __import__(name)\n',
         "import of subprocess through a name"),
        ('from subprocess import *\ndef f():\n    run(["pwsh", "-Command", "Set-Mailbox x"])\n',
         "star import from subprocess"),
        # The launcher itself replaced.
        ('import subprocess\ndef f(fake):\n    subprocess.run = fake\n', "subprocess.run replaced"),
    ],
)
def test_untraceable_launch_forms_are_reported(source: str, why: str) -> None:
    assert [reason for *_, reason in _untraceable_launches(_synthetic(source))] == [why]


def test_direct_and_aliased_launches_are_not_untraceable() -> None:
    source = (
        'import importlib, os, subprocess\nimport subprocess as sp\nfrom subprocess import run as launch\n'
        'RUN = sp.check_output\nNAMES = ("json", "csv")\n'
        'def f(argv):\n    subprocess.run(argv)\n    launch(argv)\n    RUN(argv)\n'
        '    getattr(subprocess, "Popen")(argv)\n    importlib.import_module("subprocess").call(argv)\n'
        '    for name in NAMES:\n        importlib.import_module(name)\n'
        '    return os.environ.get("X"), getattr(os, "O_CLOEXEC", 0), hasattr(os, "geteuid")\n'
    )
    assert _untraceable_launches(_synthetic(source)) == []


def _planted(tmp_path: Path, source: str, name: str = "planted.py", dotted: str | None = None) -> _Module:
    """A planted source file under ``tmp_path``, parsed as a module; ``dotted`` lets another planted module import
    it once it is in ``_MODULE_CACHE``."""
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return _Module(path.read_text(encoding="utf-8"), name, dotted)


# Launches the scan missed after the first L1/L2 round (review M04-T02 repair 1), each judged now.
_LAUNCHES_THROUGH_EVERY_BINDING = [
    # Item 1: keyword unpacking at a launcher; a literal mapping is resolved, its text keys scanned.
    ('import asyncio\nasync def f():\n    opts = {"cmd": "pwsh -Command Set-Mailbox x"}\n'
     '    await asyncio.create_subprocess_shell(**opts)\n', "Set-Mailbox is not on the read allow-list"),
    ('import subprocess\nOPTS = {"args": ["pwsh", "-Command", "Remove-Mailbox x"], "check": False}\n'
     'def f():\n    subprocess.run(**OPTS)\n', "Remove-Mailbox is not on the read allow-list"),
    # A script on standard input (``pwsh -Command -``), given directly or through ``**``.
    ('import subprocess\ndef f():\n    subprocess.run(["pwsh", "-Command", "-"], input="Set-Mailbox x", text=True)\n',
     "Set-Mailbox is not on the read allow-list"),
    ('import subprocess\ndef f():\n    subprocess.run(["pwsh", "-Command", "-"], **{"input": "Remove-Mailbox x"})\n',
     "Remove-Mailbox is not on the read allow-list"),
    # Item 2: every binding of an alias counts, and a later import of a name does not hide an earlier one.
    ('import json, subprocess\nlaunch = json.loads\nlaunch = getattr(subprocess, "Popen")\n'
     'def f():\n    launch(["pwsh", "-Command", "Set-Mailbox x"])\n', "Set-Mailbox is not on the read allow-list"),
    ('from json import loads as launch\nimport subprocess\nlaunch = subprocess.run\n'
     'def f():\n    launch(["pwsh", "-Command", "Set-Mailbox x"])\n', "Set-Mailbox is not on the read allow-list"),
    ('def a():\n    import subprocess as tool\n    tool.check_output(["pwsh", "-Command", "Set-Mailbox x"])\n'
     'def b():\n    import json as tool\n    return tool.dumps({})\n', "Set-Mailbox is not on the read allow-list"),
    # Nearby: ``getattr`` with a literal name on a runtime object, the platform module behind ``os``,
    # ``sys.modules`` and ``builtins.__import__`` with a literal name.
    ('import asyncio\nasync def f():\n    loop = asyncio.get_running_loop()\n'
     '    await getattr(loop, "subprocess_shell")(object, "pwsh -Command Set-Mailbox x")\n',
     "Set-Mailbox is not on the read allow-list"),
    ('def f(adapter):\n    return getattr(adapter, "run")("Set-Mailbox -Identity x")\n',
     "Set-Mailbox is not on the read allow-list"),
    ('import posix\ndef f():\n    posix.system("pwsh -Command Set-Mailbox x")\n', "Set-Mailbox is not on the read allow-list"),
    ('import sys\ndef f():\n    sys.modules["subprocess"].Popen(["pwsh", "-Command", "Set-Mailbox x"])\n',
     "Set-Mailbox is not on the read allow-list"),
    ('import sys\ndef f():\n    sys.modules.get("os").system("pwsh -Command Remove-Mailbox x")\n',
     "Remove-Mailbox is not on the read allow-list"),
    ('import builtins\ndef f():\n    builtins.__import__("subprocess").check_call(["pwsh", "-Command", "Set-Mailbox x"])\n',
     "Set-Mailbox is not on the read allow-list"),
    # Nearby (item 3 on the command side): a default value is evaluated where the function is defined.
    ('import os\nCMD = "pwsh -Command Set-Mailbox x"\ndef outer():\n    cmd = CMD\n'
     '    def g(cmd=cmd):\n        os.system(cmd)\n    g()\n', "Set-Mailbox is not on the read allow-list"),
]


@pytest.mark.parametrize(("source", "expected"), _LAUNCHES_THROUGH_EVERY_BINDING)
def test_launches_through_unpacking_rebinding_and_lookups_are_judged(tmp_path: Path, source: str, expected: str) -> None:
    sites, unresolved = _command_sites_in(_planted(tmp_path, source))
    violations, _ = _command_violations(sites)
    assert any(expected in item for item in violations), (violations, unresolved)


def test_unpacked_launch_options_are_resolved_or_reported(tmp_path: Path) -> None:
    # A mapping the source cannot show leaves the launch unresolved.
    source = 'import asyncio\nasync def f(opts):\n    await asyncio.create_subprocess_shell(**opts)\n'
    assert [qualname for _, qualname, _ in _command_sites_in(_planted(tmp_path, source))[1]] == ["f"]
    # One that resolves to literal dicts adds only what it holds under a non-option key (``m365_subprocess_kwargs``).
    source = (
        'import subprocess\ndef options(env):\n    return {} if env is None else {"env": env}\n'
        'def f(env):\n    subprocess.run(["m365", "setup"], check=False, **options(env))\n'
    )
    assert _command_sites_in(_planted(tmp_path, source))[1] == []


def test_a_launcher_re_exported_by_another_module_is_followed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    helpers = _planted(tmp_path, 'import subprocess as sp\nfrom os import system\nlaunch = sp.run\n', "helpers.py",
                       "planted_m04.helpers")
    monkeypatch.setitem(_MODULE_CACHE, "planted_m04.helpers", helpers)
    user = _planted(
        tmp_path,
        'from planted_m04.helpers import launch, system\nfrom planted_m04 import helpers\n'
        'def f():\n    launch(["pwsh", "-Command", "Set-Mailbox x"])\n    system("pwsh -Command Remove-Mailbox x")\n'
        '    helpers.sp.Popen(["pwsh", "-Command", "Import-Module X"])\n',
        "user.py",
        "planted_m04.user",
    )
    violations, _ = _command_violations(_command_sites_in(user)[0])
    for expected in ("Set-Mailbox is not on", "Remove-Mailbox is not on", "wrapper Import-Module outside"):
        assert any(expected in item for item in violations), violations
    assert _untraceable_launches(helpers) == _untraceable_launches(user) == []


_UNTRACEABLE_THROUGH_DYNAMIC_ACCESS = [
    ('import sys\ndef f(name):\n    return sys.modules[name].run(["pwsh"])\n',
     "sys.modules read other than by a literal name"),
    ('def f():\n    return list(map(__import__, ["subprocess"]))[0].run(["pwsh"])\n',
     "builtins.__import__ used as a value"),
    ('import importlib\ndef f():\n    mods = list(map(importlib.import_module, ["subprocess"]))\n    return mods[0].run(["pwsh"])\n',
     "importlib.import_module used as a value"),
    ('def f():\n    return eval("__import__(\'subprocess\')").run(["pwsh"])\n', "code run from text by eval"),
    ('def f(code):\n    exec(code)\n', "code run from text by exec"),
    ('from subprocess import run\ndef f():\n    return globals()["run"](["pwsh", "-Command", "Set-Mailbox x"])\n',
     "namespace read through globals()"),
    ('from helpers import *\ndef f():\n    run(["pwsh", "-Command", "Set-Mailbox x"])\n', "star import from helpers"),
    ('import asyncio\nasync def f(launch):\n    loop = asyncio.get_running_loop()\n'
     '    return launch(getattr(loop, "subprocess_exec"))\n', "event-loop subprocess_exec used as a value"),
    # Review M04-T02 repair 2: a module loaded by a path, a spec or a ``module:attribute`` text.
    ('import pkgutil\ndef f():\n    return pkgutil.resolve_name("subprocess:run")(["pwsh"])\n',
     "module loaded by pkgutil.resolve_name"),
    ('import runpy\ndef f(path):\n    return runpy.run_path(path)\n', "module loaded by runpy.run_path"),
    ('import importlib.util\ndef f(spec):\n    return importlib.util.module_from_spec(spec)\n',
     "module loaded by importlib.util.module_from_spec"),
    ('import runpy\nLOADERS = [runpy.run_module]\n', "runpy.run_module used as a value"),
]


@pytest.mark.parametrize(("source", "why"), _UNTRACEABLE_THROUGH_DYNAMIC_ACCESS)
def test_launchers_reached_through_dynamic_access_are_reported(tmp_path: Path, source: str, why: str) -> None:
    assert [reason for *_, reason in _untraceable_launches(_planted(tmp_path, source))] == [why]


def test_dynamic_access_that_cannot_reach_a_launcher_is_not_reported(tmp_path: Path) -> None:
    source = (
        'import sys\ndef tools():\n    def auditex_a():\n        return 1\n'
        '    return {name: value for name, value in locals().items() if name.startswith("auditex_")}\n'
        'def f(obj, name):\n    return getattr(obj, name), sys.modules.get("json"), __import__("os").environ.get("X")\n'
    )
    assert _untraceable_launches(_planted(tmp_path, source)) == []


# Review M04-T02 repair 2: one fail-closed rule. A value that reaches a launcher, an importer, a callee lookup or
# standard input counts only when the strict resolver proves it literal; anything else leaves the launch unresolved
# (or the import untraceable). Each planted case passed silently before this rule.
_ARGV = '["pwsh", "-Command", "Get-Date"]'
_LIST_CHANGES = [
    'argv[2] = "Set-Mailbox x"', 'argv.append("Set-Mailbox x")', 'argv.extend(["Set-Mailbox x"])',
    'argv.insert(2, "Set-Mailbox x")', "argv.pop()", "argv.clear()", 'argv.__setitem__(2, "Set-Mailbox x")',
    "del argv[2]", 'argv += ["Set-Mailbox x"]', "fill(argv)", 'alias = argv\n    alias.append("Set-Mailbox x")',
    'for alias in [argv]:\n        alias.append("Set-Mailbox x")',
]
_MAPPING_CHANGES = [
    'opts["cmd"] = "pwsh -Command Set-Mailbox x"', 'opts.update(cmd="pwsh -Command Set-Mailbox x")',
    'opts.setdefault("args", "pwsh -Command Set-Mailbox x")', 'opts.__setitem__("cmd", "pwsh -Command Set-Mailbox x")',
    'opts |= {"cmd": "pwsh -Command Set-Mailbox x"}', 'del opts["cmd"]', 'opts.pop("cmd")', "fill(opts)",
]
_CHANGED_AFTER_BINDING = [
    # Item 1: a mapping changed after it is bound, at ``**`` of a shell launcher and of ``subprocess.run``.
    'import asyncio\nasync def f():\n    opts = {}\n    opts["cmd"] = "pwsh -Command Set-Mailbox x"\n'
    '    await asyncio.create_subprocess_shell(**opts)\n',
    'import asyncio\nasync def f():\n    opts = {"cmd": "pwsh -Command Get-Date"}\n'
    '    opts.update(cmd="pwsh -Command Set-Mailbox x")\n    await asyncio.create_subprocess_shell(**opts)\n',
    *(f'import asyncio\nasync def f():\n    opts = {{"cmd": "pwsh -Command Get-Date"}}\n    {change}\n'
      f'    await asyncio.create_subprocess_shell(**opts)\n' for change in _MAPPING_CHANGES),
    *(f'import subprocess\ndef f():\n    opts = {{"args": {_ARGV}}}\n    {change.replace("cmd", "args")}\n'
      f'    subprocess.run(**opts)\n' for change in _MAPPING_CHANGES),
    # The same changes to a list handed on as ``*args`` and as an argv.
    *(f'import asyncio\nasync def f():\n    argv = {_ARGV}\n    {change}\n'
      f'    await asyncio.create_subprocess_exec(*argv)\n' for change in _LIST_CHANGES),
    *(f'import subprocess\ndef f():\n    argv = {_ARGV}\n    {change}\n    subprocess.run(argv)\n'
      for change in _LIST_CHANGES),
    # A module-level list or a class attribute changed in another scope, through a returned reference.
    f'import os\nARGV = {_ARGV}\ndef add():\n    ARGV.append("Set-Mailbox x")\ndef f():\n    os.execvp("pwsh", ARGV)\n',
    f'import subprocess\nclass R:\n    argv = {_ARGV}\n    def go(self):\n        self.argv.append("Set-Mailbox x")\n'
    '        subprocess.run(self.argv)\n',
    f'import subprocess\nARGV = {_ARGV}\ndef shared():\n    return ARGV\ndef f():\n    shared().append("Set-Mailbox x")\n'
    '    held = shared()\n    held[2] = "Set-Mailbox x"\n    subprocess.run(ARGV)\n',
    f'import subprocess\nARGV = {_ARGV}\ndef f():\n    ARGV.append("Set-Mailbox x")\n    subprocess.run(ARGV)\n',
    # Handed to a method of another object, or to a ``.run`` that is not a launch.
    'import subprocess\nclass R:\n    def go(self, other):\n        argv = ["pwsh"]\n        other.fill(argv)\n'
    '        subprocess.run(argv)\n',
    'import subprocess\ndef f(collector):\n    argv = ["pwsh"]\n    collector.run(argv)\n    subprocess.run(argv)\n',
    # Changed through a walrus, a branch, a returned reference or a default value, or passed inside a container.
    f'import subprocess\nARGV = {_ARGV}\ndef f():\n    (alias := ARGV).append("Set-Mailbox x")\n    subprocess.run(ARGV)\n',
    f'import subprocess\nARGV = {_ARGV}\ndef f(other):\n    (other or ARGV)[2] = "Set-Mailbox x"\n    subprocess.run(ARGV)\n',
    f'import subprocess\nARGV = {_ARGV}\ndef shared():\n    return ARGV\ndef f():\n    shared().pop()\n    subprocess.run(ARGV)\n',
    f'import subprocess\nARGV = {_ARGV}\ndef add(argv=ARGV):\n    argv.append("Set-Mailbox x")\n'
    'def f():\n    subprocess.run(ARGV)\n',
    f'import subprocess\nARGV = {_ARGV}\ndef f(log):\n    log([ARGV])\n    subprocess.run(ARGV)\n',
    # Item 3: bytes or bytearray on standard input, on every launcher that takes ``input=``.
    *(f'import subprocess\ndef f():\n    subprocess.{launcher}(["pwsh", "-Command", "-"], input={given})\n'
      for launcher in ("run", "check_output")
      for given in ('b"Set-Mailbox x"', 'bytearray(b"Set-Mailbox x")', '"Set-Mailbox x".encode()', 'bytes(SCRIPT)')),
    'import subprocess\ndef f():\n    subprocess.run(["pwsh", "-Command", "-"], **{"input": b"Set-Mailbox x"})\n',
    # Text the scan cannot prove: an f-string field, a ``+`` or ``%`` join, a string method, an unknown call.
    'import os\ndef f():\n    verb = "Set"\n    os.system(f"pwsh -Command {verb}-Mailbox x")\n',
    'import os\ndef f():\n    verb = "Set"\n    os.system("pwsh -Command " + verb + "-Mailbox x")\n',
    'import os\ndef f():\n    os.system("pwsh -Command %s-Mailbox x" % "Set")\n',
    'import os\ndef f():\n    os.system("pwsh -Command " + "-".join(["Set", "Mailbox"]))\n',
    'import os\ndef f():\n    os.system("pwsh -Command {}-Mailbox x".format("Set"))\n',
    'import os\ndef f():\n    os.system("pwsh -Command XSet-Mailbox x".replace("XSet", "Set"))\n',
    'import os\nfrom helpers import build\ndef f():\n    os.system(build())\n',
    'import os\ndef f():\n    cmd = "pwsh -Command Set"\n    cmd += "-Mailbox x"\n    os.system(cmd)\n',
    # A keyword or later argument the scan does not know as an option.
    'import subprocess\ndef f(script):\n    subprocess.run(["pwsh", "-Command", "-"], stdin_text=script)\n',
    'import subprocess\ndef f(program):\n    subprocess.Popen(["-Command", "Get-Date"], 0, program)\n',
    'import os\ndef f(script):\n    os.posix_spawn("/usr/bin/pwsh", ["pwsh"], {}, extra=script)\n',
    'def f(adapter, script):\n    return adapter.run("Get-Date", extra=script)\n',
    'def f(adapter, opts):\n    return adapter.run("Get-Date", **opts)\n',
]


@pytest.mark.parametrize("source", _CHANGED_AFTER_BINDING)
def test_values_the_scan_cannot_prove_literal_leave_the_launch_unresolved(tmp_path: Path, source: str) -> None:
    unresolved = _command_sites_in(_planted(tmp_path, f"SCRIPT = b'x'\ndef fill(value):\n    value.clear()\n{source}"))[1]
    assert {qualname for _, qualname, _ in unresolved} & {"f", "R.go"}, unresolved


def test_values_proved_literal_stay_resolved(tmp_path: Path) -> None:
    # Strings passed to a logger, read-only calls and a launch with only known options are proved literal.
    source = (
        'import asyncio, logging, subprocess\nLOG = logging.getLogger(__name__)\n'
        f'ARGV = {_ARGV}\nOPTS = {{"args": {_ARGV}, "check": False, "env": None}}\n'
        'def helper(argv):\n    return len(argv)\n'
        'async def f():\n    cmd = "pwsh -Command Get-Date"\n    LOG.info("running %s", cmd)\n'
        '    LOG.info("argv %s", " ".join(ARGV))\n    helper(ARGV)\n    print(list(ARGV), sorted(OPTS))\n'
        '    await asyncio.create_subprocess_shell(cmd, stdout=None, limit=1024)\n'
        '    subprocess.run(ARGV, input="Get-Date", text=True, timeout=5)\n    subprocess.run(**OPTS)\n'
        '    subprocess.run(["pwsh", "-Command", "GET-DATE".lower()])\n'
    )
    module = _planted(tmp_path, source)
    sites, unresolved = _command_sites_in(module)
    assert unresolved == [], unresolved
    assert _command_violations(sites)[0] == []


def test_a_changed_value_is_still_scanned_where_it_shows(tmp_path: Path) -> None:
    source = f'import subprocess\ndef f():\n    argv = {_ARGV}\n    argv.append("Set-Mailbox x")\n    subprocess.run(argv)\n'
    sites, unresolved = _command_sites_in(_planted(tmp_path, source))
    assert [qualname for _, qualname, _ in unresolved] == ["f"]
    assert any("Set-Mailbox is not on the read allow-list" in item for item in _command_violations(sites)[0])
    source = 'import subprocess\ndef f():\n    subprocess.run(["pwsh", "-Command", "-"], input=b"Set-Mailbox x")\n'
    sites, _ = _command_sites_in(_planted(tmp_path, source))
    assert any("Set-Mailbox is not on the read allow-list" in item for item in _command_violations(sites)[0])


# Review M04-T02 repair 3: a ``global`` or ``nonlocal`` declaration sends a binding of the name, in any form, to the
# module or the enclosing function that binds it, where it joins that scope's binding union; a use in or under the
# declaring body reads that scope. Each planted case passed silently before.
_SET_MAILBOX = '["pwsh", "-Command", "Set-Mailbox -Identity x -HiddenFromAddressListsEnabled $true"]'


def _rebound_by_global(body: str) -> str:
    return (f'import contextlib, subprocess\nARGV = {_ARGV}\ndef choose_command():\n    global ARGV\n    {body}\n'
            'def audit():\n    choose_command()\n    subprocess.run(ARGV)\n')


_DECLARED_LITERAL_BINDINGS = [
    # The reviewer's example, then the other binding forms that carry a value.
    _rebound_by_global(f"ARGV = {_SET_MAILBOX}"),
    _rebound_by_global(f"ARGV += {_SET_MAILBOX}"),
    _rebound_by_global(f"for ARGV in [{_SET_MAILBOX}]:\n        pass"),
    _rebound_by_global(f"(ARGV := {_SET_MAILBOX})"),
    _rebound_by_global(f'[ARGV := {_SET_MAILBOX} for _ in "x"]'),
    # ``nonlocal`` in a nested function, through a function that does not bind the name, and in a class body.
    f'import subprocess\ndef audit():\n    argv = {_ARGV}\n    def choose():\n        nonlocal argv\n'
    f'        argv = {_SET_MAILBOX}\n    choose()\n    subprocess.run(argv)\n',
    f'import subprocess\ndef audit():\n    argv = {_ARGV}\n    def middle():\n        def choose():\n'
    f'            nonlocal argv\n            argv = {_SET_MAILBOX}\n        choose()\n    middle()\n    subprocess.run(argv)\n',
    f'import subprocess\ndef audit():\n    argv = {_ARGV}\n    class Choice:\n        nonlocal argv\n'
    f'        argv = {_SET_MAILBOX}\n    subprocess.run(argv)\n',
    f'import subprocess\nARGV = {_ARGV}\nclass Choice:\n    global ARGV\n    ARGV = {_SET_MAILBOX}\n'
    'def audit():\n    subprocess.run(ARGV)\n',
    # A use under a ``global`` declaration reads the module, not an enclosing function's binding of the name.
    f'import subprocess\nARGV = {_SET_MAILBOX}\ndef outer():\n    ARGV = {_ARGV}\n    def audit():\n        global ARGV\n'
    '        subprocess.run(ARGV)\n    audit()\n',
    f'import subprocess\nARGV = {_SET_MAILBOX}\ndef outer():\n    ARGV = {_ARGV}\n    def middle():\n        global ARGV\n'
    '        def audit():\n            subprocess.run(ARGV)\n        audit()\n    middle()\n',
]


@pytest.mark.parametrize("source", _DECLARED_LITERAL_BINDINGS)
def test_a_declared_binding_joins_the_declared_scope(tmp_path: Path, source: str) -> None:
    violations, _ = _command_violations(_command_sites_in(_planted(tmp_path, source))[0])
    assert any("Set-Mailbox is not on the read allow-list" in item for item in violations), violations


_DECLARED_UNMODELLED_BINDINGS = [
    # Binding forms whose value the scan does not model leave the module's name unresolved.
    _rebound_by_global(f"with contextlib.nullcontext({_SET_MAILBOX}) as ARGV:\n        pass"),
    _rebound_by_global(f"match {_SET_MAILBOX}:\n        case ARGV:\n            pass"),
    _rebound_by_global("def ARGV():\n        pass"),
    _rebound_by_global("class ARGV:\n        pass"),
    _rebound_by_global(f"try:\n        raise ValueError({_SET_MAILBOX})\n    except ValueError as ARGV:\n        pass"),
    # ``del`` under a ``global`` declaration changes the module's name, not an enclosing function's.
    f'import subprocess\nARGV = {_ARGV}\ndef outer():\n    ARGV = {_ARGV}\n    def forget():\n        global ARGV\n'
    '        del ARGV\n    forget()\n    return ARGV\ndef audit():\n    subprocess.run(ARGV)\n',
]


@pytest.mark.parametrize("source", _DECLARED_UNMODELLED_BINDINGS)
def test_a_declared_binding_the_scan_cannot_follow_leaves_the_launch_unresolved(tmp_path: Path, source: str) -> None:
    unresolved = _command_sites_in(_planted(tmp_path, source))[1]
    assert [qualname for _, qualname, _ in unresolved] == ["audit"], unresolved


def test_a_declared_import_joins_the_declared_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # ``global X; from m import X`` adds what ``m`` binds ``X`` to the module's binding union.
    commands = _planted(tmp_path, f"ARGV = {_SET_MAILBOX}\n", "commands.py", "planted_m04.commands")
    monkeypatch.setitem(_MODULE_CACHE, "planted_m04.commands", commands)
    user = _planted(tmp_path, _rebound_by_global("from planted_m04.commands import ARGV"), "user.py", "planted_m04.user")
    sites, unresolved = _command_sites_in(user)
    assert any("Set-Mailbox is not on the read allow-list" in item for item in _command_violations(sites)[0])
    assert unresolved == []
    # A launcher imported under a ``global`` declaration is re-exported like a module-level import.
    launchers = _planted(tmp_path, "def load():\n    global launch\n    from subprocess import run as launch\nload()\n",
                         "launchers.py", "planted_m04.launchers")
    monkeypatch.setitem(_MODULE_CACHE, "planted_m04.launchers", launchers)
    user = _planted(tmp_path, f"from planted_m04.launchers import launch\ndef audit():\n    launch({_SET_MAILBOX})\n",
                    "user.py", "planted_m04.user")
    violations, _ = _command_violations(_command_sites_in(user)[0])
    assert any("Set-Mailbox is not on the read allow-list" in item for item in violations), violations
    assert _untraceable_launches(launchers) == _untraceable_launches(user) == []


def test_a_function_declared_global_is_called_from_its_importers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    helpers = _planted(
        tmp_path,
        'import subprocess\ndef install():\n    global launch\n    def launch(argv):\n        subprocess.run(argv)\n'
        f'install()\nlaunch({_ARGV})\n',
        "helpers.py",
        "planted_m04.helpers",
    )
    user = _planted(tmp_path, f"from planted_m04.helpers import launch\nlaunch({_SET_MAILBOX})\n", "user.py",
                    "planted_m04.user")
    call = next(node for node in ast.walk(user.tree) if isinstance(node, ast.Call))
    monkeypatch.setitem(_IMPORTERS, ("planted_m04.helpers", "launch"), [(user, call)])
    violations, _ = _command_violations(_command_sites_in(helpers)[0])
    assert any("Set-Mailbox is not on the read allow-list" in item for item in violations), violations


def test_a_google_handle_declared_global_is_a_module_handle() -> None:
    source = (
        'def outer(self):\n    service = self._service("admin", "directory_v1")\n    service.users().list().execute()\n'
        '    def install():\n        global service\n        service = self._service("admin", "directory_v1")\n'
        '    install()\ndef wipe():\n    return service.users().delete(userKey="victim").execute()\n'
    )
    assert sorted(_non_reads(source)) == ["<untraceable handle service bound at module scope>", "users.delete"]


_IMPORTER_FORMS = (
    "importlib.import_module", "importlib.__import__", "builtins.__import__", "__import__",
)


@pytest.mark.parametrize("importer", _IMPORTER_FORMS)
def test_every_importer_form_is_judged_by_its_name_keyword(tmp_path: Path, importer: str) -> None:
    # Item 2: ``name=`` resolves like a positional name; a launch through it is judged.
    head = "import builtins, importlib\n"
    source = f'{head}def f():\n    {importer}(name="subprocess").Popen(["pwsh", "-Command", "Set-Mailbox x"])\n'
    module = _planted(tmp_path, source)
    violations, _ = _command_violations(_command_sites_in(module)[0])
    assert any("Set-Mailbox is not on the read allow-list" in item for item in violations), violations
    assert _untraceable_launches(module) == []
    # A computed, changed or unpacked name, or a relative import, is reported.
    for call in (
        f"{importer}(name=name)", f'{importer}(**{{"name": "subprocess"}})', f"{importer}(*names)",
        f'{importer}(name=".tools", package="pkg")', f'{importer}(name="tools", level=1)',
        f'{importer}("subprocess", unknown=1)',
    ):
        source = f'{head}def f(name, names):\n    return {call}.run(["pwsh"])\n'
        reasons = [reason for *_, reason in _untraceable_launches(_planted(tmp_path, source))]
        assert reasons == ["import of a computed module name"], (call, reasons)
    source = f'{head}def f():\n    name = "json"\n    name += "x"\n    return {importer}(name=name)\n'
    assert [reason for *_, reason in _untraceable_launches(_planted(tmp_path, source))] == [
        "import of a computed module name"
    ]


def test_runner_options_are_the_adapters_run_keywords() -> None:
    found: set[str] = set()
    for path in _python_files(ENGINE / "adapters"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, _FUNCTION_NODES) and item.name == "run":
                        args = item.args
                        found |= {arg.arg for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)[2:]}
                        assert not args.vararg and not args.kwarg, path
    assert found == set(_RUNNER_OPTIONS)


def test_default_values_annotations_and_decorators_belong_to_the_enclosing_scope() -> None:
    tree = ast.parse(
        'def outer():\n    @deco(d)\n    def inner(a: ann = default, *, k=kw) -> ret:\n        body\n'
        '    f = lambda x=ldefault: lbody\n'
        '    class C(base, metaclass=meta):\n        cbody\n'
        '    return [elt for y in first for z in second if cond]\n'
    )
    parents = _parents(tree)
    outer = tree.body[0]
    owners = {
        node.id: _enclosing(node, parents, _NAME_SCOPES) for node in ast.walk(tree) if isinstance(node, ast.Name)
    }
    assert {name for name, owner in owners.items() if owner is outer} == {
        "deco", "d", "ann", "default", "kw", "ret", "ldefault", "base", "meta", "first", "f",
    }
    assert {name for name, owner in owners.items() if owner is not outer} == {
        "body", "lbody", "cbody", "elt", "y", "second", "z", "cond",
    }


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


def _google_api_calls() -> list[tuple[str, int, str, ast.AST]]:
    """``(file, line, "resource.chain.method", call)`` for every Google API method call in the provider."""
    return [
        call
        for path in _python_files(GOOGLE_DIR)
        for call in _google_calls_in(path.read_text(encoding="utf-8"), _relative(path))
    ]


_NAME_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef, ast.ListComp, ast.SetComp,
                ast.DictComp, ast.GeneratorExp)


class _Scopes:
    """Python name scopes of one module: which function, lambda, comprehension, class or the module binds a name."""

    def __init__(self, tree: ast.Module, parents: dict[ast.AST, ast.AST]) -> None:
        self.tree = tree
        self.parents = parents
        self.local: dict[ast.AST, set[str]] = {}
        self.globals: set[tuple[ast.AST, str]] = set()  # (function or class, name) it declares ``global``
        declared: list[tuple[ast.AST, list[str]]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
                self.local.setdefault(self.owner(node), set()).add(node.id)
            elif isinstance(node, ast.arg):
                self.local.setdefault(parents[parents[node]], set()).add(node.arg)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.local.setdefault(self.owner(node), set()).add(node.name)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    self.local.setdefault(self.owner(node), set()).add((alias.asname or alias.name).split(".", 1)[0])
            elif isinstance(node, ast.ExceptHandler) and node.name:
                self.local.setdefault(self.owner(node), set()).add(node.name)
            elif isinstance(node, (ast.Global, ast.Nonlocal)):
                declared.append((self.owner(node), node.names))
                if isinstance(node, ast.Global):
                    self.globals.update((self.owner(node), name) for name in node.names)
        for scope, names in declared:
            self.local.get(scope, set()).difference_update(names)

    def owner(self, node: ast.AST) -> ast.AST:
        """The scope that evaluates ``node``: a default value, annotation or decorator belongs to the scope the
        function is defined in, a class's bases to the scope around the class, a comprehension's first iterable
        to the scope around the comprehension."""
        current = _enclosing(node, self.parents, _NAME_SCOPES)
        return self.tree if current is None else current

    def key(self, node: ast.Name) -> tuple[ast.AST, str]:
        """``(scope, name)`` of the binding a name refers to; a class body is not seen from the functions in it. A
        ``global`` declaration in a scope on the way out sends the name to the module; a ``nonlocal`` one (the name
        is not local there) on to the enclosing functions."""
        start = scope = self.owner(node)
        while scope is not self.tree:
            if scope is start or not isinstance(scope, ast.ClassDef):
                if (scope, node.id) in self.globals:
                    return self.tree, node.id
                if node.id in self.local.get(scope, ()):
                    return scope, node.id
            scope = self.owner(scope)
        return self.tree, node.id


def _google_calls_in(source: str, label: str) -> list[tuple[str, int, str, ast.AST]]:
    """Every API method call of one module, whether executed inline or built first and executed later.

    A call on a service (``_service``/``_subject_service``/``build``, inline or bound to a name) is a resource
    accessor only when its result is used as a handle: a method that is not an ``HttpRequest`` member is called
    on it, inline or through the name it is bound to, and no ``HttpRequest`` member (``execute``, ``uri``,
    ``body``, ``to_json`` ...) is touched on it. Every other call is a request and is recorded, whether it is
    executed inline, bound to a name and executed later, inspected, passed on or returned. ``getattr(x, "name")``
    with a literal name reads as ``x.name`` (DEC-011 L3).

    Names are resolved per Python scope, not per module (DEC-011 L4): a name is a handle in the function, lambda,
    comprehension or class that binds it, only when every binding there is a service, an accessor or one method
    reference, and its uses there make it one. A name bound more than one way is a request. A default value,
    annotation or decorator is read in the scope that defines the function, a comprehension's first iterable in
    the scope around it, as Python evaluates them.

    Fails closed (DEC-011 L3): a service or handle that leaves the names the scan follows (stored in a container
    or attribute, passed as an argument or default, returned, bound to a name that is not a handle) or is read
    through ``getattr`` with a computed name is recorded as an ``<untraceable ...>`` call, which is not a read
    method; so is a handle bound at module scope (importable elsewhere) or in a class body (read as an
    attribute). Only the builder methods themselves may cache and return the service ``build`` makes.
    """
    tree = ast.parse(source)
    parents = _parents(tree)
    scopes = _Scopes(tree, parents)
    Key = tuple[ast.AST, str]

    def called(node: ast.AST) -> bool:
        parent = parents.get(node)
        return isinstance(parent, ast.Call) and parent.func is node

    def bound_name(node: ast.AST) -> ast.Name | None:
        parent = parents.get(node)
        if isinstance(parent, ast.Assign) and parent.value is node and len(parent.targets) == 1:
            target: ast.AST = parent.targets[0]
        elif isinstance(parent, ast.AnnAssign) and parent.value is node:
            target = parent.target
        else:
            return None
        return target if isinstance(target, ast.Name) else None

    def use_of(node: ast.AST) -> str:
        """How the value of ``node`` is used where it stands: "handle" (an API method or resource is taken from it
        and called), "request" (an ``HttpRequest`` member is touched), "alias" (bound to a plain name), "harmless"
        (compared or tested), "dynamic" (``getattr`` with a computed name) or "escape" (anything else: passed,
        returned, stored, an attribute taken and not called; the calls made on it are then not seen)."""
        parent = parents.get(node)
        if isinstance(parent, ast.Attribute) and parent.value is node:
            if parent.attr in _HTTP_REQUEST_MEMBERS:
                return "request"
            return "handle" if called(parent) else "escape"
        if isinstance(parent, ast.Call) and parent.func is node:
            return "handle"
        if _is_getattr(parent) and parent.args[0] is node:
            attribute = _literal_argument(parent, 1)
            if attribute is None:
                return "dynamic"
            if attribute in _HTTP_REQUEST_MEMBERS:
                return "request"
            outer = use_of(parent)
            return "handle" if outer in {"handle", "alias"} else "harmless" if outer == "harmless" else "escape"
        if bound_name(node) is not None:
            return "alias"
        if isinstance(parent, ast.Compare) or (isinstance(parent, ast.UnaryOp) and isinstance(parent.op, ast.Not)):
            return "harmless"
        if isinstance(parent, (ast.If, ast.While, ast.IfExp, ast.Assert)) and parent.test is node:
            return "harmless"
        return "escape"

    def chain_of(node: ast.AST) -> tuple[ast.AST, list[str]]:
        names: list[str] = []
        current = node
        while isinstance(current, (ast.Call, ast.Attribute)):
            if isinstance(current, ast.Attribute):
                names.append(current.attr)
                current = current.value
            elif _is_getattr(current) and (attribute := _literal_argument(current, 1)) is not None:
                names.append(attribute)
                current = current.args[0]
            else:
                current = current.func
        return current, names[::-1]

    # handle key -> the chain a direct call of it stands for (a bound method reference), else [].
    handles: dict[Key, list[str]] = {}

    def api_chain(node: ast.AST) -> list[str] | None:
        """The API part of a call chain (after the service it starts from), or None if it is not an API call."""
        if not isinstance(node, ast.Call):
            return None
        root, names = chain_of(node)
        if not isinstance(root, ast.Name):
            return None
        full = [root.id, *names]
        builder = max((index for index, name in enumerate(full) if name in _GOOGLE_SERVICE_BUILDERS), default=None)
        if builder is not None:
            return full[builder + 1 :]
        key = scopes.key(root)
        if key in handles:
            return names or handles[key]
        return None

    bindings: dict[Key, list[ast.AST]] = {}
    other_bound: set[Key] = set()
    uses: dict[Key, list[tuple[ast.Name, str]]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            uses.setdefault(scopes.key(node), []).append((node, use_of(node)))
        elif isinstance(node, ast.Name):
            parent = parents.get(node)
            if isinstance(parent, ast.AnnAssign) and parent.value is None:
                continue
            simple = isinstance(parent, (ast.Assign, ast.AnnAssign)) and bound_name(parent.value) is node
            if simple:
                bindings.setdefault(scopes.key(node), []).append(parent.value)
            else:
                other_bound.add(scopes.key(node))
        elif isinstance(node, ast.arg):
            other_bound.add((parents[parents[node]], node.arg))

    def kind(value: ast.AST) -> tuple[str, tuple[str, ...]]:
        if isinstance(value, ast.Name):
            return ("service", ()) if scopes.key(value) in handles else ("other", ())
        chain = api_chain(value)
        if chain is None:
            return "other", ()
        if _is_getattr(value):
            return "reference", tuple(chain)  # a method or resource taken by name and called later
        if not chain:
            return "service", ()
        return ("accessor", ()) if chain[-1] != "execute" else ("other", ())

    changed = True
    while changed:
        changed = False
        for key, values in bindings.items():
            if key in handles or key in other_bound:
                continue
            kinds = [kind(value) for value in values]
            names = {name for name, _ in kinds}
            used = {use for _, use in uses.get(key, [])}
            handle_use = "handle" in used and "request" not in used
            if names == {"service"}:
                handles[key] = []
            elif names == {"reference"} and len({chain for _, chain in kinds}) == 1 and handle_use:
                handles[key] = list(kinds[0][1])
            elif names <= {"service", "accessor"} and handle_use:
                handles[key] = []
            else:
                continue
            changed = True

    def in_builder(node: ast.AST) -> bool:
        current = parents.get(node)
        while current is not None:
            if isinstance(current, _FUNCTION_NODES) and current.name in _GOOGLE_SERVICE_BUILDERS:
                return True
            current = parents.get(current)
        return False

    found: list[tuple[str, int, str, ast.AST]] = []
    for node in ast.walk(tree):
        chain = api_chain(node)
        if chain is None:
            continue
        use = use_of(node)
        target = bound_name(node)
        bound_to_handle = target is not None and scopes.key(target) in handles
        if use == "dynamic":
            found.append((label, node.lineno, "<untraceable getattr with a computed name>", node))
        elif not chain:
            # A service: used in place or bound to a handle, or the calls made on it are not seen.
            if (use == "escape" or (use == "alias" and not bound_to_handle)) and not in_builder(node):
                found.append((label, node.lineno, "<untraceable service passed on>", node))
        elif chain[-1] != "execute" and use != "handle" and not bound_to_handle:
            found.append((label, node.lineno, ".".join(chain), node))
    for key in handles:
        # A module-level handle can be imported by another module, a class-body one read as ``self.x``/``C.x``:
        # either way its calls are made through names the scan does not follow.
        if isinstance(key[0], (ast.Module, ast.ClassDef)):
            where = "at module scope" if isinstance(key[0], ast.Module) else "in a class body"
            first = bindings[key][0]
            found.append((label, first.lineno, f"<untraceable handle {key[1]} bound {where}>", first))
    for key, named in uses.items():
        if key not in handles:
            continue
        for node, use in named:
            target = bound_name(node)
            if use == "dynamic":
                found.append((label, node.lineno, "<untraceable getattr with a computed name>", node))
            elif use == "escape" or (use == "alias" and target is not None and scopes.key(target) not in handles):
                found.append((label, node.lineno, f"<untraceable handle {key[1]} passed on>", node))
    return found


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


def _non_reads(source: str) -> list[str]:
    calls = _google_calls_in(source, "synthetic.py")
    return [chain for _, _, chain, _ in calls if not _GOOGLE_READ_METHOD.match(chain.rsplit(".", 1)[-1])]


_GMAIL_SETTINGS = (
    'def f(self):\n    service = self._service("gmail", "v1")\n    settings = service.users().settings()\n'
    '    imap = settings.getImap(userId="me").execute()\n'
)


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        # DEC-011 L3: a method fetched by getattr with a literal name, called inline or through a bound name.
        (_GMAIL_SETTINGS + '    getattr(settings, "updateImap")(userId="me", body={}).execute()\n', ["updateImap"]),
        (_GMAIL_SETTINGS + '    update = getattr(settings, "updateImap")\n    update(userId="me", body={}).execute()\n',
         ["updateImap"]),
        ('def f(self):\n    service = self._service("admin", "directory_v1")\n'
         '    getattr(service.users(), "delete")(userKey="victim").execute()\n', ["users.delete"]),
        # ... or with a computed name.
        (_GMAIL_SETTINGS + '    getattr(settings, name)(userId="me").execute()\n',
         ["<untraceable getattr with a computed name>"]),
        # A service kept in an attribute or a container, or passed to a helper, leaves the names the scan follows.
        ('class C:\n    def setup(self):\n        self.directory = self._service("admin", "directory_v1")\n'
         '    def wipe(self):\n        self.directory.users().delete(userKey="victim").execute()\n',
         ["<untraceable service passed on>"]),
        ('def f(self):\n    services = {"directory": self._service("admin", "directory_v1")}\n'
         '    services["directory"].users().delete(userKey="victim").execute()\n', ["<untraceable service passed on>"]),
        ('def f(self):\n    return _wipe(self._service("admin", "directory_v1"))\n'
         'def _wipe(service):\n    return service.users().delete(userKey="victim").execute()\n',
         ["<untraceable service passed on>"]),
        # A resource handle stored in an attribute, or a service handle handed on by name.
        ('def f(self):\n    users = self._service("admin", "directory_v1").users()\n    users.list().execute()\n'
         '    self.users = users\n    self.users.delete(userKey="victim").execute()\n',
         ["<untraceable handle users passed on>"]),
        ('def f(self):\n    service = self._service("admin", "directory_v1")\n    service.users().list().execute()\n'
         '    return helper(service)\n', ["<untraceable handle service passed on>"]),
        # A request stored in a container is recorded where it is made.
        ('def f(self):\n    service = self._service("admin", "directory_v1")\n'
         '    self.pending = [service.users().delete(userKey="victim")]\n', ["users.delete"]),
    ],
)
def test_google_calls_held_or_fetched_indirectly_fail_closed(source: str, expected: list[str]) -> None:
    assert _non_reads(source) == expected


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        # DEC-011 L4: the same name is a handle in one function and a request in another.
        ('def a(self):\n    service = self._service("admin", "directory_v1")\n    users = service.users()\n'
         '    return users.list(customer="c").execute()\n'
         'def b(self):\n    service = self._service("admin", "directory_v1")\n'
         '    users = service.users().delete(userKey="victim")\n    return run(users)\n', ["users.delete"]),
        # A handle in a nested function shadows nothing outside it.
        ('def a(self):\n    service = self._service("admin", "directory_v1")\n    users = service.users().delete(userKey="v")\n'
         '    def inner():\n        users = service.users()\n        return users.list().execute()\n'
         '    return run(users), inner()\n', ["users.delete"]),
        # Rebound in one scope from a resource to a request: the handle is then handed on and fails closed.
        ('def f(self):\n    service = self._service("admin", "directory_v1")\n    users = service.users()\n'
         '    users.list(customer="c").execute()\n    users = service.users().delete(userKey="victim")\n'
         '    return run(users)\n', ["<untraceable handle users passed on>"]),
        # Bound to a resource and to a parameter value: not a handle, so the accessor is recorded.
        ('def f(self, users=None):\n    users = users or self._service("admin", "directory_v1").users()\n'
         '    users.delete(userKey="victim").execute()\n', ["users"]),
    ],
)
def test_google_handles_are_classified_per_scope(source: str, expected: list[str]) -> None:
    assert _non_reads(source) == expected


def test_google_handles_resolve_through_nested_scopes() -> None:
    source = (
        'class C:\n    def f(self, top):\n        service = self._service("admin", "directory_v1")\n'
        '        settings = service.users().settings()\n'
        '        rows = [service.members().list(groupKey=g).execute() for g in top]\n'
        '        page = lambda token: service.users().list(pageToken=token)\n'
        '        def later():\n            return settings.getPop(userId="me").execute()\n'
        '        policies = getattr(service, "policies", None)\n'
        '        if policies is None:\n            return rows\n'
        '        return page, later, policies().list().execute()\n'
    )
    chains = sorted(chain for _, _, chain, _ in _google_calls_in(source, "synthetic.py"))
    assert chains == ["getPop", "list", "members.list", "users.list"]


# Handles the scan missed after the first L3/L4 round (review M04-T02 repair 1).
_HANDLES_OUTSIDE_FUNCTION_SCOPE = [
    # Item 3: a default value is evaluated where the function is defined, so it hands the outer handle on.
    ('def f(self):\n    service = self._service("admin", "directory_v1")\n'
     '    def wipe(service=service):\n        return service.users().delete(userKey="victim").execute()\n'
     '    return wipe()\n', ["<untraceable handle service passed on>"]),
    ('def f(self):\n    service = self._service("admin", "directory_v1")\n'
     '    wipe = lambda service=service: service.users().delete(userKey="victim").execute()\n    return wipe()\n',
     ["<untraceable handle service passed on>"]),
    # Nearby: a comprehension's first iterable is evaluated outside it.
    ('def f(self):\n    service = self._service("admin", "directory_v1")\n'
     '    return [service.users().delete(userKey="v").execute() for service in [service]]\n',
     ["<untraceable handle service passed on>"]),
    # Nearby: a handle bound at module scope can be imported elsewhere, one in a class body read as an attribute.
    ('SERVICE = build("admin", "directory_v1", credentials=CREDENTIALS)\n'
     'def f():\n    return SERVICE.users().list().execute()\n', ["<untraceable handle SERVICE bound at module scope>"]),
    ('class C:\n    directory = build("admin", "directory_v1", credentials=CREDENTIALS)\n'
     '    def wipe(self):\n        return self.directory.users().delete(userKey="victim").execute()\n',
     ["<untraceable handle directory bound in a class body>"]),
]


@pytest.mark.parametrize(("source", "expected"), _HANDLES_OUTSIDE_FUNCTION_SCOPE)
def test_google_handles_outside_their_function_scope_fail_closed(tmp_path: Path, source: str, expected: list[str]) -> None:
    path = tmp_path / "planted.py"
    path.write_text(source, encoding="utf-8")
    calls = _google_calls_in(path.read_text(encoding="utf-8"), "planted.py")
    assert [chain for _, _, chain, _ in calls if not _GOOGLE_READ_METHOD.match(chain.rsplit(".", 1)[-1])] == expected


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

    from auditex.google_workspace.client import (
        GROUP_SETTING_FIELDS,
        GoogleWorkspaceClient,
    )

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
