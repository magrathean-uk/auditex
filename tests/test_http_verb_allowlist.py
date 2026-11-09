"""Every HTTP call site under ``src/`` sends GET unless it is in the frozen allow-list below.

The test reads the source (it never imports or runs a transport) and enumerates every call that
can put a request on the wire: ``requests`` functions, ``Session`` and other client verb methods,
``.request(method, ...)`` and ``._request(method, ...)`` wrappers, ``.send(prepared)``, ``urllib``
``Request`` / ``urlopen`` / opener ``open``, msal token calls, and the google-auth calls that
exchange or later refresh a token. Bare names imported from a transport module
(``from requests import post``) resolve to their origin; an imported transport callable the scanner
does not know is ``VARIABLE`` (fail closed). A verb method taken as a value (``post = s.post``) or
through ``getattr(s, "post")`` is a site too. Each site resolves to a method: a literal verb, or
``VARIABLE`` when the verb is chosen at run time.

Any site whose method is not GET must match an ``ALLOW_LIST`` entry (file, enclosing function,
call expression, method, number of sites), and each entry names its transport class (the eight in
``.plan/ARCHITECTURE.md`` "Transport policy"), its inventory row and a reason. A new non-GET site,
or one more site inside an allow-listed function, fails until someone classifies it here. An entry
that no longer matches anything also fails, so the list never grows wider than the code.

The allow-list is the frozen M01-T02 inventory, section E (DEC-006), and nothing wider. Two sites
take a variable method but are GET-only behind a guard and are resolved to that guard in
``GET_ONLY_GUARDED`` instead of being allowed (inventory rows A8 and A9). A guarded entry, and an
allow-list entry that names a guard, is bound to its exact number of sites and to the method flow:
the site must pass the function's own method parameter, never rebound, and the function must apply
the guard to that parameter first (or, for A9, hand it to a receiver typed as the guarded client).

Known blind spots of a static scan: a verb reached through ``getattr`` with a computed name, and
Google API client calls (``service.users().delete().execute()``), whose read boundary M01-T04
proves.
"""
from __future__ import annotations

import ast
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"

VARIABLE = "VARIABLE"
TOKEN_POST = "POST"

# Attribute calls that are an HTTP verb whatever the receiver (requests, a Session, any client).
_VERB_METHODS = frozenset({"post", "put", "patch", "delete", "head", "options"})
# ``.get`` is everywhere (dicts); it is only enumerated as an HTTP GET on these receivers.
_GET_RECEIVERS = ("requests", "session", "self.session")
# Wrappers whose first argument (or ``method=``) is the verb.
_METHOD_ARG_CALLS = frozenset({"request", "_request"})
# google-auth construction and copy calls: the SDK exchanges or refreshes their token lazily
# inside ``execute()``, so the construction site is the only static handle (inventory A22, A24).
_GOOGLE_CREDENTIAL_CALLS = frozenset(
    {
        "from_service_account_file",
        "from_service_account_info",
        "from_authorized_user_file",
        "from_authorized_user_info",
        "from_client_secrets_file",
        "from_client_config",
        "with_subject",
        "with_scopes",
    }
)
# Explicit token exchanges inside google-auth and google_auth_oauthlib.
_GOOGLE_TOKEN_CALLS = frozenset({"refresh", "run_local_server"})
# Modules whose imported names can send a request.
_TRANSPORT_MODULES = ("requests", "httpx", "urllib3", "aiohttp", "http.client", "urllib.request")
# Imported transport names that construct or configure but never send; any other imported
# transport callable the scanner cannot classify is a VARIABLE site (fail closed).
_NON_SENDING_IMPORTS = frozenset(
    {
        "Session", "Client", "AsyncClient", "ClientSession", "PoolManager", "ProxyManager",
        "HTTPConnection", "HTTPSConnection", "HTTPAdapter", "PreparedRequest", "Response", "Timeout",
        "Limits", "Retry", "build_opener", "install_opener", "codes", "OpenerDirector",
    }
)
# urllib calls that build an opener; ``.open`` on what they return sends a request.
_OPENER_CONSTRUCTORS = frozenset({"build_opener", "OpenerDirector"})


@dataclass(frozen=True)
class CallSite:
    path: str
    function: str
    call: str
    method: str
    line: int
    target: str
    method_arg: str = ""
    receiver: str = ""

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (self.path, self.function, self.call, self.method)

    def __str__(self) -> str:
        return f"{self.path}:{self.line} {self.function} {self.call}(...) -> {self.method}"


@dataclass(frozen=True)
class Allowed:
    path: str
    function: str
    call: str
    method: str
    count: int
    transport_class: int
    rows: str
    reason: str
    target_contains: str = ""
    guard: str = ""

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (self.path, self.function, self.call, self.method)


_GRAPH = "src/azure_tenant_audit/graph.py"
_GOOGLE_AUTH = "src/auditex/google_workspace/auth.py"
_GOOGLE_CLIENT = "src/auditex/google_workspace/client.py"
_NOTIFY = "src/auditex/notify.py"

# Frozen non-GET allow-list: transport-inventory section E (M01-T02, DEC-006). Do not widen it
# without a new inventory row and decision; a site outside the eight transport classes needs sol.
ALLOW_LIST: tuple[Allowed, ...] = (
    Allowed(_GRAPH, "GraphClient.app_token_for", "self.session.post", "POST", 1, 2, "A1",
            "Entra client-credentials token for the Power BI, Power Platform, Exchange Online and Teams admin scopes"),
    Allowed(_GRAPH, "GraphClient._app_token", "self.session.post", "POST", 1, 2, "A2",
            "Entra client-credentials token for Graph"),
    Allowed(_GRAPH, "GraphClient._interactive_token", "app.acquire_token_silent", TOKEN_POST, 1, 2, "A3",
            "msal silent refresh of the interactive Graph token"),
    Allowed(_GRAPH, "GraphClient._interactive_token", "app.acquire_token_interactive", TOKEN_POST, 1, 2, "A3",
            "msal interactive sign-in token exchange"),
    Allowed(_GRAPH, "GraphClient._request", "self.session.request", VARIABLE, 1, 3, "A4a, A4b",
            "Graph dispatch: body-free GET, or POST only to /v1.0/$batch or /beta/$batch with GET-only "
            "sub-requests; its first statement is _enforce_read_only, which applies read_only_violation",
            guard="call:self._enforce_read_only"),
    Allowed(_GRAPH, "GraphClient.get_batch", "self._request", "POST", 1, 3, "A6",
            "the one $batch caller; it refuses non-GET specs and builds GET-only inner requests",
            target_contains="/$batch"),
    Allowed(_GOOGLE_AUTH, "build_google_credentials", "service_account.Credentials.from_service_account_file",
            TOKEN_POST, 1, 2, "A22",
            "service-account credentials; google-auth exchanges a JWT bearer grant lazily inside execute()"),
    Allowed(_GOOGLE_AUTH, "build_google_credentials", "credentials.with_subject", TOKEN_POST, 1, 2, "A22",
            "domain-delegated copy of the service-account credentials; lazy JWT bearer grant"),
    Allowed(_GOOGLE_AUTH, "build_google_credentials", "Credentials.from_authorized_user_file", TOKEN_POST, 1, 2,
            "A24", "cached OAuth user credentials; google-auth refreshes them lazily inside execute()"),
    Allowed(_GOOGLE_AUTH, "build_google_credentials", "credentials.refresh", TOKEN_POST, 1, 2, "A21",
            "explicit refresh of the expired cached OAuth user token"),
    Allowed(_GOOGLE_AUTH, "build_google_credentials", "InstalledAppFlow.from_client_secrets_file", TOKEN_POST, 1,
            2, "A23, A24", "OAuth first sign-in flow; the credentials it yields refresh lazily inside execute()"),
    Allowed(_GOOGLE_AUTH, "build_google_credentials", "flow.run_local_server", TOKEN_POST, 1, 2, "A23",
            "first OAuth sign-in code exchange"),
    Allowed(_GOOGLE_AUTH, "user_delegated_credentials", "with_subject", TOKEN_POST, 1, 2, "A22",
            "per-user delegated copy; lazy JWT bearer grant on first use"),
    Allowed(_GOOGLE_AUTH, "user_delegated_credentials", "with_scopes", TOKEN_POST, 1, 2, "A22",
            "per-user copy narrowed to the read scopes; lazy JWT bearer grant on first use"),
    Allowed(_GOOGLE_CLIENT, "GoogleWorkspaceClient._scoped_credentials", "with_scopes", TOKEN_POST, 1, 2, "A22",
            "credentials narrowed to one API's scopes; lazy token exchange on first use"),
    Allowed(_NOTIFY, "_send_webhook", "requests.post", "POST", 1, 5, "A14",
            "operator-configured Teams or Slack webhook, redacted"),
    Allowed(_NOTIFY, "_send_jira", "requests.post", "POST", 1, 5, "A16",
            "operator-configured Jira issue create, redacted"),
    Allowed(_NOTIFY, "_send_github", "requests.post", "POST", 2, 5, "A18, A19",
            "operator-configured GitHub issue comment and issue create, redacted"),
)



@dataclass(frozen=True)
class Guarded:
    """A variable-method site that is GET-only because the method passed a guard first.

    ``guard`` is ``membership:<NAME>`` (the function opens with ``if <param> not in <NAME>: raise``),
    ``call:<expr>`` (it opens with ``<expr>(<param>, ...)``) or ``callee:<Class>`` (the site's
    receiver is a parameter annotated ``<Class>``, whose own entry proves the guard).
    """

    path: str
    function: str
    call: str
    count: int
    method_param: str
    guard: str
    rows: str

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.path, self.function, self.call)


# Variable-method sites that are GET-only behind a guard: resolved, not allowed (inventory A8, A9).
GET_ONLY_GUARDED: tuple[Guarded, ...] = (
    Guarded("src/azure_tenant_audit/power_platform.py", "PowerPlatformClient.request", "self.session.request",
            1, "method", "membership:ALLOWED_METHODS", "A8"),
    Guarded("src/azure_tenant_audit/collectors/power_platform.py", "PowerPlatformCollector._safe_get",
            "client.request", 1, "method", "callee:PowerPlatformClient", "A9"),
)


def _call_name(func: ast.expr) -> str:
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _receiver(func: ast.expr) -> str:
    return ast.unparse(func.value) if isinstance(func, ast.Attribute) else ""


def _keyword(node: ast.Call, name: str) -> ast.expr | None:
    for keyword in node.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _literal_verb(value: ast.expr | None) -> str:
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value.upper()
    return VARIABLE


def _is_none(value: ast.expr | None) -> bool:
    return value is None or (isinstance(value, ast.Constant) and value.value is None)


def _target(value: ast.expr | None) -> str:
    return ast.unparse(value) if value is not None else ""


def _transport_imports(tree: ast.AST) -> dict[str, str]:
    """Local name -> ``module.name`` for every name imported from a transport module."""
    imports: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or not node.module:
            continue
        module = node.module
        if not any(module == root or module.startswith(root + ".") for root in _TRANSPORT_MODULES):
            continue
        for alias in node.names:
            imports[alias.asname or alias.name] = f"{module}.{alias.name}"
    return imports


def _method_arg(node: ast.Call) -> ast.expr | None:
    return node.args[0] if node.args else _keyword(node, "method")


def _method_arg_site(node: ast.Call) -> tuple[str, str]:
    url = node.args[1] if len(node.args) > 1 else _keyword(node, "url")
    return _literal_verb(_method_arg(node)), _target(url)


def _urllib_site(base: str, node: ast.Call) -> tuple[str, str] | None:
    """urllib ``Request`` (GET unless ``method=`` or a body says otherwise) and ``urlopen``."""
    first = node.args[0] if node.args else None
    data = node.args[1] if len(node.args) > 1 else _keyword(node, "data")
    if base == "Request":
        if not (node.args or node.keywords):
            return None
        method = _keyword(node, "method")
        if method is not None:
            return _literal_verb(method), _target(first)
        return ("GET" if _is_none(data) else "POST"), _target(first)
    if not _is_none(data):
        return "POST", _target(first)
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return "GET", _target(first)
    return VARIABLE, _target(first)


def _is_opener_constructor(node: ast.expr, imports: dict[str, str]) -> bool:
    """A call that builds a urllib opener: ``build_opener(...)`` or ``OpenerDirector()``, however imported."""
    if not isinstance(node, ast.Call):
        return False
    name = _call_name(node.func)
    if isinstance(node.func, ast.Name) and name in imports:
        name = imports[name].rpartition(".")[2]
    return name in _OPENER_CONSTRUCTORS


def _opener_names(tree: ast.AST, imports: dict[str, str]) -> frozenset[str]:
    """Every name or attribute the module binds to a urllib opener (module-wide, fail closed)."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
            targets, value = [node.target], node.value
        else:
            continue
        if value is not None and _is_opener_constructor(value, imports):
            names.update(ast.unparse(target) for target in targets)
    return frozenset(names)


def _classify_import(node: ast.Call, origin: str) -> tuple[str, str] | None:
    """A bare-name call to something imported from a transport module."""
    module, _, base = origin.rpartition(".")
    first = node.args[0] if node.args else None
    if base in _VERB_METHODS:
        return base.upper(), _target(first or _keyword(node, "url"))
    if base == "get":
        return "GET", _target(first or _keyword(node, "url"))
    if module.startswith("urllib") and base in {"Request", "urlopen"}:
        return _urllib_site(base, node)  # resolved by origin, so ``urlopen as send`` is still seen
    if base == "request" or base == "Request":
        return _method_arg_site(node)
    if base in _NON_SENDING_IMPORTS or base.endswith(("Error", "Exception", "Warning", "Handler")):
        return None
    return VARIABLE, _target(first)


def _classify(
    node: ast.Call, imports: dict[str, str] | None = None, openers: frozenset[str] = frozenset()
) -> tuple[str, str] | None:
    """The method a call sends and its target expression, or None when it is not an HTTP call."""
    imports = imports or {}
    func = node.func
    name = _call_name(func)
    receiver = _receiver(func)
    first = node.args[0] if node.args else None
    if isinstance(func, ast.Name) and name in imports:
        return _classify_import(node, imports[name])
    if isinstance(func, ast.Name) and name == "getattr" and len(node.args) > 1:
        attr = node.args[1]
        if isinstance(attr, ast.Constant) and attr.value in _VERB_METHODS | {"send", "request"}:
            return (attr.value.upper() if attr.value in _VERB_METHODS else VARIABLE), ""
    if isinstance(func, ast.Attribute) and name in _VERB_METHODS:
        return name.upper(), _target(first or _keyword(node, "url"))
    if isinstance(func, ast.Attribute) and name == "get" and receiver in _GET_RECEIVERS:
        return "GET", _target(first or _keyword(node, "url"))
    if isinstance(func, ast.Attribute) and name in _METHOD_ARG_CALLS:
        return _method_arg_site(node)
    if isinstance(func, ast.Attribute) and name == "send":
        # Session.send(prepared) and any other ``.send``: the verb lives in the prepared request.
        return VARIABLE, _target(first)
    if isinstance(func, ast.Attribute) and name == "Request" and receiver in {"requests", "httpx"}:
        return _method_arg_site(node)
    if name in {"Request", "urlopen"}:
        # urllib.request.Request / urlopen reached by module attribute or an unresolved name.
        return _urllib_site(name, node)
    if isinstance(func, ast.Attribute) and name == "open" and (
        receiver in openers or "opener" in receiver.lower() or _is_opener_constructor(func.value, imports)
    ):
        # An opener ``open``: the receiver was bound to ``build_opener()`` / ``OpenerDirector()``
        # anywhere in the module, is called inline, or is spelt as an opener.
        return VARIABLE, _target(first)
    if name.startswith("acquire_token"):
        return TOKEN_POST, ""
    if isinstance(func, ast.Attribute) and name in _GOOGLE_TOKEN_CALLS:
        return TOKEN_POST, ""
    if name in _GOOGLE_CREDENTIAL_CALLS:
        return TOKEN_POST, ""
    return None


@dataclass
class Scan:
    sites: list[CallSite]
    functions: dict[tuple[str, str], ast.AST]


class _Scanner(ast.NodeVisitor):
    def __init__(self, path: str, imports: dict[str, str], openers: frozenset[str] = frozenset()) -> None:
        self.path = path
        self.imports = imports
        self.openers = openers
        self.scope: list[str] = []
        self.sites: list[CallSite] = []
        self.functions: dict[str, ast.AST] = {}
        self._called: set[int] = set()

    def _enter(self, node: ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.scope.append(node.name)
        if not isinstance(node, ast.ClassDef):
            self.functions[".".join(self.scope)] = node
        self.generic_visit(node)
        self.scope.pop()

    visit_ClassDef = _enter
    visit_FunctionDef = _enter
    visit_AsyncFunctionDef = _enter

    def _add(self, node: ast.AST, call: str, method: str, target: str, method_arg: str, receiver: str) -> None:
        self.sites.append(
            CallSite(
                path=self.path,
                function=".".join(self.scope) or "<module>",
                call=call,
                method=method,
                line=node.lineno,
                target=target,
                method_arg=method_arg,
                receiver=receiver,
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        self._called.add(id(node.func))
        found = _classify(node, self.imports, self.openers)
        if found is not None:
            method, target = found
            method_expr = _method_arg(node)
            self._add(node, ast.unparse(node.func), method, target,
                      ast.unparse(method_expr) if method_expr is not None else "", _receiver(node.func))
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # ``post = session.post`` or ``callback=session.post``: a verb taken as a value.
        if node.attr in _VERB_METHODS and id(node) not in self._called:
            self._add(node, ast.unparse(node), node.attr.upper(), "", "", _receiver(node))
        self.generic_visit(node)


def scan_source(source: str, path: str = "<memory>") -> Scan:
    tree = ast.parse(source, filename=path)
    imports = _transport_imports(tree)
    scanner = _Scanner(path, imports, _opener_names(tree, imports))
    scanner.visit(tree)
    return Scan(scanner.sites, {(path, name): node for name, node in scanner.functions.items()})


def _scan_src() -> Scan:
    scan = Scan([], {})
    for file in sorted(SRC.rglob("*.py")):
        rel = file.relative_to(REPO_ROOT).as_posix()
        found = scan_source(file.read_text(encoding="utf-8"), rel)
        scan.sites += found.sites
        scan.functions.update(found.functions)
    return scan


SCAN = _scan_src()
SITES, FUNCTIONS = SCAN.sites, SCAN.functions


def _parameters(function: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, ast.arg]:
    args = function.args
    return {arg.arg: arg for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs]}


def _rebound(function: ast.AST, name: str) -> bool:
    """True when ``name`` is assigned, deleted or shadowed anywhere in the function body."""
    own = set(map(id, _parameters(function).values())) if isinstance(
        function, (ast.FunctionDef, ast.AsyncFunctionDef)) else set()
    for child in ast.walk(function):
        if isinstance(child, ast.Name) and child.id == name and isinstance(child.ctx, (ast.Store, ast.Del)):
            return True
        if isinstance(child, ast.arg) and child.arg == name and id(child) not in own:
            return True
        if isinstance(child, (ast.Global, ast.Nonlocal)) and name in child.names:
            return True
    return False


def _first_statement(function: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.stmt | None:
    body = list(function.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        body = body[1:]
    return body[0] if body else None


def _opens_with_membership_guard(function: ast.AST, param: str, allowed: str) -> bool:
    if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    first = _first_statement(function)
    if not isinstance(first, ast.If) or first.orelse:
        return False
    test = first.test
    return (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name) and test.left.id == param
        and len(test.ops) == 1 and isinstance(test.ops[0], ast.NotIn)
        and isinstance(test.comparators[0], ast.Name) and test.comparators[0].id == allowed
        and any(isinstance(stmt, ast.Raise) for stmt in first.body)
    )


def _opens_with_guard_call(function: ast.AST, param: str, guard: str) -> bool:
    if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    first = _first_statement(function)
    return (
        isinstance(first, ast.Expr) and isinstance(first.value, ast.Call)
        and ast.unparse(first.value.func) == guard
        and bool(first.value.args) and isinstance(first.value.args[0], ast.Name)
        and first.value.args[0].id == param
    )


def method_flow_problems(site: CallSite, function: ast.AST | None, param: str, guard: str) -> list[str]:
    """Why the method a guarded site sends is not proven to have passed its guard, if it is not."""
    if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return [f"{site}: enclosing function not found"]
    params = _parameters(function)
    problems: list[str] = []
    if site.method_arg != param:
        problems.append(f"{site}: sends {site.method_arg!r}, not the guarded parameter {param!r}")
    if param not in params:
        problems.append(f"{site}: {param!r} is not a parameter of {site.function}")
    elif _rebound(function, param):
        problems.append(f"{site}: {param!r} is rebound after the guard can see it")
    kind, _, value = guard.partition(":")
    if kind == "membership" and not _opens_with_membership_guard(function, param, value):
        problems.append(f"{site}: {site.function} does not open with `if {param} not in {value}: raise`")
    elif kind == "call" and not _opens_with_guard_call(function, param, value):
        problems.append(f"{site}: {site.function} does not open with {value}({param}, ...)")
    elif kind == "callee":
        receiver = params.get(site.receiver)
        if receiver is None or receiver.annotation is None or ast.unparse(receiver.annotation) != value:
            problems.append(f"{site}: receiver {site.receiver!r} is not a parameter annotated {value}")
        elif _rebound(function, site.receiver):
            problems.append(f"{site}: receiver {site.receiver!r} is rebound")
    elif kind not in {"membership", "call", "callee"}:
        problems.append(f"{site}: unknown guard kind {guard!r}")
    return problems


def unclassified(scan: Scan) -> list[str]:
    """Every non-GET site, extra site or unproven guard that the allow-list and guard map do not cover."""
    allowed = {entry.key: entry for entry in ALLOW_LIST}
    guarded = {entry.key: entry for entry in GET_ONLY_GUARDED}
    problems: list[str] = []
    seen: Counter[tuple[str, str, str, str]] = Counter()
    seen_guarded: Counter[tuple[str, str, str]] = Counter()
    for site in scan.sites:
        if site.method == "GET":
            continue
        function = scan.functions.get((site.path, site.function))
        guard_entry = guarded.get((site.path, site.function, site.call))
        if site.method == VARIABLE and guard_entry is not None:
            seen_guarded[guard_entry.key] += 1
            problems += method_flow_problems(site, function, guard_entry.method_param, guard_entry.guard)
            continue
        entry = allowed.get(site.key)
        if entry is None:
            problems.append(f"unclassified non-GET call site: {site}")
            continue
        if entry.target_contains and entry.target_contains not in site.target:
            problems.append(f"{site} targets {site.target!r}, not {entry.target_contains!r}")
            continue
        if entry.guard:
            problems += method_flow_problems(site, function, "method", entry.guard)
        seen[site.key] += 1
    for key, count in seen.items():
        if count > allowed[key].count:
            problems.append(f"{key} has {count} non-GET call sites; the allow-list classifies {allowed[key].count}")
    for key, count in seen_guarded.items():
        if count > guarded[key].count:
            problems.append(f"{key} has {count} guarded variable-method sites; the guard map classifies "
                            f"{guarded[key].count}")
    return problems


def _names_in(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.add(child.id)
        elif isinstance(child, ast.Attribute):
            names.add(child.attr)
    return names


def test_every_non_get_call_site_under_src_is_in_the_frozen_allow_list() -> None:
    problems = unclassified(SCAN)
    assert not problems, (
        "Classify each site in ALLOW_LIST with its transport class and reason (after an M01-T02 "
        "inventory row and decision), or make it a GET:\n" + "\n".join(problems)
    )


def test_every_allow_list_entry_still_matches_its_call_sites() -> None:
    counts = Counter(site.key for site in SITES)
    stale = [f"{entry.key} expects {entry.count}, found {counts[entry.key]}"
             for entry in ALLOW_LIST if counts[entry.key] != entry.count]
    assert not stale, "the allow-list must not be wider than the code:\n" + "\n".join(stale)
    variable = Counter((site.path, site.function, site.call) for site in SITES if site.method == VARIABLE)
    stale_guards = [f"{entry.key} expects {entry.count}, found {variable[entry.key]}"
                    for entry in GET_ONLY_GUARDED if variable[entry.key] != entry.count]
    assert not stale_guards, "the guard map must not be wider than the code:\n" + "\n".join(stale_guards)


def test_every_allow_list_entry_names_a_transport_class_row_and_reason() -> None:
    keys = [entry.key for entry in ALLOW_LIST]
    assert len(keys) == len(set(keys))
    for entry in ALLOW_LIST:
        # Classes 2 token, 3 Graph $batch, 5 operator sink; class 1, 4 and 8 are GET or not HTTP,
        # class 6 (the retired model endpoint) is gone, class 7 (lab response path) has no HTTP
        # non-GET site today.
        assert entry.transport_class in {2, 3, 5}, entry
        assert entry.rows.strip() and entry.reason.strip(), entry


def test_variable_method_sites_resolve_to_their_guard() -> None:
    from azure_tenant_audit import graph, power_platform

    assert graph.READ_ONLY_METHODS == frozenset({"GET"})
    assert set(power_platform.ALLOWED_METHODS) == {"GET"}
    guarded_functions = {entry.function for entry in GET_ONLY_GUARDED}
    for entry in GET_ONLY_GUARDED:
        assert entry.rows.strip(), entry
        sites = [site for site in SITES if (site.path, site.function, site.call) == entry.key]
        for site in sites:
            assert not method_flow_problems(site, FUNCTIONS[(entry.path, entry.function)],
                                            entry.method_param, entry.guard)
        kind, _, value = entry.guard.partition(":")
        if kind == "callee":
            # The receiver's class must itself be a guarded entry whose guard opens its ``request``.
            assert f"{value}.request" in guarded_functions, entry
        if kind == "membership":
            assert value == "ALLOWED_METHODS"
    for entry in ALLOW_LIST:
        if entry.guard:
            assert entry.guard.startswith("call:"), entry


def test_the_graph_dispatch_applies_the_read_guard_before_anything_else() -> None:
    dispatch = FUNCTIONS[(_GRAPH, "GraphClient._request")]
    assert isinstance(dispatch, ast.FunctionDef)
    first = dispatch.body[0]
    assert isinstance(first, ast.Expr) and isinstance(first.value, ast.Call)
    assert ast.unparse(first.value.func) == "self._enforce_read_only"
    assert "read_only_violation" in _names_in(FUNCTIONS[(_GRAPH, "GraphClient._enforce_read_only")])


def test_the_scanner_sees_the_known_get_call_sites() -> None:
    # A blind scanner would pass the allow-list test vacuously; these are inventory rows A5, A7,
    # A10, A11, A12, A13 and A17.
    gets = {(site.path, site.function) for site in SITES if site.method == "GET"}
    assert {
        (_GRAPH, "GraphClient._follow_redirects"),
        (_GRAPH, "GraphClient.get_json"),
        ("src/azure_tenant_audit/power_bi.py", "PowerBIClient.get"),
        ("src/azure_tenant_audit/adapters/teams_admin_rest.py", "_read_attempt.read"),
        ("src/azure_tenant_audit/dns_lookup.py", "DohClient.query_detailed"),
        ("src/azure_tenant_audit/exposure_lookup.py", "RequestsHttpsFetcher.get_text"),
        (_NOTIFY, "_jira_search_existing"),
        (_NOTIFY, "_github_search_existing_issue"),
    } <= gets


@pytest.mark.parametrize(
    ("source", "method"),
    [
        ("import requests\ndef f(u):\n    return requests.put(u)\n", "PUT"),
        ("import requests\ndef f(u):\n    return requests.request('DELETE', u)\n", "DELETE"),
        ("def f(s, u):\n    return s.patch(u, json={})\n", "PATCH"),
        ("def f(self, m, u):\n    return self.session.request(m, u)\n", VARIABLE),
        ("def f(self, u):\n    return self.session.request(method='POST', url=u)\n", "POST"),
        ("from urllib.request import urlopen\ndef f(u):\n    return urlopen(u, data=b'x')\n", "POST"),
        ("from urllib.request import Request\ndef f(u):\n    return Request(u, data=b'x')\n", "POST"),
        ("from urllib.request import Request\ndef f(u):\n    return Request(u, method='PUT')\n", "PUT"),
        ("def f(conn):\n    conn.request('POST', '/x')\n", "POST"),
        ("def f(self):\n    return self._request('POST', f'{GRAPH_ROOT}/users')\n", "POST"),
        ("def f(app, flow):\n    return app.acquire_token_by_device_flow(flow)\n", TOKEN_POST),
        ("def f(creds):\n    return creds.with_subject('a@b.test')\n", TOKEN_POST),
        # Review REV-M01-T03 item 1: imported transport names and prepared-request sends.
        ("from requests import post\ndef f(u):\n    return post(u)\n", "POST"),
        ("from requests import post as p\ndef f(u):\n    return p(u, json={})\n", "POST"),
        ("from requests import request\ndef f(u):\n    return request('PUT', u)\n", "PUT"),
        ("from requests.api import delete\ndef f(u):\n    return delete(u)\n", "DELETE"),
        ("from httpx import patch\ndef f(u):\n    return patch(u)\n", "PATCH"),
        ("def f(session, prepared):\n    return session.send(prepared)\n", VARIABLE),
        ("import requests\ndef f(s, u):\n    return s.send(requests.Request('POST', u).prepare())\n", VARIABLE),
        ("import requests\ndef f(u):\n    return requests.Request('POST', u)\n", "POST"),
        ("from requests import Request\ndef f(u):\n    return Request('DELETE', u)\n", "DELETE"),
        ("from urllib3 import request\ndef f(u):\n    return request('POST', u)\n", "POST"),
        ("from requests import unknown_sender\ndef f(u):\n    return unknown_sender(u)\n", VARIABLE),
        ("def f(s):\n    post = s.post\n    return post\n", "POST"),
        ("def f(s, u):\n    return getattr(s, 'delete')(u)\n", "DELETE"),
        # Review REV-M01-T03 final round item 1: aliased urllib imports resolve by origin.
        ("from urllib.request import urlopen as send\ndef f(u):\n    return send(u, data=b'x')\n", "POST"),
        ("from urllib.request import Request as R\ndef f(u):\n    return R(u, data=b'x')\n", "POST"),
        ("from urllib.request import Request as R\ndef f(u):\n    return R(u, method='DELETE')\n", "DELETE"),
        # Review REV-M01-T03 final round item 2: opener sends tracked by provenance, not spelling.
        ("from urllib.request import build_opener\ndef f(u):\n    client = build_opener()\n"
         "    return client.open(u, data=b'x')\n", VARIABLE),
        ("import urllib.request\nclass C:\n    def __init__(self):\n"
         "        self.http = urllib.request.build_opener()\n"
         "    def f(self, u):\n        return self.http.open(u, data=b'x')\n", VARIABLE),
        ("from urllib.request import build_opener as mk\ndef f(u):\n    return mk().open(u, data=b'x')\n",
         VARIABLE),
    ],
)
def test_a_new_non_get_call_site_fails_until_it_is_classified(source: str, method: str) -> None:
    scan = scan_source(source, "src/auditex/new_module.py")
    assert method in [site.method for site in scan.sites]
    assert unclassified(scan), "a new non-GET site must not pass unclassified"


def test_an_extra_non_get_site_in_an_allow_listed_function_fails() -> None:
    source = (
        "import requests\n"
        "def _send_webhook(url, body):\n"
        "    requests.post(url, json=body)\n"
        "    requests.post(url + '/again', json=body)\n"
    )
    problems = unclassified(scan_source(source, _NOTIFY))
    assert any("allow-list classifies 1" in problem for problem in problems)


def test_the_batch_entry_does_not_cover_a_post_to_another_graph_path() -> None:
    source = (
        "class GraphClient:\n"
        "    def get_batch(self):\n"
        "        return self._request('POST', f'{GRAPH_ROOT}/users/u1/assignLicense', json={})\n"
    )
    assert unclassified(scan_source(source, _GRAPH))


def test_get_calls_and_dict_lookups_are_not_flagged() -> None:
    source = (
        "import requests\n"
        "def f(self, d, u):\n"
        "    requests.get(u)\n"
        "    self.session.get(u)\n"
        "    self.session.request('GET', u)\n"
        "    d.get('k')\n"
        "    self._request('GET', u)\n"
    )
    scan = scan_source(source, "src/auditex/new_module.py")
    assert all(site.method == "GET" for site in scan.sites)
    assert len(scan.sites) == 4
    assert unclassified(scan) == []


def test_imported_constructors_and_exceptions_are_not_sites() -> None:
    source = (
        "from requests import Session\n"
        "from requests.exceptions import RequestException\n"
        "from urllib.request import ProxyHandler, build_opener\n"
        "def f():\n"
        "    build_opener(ProxyHandler({}))\n"
        "    raise RequestException(Session())\n"
    )
    assert scan_source(source, "src/auditex/new_module.py").sites == []


_POWER_PLATFORM = "src/azure_tenant_audit/power_platform.py"
_GUARDED_REQUEST = (
    "class PowerPlatformClient:\n"
    "    def request(self, method, path):\n"
    "        if method not in ALLOWED_METHODS:\n"
    "            raise PowerPlatformError('method refused')\n"
    "{extra}"
    "        return self.session.request(method, path)\n"
)


def test_the_guarded_power_platform_request_passes_as_it_stands() -> None:
    assert unclassified(scan_source(_GUARDED_REQUEST.format(extra=""), _POWER_PLATFORM)) == []


@pytest.mark.parametrize(
    "extra",
    [
        # Review REV-M01-T03 item 2: an extra variable-method send after the guard.
        "        write_method = 'POST'\n        self.session.request(write_method, path)\n",
        # The guarded parameter rebound after the guard.
        "        method = 'POST'\n",
        # A second send of the guarded parameter: one more site than the guard map classifies.
        "        self.session.request(method, path + '/again')\n",
    ],
)
def test_an_extra_or_rebound_variable_method_send_in_a_guarded_function_fails(extra: str) -> None:
    problems = unclassified(scan_source(_GUARDED_REQUEST.format(extra=extra), _POWER_PLATFORM))
    assert problems, "an unguarded variable-method send must not pass"


def test_a_guarded_function_without_its_guard_fails() -> None:
    source = (
        "class PowerPlatformClient:\n"
        "    def request(self, method, path):\n"
        "        return self.session.request(method, path)\n"
    )
    assert unclassified(scan_source(source, _POWER_PLATFORM))


def test_the_collector_guard_needs_a_receiver_typed_as_the_guarded_client() -> None:
    template = (
        "class PowerPlatformCollector:\n"
        "    def _safe_get(client{annotation}, path, *, method=None):\n"
        "        return client.request(method, path)\n"
    )
    path = "src/azure_tenant_audit/collectors/power_platform.py"
    assert unclassified(scan_source(template.format(annotation=": PowerPlatformClient"), path)) == []
    assert unclassified(scan_source(template.format(annotation=""), path))
    assert unclassified(scan_source(template.format(annotation=": Any"), path))


def test_the_graph_dispatch_entry_needs_the_guard_on_the_sent_method() -> None:
    template = (
        "class GraphClient:\n"
        "    def _request(self, method, url, **kwargs):\n"
        "        self._enforce_read_only(method, url, kwargs)\n"
        "{extra}"
        "        return self.session.request({sent}, url, **kwargs)\n"
    )
    assert unclassified(scan_source(template.format(extra="", sent="method"), _GRAPH)) == []
    assert unclassified(scan_source(template.format(extra="        verb = 'POST'\n", sent="verb"), _GRAPH))
    assert unclassified(scan_source(template.format(extra="        method = 'PATCH'\n", sent="method"), _GRAPH))
