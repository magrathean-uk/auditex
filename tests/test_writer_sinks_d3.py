"""Classify every discovered writer and verify the routed call sites."""
from __future__ import annotations
import ast
import re
from pathlib import Path

from auditex.output_writers import MCP_TOOL_INVENTORY, SINK_INVENTORY, WRITER_INVENTORY, SinkEntry, sink_entry
from azure_tenant_audit.output_redaction import PROFILES
from sink_expansions import WILDCARD_EXPANSIONS

SRC = Path(__file__).resolve().parents[1] / "src"

# -- the writer inventory is checked against the source ---------------------------------------------------------------
#
# R15. The scan is an AST scan over every module under ``src/``. It finds the usual shapes of writing, printing and
# sending (``output_writers.SCAN_LIMITS`` lists what it cannot see) and every hit must be classified in
# ``SINK_INVENTORY``. It checks that a "routed" function reaches the redaction; it does not follow data.

_REDACTION_CALLS = {
    "redact_output", "redact_payload", "_final_pass", "_redact_report_content",
    "_redacted_report_payload", "_redact_envelope", "render_report",
}
_WRITE_NAMES = {
    "write_text", "write_bytes", "copy_private_file", "secure_write_text", "secure_write_json", "copyfile",
    "copyfileobj", "copy2", "copytree", "writelines", "write",
}
_NET_VERBS = {"get", "post", "put", "patch", "delete", "request", "head", "send", "sendmail", "send_message", "starttls"}
_NET_RECEIVER = re.compile(r"(^|\.)(requests|session|_session|opener|_opener|smtp|server|client|_client|conn|http|urllib|fetcher)$")
_MODE = re.compile(r"^[rwaxbt+U]{1,4}$")
_NET_CONSTRUCTORS = {"SMTP", "SMTP_SSL", "urlopen", "HTTPConnection", "HTTPSConnection"}


def _sink_kinds(call: ast.Call) -> set[str]:
    function = call.func
    name = function.id if isinstance(function, ast.Name) else function.attr if isinstance(function, ast.Attribute) else None
    receiver = ast.unparse(function.value) if isinstance(function, ast.Attribute) else ""
    kinds: set[str] = set()
    if name in {"open", "fdopen"}:
        modes = [a.value for a in call.args[:2] if isinstance(a, ast.Constant) and isinstance(a.value, str)]
        modes += [k.value.value for k in call.keywords if k.arg == "mode" and isinstance(k.value, ast.Constant) and isinstance(k.value.value, str)]
        if any(_MODE.match(m) and re.search(r"[wax+]", m) for m in modes):
            kinds.add("open-write")
        elif name == "open" and receiver in {"", "os"} and re.search(r"O_WRONLY|O_RDWR|O_CREAT|O_APPEND|flags", ast.unparse(call)):
            kinds.add("os.open-write")
        elif name == "fdopen" and not modes:
            kinds.add("fdopen-dynamic-mode")
        elif name == "open" and receiver == "" and len(call.args) >= 2 and not modes:
            kinds.add("open-dynamic-mode")
        if name == "open" and re.search(r"opener|urllib", receiver):
            kinds.add("net:open")
    if name in _WRITE_NAMES and (isinstance(function, ast.Attribute) or name not in {"write"}):
        kinds.add(f"write:{name}")
    if name in {"copy", "move"} and "shutil" in receiver:
        kinds.add(f"write:shutil.{name}")
    if name and name.startswith("write_private_"):
        kinds.add(f"write:{name}")
    if name == "dump" and receiver in {"json", "pickle", "yaml"}:
        kinds.add(f"dump:{receiver}")
    if name == "print" and not all(isinstance(a, ast.Constant) for a in call.args):
        kinds.add("print")
    if isinstance(function, ast.Attribute) and name in _NET_VERBS and _NET_RECEIVER.search(receiver):
        kinds.add(f"net:{name}")
    if name in _NET_CONSTRUCTORS:
        kinds.add(f"net:{name}")
    return kinds


def _scan_source(source: str) -> dict[str, set[str]]:
    """Every function (and the module body) of ``source`` that contains a sink call, with the kinds found."""
    found: dict[str, set[str]] = {}

    def visit(node: ast.AST, stack: list[str]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                visit(child, [*stack, child.name])
                continue
            if isinstance(child, ast.Call):
                kinds = _sink_kinds(child)
                if kinds:
                    found.setdefault(".".join(stack) or "<module>", set()).update(kinds)
            visit(child, stack)

    visit(ast.parse(source), [])
    return found


def _scan_tree() -> dict[tuple[str, str], set[str]]:
    hits: dict[tuple[str, str], set[str]] = {}
    for path in sorted(SRC.rglob("*.py")):
        module = ".".join(path.relative_to(SRC).with_suffix("").parts)
        for qualname, kinds in _scan_source(path.read_text(encoding="utf-8")).items():
            hits[(module, qualname)] = kinds
    return hits


def _functions(module: str) -> dict[str, ast.AST]:
    tree = ast.parse((SRC / (module.replace(".", "/") + ".py")).read_text(encoding="utf-8"))
    found: dict[str, ast.AST] = {}

    def visit(node: ast.AST, stack: list[str]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                found[".".join([*stack, child.name])] = child
                visit(child, [*stack, child.name])
            elif isinstance(child, ast.ClassDef):
                visit(child, [*stack, child.name])
            else:
                visit(child, stack)

    visit(tree, [])
    return found


def _call_names(function: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(function):
        if isinstance(node, ast.Call):
            target = node.func
            if isinstance(target, ast.Name):
                names.add(target.id)
            elif isinstance(target, ast.Attribute):
                names.add(target.attr)
    return names


def _function(spec: str) -> ast.AST:
    module, qualname = spec.split(":")
    return _functions(module)[qualname]


def test_the_scan_finds_the_sink_shapes_the_review_named() -> None:
    """R15: a writer through ``with open(..., "w")`` and the other shapes the first test missed are all seen."""
    shapes = {
        "def a(p, x):\n    with open(p, 'w') as stream:\n        stream.write(x)\n": {"open-write", "write:write"},
        "def b(p, x):\n    p.write_bytes(x)\n": {"write:write_bytes"},
        "def c(x):\n    print(x)\n": {"print"},
        "def d(x):\n    print('literal only')\n": set(),
        "def e(session, x):\n    session.post('u', json=x)\n": {"net:post"},
        "import smtplib\ndef f(x):\n    smtp = smtplib.SMTP('h')\n    smtp.send_message(x)\n": {"net:SMTP", "net:send_message"},
        "import json\ndef g(x, h):\n    json.dump(x, h)\n": {"dump:json"},
        "import urllib.request\ndef h(u):\n    urllib.request.urlopen(u)\n": {"net:urlopen"},
        "import os\ndef i(p):\n    return os.fdopen(os.open(p, os.O_WRONLY | os.O_CREAT), 'wb')\n": {"open-write", "os.open-write"},
        "class K:\n    def m(self, x):\n        self.session.get(x)\n": {"net:get"},
        "import requests\nrequests.post('u')\n": {"net:post"},
    }
    for source, expected in shapes.items():
        found = _scan_source(source)
        kinds = set().union(*found.values()) if found else set()
        assert kinds == expected, (source, kinds)
    assert "<module>" in _scan_source(list(shapes)[-1])
    assert "K.m" in _scan_source(list(shapes)[-2])


def test_every_sink_the_scan_finds_in_src_is_classified_and_every_entry_is_live() -> None:
    hits = _scan_tree()
    assert hits, "the scan found nothing: it is broken"
    unknown = sorted(f"{module}:{qualname} {sorted(kinds)}" for (module, qualname), kinds in hits.items() if sink_entry(module, qualname) is None)
    assert not unknown, (
        "these functions write, print or send but are not in SINK_INVENTORY (src/auditex/output_writers.py); "
        f"classify each as routed (and redact) or private (with the reason): {unknown}"
    )
    stale = [e.pattern for e in SINK_INVENTORY if not any(e.matches(m, q) for (m, q) in hits)]
    assert not stale, f"inventory entries that match no scanned function: {stale}"
    for entry in SINK_INVENTORY:
        assert entry.classification in {"routed", "profiled", "private"} and entry.reason, entry


def _is_wildcard(entry: SinkEntry) -> bool:
    return any(char in entry.pattern for char in "*?[")


def _unreviewed_wildcard_matches(
    functions: "set[tuple[str, str]] | list[tuple[str, str]]",
    inventory: "tuple[SinkEntry, ...]" = SINK_INVENTORY,
    expansions: "dict[str, tuple[str, ...]]" = WILDCARD_EXPANSIONS,
) -> list[str]:
    """Scanned functions classified only by a wildcard that nobody has listed in the frozen expansion (S9)."""
    unreviewed = []
    for module, qualname in sorted(functions):
        matching = [entry for entry in inventory if entry.matches(module, qualname)]
        if not matching or any(not _is_wildcard(entry) for entry in matching):
            continue  # unknown (reported by the classification test) or named explicitly
        spec = f"{module}:{qualname}"
        if not any(spec in expansions.get(entry.pattern, ()) for entry in matching):
            unreviewed.append(spec)
    return unreviewed


def test_a_wildcard_never_classifies_a_new_sink_function_silently() -> None:
    """S9: every function a wildcard pattern matches is listed in ``tests/sink_expansions.py``; the list is exact."""
    hits = set(_scan_tree())
    unreviewed = _unreviewed_wildcard_matches(hits)
    assert not unreviewed, (
        "these functions write, print or send and are matched only by a wildcard in SINK_INVENTORY that has not "
        "reviewed them: read each one, then add it to WILDCARD_EXPANSIONS in tests/sink_expansions.py (it is private, "
        "with the wildcard's reason) or give it its own explicit SinkEntry (routed or private, with a reason): "
        f"{unreviewed}"
    )
    wildcards = {entry.pattern: entry for entry in SINK_INVENTORY if _is_wildcard(entry)}
    assert set(WILDCARD_EXPANSIONS) == set(wildcards), (sorted(set(WILDCARD_EXPANSIONS) ^ set(wildcards)))
    for pattern, listed in WILDCARD_EXPANSIONS.items():
        assert list(listed) == sorted(listed), f"{pattern}: keep the expansion sorted"
        current = sorted(f"{m}:{q}" for (m, q) in hits if wildcards[pattern].matches(m, q))
        assert list(listed) == current, f"{pattern}: stale expansion (removed or renamed function): {sorted(set(listed) ^ set(current))}"


def test_the_wildcard_check_catches_the_review_s9_example() -> None:
    new = ("azure_tenant_audit.output", "new_customer_export")
    source = "from pathlib import Path\ndef new_customer_export(p, payload):\n    p.write_text(payload)\n"
    assert "write:write_text" in _scan_source(source)["new_customer_export"]
    assert sink_entry(*new) is not None  # the broad wildcard does match it...
    assert _unreviewed_wildcard_matches({new}) == ["azure_tenant_audit.output:new_customer_export"]  # ...but the check refuses
    explicit = (*SINK_INVENTORY, SinkEntry("azure_tenant_audit.output:new_customer_export", "private", "reviewed: test only"))
    assert _unreviewed_wildcard_matches({new}, explicit) == []
    listed = {**WILDCARD_EXPANSIONS, "azure_tenant_audit.output:*": (*WILDCARD_EXPANSIONS["azure_tenant_audit.output:*"], "azure_tenant_audit.output:new_customer_export")}
    assert _unreviewed_wildcard_matches({new}, expansions=listed) == []


def test_every_routed_entry_reaches_the_redaction() -> None:
    for entry in SINK_INVENTORY:
        if entry.classification != "routed":
            continue
        assert entry.via, entry
        via = _function(entry.via)
        assert _call_names(via) & _REDACTION_CALLS, f"{entry.via} does not call the redaction"
        module, qualname = entry.pattern.split(":")
        if entry.via != entry.pattern:
            # Reached only through ``via``: the sink function is called from the function that redacts.
            assert qualname.split(".")[-1] in _call_names(via), f"{entry.via} does not call {qualname}"
    # The helpers the routed writers delegate to must themselves reach the shared function.
    for helper in ("auditex.reporting:_final_pass", "auditex.cli:_redact_report_content", "auditex.cli:_redacted_report_payload", "auditex.notify:_redact_envelope"):
        assert _call_names(_function(helper)) & {"redact_output", "redact_payload"}, helper


def test_every_inventoried_writer_exists_and_every_shareable_one_calls_the_redaction() -> None:
    for entry in WRITER_INVENTORY:
        assert entry.audience
        functions = _functions(entry.module)
        if entry.qualname.endswith(".*"):
            assert any(name.startswith(entry.qualname[:-1]) for name in functions), entry
            continue
        assert entry.qualname in functions, f"inventory names a function that does not exist: {entry}"
        if entry.kind == "shareable":
            assert entry.profile in PROFILES
            assert _call_names(functions[entry.qualname]) & _REDACTION_CALLS, f"{entry.qualname} does not redact"
        elif entry.kind == "profiled":
            assert entry.profile == "local"
            assert _call_names(functions[entry.qualname]) & {"preview_report", "redact_output"}
        else:
            assert entry.kind == "private" and entry.profile is None


def _profile_keywords(function: ast.AST, call_name: str) -> list[str]:
    return [ast.unparse(keyword.value) for call in ast.walk(function)
            if isinstance(call, ast.Call)
            and (call.func.id if isinstance(call.func, ast.Name) else getattr(call.func, "attr", None)) == call_name
            for keyword in call.keywords if keyword.arg == "profile"]


def test_profiled_report_routes_choose_their_audience() -> None:
    from auditex.notify import NOTIFY_PROFILE

    assert NOTIFY_PROFILE == "customer_pack"
    assert _profile_keywords(_function("auditex.exporters:_run_builtin"), "render_report") == ["PROFILE_SHAREABLE"]
    assert _profile_keywords(_function("auditex.mcp_server:preview_report"), "_preview_report") == ["PROFILE_SHAREABLE"]
    assert "PROFILE_CUSTOMER_PACK" in _profile_keywords(_function("auditex.reporting:write_enterprise_handoff_pack"), "preview_report")
    for name in ("preview_report", "render_report"):
        function = _functions("auditex.reporting")[name]
        assert isinstance(function, ast.FunctionDef)
        defaults = dict(zip((arg.arg for arg in function.args.kwonlyargs), function.args.kw_defaults))
        assert ast.unparse(defaults["profile"]) == "PROFILE_LOCAL"


def test_every_mcp_tool_is_classified_and_every_routed_one_redacts_its_response() -> None:
    from auditex import mcp_server

    handlers = set(mcp_server.tool_handlers())
    inventory = {entry.tool: entry for entry in MCP_TOOL_INVENTORY}
    assert len(inventory) == len(MCP_TOOL_INVENTORY)
    assert handlers == set(inventory), (sorted(handlers - set(inventory)), sorted(set(inventory) - handlers))
    functions = _functions("auditex.mcp_server")
    for entry in MCP_TOOL_INVENTORY:
        assert entry.classification in {"routed", "no_evidence", "operator_config", "diagnostic"}, entry
        if entry.classification != "routed":
            assert entry.reason, entry
            continue
        function = functions[entry.function]
        if entry.via:
            assert entry.via.split(":")[1].split(".")[-1] in _call_names(function) or "send_notification" in _call_names(function) or "_preview_report" in _call_names(function), entry
            assert _call_names(_function(entry.via)) & _REDACTION_CALLS, entry
        else:
            assert "redact_payload" in _call_names(function) or _delegates_to_a_redacting_function(function, functions), entry
            profiles = _profile_keywords(function, "redact_payload")
            calls = [node for node in ast.walk(function) if isinstance(node, ast.Call)
                     and isinstance(node.func, ast.Name) and node.func.id == "redact_payload"]
            assert len(profiles) == len(calls)
            assert all(profile == "PROFILE_SHAREABLE" for profile in profiles), entry


def _delegates_to_a_redacting_function(function: ast.AST, functions: dict[str, ast.AST]) -> bool:
    return any(
        name in functions and name != getattr(function, "name", "") and "redact_payload" in _call_names(functions[name])
        for name in _call_names(function)
    )


def test_the_report_commands_that_print_or_write_payloads_go_through_the_one_emitter() -> None:
    source = (SRC / "auditex" / "cli.py").read_text(encoding="utf-8")
    assert source.count("_emit_report_payload(") == 7  # the definition, analyze, api-calls, permissions, proof-table, handoff and the setup guide
    # The only opt-out is the setup guide's emitter call (the definition's own default is ``redact: bool = True``).
    assert source.count("output_path=output_path, redact=False)") == 1
