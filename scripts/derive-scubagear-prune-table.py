#!/usr/bin/env python3
"""Derive the internal ScubaGear pruning table from pinned Rego and validated shapes.

This is an offline, conservative scan of the pinned OPA parser AST. It never invokes ScubaGear.
"""
from __future__ import annotations

import inspect
import json
import os
import subprocess
import sys
import tempfile
from collections import deque
from hashlib import sha256
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from auditex.scuba_projection import PACK_SHAPE_DIGESTS, _json  # noqa: E402
from azure_tenant_audit.argument_parser import build_argument_parser  # noqa: E402

PINNED_REVISION = "2446ad723b7f55031cc02c8aca244d731d468cba"
SECTIONS = ("SPO_tenant", "accepted_domains", "authorization_policies", "conditional_access_policies",
            "dkim_config", "dkim_records", "dmarc_records", "meeting_policies", "org_config",
            "privileged_roles", "service_plans", "spf_records", "transport_config")
PRUNE_REASONS = ("reads_unvalidated_field", "whole_object_use", "unresolved_reference", "no_rego_reader")
# Human adjudication is permitted only for an unresolved use at the pinned location.
ADJUDICATIONS: dict[str, tuple[str, str]] = {}


def shape_paths(descriptor: object) -> tuple[str, ...]:
    """Enumerate the object and array paths in a canonical shape descriptor."""
    result: set[str] = set()

    def visit(node: object, base: str) -> None:
        if isinstance(node, str) and node[:1] in {'{', '[', '"'}:
            try:
                visit(json.loads(node), base)
                return
            except json.JSONDecodeError:
                pass
        if isinstance(node, dict):
            if "object" in node and len(node) == 1:
                for key, child in node["object"].items():
                    path = base + "." + key if base else key
                    result.add(path)
                    visit(child, path)
            elif "array" in node and len(node) == 1:
                for child in node["array"]:
                    visit(child, base + "[]")

    visit(descriptor, "")
    return tuple(sorted(result))


def shape_kinds(descriptor: object) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    def visit(node: object, path: str) -> None:
        if isinstance(node, str) and node[:1] in {'{', '[', '"'}:
            try:
                visit(json.loads(node), path)
                return
            except json.JSONDecodeError:
                pass
        if isinstance(node, dict) and set(node) == {"object"}:
            result.setdefault(path, set()).add("empty_object" if not node["object"] else "object")
            for key, child in node["object"].items():
                visit(child, path + "." + key if path else key)
        elif isinstance(node, dict) and set(node) == {"array"}:
            result.setdefault(path, set()).add("array")
            for child in node["array"]:
                visit(child, path + "[]")
        else:
            result.setdefault(path, set()).add("null" if node == "NoneType" else "leaf")
    visit(descriptor, "")
    return result


def verdict_of(row: dict) -> str:
    """Recompute the decision from a row's evidence; never trust its stored verdict."""
    return _decision(row)[0]


def _decision(row: dict) -> tuple[str, str]:
    reads, validated = set(row["rego_read"]), set(row["validated"])
    if not reads:
        return "withheld", "no_rego_reader"
    for read in reads:
        path = read
        while path:
            if path not in validated and path != "[]" and not path.endswith("[]"):
                return "withheld", "reads_unvalidated_field"
            if "." in path:
                path = path.rsplit(".", 1)[0]
            elif path.endswith("[]"):
                path = path[:-2]
            else:
                path = ""
    classes = {entry.split(":", 1)[0] for entry in row["adjudicated"]}
    if "whole_object" in classes:
        return "withheld", "whole_object_use"
    if "unresolved" in classes:
        return "withheld", "unresolved_reference"
    return "prunable", ""


def _ast_nodes(value: object):
    if isinstance(value, dict):
        if "type" in value:
            yield value
        for key, child in value.items():
            if key != "location":
                yield from _ast_nodes(child)
    elif isinstance(value, list):
        for child in value:
            yield from _ast_nodes(child)


def _ast_contexts(value: object, parent=None, index=None, ancestors=()):
    if isinstance(value, dict):
        if "type" in value:
            yield value, parent, index, ancestors
        for key, child in value.items():
            if key == "location":
                continue
            trail = (*ancestors, (value, key))
            if isinstance(child, list):
                for offset, item in enumerate(child):
                    yield from _ast_contexts(item, value, offset, trail)
            else:
                yield from _ast_contexts(child, value, key, trail)
    elif isinstance(value, list):
        for offset, item in enumerate(value):
            yield from _ast_contexts(item, parent, offset, ancestors)


def _ast_ref(term: object) -> list[str | int | float] | None:
    if not isinstance(term, dict):
        return None
    if term.get("type") == "var":
        return [term["value"]]
    if term.get("type") != "ref":
        return None
    parts = term.get("value", [])
    if not isinstance(parts, list) or any(not isinstance(part, dict) or
                                          part.get("type") not in {"var", "string", "number"} for part in parts):
        return None
    return ["[]" if part["type"] == "number" or part["type"] == "var" and
            part["value"].startswith("$") and part["value"][1:].isdigit()
            else part["value"] for part in parts]


def _ast_name(term: object) -> str | None:
    parts = _ast_ref(term)
    return ".".join(map(str, parts)) if parts else None


def _ast_terms(expression: dict) -> list[dict]:
    terms = expression.get("terms", {})
    if isinstance(terms, list):
        return terms
    if isinstance(terms, dict) and "symbols" in terms:
        return terms["symbols"]
    return [terms] if isinstance(terms, dict) else []


def _ast_expressions(value: object):
    if isinstance(value, dict):
        if "terms" in value:
            yield value
        for key, child in value.items():
            if key != "location":
                yield from _ast_expressions(child)
    elif isinstance(value, list):
        for child in value:
            yield from _ast_expressions(child)


def _ast_calls(value: object):
    yield from (node for node in _ast_nodes(value) if node.get("type") == "call")
    for expression in _ast_expressions(value):
        terms = expression.get("terms")
        if isinstance(terms, list) and len(terms) > 1:
            yield {"value": terms, "location": expression.get("location", {})}


def _ast_location(node: dict, path: str) -> str:
    return f"{path}:{node.get('location', {}).get('row', 0)}"


def _ast_path(parts: tuple | list) -> str:
    return "".join(part if part == "[]" else "." + str(part) for part in parts).lstrip(".")


def _ast_origin(term: object, section: str, trace: dict[str, tuple]) -> tuple | None:
    parts = _ast_ref(term)
    if not parts:
        return None
    if parts[:2] == ["input", section]:
        return tuple(parts[2:])
    if parts[0] in trace:
        return (*trace[parts[0]], *parts[1:])
    if len(parts) >= 3 and parts[0] == "data" and parts[-1] in trace:
        return trace[parts[-1]]
    return None


def _parse_modules(sources: dict[str, str], rego_dir: Path | None) -> dict[str, dict]:
    opa = os.environ.get("AUDITEX_TEST_OPA")
    if not opa or not Path(opa).is_file():
        raise FileNotFoundError("AUDITEX_TEST_OPA must point to pinned OPA 1.20.2")
    version = subprocess.run([opa, "version"], capture_output=True, text=True, check=False)
    if version.returncode or "Version: 1.20.2" not in version.stdout:
        raise ValueError("AUDITEX_TEST_OPA must be pinned OPA 1.20.2")
    modules = {}
    with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as scratch:
        for name, source in sorted(sources.items()):
            target = rego_dir / name if rego_dir else Path(scratch) / name
            if rego_dir is None:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(source, encoding="utf-8")
            completed = subprocess.run(
                [opa, "parse", "--format", "json", "--json-include", "locations", str(target)],
                capture_output=True, text=True, check=False,
            )
            if completed.returncode:
                raise ValueError(f"OPA failed to parse {name}")
            modules[name] = json.loads(completed.stdout)
    return modules


def scan_rego(sources: dict[str, str], validated: dict[str, tuple[str, ...]],
              kinds: dict[str, dict[str, set[str]]] | None = None,
              *, rego_dir: Path | None = None) -> dict[str, dict]:
    """Trace only explicitly understood OPA AST patterns; withhold every other use."""
    modules = _parse_modules(sources, rego_dir)
    kinds = kinds or {section: {"": {"array"}, "[]": {"object"}} for section in SECTIONS}
    rules = [(path, rule) for path, module in modules.items() for rule in module.get("rules", [])]
    definitions: dict[str, list[tuple[str, dict]]] = {}
    for path, rule in rules:
        definitions.setdefault(rule["head"]["name"], []).append((path, rule))

    aliases: dict[str, dict[str, tuple]] = {section: {} for section in SECTIONS}
    for _path, rule in rules:
        value = rule["head"].get("value")
        if not isinstance(value, dict):
            continue
        call = value
        suffix: tuple = ()
        if value.get("type") == "ref" and value.get("value", [{}])[0].get("type") == "call":
            call = value["value"][0]
            if len(value["value"]) > 1 and value["value"][1].get("value") == 0:
                suffix = ("[]",)
        if call.get("type") == "call" and _ast_name(call["value"][0]) == "object.get" and len(call["value"]) >= 3:
            key = call["value"][2]
            if _ast_ref(call["value"][1]) == ["input"] and key.get("type") == "string" and key["value"] in SECTIONS:
                aliases[key["value"]][rule["head"]["name"]] = suffix
        elif value.get("type") == "ref":
            parts = _ast_ref(value)
            if parts and parts[0] == "input" and len(parts) > 1 and parts[1] in SECTIONS:
                aliases[parts[1]][rule["head"]["name"]] = tuple(parts[2:])

    literal_arguments: dict[str, dict[str, set[str]]] = {}
    unknown_arguments: set[tuple[str, str]] = set()
    for _path, rule in rules:
        for call in _ast_calls(rule):
            values = call.get("value", [])
            if not values:
                continue
            name = _ast_name(values[0])
            for _callee_path, callee in definitions.get(name, []):
                for index, argument in enumerate(values[1:]):
                    parameters = callee["head"].get("args", [])
                    if index >= len(parameters):
                        continue
                    parameter = _ast_ref(parameters[index])
                    if not parameter or len(parameter) != 1:
                        continue
                    if argument.get("type") == "string":
                        literal_arguments.setdefault(name, {}).setdefault(parameter[0], set()).add(argument["value"])
                    elif argument.get("type") != "var" or argument.get("value") != parameter[0]:
                        unknown_arguments.add((name, parameter[0]))

    found = {section: {"reads": set(), "evidence": set(), "uses": set()} for section in SECTIONS}
    for path, module in modules.items():
        for imported in module.get("imports", []):
            parts = _ast_ref(imported.get("path"))
            if parts == ["input"]:
                for section in SECTIONS:
                    found[section]["uses"].add("unresolved:" + _ast_location(imported, path))
        for node, parent, index, _trail in _ast_contexts(module.get("rules", [])):
            if node.get("type") != "ref":
                continue
            parts = node.get("value", [])
            if not parts or parts[0].get("type") != "var" or parts[0].get("value") != "input":
                continue
            if len(parts) > 1 and parts[1].get("type") != "string":
                for section in SECTIONS:
                    found[section]["uses"].add("unresolved:" + _ast_location(node, path))
            if len(parts) == 1:
                values = parent.get("value") if isinstance(parent, dict) and parent.get("type") == "call" else None
                safe_get = (values and index == 1 and _ast_name(values[0]) == "object.get" and
                            len(values) > 2 and values[2].get("type") == "string")
                if not safe_get:
                    for section in SECTIONS:
                        found[section]["uses"].add("unresolved:" + _ast_location(node, path))
        for call in _ast_calls(module.get("rules", [])):
            values = call.get("value", [])
            if _ast_name(values[0]) == "object.get" and len(values) >= 3 and _ast_ref(values[1]) == ["input"]:
                if values[2].get("type") != "string":
                    for section in SECTIONS:
                        found[section]["uses"].add("unresolved:" + _ast_location(call, path))

    queue = deque((path, rule, section, (), 0) for path, rule in rules for section in SECTIONS)
    visited = set()
    while queue:
        path, rule, section, seeds, depth = queue.popleft()
        state = (path, rule["head"]["name"], rule.get("location", {}).get("row"), section, seeds)
        if state in visited:
            continue
        visited.add(state)
        if depth > 8:
            found[section]["uses"].add("unresolved:" + _ast_location(rule, path))
            continue
        trace = dict(aliases[section])
        trace.update(dict(seeds))
        for imported in modules[path].get("imports", []):
            parts = _ast_ref(imported.get("path"))
            if parts and parts[:2] == ["input", section]:
                alias = imported.get("alias")
                if isinstance(alias, dict):
                    alias = alias.get("value")
                trace[alias or parts[-1]] = tuple(parts[2:])
        for _ in range(10):
            changed = False
            for expression in _ast_expressions(rule):
                every = expression.get("terms")
                if isinstance(every, dict) and "domain" in every:
                    origin = _ast_origin(every["domain"], section, trace)
                    target = _ast_ref(every.get("value"))
                    if origin is not None:
                        if every.get("key") is not None:
                            found[section]["uses"].add("whole_object:" + _ast_location(expression, path))
                        elif not target or len(target) != 1:
                            found[section]["uses"].add("unresolved:" + _ast_location(expression, path))
                        elif trace.get(target[0]) != (*origin, "[]"):
                            trace[target[0]] = (*origin, "[]")
                            changed = True
                terms = _ast_terms(expression)
                if len(terms) == 1 and terms[0].get("type") == "call":
                    terms = terms[0].get("value", [])
                if len(terms) < 3:
                    continue
                operation = _ast_name(terms[0])
                if operation not in {"assign", "eq", "equal", "internal.member_2", "internal.member_3"}:
                    continue
                origin = _ast_origin(terms[-1], section, trace)
                target = _ast_ref(terms[1])
                if origin is None or not target or len(target) != 1:
                    continue
                if operation in {"internal.member_2", "internal.member_3"}:
                    origin = (*origin, "[]")
                if trace.get(target[0]) != origin:
                    trace[target[0]] = origin
                    changed = True
            if not changed:
                break

        for node in _ast_nodes(rule):
            if node.get("type") != "ref":
                continue
            origin = _ast_origin(node, section, trace)
            parts = _ast_ref(node)
            if origin is None or not parts:
                continue
            base = () if parts[:2] == ["input", section] else trace.get(parts[0], ())
            suffix = parts[2:] if parts[:2] == ["input", section] else parts[1:]
            if suffix:
                variable_keys = [part["value"] for part in node.get("value", [])[1:]
                                 if part.get("type") == "var" and not part["value"].startswith("$")]
                if any(key not in literal_arguments.get(rule["head"]["name"], {}) or
                       (rule["head"]["name"], key) in unknown_arguments for key in variable_keys):
                    found[section]["uses"].add("unresolved:" + _ast_location(node, path))
                    continue
                path_parts = [*base]
                for part in suffix:
                    if isinstance(part, (int, float)) or part == "_":
                        path_parts.append("[]")
                    elif isinstance(part, str) and part in literal_arguments.get(rule["head"]["name"], {}):
                        literals = literal_arguments[rule["head"]["name"]][part]
                        if len(literals) == 1 and (rule["head"]["name"], part) not in unknown_arguments:
                            path_parts.append(next(iter(literals)))
                        else:
                            found[section]["uses"].add("unresolved:" + _ast_location(node, path))
                    elif isinstance(part, str):
                        path_parts.append(part)
                    else:
                        found[section]["uses"].add("unresolved:" + _ast_location(node, path))
                # Indexing a section can return a whole object; the parent context decides safety.
                field = _ast_path(path_parts)
                if field and field != "[]":
                    found[section]["reads"].add(field)
                    found[section]["evidence"].add(_ast_location(node, path))
        for call in _ast_calls(rule):
            values = call.get("value", [])
            if not values:
                continue
            name = _ast_name(values[0])
            if name == "object.get" and len(values) >= 3:
                first, key = values[1:3]
                parts = _ast_ref(first)
                if key.get("type") == "string":
                    if parts == ["input"] and key["value"] == section:
                        found[section]["evidence"].add(_ast_location(call, path))
                    elif parts and parts[0] in trace:
                        field = _ast_path((*trace[parts[0]], *parts[1:], key["value"]))
                        found[section]["reads"].add(field)
                        found[section]["evidence"].add(_ast_location(call, path))
                elif _ast_origin(first, section, trace) is not None:
                    kind = "unresolved" if rule["head"].get("args") else "whole_object"
                    found[section]["uses"].add(kind + ":" + _ast_location(call, path))
            for index, argument in enumerate(values[1:]):
                origin = _ast_origin(argument, section, trace)
                if origin is None:
                    continue
                if name == "Count":
                    kind = kinds[section].get(_ast_path(origin), {"object"})
                    use = "cardinality" if kind == {"array"} else "leaf" if kind <= {"leaf", "null"} or kind == {"array", "null"} else "whole_object"
                    for callee_path, callee in definitions.get(name, []):
                        found[section]["uses"].add(use + ":" + _ast_location(callee["head"], callee_path))
                for callee_path, callee in definitions.get(name, []):
                    parameters = callee["head"].get("args", [])
                    if index < len(parameters):
                        parameter = _ast_ref(parameters[index])
                        if parameter and len(parameter) == 1:
                            queue.append((callee_path, callee, section, ((parameter[0], origin),), depth + 1))

        for expression in rule.get("body", []):
            terms = _ast_terms(expression)
            if len(terms) != 3 or _ast_name(terms[0]) != "assign" or _ast_ref(terms[1]) != ["Status"]:
                continue
            right = terms[2]
            if right.get("type") != "call" or _ast_name(right["value"][0]) not in {"equal", "internal.member_2"}:
                continue
            source = _ast_ref(right["value"][1])
            if source and source[0] in trace and len(source) > 1:
                for pair in rule["head"].get("key", {}).get("value", []):
                    if isinstance(pair, list) and len(pair) == 2 and pair[0].get("value") == "RequirementMet" and _ast_ref(pair[1]) == ["Status"]:
                        found[section]["uses"].add("leaf:" + _ast_location(pair[1], path))

        for node, parent, index, ancestors in _ast_contexts(rule):
            if node.get("type") not in {"ref", "var"} or parent and parent.get("type") == "ref":
                continue
            parts = _ast_ref(node)
            origin = _ast_origin(node, section, trace)
            if not parts or origin is None:
                continue
            variable_keys = [part["value"] for part in (node.get("value", []) if node.get("type") == "ref" else [])[1:]
                             if part.get("type") == "var" and not part["value"].startswith("$")]
            unresolved_key = any(key not in literal_arguments.get(rule["head"]["name"], {}) or
                                 len(literal_arguments[rule["head"]["name"]][key]) != 1 or
                                 (rule["head"]["name"], key) in unknown_arguments for key in variable_keys)
            if variable_keys and not unresolved_key:
                origin = tuple(next(iter(literal_arguments[rule["head"]["name"]][part]))
                               if part in variable_keys else part for part in origin)
            base = () if parts[:2] == ["input", section] else trace.get(parts[0], ())
            suffix = parts[2:] if parts[:2] == ["input", section] else parts[1:]
            location = _ast_location(node, path)
            if any(key == "args" for _ancestor, key in ancestors):
                continue
            if any(ancestor is rule["head"] and key in {"name", "ref"} for ancestor, key in ancestors):
                continue
            if parent is rule["head"] and index in {"ref", "args"}:
                continue
            node_kinds = kinds[section].get(_ast_path(origin), {"object"})
            operands = (parent.get("value") if parent and parent.get("type") == "call" else
                        parent.get("terms") if parent and isinstance(parent.get("terms"), list) else None)
            call = _ast_name(operands[0]) if operands and isinstance(index, int) and index != 0 else None
            if suffix:
                if not unresolved_key and node is rule["head"].get("value") and rule["head"].get("args") and (
                    node_kinds & {"object", "empty_object"} or "array" in node_kinds and
                    not kinds[section].get(_ast_path((*origin, "[]")), {"leaf"}) <= {"leaf", "null"}
                ):
                    found[section]["uses"].add("whole_object:" + location)
                if call in {"internal.member_2", "internal.member_3"} and index == 2 and "array" not in node_kinds:
                    found[section]["uses"].add("whole_object:" + location)
                if any(isinstance(part, str) and part not in {"_"} and
                       any(child.get("type") == "var" and child.get("value") == part for child in node.get("value", [])[1:])
                       for part in suffix):
                    unresolved = any(part not in literal_arguments.get(rule["head"]["name"], {}) or
                                     (rule["head"]["name"], part) in unknown_arguments
                                     for part in suffix if isinstance(part, str) and part != "_")
                    if unresolved:
                        found[section]["uses"].add("unresolved:" + location)
                if not unresolved_key and (node_kinds & {"object", "empty_object"} or "array" in node_kinds and
                                           not kinds[section].get(_ast_path((*origin, "[]")), {"leaf"}) <= {"leaf", "null"}):
                    null_comparison = (call in {"equal", "eq", "neq"} and
                                       any(value.get("type") == "null" for offset, value in enumerate(operands[1:], 1)
                                           if offset != index))
                    if call and call not in definitions and call not in {"object.get", "internal.member_2", "internal.member_3", "assign"} and not null_comparison:
                        found[section]["uses"].add("whole_object:" + location)
                    elif any(ancestor.get("type") == "call" and _ast_name(ancestor.get("value", [{}])[0]) in {"json.marshal", "json.filter", "sprintf", "object.union", "object.keys", "object.remove", "object.filter", "walk"}
                             for ancestor, _key in ancestors if isinstance(ancestor, dict)):
                        found[section]["uses"].add("whole_object:" + location)
                    elif call is None and not any(ancestor.get("type") == "object" and any(
                        isinstance(pair, list) and len(pair) == 2 and pair[0].get("value") in
                        {"ActualValue", "ReportDetails", "NearMisses", "MissingExclusionTypes", "ErrorDetails", "PolicyName"} and
                        any(child is node for child in _ast_nodes(pair[1])) for pair in ancestor.get("value", []))
                        for ancestor, _key in ancestors if isinstance(ancestor, dict)):
                        found[section]["uses"].add("whole_object:" + location)
                continue
            kind = node_kinds
            use = None
            if node is rule["head"].get("value") and rule["head"].get("args") and kind & {"object", "empty_object"}:
                use = "whole_object"
            elif parent and "domain" in parent and index in {"domain", "value"}:
                if index == "domain" and "array" not in kind:
                    use = "whole_object"
            elif call in {"internal.member_2", "internal.member_3"} and index in {1, 2}:
                is_some = any(isinstance(ancestor.get("terms"), dict) and ancestor["terms"].get("symbols") is not None and
                              ancestor["terms"].get("location", {}).get("text") == "c29tZQ=="
                              for ancestor, _key in ancestors if isinstance(ancestor, dict))
                if index == 1:
                    if not is_some:
                        use = "leaf" if kind <= {"leaf", "null"} else "whole_object"
                elif not is_some:
                    use = "leaf" if kind == {"array"} and kinds[section].get(_ast_path((*origin, "[]")), {"object"}) <= {"leaf", "null"} else "whole_object"
                elif "array" not in kind:
                    use = "whole_object"
            elif call in {"assign", "internal.assign"} and index in {1, 2}:
                pass
            elif call in {"equal", "eq", "neq"}:
                others = [value for offset, value in enumerate(operands[1:], 1) if offset != index]
                if len(others) == 1 and others[0].get("type") == "null":
                    use = "null_test"
                elif "leaf" in kind:
                    use = "leaf"
                else:
                    use = "whole_object"
            elif call in {"count", "Count"}:
                if kind == {"array"}:
                    use = "cardinality"
                elif kind <= {"object", "empty_object"}:
                    use = "whole_object" if "empty_object" in kind else "emptiness"
                else:
                    use = "leaf"
            elif call == "object.get" and index == 1:
                key = operands[2] if len(operands) > 2 else None
                if not key or key.get("type") != "string":
                    use = "unresolved"
            elif call in definitions:
                pass
            elif call is not None:
                use = "leaf" if kind <= {"leaf", "null"} else "whole_object"
            elif any(ancestor.get("type") == "call" and _ast_name(ancestor.get("value", [{}])[0]) in
                     {"sprintf", "json.marshal", "json.filter", "object.union", "object.keys", "object.remove",
                      "object.filter", "walk"} for ancestor, _key in ancestors if isinstance(ancestor, dict)):
                use = "whole_object"
            elif any(ancestor.get("type") == "object" and any(
                isinstance(pair, list) and len(pair) == 2 and pair[0].get("value") in
                {"ActualValue", "ReportDetails", "NearMisses", "MissingExclusionTypes", "ErrorDetails", "PolicyName"} and
                any(child is node for child in _ast_nodes(pair[1])) for pair in ancestor.get("value", []))
                for ancestor, _key in ancestors if isinstance(ancestor, dict)):
                use = "report_only"
            elif "leaf" in kind or kind == {"array"} and kinds[section].get(_ast_path((*origin, "[]"))) <= {"leaf", "null"}:
                use = "leaf"
            else:
                use = "whole_object"
            if use:
                found[section]["uses"].add(use + ":" + location)

    rows = {}
    unused = set(ADJUDICATIONS)
    for section in SECTIONS:
        item = found[section]
        adjudicated = []
        for use in item["uses"]:
            kind, location = use.split(":", 1)
            if kind == "unresolved" and location in ADJUDICATIONS:
                kind, _reason = ADJUDICATIONS[location]
                unused.discard(location)
            adjudicated.append(kind + ":" + location)
        row = {"rego_read": tuple(sorted(item["reads"])), "validated": validated[section],
               "verdict": "", "reason": "", "evidence": tuple(sorted(item["evidence"])),
               "adjudicated": tuple(sorted(set(adjudicated)))}
        row["verdict"], row["reason"] = _decision(row)
        rows[section] = row
    if unused:
        raise ValueError("Unused ScubaGear adjudication")
    return rows

def derive(rego_dir: Path, shapes: Path) -> str:
    manifest = {str(path.relative_to(rego_dir)): sha256(path.read_bytes()).hexdigest()
                for path in sorted(rego_dir.rglob("*.rego"))}
    if len(manifest) != 12:
        raise ValueError("Expected twelve pinned Rego files")
    descriptors = json.loads(shapes.read_text(encoding="utf-8"))["sections"]
    validated = {}
    for section in SECTIONS:
        accepted = PACK_SHAPE_DIGESTS[section]
        validated[section] = tuple(sorted({path for descriptor in descriptors[section]
                                           if sha256(_json(descriptor).encode()).hexdigest() in accepted
                                           for path in shape_paths(descriptor)}))
    sources = {name: (rego_dir / name).read_text(encoding="utf-8") for name in manifest}
    kinds: dict[str, dict[str, set[str]]] = {}
    for section in SECTIONS:
        kinds[section] = {}
        for descriptor in descriptors[section]:
            if sha256(_json(descriptor).encode()).hexdigest() in PACK_SHAPE_DIGESTS[section]:
                for path, node_kinds in shape_kinds(descriptor).items():
                    kinds[section].setdefault(path, set()).update(node_kinds)
    rows = scan_rego(sources, validated, kinds, rego_dir=rego_dir)
    digest = sha256("\n".join(sorted(d for section in SECTIONS for d in PACK_SHAPE_DIGESTS[section])).encode()).hexdigest()
    import pprint
    header = '"""Pinned, generated ScubaGear static pruning proof; regenerate with the internal script."""\n'
    header += 'from __future__ import annotations\n\nimport json\n\n'
    for name, value in (("PROOF_VERSION", 1), ("PINNED_REVISION", PINNED_REVISION),
                        ("REGO_SHA256", manifest), ("GATE_DIGEST", digest),
                        ("PRUNE_REASONS", PRUNE_REASONS), ("PRUNE_PROOF", rows)):
        if name == "REGO_SHA256":
            chunks = {key: tuple(value[index:index + 8] for index in range(0, len(value), 8))
                      for key, value in manifest.items()}
            header += ("REGO_SHA256 = {name: ''.join(parts) for name, parts in " +
                       pprint.pformat(chunks, width=110, sort_dicts=True) + ".items()}\n\n")
        else:
            header += name + " = " + pprint.pformat(value, width=110, sort_dicts=True) + "\n\n"
    header += inspect.getsource(shape_paths) + "\n" + inspect.getsource(verdict_of) + "\n" + inspect.getsource(_decision)
    return header


def main() -> int:
    parser = build_argument_parser(description=__doc__)
    parser.add_argument("rego_dir", type=Path)
    parser.add_argument("--shapes", type=Path, default=Path(__file__).resolve().parents[1] /
                        "tests/fixtures/scuba-projection-shapes-v7.json")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    result = derive(args.rego_dir, args.shapes)
    if args.out:
        args.out.write_text(result, encoding="utf-8")
    else:
        print(result, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
