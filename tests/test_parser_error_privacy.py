"""Parser failures must never echo any part of the supplied arguments."""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import contextlib
import copy
import importlib.util
import io
import inspect
import logging
import os
from pathlib import Path
import re
import subprocess
import sys
import traceback
from types import ModuleType
from unittest.mock import patch

import pytest

from auditex import cli as product_cli, model_training
from auditex.demo import build_demo_parser
from auditex.guided import build_guided_parser
from auditex.mcp_server import _build_mcp_parser
from azure_tenant_audit import cli as engine_cli


ROOT = Path(__file__).resolve().parents[1]
VENDORED = ROOT / "tenant-bootstrap" / "azure_tenant_audit"
SECRET = "SECRETVALUE-1234"
FIXED = "error: invalid arguments"


def _children(parser):
    yield parser
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for child in action.choices.values():
                yield from _children(child)


def _captured_parser(module, entry, argv):
    made = []
    original = module.build_argument_parser

    def capture(*args, **kwargs):
        parser = original(*args, **kwargs)
        made.append(parser)
        return parser

    # Bad argv stops before any command handler, network or credential access.
    with patch.object(module, "build_argument_parser", capture), contextlib.redirect_stderr(io.StringIO()):
        with pytest.raises(SystemExit):
            entry(argv)
    assert len(made) == 1
    return made[0]


def _vendored_parser(shared_helper):
    name = "_parser_privacy_bootstrap_shared" if shared_helper else "_parser_privacy_bootstrap_standalone"
    package = ModuleType(name)
    package.__path__ = [str(VENDORED)]
    if shared_helper:
        package.__path__.append(str(ROOT / "src" / "azure_tenant_audit"))
    sys.modules[name] = package
    spec = importlib.util.spec_from_file_location(f"{name}.cli", VENDORED / "cli.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.build_parser()


BUILDERS = [
    engine_cli.build_parser, build_guided_parser, build_demo_parser, _build_mcp_parser,
    *(getattr(product_cli, name) for name in sorted(vars(product_cli))
      if name.startswith("_build_") and name.endswith("_parser")),
]


# Maintenance scripts are scanned too. Capture their parsers before dispatch,
# so no script reads inputs or performs its normal work during these tests.
SCRIPT_BUILDERS = [
    ("annotate-oracle-cases.py", "main"),
    ("assess-scubagear-export.py", "main"),
    ("build-lab-model-cases.py", "main"),
    ("build-model-examples.py", "main"),
    ("build-oracle-cases.py", "main"),
    ("build-prowler-cases.py", "main"),
    ("derive-scuba-projection-shapes.py", "main"),
    ("derive-scubagear-prune-table.py", "main"),
    ("generate-explainer-baselines.py", "main"),
    ("generate-explainer.py", "main"),
    ("generate-rule-packs.py", "main"),
    ("run-model-benchmark.py", "parser"),
    ("score-adapter-checkpoints.py", "build_parser"),
    ("score-model-precheck.py", "main"),
    ("split-oracle-cases.py", "main"),
]


def _script_parser(filename, entry):
    from azure_tenant_audit.argument_parser import DiagnosticRedactingArgumentParser

    name = "_parser_privacy_script_" + filename.replace("-", "_").replace(".", "_")
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    if entry != "main":
        return getattr(module, entry)()

    class ParserCaptured(Exception):
        pass

    def capture(parser, *args, **kwargs):
        raise ParserCaptured(parser)

    parser_class = (module._parser_module.DiagnosticRedactingArgumentParser
                    if filename == "build-prowler-cases.py" else DiagnosticRedactingArgumentParser)
    with patch.object(parser_class, "parse_args", capture):
        try:
            module.main()
        except ParserCaptured as exc:
            return exc.args[0]
    raise AssertionError(f"{filename} did not parse arguments")


def _all_parsers():
    with patch.dict(os.environ, {"AUDITEX_ENABLE_RESPONSE": "1"}):
        roots = [builder() for builder in BUILDERS]
        roots.extend([
            _captured_parser(product_cli, product_cli.main, ["setup", "--bad-option"]),
            _captured_parser(product_cli, product_cli.main, ["doctor", "--bad-option"]),
            _captured_parser(model_training, model_training.training_main, []),
            _vendored_parser(False), _vendored_parser(True),
        ])
        roots.extend(_script_parser(filename, entry) for filename, entry in SCRIPT_BUILDERS)
    return [child for root in roots for child in _children(root)]


PARSERS = _all_parsers()


@pytest.mark.parametrize("parser", PARSERS, ids=lambda parser: parser.prog)
def test_discovered_parsers_use_the_factory(parser):
    assert parser.__class__.__name__ == "DiagnosticRedactingArgumentParser"
    assert parser.__class__.__module__.endswith(".argument_parser")
    assert parser.allow_abbrev is False


def _add_test_options(parser):
    for flags, kwargs in [
        (("--privacy-switch",), {"action": "store_true"}),
        (("-q",), {"action": "store_true"}),
        (("-z", "--privacy-int"), {"type": int}),
        (("--privacy-choice",), {"choices": ("valid",)}),
        (("-Talpha",), {"action": "store_true"}),
        (("-Tbeta",), {"action": "store_true"}),
    ]:
        if flags[0] not in parser._option_string_actions:
            parser.add_argument(*flags, **kwargs)


@pytest.mark.parametrize("parser", PARSERS, ids=lambda parser: parser.prog)
@pytest.mark.parametrize("argv", [
    [f"--privacy-switch=x --client-secret {SECRET}"],
    [f"--privacy-switch=x --client-secret={SECRET}"],
    [f"-qqq--client-secret {SECRET}"],
    [f"-qqq--client-secret={SECRET}"],
    [f"--privacy-int=--client-secret{SECRET}"],
    [f"-z{SECRET}"],
    ["--privacy-choice", SECRET],
    ["--privacy-int", SECRET],
    [f"--client-secret={SECRET}", "--privacy-int", "invalid"],
    [f"--out=x --client-secret={SECRET}", "--privacy-int", "invalid"],
    ["--privacy-int", "--privacy-switch", SECRET],
    ["-T", SECRET],
    ["--not-a-real-option", SECRET],
])
def test_all_parser_errors_hide_malformed_argument_values(parser, argv, capsys):
    # The extra options force argparse down each error path on every parser,
    # including parsers whose real options have no choices or short forms.
    _add_test_options(parser)
    with pytest.raises(SystemExit) as caught:
        parser.parse_args(argv)
    captured = capsys.readouterr()
    assert caught.value.code == 2
    assert captured.out == ""
    assert SECRET not in captured.out + captured.err + str(caught.value)
    assert captured.err == parser.format_usage() + FIXED + "\n"


@pytest.mark.parametrize("parser", PARSERS, ids=lambda parser: parser.prog)
@pytest.mark.parametrize("method", ["error", "exit", "print_message", "print_message_stdout"])
def test_direct_diagnostic_paths_hide_values(parser, method, capsys):
    if method.startswith("print_message"):
        parser._print_message(SECRET, sys.stdout if method.endswith("stdout") else sys.stderr)
    else:
        with pytest.raises(SystemExit) as caught:
            if method == "error":
                parser.error(SECRET)
            else:
                parser.exit(2, SECRET)
        assert caught.value.code == 2
        assert SECRET not in str(caught.value)
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err
    diagnostic = captured.out if method.endswith("stdout") else captured.err
    assert diagnostic == parser.format_usage() + FIXED + "\n"


@pytest.mark.parametrize("parser", PARSERS, ids=lambda parser: parser.prog)
@pytest.mark.parametrize("status,message", [(1, SECRET), (0, SECRET), (SECRET, None)])
def test_exit_never_leaks_a_status_or_reports_success_for_an_error(parser, status, message, capsys):
    with pytest.raises(SystemExit) as caught:
        parser.exit(status, message)
    captured = capsys.readouterr()
    assert caught.value.code == 2
    assert SECRET not in captured.out + captured.err + str(caught.value)
    assert captured.out == ""
    assert captured.err == parser.format_usage() + FIXED + "\n"


@pytest.mark.parametrize("parser", PARSERS, ids=lambda parser: parser.prog)
def test_subparsers_cannot_bypass_the_factory(parser):
    with pytest.raises(ValueError, match="shared argument parser factory"):
        parser.add_subparsers(parser_class=argparse.ArgumentParser)


@pytest.mark.parametrize("parser", PARSERS, ids=lambda parser: parser.prog)
@pytest.mark.parametrize("argv", [["--privacy-choice", SECRET], ["--privacy-int", SECRET]])
def test_parser_exceptions_have_no_secret_context_or_logged_traceback(parser, argv, capsys):
    _add_test_options(parser)
    stream = io.StringIO()
    logger = logging.Logger("parser-privacy")
    logger.addHandler(logging.StreamHandler(stream))
    try:
        parser.parse_args(argv)
    except SystemExit as exc:
        formatted = "".join(traceback.format_exception(exc))
        logger.exception("parser failed", exc_info=True)
        assert exc.code == 2
        assert SECRET not in formatted + stream.getvalue()
        assert exc.__cause__ is None
        assert exc.__context__ is None
    else:
        pytest.fail("invalid input did not exit")
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err + formatted + stream.getvalue()
    assert captured.err == parser.format_usage() + FIXED + "\n"


@pytest.mark.parametrize("parser", PARSERS, ids=lambda parser: parser.prog)
@pytest.mark.parametrize("method", ["parse_known_args", "parse_intermixed_args", "parse_known_intermixed_args"])
def test_argument_error_keeps_its_type_without_its_value(parser, method, capsys):
    _add_test_options(parser)
    if "intermixed" in method and any(
        action.nargs in (argparse.PARSER, argparse.REMAINDER)
        for action in parser._get_positional_actions()
    ):
        pytest.skip("argparse does not support intermixed parsing with subparsers or REMAINDER")
    previous = parser.exit_on_error
    parser.exit_on_error = False
    try:
        with pytest.raises(argparse.ArgumentError) as caught:
            getattr(parser, method)([f"-z{SECRET}"])
    finally:
        parser.exit_on_error = previous
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err + str(caught.value) + repr(caught.value)
    assert FIXED in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


@pytest.mark.parametrize("parser", PARSERS, ids=lambda parser: parser.prog)
@pytest.mark.parametrize("method", ["parse_args", "parse_known_args", "parse_intermixed_args", "parse_known_intermixed_args"])
def test_unknown_arguments_do_not_leak_from_exceptions(parser, method, capsys):
    # Isolate this path from each parser's required options, positionals and
    # subparsers. Intermixed parsing cannot handle the latter at all.
    parser = copy.deepcopy(parser)
    parser._actions[:] = [action for action in parser._actions if action.option_strings]
    parser._positionals._group_actions[:] = []
    for action in parser._actions:
        action.required = False
    for group in parser._mutually_exclusive_groups:
        group.required = False
    _add_test_options(parser)
    parser.exit_on_error = False
    unknown = f"--privacy-unknown={SECRET}"
    parse = getattr(parser, method)
    if "known" in method:
        # Known parsers deliberately return unrecognised arguments. Exercise
        # an error as well, with both the unknown token and a bad value present.
        _, remaining = parse([unknown])
        assert remaining == [unknown]
        argv = [unknown, f"-z{SECRET}"]
    else:
        argv = [unknown]
    stream = io.StringIO()
    logger = logging.Logger("parser-privacy-unknown")
    logger.addHandler(logging.StreamHandler(stream))
    try:
        parse(argv)
    except (argparse.ArgumentError, SystemExit) as exc:
        formatted = "".join(traceback.format_exception(exc))
        logger.exception("parser failed")
        if isinstance(exc, SystemExit):
            # Python 3.11 calls error() for unknown arguments even when
            # exit_on_error is false.
            assert "known" not in method and exc.code == 2
        else:
            assert FIXED in str(exc)
        captured = capsys.readouterr()
        assert SECRET not in (str(exc) + repr(exc.args) + formatted + stream.getvalue()
                              + captured.out + captured.err)
        assert exc.__cause__ is None
        assert exc.__context__ is None
    else:
        pytest.fail("invalid input did not raise")


def test_help_and_version_remain_available(capsys):
    from azure_tenant_audit.secret_hygiene import build_argument_parser

    parser = build_argument_parser(prog="privacy-test")
    parser.add_argument("--version", action="version", version="privacy-test 1.0")
    for flag, expected in [("--help", "usage: privacy-test"), ("--version", "privacy-test 1.0")]:
        with pytest.raises(SystemExit) as caught:
            parser.parse_args([flag])
        assert caught.value.code == 0
        captured = capsys.readouterr()
        assert expected in captured.out
        assert captured.err == ""


def test_prowler_script_help_needs_only_the_standard_library():
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-B", str(ROOT / "scripts" / "build-prowler-cases.py"), "--help"],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0
    assert "usage:" in result.stdout
    assert result.stderr == ""


def _parser_violations(tree, allowed_type_calls=frozenset()):
    violations = []
    constructors = {alias.asname or alias.name for node in ast.walk(tree)
                    if isinstance(node, ast.ImportFrom)
                    for alias in node.names
                    if alias.name in {"ArgumentParser", "DiagnosticRedactingArgumentParser"}}
    constructors.update({"ArgumentParser", "DiagnosticRedactingArgumentParser"})
    argparse_names = {alias.asname or "argparse" for node in ast.walk(tree)
                      if isinstance(node, ast.Import) for alias in node.names if alias.name == "argparse"}
    argparse_names.add("argparse")
    builtins_names = {alias.asname or "builtins" for node in ast.walk(tree)
                      if isinstance(node, ast.Import) for alias in node.names if alias.name == "builtins"}
    builtins_names.add("builtins")
    type_names = {alias.asname or "type" for node in ast.walk(tree)
                  if isinstance(node, ast.ImportFrom) and node.module == "builtins"
                  for alias in node.names if alias.name == "type"}
    type_names.add("type")
    factory_modules = {"argument_parser", "secret_hygiene"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            factory_modules.update(alias.asname for alias in node.names
                                   if alias.asname and alias.name in {
                                       "azure_tenant_audit.argument_parser", "azure_tenant_audit.secret_hygiene"})
        elif isinstance(node, ast.ImportFrom):
            factory_modules.update(alias.asname or alias.name for alias in node.names
                                   if alias.name in {"argument_parser", "secret_hygiene"})
    assignments = [node for node in ast.walk(tree) if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr))]
    # Follow simple module aliases so reflection cannot hide behind them.
    while True:
        before = len(argparse_names) + len(builtins_names) + len(factory_modules) + len(type_names)
        for node in assignments:
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = {part.id for target in targets for part in ast.walk(target)
                     if isinstance(part, ast.Name) and isinstance(part.ctx, ast.Store)}
            if isinstance(value, ast.Name) and value.id in argparse_names:
                argparse_names.update(names)
            if isinstance(value, ast.Name) and value.id in builtins_names:
                builtins_names.update(names)
            if ((isinstance(value, ast.Name) and value.id in type_names)
                    or (isinstance(value, ast.Attribute) and value.attr == "type"
                        and isinstance(value.value, ast.Name) and value.value.id in builtins_names)):
                type_names.update(names)
            if ((isinstance(value, ast.Name) and value.id in factory_modules)
                    or (isinstance(value, ast.Attribute) and value.attr in {"argument_parser", "secret_hygiene"})):
                factory_modules.update(names)
        if len(argparse_names) + len(builtins_names) + len(factory_modules) + len(type_names) == before:
            break

    def is_type_function(function):
        return ((isinstance(function, ast.Name) and function.id in type_names)
                or (isinstance(function, ast.Attribute) and function.attr == "type"
                    and isinstance(function.value, ast.Name) and function.value.id in builtins_names))

    type_aliases = {part.id for node in assignments
                    if isinstance(node.value, ast.Call) and is_type_function(node.value.func)
                    for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
                    for part in ast.walk(target) if isinstance(part, ast.Name) and isinstance(part.ctx, ast.Store)}
    while True:
        before = len(type_aliases)
        for node in assignments:
            if isinstance(node.value, ast.Name) and node.value.id in type_aliases:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                type_aliases.update(part.id for target in targets for part in ast.walk(target)
                                    if isinstance(part, ast.Name) and isinstance(part.ctx, ast.Store))
        if len(type_aliases) == before:
            break
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}

    def reflection_name(function):
        if isinstance(function, ast.Name) and function.id in {"getattr", "vars"}:
            return function.id
        if (isinstance(function, ast.Attribute) and function.attr in {"getattr", "vars"}
                and isinstance(function.value, ast.Name) and function.value.id in builtins_names):
            return function.attr
        return None

    factory_names = set()
    other_imports = set()
    shadowed_names = set()
    wildcard_import = False
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            trusted = (node.module in {"azure_tenant_audit.argument_parser", "azure_tenant_audit.secret_hygiene"}
                       or (node.level == 1 and node.module in {"argument_parser", "secret_hygiene"}))
            for alias in node.names:
                name = alias.asname or alias.name
                wildcard_import |= alias.name == "*"
                # The registry only counts calls using the canonical name.
                if alias.name == "build_argument_parser" and alias.asname and alias.asname != alias.name:
                    violations.append(node.lineno)
                if (node.module == "builtins" and alias.name in {"getattr", "vars"}
                        and alias.asname and alias.asname != alias.name):
                    violations.append(node.lineno)
                if trusted and alias.name == "build_argument_parser":
                    factory_names.add(name)
                else:
                    other_imports.add(name)
        elif isinstance(node, ast.Import):
            other_imports.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            shadowed_names.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            shadowed_names.add(node.name)
        elif isinstance(node, ast.arg):
            shadowed_names.add(node.arg)
    factory_names.difference_update(other_imports | shadowed_names)
    if wildcard_import:
        factory_names.clear()
    annotation_nodes = set()
    for node in ast.walk(tree):
        annotation = None
        if isinstance(node, (ast.arg, ast.AnnAssign)):
            annotation = node.annotation
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            annotation = node.returns
        if annotation is not None:
            annotation_nodes.update(id(part) for part in ast.walk(annotation))

    for node in ast.walk(tree):
        direct = (isinstance(node, ast.Attribute)
                  and node.attr in {"ArgumentParser", "DiagnosticRedactingArgumentParser"})
        direct |= isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in constructors
        if id(node) in annotation_nodes:
            # A type reference is harmless, but annotations can also execute
            # calls, including a parser constructor, without postponed evaluation.
            parent = parents.get(node)
            direct &= isinstance(parent, ast.Call) and parent.func is node
        indirect = (isinstance(node, ast.Call) and reflection_name(node.func) is not None
                    and ((node.args
                          and ((isinstance(node.args[0], ast.Name)
                                and node.args[0].id in argparse_names | builtins_names | factory_modules)
                               or (isinstance(node.args[0], ast.Attribute)
                                   and node.args[0].attr in {"argument_parser", "secret_hygiene"})))
                         or (reflection_name(node.func) == "getattr" and len(node.args) >= 2
                             and isinstance(node.args[1], ast.Constant)
                             and node.args[1].value in {"ArgumentParser", "build_argument_parser"})))
        factory_lookup = (isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant)
                          and node.slice.value == "build_argument_parser" and isinstance(node.value, ast.Call)
                          and reflection_name(node.value.func) == "vars")
        type_constructor = (isinstance(node, ast.Call) and isinstance(node.func, ast.Call)
                            and is_type_function(node.func.func))
        type_alias_call = (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                           and node.func.id in type_aliases and id(node) not in allowed_type_calls)
        type_base = (isinstance(node, ast.ClassDef) and any(
            (isinstance(base, ast.Call) and is_type_function(base.func))
            or (isinstance(base, ast.Name) and base.id in type_aliases)
            for base in node.bases))
        reflected_module = (isinstance(node, ast.Attribute) and node.attr == "__dict__"
                            and ((isinstance(node.value, ast.Name)
                                  and node.value.id in argparse_names | builtins_names | factory_modules)
                                 or (isinstance(node.value, ast.Attribute)
                                     and node.value.attr in {"argument_parser", "secret_hygiene"})))
        builtin_alias = (reflection_name(node) is not None
                         and not (isinstance(parents.get(node), ast.Call) and parents[node].func is node))
        factory_reference = ((isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
                              and node.id == "build_argument_parser")
                             or (isinstance(node, ast.Attribute) and node.attr == "build_argument_parser"))
        if factory_reference:
            parent = parents.get(node)
            call = parents.get(parent)
            subparser_keyword = (isinstance(parent, ast.keyword) and parent.arg == "parser_class"
                                 and isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                                 and call.func.attr == "add_subparsers")
            # Only a direct call or the checked parser_class argument can use
            # the factory. Storing or passing it could hide subsequent calls.
            factory_reference = not (
                isinstance(parent, ast.Call) and parent.func is node
                or subparser_keyword)
        override = False
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "add_subparsers":
            for keyword in node.keywords:
                if keyword.arg is None:
                    override = True
                elif keyword.arg == "parser_class":
                    value = keyword.value
                    safe = isinstance(value, ast.Name) and value.id in factory_names
                    override |= not safe
        if (direct or indirect or override or type_constructor or type_alias_call or type_base or factory_reference
                or factory_lookup or reflected_module or builtin_alias):
            violations.append(node.lineno)
    return violations


def _python_sources(roots):
    """Include extensionless Python entry points as well as .py modules."""
    for root in roots:
        for path in root.rglob("*"):
            if path.is_symlink() or not path.is_file():
                continue
            if path.suffix == ".py":
                yield path
            elif not path.suffix:
                with path.open("rb") as source:
                    shebang = source.readline(512)
                if shebang.startswith(b"#!") and re.search(
                    rb"(?:^|[/\s])python(?:\d+(?:\.\d+)*)?(?:\s|$)", shebang[2:], re.IGNORECASE
                ):
                    yield path


def _known_collection_type_calls(path, tree):
    # The redactor reconstructs sets and frozensets with their original
    # concrete type. This is the one non-parser use of a type-result alias;
    # verify its exact assignment and call before allowing it in this file.
    if path != ROOT / "src" / "azure_tenant_audit" / "output_redaction.py":
        return frozenset()
    redactor = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "_Redactor")
    walk = next(node for node in redactor.body if isinstance(node, ast.FunctionDef) and node.name == "walk")
    stores = [node for node in ast.walk(walk) if isinstance(node, ast.Name)
              and isinstance(node.ctx, ast.Store) and node.id == "collection_type"]
    assignments = [node for node in ast.walk(walk) if isinstance(node, ast.Assign)
                   and any(target is stores[0] for target in node.targets)] if len(stores) == 1 else []
    calls = [node for node in ast.walk(walk) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Name) and node.func.id == "collection_type"]
    expected_assignment = ast.parse("collection_type = type(value)").body[0]
    expected_call = ast.parse("collection_type(self.walk(item, controlled) for item in value)").body[0].value
    assert len(assignments) == len(calls) == 1
    assert ast.dump(assignments[0]) == ast.dump(expected_assignment)
    assert ast.dump(calls[0]) == ast.dump(expected_call)
    return frozenset({id(calls[0])})


@pytest.mark.parametrize("source", [
    "import argparse\nclass P(argparse.ArgumentParser): pass\nP()",
    "import argparse\nAP = argparse.ArgumentParser\nAP()",
    "from argparse import ArgumentParser as AP\nclass P(AP): pass\nP()",
    "import argparse\ngetattr(argparse, 'ArgumentParser')()",
    "parser.add_subparsers(parser_class=UnsafeParser)",
    "class build_argument_parser: pass\nparser.add_subparsers(parser_class=build_argument_parser)",
    "from unsafe import build_argument_parser\nparser.add_subparsers(parser_class=build_argument_parser)",
    "parser.add_subparsers(parser_class=unsafe.build_argument_parser)",
    "from azure_tenant_audit.secret_hygiene import build_argument_parser\n"
    "build_argument_parser = UnsafeParser\nparser.add_subparsers(parser_class=build_argument_parser)",
    "from azure_tenant_audit.secret_hygiene import build_argument_parser\n"
    "from unsafe import *\nparser.add_subparsers(parser_class=build_argument_parser)",
    "parser.add_subparsers(**options)",
    "import argparse\nname = 'ArgumentParser'\ngetattr(argparse, name)()",
    "import argparse\ngetattr(argparse, 'anything')()",
    "import argparse as ap\ngetattr(ap, name)()",
    "import argparse\nap = argparse\ngetattr(ap, name)()",
    "import argparse\nvars(argparse)['ArgumentParser']()",
    "import argparse\nvars(argparse)[name]()",
    "import argparse\nap = argparse\nvars(ap)[name]()",
    "import argparse\ng = getattr\ng(argparse, 'ArgumentParser')()",
    "import argparse\nfrom builtins import getattr as g\ng(argparse, name)()",
    "import argparse\nimport builtins as b\nb.getattr(argparse, name)()",
    "import argparse\nimport builtins as b\ng = b.getattr\ng(argparse, name)()",
    "import argparse, builtins\nb = builtins\nb.getattr(argparse, name)()",
    "import argparse, builtins\nb = builtins\nother = b\nother.vars(argparse)[name]()",
    *[f"import argparse, builtins\nname = {member!r}\nhelper = {lookup}\n{invoke}"
      for member, invoke in (("getattr", "helper(argparse, field)()"),
                             ("vars", "helper(argparse)[field]()"),
                             ("type", "helper(parser)()"))
      for lookup in ("getattr(builtins, name)", "vars(builtins)[name]", "builtins.__dict__[name]")],
    "from azure_tenant_audit.secret_hygiene import build_argument_parser as make\nmake()",
    "from auditex.cli import build_argument_parser as make\nmake()",
    "from azure_tenant_audit.secret_hygiene import build_argument_parser\nmake = build_argument_parser\nmake()",
    "make = secret_hygiene.build_argument_parser\nmake()",
    "from azure_tenant_audit.secret_hygiene import build_argument_parser\n"
    "make = relay(parser_class=build_argument_parser)\nmake()",
    "from azure_tenant_audit import secret_hygiene\nmake = getattr(secret_hygiene, 'build_argument_parser')\nmake()",
    "from azure_tenant_audit import secret_hygiene\nmake = vars(secret_hygiene)['build_argument_parser']\nmake()",
    "from azure_tenant_audit import secret_hygiene as sh\nmake = getattr(sh, name)\nmake()",
    "from azure_tenant_audit import argument_parser as ap\nmake = vars(ap)[name]\nmake()",
    "from azure_tenant_audit import secret_hygiene as sh\nmake = sh.__dict__['build_argument_parser']\nmake()",
    "from azure_tenant_audit import secret_hygiene as sh\nmake = sh.__dict__[name]\nmake()",
    "class P(DiagnosticRedactingArgumentParser): pass",
    "from azure_tenant_audit.argument_parser import DiagnosticRedactingArgumentParser as D\nclass P(D): pass",
    "class P(a.DiagnosticRedactingArgumentParser): pass",
    "class P(type(parser)): pass",
    "Base = type(parser)\nclass P(Base): pass\nP()",
    "Base = type(parser)\nAlias = Base\nclass P(Alias): pass\nP()",
    "Base = type(parser)\nBase()",
    "collection_type = type(parser)\ncollection_type()",
    "P = type('P', (type(parser),), {})\nP()",
    "type(parser)()",
    "from builtins import type as T\nT(parser)()",
    "T = type\nT(parser)()",
    "import builtins as b\nclass P(b.type(parser)): pass",
    "import builtins\nb = builtins\nb.type(parser)()",
    "def f(x: type(parser)()): pass",
    "def f(x: getattr(argparse, name)): pass",
    "def f(x: argparse.ArgumentParser()): pass",
])
def test_parser_ast_guard_rejects_bypass_mutations(source):
    assert _parser_violations(ast.parse(source))
    assert not _parser_violations(ast.parse(
        "from azure_tenant_audit.secret_hygiene import build_argument_parser\n"
        "parser.add_subparsers(parser_class=build_argument_parser)"
    ))
    assert not _parser_violations(ast.parse("def f(parser: argparse.ArgumentParser) -> argparse.ArgumentParser: pass"))


def test_parser_ast_guard_scans_scripts_and_extensionless_python_entries(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    module = scripts / "unsafe.py"
    module.write_text("import argparse\ngetattr(argparse, name)()\n", encoding="utf-8")
    entry = scripts / "entry"
    entry.write_text("#!/usr/bin/env python3\nclass P(type(parser)): pass\n", encoding="utf-8")
    other = scripts / "not-python"
    other.write_text("#!/bin/sh\necho hello\n", encoding="utf-8")
    paths = set(_python_sources([scripts]))
    assert paths == {module, entry}
    assert all(_parser_violations(ast.parse(path.read_text(encoding="utf-8"))) for path in paths)


def test_no_parser_constructor_or_subparser_override_outside_factory():
    roots = [ROOT / "src" / "azure_tenant_audit", ROOT / "src" / "auditex", VENDORED, ROOT / "scripts"]
    # A dedicated parser module is mirrored in the standalone bootstrap kit;
    # it is the sole place where either copy may construct the parser class.
    factories = {
        ROOT / "src" / "azure_tenant_audit" / "argument_parser.py",
        VENDORED / "argument_parser.py",
    }
    violations = []
    for path in _python_sources(roots):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if path not in factories:
            allowed = _known_collection_type_calls(path, tree)
            violations.extend((str(path.relative_to(ROOT)), line) for line in _parser_violations(tree, allowed))
    assert not violations
    assert (ROOT / "src" / "azure_tenant_audit" / "argument_parser.py").read_bytes() == (VENDORED / "argument_parser.py").read_bytes()


def _factory_calls(tree, path):
    found = Counter()

    class Visitor(ast.NodeVisitor):
        def __init__(self, path):
            self.path = path
            self.functions = []

        def visit_FunctionDef(self, node):
            self.functions.append(node.name)
            self.generic_visit(node)
            self.functions.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Call(self, node):
            if ((isinstance(node.func, ast.Name) and node.func.id == "build_argument_parser")
                    or (isinstance(node.func, ast.Attribute) and node.func.attr == "build_argument_parser")):
                found[(self.path, self.functions[-1] if self.functions else "<module>")] += 1
            self.generic_visit(node)

    Visitor(path).visit(tree)
    return found


def test_factory_ast_guard_counts_attribute_calls():
    source = "def build():\n    return secret_hygiene.build_argument_parser()"
    assert _factory_calls(ast.parse(source), "synthetic.py") == {("synthetic.py", "build"): 1}


def test_factory_call_sites_are_in_the_parser_matrix():
    expected = Counter((str(Path(inspect.getfile(builder)).relative_to(ROOT)), builder.__name__)
                       for builder in BUILDERS)
    # These entry points construct parsers inside the handler rather than
    # exposing a builder; _all_parsers captures them before dispatch.
    expected[("src/auditex/cli.py", "main")] += 2
    expected[("src/auditex/model_training.py", "training_main")] += 1
    expected[("tenant-bootstrap/azure_tenant_audit/cli.py", "build_parser")] += 1
    expected.update((f"scripts/{filename}", entry) for filename, entry in SCRIPT_BUILDERS)
    found = Counter()
    roots = [ROOT / "src" / "auditex", ROOT / "src" / "azure_tenant_audit", VENDORED, ROOT / "scripts"]
    for path in _python_sources(roots):
        found.update(_factory_calls(ast.parse(path.read_text(encoding="utf-8")), str(path.relative_to(ROOT))))
    assert found == expected
