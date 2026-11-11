from __future__ import annotations

import importlib
import inspect
import sys
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parent
CANONICAL_RUNTIME_ROOT = REPO_ROOT / "src" / "azure_tenant_audit"


@contextmanager
def _bootstrap_runtime_imports():
    original_modules = {name: module for name, module in sys.modules.items() if name == "azure_tenant_audit" or name.startswith("azure_tenant_audit.")}
    for name in list(original_modules):
        sys.modules.pop(name, None)
    sys.path.insert(0, str(ROOT))
    try:
        yield
    finally:
        sys.path = [entry for entry in sys.path if entry != str(ROOT)]
        for name in list(sys.modules):
            if name == "azure_tenant_audit" or name.startswith("azure_tenant_audit."):
                sys.modules.pop(name, None)
        sys.modules.update(original_modules)


def _assert_loaded_from_canonical(obj, expected_relative_path: str) -> None:
    source = inspect.getsourcefile(obj)
    assert source is not None
    assert Path(source) == CANONICAL_RUNTIME_ROOT / expected_relative_path


def test_bootstrap_imports_forward_to_canonical_runtime():
    with _bootstrap_runtime_imports():
        cli = importlib.import_module("azure_tenant_audit.cli")
        output = importlib.import_module("azure_tenant_audit.output")
        normalize = importlib.import_module("azure_tenant_audit.normalize")
        identity = importlib.import_module("azure_tenant_audit.collectors.identity")
        adapters = importlib.import_module("azure_tenant_audit.adapters")

        _assert_loaded_from_canonical(cli.build_parser, "cli.py")
        _assert_loaded_from_canonical(output.AuditWriter, "output.py")
        _assert_loaded_from_canonical(normalize.build_normalized_snapshot, "normalize.py")
        _assert_loaded_from_canonical(identity.IdentityCollector, "collectors/identity.py")
        _assert_loaded_from_canonical(adapters.get_adapter, "adapters/__init__.py")
