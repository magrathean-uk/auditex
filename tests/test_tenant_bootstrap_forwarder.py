"""Prove the tenant-bootstrap forwarder resolves to the canonical runtime.

Runs in a subprocess with ``tenant-bootstrap`` first on ``sys.path`` so the
test does not disturb imports in the pytest process.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = REPO_ROOT / "tenant-bootstrap"
CANONICAL = REPO_ROOT / "src" / "azure_tenant_audit"

_PROBE = """
import importlib, json, sys
sys.path[:] = [sys.argv[1]] + [p for p in sys.path if p not in ("", sys.argv[1])]
names = ["azure_tenant_audit", "azure_tenant_audit.cli", "azure_tenant_audit.output"]
mods = {n: importlib.import_module(n) for n in names}
print(json.dumps({
    "package": mods["azure_tenant_audit"].__file__,
    "cli": mods["azure_tenant_audit.cli"].__file__,
    "output": mods["azure_tenant_audit.output"].__file__,
    "main": callable(mods["azure_tenant_audit"].main),
}))
"""


def test_forwarder_resolves_modules_under_canonical_src() -> None:
    result = subprocess.run(
        [sys.executable, "-I", "-c", _PROBE, str(BOOTSTRAP)],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout.strip().splitlines()[-1])
    assert Path(data["package"]) == BOOTSTRAP / "azure_tenant_audit" / "__init__.py"
    assert Path(data["cli"]) == CANONICAL / "cli.py"
    assert Path(data["output"]) == CANONICAL / "output.py"
    assert data["main"] is True
