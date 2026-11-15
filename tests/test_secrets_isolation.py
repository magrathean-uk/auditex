"""Regression: the test session must NOT touch the real secrets dir.

Before tests/conftest.py existed, running ``make test`` could silently
overwrite the developer's ``.secrets/m365-auth.env`` with test fixture
values via the guided-flow path. That local auth env file and its writer
are gone (DEC-107, DEC-108 D4); conftest still redirects the old paths so
nothing an old helper might resolve lands in the real secrets dir.
"""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_environment_variables_point_at_the_test_tmp_dir() -> None:
    for name in ("AUDITEX_LOCAL_AUTH_ENV", "AUDITEX_AUTH_CONTEXTS_PATH", "AUDITEX_M365_HOME"):
        value = os.environ.get(name)
        assert value, f"{name} not set"
        assert "auditex-test-secrets" in value, f"{name} did not redirect to a test tmp dir: {value}"


def test_no_product_module_writes_the_local_auth_env_file() -> None:
    offenders = [
        str(path.relative_to(ROOT)) for path in sorted((ROOT / "src").rglob("*.py"))
        if "m365-auth.env" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []
