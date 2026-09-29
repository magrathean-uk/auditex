"""Shared pytest fixtures for the tenant-bootstrap tests."""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_m365_home(tmp_path, monkeypatch):
    """Keep the private m365 folder (AUDITEX_M365_HOME) inside tmp_path so no test creates it in the real data home."""
    monkeypatch.setenv("AUDITEX_M365_HOME", str(tmp_path / "m365-home"))
