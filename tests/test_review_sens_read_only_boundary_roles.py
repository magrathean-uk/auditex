"""R018/R014/R075: the reader app is given Global Reader and no other role, so no plan or blocker suggests an
administrator role: each can write, and Privileged Role Administrator can grant Global Administrator."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from auditex.setup_guide import build_setup_guide, render_setup_guide_markdown
from azure_tenant_audit.diagnostics import build_diagnostics

ROOT = Path(__file__).resolve().parents[1]


def _admin_roles(roles: object) -> list[str]:
    return [str(role) for role in roles or [] if "administrator" in str(role).lower()]


def test_shipped_role_hints_name_no_administrator_role() -> None:
    hints = json.loads((ROOT / "configs" / "collector-permissions.json").read_text(encoding="utf-8"))["collector_permissions"]
    offenders = {name: _admin_roles(row.get("minimum_role_hints")) for name, row in hints.items()}
    assert {name: roles for name, roles in offenders.items() if roles} == {}
    assert all(row.get("minimum_role_hints") for row in hints.values()), "every collector names its reader role"


def _hints_with_admin_roles(tmp_path: Path) -> Path:
    path = tmp_path / "collector-permissions.json"
    path.write_text(json.dumps({"collector_permissions": {
        "identity": {"graph_scopes": ["Directory.Read.All"], "minimum_role_hints": ["Global Reader", "Privileged Role Administrator"]},
        "exchange_policy": {"graph_scopes": [], "minimum_role_hints": ["Exchange Reader", "Exchange Administrator"]},
    }}), encoding="utf-8")
    return path


@pytest.mark.parametrize("preset", ["full", None])
def test_setup_guide_role_hints_are_reader_roles_only(preset: str | None) -> None:
    guide = build_setup_guide(provider="m365", auditor_profile="global-reader", collector_preset=preset)
    assert _admin_roles(guide["minimum_role_hints"]) == []
    for row in guide["collector_permissions"]:
        assert _admin_roles(row["minimum_role_hints"]) == [], row["collector"]
    section = render_setup_guide_markdown(guide).split("## Role Hints", 1)[1].split("\n## ", 1)[0]
    assert "Global Reader" in section and "Administrator" not in section


def test_setup_guide_drops_administrator_roles_from_a_custom_hint_file(tmp_path: Path) -> None:
    guide = build_setup_guide(
        provider="m365", collectors="identity,exchange_policy", permission_hints_path=_hints_with_admin_roles(tmp_path),
    )
    assert _admin_roles(guide["minimum_role_hints"]) == []
    assert all(_admin_roles(row["minimum_role_hints"]) == [] for row in guide["collector_permissions"])
    assert "Exchange Reader" in guide["minimum_role_hints"]


def test_blocker_advice_never_recommends_an_administrator_role(tmp_path: Path) -> None:
    hints = json.loads(_hints_with_admin_roles(tmp_path).read_text(encoding="utf-8"))["collector_permissions"]
    results = [
        {"name": "identity", "status": "failed", "error": "403"},
        {"name": "exchange_policy", "status": "partial", "error": None},
    ]
    coverage = [{"collector": "exchange_policy", "name": "acceptedDomain", "status": "failed", "type": "graph", "error_class": "insufficient_permissions"}]
    failures = build_diagnostics(results, coverage, hints, "global-reader")
    assert failures
    for failure in failures:
        roles = failure["recommendations"].get("recommended_roles")
        assert roles, failure
        assert _admin_roles(roles) == [], failure
        assert _admin_roles(failure["recommendations"].get("profile_role_hints")) == []
