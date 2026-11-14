"""The permission config and admin guide list what the default collectors need, and nothing else."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WRITE_CAPABLE = re.compile(r"\.(ReadWrite|FullControl|Write)\b|\.ReadWrite\.|\.Send\b")
def _load(name: str) -> dict:
    return json.loads((ROOT / "configs" / name).read_text(encoding="utf-8"))


def _default_needs() -> set[str]:
    collectors = _load("collector-definitions.json")["collectors"]
    return {perm for row in collectors.values() if row.get("enabled") for perm in row["required_permissions"]}


SCOPE = re.compile(r"`([A-Z][A-Za-z-]*(?:\.[A-Za-z]+)+)`")
GUIDE = ROOT / "docs" / "guides" / "admin-permission-guide.md"


def _recommendation_section(text: str) -> list[str]:
    """Bullet lines of the App-Readonly recommendation, from its heading to the closing paragraph."""
    lines = text.split("### App-Readonly", 1)[1].splitlines()
    end = next(i for i, line in enumerate(lines) if line.startswith("Use `auditex probe live --mode app`"))
    return [line for line in lines[:end] if line.startswith("- ")]


def _is_opt_in(line: str) -> bool:
    return " only when " in line


def _is_note(line: str) -> bool:
    """A bullet that explains a scope Auditex does not require (a least-privilege alternative)."""
    return " does not require " in line


def guide_default_scopes(text: str) -> set[str]:
    """Scopes on bullets of the recommendation that are not marked opt-in ("only when")."""
    return {s for line in _recommendation_section(text) if not _is_opt_in(line) and not _is_note(line) for s in SCOPE.findall(line)}


def guide_opt_in_scopes(text: str) -> set[str]:
    return {s for line in _recommendation_section(text) if _is_opt_in(line) for s in SCOPE.findall(line)}


def test_new_scopes_are_declared_by_their_collectors() -> None:
    from azure_tenant_audit.collectors.intune_depth import IntuneDepthCollector
    from azure_tenant_audit.collectors.onedrive_posture import OneDrivePostureCollector
    from azure_tenant_audit.collectors.sharepoint import SharePointCollector
    from azure_tenant_audit.collectors.sharepoint_access import (
        SharePointAccessCollector,
    )

    definitions = _load("collector-definitions.json")["collectors"]
    for cls in (SharePointCollector, SharePointAccessCollector, OneDrivePostureCollector, IntuneDepthCollector):
        assert definitions[cls.name]["required_permissions"] == cls.required_permissions
    assert "SharePointTenantSettings.Read.All" in SharePointCollector.required_permissions
    assert "DeviceManagementScripts.Read.All" in IntuneDepthCollector.required_permissions


def test_permission_config_lists_exactly_the_default_collector_needs() -> None:
    need = _default_needs()
    config = _load("collector-permissions.json")
    assert {"SharePointTenantSettings.Read.All", "DeviceManagementScripts.Read.All", "Sites.Read.All"} <= need
    assert set(config["global_app_recommendation"]) == need
    per_collector = {s for row in config["collector_permissions"].values() for s in row.get("graph_scopes", [])}
    assert need <= per_collector
    assert not [s for s in need if WRITE_CAPABLE.search(s)]


def test_admin_guide_lists_exactly_the_default_permissions() -> None:
    need = _default_needs()
    text = GUIDE.read_text(encoding="utf-8")
    assert guide_default_scopes(text) == need
    assert not [s for s in guide_default_scopes(text) if WRITE_CAPABLE.search(s)]
    assert guide_opt_in_scopes(text).isdisjoint(need)
    assert not [s for s in guide_opt_in_scopes(text) if WRITE_CAPABLE.search(s)]
    notes = {s for line in _recommendation_section(text) if _is_note(line) for s in SCOPE.findall(line)}
    assert not [s for s in notes if WRITE_CAPABLE.search(s)]


def test_guide_check_rejects_extra_missing_and_write_capable_scopes() -> None:
    text = GUIDE.read_text(encoding="utf-8")
    need = _default_needs()
    marker = "- `Policy.Read.All`\n"
    assert marker in text
    for extra in ("Calendars.Read", "MailboxSettings.ReadWrite", "Sites.FullControl.All", "Mail.Read"):
        assert guide_default_scopes(text.replace(marker, marker + f"- `{extra}`\n", 1)) != need, extra
    assert guide_default_scopes(text.replace("`Reports.Read.All`", "Reports", 1)) != need
    opt_in = "- `IdentityRiskyUser.Read.All` only when"
    assert opt_in in text
    moved = text.replace(opt_in, "- `IdentityRiskyUser.Read.All` and")
    assert guide_default_scopes(moved) != need


def test_stale_notes_are_gone() -> None:
    blob = " ".join(
        (ROOT / p).read_text(encoding="utf-8")
        for p in (
            "configs/collector-permissions.json",
            "docs/guides/admin-permission-guide.md",
            "docs/reference/api-call-catalog.md",
        )
    )
    assert "no new scope is needed" not in blob.lower()
    assert "adds no new scope" not in blob
    assert "authenticationMethodsPolicy/authenticationMethodConfigurations" not in blob
