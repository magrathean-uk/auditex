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


# The reader-app guide: the one list a customer's tenant administrator follows.
READER_GUIDE = ROOT / "docs" / "guides" / "reader-app-permissions.md"
GRANT_ROW = re.compile(r"^\| (?P<api>[^|`]+?) \| `(?P<perm>[^`]+)` \| (?P<type>[^|]+?) \| (?P<consent>[^|]+?) \|")
OPTIONAL_ROW = re.compile(r"^\| (?P<collector>[a-z_]+) \| `(?P<perm>[^`]+)` \| (?P<api>[^|]+?) \| (?P<type>[^|]+?) \| (?P<consent>[^|]+?) \|")
NON_GRAPH_GRANT = {
    ("Office 365 Exchange Online", "Exchange.ManageAsApp"),
    ("Microsoft Exchange Online Protection", "Exchange.ManageAsApp"),
    ("SharePoint (Office 365 SharePoint Online)", "Sites.FullControl.All"),
}


def _between(text: str, start: str, end: str) -> list[str]:
    return text.split(start, 1)[1].split(end, 1)[0].splitlines()


def reader_grant(text: str) -> list[tuple[str, str, str, str]]:
    """API permission rows of step 2: (api, permission, type, admin consent)."""
    rows = _between(text, "## Step 2:", "### Exchange.ManageAsApp, twice")
    return [m.group("api", "perm", "type", "consent") for line in rows if (m := GRANT_ROW.match(line))]


def reader_optional(text: str) -> list[tuple[str, str, str, str, str]]:
    rows = text.split("## Optional collectors", 1)[1].splitlines()
    return [m.group("collector", "perm", "api", "type", "consent") for line in rows if (m := OPTIONAL_ROW.match(line))]


def reader_check_collectors(text: str) -> list[str]:
    match = re.search(r"--collectors ([a-z_,]+)", text.split("## Step 7:", 1)[1])
    assert match, "the check command names its collectors"
    return match.group(1).split(",")


def _needs(collectors: list[str]) -> set[str]:
    definitions = _load("collector-definitions.json")["collectors"]
    return {perm for name in collectors for perm in definitions[name]["required_permissions"]}


def _reader_findings(text: str) -> list[str]:
    """Every way the guide disagrees with the code; empty when it is exact."""
    findings: list[str] = []
    rows = reader_grant(text)
    collectors = reader_check_collectors(text)
    definitions = _load("collector-definitions.json")["collectors"]
    unknown = [name for name in collectors if name not in definitions]
    if unknown:
        return [f"unknown collector {name}" for name in unknown]
    graph = [perm for api, perm, _, _ in rows if api == "Microsoft Graph"]
    if len(graph) != len(set(graph)):
        findings.append("a Microsoft Graph permission is listed twice")
    need = _needs(collectors)
    findings += [f"missing {perm}" for perm in sorted(need - set(graph))]
    findings += [f"extra {perm}" for perm in sorted(set(graph) - need)]
    findings += [f"write-capable Graph {perm}" for perm in graph if WRITE_CAPABLE.search(perm)]
    other = {(api, perm) for api, perm, _, _ in rows if api != "Microsoft Graph"}
    if other != NON_GRAPH_GRANT:
        findings.append(f"non-Graph grant {sorted(other)}")
    findings += [f"{perm} type {kind}" for _, perm, kind, _ in rows if kind != "Application"]
    findings += [f"{perm} consent {consent}" for _, perm, _, consent in rows if consent != "Yes"]
    if f"2. {len(rows)} application permissions" not in text:
        findings.append(f"stated count differs from the {len(rows)} rows")
    return findings


def test_reader_guide_lists_exactly_what_the_check_run_needs() -> None:
    from azure_tenant_audit.profiles import PROFILES

    text = READER_GUIDE.read_text(encoding="utf-8")
    assert _reader_findings(text) == []
    rows = reader_grant(text)
    assert len(rows) == 30
    collectors = reader_check_collectors(text)
    assert set(PROFILES["global-reader"].default_collectors) <= set(collectors)
    assert {"power_bi", "power_platform", "sharepoint_admin"} <= set(collectors)
    # The guide's Graph list is the permission config's recommendation without the opt-in collectors' scopes.
    graph = {perm for api, perm, _, _ in rows if api == "Microsoft Graph"}
    recommendation = set(_load("collector-permissions.json")["global_app_recommendation"])
    assert recommendation - graph == {"MailboxSettings.Read"}
    assert graph <= recommendation


def test_reader_guide_optional_collectors_are_outside_the_grant() -> None:
    text = READER_GUIDE.read_text(encoding="utf-8")
    definitions = _load("collector-definitions.json")["collectors"]
    grant = {perm for _, perm, _, _ in reader_grant(text)}
    collectors = set(reader_check_collectors(text))
    optional = reader_optional(text)
    assert optional
    for collector, perm, api, kind, consent in optional:
        assert collector not in collectors
        assert perm in definitions[collector]["required_permissions"]
        assert perm not in grant
        assert (api, kind, consent) == ("Microsoft Graph", "Application", "Yes")
        assert not WRITE_CAPABLE.search(perm)
    left_over = _needs(sorted(set(definitions) - collectors)) - grant
    assert left_over - {perm for _, perm, _, _, _ in optional} == {"CopilotSettings-LimitedMode.Read"}
    assert "`CopilotSettings-LimitedMode.Read`, which Microsoft publishes only as a delegated" in text


def test_reader_guide_check_rejects_extra_missing_delegated_and_wrong_api_rows() -> None:
    text = READER_GUIDE.read_text(encoding="utf-8")
    row = "| Microsoft Graph | `Policy.Read.All` | Application | Yes |"
    line = next(item for item in text.splitlines() if item.startswith(row))
    cases = {
        "extra": text.replace(line, line + "\n" + line.replace("Policy.Read.All", "Mail.Read"), 1),
        "missing": text.replace(line + "\n", "", 1),
        "write": text.replace(line, line + "\n" + line.replace("Policy.Read.All", "Sites.ReadWrite.All"), 1),
        "delegated": text.replace(row, row.replace("Application", "Delegated"), 1),
        "no consent": text.replace(row, row.replace("| Yes |", "| No |"), 1),
        "wrong api": text.replace("| Microsoft Exchange Online Protection | `Exchange.ManageAsApp`",
                                  "| Microsoft Graph | `Exchange.ManageAsApp`", 1),
        "dropped exchange": text.replace("| Microsoft Exchange Online Protection | `Exchange.ManageAsApp`",
                                         "| Microsoft Exchange Online Protection | Exchange.ManageAsApp", 1),
        "opt-in collector in the run": text.replace("--collectors identity,", "--collectors mailbox_forwarding,identity,", 1),
    }
    for name, changed in cases.items():
        assert changed != text, name
        assert _reader_findings(changed), name


def test_reader_guide_is_linked_from_the_setup_and_admin_guides() -> None:
    for name in ("setup-guide.md", "admin-permission-guide.md"):
        text = (ROOT / "docs" / "guides" / name).read_text(encoding="utf-8")
        assert "(reader-app-permissions.md)" in text, name
