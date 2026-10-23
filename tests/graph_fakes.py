"""A scripted Graph client and Intune fixtures for tests that drive ``cli.run_live`` end to end (no network).

``FakeGraph`` answers the calls the collectors make (paged lists, single objects, ``$batch``) from dictionaries, so a
test can describe a tenant (a list of managed devices, a refused endpoint) and read what the run, its bundle, the gate
and the handoff made of it.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from azure_tenant_audit import cli
from azure_tenant_audit.graph import GRAPH_BETA_ROOT, GRAPH_ROOT, GraphError

NOW = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _key(path: str) -> str:
    for root, tag in ((GRAPH_BETA_ROOT, "beta:"), (GRAPH_ROOT, "")):
        if path.startswith(root):
            path = tag + path[len(root):]
            break
    return path.split("?", 1)[0]


class FakeGraph:
    """``lists``: key -> rows; ``errors``: key -> (status, message); ``objects``: key -> dict.

    Keys are Graph paths; a beta path is prefixed with ``beta:``. ``batch_errors`` refuses only the ``$batch`` inner call.
    """

    page_size = 100

    def __init__(
        self,
        lists: dict[str, list[dict[str, Any]]] | None = None,
        errors: dict[str, tuple[int, str]] | None = None,
        objects: dict[str, dict[str, Any]] | None = None,
        batch_errors: dict[str, tuple[int, str]] | None = None,
    ) -> None:
        self.lists = lists or {}
        self.errors = errors or {}
        self.objects = objects or {}
        self.batch_errors = batch_errors or {}
        self.calls: list[str] = []

    def _maybe_raise(self, key: str) -> None:
        if key in self.errors:
            status, message = self.errors[key]
            raise GraphError(message, status=status, request=key)

    def iter_pages(self, path: str, params: Any = None):
        key = _key(path)
        self.calls.append("pages " + key)
        self._maybe_raise(key)
        rows = self.lists.get(key, [])
        if not rows:
            yield {"value": []}
            return
        for start in range(0, len(rows), self.page_size):
            page: dict[str, Any] = {"value": rows[start:start + self.page_size]}
            if start + self.page_size < len(rows):
                page["@odata.nextLink"] = f"{GRAPH_ROOT}{key}?$skiptoken={start}"
            yield page

    def iter_items(self, path: str, params: Any = None, result_limit: int | None = None):
        key = _key(path)
        self.calls.append("items " + key)
        self._maybe_raise(key)
        rows = self.lists.get(key, [])
        return iter(rows if result_limit is None else rows[:result_limit])

    def get_all(self, path: str, params: Any = None) -> list[dict[str, Any]]:
        key = _key(path)
        self.calls.append("all " + key)
        self._maybe_raise(key)
        return list(self.lists.get(key, []))

    def get_json(self, path: str, params: Any = None, full_url: bool = False) -> dict[str, Any]:
        key = _key(path)
        self.calls.append("json " + key)
        self._maybe_raise(key)
        if key in self.objects:
            return self.objects[key]
        if key in self.lists:
            return {"value": list(self.lists[key])}
        return {"value": []}

    def get_content(self, path: str, params: Any = None, full_url: bool = False) -> str:
        return ""

    def get_batch(self, requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for request in requests:
            key = _key(request["path"])
            self.calls.append("batch " + key)
            if key in self.batch_errors or key in self.errors:
                status, message = self.batch_errors.get(key) or self.errors[key]
                out.append({"status": status, "body": {"error": {"code": "Forbidden", "message": message}}})
            elif key in self.objects:
                out.append({"status": 200, "body": self.objects[key]})
            elif key in self.lists:
                out.append({"status": 200, "body": {"value": list(self.lists[key])}})
            else:
                out.append({"status": 404, "body": {"error": {"code": "NotFound", "message": "not found"}}})
        return out

    def token_claims(self) -> dict[str, Any]:
        return {}


def run_collectors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fake: FakeGraph,
    collectors: str,
    *extra: str,
    name: str = "r",
) -> tuple[int, Path]:
    """Run the live path with ``fake`` as the Graph client; returns the exit code and the run directory."""
    args = cli.build_parser().parse_args(
        [
            "--tenant-name", "acme", "--tenant-id", "t-1", "--access-token", "x.y.z",
            "--collectors", collectors, "--out", str(tmp_path), "--run-name", name, *extra,
        ]
    )
    monkeypatch.setattr(cli, "GraphClient", lambda auth, **kwargs: fake)
    rc = cli.run_live(args)
    return rc, tmp_path / f"acme-{name}"


def load(run_dir: Path, relative: str) -> Any:
    path = run_dir / relative
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def rule_statuses(run_dir: Path) -> dict[str, set[tuple[str, str]]]:
    """``rule id -> {(status, reason)}`` across every framework control of the report pack."""
    pack = load(run_dir, "reports/report-pack.json")
    alignment = pack.get("baseline_alignment") or pack.get("summary", {}).get("baseline_alignment")
    out: dict[str, set[tuple[str, str]]] = {}
    for framework in alignment["frameworks"].values():
        for control in framework["controls"]:
            for status in control["rule_statuses"]:
                out.setdefault(status["rule_id"], set()).add((status["status"], status.get("reason") or ""))
    return out


GOOD_AV = {
    "malwareProtectionEnabled": True, "realTimeProtectionEnabled": True, "signatureUpdateOverdue": False,
    "quickScanOverdue": False, "fullScanOverdue": False, "tamperProtectionEnabled": True, "productStatus": "noStatus",
    "deviceState": "clean", "isVirtualMachine": False,
}

COMPLIANCE_POLICY = {
    "id": "cp-1", "displayName": "Win compliance", "@odata.type": "#microsoft.graph.windows10CompliancePolicy",
    "bitLockerEnabled": True, "passwordRequired": True, "defenderEnabled": True,
}
RING = {
    "id": "ring-1", "displayName": "Ring", "@odata.type": "#microsoft.graph.windowsUpdateForBusinessConfiguration",
    "qualityUpdatesDeferralPeriodInDays": 0, "featureUpdatesDeferralPeriodInDays": 0, "deadlineForQualityUpdatesInDays": 3,
    "deadlineGracePeriodInDays": 2, "qualityUpdatesPaused": False, "featureUpdatesPaused": False,
}
ASSIGN_ALL = [{"id": "a1", "target": {"@odata.type": "#microsoft.graph.allDevicesAssignmentTarget"}}]


def devices(count: int, *, os: str = "Windows", start: int = 0) -> list[dict[str, Any]]:
    return [
        {
            "id": f"dev-{os}-{index}", "deviceName": f"PC{index}", "operatingSystem": os, "osVersion": "10.0.26200.6000",
            "complianceState": "compliant", "lastSyncDateTime": NOW, "isEncrypted": True, "jailBroken": "False",
            "managedDeviceOwnerType": "company", "enrolledDateTime": "2026-01-01T00:00:00Z",
            "deviceEnrollmentType": "windowsAzureADJoin",
        }
        for index in range(start, start + count)
    ]


def intune_lists(
    device_rows: list[dict[str, Any]],
    *,
    compliance: tuple[dict[str, Any], ...] = (COMPLIANCE_POLICY,),
    configs: tuple[dict[str, Any], ...] = (RING,),
    quality: tuple[dict[str, Any], ...] = (),
    feature: tuple[dict[str, Any], ...] = (),
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, dict[str, Any]]]:
    """The lists and objects of a small Intune tenant: devices, one compliance policy, one update ring, all assigned."""
    lists: dict[str, list[dict[str, Any]]] = {
        "/deviceManagement/managedDevices": list(device_rows),
        "/deviceManagement/deviceCompliancePolicies": list(compliance),
        "/deviceManagement/deviceConfigurations": list(configs),
        "beta:/deviceManagement/windowsQualityUpdateProfiles": list(quality),
        "beta:/deviceManagement/windowsFeatureUpdateProfiles": list(feature),
    }
    for policy in compliance:
        lists[f"/deviceManagement/deviceCompliancePolicies/{policy['id']}/assignments"] = ASSIGN_ALL
    for config in configs:
        lists[f"/deviceManagement/deviceConfigurations/{config['id']}/assignments"] = ASSIGN_ALL
    for profile in quality:
        lists[f"beta:/deviceManagement/windowsQualityUpdateProfiles/{profile['id']}/assignments"] = ASSIGN_ALL
    for profile in feature:
        lists[f"beta:/deviceManagement/windowsFeatureUpdateProfiles/{profile['id']}/assignments"] = ASSIGN_ALL
    objects = {f"/deviceManagement/managedDevices/{row['id']}/windowsProtectionState": dict(GOOD_AV) for row in device_rows}
    return lists, objects
