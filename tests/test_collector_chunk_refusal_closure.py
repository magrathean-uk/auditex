"""Collector completion after a structured chunk refusal (synthetic runs only).

The chunk reader turns a guard refusal into constant-code issues. A collector that consumes the chunked
list must then stay partial, keep a fixed incomplete-evidence marker, never restore rows from the inline
sample of a chunked section, and make no follow-up request.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from azure_tenant_audit.collectors import identity_governance as governance_module
from azure_tenant_audit.collectors import onedrive_posture as onedrive_module
from azure_tenant_audit.collectors.identity_governance import (
    IdentityGovernanceCollector,
)
from azure_tenant_audit.collectors.onedrive_posture import OneDrivePostureCollector

CANARY = "inline-only-canary-site.example.invalid"
PRIVATE = "private-operator-canary@example.invalid"
VARIANTS = ("symlink", "hardlink", "outside")


def _run(tmp_path: Path) -> Path:
    root = tmp_path / "run"
    private = root / "operator-inputs"
    private.mkdir(parents=True, mode=0o700)
    from azure_tenant_audit.sensitive_users import SensitiveUsers

    key = b"k" * 32
    (private / "sensitive-users.txt").write_text(PRIVATE + "\n", encoding="utf-8")
    (private / "sensitive-users.key").write_bytes(key)
    (root / "run-manifest.json").write_text(json.dumps({"operator_inputs": {"sensitive_users": SensitiveUsers((PRIVATE,)).manifest(key)}}), encoding="utf-8")
    (root / "chunks").mkdir(mode=0o700)
    return root


def _refused(root: Path, variant: str, name: str) -> str:
    target = root / "chunks" / name
    private = root / "operator-inputs" / "sensitive-users.txt"
    if variant == "symlink":
        target.symlink_to(private)
        return f"chunks/{name}"
    if variant == "hardlink":
        # Refuse this multiply-linked chunk without invalidating the private pair for every otherwise valid chunk.
        original = root / ("hardlink-source-" + name)
        original.write_text(json.dumps({"id": PRIVATE}) + "\n", encoding="utf-8")
        os.link(original, target)
        return f"chunks/{name}"
    return f"../{name}"


def _valid(root: Path, name: str, rows: list[dict[str, Any]]) -> str:
    path = root / "chunks" / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")
    return f"chunks/{name}"


def _section(chunks: list[str], inline: list[dict[str, Any]], count: int) -> dict[str, Any]:
    return {"value": inline, "chunk_files": chunks, "chunk_count": len(chunks), "item_count": count}


def _ok(name: str, endpoint: str, count: int = 0) -> dict[str, Any]:
    return {"collector": "x", "type": "graph", "name": name, "endpoint": endpoint, "status": "ok", "item_count": count}


class _Client:
    """Records every request; the collectors under test must not make a policy request after a refusal."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def _note(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append(str(args[0]) if args else "")
        return {"value": []}

    get_json = get_all = iter_pages = iter_items = get_batch = _note


def _onedrive(monkeypatch: pytest.MonkeyPatch, root: Path | None, sites: dict[str, Any]) -> tuple[Any, list[tuple[str, list[dict[str, Any]]]]]:
    payload = {"sharePointSettings": {"sharingCapability": "Disabled"}, "sites": sites}
    coverage = [_ok("sharePointSettings", "/admin/sharepoint/settings"), _ok("sites", "/sites")]
    monkeypatch.setattr(onedrive_module, "run_graph_endpoints", lambda *a, **k: (payload, coverage))
    written: list[tuple[str, list[dict[str, Any]]]] = []

    def writer(collector: str, name: str, page: int, rows: list[dict[str, Any]], meta: Any = None) -> str:
        written.append((name, [dict(r) for r in rows]))
        return f"chunks/derived-{name}-{page}.jsonl"

    context = {"client": object(), "run_dir": root, "chunk_writer": writer}
    return OneDrivePostureCollector().run(context), written


def _incomplete(payload: dict[str, Any]) -> bool:
    return all(
        payload[name].get("error_class") == "incomplete_evidence" and payload[name].get("error") == "The site list could not be read in full."
        for name in ("oneDriveSites", "teamSites")
    )


@pytest.mark.parametrize("variant", VARIANTS)
def test_onedrive_refused_chunks_never_fall_back_to_the_inline_sample(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variant: str) -> None:
    root = _run(tmp_path)
    inline = [{"id": "s1", "webUrl": f"https://{CANARY}/sites/a"}, {"id": "s2", "webUrl": "https://t-my.sharepoint.com/personal/x"}]
    sites = _section([_refused(root, variant, "sites-1.jsonl")], inline, 2)
    result, written = _onedrive(monkeypatch, root, sites)

    assert result.status == "partial"
    assert _incomplete(result.payload)
    assert result.payload["oneDriveSites"].get("value", []) == []
    assert result.payload["teamSites"].get("value", []) == []
    assert written == []
    assert result.payload["sites"]["value"] == []
    rendered = json.dumps(result.payload) + json.dumps(written) + json.dumps(result.coverage)
    assert CANARY not in rendered and PRIVATE not in rendered and "sensitive-users" not in rendered and str(tmp_path) not in rendered
    assert any(row.get("status") != "ok" and row.get("error_class") == "incomplete_evidence" for row in result.coverage)


@pytest.mark.parametrize("variant", VARIANTS)
def test_onedrive_mixed_chunks_keep_readable_rows_but_stay_partial(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variant: str) -> None:
    root = _run(tmp_path)
    good = [{"id": "g1", "webUrl": "https://t-my.sharepoint.com/personal/a"}, {"id": "g2", "webUrl": "https://t.sharepoint.com/sites/b"}]
    chunks = [_valid(root, "sites-1.jsonl", good), _refused(root, variant, "sites-2.jsonl")]
    inline = [{"id": "s9", "webUrl": f"https://{CANARY}/sites/z"}]
    result, written = _onedrive(monkeypatch, root, _section(chunks, inline, 3))

    assert result.status == "partial"
    assert _incomplete(result.payload)
    kept = [row["id"] for _, rows in written for row in rows]
    assert sorted(kept) == ["g1", "g2"]
    assert CANARY not in json.dumps(written) + json.dumps(result.payload["sites"])
    assert any(row.get("status") != "ok" and row.get("error_class") == "incomplete_evidence" for row in result.coverage)


def test_onedrive_valid_chunks_stay_complete(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _run(tmp_path)
    good = [{"id": "g1", "webUrl": "https://t-my.sharepoint.com/personal/a"}, {"id": "g2", "webUrl": "https://t.sharepoint.com/sites/b"}]
    result, written = _onedrive(monkeypatch, root, _section([_valid(root, "sites-1.jsonl", good)], good[:1], 2))

    assert result.status == "ok"
    assert "error_class" not in result.payload["oneDriveSites"] and "error_class" not in result.payload["teamSites"]
    assert sorted(name for name, _ in written) == ["oneDriveSites", "teamSites"]


def test_onedrive_genuinely_unchunked_sites_stay_inline(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [{"id": "i1", "webUrl": "https://t-my.sharepoint.com/personal/a"}, {"id": "i2", "webUrl": "https://t.sharepoint.com/sites/b"}]
    result, written = _onedrive(monkeypatch, None, {"value": rows})

    assert result.status == "ok"
    assert [r["id"] for r in result.payload["oneDriveSites"]["value"]] == ["i1"]
    assert [r["id"] for r in result.payload["teamSites"]["value"]] == ["i2"]
    assert written == []


def _governance(monkeypatch: pytest.MonkeyPatch, root: Path, assignments: dict[str, Any]) -> tuple[Any, _Client]:
    payload = {"roleAssignmentSchedules": {"value": []}, governance_module.POLICY_ASSIGNMENTS: assignments}
    coverage = [_ok(governance_module.POLICY_ASSIGNMENTS, "/policies/roleManagementPolicyAssignments")]
    monkeypatch.setattr(governance_module, "run_graph_endpoints", lambda *a, **k: (payload, coverage))
    client = _Client()
    return IdentityGovernanceCollector().run({"client": client, "run_dir": root}), client


def _marker(result: Any) -> dict[str, Any]:
    return next(row for row in result.coverage if row.get("name") == governance_module.POLICY_RULES_FANOUT)


@pytest.mark.parametrize("variant", VARIANTS)
def test_governance_refused_assignment_chunks_stay_partial_with_fixed_issues(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variant: str) -> None:
    root = _run(tmp_path)
    inline = [{"policyId": "inline-only-policy"}]
    result, client = _governance(monkeypatch, root, _section([_refused(root, variant, "assign-1.jsonl")], inline, 1))

    assert result.status == "partial"
    assert client.calls == []
    row = _marker(result)
    assert row["status"] == "partial" and row["error_class"] == "incomplete_evidence"
    assert row["input_complete"] is False and row["input_unreadable"] is True
    assert row["input_issues"] and all(set(issue) <= {"code", "chunk_index", "expected_count", "observed_count"} for issue in row["input_issues"])
    section = result.payload[governance_module.POLICY_RULES]
    assert section["value"] == []
    rendered = json.dumps(result.payload) + json.dumps(result.coverage)
    assert "inline-only-policy" not in json.dumps(section) and PRIVATE not in rendered and str(tmp_path) not in rendered


def test_governance_mixed_chunks_stop_expansion_and_stay_partial(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _run(tmp_path)
    chunks = [_valid(root, "assign-1.jsonl", [{"policyId": "p1"}]), _refused(root, "symlink", "assign-2.jsonl")]
    result, client = _governance(monkeypatch, root, _section(chunks, [{"policyId": "inline-only-policy"}], 2))

    assert result.status == "partial"
    assert _marker(result)["input_complete"] is False
    assert client.calls == []


def test_governance_valid_collection_is_unchanged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _run(tmp_path)
    chunk = _valid(root, "assign-1.jsonl", [{"policyId": "p1"}])
    result, client = _governance(monkeypatch, root, _section([chunk], [{"policyId": "p1"}], 1))

    assert result.status == "ok"
    assert client.calls and all("/p1/" in call or "p1" in call for call in client.calls)
    assert _marker(result)["status"] == "ok"
