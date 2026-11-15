from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from azure_tenant_audit.collectors.base import CollectorResult
from azure_tenant_audit.config import CollectorConfig, CollectorDefinition, RunConfig
from azure_tenant_audit.profiles import get_profile
from azure_tenant_audit.run import build_live_run_plan, run_preflight_probe


def _args(**overrides: Any) -> SimpleNamespace:
    defaults = {
        "tenant_name": "acme",
        "collectors": None,
        "exclude": None,
        "include_exchange": False,
        "offline": False,
        "sample": "sample.json",
        "run_name": None,
        "top": 50,
        "page_size": 25,
        "auditor_profile": "global-reader",
        "plane": "full",
        "since": None,
        "until": None,
        "collector_preset": "identity-only",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def test_run_module_plans_collectors_and_plane_without_graph(tmp_path: Path) -> None:
    config = CollectorConfig(
        collectors={
            "identity": CollectorDefinition(
                collector_id="identity",
                description="Identity",
                enabled=True,
                required_permissions=["Directory.Read.All"],
                query_plan=[],
            ),
            "security": CollectorDefinition(
                collector_id="security",
                description="Security",
                enabled=True,
                required_permissions=["SecurityEvents.Read.All"],
                query_plan=[],
            ),
        },
        default_order=["identity", "security"],
    )

    plan = build_live_run_plan(
        _args(),
        output_dir=tmp_path,
        collector_config=config,
        permission_hints={},
        profile=get_profile("global-reader"),
        collector_presets={"identity-only": {"include": ["identity"], "exclude": []}},
    )

    assert plan.selected_collectors == ["identity"]
    assert plan.execution_plane == "export"
    assert not hasattr(plan, "auth_scopes")
    assert plan.run_config.output_dir == tmp_path


def test_run_module_preflight_uses_injected_registry_seam(tmp_path: Path) -> None:
    class _BlockedCollector:
        name = "security"

        def run(self, _context: dict[str, Any]) -> CollectorResult:
            return CollectorResult(
                name=self.name,
                status="partial",
                item_count=0,
                message="blocked",
                payload={},
                coverage=[{"collector": self.name, "status": "failed"}],
            )

    class _Writer:
        run_dir = tmp_path

        def __init__(self) -> None:
            self.events: list[str] = []
            self.artifact_payload: dict[str, Any] | None = None

        def log_event(self, event: str, _message: str, _payload: dict[str, Any] | None = None) -> None:
            self.events.append(event)

        def write_json_artifact(self, name: str, payload: dict[str, Any]) -> Path:
            self.artifact_payload = payload
            return self.run_dir / name

    writer = _Writer()
    run_config = RunConfig(tenant_name="acme", output_dir=tmp_path, top_items=500, page_size=100)

    runnable, rows, artifact_path = run_preflight_probe(
        selected_collectors=["security"],
        completed_collectors=set(),
        client=object(),
        run_cfg=run_config,
        writer=writer,
        include_blocked=False,
        registry={"security": _BlockedCollector()},
    )

    assert runnable == []
    assert artifact_path == "preflight-plan.json"
    assert rows[0]["decision"] == "skip"
    assert rows[0]["reason"] == "known_blocked"
    assert writer.artifact_payload == {
        "collectors": rows,
        "runnable_collectors": [],
        "skipped_collectors": ["security"],
    }
