"""Scripted collectors for tests that drive ``cli.run_live`` with the payloads and coverage rows they choose (no network)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from azure_tenant_audit import cli
from azure_tenant_audit.collectors.base import CollectorResult

REPO_ROOT = Path(__file__).resolve().parents[1]


class FakeClient:
    """A Graph client that answers nothing: the scripted collectors never reach it."""

    def __init__(self, auth: Any, audit_event: Any = None) -> None:
        self.audit_event = audit_event

    def get_json(self, path: str, **_: Any) -> dict[str, Any]:
        return {}

    def get_all(self, path: str, params: Any = None) -> list[Any]:  # noqa: ARG002
        return []


class Scripted:
    """A collector whose ``run`` returns the next scripted step: ``(status, coverage rows, payload)`` or raises it.

    The last step repeats. ``windowed`` marks it as a collector that reads events between ``--since`` and ``--until``.
    """

    def __init__(self, name: str, *steps: Any, windowed: bool = False) -> None:
        self.name = name
        self.steps = list(steps)
        self.calls = 0
        self.contexts: list[dict[str, Any]] = []
        self.time_windowed = windowed

    def run(self, context: dict[str, Any]) -> CollectorResult:
        self.contexts.append({"since": context.get("since"), "until": context.get("until")})
        step = self.steps[min(self.calls, len(self.steps) - 1)]
        self.calls += 1
        if isinstance(step, BaseException):
            raise step
        status, coverage, payload = step
        return CollectorResult(
            name=self.name,
            status=status,
            item_count=sum(int(row.get("item_count") or 0) for row in coverage),
            message=status,
            error=None if status == "ok" else "x",
            payload=payload,
            coverage=coverage,
        )


def ok_row(collector: str, name: str, count: int = 1, **extra: Any) -> dict[str, Any]:
    return {
        "collector": collector, "type": "graph", "name": name, "endpoint": f"/{collector}/{name}", "status": "ok",
        "item_count": count, "error_class": None, "error": None, **extra,
    }


def failed_row(collector: str, name: str, error_class: str = "service_unavailable", error: str = "503 Service Unavailable") -> dict[str, Any]:
    return {
        "collector": collector, "type": "graph", "name": name, "endpoint": f"/{collector}/{name}", "status": "failed",
        "item_count": 0, "error_class": error_class, "error": error,
    }


def ok_step(collector: str, payload: dict[str, Any]) -> tuple[str, list[dict[str, Any]], dict[str, Any]]:
    """An ``ok`` step: one ``ok`` coverage row per section of ``payload``."""
    rows = [ok_row(collector, name, len(section.get("value") or [])) for name, section in payload.items() if isinstance(section, dict)]
    return "ok", rows, payload


def failed_step(collector: str, *sections: str, error_class: str = "service_unavailable", error: str = "503 Service Unavailable") -> tuple[str, list[dict[str, Any]], dict[str, Any]]:
    """A ``partial`` step in which every named section failed."""
    return (
        "partial",
        [failed_row(collector, name, error_class, error) for name in sections],
        {name: {"error": error, "error_class": error_class} for name in sections},
    )


def sample(name: str) -> dict[str, Any]:
    return json.loads((REPO_ROOT / "examples" / "sample_audit_bundle" / name).read_text(encoding="utf-8"))


def run_scripted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    registry: dict[str, Any],
    collectors: str,
    *extra: str,
    run_name: str = "probe",
) -> int:
    """Run ``cli.run_live`` with ``registry`` as the collector registry; the run lands in ``tmp_path/acme-<run_name>``."""
    args = cli.build_parser().parse_args(
        [
            "--tenant-name", "acme", "--tenant-id", "t-123", "--use-azure-cli-token", "--collectors", collectors,
            "--out", str(tmp_path), "--run-name", run_name, *extra,
        ]
    )
    monkeypatch.setattr(cli, "GraphClient", FakeClient)
    monkeypatch.setattr(cli, "REGISTRY", registry)
    monkeypatch.setattr(cli, "_acquire_azure_cli_access_token", lambda *_, **__: "cached-token")
    return cli.run_live(args)


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def rule_statuses(run_dir: Path) -> dict[str, set[tuple[str, str]]]:
    """``rule id -> {(status, reason)}`` across every framework control of the report pack."""
    pack = load(run_dir / "reports" / "report-pack.json")
    alignment = pack.get("baseline_alignment") or pack.get("summary", {}).get("baseline_alignment")
    out: dict[str, set[tuple[str, str]]] = {}
    for framework in alignment["frameworks"].values():
        for control in framework["controls"]:
            for status in control["rule_statuses"]:
                out.setdefault(status["rule_id"], set()).add((status["status"], status.get("reason") or ""))
    return out


def control_statuses(run_dir: Path, framework: str) -> dict[str, str]:
    pack = load(run_dir / "reports" / "report-pack.json")
    alignment = pack.get("baseline_alignment") or pack.get("summary", {}).get("baseline_alignment")
    return {control["control_id"]: control["status"] for control in alignment["frameworks"][framework]["controls"]}
