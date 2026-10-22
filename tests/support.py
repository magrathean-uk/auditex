from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def complete_admin_set_evidence(**overrides: Any) -> Any:
    """Evidence that every source of the effective administrator set was read in full."""
    from azure_tenant_audit.effective_admins import AdminSetEvidence
    from azure_tenant_audit.identity_controls import Evidence

    collected = Evidence("collected")
    values: dict[str, Any] = {
        "role_definitions": collected,
        "role_assignments": collected,
        "assignment_schedules": collected,
        "eligibility_schedules": collected,
        "group_fanout": collected,
    }
    values.update(overrides)
    return AdminSetEvidence(**values)


def with_effective_admin_set(snapshot: dict[str, Any], evidence: Any = None) -> dict[str, Any]:
    """A hand-built normalized snapshot plus its ``effective_admin_set`` section.

    Normalization derives the section from the snapshot's own users, groups, role and membership
    records; ``evidence`` says how completely the sources were read (all of them, by default).
    """
    from azure_tenant_audit.effective_admins import SECTION, build_effective_admin_set

    def records(name: str) -> list[dict[str, Any]]:
        return list((snapshot.get(name) or {}).get("records") or [])

    section = build_effective_admin_set(
        users=records("users"),
        groups=records("groups"),
        service_principals=records("service_principals"),
        role_definitions=records("role_definitions"),
        role_assignments=records("role_assignments"),
        governance_objects=records("governance_objects"),
        membership_edges=records("group_membership_edges"),
        evidence=evidence or complete_admin_set_evidence(),
    )
    return {**snapshot, SECTION: {"kind": SECTION, "records": section}}


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


@dataclass
class RunBundleBuilder:
    base_dir: Path
    name: str = "run"
    _manifest: dict[str, Any] = field(default_factory=dict)
    _summary: dict[str, Any] = field(default_factory=dict)
    _summary_md: str | None = None
    _report_pack: dict[str, Any] | None = None
    _report_pack_path: str = "reports/report-pack.json"
    _action_plan: object | None = None
    _action_plan_path: str = "reports/action-plan.json"
    _findings: object | None = None
    _blockers: object | None = None
    _auth_context: dict[str, Any] | None = None
    _auth_context_path: str = "auth-context.json"
    _session_context: dict[str, Any] | None = None
    _capability_matrix: object | None = None
    _toolchain_readiness: dict[str, Any] | None = None
    _live_readiness: dict[str, Any] | None = None
    _live_readiness_path: str = "live-readiness.json"
    _api_inventory: dict[str, Any] | None = None
    _api_inventory_path: str = "api-inventory.json"
    _data_handling: dict[str, Any] | None = None
    _data_handling_path: str = "data-handling.json"
    _evidence_db_path: str | None = None

    @property
    def run_dir(self) -> Path:
        return self.base_dir / self.name

    def manifest(self, **overrides: Any) -> RunBundleBuilder:
        self._manifest.update(overrides)
        return self

    def summary(self, **overrides: Any) -> RunBundleBuilder:
        self._summary.update(overrides)
        return self

    def summary_md(self, text: str = "# Audit Summary") -> RunBundleBuilder:
        self._summary_md = text
        return self

    def report_pack(self, *, path: str = "reports/report-pack.json", **overrides: Any) -> RunBundleBuilder:
        self._report_pack_path = path
        payload = {
            "summary": {"tenant_name": "acme", "overall_status": "partial", "finding_count": 0},
            "findings": [],
            "evidence_paths": [],
        }
        payload.update(overrides)
        self._report_pack = payload
        return self

    def action_plan(self, payload: object | None = None, *, path: str = "reports/action-plan.json") -> RunBundleBuilder:
        self._action_plan_path = path
        self._action_plan = payload if payload is not None else {
            "open_findings": [],
            "waived_findings": [],
            "blocked": [],
        }
        return self

    def findings(self, payload: object) -> RunBundleBuilder:
        self._findings = payload
        return self

    def blockers(self, payload: object) -> RunBundleBuilder:
        self._blockers = payload
        return self

    def auth_context(self, payload: dict[str, Any], *, path: str = "auth-context.json") -> RunBundleBuilder:
        self._auth_context_path = path
        self._auth_context = payload
        self._manifest.setdefault("auth_context_path", path)
        return self

    def session_context(self, payload: dict[str, Any]) -> RunBundleBuilder:
        self._session_context = payload
        return self

    def capability_matrix(self, payload: object) -> RunBundleBuilder:
        self._capability_matrix = payload
        return self

    def toolchain_readiness(self, payload: dict[str, Any]) -> RunBundleBuilder:
        self._toolchain_readiness = payload
        return self

    def live_readiness(self, payload: dict[str, Any], *, path: str = "live-readiness.json") -> RunBundleBuilder:
        self._live_readiness_path = path
        self._live_readiness = payload
        self._manifest.setdefault("live_readiness_path", path)
        return self

    def api_inventory(self, payload: dict[str, Any], *, path: str = "api-inventory.json") -> RunBundleBuilder:
        self._api_inventory_path = path
        self._api_inventory = payload
        self._manifest.setdefault("api_inventory_path", path)
        return self

    def data_handling(self, payload: dict[str, Any], *, path: str = "data-handling.json") -> RunBundleBuilder:
        self._data_handling_path = path
        self._data_handling = payload
        self._manifest.setdefault("data_handling_path", path)
        return self

    def evidence_db(self, *, path: str = "index/evidence.sqlite") -> RunBundleBuilder:
        self._evidence_db_path = path
        self._manifest.setdefault("evidence_db_path", path)
        return self

    def build(self) -> Path:
        manifest = {
            "tenant_name": "acme",
            "tenant_id": "tenant-1",
            "run_id": "run-1",
            "created_utc": "2026-04-21T10:00:00Z",
            "overall_status": "partial",
        }
        manifest.update(self._manifest)
        summary = {"tenant_name": manifest["tenant_name"], "collectors": []}
        summary.update(self._summary)

        write_json(self.run_dir / "run-manifest.json", manifest)
        write_json(self.run_dir / "summary.json", summary)
        if self._summary_md is not None:
            (self.run_dir / "summary.md").write_text(self._summary_md, encoding="utf-8")
        if self._report_pack is not None:
            write_json(self.run_dir / self._report_pack_path, self._report_pack)
        if self._action_plan is not None:
            write_json(self.run_dir / self._action_plan_path, self._action_plan)
        if self._findings is not None:
            write_json(self.run_dir / "findings" / "findings.json", self._findings)
        if self._blockers is not None:
            write_json(self.run_dir / "blockers" / "blockers.json", self._blockers)
        if self._auth_context is not None:
            write_json(self.run_dir / self._auth_context_path, self._auth_context)
        if self._session_context is not None:
            write_json(self.run_dir / "session-context.json", self._session_context)
        if self._capability_matrix is not None:
            write_json(self.run_dir / "capability-matrix.json", self._capability_matrix)
        if self._toolchain_readiness is not None:
            write_json(self.run_dir / "toolchain-readiness.json", self._toolchain_readiness)
        if self._live_readiness is not None:
            write_json(self.run_dir / self._live_readiness_path, self._live_readiness)
        if self._api_inventory is not None:
            write_json(self.run_dir / self._api_inventory_path, self._api_inventory)
        if self._data_handling is not None:
            write_json(self.run_dir / self._data_handling_path, self._data_handling)
        if self._evidence_db_path is not None:
            evidence_path = self.run_dir / self._evidence_db_path
            evidence_path.parent.mkdir(parents=True, exist_ok=True)
            evidence_path.write_text("", encoding="utf-8")
        return self.run_dir


def make_contract_valid(run_dir: Path) -> Path:
    """Complete a hand-built bundle so that it passes a real validation, and leave what it states alone.

    Handoff, the customer pack and the explorer recompute validation instead of trusting a
    ``validation.json`` that only says ``valid``. A bundle built from ``RunBundleBuilder`` has the
    artifacts a test cares about; this adds what the contract also needs (the root artifacts'
    required fields, an evidence index, an ``ai_context.json``) and a record for every evidence
    reference to land on. It does not touch ``validation.json`` if the test wrote one, and it raises
    with the validation issues if the bundle is still not valid.
    """
    from azure_tenant_audit.contracts import CONTRACT_VERSION, build_validation_report
    from azure_tenant_audit.evidence_db import build_run_evidence_index

    def load(relative: str, default: Any) -> Any:
        path = run_dir / relative
        if not path.is_file():
            return default
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            return default

    manifest = load("run-manifest.json", {})
    summary = load("summary.json", {})
    tenant = manifest.get("tenant_name") or "acme"
    run_id = manifest.get("run_id") or "run-1"
    for key, value in {
        "schema_version": "2026-04-21",
        "tenant_name": tenant,
        "run_id": run_id,
        "overall_status": "ok",
        "mode": "offline",
        "auditor_profile": "global-reader",
        "selected_collectors": [],
        "artifacts": [],
        "evidence_db_path": "index/evidence.sqlite",
        "ai_context_path": "ai_context.json",
        "validation_path": "validation.json",
        "schema_contract_version": CONTRACT_VERSION,
    }.items():
        manifest.setdefault(key, value)
    for key, value in {"schema_version": "2026-04-21", "tenant_name": tenant, "run_id": run_id, "collectors": []}.items():
        summary.setdefault(key, value)

    pack_path = run_dir / str(manifest.get("report_pack_path") or "reports/report-pack.json")
    pack = load(str(pack_path.relative_to(run_dir)), {})
    pack.setdefault("schema_version", "2026-04-21")
    pack.setdefault("summary", {"tenant_name": tenant, "overall_status": manifest["overall_status"]})
    pack.setdefault("findings", [])
    pack.setdefault("evidence_paths", [])

    write_json(run_dir / "run-manifest.json", manifest)
    write_json(run_dir / "summary.json", summary)
    write_json(pack_path, pack)
    # Every evidence reference needs a record to land on: give each cited artifact a row for its key.
    cited: dict[str, list[str]] = {}
    findings_file = load("findings/findings.json", [])
    rows = [*pack["findings"], *(findings_file if isinstance(findings_file, list) else [])]
    refs = [ref for finding in rows for ref in finding.get("evidence_refs") or []]
    refs += [row for row in pack.get("proof_table") or [] if isinstance(row, dict)]
    for ref in refs:
        if isinstance(ref, dict) and ref.get("artifact_path"):
            keys = cited.setdefault(str(ref["artifact_path"]), [])
            if ref.get("record_key") and ref["record_key"] not in keys:
                keys.append(str(ref["record_key"]))
    for relative, keys in cited.items():
        document = load(relative, {})
        if isinstance(document, list):
            document.extend({"key": key} for key in keys)
        else:
            document.setdefault("records", [])
            document["records"].extend({"key": key} for key in keys)
        write_json(run_dir / relative, document)

    (run_dir / "normalized").mkdir(parents=True, exist_ok=True)
    if not (run_dir / "ai_context.json").is_file():
        write_json(
            run_dir / "ai_context.json",
            {
                "schema_version": "2026-04-21",
                "run": {"tenant_name": tenant, "run_id": run_id, "platform": manifest.get("platform", "m365")},
                "privacy": {"safe_for_external_llm": False},
                "counts": {"normalized_counts": {}},
                "coverage": {},
                "findings": {"count": len(rows)},
                "artifacts": {"root": []},
                "read_order": [],
            },
        )
    build_run_evidence_index(run_dir)
    if not (run_dir / "validation.json").is_file():
        write_json(run_dir / "validation.json", build_validation_report(run_dir=run_dir, read_only=True))
    report = build_validation_report(run_dir=run_dir, read_only=True)
    if not report["valid"]:
        raise AssertionError(f"hand-built bundle still fails validation: {json.dumps(report['issues'], indent=2)}")
    return run_dir


@dataclass(frozen=True)
class FakeDoctorToolchain:
    blocked_tools: set[str] = field(default_factory=set)
    versions: dict[str, str] = field(default_factory=dict)
    azure_auth: dict[str, Any] = field(
        default_factory=lambda: {"status": "supported", "user_name": "reader@contoso.test"}
    )
    m365_auth: dict[str, Any] = field(
        default_factory=lambda: {"status": "supported", "active_connection": "tenant-user"}
    )
    exchange_auth: dict[str, Any] = field(
        default_factory=lambda: {"status": "supported", "module_version": "3.7.0"}
    )

    def install(self, monkeypatch: Any, bootstrap_module: Any) -> None:
        monkeypatch.setattr(
            bootstrap_module,
            "_selected_python",
            lambda: {"status": "supported", "path": "/usr/bin/python3.13", "version": "Python 3.13.2"},
        )
        monkeypatch.setattr(
            bootstrap_module,
            "_venv_status",
            lambda: {"status": "supported", "path": "/tmp/.venv", "python_path": "/tmp/.venv/bin/python"},
        )
        monkeypatch.setattr(bootstrap_module, "detect_package_manager", lambda: "brew")
        monkeypatch.setattr(bootstrap_module, "_tool_status", self.tool_status)
        monkeypatch.setattr("auditex.auth.get_auth_status", self.auth_status)

    def tool_status(self, name: str, **_: object) -> dict[str, object]:
        if name in self.blocked_tools:
            return {"name": name, "status": "blocked", "path": None, "version": None, "error": "command_not_found"}
        return {
            "name": name,
            "status": "supported",
            "path": f"/usr/bin/{name}",
            "version": self.versions.get(name, f"{name}-1.0"),
            "error": None,
        }

    def auth_status(self, **_: object) -> dict[str, Any]:
        return {
            "azure_cli": self.azure_auth,
            "m365": self.m365_auth,
            "exchange": self.exchange_auth,
        }


class FakeGraphResponse:
    def __init__(self, status_code: int, body: object, *, headers: dict[str, str] | None = None) -> None:
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}
        self.url = "https://graph.microsoft.com/v1.0/me"

    @property
    def text(self) -> str:
        if isinstance(self._body, str):
            return self._body
        return str(self._body)

    def json(self) -> object:
        return self._body


def graph_response(status_code: int, body: object, *, headers: dict[str, str] | None = None) -> FakeGraphResponse:
    return FakeGraphResponse(status_code, body, headers=headers)


def graph_auth(**overrides: Any):
    from azure_tenant_audit.config import AuthConfig

    defaults = {"tenant_id": "t-1", "client_id": "c-1", "auth_mode": "access_token", "access_token": "x"}
    defaults.update(overrides)
    return AuthConfig(**defaults)


def fake_graph_client(**auth_overrides: Any):
    from azure_tenant_audit.graph import GraphClient

    return GraphClient(graph_auth(**auth_overrides))
