#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCRIPT_PATH = Path(__file__).resolve()
TENANT_BOOTSTRAP_ROOT = SCRIPT_PATH.parents[1]
REPO_ROOT = SCRIPT_PATH.parents[2]
SRC_ROOT = REPO_ROOT / "src"

for candidate in (SRC_ROOT, REPO_ROOT):
    text = str(candidate)
    if text not in sys.path:
        sys.path.insert(0, text)

from auditex.google_workspace.run import run_google_offline
from azure_tenant_audit.cli import run_offline


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class FixtureReplaySpec:
    key: str
    tenant_name: str
    run_name: str
    sample_path: Path
    provider: str
    domain: str | None = None
    customer_id: str | None = None
    auditor_profile: str = "global-reader"
    plane: str = "inventory"


FIXTURE_SPECS: dict[str, FixtureReplaySpec] = {
    "m365": FixtureReplaySpec(
        key="m365",
        tenant_name="contoso",
        run_name="known-bad",
        sample_path=REPO_ROOT / "examples" / "sample_audit_bundle" / "known_bad_result.json",
        provider="m365",
    ),
    "google": FixtureReplaySpec(
        key="google",
        tenant_name="Example",
        run_name="google-known-bad",
        sample_path=REPO_ROOT / "examples" / "google_workspace_sample.json",
        provider="google_workspace",
        domain="example.com",
        customer_id="C123",
    ),
}


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _fixture_provenance(path: Path) -> dict[str, Any]:
    payload = _load_json(path)
    fixture_provenance = payload.get("_fixture_provenance")
    return dict(fixture_provenance) if isinstance(fixture_provenance, dict) else {}


def _bootstrap_seed_provenance(run_dir: Path | None) -> dict[str, Any] | None:
    if run_dir is None:
        return None
    resolved = run_dir.expanduser().resolve()
    identity_manifest = resolved / "identity-seed-az-manifest.json"
    workload_manifest = resolved / "workload-seed-az-manifest.json"
    payload: dict[str, Any] = {"run_dir": str(resolved)}
    if identity_manifest.exists():
        identity = _load_json(identity_manifest)
        payload["identity"] = {
            "manifest_path": str(identity_manifest),
            "runName": identity.get("runName"),
            "tenantId": identity.get("tenantId"),
            "tenantDomain": identity.get("tenantDomain"),
            "plannedUsers": identity.get("plannedUsers"),
            "plannedStaticGroups": identity.get("plannedStaticGroups"),
            "plannedDynamicGroups": identity.get("plannedDynamicGroups"),
            "status": identity.get("status"),
            "completedAt": identity.get("completedAt"),
        }
    if workload_manifest.exists():
        workload = _load_json(workload_manifest)
        payload["workload"] = {
            "manifest_path": str(workload_manifest),
            "runName": workload.get("runName"),
            "tenantId": workload.get("tenantId"),
            "tenantDomain": workload.get("tenantDomain"),
            "steps": workload.get("steps"),
            "teamIds": workload.get("teamIds"),
            "status": workload.get("status"),
            "completedAt": workload.get("completedAt"),
        }
    return payload if len(payload) > 1 else None


def _run_dir(base_out: Path, spec: FixtureReplaySpec) -> Path:
    return base_out / f"{spec.tenant_name}-{spec.run_name}"


def _replay_fixture(spec: FixtureReplaySpec, *, out_dir: Path, clean: bool, bootstrap_run_dir: Path | None) -> dict[str, Any]:
    sample_path = spec.sample_path.resolve()
    if not sample_path.exists():
        raise FileNotFoundError(f"fixture sample not found: {sample_path}")

    run_dir = _run_dir(out_dir, spec)
    if run_dir.exists():
        if not clean:
            raise FileExistsError(f"fixture replay output already exists: {run_dir}")
        shutil.rmtree(run_dir)

    bootstrap_seed = _bootstrap_seed_provenance(bootstrap_run_dir)
    fixture_override = {"bootstrap_seed": bootstrap_seed} if bootstrap_seed else None

    if spec.provider == "m365":
        rc = run_offline(
            sample_path=sample_path,
            out=out_dir,
            tenant_name=spec.tenant_name,
            run_name=spec.run_name,
            auditor_profile=spec.auditor_profile,
            plane=spec.plane,
            fixture_provenance_override=fixture_override,
        )
    else:
        rc = run_google_offline(
            sample_path=sample_path,
            out=out_dir,
            tenant_name=spec.tenant_name,
            run_name=spec.run_name,
            domain=spec.domain,
            customer_id=spec.customer_id,
            fixture_provenance_override=fixture_override,
        )
    if rc != 0:
        raise RuntimeError(f"{spec.key} fixture replay failed with exit code {rc}")

    manifest = _load_json(run_dir / "run-manifest.json")
    report_pack = _load_json(run_dir / "reports" / "report-pack.json")
    validation = _load_json(run_dir / "validation.json")
    fixture_provenance = _fixture_provenance(sample_path)
    if bootstrap_seed:
        fixture_provenance["bootstrap_seed"] = bootstrap_seed
    return {
        "fixture": spec.key,
        "provider": spec.provider,
        "sample_path": str(sample_path),
        "run_dir": str(run_dir),
        "run_manifest_path": str(run_dir / "run-manifest.json"),
        "report_pack_path": str(run_dir / "reports" / "report-pack.json"),
        "validation_path": str(run_dir / "validation.json"),
        "contract_status": manifest.get("contract_status"),
        "validation_valid": bool(validation.get("valid")),
        "finding_count": int(report_pack.get("summary", {}).get("finding_count") or 0),
        "fixture_provenance": fixture_provenance,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Replay shipped known-bad fixtures into validated offline Auditex bundles.")
    parser.add_argument(
        "--fixture",
        action="append",
        choices=sorted(FIXTURE_SPECS),
        dest="fixtures",
        help="Fixture key to replay. Repeat to limit output. Defaults to all known fixtures.",
    )
    parser.add_argument(
        "--bootstrap-run-dir",
        default=None,
        help="Optional tenant-bootstrap run directory with identity/workload seed manifests to attach as fixture provenance.",
    )
    parser.add_argument(
        "--out",
        default=str(TENANT_BOOTSTRAP_ROOT / "fixture-output"),
        help="Output directory for replayed bundles and manifest.",
    )
    parser.add_argument(
        "--manifest-name",
        default="known-bad-fixture-replay.json",
        help="Manifest filename written under --out.",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Remove existing replayed run directories before regenerating them.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    selected = args.fixtures or list(FIXTURE_SPECS)
    out_dir = Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    bootstrap_run_dir = Path(args.bootstrap_run_dir).expanduser().resolve() if args.bootstrap_run_dir else None

    replay_rows = [
        _replay_fixture(FIXTURE_SPECS[key], out_dir=out_dir, clean=args.clean, bootstrap_run_dir=bootstrap_run_dir)
        for key in selected
    ]
    manifest = {
        "kind": "known_bad_fixture_replay",
        "generated_utc": _now_iso(),
        "tenant_bootstrap_root": str(TENANT_BOOTSTRAP_ROOT),
        "repo_root": str(REPO_ROOT),
        "bootstrap_run_dir": str(bootstrap_run_dir) if bootstrap_run_dir is not None else None,
        "fixtures": replay_rows,
    }
    manifest_path = out_dir / args.manifest_name
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
