"""Customer packs, rendered reports and the explorer: what they read, what they say and how they are written.

Covers symbolic links and unlisted files in a run (integrity, handoff, pack copy), what verify-pack checks
beyond its own manifest (the copied bundle-hashes.json, extra files, expected digests, paths), the transport
ledger and the read-only wording in every renderer, and file modes under a permissive umask.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
from pathlib import Path
from typing import Any

import pytest

from auditex import cli as auditex_cli
from auditex.explorer import write_explorer
from auditex.reporting import (
    BundleIntegrityError,
    PackOutputError,
    _copy_source_artifact,
    _scope_risk_limitation,
    enterprise_handoff,
    render_api_call_inventory_markdown,
    render_enterprise_handoff_markdown,
    render_report,
    verify_enterprise_handoff_pack,
    write_enterprise_handoff_pack,
)
from azure_tenant_audit.api_inventory import with_observed_ledger
from azure_tenant_audit.bundle_integrity import BUNDLE_HASHES_PATH, verify_bundle_hashes
from azure_tenant_audit.cli import run_offline
from azure_tenant_audit.data_handling import build_data_handling_summary, classify_auth_scope
from azure_tenant_audit.private_io import copy_private_file, write_private_text

REPO_ROOT = Path(__file__).resolve().parents[1]


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture(scope="module")
def demo_bundle(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("pack-demo")
    rc = run_offline(
        REPO_ROOT / "examples" / "demo_tenant" / "demo_tenant.json", root, "halcyon", "demo",
        auditor_profile="global-reader", plane="inventory",
    )
    assert rc in (0, 1)
    return root / "halcyon-demo"


@pytest.fixture
def bundle(demo_bundle: Path, tmp_path: Path) -> Path:
    """A private copy of the demo bundle that a test may damage."""
    target = tmp_path / "work" / "halcyon-demo"
    shutil.copytree(demo_bundle, target)
    return target


@pytest.fixture(scope="module")
def google_bundle(tmp_path_factory: pytest.TempPathFactory) -> Path:
    from auditex.google_workspace.run import run_google_offline

    root = tmp_path_factory.mktemp("pack-google")
    rc = run_google_offline(
        sample_path=REPO_ROOT / "examples" / "google_workspace_sample.json",
        out=root, tenant_name="acme", run_name="google", domain="example.com", customer_id=None,
    )
    assert rc in (0, 1)
    return root / "acme-google"


@pytest.fixture
def umask_022():
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)


def _modes(root: Path) -> tuple[dict[str, int], dict[str, int]]:
    dirs = {".": stat.S_IMODE(root.stat().st_mode)}
    files: dict[str, int] = {}
    for current, directories, names in os.walk(root):
        for name in directories:
            path = Path(current) / name
            dirs[str(path.relative_to(root))] = stat.S_IMODE(path.stat().st_mode)
        for name in names:
            path = Path(current) / name
            files[str(path.relative_to(root))] = stat.S_IMODE(path.lstat().st_mode)
    return dirs, files


# --- links and unlisted files in a run (finding: unlisted and symlinked files read while integrity says verified) ----------


def test_a_symlink_to_a_file_outside_the_run_is_an_integrity_mismatch(bundle: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside.json"
    outside.write_text('{"trust_level": "trusted_complete"}', encoding="utf-8")
    (bundle / "live-readiness.json").symlink_to(outside)

    result = verify_bundle_hashes(bundle)

    assert result["status"] == "mismatch"
    assert result["symlinks"] == ["live-readiness.json"] and result["symlink_count"] == 1
    # A link is not an ordinary unlisted file: it is never hashed, never followed, and always a failure.
    assert result["unlisted"] == []


def test_a_symlinked_directory_is_an_integrity_mismatch(bundle: Path, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (bundle / "extra").symlink_to(elsewhere, target_is_directory=True)

    result = verify_bundle_hashes(bundle)

    assert result["status"] == "mismatch" and result["symlinks"] == ["extra"]


def test_a_link_in_a_bundle_without_a_hash_manifest_is_still_a_mismatch(bundle: Path, tmp_path: Path) -> None:
    (bundle / BUNDLE_HASHES_PATH).unlink()
    manifest = _json(bundle / "run-manifest.json")
    manifest["artifacts"].remove(BUNDLE_HASHES_PATH)
    manifest["schema_contract_version"] = "2026-10-20"  # finalized before the hash manifest existed
    (bundle / "run-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert verify_bundle_hashes(bundle)["status"] == "absent"
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    (bundle / "audit-plan.json").unlink()
    (bundle / "audit-plan.json").symlink_to(outside)

    result = verify_bundle_hashes(bundle)

    assert result["status"] == "mismatch" and result["symlinks"] == ["audit-plan.json"]


def test_a_symlink_makes_the_handoff_unusable_and_the_pack_is_refused(bundle: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside.json"
    outside.write_text('{"trust_level": "trusted_complete"}', encoding="utf-8")
    (bundle / "live-readiness.json").symlink_to(outside)

    handoff = enterprise_handoff(bundle)

    assert handoff["handoff_status"] == "unusable" and "bundle_integrity_mismatch" in handoff["status_reasons"]
    assert handoff["integrity"]["symlink_paths"] == ["live-readiness.json"]
    limit = next(row for row in handoff["limitations"] if row["surface"] == "bundle_integrity")
    assert "live-readiness.json" in limit["paths"] and "symbolic link" in limit["message"]
    pack = tmp_path / "pack"
    with pytest.raises(BundleIntegrityError):
        write_enterprise_handoff_pack(bundle, pack)
    assert not pack.exists()


@pytest.mark.parametrize("relative", ["live-readiness.json", "normalized/injected.json", "findings/extra.json", "blockers/extra.json"])
def test_an_unlisted_file_where_the_product_reads_fails_the_check(bundle: Path, tmp_path: Path, relative: str) -> None:
    target = bundle / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text('{"trust_level": "trusted_complete"}', encoding="utf-8")

    result = verify_bundle_hashes(bundle)

    assert result["status"] == "mismatch"
    assert result["unexpected"] == [relative] and result["unexpected_count"] == 1
    assert relative in result["unlisted"]
    handoff = enterprise_handoff(bundle)
    assert handoff["handoff_status"] == "unusable" and handoff["status_reasons"] == ["bundle_integrity_mismatch"]
    assert handoff["integrity"]["unexpected_paths"] == [relative]
    with pytest.raises(BundleIntegrityError) as caught:
        write_enterprise_handoff_pack(bundle, tmp_path / "pack")
    assert caught.value.integrity["unexpected_paths"] == [relative]


@pytest.mark.parametrize(
    "relative",
    ["reports/explorer.html", "reports/rendered-report.md", "reports/rendered-report.sarif.json", "reports/api-calls.md", "reports/proof-table.json"],
)
def test_a_named_output_written_after_finalization_does_not_fail_the_check(bundle: Path, relative: str) -> None:
    (bundle / relative).write_text("output", encoding="utf-8")

    result = verify_bundle_hashes(bundle)

    assert result["status"] == "verified" and result["unexpected"] == [] and result["unlisted"] == [relative]
    handoff = enterprise_handoff(bundle)
    assert handoff["handoff_status"] != "unusable"
    # The page the tooling writes on request is not a limitation of the run.
    assert not [row for row in handoff["limitations"] if row.get("status") == "unlisted_files"]


def test_an_unlisted_file_outside_the_paths_the_product_reads_is_a_limitation_not_a_failure(bundle: Path) -> None:
    (bundle / "raw").mkdir(exist_ok=True)
    (bundle / "raw" / "operator-note.txt").write_text("note", encoding="utf-8")

    result = verify_bundle_hashes(bundle)
    handoff = enterprise_handoff(bundle)

    assert result["status"] == "verified" and result["unexpected"] == []
    limit = next(row for row in handoff["limitations"] if row.get("status") == "unlisted_files")
    assert limit["paths"] == ["raw/operator-note.txt"]
    assert handoff["handoff_status"] != "unusable"


def test_the_pack_copy_never_follows_a_link_or_copies_a_file_the_manifest_does_not_list(bundle: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside.json"
    outside.write_text('{"secret": true}', encoding="utf-8")
    (bundle / "live-readiness.json").symlink_to(outside)
    (bundle / "data-handling.json").rename(bundle / "data-handling.moved")
    (bundle / "data-handling.json").symlink_to(bundle / "data-handling.moved")
    listed = {row["path"] for row in _json(bundle / BUNDLE_HASHES_PATH)["artifacts"]}
    root = tmp_path / "copied"

    linked = _copy_source_artifact(bundle, root, "live-readiness.json", "p", listed)
    through_a_link_in_the_run = _copy_source_artifact(bundle, root, "data-handling.json", "p", listed)
    unlisted = _copy_source_artifact(bundle, root, "data-handling.moved", "p", listed)
    plain = _copy_source_artifact(bundle, root, "summary.json", "p", listed)
    missing = _copy_source_artifact(bundle, root, "no-such-file.json", "p", listed)

    assert linked["present"] is False and linked["skipped_reason"] == "symbolic_link"
    assert through_a_link_in_the_run["present"] is False and through_a_link_in_the_run["skipped_reason"] == "symbolic_link"
    assert unlisted["present"] is False and unlisted["skipped_reason"] == "not_in_bundle_hashes"
    assert plain["present"] is True and Path(plain["path"]).read_bytes() == (bundle / "summary.json").read_bytes()
    assert "transformed" not in plain
    assert missing["present"] is False and "skipped_reason" not in missing
    assert sorted(path.name for path in root.rglob("*") if path.is_file()) == ["summary.json"]


# --- verify-pack (findings: copied bundle-hashes.json ignored, extra files ignored, absolute local paths) -----------------


def _write_pack(bundle: Path, tmp_path: Path, name: str = "pack") -> Path:
    pack = tmp_path / name
    write_enterprise_handoff_pack(bundle, pack)
    assert verify_enterprise_handoff_pack(pack)["valid"] is True
    return pack


def _rehash(pack: Path, *relatives: str) -> None:
    """Re-hash pack files the way someone who can write to the whole pack would: manifest, checksums, and the checksums row."""
    manifest_path = pack / "pack-manifest.json"
    manifest = _json(manifest_path)
    rows = {row["path"]: row for row in manifest["generated_files"] if row.get("path")}
    rows.update({row["path"]: row for row in manifest["source_artifacts"] if row.get("path")})
    for relative in relatives:
        rows[relative]["sha256"] = _sha256(pack / relative)
    checksum_lines = []
    for line in (pack / "checksums.sha256").read_text(encoding="utf-8").splitlines():
        digest, path = line.split(None, 1)
        checksum_lines.append(f"{_sha256(pack / path.strip())}  {path.strip()}" if path.strip() in relatives else line)
    (pack / "checksums.sha256").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
    rows["checksums.sha256"]["sha256"] = _sha256(pack / "checksums.sha256")
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def test_verify_pack_catches_an_edited_source_artifact_that_was_rehashed_with_the_pack(bundle: Path, tmp_path: Path) -> None:
    pack = _write_pack(bundle, tmp_path)
    target = pack / "source-artifacts" / "reports" / "report-pack.json"
    document = _json(target)
    for finding in document.get("findings") or []:
        finding["severity"] = "low"
    document["summary"]["edited"] = True
    target.write_text(json.dumps(document), encoding="utf-8")
    _rehash(pack, "source-artifacts/reports/report-pack.json")

    result = verify_enterprise_handoff_pack(pack)

    assert result["valid"] is False
    issue = next(item for item in result["issues"] if item["code"] == "source_artifact_bundle_hash_mismatch")
    assert issue["source_path"] == "reports/report-pack.json" and issue["expected"] != issue["actual"]
    assert issue["path"] == "source-artifacts/reports/report-pack.json"


def test_verify_pack_catches_a_replaced_bundle_hash_manifest(bundle: Path, tmp_path: Path) -> None:
    pack = _write_pack(bundle, tmp_path)
    target = pack / "source-artifacts" / "reports" / "report-pack.json"
    target.write_text(target.read_text(encoding="utf-8").replace('"summary"', '"summary_edited"', 1), encoding="utf-8")
    hashes_path = pack / "source-artifacts" / BUNDLE_HASHES_PATH
    hashes = _json(hashes_path)
    for row in hashes["artifacts"]:
        if row["path"] == "reports/report-pack.json":
            row["sha256"] = _sha256(target)
    hashes_path.write_text(json.dumps(hashes), encoding="utf-8")
    _rehash(pack, "source-artifacts/reports/report-pack.json", f"source-artifacts/{BUNDLE_HASHES_PATH}")

    result = verify_enterprise_handoff_pack(pack)

    codes = {item["code"] for item in result["issues"]}
    assert result["valid"] is False and "bundle_hashes_digest_mismatch" in codes
    assert "source_artifact_bundle_hash_mismatch" not in codes  # the replaced manifest agrees with the edit; its own digest does not


def test_verify_pack_checks_the_digests_supplied_separately(bundle: Path, tmp_path: Path, capsys) -> None:
    pack = _write_pack(bundle, tmp_path)
    digests = verify_enterprise_handoff_pack(pack)["digests"]
    assert digests["bundle_hashes_sha256"] == _sha256(bundle / BUNDLE_HASHES_PATH)
    assert digests["checksums_sha256"] == _sha256(pack / "checksums.sha256")
    assert digests["pack_manifest_sha256"] == _sha256(pack / "pack-manifest.json")

    assert verify_enterprise_handoff_pack(
        pack, expect_manifest_sha256=digests["bundle_hashes_sha256"], expect_checksums_sha256=digests["checksums_sha256"]
    )["valid"] is True
    wrong = verify_enterprise_handoff_pack(pack, expect_manifest_sha256="0" * 64, expect_checksums_sha256="1" * 64)
    assert {item["code"] for item in wrong["issues"]} == {"expected_manifest_sha256_mismatch", "expected_checksums_sha256_mismatch"}

    assert auditex_cli.main(["report", "verify-pack", str(pack), "--expect-manifest-sha256", digests["bundle_hashes_sha256"]]) == 0
    capsys.readouterr()
    assert auditex_cli.main(["report", "verify-pack", str(pack), "--expect-manifest-sha256", "0" * 64]) == 1
    assert "expected_manifest_sha256_mismatch" in capsys.readouterr().out


def test_verify_pack_reports_files_the_manifest_does_not_list(bundle: Path, tmp_path: Path) -> None:
    pack = _write_pack(bundle, tmp_path)
    (pack / "EXTRA.md").write_text("planted", encoding="utf-8")
    (pack / "source-artifacts" / "normalized").mkdir()
    (pack / "source-artifacts" / "normalized" / "injected.json").write_text("{}", encoding="utf-8")
    (pack / "link.md").symlink_to(pack / "handoff.md")

    result = verify_enterprise_handoff_pack(pack)

    unexpected = sorted(item["path"] for item in result["issues"] if item["code"] == "unexpected_file")
    assert unexpected == ["EXTRA.md", "link.md", "source-artifacts/normalized/injected.json"]
    assert result["valid"] is False


def test_a_pack_carries_no_absolute_path_of_the_operators_machine(bundle: Path, tmp_path: Path) -> None:
    pack = _write_pack(bundle, tmp_path)
    needles = {str(bundle), str(bundle.resolve()), str(tmp_path), str(tmp_path.resolve()), str(pack), str(pack.resolve())}

    offenders = {
        str(path.relative_to(pack)): needle
        for path in pack.rglob("*")
        if path.is_file()
        for needle in needles
        if needle in path.read_text(encoding="utf-8", errors="ignore")
    }

    assert offenders == {}
    manifest = _json(pack / "pack-manifest.json")
    assert manifest["run_dir"] == bundle.name and manifest["output_dir"] == "." and manifest["path_style"] == "pack_relative"
    assert all(not Path(row["path"]).is_absolute() for row in [*manifest["generated_files"], *manifest["source_artifacts"]] if row.get("path"))
    handoff = _json(pack / "handoff.json")
    assert handoff["run_dir"] == bundle.name
    assert set(handoff["review_commands"].values()) == {
        "auditex report render <run-dir> --format md",
        "auditex report api-calls <run-dir> --format md",
        "auditex report proof-table <run-dir> --format md",
        "auditex report handoff <run-dir> --format md",
    }


def test_a_pack_written_with_absolute_paths_by_an_earlier_version_still_verifies(bundle: Path, tmp_path: Path) -> None:
    pack = _write_pack(bundle, tmp_path)
    manifest_path = pack / "pack-manifest.json"
    manifest = _json(manifest_path)
    manifest["output_dir"] = str(pack)
    for row in [*manifest["generated_files"], *manifest["source_artifacts"]]:
        if row.get("path"):
            row["path"] = str(pack / row["path"])
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    moved = tmp_path / "received"
    shutil.move(str(pack), moved)

    assert verify_enterprise_handoff_pack(moved)["valid"] is True


def test_a_pack_refuses_a_directory_that_holds_something_else(bundle: Path, tmp_path: Path, capsys) -> None:
    target = tmp_path / "shared-folder"
    target.mkdir()
    (target / "notes.txt").write_text("someone else's file", encoding="utf-8")

    with pytest.raises(PackOutputError):
        write_enterprise_handoff_pack(bundle, target)
    assert [path.name for path in target.iterdir()] == ["notes.txt"]
    assert auditex_cli.main(["report", "customer-pack", str(bundle), "--output-dir", str(target)]) == 2
    assert "refusing to write a customer pack" in capsys.readouterr().err


def test_a_pack_directory_is_reused_for_the_next_pack_without_stale_files(bundle: Path, tmp_path: Path) -> None:
    pack = _write_pack(bundle, tmp_path)
    stale = pack / "source-artifacts" / "live-readiness.json"
    stale.write_text("{}", encoding="utf-8")
    assert any(item["code"] == "unexpected_file" for item in verify_enterprise_handoff_pack(pack)["issues"])

    write_enterprise_handoff_pack(bundle, pack)

    assert not stale.exists()
    assert verify_enterprise_handoff_pack(pack)["valid"] is True


def test_an_empty_directory_is_a_fine_place_for_a_pack(bundle: Path, tmp_path: Path) -> None:
    target = tmp_path / "empty"
    target.mkdir()

    write_enterprise_handoff_pack(bundle, target)

    assert verify_enterprise_handoff_pack(target)["valid"] is True


# --- the transport ledger and the read-only wording ----------------------------------------------------------------------


_LEDGER_EVENTS = [
    {"event": "graph.request.started", "details": {"method": "GET", "url": "https://graph.microsoft.com/v1.0/users", "attempt": 1, "params": {}}},
    {"event": "graph.request.completed", "details": {"method": "GET", "url": "https://graph.microsoft.com/v1.0/users", "attempt": 1, "status": 200}},
    {"event": "graph.request.started", "details": {"method": "GET", "url": "https://graph.microsoft.com/v1.0/devices", "attempt": 1, "params": {}}},
    {"event": "command.started", "details": {"adapter": "m365_cli", "command": "m365 purview hold list", "command_words": ["purview", "hold", "list"]}},
    {"event": "command.completed", "details": {"command": "m365 purview hold list", "status": "ok"}},
    {"event": "graph.request.refused", "details": {"method": "DELETE", "url": "https://graph.microsoft.com/v1.0/users/x", "reason": "not a read"}},
]


def _observed_inventory(events: list[dict[str, Any]] = _LEDGER_EVENTS) -> dict[str, Any]:
    return {
        "run_dir": "run",
        **with_observed_ledger(
            {
                "platform": "m365",
                "observed_calls": [{"collector": "identity", "endpoint": "/users", "method": "GET", "api_version": "v1.0", "status": "ok"}],
                "counts": {"observed_calls": 1},
                "safety": {"read_only": True, "no_content_reads": True},
            },
            events,
        ),
    }


def test_api_calls_markdown_renders_the_transport_ledger_beside_the_declared_rows() -> None:
    text = render_api_call_inventory_markdown(_observed_inventory())

    assert "- Declared calls: 1" in text and "- Observed calls: 1" not in text
    assert "## Declared calls" in text and "## Observed calls (transport ledger)" in text
    assert "- Basis: transport_audit_log" in text
    assert "- Graph requests attempted: 2" in text and "- Commands executed: 1" in text
    assert "| GET | /devices | v1.0 | 1 |" in text and "| GET | /users | v1.0 | 1 | 200: 1 |" in text
    assert "| m365_cli | purview hold list | 1 | ok: 1 | True |" in text
    assert "| graph | DELETE /users/x | not a read |" in text
    assert "### Calls outside the declared set" in text and "| graph | GET /devices |" in text
    assert "- Observed calls outside the declared set: 1" in text
    # The log shows a refused call, so the run is not read-only, and the page says it was observed.
    assert "- Read-only: False (observed in the transport audit log)" in text


def test_a_declared_only_inventory_says_it_is_declared_not_observed() -> None:
    text = render_api_call_inventory_markdown(
        {
            "platform": "google_workspace",
            "observed_calls": [{"collector": "google_directory", "endpoint": "admin.directory.users.list", "method": "GET"}],
            "counts": {"observed_calls": 1},
            "safety": {"read_only": True, "no_content_reads": True},
        }
    )

    assert "Read-only: True (declared, not observed)" in text
    assert "No content reads: True (declared, not observed)" in text
    assert not re.search(r"Read-only: True(?! \()", text)
    assert "No transport ledger in this bundle" in text


def test_the_handoff_and_pack_of_a_replay_say_it_was_replayed_and_never_claim_transport_observation(
    bundle: Path, tmp_path: Path
) -> None:
    """The demo bundle is an offline replay of a saved sample: no tenant was contacted, so no call was observed."""
    pack = _write_pack(bundle, tmp_path)
    handoff = _json(pack / "handoff.json")

    assert handoff["safety"]["observation_basis"] == "offline_replay"
    assert handoff["safety"]["replay_source"] == "demo_tenant.json"
    counts = handoff["counts"]
    assert counts["declared_calls"] == counts["api_calls"]
    assert {"observed_graph_requests", "observed_commands", "observed_outside_declared"} <= set(counts)
    for name in ("README.md", "handoff.md", "api-calls.md", "report.md"):
        text = (pack / name).read_text(encoding="utf-8")
        assert "Read-only: True (replayed from demo_tenant.json, no tenant contact)" in text, name
        assert "No content reads: True (replayed from demo_tenant.json, no tenant contact)" in text, name
        assert "observed in the transport audit log" not in text, name
        assert not re.search(r"(Read-only|No content reads): True(?! \()", text), name
    for name in ("README.md", "handoff.md", "api-calls.md"):
        text = (pack / name).read_text(encoding="utf-8")
        assert "Declared calls:" in text and "- API calls:" not in text, name
        assert "Observed Graph requests" not in text, name
        assert "Observed calls: none (replayed from demo_tenant.json, no tenant contact" in text, name
    assert "- Observation basis: offline_replay" in (pack / "handoff.md").read_text(encoding="utf-8")
    api = (pack / "api-calls.md").read_text(encoding="utf-8")
    assert "## Observed calls (transport ledger)" in api and "No transport ledger applies" in api
    assert "Graph requests attempted" not in api
    report = (pack / "report.md").read_text(encoding="utf-8")  # report.md nests the ledger under its API Calls section
    assert not re.search(r"^## Observed calls", report, re.MULTILINE)
    assert re.search(r"^### Observed calls \(transport ledger\)", report, re.MULTILINE)
    assert "every observed API call" not in (pack / "README.md").read_text(encoding="utf-8")
    assert "transport audit log recorded no" not in " ".join(row["message"] for row in handoff["limitations"])


def test_a_google_replay_pack_says_it_was_replayed_not_observed_or_merely_declared(google_bundle: Path, tmp_path: Path) -> None:
    pack = _write_pack(google_bundle, tmp_path)
    inventory = _json(google_bundle / "api-inventory.json")
    assert inventory["safety"]["observation_basis"] == "offline_replay"
    assert inventory["safety"]["replay_source"] == "google_workspace_sample.json"

    for name in ("README.md", "handoff.md", "api-calls.md", "report.md"):
        text = (pack / name).read_text(encoding="utf-8")
        assert "Read-only: True (replayed from google_workspace_sample.json, no tenant contact)" in text, name
        assert "No content reads: True (replayed from google_workspace_sample.json, no tenant contact)" in text, name
        assert not re.search(r"(Read-only|No content reads): True(?! \()", text), name
        assert "observed in the transport audit log" not in text, name
    handoff = (pack / "handoff.md").read_text(encoding="utf-8")
    assert "Auditex still stayed read-only" not in handoff
    assert "nothing was observed about calls to a tenant" in handoff
    assert _json(pack / "handoff.json")["safety"]["observation_basis"] == "offline_replay"


def test_a_live_run_keeps_the_transport_wording_and_a_declared_run_keeps_the_declared_wording() -> None:
    live = {
        "handoff_status": "ready",
        "safety": {"read_only": True, "no_content_reads": True, "observation_basis": "transport_audit_log"},
        "counts": {"declared_calls": 3, "observed_graph_requests": 7, "observed_commands": 0, "observed_outside_declared": 0},
    }
    declared = {**live, "safety": {"read_only": True, "no_content_reads": True, "observation_basis": "coverage_ledger_only"}}

    live_text = render_enterprise_handoff_markdown(live)
    declared_text = render_enterprise_handoff_markdown(declared)

    assert "- Read-only: True (observed in the transport audit log)" in live_text
    assert "- Observed Graph requests: 7" in live_text and "replayed" not in live_text
    assert "- Read-only: True (declared, not observed)" in declared_text and "replayed" not in declared_text


def test_the_scope_risk_limitation_claims_read_only_only_when_it_was_observed() -> None:
    observed = {"observation_basis": "transport_audit_log"}
    declared = {"observation_basis": "coverage_ledger_only"}

    seen = _scope_risk_limitation(platform="m365", scope_risk="write_capable_scope_present", write_capable_scopes=["a"], safety=observed, read_only=True)
    unseen = _scope_risk_limitation(platform="google_workspace", scope_risk="write_capable_scope_present", write_capable_scopes=["a"], safety=declared, read_only=True)
    broken = _scope_risk_limitation(platform="m365", scope_risk="read_only_scopes", write_capable_scopes=[], safety=observed, read_only=False)
    bare = _scope_risk_limitation(platform="m365", scope_risk="read_only_scopes", write_capable_scopes=[])

    assert "transport audit log recorded no write" in seen["message"] and "DNS, exposure and Power Platform" in seen["message"]
    assert "still stayed read-only" not in seen["message"] + unseen["message"] + broken["message"] + bare["message"]
    assert "stayed read-only" not in seen["message"] + broken["message"]
    assert "was not observed for this run" in unseen["message"] and unseen["observation_basis"] == "coverage_ledger_only"
    assert "not read-only" in broken["message"]
    assert "was not observed for this run" in bare["message"]
    assert seen["write_capable_scopes"] == ["a"]


def test_a_content_capable_google_scope_is_not_filed_under_read_only() -> None:
    drive = "https://www.googleapis.com/auth/drive.readonly"

    assert classify_auth_scope(drive) == "content_capable"
    assert classify_auth_scope("User.Read.All") == "read_only"
    assert classify_auth_scope("https://www.googleapis.com/auth/gmail.settings.basic") == "write_capable"
    summary = build_data_handling_summary(
        platform="google_workspace", mode="live", plane="inventory", collectors=["google_drive_posture"],
        auth_scopes=[drive, "https://www.googleapis.com/auth/admin.directory.user.readonly"],
    )
    assert summary["auth_scope_summary"]["content_capable"] == [drive]
    assert drive not in summary["auth_scope_summary"]["read_only"]
    assert summary["scope_risk"] == "content_capable_scope_present"
    write_capable = build_data_handling_summary(
        platform="google_workspace", mode="live", plane="inventory", collectors=[],
        auth_scopes=[drive, "https://www.googleapis.com/auth/gmail.settings.basic"],
    )
    assert write_capable["scope_risk"] == "write_capable_scope_present"


# --- file modes under a permissive umask (finding: packs, reports and the explorer take the caller's umask) -------------


def test_a_customer_pack_is_private_under_umask_022(bundle: Path, tmp_path: Path, umask_022) -> None:
    pack = tmp_path / "pack"

    write_enterprise_handoff_pack(bundle, pack)

    dirs, files = _modes(pack)
    assert files and {name: mode for name, mode in files.items() if mode != 0o600} == {}
    assert {name: mode for name, mode in dirs.items() if mode != 0o700} == {}
    assert "source-artifacts/reports/report-pack.json" in files and "pack-manifest.json" in files


def test_a_pack_written_into_a_loose_empty_directory_tightens_it(bundle: Path, tmp_path: Path, umask_022) -> None:
    target = tmp_path / "loose"
    target.mkdir()
    target.chmod(0o755)

    write_enterprise_handoff_pack(bundle, target)

    assert stat.S_IMODE(target.stat().st_mode) == 0o700


def test_the_rendered_report_and_the_explorer_are_private_inside_the_run(bundle: Path, umask_022) -> None:
    (bundle / "reports").chmod(0o700)

    rendered = render_report(run_dir=str(bundle), format_name="html")
    page = write_explorer([bundle], bundle / "reports" / "explorer.html")
    via_cli = auditex_cli.main(["report", "explorer", str(bundle)])

    assert via_cli == 0
    for path in (Path(rendered["output_path"]), page):
        assert stat.S_IMODE(path.lstat().st_mode) == 0o600, path
    dirs, files = _modes(bundle)
    assert {name: mode for name, mode in files.items() if mode != 0o600} == {}
    assert {name: mode for name, mode in dirs.items() if mode != 0o700} == {}
    assert verify_bundle_hashes(bundle)["status"] == "verified"


def test_a_report_payload_written_with_output_is_private_and_leaves_existing_directories_alone(bundle: Path, tmp_path: Path, umask_022, capsys) -> None:
    existing = tmp_path / "shared"
    existing.mkdir()
    existing.chmod(0o755)
    target = existing / "nested" / "deeper" / "api-calls.md"

    rc = auditex_cli.main(["report", "api-calls", str(bundle), "--format", "md", "--output", str(target)])

    assert rc == 0 and target.is_file()
    capsys.readouterr()
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert stat.S_IMODE(target.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(target.parent.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(existing.stat().st_mode) == 0o755


def test_the_private_writer_tightens_an_existing_file_and_never_writes_through_a_link(tmp_path: Path, umask_022) -> None:
    loose = tmp_path / "loose.txt"
    loose.write_text("old", encoding="utf-8")
    loose.chmod(0o644)
    victim = tmp_path / "victim.txt"
    victim.write_text("untouched", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(victim)

    write_private_text(loose, "new")
    write_private_text(link, "through the link?")
    source = tmp_path / "source.bin"
    source.write_bytes(b"\x00\x01")
    copy_private_file(source, tmp_path / "deep" / "copy.bin")

    assert loose.read_text(encoding="utf-8") == "new" and stat.S_IMODE(loose.stat().st_mode) == 0o600
    assert victim.read_text(encoding="utf-8") == "untouched"
    assert not link.is_symlink() and link.read_text(encoding="utf-8") == "through the link?"
    assert (tmp_path / "deep" / "copy.bin").read_bytes() == b"\x00\x01"
    assert stat.S_IMODE((tmp_path / "deep").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "deep" / "copy.bin").stat().st_mode) == 0o600
    assert not [path for path in tmp_path.rglob("*.tmp")]


def test_the_handoff_markdown_names_the_basis_next_to_the_flags(bundle: Path) -> None:
    text = render_enterprise_handoff_markdown(enterprise_handoff(bundle))

    assert "- Read-only: True (replayed from demo_tenant.json, no tenant contact)" in text
    assert "- Observation basis: offline_replay" in text
    assert "- Declared calls:" in text and "- Observed calls: none (replayed from demo_tenant.json, no tenant contact)" in text
    assert "Observed Graph requests" not in text
