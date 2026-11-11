"""Follow-ups to the private-input boundary: leftover writer temporaries and unsafe diff inputs."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from azure_tenant_audit.bundle_integrity import (
    build_bundle_hash_manifest,
    verify_bundle_hashes,
)

HEX = "0123456789abcdef01234567"
CANARY = b"synthetic-canary-list-bytes.example.invalid\n"
TEMPORARY_NAMES = (
    f".sensitive-users.txt.{HEX}.tmp",
    f".sensitive-users.key.{HEX}.tmp",
    f".partner-domains.txt.{HEX}.tmp",
    f".partner-domains.key.{HEX}.tmp",
    f"..gitignore.{HEX}.tmp",
    ".sensitive-users.txt.4242.tmp",
)


def _run(tmp_path: Path) -> Path:
    run = tmp_path / "run"
    (run / "reports").mkdir(parents=True)
    (run / "reports" / "a.json").write_text("{}\n")
    (run / "run-manifest.json").write_text("{}\n")
    return run


@pytest.mark.parametrize("directory", ["operator-inputs", "Operator-Inputs"])
@pytest.mark.parametrize("name", TEMPORARY_NAMES)
def test_private_writer_temporaries_are_named_without_hash_or_size(tmp_path, directory, name):
    run = _run(tmp_path)
    (run / directory).mkdir()
    (run / directory / name).write_bytes(CANARY)
    manifest = build_bundle_hash_manifest(run)
    relative = f"{directory}/{name}"
    assert relative not in {row["path"] for row in manifest["artifacts"]}
    assert {"path": relative, "reason": "redacted_operator_input"} in manifest["excluded"]
    assert "reports/a.json" in {row["path"] for row in manifest["artifacts"]}
    assert hashlib.sha256(CANARY).hexdigest() not in json.dumps(manifest)
    assert relative not in verify_bundle_hashes(run)["unlisted"]


@pytest.mark.parametrize("relative", [
    "operator-inputs/planted.json",
    "operator-inputs/.partner-domains.key.tmp",
    "operator-inputs/.sensitive-users.txt.tmp",
    "operator-inputs/.sensitive-users.txt.4242.tmp\n",
    f"operator-inputs/.sensitive-users.txt.{HEX}.tmp\n",
    "operator-inputs/.sensitive-users.txt.tmp.bak",
    f"operator-inputs/.sensitive-users.txt.{HEX}.tmpx",
    f"operator-inputs/.other.txt.{HEX}.tmp",
    f"operator-inputs/sub/.sensitive-users.txt.{HEX}.tmp",
    f"reports/.sensitive-users.txt.{HEX}.tmp",
    f".sensitive-users.txt.{HEX}.tmp",
    ".partner-domains.key.tmp",
    ".sensitive-users.txt.tmp",
    ".sensitive-users.txt.4242.tmp\n",
    f".sensitive-users.txt.{HEX}.tmp\n",
    f".sensitive-users.txt.{HEX.upper()}.tmp",
])
def test_near_neighbour_files_stay_integrity_accounted(tmp_path, relative):
    run = _run(tmp_path)
    target = run / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"{}\n")
    manifest = build_bundle_hash_manifest(run)
    assert relative in {row["path"] for row in manifest["artifacts"]}
    # Unknown files are also still reported by verification (unlisted when added after the seal).
    (run / "bundle-hashes.json").write_text(json.dumps({**manifest, "artifacts": [], "artifact_count": 0}))
    assert relative in verify_bundle_hashes(run)["unlisted"]


# --- Existing manifests that already carry private fingerprints, and case aliases ---------------------------

SEAL_REFUSAL = "private operator input"


def _real_run(tmp_path: Path) -> Path:
    from gate_support import offline_run

    run = offline_run(tmp_path / "src")
    assert verify_bundle_hashes(run)["status"] == "verified"
    return run


def _prefix_manifest(run: Path, relative: str, content: bytes = CANARY) -> str:
    """Save a manifest in the shape the older writer produced: the private file listed with its digest and size."""
    target = run / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    manifest = json.loads((run / "bundle-hashes.json").read_text())
    digest = hashlib.sha256(content).hexdigest()
    manifest["artifacts"].append({"path": relative, "sha256": digest, "bytes": len(content)})
    manifest["artifact_count"] = len(manifest["artifacts"])
    (run / "bundle-hashes.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return digest


@pytest.mark.parametrize("relative", [
    f"operator-inputs/.sensitive-users.txt.{HEX}.tmp",
    "operator-inputs/.partner-domains.key.4242.tmp",
    "Operator-Inputs/.partner-domains.txt." + HEX + ".tmp",
])
def test_existing_manifest_row_for_a_private_input_is_refused_and_never_packed(tmp_path, relative):
    from auditex.reporting import BundleIntegrityError, write_enterprise_handoff_pack

    run = _real_run(tmp_path)
    digest = _prefix_manifest(run, relative)
    before = (run / "bundle-hashes.json").read_bytes()
    integrity = verify_bundle_hashes(run)
    assert integrity["status"] == "invalid"
    assert SEAL_REFUSAL in integrity["message"]
    assert relative not in integrity["message"] and digest not in json.dumps(integrity)
    assert integrity["modified"] == [] and integrity["checked_count"] == 0
    pack = tmp_path / "pack"
    with pytest.raises(BundleIntegrityError):
        write_enterprise_handoff_pack(run, pack)
    assert not pack.exists() or digest.encode() not in b"".join(
        p.read_bytes() for p in pack.rglob("*") if p.is_file())
    assert (run / "bundle-hashes.json").read_bytes() == before  # the legacy bundle is never rewritten


def test_new_manifest_with_reason_only_exclusions_and_ordinary_run_verifies_and_packs(tmp_path):
    from auditex.reporting import (
        verify_enterprise_handoff_pack,
        write_enterprise_handoff_pack,
    )

    run = _real_run(tmp_path)
    for name in (f".sensitive-users.txt.{HEX}.tmp", ".partner-domains.key.4242.tmp"):
        (run / "operator-inputs").mkdir(exist_ok=True)
        (run / "operator-inputs" / name).write_bytes(CANARY)
    manifest = build_bundle_hash_manifest(run)
    (run / "bundle-hashes.json").write_text(json.dumps(manifest, indent=2) + "\n")
    assert {row["reason"] for row in manifest["excluded"] if "tmp" in row["path"]} == {"redacted_operator_input"}
    integrity = verify_bundle_hashes(run)
    assert integrity["status"] == "verified" and integrity["unexpected"] == []
    pack = tmp_path / "pack"
    write_enterprise_handoff_pack(run, pack)
    assert verify_enterprise_handoff_pack(pack)["valid"]
    digest = hashlib.sha256(CANARY).hexdigest().encode()
    assert digest not in b"".join(p.read_bytes() for p in pack.rglob("*") if p.is_file())


def test_unknown_unlisted_file_next_to_valid_exclusions_is_still_flagged(tmp_path):
    run = _real_run(tmp_path)
    (run / "operator-inputs").mkdir(exist_ok=True)
    (run / "operator-inputs" / f".sensitive-users.txt.{HEX}.tmp").write_bytes(CANARY)
    (run / "bundle-hashes.json").write_text(json.dumps(build_bundle_hash_manifest(run)))
    (run / "findings").mkdir(exist_ok=True)
    (run / "findings" / "planted.json").write_text("{}")
    integrity = verify_bundle_hashes(run)
    assert integrity["status"] == "mismatch" and "findings/planted.json" in integrity["unexpected"]


def _fs_is_case_insensitive(directory: Path) -> bool:
    probe = directory / "CaseProbe.tmp"
    probe.write_text("x")
    try:
        return (directory / "caseprobe.tmp").exists()
    finally:
        probe.unlink()


def test_case_renamed_writer_temporary_follows_the_real_filesystem(tmp_path):
    run = _run(tmp_path)
    inputs = run / "operator-inputs"
    inputs.mkdir()
    insensitive = _fs_is_case_insensitive(inputs)
    canonical = f".sensitive-users.txt.{HEX}.tmp"
    alias = f".SENSITIVE-USERS.TXT.{HEX}.TMP"
    (inputs / canonical).write_bytes(CANARY)
    if insensitive:
        # The residual was renamed in case only: the same file, so the same private classification.
        os.rename(inputs / canonical, inputs / "tmp-step")
        os.rename(inputs / "tmp-step", inputs / alias)
        assert (inputs / canonical).exists()
        manifest = build_bundle_hash_manifest(run)
        assert {"path": f"operator-inputs/{alias}", "reason": "redacted_operator_input"} in manifest["excluded"]
        assert hashlib.sha256(CANARY).hexdigest() not in json.dumps(manifest)
    else:
        # A separate upper-case file is not an alias of anything: it stays hashed and accounted.
        (inputs / alias).write_bytes(b"{}\n")
        manifest = build_bundle_hash_manifest(run)
        assert f"operator-inputs/{alias}" in {row["path"] for row in manifest["artifacts"]}
        assert f"operator-inputs/{canonical}" not in {row["path"] for row in manifest["artifacts"]}


def test_upper_case_unrelated_file_is_never_exempt(tmp_path):
    run = _run(tmp_path)
    (run / "operator-inputs").mkdir()
    (run / "operator-inputs" / f".SENSITIVE-USERS.TXT.{HEX}.TMP").write_bytes(b"{}\n")
    manifest = build_bundle_hash_manifest(run)
    paths = {row["path"] for row in manifest["artifacts"]}
    insensitive = _fs_is_case_insensitive(run / "operator-inputs")
    # With no lower-case file standing beside it there is nothing it can alias, on either filesystem.
    assert f"operator-inputs/.SENSITIVE-USERS.TXT.{HEX}.TMP" in paths or insensitive


def test_symlinked_lowercase_name_is_not_an_alias(tmp_path):
    run = _run(tmp_path)
    inputs = run / "operator-inputs"
    inputs.mkdir()
    upper = inputs / f".SENSITIVE-USERS.TXT.{HEX}.TMP"
    upper.write_bytes(b"{}\n")
    lower = inputs / f".sensitive-users.txt.{HEX}.tmp"
    if lower.exists():  # case-insensitive filesystem: the names are one file, nothing to link
        pytest.skip("case-insensitive filesystem")
    lower.symlink_to(upper)
    manifest = build_bundle_hash_manifest(run)
    assert f"operator-inputs/.SENSITIVE-USERS.TXT.{HEX}.TMP" in {row["path"] for row in manifest["artifacts"]}


@pytest.mark.parametrize("relative", [
    "operator-inputs/sensitive-users.txt", "operator-inputs/sensitive-users.key",
    "operator-inputs/partner-domains.txt", "operator-inputs/partner-domains.key", "operator-inputs/.gitignore",
    "./operator-inputs/partner-domains.key", f"Operator-Inputs/.sensitive-users.key.{HEX}.tmp",
])
def test_private_row_classifier_covers_named_inputs_and_temporaries(relative):
    from azure_tenant_audit.bundle_integrity import is_private_operator_input

    assert is_private_operator_input(relative)


@pytest.mark.parametrize("relative", [
    "reports/a.json", "operator-inputs/planted.json", ".sensitive-users.txt." + HEX + ".tmp",
    "operator-inputs/.partner-domains.key.tmp", f"operator-inputs/.sensitive-users.txt.{HEX}.tmp\n",
    f"operator-inputs/sub/.sensitive-users.txt.{HEX}.tmp",
])
def test_private_row_classifier_leaves_ordinary_rows_alone(relative):
    from azure_tenant_audit.bundle_integrity import is_private_operator_input

    assert not is_private_operator_input(relative)
