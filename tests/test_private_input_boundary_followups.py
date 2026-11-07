"""Follow-ups to the private-input boundary: leftover writer temporaries and unsafe diff inputs."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from azure_tenant_audit.bundle_integrity import build_bundle_hash_manifest, verify_bundle_hashes

HEX = "0123456789abcdef01234567"
CANARY = b"synthetic-canary-list-bytes.example.invalid\n"
TEMPORARY_NAMES = (
    f".sensitive-users.txt.{HEX}.tmp",
    f".sensitive-users.key.{HEX}.tmp",
    f".partner-domains.txt.{HEX}.tmp",
    f".partner-domains.key.{HEX}.tmp",
    f"..gitignore.{HEX}.tmp",
    ".sensitive-users.txt.4242.tmp",
    ".partner-domains.key.tmp",
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
    import hashlib
    assert hashlib.sha256(CANARY).hexdigest() not in json.dumps(manifest)
    assert relative not in verify_bundle_hashes(run)["unlisted"]


@pytest.mark.parametrize("relative", [
    "operator-inputs/planted.json",
    "operator-inputs/.sensitive-users.txt.tmp.bak",
    f"operator-inputs/.sensitive-users.txt.{HEX}.tmpx",
    f"operator-inputs/.other.txt.{HEX}.tmp",
    f"operator-inputs/sub/.sensitive-users.txt.{HEX}.tmp",
    f"reports/.sensitive-users.txt.{HEX}.tmp",
    f".sensitive-users.txt.{HEX}.tmp",
])
def test_near_neighbour_files_stay_integrity_accounted(tmp_path, relative):
    run = _run(tmp_path)
    target = run / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"{}\n")
    manifest = build_bundle_hash_manifest(run)
    assert relative in {row["path"] for row in manifest["artifacts"]}
