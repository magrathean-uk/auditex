"""Offline metadata must use the same transient target boundary as the replay copy."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from azure_tenant_audit import cli


CANARIES = ("Zebulon Quarkwright", "zq-canary@unlisted-canary.invalid")


@pytest.mark.parametrize("origin", ["sample", "override", "both"])
@pytest.mark.parametrize("encoded", [False, True])
def test_fixture_provenance_cannot_bypass_target_minimisation(tmp_path, capsys, caplog, origin, encoded):
    carrier = {"TargetedUsersToProtect": list(CANARIES), "error": CANARIES[0]}
    provenance = {"payload": json.dumps(carrier)} if encoded else carrier
    sample = {"identity": {"users": {"value": []}}}
    if origin in {"sample", "both"}:
        sample["_fixture_provenance"] = provenance
    sample_path = tmp_path / "sample.json"
    sample_path.write_text(json.dumps(sample))
    before = sample_path.read_bytes()
    override = provenance if origin in {"override", "both"} else None
    cli.run_offline(sample_path, tmp_path / "runs", "acme", "fixture-boundary",
                    fixture_provenance_override=override)
    run = tmp_path / "runs" / "acme-fixture-boundary"
    assert (run / "run-manifest.json").is_file()
    leaks = [(str(path.relative_to(run)), canary)
             for path in run.rglob("*") if path.is_file()
             for canary in CANARIES if canary.encode() in path.read_bytes()]
    assert leaks == [], "fixture provenance must never retain target-bearing metadata"
    output = capsys.readouterr()
    assert all(canary not in output.out + output.err + caplog.text for canary in CANARIES)
    assert sample_path.read_bytes() == before
    assert override is None or override == provenance


def test_safe_fixture_provenance_preserves_existing_merge_semantics(tmp_path):
    sample = {"identity": {"users": {"value": []}},
              "_fixture_provenance": {"scenario": "synthetic", "facts": {"a": 1}}}
    source = tmp_path / "safe.json"
    source.write_text(json.dumps(sample))
    cli.run_offline(source, tmp_path / "runs", "acme", "safe-metadata",
                    fixture_provenance_override={"facts": {"b": 2}})
    run = tmp_path / "runs" / "acme-safe-metadata"
    manifest = json.loads((run / "run-manifest.json").read_text())
    assert manifest["fixture_provenance"] == {"scenario": "synthetic", "facts": {"a": 1, "b": 2}}
