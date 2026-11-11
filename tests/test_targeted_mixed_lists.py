"""A target-bearing unsupported list is a diagnostic component, not a free-text passthrough."""
from __future__ import annotations

import json
from copy import deepcopy

import pytest

from azure_tenant_audit import cli
from azure_tenant_audit.collectors.targeted_users_coverage import sanitise_sample

CANARIES = ("Zebulon Quarkwright", "zq-canary@unlisted-canary.invalid")
SAFE = {"id": "safe-identity", "displayName": "Ordinary", "enabled": True}


def _carrier():
    return [{"TargetedUsersToProtect": list(CANARIES)}, "failed for " + CANARIES[0], CANARIES[1],
            deepcopy(SAFE), 3, False, None]


@pytest.mark.parametrize("placement", ["root", "operation", "nested-list"])
def test_affected_lists_drop_free_text_but_preserve_independent_records_and_counts(placement):
    carrier = _carrier()
    sample = {"legacyRows": carrier} if placement == "root" else {
        "identity": {"legacyRows": carrier if placement == "operation" else [carrier]}}
    sample["other"] = {"values": ["unrelated string", "keep.example.invalid", 1]}
    original = deepcopy(sample)
    cleaned = sanitise_sample(sample, None, None)
    text = json.dumps(cleaned)
    assert all(canary not in text for canary in CANARIES)
    assert SAFE["displayName"] in text and SAFE["id"] in text
    assert cleaned["other"] == sample["other"]
    assert sample == original
    selected = cleaned["legacyRows"] if placement == "root" else cleaned["identity"]["legacyRows"]
    if placement == "nested-list":
        selected = selected[0]
    assert 3 in selected and False in selected and None in selected


def test_offline_list_diagnostics_never_reach_files_stdout_or_logs(tmp_path, capsys, caplog):
    sample = {"legacyRows": _carrier(), "identity": {"users": {"value": [deepcopy(SAFE)]}}}
    source = tmp_path / "mixed.json"
    source.write_text(json.dumps(sample))
    original = source.read_bytes()
    cli.run_offline(source, tmp_path / "runs", "acme", "mixed")
    run = tmp_path / "runs/acme-mixed"
    assert (run / "run-manifest.json").is_file()
    leaks = [(str(path.relative_to(run)), canary) for path in run.rglob("*") if path.is_file()
             for canary in CANARIES if canary.encode() in path.read_bytes()]
    assert leaks == []
    captured = capsys.readouterr()
    assert all(canary not in captured.out + captured.err + caplog.text for canary in CANARIES)
    assert source.read_bytes() == original


def test_non_bearing_lists_are_unchanged():
    sample = {"legacyRows": ["an ordinary diagnostic", "domain.example.invalid", 1, False, None, deepcopy(SAFE)]}
    assert sanitise_sample(sample, None, None) == sample
