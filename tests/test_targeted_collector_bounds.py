"""Walk bounds must omit unusable data while retaining a collector's existing refusal."""
from __future__ import annotations

import json
from copy import deepcopy

import pytest

from auditex.scuba_projection import project_run
from azure_tenant_audit import cli
from azure_tenant_audit.collectors.targeted_users_coverage import sanitise_sample
from azure_tenant_audit.value_rules import assess

POLICY = "MS.AAD.6.1v1"
CANARY = "zq-bounds-canary@unlisted.invalid"
DOMAINS = {"status": "ok", "value": [{"id": "acme.example.invalid", "isVerified": True,
    "authenticationType": "Managed", "isRoot": True, "passwordValidityPeriodInDays": 2147483647}]}


def _sample(refusal=None):
    identity = {"domains": deepcopy(DOMAINS)}
    if refusal:
        deep = {"TargetedUsersToProtect": [CANARY]}
        for _ in range(80):
            deep = {"nested": deep}
        identity.update({refusal: "collector failed for " + CANARY, "value": [deep]})
    return {"identity": identity}


@pytest.mark.parametrize("refusal", ["error", "error_class"])
def test_past_bounds_own_data_keeps_refusal_and_independent_operation(refusal):
    sample = _sample(refusal)
    before = deepcopy(sample)
    cleaned = sanitise_sample(sample, None, None)
    assert cleaned["identity"].get(refusal), "the collector's refusal cannot disappear with its unusable own data"
    assert cleaned["identity"]["domains"] == DOMAINS
    assert CANARY not in json.dumps(cleaned)
    assert sample == before


def _replay(tmp_path, sample, name):
    source = tmp_path / (name + ".json")
    source.write_text(json.dumps(sample))
    before = source.read_bytes()
    cli.run_offline(source, tmp_path / "runs", "acme", name)
    assert source.read_bytes() == before
    return tmp_path / "runs" / ("acme-" + name)


def _verdict(run):
    projection = project_run(run)
    return assess(POLICY, deepcopy(projection.rule_sections))["verdict"]


def test_healthy_domain_control_is_met(tmp_path):
    assert _verdict(_replay(tmp_path, _sample(), "healthy")) == "met"


@pytest.mark.parametrize("refusal", ["error", "error_class"])
def test_bounded_minimisation_cannot_promote_a_failed_identity_collector(tmp_path, capsys, caplog, refusal):
    run = _replay(tmp_path, _sample(refusal), "failed")
    assert _verdict(run) == "not_assessed"
    # Offline replay publishes no per-collector raw file; the sanitised replay input is the identity evidence the
    # projection reads. It keeps the collector's refusal and the independent domains read.
    replayed = json.loads((run / "raw/sample_input.json").read_text())["identity"]
    assert replayed.get(refusal) and replayed["domains"] == DOMAINS
    assert all(CANARY.encode() not in p.read_bytes() for p in run.rglob("*") if p.is_file())
    captured = capsys.readouterr()
    assert CANARY not in captured.out + captured.err + caplog.text
