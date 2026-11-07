"""SS 2.1 offline replay: the sample's target lists are summarised and dropped before the replay copy and iteration.

Uses only the base ``run_offline`` API plus product consumers, so on a base without the collect boundary the planted
canaries reach ``raw/sample_input.json`` and the tests fail on their assertions. Constructed data only.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from azure_tenant_audit import cli
from azure_tenant_audit.sensitive_users import SensitiveUsers

SS21 = "MS.SECURITYSUITE.2.1v1"
CONFIGURED = ("ss21-configured-a@configured-canary.invalid", "ss21-configured-b@configured-canary.invalid")
UNCONFIGURED = ("Zebulon Quarkwright", "zq-canary@unlisted-canary.invalid", "canary-domain-x.invalid",
                "Name;;bad@@canary-malformed")
FRAGMENTS = ("Zebulon", "Quarkwright", "zq-canary", "unlisted-canary", "canary-domain-x", "canary-malformed",
             "configured-canary", "Configured Person")
OLD_DIGEST = "ab" * 32
SETTINGS = {"Identity": "Default", "Name": "Default", "IsDefault": True, "Enabled": True,
            "EnableTargetedUserProtection": True, "TargetedUserProtectionAction": "Quarantine"}
TARGETS = [f"Configured Person;{CONFIGURED[0]}", CONFIGURED[1].upper(), *UNCONFIGURED]
HEALTHY = {name: {"status": "ok", "value": []} for name in (
    "acceptedDomains", "antiPhishRules", "eopProtectionPolicyRules", "atpProtectionPolicyRules", "atpPolicyForO365")}


def _custom(identity, **fields):
    return {**SETTINGS, "Identity": identity, "Name": identity, "IsDefault": False, **fields}


def _sample(anti_phish):
    return {"exchange_policy": {
        **deepcopy(HEALTHY),
        "antiPhishPolicies": anti_phish,
        "legacyAntiPhish": {"value": [{"Identity": "Legacy", "TargetedUsersToProtect": list(UNCONFIGURED)}]},
        "unexpected": {"nested": {"deeper": [{"targetedUsersToProtect": list(UNCONFIGURED)}]}},
    }, "defender": {"value": [{"TargetedUsersToProtect": list(UNCONFIGURED), "Identity": "Flat"}]}}


ALL_SHAPES = {"status": "ok", "value": [
    {**SETTINGS, "TargetedUsersToProtect": TARGETS, "Extra": UNCONFIGURED[0]},
    _custom("Custom-old-proof", TargetedUsersCoverage={
        "version": 1, "state": "known", "input_hmac_sha256": OLD_DIGEST, "input_count": 2,
        "protected_nonempty": True, "missing_count": 0}),
    _custom("Custom-bad", TargetedUsersToProtect=[{"Name": UNCONFIGURED[0]}, *CONFIGURED]),
    _custom("Custom-both", TargetedUsersToProtect=[CONFIGURED[0]], TargetedUsersCoverage={
        "version": 1, "state": "known", "input_hmac_sha256": OLD_DIGEST, "input_count": 2,
        "protected_nonempty": True, "missing_count": 0}),
]}


def _replay(tmp_path: Path, sample: dict, *, users=CONFIGURED, name="ss21"):
    path = tmp_path / f"{name}-sample.json"
    path.write_text(json.dumps(sample))
    before = path.read_bytes()
    out = tmp_path / "out"
    cli.run_offline(path, out, "acme", name, sensitive_users=SensitiveUsers(tuple(sorted(users))) if users else None)
    assert (out / f"acme-{name}" / "run-manifest.json").is_file()
    assert path.read_bytes() == before, "the source sample is never modified"
    return out / f"acme-{name}"


def _files(root: Path):
    return sorted(p for p in root.rglob("*") if p.is_file())


def _scan(root: Path, *, allowed_configured: tuple[str, ...] = ("operator-inputs/sensitive-users.txt",)):
    leaks = []
    for path in _files(root):
        relative = path.relative_to(root).as_posix()
        data = path.read_bytes()
        for fragment in FRAGMENTS:
            configured = fragment in ("configured-canary",)
            if fragment.encode() in data and not (configured and any(relative.endswith(a) for a in allowed_configured)):
                leaks.append((relative, fragment))
        if b"TargetedUsersToProtect\"" in data or b"targetedUsersToProtect\"" in data:
            leaks.append((relative, "target key"))
    return leaks


def _manifest(run_dir: Path):
    return json.loads((run_dir / "run-manifest.json").read_text())


def _anti_phish(run_dir: Path):
    sample = json.loads((run_dir / "raw/sample_input.json").read_text())
    return sample["exchange_policy"]["antiPhishPolicies"]


def test_replay_summarises_fresh_literals_and_never_rebinds_an_old_proof(tmp_path, capsys, caplog):
    run_dir = _replay(tmp_path, _sample(deepcopy(ALL_SHAPES)))
    assert _scan(run_dir) == []
    captured = capsys.readouterr()
    assert not [f for f in FRAGMENTS if f in captured.out + captured.err + caplog.text]
    digest = _manifest(run_dir)["operator_inputs"]["sensitive_users"]["hmac_sha256"]
    rows = _anti_phish(run_dir)["value"]
    assert [row["TargetedUsersCoverage"] for row in rows] == [
        {"version": 1, "state": "known", "input_hmac_sha256": digest, "input_count": 2,
         "protected_nonempty": True, "missing_count": 0},
        {"version": 1, "state": "not_collected"},
        {"version": 1, "state": "unusable"},
        {"version": 1, "state": "known", "input_hmac_sha256": digest, "input_count": 2,
         "protected_nonempty": True, "missing_count": 1},
    ]
    assert "Extra" not in rows[0] and rows[2]["TargetedUserProtectionAction"] == "Quarantine"
    assert all(OLD_DIGEST.encode() not in path.read_bytes() for path in _files(run_dir))
    private = (run_dir / "operator-inputs/sensitive-users.txt").read_text()
    assert private == "\n".join(CONFIGURED) + "\n"


def test_replay_without_operator_input_keeps_no_proof_and_no_literals(tmp_path):
    run_dir = _replay(tmp_path, _sample(deepcopy(ALL_SHAPES)), users=None)
    assert _scan(run_dir, allowed_configured=()) == []
    assert {row["TargetedUsersCoverage"]["state"] for row in _anti_phish(run_dir)["value"]} == {"not_collected"}


@pytest.mark.parametrize("envelope", [
    {"error": "command_failed:1 Zebulon Quarkwright", "error_class": "command_error", "return_code": 1,
     "stdout": json.dumps([{"TargetedUsersToProtect": list(UNCONFIGURED)}]), "stderr": "zq-canary@unlisted-canary.invalid"},
    {"status": "ok", "value": [{**SETTINGS, "TargetedUsersToProtect": TARGETS}, "Zebulon Quarkwright"]},
    {"status": "ok", "value": "Zebulon Quarkwright"},
    {"status": "ok", "rows": [{**SETTINGS, "TargetedUsersToProtect": TARGETS}]},
])
def test_replay_error_envelopes_and_unrecognised_layouts_keep_no_target_text(tmp_path, envelope):
    run_dir = _replay(tmp_path, _sample(deepcopy(envelope)))
    assert _scan(run_dir) == []
    replayed = _anti_phish(run_dir)
    if isinstance(replayed, dict):
        assert "value" not in replayed or all(isinstance(row, dict) for row in replayed["value"])
        assert not {"stdout", "stderr"} & set(replayed)


def test_each_fresh_replay_binds_to_its_own_key(tmp_path):
    first = _replay(tmp_path, _sample(deepcopy(ALL_SHAPES)), name="first")
    second = _replay(tmp_path, _sample(deepcopy(ALL_SHAPES)), name="second")
    digests = [_manifest(run)["operator_inputs"]["sensitive_users"]["hmac_sha256"] for run in (first, second)]
    assert digests[0] != digests[1], "a new run never imports an old run's key"
    for run, digest in zip((first, second), digests):
        assert _anti_phish(run)["value"][0]["TargetedUsersCoverage"]["input_hmac_sha256"] == digest
    assert (first / "operator-inputs/sensitive-users.key").read_bytes() != (
        second / "operator-inputs/sensitive-users.key").read_bytes()


def test_replayed_summary_reaches_the_rule_and_stays_out_of_every_shareable_output(tmp_path):
    from auditex.cli import render_report, write_customer_pack
    from auditex.model_serving import assess_run
    from auditex.reporting import FORMAT_EXTENSIONS
    from auditex.scuba_projection import project_run, rule_policy_section
    from azure_tenant_audit.value_rules import assess

    run_dir = _replay(tmp_path, _sample({"status": "ok", "value": [{**SETTINGS, "TargetedUsersToProtect": TARGETS}]}))
    projection = project_run(run_dir)
    sections = deepcopy(projection.rule_sections)
    sections["scuba_config"] = rule_policy_section(projection, SS21, "scuba_config")
    record = assess(SS21, sections)
    assert (record["verdict"], record["cell"]) == ("met", "default_qualifies")

    digest = _manifest(run_dir)["operator_inputs"]["sensitive_users"]["hmac_sha256"]
    assess_run(run_dir, policies=[SS21])
    assess_run(run_dir, policies=[SS21], dry_run=True)
    rendered = 0
    for format_name in sorted(FORMAT_EXTENSIONS):
        render_report(run_dir=str(run_dir), format_name=format_name,
                      output_path=str(tmp_path / f"report-{format_name}{FORMAT_EXTENSIONS[format_name]}"))
        rendered += 1
    assert rendered >= 3
    pack = tmp_path / "pack"
    write_customer_pack(str(run_dir), str(pack))
    assert _scan(run_dir) == [] and _scan(tmp_path / "out") == []
    shareable = [*_files(pack), *(p for p in _files(tmp_path)
                                  if any(part.startswith("report-") for part in p.relative_to(tmp_path).parts))]
    assert shareable
    for path in shareable:
        data = path.read_bytes()
        assert digest.encode() not in data and b"TargetedUsersCoverage" not in data, path.name
        assert not [f for f in FRAGMENTS if f.encode() in data], path.name
