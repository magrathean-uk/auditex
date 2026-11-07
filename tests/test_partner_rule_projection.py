"""SS 2.3 private PartnerDomains consumer in the deterministic rule view.

Constructed bundles only: the real AuditWriter publishes the private pairs and the real guard
verifies them. Nothing here mocks admission or the HMAC.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from azure_tenant_audit.guarded_io import UnsafeRunFileError
from azure_tenant_audit.model_evidence import NOT_COLLECTED
from azure_tenant_audit.partner_domains import (
    BUNDLE_PATH as PARTNER_PATH, KEY_PATH as PARTNER_KEY_PATH, PartnerDomains,
)
from azure_tenant_audit.sensitive_users import (
    BUNDLE_PATH as USERS_PATH, KEY_PATH as USERS_KEY_PATH, SensitiveUsers,
)

SS21 = "MS.SECURITYSUITE.2.1v1"
SS23 = "MS.SECURITYSUITE.2.3v1"
SS32 = "MS.SECURITYSUITE.3.2v1"
DOMAINS = ("partner-rule-a.example.invalid", "partner-rule-b.example.invalid")
USERS = ("sensitive-rule-a@example.invalid", "sensitive-rule-b@example.invalid")


def bundle(tmp_path, *, users=USERS, domains=DOMAINS, name="partner-rules"):
    from azure_tenant_audit.output import AuditWriter

    writer = AuditWriter(tmp_path, "mocktenant", name)
    if users:
        writer.write_sensitive_users(SensitiveUsers(users))
    if domains:
        writer.write_partner_domains(PartnerDomains(domains))
    writer.write_bundle({"collectors": [], "overall_status": "ok"})
    return writer.run_dir


def rule_view(projection, policy):
    from auditex.scuba_projection import rule_policy_section

    return rule_policy_section(projection, policy, "scuba_config")


def test_partner_domains_reach_only_the_ss23_rule_view(tmp_path):
    from auditex.scuba_projection import project_run

    projection = project_run(bundle(tmp_path, users=()))
    assert rule_view(projection, SS23) == {"SecuritySuite": {SS23: {"PartnerDomains": list(DOMAINS)}}}
    assert rule_view(projection, SS21) == NOT_COLLECTED
    assert rule_view(projection, SS32) == NOT_COLLECTED


def test_both_inputs_fill_independent_slots(tmp_path):
    from auditex.scuba_projection import project_run

    projection = project_run(bundle(tmp_path))
    assert rule_view(projection, SS21) == {"SecuritySuite": {SS21: {"SensitiveUsers": list(USERS)}}}
    assert rule_view(projection, SS23) == {"SecuritySuite": {SS23: {"PartnerDomains": list(DOMAINS)}}}
    assert rule_view(projection, SS32) == NOT_COLLECTED


def test_absent_partner_domains_leave_ss21_and_ss23_unprojected(tmp_path):
    from auditex.scuba_projection import project_run

    projection = project_run(bundle(tmp_path, domains=()))
    assert rule_view(projection, SS21) == {"SecuritySuite": {SS21: {"SensitiveUsers": list(USERS)}}}
    assert rule_view(projection, SS23) == NOT_COLLECTED


def test_neither_input_projects_no_security_suite_rule_view(tmp_path):
    from auditex.scuba_projection import project_run

    projection = project_run(bundle(tmp_path, users=(), domains=()))
    assert all(rule_view(projection, policy) == NOT_COLLECTED for policy in (SS21, SS23, SS32))


def test_real_hmac_is_verified_once_per_pair_and_reads_each_file_once(tmp_path, monkeypatch):
    from auditex.scuba_projection import project_run

    root = bundle(tmp_path)
    original, opened = os.open, []

    def capture(path, flags, *args, **kwargs):
        if Path(path).name in {"partner-domains.txt", "partner-domains.key"}:
            opened.append(Path(path).name)
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", capture)
    projection = project_run(root)
    assert rule_view(projection, SS23)["SecuritySuite"][SS23]["PartnerDomains"] == list(DOMAINS)
    assert opened == ["partner-domains.txt", "partner-domains.key"]


@pytest.mark.parametrize("damage", [
    "tampered", "hmac", "count", "bool-count", "missing-key", "missing-list", "short-key",
    "false-with-pair", "extra-metadata", "bad-metadata", "symlink-list", "symlink-key",
    "swap-with-users", "key-is-users-key",
])
@pytest.mark.parametrize("sibling", [True, False])
def test_unsafe_partner_pair_refuses_the_whole_run(tmp_path, damage, sibling):
    """Admission fails before projection; a healthy SensitiveUsers sibling is not salvaged."""
    from auditex.scuba_projection import project_run

    root = bundle(tmp_path, users=USERS if sibling else ())
    target, key = root / PARTNER_PATH, root / PARTNER_KEY_PATH
    manifest_path = root / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    metadata = manifest["operator_inputs"]["partner_domains"]
    if damage == "tampered":
        target.write_text(DOMAINS[0] + "\n")
    elif damage == "hmac":
        metadata["hmac_sha256"] = "0" * 64
    elif damage == "count":
        metadata["count"] = 1
    elif damage == "bool-count":
        metadata["count"] = True
    elif damage == "missing-key":
        key.unlink()
    elif damage == "missing-list":
        target.unlink()
    elif damage == "short-key":
        key.write_bytes(b"short")
    elif damage == "false-with-pair":
        manifest["operator_inputs"]["partner_domains"] = {"supplied": False}
    elif damage == "extra-metadata":
        metadata["unexpected"] = True
    elif damage == "bad-metadata":
        manifest["operator_inputs"]["partner_domains"] = []
    elif damage == "symlink-list":
        target.unlink()
        target.symlink_to(root / "run-manifest.json")
    elif damage == "symlink-key":
        key.unlink()
        key.symlink_to(target)
    elif damage == "swap-with-users":
        # The users list standing in for the partner list: refused, not tolerated.
        if not sibling:
            pytest.skip("needs a SensitiveUsers pair to swap in")
        target.unlink()
        target.symlink_to(root / USERS_PATH)
    elif damage == "key-is-users-key":
        if not sibling:
            pytest.skip("needs a SensitiveUsers pair to alias")
        key.unlink()
        key.symlink_to(root / USERS_KEY_PATH)
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(UnsafeRunFileError):
        project_run(root)


@pytest.mark.parametrize("damage", ["bad-metadata", "extra-metadata", "missing-key", "tampered"])
def test_malformed_sibling_metadata_is_not_tolerated_for_valid_partner_domains(tmp_path, damage):
    """The guard stays whole-run: a damaged SensitiveUsers sibling refuses a valid PartnerDomains pair."""
    from auditex.scuba_projection import project_run

    root = bundle(tmp_path)
    manifest_path = root / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if damage == "bad-metadata":
        manifest["operator_inputs"]["sensitive_users"] = []
    elif damage == "extra-metadata":
        manifest["operator_inputs"]["sensitive_users"]["unexpected"] = True
    elif damage == "missing-key":
        (root / USERS_KEY_PATH).unlink()
    else:
        (root / USERS_PATH).write_text(USERS[0] + "\n")
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(UnsafeRunFileError):
        project_run(root)


def test_unreadable_partner_pair_refuses_the_run(tmp_path, monkeypatch):
    from auditex.scuba_projection import project_run

    root = bundle(tmp_path, users=())
    original = os.open

    def deny(path, flags, *args, **kwargs):
        if Path(path).name == "partner-domains.txt":
            raise PermissionError(13, "constructed denial")
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", deny)
    with pytest.raises(UnsafeRunFileError):
        project_run(root)


def test_resume_with_existing_writer_replaces_and_clears_the_partner_view(tmp_path):
    from auditex.scuba_projection import project_run
    from azure_tenant_audit.output import AuditWriter

    root = bundle(tmp_path, users=())
    assert rule_view(project_run(root), SS23)["SecuritySuite"][SS23]["PartnerDomains"] == list(DOMAINS)
    resumed = AuditWriter(tmp_path, "mocktenant", "partner-rules", run_dir=root)
    resumed.write_partner_domains(PartnerDomains(DOMAINS[:1]))
    resumed.write_bundle({"collectors": [], "overall_status": "ok"})
    assert rule_view(project_run(root), SS23) == {"SecuritySuite": {SS23: {"PartnerDomains": [DOMAINS[0]]}}}
    resumed.write_partner_domains(PartnerDomains())
    resumed.write_bundle({"collectors": [], "overall_status": "ok"})
    assert rule_view(project_run(root), SS23) == NOT_COLLECTED


def test_private_values_never_reach_model_views_or_public_outputs(tmp_path, monkeypatch):
    from auditex import scuba_projection as module

    (tmp_path / "with").mkdir()
    (tmp_path / "without").mkdir()
    with_inputs = bundle(tmp_path / "with")
    without = bundle(tmp_path / "without", users=(), domains=())
    for name in ("_seen_shape", "_oversize"):
        original = getattr(module, name)

        def guarded(*args, _original=original, **kwargs):
            assert not any(value in repr(args) for value in DOMAINS + USERS)
            return _original(*args, **kwargs)

        monkeypatch.setattr(module, name, guarded)
    for redact in (True, False):
        a = module.project_run(with_inputs, redact=redact, max_items=1, max_chars=10)
        b = module.project_run(without, redact=redact, max_items=1, max_chars=10)
        assert module.policy_section(a, SS23, "scuba_config") == NOT_COLLECTED
        public = json.dumps([a, a.views, a.report, a.rule_sections])
        assert not any(value in public for value in DOMAINS + USERS)
        # Model-facing projection is byte-identical with and without the private inputs.
        assert json.dumps(a.views, sort_keys=True) == json.dumps(b.views, sort_keys=True)
        assert json.dumps(a.rule_sections, sort_keys=True) == json.dumps(b.rule_sections, sort_keys=True)


def test_assessment_and_dry_run_outputs_keep_partner_domains_private(tmp_path, monkeypatch, capsys, caplog):
    from auditex.model_serving import ModelClient, assess_run
    from azure_tenant_audit.model_assessment import validate_assessment

    caplog.set_level("DEBUG")
    root = bundle(tmp_path, users=())
    monkeypatch.setattr(ModelClient, "assess", lambda *args: pytest.fail("operator input called the model"))
    result = assess_run(root, policies=[SS23])
    validate_assessment(result)
    dry = assess_run(root, policies=[SS23], dry_run=True)
    captured = capsys.readouterr()
    text = json.dumps([result, dry]) + captured.out + captured.err + caplog.text
    assert not any(value in text for value in DOMAINS)
    exempt = {root / PARTNER_PATH, root / PARTNER_KEY_PATH}
    for artifact in tmp_path.rglob("*"):
        if artifact.is_file() and artifact not in exempt:
            data = artifact.read_bytes().lower()
            assert not any(value.encode() in data for value in DOMAINS), artifact


# End-to-end deterministic SS 2.3 (phish_exists, need partner_domains) over real collector envelopes.
# The Defender adapter keeps TargetedDomainsToProtect, so no projection injection is needed here.
POLICY = {"Identity": "Default", "Name": "Default", "Enabled": True, "IsDefault": True,
          "EnableTargetedDomainsProtection": True, "TargetedDomainProtectionAction": "Quarantine",
          "TargetedDomainsToProtect": list(DOMAINS)}
OPERATIONS = ("acceptedDomains", "antiPhishRules", "eopProtectionPolicyRules",
              "atpProtectionPolicyRules", "atpPolicyForO365")
EXCHANGE = "raw/exchange_policy.json"


def write_policy(root, **changes):
    """Constructed Exchange envelopes: one Default anti-phish policy, edited per case."""
    policy = {**POLICY, **changes}
    policy = {key: value for key, value in policy.items() if value is not ...}
    operations = {name: [] for name in OPERATIONS}
    operations["antiPhishPolicies"] = [policy]
    (root / "raw").mkdir(exist_ok=True)
    (root / EXCHANGE).write_text(json.dumps({
        name: {"value": rows, "status": "ok"} for name, rows in operations.items()}))


def direct_record(projection):
    from copy import deepcopy
    from azure_tenant_audit.value_rules import assess

    sections = deepcopy(projection.rule_sections)
    sections["scuba_config"] = rule_view(projection, SS23)
    return assess(SS23, sections)


CASES = [
    pytest.param({}, "default_qualifies", "met", id="met-every-target"),
    pytest.param({"TargetedDomainsToProtect": [DOMAINS[1].upper() + " ", DOMAINS[0], "extra.example.invalid"]},
                 "default_qualifies", "met", id="met-case-space-and-extra-target"),
    pytest.param({"TargetedDomainsToProtect": [DOMAINS[0]]}, "no_qualifying_policy", "not_met",
                 id="missing-one-target"),
    pytest.param({"TargetedDomainProtectionAction": "NoAction"}, "no_qualifying_policy", "not_met",
                 id="constant-unacceptable-action"),
    pytest.param({"EnableTargetedDomainsProtection": False}, "no_qualifying_policy", "not_met",
                 id="protection-disabled"),
    pytest.param({"EnableTargetedDomainsProtection": ...}, "policy_field_unusable", "not_assessed",
                 id="flag-absent"),
    pytest.param({"TargetedDomainProtectionAction": ...}, "policy_field_unusable", "not_assessed",
                 id="action-absent"),
    pytest.param({"TargetedDomainProtectionAction": "UnrecognisedAction"}, "policy_field_unusable",
                 "not_assessed", id="action-unrecognised"),
    pytest.param({"TargetedDomainsToProtect": ...}, "policy_field_unusable", "not_assessed",
                 id="target-list-absent"),
]


@pytest.mark.parametrize("changes,cell,verdict", CASES)
def test_verified_partner_domains_without_sensitive_users_decide_ss23(tmp_path, monkeypatch, changes, cell, verdict):
    """Fail-first on the base: with no PartnerDomains consumer every case is section_not_collected."""
    from auditex.model_serving import ModelClient, assess_run
    from auditex.scuba_projection import project_run
    from azure_tenant_audit.model_assessment import validate_assessment

    root = bundle(tmp_path, users=())
    write_policy(root, **changes)
    projection = project_run(root)
    assert rule_view(projection, SS21) == NOT_COLLECTED
    record = direct_record(projection)
    assert (record["cell"], record["verdict"]) == (cell, verdict)
    monkeypatch.setattr(ModelClient, "assess", lambda *args: pytest.fail("operator input called the model"))
    result = assess_run(root, policies=[SS23])
    validate_assessment(result)
    assert result["policies"][0]["rule_precheck"]["cell"] == cell


def test_ss23_decides_independently_beside_sensitive_users(tmp_path):
    from auditex.scuba_projection import project_run

    root = bundle(tmp_path)
    write_policy(root)
    projection = project_run(root)
    assert direct_record(projection)["cell"] == "default_qualifies"
    assert rule_view(projection, SS21) == {"SecuritySuite": {SS21: {"SensitiveUsers": list(USERS)}}}


def test_absent_partner_domains_keep_ss23_not_collected(tmp_path, monkeypatch):
    from auditex.model_serving import ModelClient, assess_run
    from auditex.scuba_projection import project_run

    for name, users in (("none", ()), ("users", USERS)):
        (tmp_path / name).mkdir()
        root = bundle(tmp_path / name, users=users, domains=())
        write_policy(root)
        assert rule_view(project_run(root), SS23) == NOT_COLLECTED
        monkeypatch.setattr(ModelClient, "assess", lambda *args: pytest.fail("operator input called the model"))
        result = assess_run(root, policies=[SS23])
        assert result["policies"][0]["rule_precheck"]["cell"] == "section_not_collected"


def test_resume_and_offline_replay_reach_the_same_ss23_cells(tmp_path):
    import shutil
    from auditex.model_serving import assess_run
    from auditex.scuba_projection import project_run
    from azure_tenant_audit.output import AuditWriter

    (tmp_path / "run").mkdir()
    root = bundle(tmp_path / "run")
    write_policy(root)
    first = assess_run(root, policies=[SS23])
    replay = tmp_path / "offline-replay"
    shutil.copytree(root, replay)
    assert assess_run(replay, policies=[SS23])["policies"] == first["policies"]
    # Resume with the existing writer and an identical list: same cell. Narrow the list: the target is missing.
    resumed = AuditWriter(tmp_path / "run", "mocktenant", "partner-rules", run_dir=root)
    resumed.write_partner_domains(PartnerDomains(DOMAINS))
    resumed.write_bundle({"collectors": [], "overall_status": "ok"})
    assert assess_run(root, policies=[SS23])["policies"] == first["policies"]
    assert first["policies"][0]["rule_precheck"]["cell"] == "default_qualifies"
    resumed.write_partner_domains(PartnerDomains(DOMAINS + ("added-partner.example.invalid",)))
    resumed.write_bundle({"collectors": [], "overall_status": "ok"})
    assert direct_record(project_run(root))["cell"] == "no_qualifying_policy"
    resumed.write_partner_domains(PartnerDomains())
    resumed.write_bundle({"collectors": [], "overall_status": "ok"})
    assert assess_run(root, policies=[SS23])["policies"][0]["rule_precheck"]["cell"] == "section_not_collected"


def test_ss23_end_to_end_keeps_model_shape_and_canaries_private(tmp_path, monkeypatch, capsys, caplog):
    import json as _json
    from auditex import scuba_projection as module
    from auditex.model_serving import ModelClient, assess_run
    from azure_tenant_audit.model_assessment import validate_assessment

    caplog.set_level("DEBUG")
    for name in ("with", "without"):
        (tmp_path / name).mkdir()
    with_inputs = bundle(tmp_path / "with", users=())
    without = bundle(tmp_path / "without", users=(), domains=())
    for root in (with_inputs, without):
        write_policy(root)
    monkeypatch.setattr(ModelClient, "assess", lambda *args: pytest.fail("operator input called the model"))
    a, b = module.project_run(with_inputs), module.project_run(without)
    # Model-facing case material is byte-identical; only the in-memory rule view differs.
    for part in ("views", "report", "rule_sections"):
        assert _json.dumps(getattr(a, part), sort_keys=True) == _json.dumps(getattr(b, part), sort_keys=True)
    assert dict(a) == dict(b)
    assert module.policy_section(a, SS23, "scuba_config") == NOT_COLLECTED
    result = assess_run(with_inputs, policies=[SS23])
    validate_assessment(result)
    dry = assess_run(with_inputs, policies=[SS23], dry_run=True)
    captured = capsys.readouterr()
    # The synthetic Exchange envelope legitimately holds the targets; nothing derived may.
    assert not any(value in captured.out + captured.err + caplog.text for value in DOMAINS)
    assert not any(value in _json.dumps([a, a.views, a.report, result, dry]) for value in DOMAINS)
    exempt = {with_inputs / EXCHANGE, without / EXCHANGE, with_inputs / PARTNER_PATH, with_inputs / PARTNER_KEY_PATH}
    for artifact in tmp_path.rglob("*"):
        if artifact.is_file() and artifact not in exempt:
            data = artifact.read_bytes().lower()
            assert not any(value.encode() in data for value in DOMAINS), artifact
