"""SS 2.1 ``--resume-from``: exchange_policy is carried only while its summaries are bound to the current input.

The real ExchangePolicyCollector and PowerShellGraphAdapter run; ``pwsh`` is a synthetic child for the anti-phish
read and every other Exchange read returns an empty healthy list. Base APIs only (``run_live``), so on a base without
the collect boundary the changed-list resume carries the stale evidence and the literal targets reach raw output.
"""
from __future__ import annotations

from copy import deepcopy
import json
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

from azure_tenant_audit import cli
from azure_tenant_audit.adapters import powershell_graph as pg
from azure_tenant_audit.adapters.powershell_graph import PowerShellGraphAdapter
from azure_tenant_audit.collectors.base import CollectorResult
from azure_tenant_audit.collectors.exchange_policy import ExchangePolicyCollector
from azure_tenant_audit.guarded_io import UnsafeRunFileError

SS21 = "MS.SECURITYSUITE.2.1v1"
ALICE, BOB, CAROL = (f"{n}@configured-canary.invalid" for n in ("ss21-alice", "ss21-bob", "ss21-carol"))
UNCONFIGURED = ("Zebulon Quarkwright", "zq-canary@unlisted-canary.invalid", "canary-domain-x.invalid")
FRAGMENTS = ("Zebulon", "Quarkwright", "zq-canary", "unlisted-canary", "canary-domain-x", "Configured Person")
ROW = {"Identity": "Default", "Name": "Default", "IsDefault": True, "Enabled": True,
       "EnableTargetedUserProtection": True, "TargetedUserProtectionAction": "Quarantine",
       "TargetedUsersToProtect": [f"Configured Person;{ALICE}", BOB.upper(), *UNCONFIGURED]}
CHILD = "import os, sys\nsys.stdout.write(open(os.environ['SS21_ROWS']).read())\n"


class _FakeClient:
    def __init__(self, auth: Any, audit_event: Any = None) -> None:
        self.audit_event = audit_event

    def get_json(self, path: str, **_: Any) -> dict[str, Any]:
        return {}

    def get_all(self, path: str, params: Any = None) -> list[Any]:  # noqa: ARG002
        return []


class _Identity:
    name = "identity"

    def run(self, context: dict[str, Any]) -> CollectorResult:
        assert "sensitive_users" not in context and "sensitive_users_binding" not in context
        return CollectorResult(name="identity", status="ok", item_count=1, message="ok",
                               payload={"rows": {"value": [{"id": "identity-1"}]}}, coverage=[])


class _Adapter(PowerShellGraphAdapter):
    """Real adapter (and its boundary) for the anti-phish read; every other read is an empty healthy list."""

    anti_phish_calls = 0

    def run(self, command, log_event=None, session=None, response_transform=None):
        if command.startswith("Get-AntiPhishPolicy"):
            type(self).anti_phish_calls += 1
            extra = {"response_transform": response_transform} if response_transform is not None else {}
            return super().run(command, log_event=log_event, session=session, **extra)
        return {"value": [], "command": command}


@pytest.fixture
def harness(tmp_path, monkeypatch):
    script = tmp_path / "pwsh"
    script.write_text(f"#!{sys.executable} -I\n{CHILD}")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    rows = tmp_path / "rows.json"
    rows.write_text(json.dumps([ROW]))
    monkeypatch.setenv("SS21_ROWS", str(rows))
    monkeypatch.setattr(pg.shutil, "which", lambda name: str(script) if name == "pwsh" else None)
    _Adapter.anti_phish_calls = 0
    monkeypatch.setattr("azure_tenant_audit.collectors.exchange_policy.get_adapter", lambda _name: _Adapter())
    monkeypatch.setattr(cli, "GraphClient", _FakeClient)
    monkeypatch.setattr(cli, "REGISTRY", {"exchange_policy": ExchangePolicyCollector(), "identity": _Identity()})
    monkeypatch.setattr(cli, "_acquire_azure_cli_access_token", lambda *_, **__: "cached-token")
    monkeypatch.delenv("AUDITEX_SENSITIVE_USERS_FILE", raising=False)
    out = tmp_path / "out"

    def live(collectors: str, users: str | None, *extra: str, public: bool = False) -> int:
        argv = ["--tenant-name", "acme", "--tenant-id", "t-123", "--use-azure-cli-token", "--collectors", collectors,
                "--out", str(out), "--run-name", "resume", *extra]
        if users is not None:
            source = tmp_path / f"users-{abs(hash(users))}.txt"
            source.write_text(users)
            argv += ["--sensitive-users", str(source)]
        if public:
            return cli.main(argv)  # the guarded console entry point, as an operator runs it
        return cli.run_live(cli.build_parser().parse_args(argv))
    return live, out / "acme-resume"


def _manifest_digest(run_dir: Path):
    return json.loads((run_dir / "run-manifest.json").read_text())["operator_inputs"]["sensitive_users"].get("hmac_sha256")


def _raw_summary(run_dir: Path):
    payload = json.loads((run_dir / "raw/exchange_policy.json").read_text())
    (row,) = payload["antiPhishPolicies"]["value"]
    assert "TargetedUsersToProtect" not in row
    return row["TargetedUsersCoverage"]


def _normalised_summary(run_dir: Path):
    records = json.loads((run_dir / "normalized/exchange_policy_objects.json").read_text())["records"]
    return [r["TargetedUsersCoverage"] for r in records if r.get("source_name") == "antiPhishPolicies"]


def _assert_no_canaries(root: Path):
    leaks = [(p.relative_to(root).as_posix(), f) for p in root.rglob("*") if p.is_file()
             for f in FRAGMENTS if f.encode() in p.read_bytes()]
    assert leaks == []
    configured = [p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()
                  and b"configured-canary" in p.read_bytes()]
    assert set(configured) <= {"operator-inputs/sensitive-users.txt"}


def _known(digest, missing):
    return {"version": 1, "state": "known", "input_hmac_sha256": digest, "input_count": 2,
            "protected_nonempty": True, "missing_count": missing}


def test_first_run_binds_the_summary_and_the_frozen_bundle_assesses_met(harness):
    from auditex.scuba_projection import project_run, rule_policy_section
    from azure_tenant_audit.value_rules import assess
    live, run_dir = harness
    live("exchange_policy", f"{ALICE}\n{BOB}\n")
    digest = _manifest_digest(run_dir)
    assert _raw_summary(run_dir) == _known(digest, 0)
    _assert_no_canaries(run_dir)
    projection = project_run(run_dir)
    sections = deepcopy(projection.rule_sections)
    sections["scuba_config"] = rule_policy_section(projection, SS21, "scuba_config")
    assert (assess(SS21, sections)["verdict"], assess(SS21, sections)["cell"]) == ("met", "default_qualifies")


def test_an_equivalent_list_reuses_the_bound_summary(harness):
    live, run_dir = harness
    live("exchange_policy", f"{ALICE}\n{BOB}\n")
    digest = _manifest_digest(run_dir)
    equivalent = json.dumps([BOB.upper(), f"Alice Name;{ALICE}", BOB, f" {ALICE} "])
    live("exchange_policy", equivalent, "--resume-from", str(run_dir))
    assert _Adapter.anti_phish_calls == 1, "same canonical tuple and key: carried, not read again"
    assert _manifest_digest(run_dir) == digest and _raw_summary(run_dir) == _known(digest, 0)
    _assert_no_canaries(run_dir)


def test_a_changed_list_of_the_same_size_is_read_again_under_the_new_binding(harness):
    live, run_dir = harness
    live("exchange_policy", f"{ALICE}\n{BOB}\n")
    old = _manifest_digest(run_dir)
    live("exchange_policy", f"{ALICE}\n{CAROL}\n", "--resume-from", str(run_dir))
    new = _manifest_digest(run_dir)
    assert _Adapter.anti_phish_calls == 2 and new != old
    assert _raw_summary(run_dir) == _known(new, 1)
    assert old.encode() not in (run_dir / "raw/exchange_policy.json").read_bytes()
    _assert_no_canaries(run_dir)


def test_a_cleared_list_is_read_again_and_proves_nothing(harness):
    live, run_dir = harness
    live("exchange_policy", f"{ALICE}\n{BOB}\n")
    live("exchange_policy", None, "--resume-from", str(run_dir))
    assert _Adapter.anti_phish_calls == 2
    assert _raw_summary(run_dir) == {"version": 1, "state": "not_collected"}
    assert _manifest_digest(run_dir) is None
    _assert_no_canaries(run_dir)


def test_a_list_supplied_only_on_resume_is_read_again(harness):
    live, run_dir = harness
    live("exchange_policy", None)
    assert _raw_summary(run_dir) == {"version": 1, "state": "not_collected"}
    live("exchange_policy", f"{ALICE}\n{BOB}\n", "--resume-from", str(run_dir))
    assert _Adapter.anti_phish_calls == 2
    assert _raw_summary(run_dir) == _known(_manifest_digest(run_dir), 0)


def test_a_missing_key_keeps_the_existing_refusal_and_makes_no_replacement(harness):
    live, run_dir = harness
    live("exchange_policy", f"{ALICE}\n{BOB}\n")
    summary = _raw_summary(run_dir)
    key = run_dir / "operator-inputs/sensitive-users.key"
    key.unlink()
    # The writer's existing refusal is UnsafeRunFileError (as for AuditWriter alone); the public entry point turns it
    # into the fixed exit 2. Neither path reads anti-phish again, makes a replacement key or rewrites the summary.
    with pytest.raises(UnsafeRunFileError):
        live("exchange_policy", f"{ALICE}\n{BOB}\n", "--resume-from", str(run_dir))
    assert not key.exists() and _Adapter.anti_phish_calls == 1 and _raw_summary(run_dir) == summary
    assert live("exchange_policy", f"{ALICE}\n{BOB}\n", "--resume-from", str(run_dir), public=True) == 2
    assert not key.exists() and _Adapter.anti_phish_calls == 1 and _raw_summary(run_dir) == summary


def test_a_changed_list_that_cannot_be_read_again_keeps_other_evidence_without_proof(harness):
    live, run_dir = harness
    live("exchange_policy,identity", f"{ALICE}\n{BOB}\n")
    old = _manifest_digest(run_dir)
    stored = (run_dir / "raw/exchange_policy.json").read_bytes()
    live("identity", f"{ALICE}\n{CAROL}\n", "--resume-from", str(run_dir))
    assert _Adapter.anti_phish_calls == 1
    assert (run_dir / "raw/exchange_policy.json").read_bytes() == stored, "the old summary is never rebound"
    assert old.encode() in stored and _manifest_digest(run_dir) != old
    assert _normalised_summary(run_dir) == [{"version": 1, "state": "not_collected"}]
    _assert_no_canaries(run_dir)


def test_a_carried_bundle_with_stale_literals_is_minimised_before_reuse(harness):
    from azure_tenant_audit.collectors.targeted_users_coverage import resume_payload
    from azure_tenant_audit.sensitive_users import SensitiveUsers
    from azure_tenant_audit.value_rules.defender_targeted_users import SensitiveUsersBinding
    digest = "440e979a9184114e5d0376ee777b8c0ff444ca0db3a2242e01937331f494538a"
    binding = SensitiveUsersBinding(2, digest)
    users = SensitiveUsers(("alice@example.invalid", "bob@example.invalid"))
    known = _known(digest, 0)
    healthy = {"antiPhishPolicies": {"value": [{"Identity": "Default", "TargetedUsersCoverage": known}]},
               "transportConfig": {"value": [{"Name": "Admin"}]}}
    assert resume_payload(healthy, users, binding) == (healthy, True)
    for stale in (
        {**healthy, "antiPhishPolicies": {"value": [{"Identity": "Default", "TargetedUsersCoverage": known,
                                                     "TargetedUsersToProtect": list(UNCONFIGURED)}]}},
        {**healthy, "antiPhishPolicies": {"value": [{"Identity": "Default",
                                                     "TargetedUsersCoverage": {**known, "missing_count": 1,
                                                                               "input_hmac_sha256": "0" * 64}}]}},
        {**healthy, "antiPhishPolicies": {"value": [{"Identity": "Default"}]}},
        {**healthy, "antiPhishPolicies": {"value": [{"Identity": "Default",
                                                     "TargetedUsersCoverage": {"version": 1, "state": "unusable"}}]}},
        {"transportConfig": healthy["transportConfig"]},
    ):
        payload, reusable = resume_payload(stale, users, binding)
        assert not reusable and payload.get("transportConfig") == healthy["transportConfig"]
        assert not [f for f in FRAGMENTS if f in json.dumps(payload)]
        for row in payload.get("antiPhishPolicies", {}).get("value", []):
            assert row["TargetedUsersCoverage"] == {"version": 1, "state": "not_collected"}
    assert resume_payload(healthy, SensitiveUsers(), None)[1] is False
    unbound = {**healthy, "antiPhishPolicies": {"value": [{"Identity": "Default",
                                                          "TargetedUsersCoverage": {"version": 1, "state": "not_collected"}}]}}
    assert resume_payload(unbound, SensitiveUsers(), None) == (unbound, True)
