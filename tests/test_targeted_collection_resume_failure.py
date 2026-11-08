"""SS 2.1 ``--resume-from``: a binding-invalidated Exchange re-run that cannot produce a full replacement.

The operator list changed (or was cleared) after a completed run, so ``exchange_policy`` is not carried and re-runs.
When that attempt crashes, or returns failed or partial operation envelopes, the run keeps the earlier session's safe
unrelated Exchange evidence: anti-phish membership ``not_collected``, no target literal, the old proof neither kept as
proof nor rebound to the new HMAC. The new failure or partial status, checkpoint and coverage stay visible, so no
retained row is admitted as a fresh read and SS 2.1 is never met. A healthy operation the re-run did read replaces its
old copy. Another collector selected in the same session still writes its raw evidence, the retained private key is
reused unchanged, the operator's source file is untouched, and the frozen original bundle still assesses ``met``.

The real ExchangePolicyCollector, PowerShellGraphAdapter boundary (anti-phish read only), AuditWriter and run_live run;
``pwsh`` is a synthetic child script and the Graph client is fake. Only APIs present before the staged re-run exist are
imported, so on that base these tests fail on their assertions, not on an import.
"""
from __future__ import annotations

from copy import deepcopy
import json
import shutil
import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from azure_tenant_audit import cli
from azure_tenant_audit.adapters import powershell_graph as pg
from azure_tenant_audit.adapters.powershell_graph import PowerShellGraphAdapter
from azure_tenant_audit.collectors.base import CollectorResult
from azure_tenant_audit.collectors.exchange_policy import ExchangePolicyCollector

SS21 = "MS.SECURITYSUITE.2.1v1"
ALICE, BOB, CAROL = (f"{n}@configured-canary.invalid" for n in ("ss21-alice", "ss21-bob", "ss21-carol"))
UNCONFIGURED = ("Zebulon Quarkwright", "zq-canary@unlisted-canary.invalid", "canary-domain-x.invalid")
FRAGMENTS = ("Zebulon", "Quarkwright", "zq-canary", "unlisted-canary", "canary-domain-x", "Configured Person")
ROW = {"Identity": "Default", "Name": "Default", "IsDefault": True, "Enabled": True,
       "EnableTargetedUserProtection": True, "TargetedUserProtectionAction": "Quarantine",
       "TargetedUsersToProtect": [f"Configured Person;{ALICE}", BOB.upper(), *UNCONFIGURED]}
# The anti-phish child exits non-zero when SS21_FAIL is set: the real adapter boundary returns its controlled failure.
CHILD = (
    "import os, sys\n"
    "if os.environ.get('SS21_FAIL'):\n"
    "    sys.exit(3)\n"
    "sys.stdout.write(open(os.environ['SS21_ROWS']).read())\n"
)
NOT_COLLECTED = {"version": 1, "state": "not_collected"}
OLD_TRANSPORT, NEW_TRANSPORT, OLD_MALWARE = "RetainedTransportMarker", "FreshTransportMarker", "RetainedMalwareMarker"
FIRST = {
    "Get-TransportConfig": {"value": [{"Name": OLD_TRANSPORT, "SmtpClientAuthenticationDisabled": True}]},
    "Get-MalwareFilterPolicy": {"value": [{"Identity": OLD_MALWARE, "Name": OLD_MALWARE, "IsDefault": True,
                                           "EnableFileFilter": True}]},
}
FAILED = {"error": "command_failed:1", "error_class": "command_error"}


class _FakeClient:
    def __init__(self, auth: Any, audit_event: Any = None) -> None:
        self.audit_event = audit_event

    def get_json(self, path: str, **_: Any) -> dict[str, Any]:
        return {}

    def get_all(self, path: str, params: Any = None) -> list[Any]:  # noqa: ARG002
        return []


class _Identity:
    """Another collector selected only in the resumed session: its raw evidence must still be written."""

    name = "identity"

    def run(self, context: dict[str, Any]) -> CollectorResult:
        assert "sensitive_users" not in context and "sensitive_users_binding" not in context
        return CollectorResult(name="identity", status="ok", item_count=1, message="ok",
                               payload={"rows": {"value": [{"id": "identity-resumed-session"}]}}, coverage=[])


class _Adapter(PowerShellGraphAdapter):
    """Real adapter (and its boundary) for the anti-phish read; every other read comes from ``responses``.

    ``responses`` maps a cmdlet name to the envelope to return, or to an exception to raise (which crashes the
    collector); any other read is an empty healthy list.
    """

    anti_phish_calls = 0
    responses: dict[str, Any] = {}

    def run(self, command, log_event=None, session=None, response_transform=None):
        if command.startswith("Get-AntiPhishPolicy"):
            type(self).anti_phish_calls += 1
            extra = {"response_transform": response_transform} if response_transform is not None else {}
            return super().run(command, log_event=log_event, session=session, **extra)
        for cmdlet, response in type(self).responses.items():
            if cmdlet in command:
                if isinstance(response, BaseException):
                    raise response
                return {**deepcopy(response), "command": command}
        return {"value": [], "command": command}


@pytest.fixture
def harness(tmp_path, monkeypatch):
    script = tmp_path / "pwsh"
    script.write_text(f"#!{sys.executable} -I\n{CHILD}")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    rows = tmp_path / "rows.json"
    rows.write_text(json.dumps([ROW]))
    monkeypatch.setenv("SS21_ROWS", str(rows))
    monkeypatch.delenv("SS21_FAIL", raising=False)
    monkeypatch.setattr(pg.shutil, "which", lambda name: str(script) if name == "pwsh" else None)
    monkeypatch.setattr(_Adapter, "anti_phish_calls", 0)
    monkeypatch.setattr(_Adapter, "responses", dict(FIRST))
    monkeypatch.setattr("azure_tenant_audit.collectors.exchange_policy.get_adapter", lambda _name: _Adapter())
    monkeypatch.setattr(cli, "GraphClient", _FakeClient)
    monkeypatch.setattr(cli, "REGISTRY", {"exchange_policy": ExchangePolicyCollector(), "identity": _Identity()})
    monkeypatch.setattr(cli, "_acquire_azure_cli_access_token", lambda *_, **__: "cached-token")
    monkeypatch.delenv("AUDITEX_SENSITIVE_USERS_FILE", raising=False)
    out = tmp_path / "out"
    sources: list[tuple[Path, str]] = []

    def live(collectors: str, users: str | None, *extra: str) -> int:
        argv = ["--tenant-name", "acme", "--tenant-id", "t-123", "--use-azure-cli-token", "--collectors", collectors,
                "--out", str(out), "--run-name", "resume", *extra]
        if users is not None:
            source = tmp_path / f"users-{len(sources)}.txt"
            source.write_text(users)
            sources.append((source, users))
            argv += ["--sensitive-users", str(source)]
        return cli.run_live(cli.build_parser().parse_args(argv))

    return SimpleNamespace(live=live, run_dir=out / "acme-resume", sources=sources, tmp=tmp_path)


def _json(path: Path) -> Any:
    return json.loads(path.read_text())


def _manifest_digest(run_dir: Path):
    return _json(run_dir / "run-manifest.json")["operator_inputs"]["sensitive_users"].get("hmac_sha256")


def _checkpoint(run_dir: Path) -> dict[str, Any]:
    return _json(run_dir / "checkpoints/checkpoint-state.json").get("collectors", {})


def _rows(payload: dict[str, Any], operation: str) -> list[Any]:
    section = payload.get(operation)
    if not isinstance(section, dict):
        return []
    return section.get("value") or []


def _names(payload: dict[str, Any], operation: str) -> list[Any]:
    return [row.get("Name") for row in _rows(payload, operation) if isinstance(row, dict)]


def _exchange_coverage(run_dir: Path) -> list[dict[str, Any]]:
    data = _json(run_dir / "coverage.json")
    rows = data.get("records") if isinstance(data, dict) else data
    return [row for row in rows if isinstance(row, dict) and row.get("collector") == "exchange_policy"]


def _coverage_status(run_dir: Path) -> dict[str, list[Any]]:
    status: dict[str, list[Any]] = {}
    for row in _exchange_coverage(run_dir):
        status.setdefault(row.get("name"), []).append(row.get("status"))
    return status


def _verdict(run_dir: Path) -> tuple[Any, Any]:
    from auditex.scuba_projection import project_run, rule_policy_section
    from azure_tenant_audit.value_rules import assess
    projection = project_run(run_dir)
    sections = deepcopy(projection.rule_sections)
    sections["scuba_config"] = rule_policy_section(projection, SS21, "scuba_config")
    result = assess(SS21, sections)
    return result["verdict"], result["cell"]


def _assert_no_canaries(root: Path) -> None:
    leaks = [(p.relative_to(root).as_posix(), f) for p in root.rglob("*") if p.is_file()
             for f in FRAGMENTS if f.encode() in p.read_bytes()]
    assert leaks == []
    configured = [p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()
                  and b"configured-canary" in p.read_bytes()]
    assert set(configured) <= {"operator-inputs/sensitive-users.txt"}


def _first_run(h) -> tuple[str, Path, bytes]:
    """A completed run whose anti-phish summary is bound to ALICE and BOB, plus a frozen copy of that bundle."""
    h.live("exchange_policy", f"{ALICE}\n{BOB}\n")
    run_dir = h.run_dir
    old = _manifest_digest(run_dir)
    assert _checkpoint(run_dir)["exchange_policy"]["status"] == "ok"
    raw = _json(run_dir / "raw/exchange_policy.json")
    assert [row.get("TargetedUsersCoverage") for row in _rows(raw, "antiPhishPolicies")] == [
        {"version": 1, "state": "known", "input_hmac_sha256": old, "input_count": 2,
         "protected_nonempty": True, "missing_count": 0}]
    assert _names(raw, "transportConfig") == [OLD_TRANSPORT] and _names(raw, "malwareFilterPolicy") == [OLD_MALWARE]
    frozen = h.tmp / "frozen" / run_dir.name
    shutil.copytree(run_dir, frozen)
    return old, frozen, (run_dir / "operator-inputs/sensitive-users.key").read_bytes()


def _assert_retained_without_proof(h, old: str, frozen: Path, key: bytes, *, status: str,
                                   cleared: bool = False) -> dict[str, Any]:
    """The common contract of every failed staged re-run; returns the published raw payload."""
    run_dir = h.run_dir
    raw_bytes = (run_dir / "raw/exchange_policy.json").read_bytes()
    raw = json.loads(raw_bytes)
    normalised_bytes = (run_dir / "normalized/exchange_policy_objects.json").read_bytes()
    new = _manifest_digest(run_dir)
    assert new != old
    # The earlier anti-phish rows are kept as safe settings evidence with membership unknown: the old proof is not
    # carried, and no new HMAC is written over it.
    anti_phish = [row for row in _rows(raw, "antiPhishPolicies") if isinstance(row, dict)]
    assert [(row.get("Identity"), row.get("TargetedUsersCoverage")) for row in anti_phish] == [("Default", NOT_COLLECTED)]
    assert not any("TargetedUsersToProtect" in row for row in anti_phish)
    normalised = [r.get("TargetedUsersCoverage") for r in json.loads(normalised_bytes).get("records", [])
                  if r.get("source_name") == "antiPhishPolicies"]
    assert normalised == [NOT_COLLECTED]
    for digest in (old, new):
        if digest:
            assert digest.encode() not in raw_bytes and digest.encode() not in normalised_bytes
    # The new attempt's failure stays the collector's status, checkpoint and coverage; no old ok row comes back.
    assert _checkpoint(run_dir)["exchange_policy"]["status"] == status
    assert "ok" not in _coverage_status(run_dir).get("antiPhishPolicies", [])
    # Retained rows are evidence, never a fresh read: SS 2.1 is not met on the resumed bundle.
    assert _verdict(run_dir)[0] != "met"
    # Another collector selected in this session still published its raw evidence through the runner.
    assert b"identity-resumed-session" in (run_dir / "raw/identity.json").read_bytes()
    # A changed list reuses the retained private key unchanged. A cleared list removes this input and its key (the
    # writer's documented clearing): nothing is kept to bind, and neither file is regenerated by the failed re-run.
    # Either way no replacement key is made. The operator's source is untouched.
    private = run_dir / "operator-inputs"
    if cleared:
        for name in ("sensitive-users.key", "sensitive-users.txt"):
            assert not (private / name).exists() and not (private / name).is_symlink(), name
    else:
        assert (private / "sensitive-users.key").read_bytes() == key
    assert all(path.read_text() == text for path, text in h.sources)
    _assert_no_canaries(run_dir)
    # The frozen original bundle still assesses against its own summary and key.
    assert _verdict(frozen) == ("met", "default_qualifies")
    return raw


@pytest.mark.parametrize("resume_users", [f"{ALICE}\n{CAROL}\n", None], ids=["changed", "cleared"])
def test_a_selected_rerun_that_crashes_keeps_safe_prior_evidence_without_proof(harness, monkeypatch, resume_users):
    old, frozen, key = _first_run(harness)
    monkeypatch.setattr(_Adapter, "responses", {**FIRST, "Get-TransportRule": RuntimeError("simulated exchange crash")})
    harness.live("exchange_policy,identity", resume_users, "--resume-from", str(harness.run_dir))
    raw = _assert_retained_without_proof(harness, old, frozen, key, status="failed", cleared=resume_users is None)
    assert _names(raw, "transportConfig") == [OLD_TRANSPORT]
    assert _names(raw, "malwareFilterPolicy") == [OLD_MALWARE]
    normalised = (harness.run_dir / "normalized/exchange_policy_objects.json").read_bytes()
    assert OLD_TRANSPORT.encode() in normalised and OLD_MALWARE.encode() in normalised
    # The crash is recorded as such: only the collector-wide failure row, which withholds every Exchange section.
    assert _coverage_status(harness.run_dir) == {"collector": ["failed"]}
    if resume_users is None:
        assert _manifest_digest(harness.run_dir) is None


def test_a_selected_rerun_whose_reads_all_fail_keeps_safe_prior_evidence_without_proof(harness, monkeypatch):
    old, frozen, key = _first_run(harness)
    monkeypatch.setenv("SS21_FAIL", "1")
    monkeypatch.setattr(_Adapter, "responses", {"Get-": FAILED})
    harness.live("exchange_policy,identity", f"{ALICE}\n{CAROL}\n", "--resume-from", str(harness.run_dir))
    assert _Adapter.anti_phish_calls == 2, "the changed binding forced a new anti-phish read, which failed"
    raw = _assert_retained_without_proof(harness, old, frozen, key, status="partial")
    assert _names(raw, "transportConfig") == [OLD_TRANSPORT]
    assert _names(raw, "malwareFilterPolicy") == [OLD_MALWARE]
    coverage = _coverage_status(harness.run_dir)
    for operation in ("antiPhishPolicies", "transportConfig", "malwareFilterPolicy"):
        assert coverage.get(operation) == ["failed"], operation


def test_a_partial_rerun_publishes_its_healthy_reads_and_keeps_prior_evidence_for_the_failed_ones(harness, monkeypatch):
    old, frozen, key = _first_run(harness)
    monkeypatch.setenv("SS21_FAIL", "1")
    monkeypatch.setattr(_Adapter, "responses", {
        "Get-TransportConfig": {"value": [{"Name": NEW_TRANSPORT, "SmtpClientAuthenticationDisabled": False}]},
        "Get-MalwareFilterPolicy": FAILED,
    })
    harness.live("exchange_policy,identity", f"{ALICE}\n{CAROL}\n", "--resume-from", str(harness.run_dir))
    assert _Adapter.anti_phish_calls == 2
    raw = _assert_retained_without_proof(harness, old, frozen, key, status="partial")
    # The fresh healthy read replaces its old copy everywhere; the failed one keeps the earlier safe evidence.
    assert _names(raw, "transportConfig") == [NEW_TRANSPORT]
    assert _names(raw, "malwareFilterPolicy") == [OLD_MALWARE]
    for artefact in ("raw/exchange_policy.json", "normalized/exchange_policy_objects.json"):
        assert OLD_TRANSPORT.encode() not in (harness.run_dir / artefact).read_bytes(), artefact
    coverage = _coverage_status(harness.run_dir)
    assert coverage.get("transportConfig") == ["ok"]
    assert coverage.get("malwareFilterPolicy") == ["failed"] and coverage.get("antiPhishPolicies") == ["failed"]
