"""Sensitive wire envelopes must be admitted before generic normalisation can disguise their shape."""
from __future__ import annotations

from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from azure_tenant_audit.adapters import powershell_graph as pg
from azure_tenant_audit.collectors import targeted_users_coverage as tuc
from azure_tenant_audit.collectors.exchange_policy import ExchangePolicyCollector
from azure_tenant_audit.sensitive_users import SensitiveUsers
from azure_tenant_audit.value_rules.defender_targeted_users import SensitiveUsersBinding


ADDRESS = "alice@configured-wire.invalid"
CANARY = "zq-canary@unlisted-canary.invalid"
COMMAND = dict(ExchangePolicyCollector.command_collectors)["antiPhishPolicies"]
USERS = SensitiveUsers((ADDRESS,))
BINDING = SensitiveUsersBinding(1, "cd" * 32)
ROW = {"Identity": "Default", "Name": "Default", "IsDefault": True, "Enabled": True,
       "EnableTargetedUserProtection": True, "TargetedUserProtectionAction": "Quarantine",
       "TargetedUsersToProtect": [ADDRESS]}


def _read(monkeypatch, wire, mode):
    data = json.dumps(wire).encode()
    def bounded(*args, **kwargs):
        return SimpleNamespace(stdout=bytearray(data), stderr="", returncode=0, timed_out=False, overflow=False,
                               stdout_total=len(data), stderr_total=0, duration_ms=1)
    monkeypatch.setattr(pg, "_run_bounded", bounded)
    monkeypatch.setattr(pg.shutil, "which", lambda name: "synthetic-pwsh" if name == "pwsh" else None)
    monkeypatch.setattr(pg.subprocess, "Popen", lambda *a, **k: pytest.fail("bounded seam must prevent a real child"))
    calls = []
    proof = tuc.sanitise_response({"value": [deepcopy(ROW)]}, USERS, BINDING, observed=True)
    def transform(response):
        calls.append(True)
        if mode == "lying":
            response.clear()
            response.update(deepcopy(proof))
            return deepcopy(proof)
        return tuc.sanitise_response(response, USERS, BINDING, observed=True)
    events = []
    result = pg.PowerShellGraphAdapter().run(COMMAND,
        response_transform=None if mode == "none" else transform,
        log_event=lambda *args: events.append(args))
    return result, calls, events


@pytest.mark.parametrize("value", [None, {}, {"Name": "Default"}, True, 1, "not rows"])
@pytest.mark.parametrize("mode", ["none", "sanitising", "lying"])
def test_declared_non_list_wire_value_is_refused_before_any_transform(monkeypatch, capsys, caplog, value, mode):
    result, calls, events = _read(monkeypatch,
        {"status": "ok", "value": value, "sample_truncated": True, "stdout": CANARY}, mode)
    assert result.get("error_class") == "command_parse_error"
    assert "value" not in result and calls == []
    assert CANARY not in json.dumps([result, events])
    captured = capsys.readouterr()
    assert CANARY not in captured.out + captured.err + caplog.text


@pytest.mark.parametrize("wire", [
    {"sample_truncated": True}, {"item_count": 0}, {"chunk_files": []}, {"status": "ok"},
])
def test_declared_wire_envelope_without_rows_cannot_be_disguised_as_a_policy(monkeypatch, wire):
    result, calls, _ = _read(monkeypatch, wire, "lying")
    assert result.get("error_class") == "command_parse_error" and "value" not in result
    assert calls == []


@pytest.mark.parametrize("wire", [deepcopy(ROW), [deepcopy(ROW)], {"value": [deepcopy(ROW)]}, []])
@pytest.mark.parametrize("mode", ["none", "sanitising"])
def test_supported_wire_policy_and_explicit_empty_live_read_stay_successful(monkeypatch, wire, mode):
    result, _, _ = _read(monkeypatch, wire, mode)
    assert not result.get("error") and not result.get("error_class")
    assert isinstance(result["value"], list)
    assert ADDRESS not in json.dumps(result)
