"""Regression tests for the collectors-transport review lane (Graph transport, retries and the permission stop)."""
from __future__ import annotations

import pytest
from support import fake_graph_client, graph_response

from azure_tenant_audit.collectors.base import _classify_graph_error
from azure_tenant_audit.graph import GraphError


def _licence_403(code: str = "AadPremiumLicenseRequired") -> object:
    return graph_response(
        403,
        {"error": {"code": code, "message": "The tenant needs to have Microsoft Entra ID P2 license."}},
    )


@pytest.mark.parametrize("mode", ["safe", "ultra-safe"])
def test_licence_403s_do_not_trip_the_permission_stop(monkeypatch, mode) -> None:
    """R004: a licence answer is not a permission refusal, so sibling reads of the family are still sent."""
    client = fake_graph_client(throttle_mode=mode)
    client.sleep = lambda _seconds: None
    sent: list[str] = []

    def _request(method, url, headers=None, timeout=None, **kwargs):  # noqa: ARG001
        sent.append(url)
        return _licence_403()

    monkeypatch.setattr(client.session, "request", _request)
    for path in (
        "/roleManagement/directory/roleAssignmentSchedules",
        "/roleManagement/directory/roleAssignmentScheduleInstances",
        "/roleManagement/directory/roleEligibilitySchedules",
    ):
        with pytest.raises(GraphError) as caught:
            client.get_json(path)
        assert caught.value.error_code != "PermissionStop"
        assert _classify_graph_error(caught.value)[0] == "license_required"
    assert len(sent) == 3


def test_genuine_permission_refusals_still_trip_the_stop(monkeypatch) -> None:
    client = fake_graph_client(throttle_mode="ultra-safe")
    monkeypatch.setattr(
        client.session,
        "request",
        lambda *a, **k: graph_response(
            403, {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}}
        ),
    )
    with pytest.raises(GraphError):
        client.get_json("/users")
    with pytest.raises(GraphError) as caught:
        client.get_json("/users")
    assert caught.value.error_code == "PermissionStop"
