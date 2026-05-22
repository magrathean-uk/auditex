from __future__ import annotations

from auditex.mcp_registry import iter_tool_specs, register_fastmcp_tools


def test_registry_owns_tool_names_and_read_only_hints(monkeypatch) -> None:
    monkeypatch.delenv("AUDITEX_ENABLE_RESPONSE", raising=False)
    specs = list(iter_tool_specs())
    by_name = {item["name"]: item for item in specs}

    assert "auditex_list_profiles" in by_name
    assert by_name["auditex_list_profiles"]["readOnlyHint"] is True
    assert by_name["auditex_run_delegated_audit"]["readOnlyHint"] is False
    assert by_name["auditex_google_doctor"]["readOnlyHint"] is True
    assert by_name["auditex_google_probe"]["readOnlyHint"] is False
    assert by_name["auditex_run_google_workspace_audit"]["readOnlyHint"] is False
    assert by_name["auditex_report_analyze"]["readOnlyHint"] is True
    assert by_name["auditex_api_inventory"]["readOnlyHint"] is True
    assert by_name["auditex_permissions_ledger"]["readOnlyHint"] is True
    assert by_name["auditex_proof_table"]["readOnlyHint"] is True
    assert by_name["auditex_enterprise_handoff"]["readOnlyHint"] is True
    assert by_name["auditex_verify_customer_pack"]["readOnlyHint"] is True
    assert "auditex_run_response_action" not in by_name
    assert len(by_name) == len(specs)


def test_registry_includes_response_tools_only_when_enabled(monkeypatch) -> None:
    monkeypatch.setenv("AUDITEX_ENABLE_RESPONSE", "1")
    by_name = {item["name"]: item for item in iter_tool_specs()}

    assert by_name["auditex_list_response_actions"]["readOnlyHint"] is True
    assert by_name["auditex_run_response_action"]["readOnlyHint"] is False


def test_registry_registers_fake_fastmcp_from_handlers() -> None:
    registered: list[tuple[str, str, bool]] = []

    class _FakeFastMCP:
        def tool(self, **metadata):
            def decorator(func):
                registered.append(
                    (
                        metadata["name"],
                        func.__name__,
                        metadata["annotations"]["readOnlyHint"],
                    )
                )
                return func

            return decorator

    def _handler() -> dict[str, bool]:
        return {"ok": True}

    register_fastmcp_tools(_FakeFastMCP(), {"auditex_list_profiles": _handler})

    assert registered == [("auditex_list_profiles", "auditex_list_profiles", True)]
