"""api-inventory.json: read-only and no-content-read are observed from audit-log.jsonl, not declared."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from azure_tenant_audit.api_inventory import (
    build_api_call_inventory,
    endpoint_template,
    observe_audit_events,
    read_audit_events,
    with_observed_ledger,
)
from azure_tenant_audit.finalize import finalize_bundle_contract
from azure_tenant_audit.graph import GRAPH_ROOT, GraphClient
from azure_tenant_audit.output import AuditWriter
from support import graph_auth, graph_response
from test_finalize_idempotent import _prepare_bundle_for_finalize

GUID = "5f7b3a1e-0c4d-4e2b-9a6f-1d2c3b4a5e6f"


def _event(name: str, **details: Any) -> dict[str, Any]:
    return {"ts_utc": "2026-10-22T00:00:00Z", "event": name, "message": "", "details": details}


def _get(url: str, status: int = 200, **extra: Any) -> list[dict[str, Any]]:
    return [
        _event("graph.request.started", method="GET", url=url, attempt=1, params=extra.get("params", {})),
        _event("graph.request.completed", method="GET", url=url, attempt=1, status=status),
    ]


def _inventory(*, calls: list[dict[str, Any]] | None = None, platform: str = "m365") -> dict[str, Any]:
    return build_api_call_inventory(
        platform=platform,
        selected_collectors=["identity"],
        capability_rows=[],
        coverage_rows=calls
        if calls is not None
        else [{"collector": "identity", "name": "users", "endpoint": "/users", "status": "ok", "item_count": 1}],
        data_handling={"plane": "inventory", "read_only": True, "content_reads": False, "write_actions": False},
    )


def test_declared_only_inventory_says_so() -> None:
    inventory = _inventory()

    assert "observed_ledger" not in inventory
    assert inventory["safety"]["observation_basis"] == "coverage_ledger_only"


def test_endpoint_template_strips_host_version_query_and_ids() -> None:
    assert endpoint_template(f"{GRAPH_ROOT}/users/{GUID}/mailboxSettings?$select=id") == ("/users/{id}/mailboxSettings", "v1.0")
    assert endpoint_template("https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts") == (
        "/deviceManagement/deviceManagementScripts",
        "beta",
    )
    assert endpoint_template("/groups/alice@contoso.com/members", default_version=None) == ("/groups/{id}/members", None)
    assert endpoint_template(f"{GRAPH_ROOT}/reports/getMailboxUsageDetail(period='D30')")[0] == "/reports/getMailboxUsageDetail(...)"


def test_ledger_records_methods_endpoints_statuses_and_batch_inner_calls() -> None:
    events = [
        *_get(f"{GRAPH_ROOT}/users"),
        *_get(f"{GRAPH_ROOT}/users?$skiptoken=abc"),
        *_get(f"{GRAPH_ROOT}/users/{GUID}/mailboxSettings", status=403),
        _event(
            "graph.request.started",
            method="POST",
            url=f"{GRAPH_ROOT}/$batch",
            attempt=1,
            params={},
            batch={"size": 2, "methods": ["GET"], "urls": [f"/users/{GUID}/manager", "/groups/g1/owners"]},
        ),
        _event("graph.request.completed", method="POST", url=f"{GRAPH_ROOT}/$batch", attempt=1, status=200),
        _event("graph.token.requested", mode="client_credentials"),
        _event("graph.token.succeeded", status=200),
    ]

    inventory = with_observed_ledger(_inventory(), events)
    ledger = inventory["observed_ledger"]

    graph = ledger["graph"]
    assert graph["methods_seen"] == ["GET", "POST"]  # POST is the /$batch envelope only
    assert graph["data_methods_seen"] == ["GET"]
    assert graph["batch_requests"] == 1 and graph["batch_inner_requests"] == 2
    by_endpoint = {row["endpoint"]: row for row in graph["endpoints"]}
    assert by_endpoint["/users"]["count"] == 2 and by_endpoint["/users"]["statuses"] == {"200": 2}
    assert by_endpoint["/users/{id}/mailboxSettings"]["statuses"] == {"403": 1}
    assert "/users/{id}/manager" in by_endpoint and "/groups/g1/owners" in by_endpoint
    assert ledger["auth"] == {"token_requests": 1, "token_succeeded": 1}
    assert ledger["basis"] == "transport_audit_log"
    assert inventory["safety"]["read_only"] is True and inventory["safety"]["no_content_reads"] is True
    assert inventory["safety"]["observation_basis"] == "transport_audit_log"
    assert inventory["safety"]["observed_methods"] == ["GET"]
    assert inventory["counts"]["observed_graph_requests"] == 4  # HTTP attempts: the batch envelope counts once
    assert inventory["counts"]["observed_graph_endpoints"] == len(graph["endpoints"])


def test_an_observed_write_overrides_a_clean_declaration() -> None:
    declared = _inventory()
    assert declared["safety"]["read_only"] is True
    events = [
        *_get(f"{GRAPH_ROOT}/users"),
        _event("graph.request.started", method="PATCH", url=f"{GRAPH_ROOT}/users/{GUID}", attempt=1, params={}),
    ]

    inventory = with_observed_ledger(declared, events)

    assert inventory["safety"]["read_only"] is False
    assert inventory["safety"]["write_actions"] is True
    assert inventory["safety"]["observed_write_calls"] == [{"method": "PATCH", "endpoint": "/users/{id}"}]
    assert inventory["observed_ledger"]["graph"]["data_methods_seen"] == ["GET", "PATCH"]


def test_a_batch_with_a_non_get_inner_method_or_unrecorded_inner_calls_is_not_read_only() -> None:
    inner_write = _event(
        "graph.request.started",
        method="POST",
        url=f"{GRAPH_ROOT}/$batch",
        attempt=1,
        params={},
        batch={"size": 1, "methods": ["DELETE"], "urls": ["/users/u1"]},
    )
    unrecorded = _event("graph.request.started", method="POST", url=f"{GRAPH_ROOT}/$batch", attempt=1, params={})

    assert with_observed_ledger(_inventory(), [inner_write])["safety"]["read_only"] is False
    unverified = with_observed_ledger(_inventory(), [unrecorded])
    assert unverified["safety"]["read_only"] is False
    assert unverified["observed_ledger"]["graph"]["unverified_batch_requests"] == 1


def test_content_reading_endpoints_and_body_selects_flip_no_content_reads() -> None:
    cases = [
        f"{GRAPH_ROOT}/users/{GUID}/messages",
        f"{GRAPH_ROOT}/users/{GUID}/mailFolders/inbox/messages/AAMkAGI2TG93AAA=",
        f"{GRAPH_ROOT}/users/{GUID}/messages/AAMkAGI2TG93AAA=/attachments",
        f"{GRAPH_ROOT}/drives/{GUID}/items/{GUID}/content",
        f"{GRAPH_ROOT}/users/{GUID}/photo/$value",
        f"{GRAPH_ROOT}/users/{GUID}/events",
        f"{GRAPH_ROOT}/users/{GUID}/onenote/pages",
    ]
    for url in cases:
        inventory = with_observed_ledger(_inventory(), _get(url))
        assert inventory["safety"]["no_content_reads"] is False, url
        assert inventory["safety"]["content_reads"] is True
        assert inventory["safety"]["observed_content_read_calls"], url

    selected = with_observed_ledger(_inventory(), _get(f"{GRAPH_ROOT}/users", params={"$select": "id,displayName,bodyPreview"}))
    assert selected["safety"]["no_content_reads"] is False

    benign = with_observed_ledger(
        _inventory(),
        [
            *_get(f"{GRAPH_ROOT}/admin/serviceAnnouncement/messages"),
            *_get(f"{GRAPH_ROOT}/users/{GUID}/mailboxSettings"),
            *_get(f"{GRAPH_ROOT}/users", params={"$select": "id,userPrincipalName"}),
            *_get(f"{GRAPH_ROOT}/reports/getMailboxUsageDetail(period='D30')"),
        ],
    )
    assert benign["safety"]["no_content_reads"] is True
    assert benign["observed_ledger"]["graph"]["content_read_calls"] == []


def test_a_refused_call_means_the_run_was_not_read_only_but_nothing_was_written() -> None:
    events = [
        *_get(f"{GRAPH_ROOT}/users"),
        _event("graph.request.refused", method="DELETE", url=f"{GRAPH_ROOT}/users/{GUID}", reason="DELETE is not a read method"),
        _event("command.refused", adapter="powershell_graph", command="Remove-Mailbox x", reason="Remove-Mailbox is not on the read allowlist"),
    ]

    inventory = with_observed_ledger(_inventory(), events)

    # The run tried something that is not a read, so it is not read-only; nothing reached the tenant, so no write happened.
    assert inventory["safety"]["read_only"] is False
    assert inventory["safety"]["write_actions"] is False
    assert inventory["safety"]["observed_write_calls"] == []
    assert inventory["safety"]["refused_calls"] == 2
    assert inventory["counts"]["refused_calls"] == 2
    assert inventory["observed_ledger"]["graph"]["refused"][0]["endpoint"] == "/users/{id}"
    assert inventory["observed_ledger"]["commands"]["refused"][0]["adapter"] == "powershell_graph"


def test_each_kind_of_refusal_alone_clears_read_only() -> None:
    graph_only = [_event("graph.request.refused", method="PATCH", url=f"{GRAPH_ROOT}/users/{GUID}", reason="PATCH is not a read method")]
    command_only = [_event("command.refused", adapter="m365_cli", command="m365 login", reason="m365 login does not end in list, get or status")]

    assert with_observed_ledger(_inventory(), graph_only)["safety"]["read_only"] is False
    assert with_observed_ledger(_inventory(), command_only)["safety"]["read_only"] is False
    assert with_observed_ledger(_inventory(), _get(f"{GRAPH_ROOT}/users"))["safety"]["read_only"] is True


def test_an_empty_log_next_to_declared_calls_observed_nothing_so_it_is_not_read_only(tmp_path: Path) -> None:
    from_list = with_observed_ledger(_inventory(), [])
    empty_file = tmp_path / "audit-log.jsonl"
    empty_file.write_text("", encoding="utf-8")
    from_file = with_observed_ledger(_inventory(), read_audit_events(empty_file))

    for inventory in (from_list, from_file):
        assert inventory["observed_ledger"]["log"] == {"readable": True, "malformed_lines": 0, "empty": True}
        assert inventory["safety"]["observation_basis"] == "transport_audit_log"
        assert inventory["safety"]["observed_log_complete"] is False
        assert inventory["safety"]["read_only"] is False
    # A run that declared no call has nothing to observe; an offline replay never observed a transport at all.
    assert with_observed_ledger(_inventory(calls=[]), [])["safety"]["read_only"] is True
    replay = with_observed_ledger(_inventory(), [_event("run.started", mode="offline", sample="s.json")])
    assert replay["safety"]["observation_basis"] == "offline_replay" and replay["safety"]["read_only"] is True


def test_command_events_are_classified_by_the_read_rules_not_trusted() -> None:
    events = [
        _event("command.started", adapter="powershell_graph", command="Get-RemoteDomain '|' Select-Object Name", command_words=["Get-RemoteDomain", "Select-Object"], executable="/usr/bin/pwsh"),
        _event("command.completed", command="Get-RemoteDomain '|' Select-Object Name", status="ok", return_code=0),
        _event("command.started", adapter="m365_cli", command="m365 purview dlp policy list", command_words=["purview", "dlp", "policy", "list"]),
        # A log from a build that did not enforce the allowlist: a write verb was executed.
        _event("command.started", adapter="powershell_graph", command="Remove-Mailbox x", command_words=["Remove-Mailbox"]),
        # Older event without words or adapter: classified from the logged text and the executable.
        _event("command.started", command="m365 spo site remove --url x", executable="/opt/bin/m365"),
    ]

    inventory = with_observed_ledger(_inventory(calls=[]), events)
    commands = inventory["observed_ledger"]["commands"]

    executed = {(row["adapter"], row["command"]): row for row in commands["executed"]}
    assert executed[("powershell_graph", "Get-RemoteDomain Select-Object")]["read_only"] is True
    assert executed[("powershell_graph", "Get-RemoteDomain Select-Object")]["statuses"] == {"ok": 1}
    assert executed[("m365_cli", "purview dlp policy list")]["read_only"] is True
    assert executed[("powershell_graph", "Remove-Mailbox")]["read_only"] is False
    assert executed[("m365_cli", "spo site remove")]["read_only"] is False
    assert {(row["adapter"], row["command"]) for row in commands["write_calls"]} == {
        ("powershell_graph", "Remove-Mailbox"),
        ("m365_cli", "spo site remove"),
    }
    assert inventory["safety"]["read_only"] is False
    assert inventory["counts"]["observed_commands"] == 4


def test_observed_calls_outside_the_declared_set_are_reported() -> None:
    declared = _inventory(
        calls=[
            {"collector": "identity", "name": "users", "endpoint": "/users", "status": "ok"},
            {"collector": "exchange", "type": "command", "name": "domains", "endpoint": "domains", "command": "m365 purview dlp policy list --output json", "status": "ok"},
        ]
    )
    events = [
        *_get(f"{GRAPH_ROOT}/users"),
        *_get(f"{GRAPH_ROOT}/groups"),
        _event("command.started", adapter="m365_cli", command="m365 purview dlp policy list", command_words=["purview", "dlp", "policy", "list"]),
        _event("command.started", adapter="m365_cli", command="m365 tenant info get", command_words=["tenant", "info", "get"]),
    ]

    inventory = with_observed_ledger(declared, events)
    outside = inventory["observed_ledger"]["outside_declared"]

    assert [row["endpoint"] for row in outside["graph"]] == ["/groups"]
    assert [row["command"] for row in outside["commands"]] == ["tenant info get"]
    assert outside["count"] == 2
    assert inventory["safety"]["observed_outside_declared"] == 2
    # Reading outside the declaration is reported; it is not by itself a write.
    assert inventory["safety"]["read_only"] is True


def test_google_runs_are_marked_as_not_instrumented() -> None:
    inventory = with_observed_ledger(_inventory(platform="google_workspace"), [])

    assert inventory["observed_ledger"]["basis"] == "not_instrumented"
    assert inventory["observed_ledger"]["instrumentation"] == {"graph": False, "commands": False, "google_api": False}
    assert inventory["safety"]["observation_basis"] == "coverage_ledger_only"


def test_ledger_is_deterministic_and_ignores_unrelated_events() -> None:
    graph_events = [*_get(f"{GRAPH_ROOT}/users"), *_get(f"{GRAPH_ROOT}/groups")]
    later = [_event("run.completed", overall_status="ok"), _event("contract.validation.passed", valid=True)]

    first = json.dumps(observe_audit_events(graph_events), sort_keys=True)
    second = json.dumps(observe_audit_events([*graph_events, *later]), sort_keys=True)

    assert first == second


def test_read_audit_events_skips_blank_and_malformed_lines(tmp_path: Path) -> None:
    log = tmp_path / "audit-log.jsonl"
    log.write_text('{"event": "a"}\n\nnot json\n[1, 2]\n{"event": "b"}\n', encoding="utf-8")

    assert [row["event"] for row in read_audit_events(log)] == ["a", "b"]
    assert read_audit_events(tmp_path / "missing.jsonl") == []


def test_writer_derives_the_ledger_from_its_own_audit_log(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path, tenant_name="contoso", run_name="r1")
    # A real client wired to the writer, with a fake session: the ledger sees what the transport did.
    session = type("S", (), {})()
    session.request = lambda method, url, headers=None, timeout=None, **kw: graph_response(200, {"value": [{"id": "1"}]})
    client = GraphClient(graph_auth(), session=session, audit_event=writer.log_event)  # type: ignore[arg-type]
    client.get_all("/users")
    try:
        client._request("DELETE", f"{GRAPH_ROOT}/users/{GUID}")
    except Exception:  # noqa: BLE001
        pass

    # The caller declares a clean inventory; the writer must still attach what the log shows.
    declared = _inventory()
    path = writer.write_json_artifact("api-inventory.json", declared)

    written = json.loads(path.read_text(encoding="utf-8"))
    assert written["safety"]["observation_basis"] == "transport_audit_log"
    assert written["observed_ledger"]["graph"]["data_methods_seen"] == ["GET"]
    assert written["observed_ledger"]["graph"]["refused_count"] == 1
    assert written["safety"]["read_only"] is False  # a refused DELETE: not read-only, but nothing was written
    assert written["safety"]["write_actions"] is False
    assert [row["endpoint"] for row in written["observed_ledger"]["graph"]["endpoints"]] == ["/users"]
    assert "observed_ledger" not in declared  # the caller's dict is not mutated


def test_writer_marks_a_run_whose_log_shows_a_write_as_not_read_only(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path, tenant_name="contoso", run_name="r1")
    writer.log_event("graph.request.started", "x", {"method": "PUT", "url": f"{GRAPH_ROOT}/users/{GUID}", "attempt": 1, "params": {}})

    written = json.loads(writer.write_json_artifact("api-inventory.json", _inventory()).read_text(encoding="utf-8"))

    assert written["safety"]["read_only"] is False
    assert written["safety"]["observed_write_calls"] == [{"method": "PUT", "endpoint": "/users/{id}"}]


def test_finalize_writes_an_observed_ledger_for_an_offline_run(tmp_path: Path) -> None:
    writer, kwargs = _prepare_bundle_for_finalize(tmp_path)
    finalize_bundle_contract(**kwargs)

    manifest = json.loads((writer.run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    inventory = json.loads((writer.run_dir / manifest["api_inventory_path"]).read_text(encoding="utf-8"))

    assert inventory["observed_ledger"]["source"] == "audit-log.jsonl"
    assert inventory["observed_ledger"]["graph"]["request_attempts"] == 0
    assert inventory["observed_ledger"]["graph"]["data_methods_seen"] == []
    assert inventory["safety"]["observation_basis"] == "transport_audit_log"
    assert inventory["safety"]["read_only"] is True
    validation = json.loads((writer.run_dir / "validation.json").read_text(encoding="utf-8"))
    assert validation["valid"] is True, validation["issues"]


def test_writer_replaces_a_ledger_the_caller_supplied(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path, tenant_name="contoso", run_name="r1")
    writer.log_event("graph.request.started", "x", {"method": "DELETE", "url": f"{GRAPH_ROOT}/users/{GUID}", "attempt": 1, "params": {}})
    forged = with_observed_ledger(_inventory(), _get(f"{GRAPH_ROOT}/users"))  # a clean ledger built from a clean log
    assert forged["safety"]["read_only"] is True

    written = json.loads(writer.write_json_artifact("api-inventory.json", forged).read_text(encoding="utf-8"))

    assert written["safety"]["read_only"] is False
    assert written["observed_ledger"]["graph"]["write_calls"] == [{"method": "DELETE", "endpoint": "/users/{id}"}]


# --- bypasses found in review ---------------------------------------------------------------------


def _batch_started(**batch: Any) -> dict[str, Any]:
    return _event("graph.request.started", method="POST", url=f"{GRAPH_ROOT}/$batch", attempt=1, params={}, batch=batch)


def test_a_batch_summary_without_methods_is_not_treated_as_get_only() -> None:
    cases = [
        {"size": 1, "methods": [], "urls": ["/users/u1"]},  # methods missing
        {"size": 1, "urls": ["/users/u1"]},  # methods key absent
        {"size": 1, "methods": "GET", "urls": ["/users/u1"]},  # methods of the wrong type
        {"size": 3, "methods": ["GET"], "urls": ["/users/u1"]},  # size and urls disagree
        {"size": 0, "methods": ["GET"], "urls": []},  # nothing recorded
        {"methods": ["GET"], "urls": ["/users/u1"]},  # size absent
    ]
    for batch in cases:
        inventory = with_observed_ledger(_inventory(), [_batch_started(**batch)])
        assert inventory["observed_ledger"]["graph"]["unverified_batch_requests"] == 1, batch
        assert inventory["safety"]["read_only"] is False, batch
        assert inventory["safety"]["observed_log_complete"] is False, batch

    ok = with_observed_ledger(_inventory(), [_batch_started(size=1, methods=["GET"], urls=["/users/u1"])])
    assert ok["observed_ledger"]["graph"]["unverified_batch_requests"] == 0
    assert ok["safety"]["read_only"] is True and ok["safety"]["observed_log_complete"] is True


def test_unverified_batch_urls_are_listed_without_claiming_a_method() -> None:
    inventory = with_observed_ledger(_inventory(), [_batch_started(size=1, methods=[], urls=["/users/u1"])])

    graph = inventory["observed_ledger"]["graph"]
    assert [(row["method"], row["endpoint"]) for row in graph["endpoints"]] == [("UNVERIFIED", "/users/u1")]
    assert graph["data_methods_seen"] == []


def test_malformed_log_lines_are_counted_and_stop_the_run_being_read_only(tmp_path: Path) -> None:
    log = tmp_path / "audit-log.jsonl"
    good = json.dumps(_event("graph.request.started", method="GET", url=f"{GRAPH_ROOT}/users", attempt=1, params={}))
    log.write_text(f"{good}\nnot json\n[1, 2]\n\n{{\"event\": \"graph.request.started\", \"details\": {{\n", encoding="utf-8")

    events = read_audit_events(log)
    inventory = with_observed_ledger(_inventory(), events)

    assert len(events) == 1 and events.malformed_lines == 3 and events.readable is True
    assert inventory["observed_ledger"]["log"] == {"readable": True, "malformed_lines": 3}
    assert inventory["safety"]["malformed_log_lines"] == 3
    assert inventory["safety"]["observed_log_complete"] is False
    assert inventory["safety"]["read_only"] is False


def test_an_unreadable_audit_log_stops_the_run_being_read_only(tmp_path: Path) -> None:
    events = read_audit_events(tmp_path / "missing.jsonl")

    inventory = with_observed_ledger(_inventory(), events)

    assert events.readable is False
    assert inventory["observed_ledger"]["log"]["readable"] is False
    assert inventory["safety"]["read_only"] is False


def test_a_clean_log_and_a_plain_event_list_are_complete(tmp_path: Path) -> None:
    log = tmp_path / "audit-log.jsonl"
    log.write_text(json.dumps(_event("graph.request.started", method="GET", url=f"{GRAPH_ROOT}/users", attempt=1, params={})) + "\n", encoding="utf-8")

    from_file = with_observed_ledger(_inventory(), read_audit_events(log))
    from_list = with_observed_ledger(_inventory(), _get(f"{GRAPH_ROOT}/users")[:1])

    for inventory in (from_file, from_list):
        assert inventory["observed_ledger"]["log"] == {"readable": True, "malformed_lines": 0}
        assert inventory["safety"]["observed_log_complete"] is True
        assert inventory["safety"]["read_only"] is True


def test_the_writer_reports_malformed_lines_in_the_written_inventory(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path, tenant_name="contoso", run_name="r1")
    with writer.audit.jsonl_path.open("a", encoding="utf-8") as handle:
        handle.write("{truncated\n")

    written = json.loads(writer.write_json_artifact("api-inventory.json", _inventory()).read_text(encoding="utf-8"))

    assert written["safety"]["malformed_log_lines"] == 1
    assert written["safety"]["read_only"] is False


def test_logged_command_words_that_disagree_with_the_logged_text_are_not_trusted() -> None:
    claims_read = ["Get-Mailbox"]
    cases = [
        # The words say a read; the text ran something else as well.
        ("powershell_graph", claims_read, "Get-Mailbox ';' Remove-Mailbox x"),
        ("powershell_graph", claims_read, "Get-Mailbox '|' Set-Mailbox x"),
        # The words name a cmdlet that is not in the text at all.
        ("powershell_graph", ["Get-Mailbox", "Select-Object"], "Get-Mailbox Name"),
        # m365: the words say `list`; the text says `remove`.
        ("m365_cli", ["spo", "list"], "m365 spo list remove --url x"),
        ("m365_cli", ["spo", "list"], "m365 spo site remove --url x"),
    ]
    for adapter, words, text in cases:
        events = [_event("command.started", adapter=adapter, command=text, command_words=words)]
        inventory = with_observed_ledger(_inventory(calls=[]), events)
        assert inventory["safety"]["read_only"] is False, (adapter, text)
        assert inventory["safety"]["observed_write_calls"], (adapter, text)


def test_consistent_command_words_and_text_stay_read_only() -> None:
    events = [
        _event("command.started", adapter="powershell_graph", command="Get-Mailbox '|' Select-Object Name", command_words=["Get-Mailbox", "Select-Object"]),
        _event("command.started", adapter="m365_cli", command="m365 purview dlp policy list --output json", command_words=["purview", "dlp", "policy", "list"]),
        _event("command.started", adapter="m365dsc", command="Export-M365DSCConfiguration -Components @(AADUser)", command_words=["Export-M365DSCConfiguration"]),
        _event("command.started", adapter="powershell_graph", command_words=["Get-Mailbox"]),  # an older event without text
    ]

    inventory = with_observed_ledger(_inventory(calls=[]), events)

    assert inventory["safety"]["read_only"] is True
    assert inventory["safety"]["observed_write_calls"] == []


def test_every_shipped_powershell_command_logged_by_the_adapter_is_read_only_in_the_ledger(monkeypatch) -> None:
    """The logged text is quoted by the redaction; the cross-check must still accept what the adapters really log."""
    import subprocess

    from azure_tenant_audit.adapters.powershell_graph import PowerShellGraphAdapter
    from azure_tenant_audit.collectors.exchange_policy import ExchangePolicyCollector
    from azure_tenant_audit.collectors.teams_policy import TeamsPolicyCollector

    monkeypatch.setattr("subprocess.run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, stdout="[]", stderr=""))
    monkeypatch.setattr("shutil.which", lambda name, *a, **k: f"/usr/bin/{name}")
    events: list[dict[str, Any]] = []
    adapter = PowerShellGraphAdapter()
    commands = [command for _, command in (*ExchangePolicyCollector.command_collectors, *TeamsPolicyCollector.command_collectors)]
    for command in commands:
        adapter.run(command, log_event=lambda event, message, details=None: events.append(_event(event, **(details or {}))))

    inventory = with_observed_ledger(_inventory(calls=[]), events)

    assert inventory["observed_ledger"]["commands"]["write_calls"] == []
    assert all(row["read_only"] for row in inventory["observed_ledger"]["commands"]["executed"])
    assert inventory["counts"]["observed_commands"] == len(commands)
    assert inventory["safety"]["read_only"] is True
