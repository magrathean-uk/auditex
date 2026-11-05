from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

from auditex.command_runner import run_cli_command
from azure_tenant_audit.adapters.m365_cli import M365CLIAdapter
from azure_tenant_audit.adapters.powershell_graph import PowerShellGraphAdapter
from azure_tenant_audit.output import AuditWriter
from azure_tenant_audit.secret_hygiene import redact_output


EMAIL = "recipient-canary+tag@mocktenant.test"
UPN = "guest_canary_mocktenant.test#EXT#@mocktenant.onmicrosoft.com"
GUID = "A17E23D4-5B69-47AB-8C01-23456789ABCD"
CANARIES = (EMAIL, UPN, GUID)
DIAGNOSTIC = f"Get-Mailbox: SentTo={EMAIL}; UserPrincipalName={UPN}; ObjectId={{{GUID}}}"


def _assert_private(text: str) -> None:
    for canary in CANARIES:
        assert canary not in text
    assert "recipient-canary" not in text
    assert "guest_canary" not in text


@pytest.mark.parametrize("value", [DIAGNOSTIC, DIAGNOSTIC.encode(), None])
def test_diagnostic_mask_preserves_error_structure(value) -> None:
    masked = redact_output(value)
    _assert_private(masked)
    assert len(masked) <= 500
    if value:
        assert masked == (
            "Get-Mailbox: SentTo=***@mocktenant.test; "
            "UserPrincipalName=***@mocktenant.onmicrosoft.com; ObjectId={<redacted-guid>}"
        )
        assert redact_output(masked) == masked


@pytest.mark.parametrize("canary", [
    EMAIL, UPN, GUID, "üser@mocktenant", "o'canary@mocktenant.test",
    "equal=canary@mocktenant.test", '"quoted canary"@mocktenant.test',
])
def test_personal_values_are_masked_before_sample_boundary(canary: str) -> None:
    masked = redact_output("x " + " " * 490 + canary + " tail" * 100)
    assert len(masked) == 500
    assert canary[:5] not in masked


@pytest.mark.parametrize("address", [EMAIL, "üser@mocktenant", '"quoted canary"@mocktenant.test'])
def test_email_mask_preserves_json_and_diagnostic_quotes(address: str) -> None:
    masked = redact_output(json.dumps({"SentTo": address}))
    assert json.loads(masked) == {"SentTo": "***@" + address.rsplit("@", 1)[1]}
    assert redact_output(f"SentTo='{EMAIL}'") == "SentTo='***@mocktenant.test'"


def test_guid_mask_handles_identifier_separators() -> None:
    assert redact_output(f"id_{GUID}_suffix") == "id_<redacted-guid>_suffix"


def test_output_mask_retains_credential_redaction() -> None:
    masked = redact_output(DIAGNOSTIC + ' "client_secret": "secret-canary" Bearer bearer-canary password=known', {"known"})
    _assert_private(masked)
    assert all(value not in masked for value in ("secret-canary", "bearer-canary", "known"))


@pytest.mark.parametrize("secret", [
    "Secr3t%2DValue", "ab%7Bcd%7D", "p%40ssword99", r"p\u0040ssword99", "p&#64;ssword99", "s＠cret",
])
@pytest.mark.parametrize("as_bytes", [False, True])
def test_output_mask_redacts_literal_credentials_before_decoding(secret, as_bytes) -> None:
    value = secret.encode() if as_bytes else secret
    assert redact_output(value, {secret}) == "***redacted***"


def test_output_mask_reuses_sensitive_iterator_after_decoding() -> None:
    assert redact_output("Secr3t%2DValue", iter(["Secr3t-Value"])) == "***redacted***"


@pytest.mark.parametrize("value", [0, False, 42, 1.5, [], [EMAIL], {"user": EMAIL}, bytearray(EMAIL.encode()), memoryview(EMAIL.encode())])
def test_output_mask_coerces_unexpected_types(value) -> None:
    assert redact_output(value) == redact_output(str(value))
    _assert_private(redact_output(value))


@pytest.mark.parametrize("limit", [-5000, -5, 0])
@pytest.mark.parametrize("value", ["diagnostic text", DIAGNOSTIC, DIAGNOSTIC.encode(), "x" * 3000])
def test_output_mask_nonpositive_limit_is_empty(value, limit) -> None:
    assert redact_output(value, limit=limit) == ""


@pytest.mark.parametrize("value", [42, 1.5, [EMAIL], {"user": EMAIL}])
def test_toolchain_parser_nonstring_version_is_coerced_and_masked(value) -> None:
    from auditex.auth_runtime import ToolchainRuntime, ToolchainRuntimeAdapters

    runtime = ToolchainRuntime(ToolchainRuntimeAdapters(
        run_json_command=lambda _: {"status": "supported", "stdout": json.dumps({"azure-cli": value})},
    ))
    version, error = runtime.command_version(["az", "version"], parser=lambda output: json.loads(output)["azure-cli"])
    assert error is None
    assert version == redact_output(str(value))
    _assert_private(version)


@pytest.mark.parametrize("value", [42, 1.5, [EMAIL], {"user": EMAIL}])
def test_m365_cli_nonstring_exception_output_is_coerced_and_masked(monkeypatch, value) -> None:
    def fake_run(cmd, **kwargs):
        raise subprocess.CalledProcessError(1, cmd, output=value)

    monkeypatch.setattr("shutil.which", lambda _: "/mock/m365")
    monkeypatch.setattr("subprocess.run", fake_run)
    response = M365CLIAdapter().run("m365 aad user list --output json")
    assert response["error_class"] == "command_error"
    assert response["output"] == redact_output(str(value))
    _assert_private(json.dumps(response))


@pytest.mark.parametrize("adapter,command", [
    (PowerShellGraphAdapter, "Get-Mailbox"),
    (M365CLIAdapter, "m365 aad user list --output json"),
])
@pytest.mark.parametrize("outcome", ["success", "nonzero", "invalid_json", "empty", "auth", "not_found", "help", "exception", "called_process", "timeout"])
def test_adapter_output_never_leaks_to_logs_or_error_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
    adapter, command: str, outcome: str,
) -> None:
    payload = {"SentTo": EMAIL, "UserPrincipalName": UPN, "ObjectId": GUID}
    stdout = json.dumps([payload])
    stderr = DIAGNOSTIC
    returncode = 1 if outcome == "nonzero" else 0
    if outcome == "invalid_json":
        stdout = DIAGNOSTIC
    elif outcome == "empty":
        stdout = ""
    elif outcome == "auth":
        stderr = "access denied; please sign in; " + DIAGNOSTIC
    elif outcome == "not_found":
        stderr = "command not found; " + DIAGNOSTIC
    elif outcome == "help":
        stdout = "CLI for Microsoft 365 v1 Commands: " + DIAGNOSTIC

    def fake_run(cmd, **kwargs):
        if outcome == "exception":
            raise RuntimeError(DIAGNOSTIC)
        if outcome == "called_process":
            raise subprocess.CalledProcessError(1, [DIAGNOSTIC], output=stdout, stderr=stderr)
        if outcome == "timeout":
            raise subprocess.TimeoutExpired([DIAGNOSTIC], 120, output=stdout.encode(), stderr=stderr.encode())
        return subprocess.CompletedProcess(cmd, returncode, stdout, stderr)

    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setattr("shutil.which", lambda name: f"/mock/{name}")
    observed = []
    writer = AuditWriter(tmp_path, tenant_name="mocktenant", run_name="privacy", event_listener=observed.append)
    with caplog.at_level(logging.DEBUG):
        response = adapter().run(command, log_event=writer.log_event)
        if outcome == "success":
            # Evidence remains intact in memory, while its log sample is masked.
            assert response["value"] == [payload]
        else:
            assert response.get("error")
            writer.write_raw("diagnostic", response)

    for path in writer.run_dir.rglob("*"):
        if path.is_file():
            _assert_private(path.read_text())
    _assert_private(caplog.text)
    _assert_private(repr(observed))
    for name in ("audit-log.jsonl", "audit-command-log.jsonl", "audit-debug.log"):
        assert (writer.run_dir / name).stat().st_size > 0
    completed = [event["details"] for event in observed if event["event"] == "command.completed"]
    if completed:
        assert len(completed[0]["stdout_sample"]) <= 500
        assert completed[0]["stdout_bytes"] == len(stdout)
        assert completed[0]["stderr_bytes"] == len(stderr)
    for key in ("stdout", "stderr", "output", "error"):
        if key in response:
            assert len(response[key]) <= 500


@pytest.mark.parametrize("timeout", [False, True])
def test_command_runner_masks_both_streams_without_clipping_structured_output(monkeypatch, timeout) -> None:
    stdout = json.dumps({"rows": [DIAGNOSTIC] * 20})

    def fake_run(cmd, **kwargs):
        if timeout:
            raise subprocess.TimeoutExpired(cmd, 1, output=stdout.encode(), stderr=DIAGNOSTIC.encode())
        return subprocess.CompletedProcess(cmd, 0, stdout, DIAGNOSTIC)

    monkeypatch.setattr("subprocess.run", fake_run)
    response = run_cli_command(["auditex", "doctor"])
    _assert_private(json.dumps(response))
    assert len(json.loads(response["stdout"])["rows"]) == 20
    assert "Get-Mailbox" in response["stderr"]


@pytest.mark.parametrize("returncode,stdout_kind", [(0, "text"), (0, "list"), (0, "dict"), (1, "text")])
@pytest.mark.parametrize("stderr", ["", DIAGNOSTIC])
def test_probe_raw_and_error_snippets_are_masked(tmp_path, monkeypatch, returncode, stdout_kind, stderr) -> None:
    from azure_tenant_audit import probe

    class FakeAdapter:
        def dependency_check(self):
            return True

        def run(self, command, log_event):
            if returncode:
                return {"error": DIAGNOSTIC}
            return {"value": [{"connectedAs": EMAIL, "id": GUID, "nested": [UPN]}]}

    stdout = {
        "text": DIAGNOSTIC,
        "list": json.dumps([DIAGNOSTIC]),
        "dict": json.dumps({"tenant": GUID, "nested": {"user": UPN}, "address": EMAIL}),
    }[stdout_kind]
    monkeypatch.setattr(probe.shutil, "which", lambda name: f"/mock/{name}")
    monkeypatch.setattr(probe, "get_adapter", lambda _: FakeAdapter())
    monkeypatch.setattr(probe, "_subprocess_probe", lambda cmd: (returncode, stdout, stderr))
    writer = AuditWriter(tmp_path, tenant_name="mocktenant", run_name="probe-privacy")
    rows = probe._probe_toolchain_statuses(include_response=True, log_event=writer.log_event)
    writer.write_json_artifact("toolchain-readiness.json", rows)
    _assert_private(json.dumps(rows))
    for path in writer.run_dir.rglob("*"):
        if path.is_file():
            _assert_private(path.read_text())


@pytest.mark.parametrize("adapter,command", [
    (PowerShellGraphAdapter, "Get-Mailbox"),
    (M365CLIAdapter, "m365 aad user list --output json"),
])
def test_successful_adapter_evidence_retains_identifiers(tmp_path, monkeypatch, adapter, command) -> None:
    payload = {"SentTo": EMAIL, "UserPrincipalName": UPN, "ObjectId": GUID, "padding": "x" * 1000}
    monkeypatch.setattr("shutil.which", lambda name: f"/mock/{name}")
    monkeypatch.setattr("subprocess.run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, json.dumps([payload]), ""))
    writer = AuditWriter(tmp_path, tenant_name="mocktenant", run_name="evidence")
    response = adapter().run(command, log_event=writer.log_event)
    writer.write_raw("evidence", response)
    assert json.loads((writer.raw_dir / "evidence.json").read_text())["value"] == [payload]
    _assert_private((writer.run_dir / "audit-log.jsonl").read_text())


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_azure_cli_token_failure_sample_is_private(tmp_path, monkeypatch, caplog, stream) -> None:
    from azure_tenant_audit.auth_runtime import acquire_azure_cli_access_token

    streams = {"stdout": "", "stderr": "", stream: DIAGNOSTIC + " detail" * 200}
    monkeypatch.setattr("subprocess.run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, **streams))
    writer = AuditWriter(tmp_path, tenant_name="mocktenant", run_name="token-failure")
    with pytest.raises(RuntimeError) as error:
        acquire_azure_cli_access_token("mocktenant", log_event=writer.log_event)
    _assert_private(str(error.value))
    _assert_private(caplog.text)
    for path in writer.run_dir.iterdir():
        if path.is_file():
            _assert_private(path.read_text())


@pytest.mark.parametrize("default", [False, True])
@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_exchange_module_error_snippet_is_private(monkeypatch, default, stream) -> None:
    from auditex import auth, auth_runtime

    streams = {"stdout": "", "stderr": "", stream: DIAGNOSTIC + " detail" * 200}
    monkeypatch.setattr("shutil.which", lambda name: f"/mock/{name}")
    monkeypatch.setattr("subprocess.run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, **streams))
    check = auth_runtime._default_exchange_module_status if default else auth._pwsh_exchange_module_status
    response = check()
    _assert_private(json.dumps(response))
    assert len(response["error"]) == 500


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_auth_and_toolchain_report_boundaries_mask_diagnostics(tmp_path, stream) -> None:
    from auditex.auth_runtime import AuthRuntimeAdapters, ProductAuthRuntime, ToolchainRuntime, ToolchainRuntimeAdapters

    def blocked(command):
        return {"status": "blocked", stream: DIAGNOSTIC + " detail" * 200}

    auth = ProductAuthRuntime(AuthRuntimeAdapters(json_command=blocked))
    response = auth.get_auth_status(include_exchange=False)
    _assert_private(json.dumps(response))
    for operation in (auth.list_connections, lambda: auth.use_connection("mocktenant")):
        with pytest.raises(RuntimeError) as error:
            operation()
        _assert_private(str(error.value))
        assert len(str(error.value)) == 500

    selector = tmp_path / "select-python.sh"
    selector.touch()
    toolchain = ToolchainRuntime(ToolchainRuntimeAdapters(run_json_command=blocked), select_python_script=selector)
    version, error = toolchain.command_version(["mock-tool"])
    assert version is None and len(error) == 500
    _assert_private(error)
    _assert_private(json.dumps(toolchain.selected_python()))


def test_toolchain_parser_sees_original_output_before_diagnostics_are_masked() -> None:
    from auditex.auth_runtime import ToolchainRuntime, ToolchainRuntimeAdapters

    def supported(command):
        return {"status": "supported", "stdout": json.dumps({"version": DIAGNOSTIC})}

    def parser(output):
        assert json.loads(output)["version"] == DIAGNOSTIC
        return json.loads(output)["version"]

    runtime = ToolchainRuntime(ToolchainRuntimeAdapters(run_json_command=supported))
    version, error = runtime.command_version(["mock-tool"], parser=parser)
    _assert_private(version)
    assert error is None
    _assert_private(runtime.command_version(["mock-tool"])[0])

    def bad_parser(output):
        raise ValueError(DIAGNOSTIC)

    _assert_private(runtime.command_version(["mock-tool"], parser=bad_parser)[1])


# The supplied review does not enumerate its full 57-case timing corpus.
# Retain the eight existing units and cover query/filter starts, encodings, quotes,
# credential pattern and long escaped local part in a reproducible 57-case corpus.
@pytest.mark.parametrize("unit", [
    "a'", "To='", r"\u4e2d", "@", "a@", ".", "a17e23d45b6947ab8c0123456789abcd", "-eyJa",
    "a", f"Trace ID: {GUID} ", f"Correlation ID: {GUID} ", GUID + "f", "a+", "a|", "a?", "a&", "a%20", "a%27",
    "a%3D", "a%40", r"a\u0040", "a&#64;", "a＠", "'", '"', r'\"', "\\", r"\u",
    r"\u0061", r"\n", r"\t", r"\r", "%", "%2", "%27", "%20", "%3D", "%40",
    "&#64;", "a'@", '"a"@', r'\"a\"@', r"\u0061" * 64 + "@x ",
    "a@x&bob@y", "a@x?bob@y", "a@x|bob@y", "a@x+bob@y", "a@x'bob@y",
    "a@x%20bob@y", "a@x%27bob@y", "a@x%3Dbob@y", "password=", "password='",
    'password="', "Bearer ", "eyJa.", "eyJa.eyJa.",
])
def test_output_mask_megabyte_adversarial_input_is_bounded(unit, record_property) -> None:
    # Allow host-load variation with a fixed, generous 15-second budget per MB.
    # A separate child deadline bounds future regex regressions too.
    script = r"""
import json, re, sys, time
from auditex.command_runner import _redact_text
from azure_tenant_audit import secret_hygiene
unit = sys.argv[1]
text = (unit * (1_048_576 // len(unit) + 1))[:1_048_576]
timings = {}
def timed(name, operation):
    started = time.monotonic()
    operation()
    timings[name] = time.monotonic() - started
    assert timings[name] < 15.0, (name, timings[name])
for name, pattern in vars(secret_hygiene).items():
    if isinstance(pattern, re.Pattern):
        timed(name, lambda: pattern.sub('', text))
timed('trailing_token', lambda: re.split(r'''[\s,;:"'<>()\[\]{}]''', text))
timed('full', lambda: secret_hygiene.redact_output(text, limit=None))
timed('clipped', lambda: secret_hygiene.redact_output(text))
# Force the real exemption pass even when this pattern has no operator value.
operator = 'a' * 512
timed('operator', lambda: _redact_text(text + '\n' + operator, set(), {operator}))
print(json.dumps(timings))
"""
    result = subprocess.run(
        [sys.executable, "-c", script, unit],
        cwd=Path(__file__).resolve().parents[1],
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")},
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    record_property("adversarial_timings", result.stdout.strip())


@pytest.mark.parametrize("encoded", [
    "alice%40contoso.com", r"alice\u0040contoso.com", "alice&#64;contoso.com", "alice＠contoso.com",
])
def test_output_mask_decodes_address_separators(encoded) -> None:
    assert redact_output(encoded) == "***@contoso.com"


@pytest.mark.parametrize("encoded,expected", [
    (f"%7B{GUID}%7D", "{<redacted-guid>}"),
    (GUID.replace("-", "%2D"), "<redacted-guid>"),
    (f"objectid=cafe{GUID}", "objectid=cafe<redacted-guid>"),
])
def test_output_mask_decodes_and_finds_embedded_guids(encoded, expected) -> None:
    assert redact_output(encoded) == expected


@pytest.mark.parametrize("local", ["a" * 64, "o'" + "a" * 62, '"' + "a" * 64 + '"', r"\u4e2d" * 64])
def test_output_mask_handles_maximum_local_part_at_cut(local) -> None:
    # A maximum-length suffix must still be recognised beyond the sample cut.
    domain = ".".join(["b" * 63] * 3 + ["c" * 61])
    result = redact_output(" " * 495 + local + "@" + domain)
    assert result == (" " * 495 + "***@" + domain)[:500]


def test_output_mask_only_scans_sample_and_safety_margin(monkeypatch) -> None:
    from azure_tenant_audit import secret_hygiene

    original = secret_hygiene.redact_text
    lengths = []

    def observe(value, sensitive_values):
        lengths.append(len(value))
        return original(value, sensitive_values)

    monkeypatch.setattr(secret_hygiene, "redact_text", observe)
    # The final unterminated run is dropped even when it fills the whole window.
    assert redact_output("x" * 1_048_576) == ""
    assert lengths == [500 + 2048, 500 + 2048]


def test_output_mask_graph_or_filter_masks_both_addresses() -> None:
    text = (
        "Uri: https://graph.microsoft.com/v1.0/users?$filter="
        "mail%20eq%20%27a%40contoso.com%27%20or%20mail%20eq%20%27bob%40contoso.com%27"
    )
    masked = redact_output(text)
    assert "a@contoso.com" not in masked
    assert "bob" not in masked
    assert masked.count("***@contoso.com") == 2
    assert masked.startswith("Uri: https://graph.microsoft.com/")


@pytest.mark.parametrize("text", [
    "?SenderAddress=a@x&b=c@y", "?SenderAddress=alice@x&RecipientAddress=bob@y",
    "mailto:a@x?cc=bob@y", "a@x&bob@y", "a@x?bob@y", "a@x%20bob@y", "a@x%27bob@y",
    "a@x|bob@y", "a@x+bob@y", "a@x'bob@y",
])
def test_output_mask_glued_addresses_masks_second_local_part(text) -> None:
    masked = redact_output(text)
    assert masked.count("***@") == 2
    assert "a@x" not in masked and "alice" not in masked
    assert all(local not in masked for local in ("b=c@", "bob"))


@pytest.mark.parametrize("text,expected", [
    ("https://graph.microsoft.com/v1.0/users/alice@contoso.com/messages",
     "https://graph.microsoft.com/v1.0/users/***@contoso.com/messages"),
    ("@pnp/cli-microsoft365@10.1.0", "@pnp/cli-microsoft365@10.1.0"),
    ("git@github.com", "git@github.com"),
    ("git@gitlab.com", "git@gitlab.com"),
    ("ssh://git@ssh.dev.azure.com", "ssh://git@ssh.dev.azure.com"),
    (f"request-id: {GUID}\nclient-request-id: {GUID}",
     "request-id: <redacted-guid>\nclient-request-id: <redacted-guid>"),
    ("request-id: support-reference\nclient-request-id: another-reference",
     "request-id: support-reference\nclient-request-id: another-reference"),
    ("%2D%2Dhelp", "--help"),
    (GUID.replace("-", ""), GUID.replace("-", "")),
    (f'Trace ID: {GUID}\nCorrelation ID: {GUID}\nObjectId: {GUID}',
     f'Trace ID: {GUID}\nCorrelation ID: {GUID}\nObjectId: <redacted-guid>'),
])
def test_output_mask_preserves_diagnostic_context(text, expected) -> None:
    assert redact_output(text) == expected


@pytest.mark.parametrize("timeout", [False, True])
@pytest.mark.parametrize("flag", ["--tenant-name", "--tenant-id", "--out", "--run-name", "--target", "--subject", "--domain"])
@pytest.mark.parametrize("inline", [False, True])
def test_mcp_operator_identifiers_survive_without_exposing_cmdlet_output(monkeypatch, tmp_path, timeout, flag, inline) -> None:
    operator_value = "operator@mocktenant.test" if flag in {"--subject", "--domain"} else GUID
    command = ["auditex", "run", f"{flag}={operator_value}"] if inline else ["auditex", "run", flag, operator_value]
    run_dir = tmp_path / f"{operator_value}-run_20261105_110229"
    stderr = f"INFO: Offline sample written to {run_dir}\n{DIAGNOSTIC}"

    def fake_run(cmd, **kwargs):
        if timeout:
            raise subprocess.TimeoutExpired(cmd, 1, output=b"{}", stderr=stderr.encode())
        return subprocess.CompletedProcess(cmd, 0, "{}", stderr)

    monkeypatch.setattr("subprocess.run", fake_run)
    response = run_cli_command(command, cwd=str(tmp_path))
    assert str(run_dir) in response["stderr"]
    assert EMAIL not in response["stderr"] and "recipient-canary" not in response["stderr"]


def test_m365dsc_classifies_module_missing_before_diagnostic_clipping(monkeypatch) -> None:
    from azure_tenant_audit.adapters.m365dsc import M365DSCAdapter

    stderr = "prelude " * 100 + DIAGNOSTIC + " Microsoft365DSC module not installed"

    def fake_run(cmd, **kwargs):
        if "Get-Module -ListAvailable" in cmd[-1]:
            return subprocess.CompletedProcess(cmd, 0, '[{"module_version":"2.26.1015.1"}]', "")
        return subprocess.CompletedProcess(cmd, 1, "", stderr)

    monkeypatch.setattr("shutil.which", lambda _: "/mock/pwsh")
    monkeypatch.setattr("subprocess.run", fake_run)
    events = []
    response = M365DSCAdapter().run("Get-M365DSCResource", log_event=lambda *args: events.append(args))
    assert response["error_class"] == "module_not_found"
    assert response["error"] == "module_not_found"
    assert len(response["stderr"]) <= 500
    _assert_private(json.dumps(response))
    assert events[-1][2]["error_class"] == "module_not_found"


def test_mcp_resolved_output_path_survives_and_credentials_take_precedence(monkeypatch, tmp_path) -> None:
    command = ["auditex", "run", "--out", "../" + GUID, "--subject", EMAIL, "--client-secret", EMAIL]
    out = (tmp_path / ".." / GUID).resolve()
    monkeypatch.setattr("subprocess.run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "{}", f"{out}/demo-run\npassword={EMAIL}"))
    response = run_cli_command(command, cwd=str(tmp_path))
    assert f"{out}/demo-run" in response["stderr"]
    assert EMAIL not in json.dumps(response)


def test_mcp_ordinary_operator_label_does_not_exempt_email_local_part(monkeypatch) -> None:
    monkeypatch.setattr("subprocess.run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "{}", DIAGNOSTIC))
    response = run_cli_command(["auditex", "run", "--tenant-name", "recipient-canary"])
    _assert_private(response["stderr"])


def test_mcp_offline_guid_run_path_can_be_used_by_next_tool(monkeypatch, tmp_path) -> None:
    from auditex.mcp_server import build_cli_command, summarize_run, summarize_run_raw

    repo = Path(__file__).resolve().parents[1]
    monkeypatch.setenv("PYTHONPATH", str(repo / "src"))
    command = build_cli_command(tenant_name=GUID, out_dir=str(tmp_path), offline=True)
    real_run = subprocess.run

    def with_cmdlet_diagnostic(cmd, **kwargs):
        result = real_run(cmd, **kwargs)
        result.stderr += "\nGet-Mailbox: " + EMAIL
        return result

    monkeypatch.setattr("subprocess.run", with_cmdlet_diagnostic)
    response = run_cli_command(command, cwd=str(repo))
    assert response["returncode"] == 0, response
    run_dir = next(tmp_path.glob(f"{GUID}-run_*"))
    assert str(run_dir) in response["stderr"]
    assert EMAIL not in response["stderr"] and "recipient-canary" not in response["stderr"]
    # The operator's own read keeps the real tenant name. The MCP response leaves the machine, so it passes the
    # shareable redaction: the same run is found and summarised, with the GUID pseudonymised (a valid GUID).
    assert summarize_run_raw(str(run_dir))["manifest"]["tenant_name"] == GUID
    shared = summarize_run(str(run_dir))["manifest"]["tenant_name"]
    assert shared != GUID and shared.startswith("00000000-0000-4000-8000-")


@pytest.mark.parametrize("adapter,command", [
    (PowerShellGraphAdapter, "Get-Mailbox"),
    ("m365dsc", "Get-M365DSCResource"),
])
def test_adapter_exit_zero_with_path_warning_keeps_evidence(monkeypatch, adapter, command) -> None:
    from azure_tenant_audit.adapters.m365dsc import M365DSCAdapter

    payload = [{"SentTo": EMAIL, "ObjectId": GUID}]

    def fake_run(cmd, **kwargs):
        if "Get-Module -ListAvailable" in cmd[-1]:
            return subprocess.CompletedProcess(cmd, 0, '[{"module_version":"2.26.1015.1"}]', "")
        return subprocess.CompletedProcess(
            cmd, 0, json.dumps(payload), r"WARNING: Cannot find path 'C:\cache\x.json' because it does not exist.",
        )

    monkeypatch.setattr("shutil.which", lambda _: "/mock/pwsh")
    monkeypatch.setattr("subprocess.run", fake_run)
    events = []
    response = (M365DSCAdapter if adapter == "m365dsc" else adapter)().run(
        command, log_event=lambda *args: events.append(args),
    )
    assert not response.get("error"), response
    assert response["value"] == payload
    assert events[-1][2]["status"] == "ok"


@pytest.mark.parametrize("returncode", [0, 1])
def test_m365dsc_module_missing_uses_stderr_only(monkeypatch, returncode) -> None:
    from azure_tenant_audit.adapters.m365dsc import M365DSCAdapter

    payload = [{"description": "Microsoft365DSC module not installed"}]

    def fake_run(cmd, **kwargs):
        if "Get-Module -ListAvailable" in cmd[-1]:
            return subprocess.CompletedProcess(cmd, 0, '[{"module_version":"2.26.1015.1"}]', "")
        return subprocess.CompletedProcess(cmd, returncode, json.dumps(payload), "other diagnostic")

    monkeypatch.setattr("shutil.which", lambda _: "/mock/pwsh")
    monkeypatch.setattr("subprocess.run", fake_run)
    response = M365DSCAdapter().run("Get-M365DSCResource")
    if returncode:
        assert response["error_class"] == "command_error"
    else:
        assert response["value"] == payload


@pytest.mark.parametrize("flag,operator,other", [
    ("--subject", "admin@contoso.com", "superadmin@contoso.com"),
    ("--subject", "admin@contoso.com", "x.admin@contoso.com"),
    ("--tenant-name", "a@contoso.com", "alice.a@contoso.com"),
    ("--domain", "e@c.io", "joe@c.io"),
])
@pytest.mark.parametrize("timeout", [False, True])
def test_mcp_operator_exemption_does_not_preserve_other_local_parts(monkeypatch, flag, operator, other, timeout) -> None:
    output = f"{operator}\n{other}"

    def fake_run(cmd, **kwargs):
        if timeout:
            raise subprocess.TimeoutExpired(cmd, 1, output=output.encode(), stderr=output.encode())
        return subprocess.CompletedProcess(cmd, 0, output, output)

    monkeypatch.setattr("subprocess.run", fake_run)
    response = run_cli_command(["auditex", "run", flag, operator])
    expected = operator + "\n***@" + other.split("@", 1)[1]
    assert response["stdout"] == response["stderr"] == expected


@pytest.mark.parametrize("escape", [r"\n", r"\t", r"\r", r"\b", r"\f"])
def test_output_mask_after_json_whitespace_escape(escape) -> None:
    assert redact_output(f"Failed:{escape}alice@contoso.com") == f"Failed:{escape}***@contoso.com"


@pytest.mark.parametrize("fragment", ["victimlocalpart@", "victimlocalpart"])
@pytest.mark.parametrize("as_bytes", [False, True])
def test_output_mask_drops_scan_edge_after_large_shrink(fragment, as_bytes) -> None:
    prefix = (r"\u0061" * 64 + "@c.io ") * 6
    text = prefix + " " * (500 + 2048 - len(prefix) - len(fragment)) + "victimlocalpart@contoso.com"
    result = redact_output(text.encode() if as_bytes else text)
    assert "victim" not in result
    assert result.count("***@c.io") == 6
    assert len(result) <= 500


def test_output_mask_keeps_complete_tail_when_window_is_not_clipped() -> None:
    prefix = (r"\u0061" * 64 + "@c.io ") * 6
    text = prefix + " " * (500 + 2048 - len(prefix) - len("support-tail")) + "support-tail"
    assert redact_output(text).endswith("support-tail")


@pytest.mark.parametrize("token", ["eyJabc.def.ghi", "eyJabc.def.ghi_", "eyJabc.def.ghi-"])
def test_output_mask_redacts_whole_jwt(token) -> None:
    assert redact_output(f"token: {token}") == "token: ***redacted-jwt***"
