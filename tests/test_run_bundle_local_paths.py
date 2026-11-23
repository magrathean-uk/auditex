"""No file in a run bundle holds an absolute local path (PyPI review C-repair2, follow-up to PR #176).

Every bundle (Microsoft 365 or Google Workspace; offline, probe, blocked or failed) is written with an absolute
``--out`` and absolute credential, sample and waiver paths under one folder whose name is the needle. Every file the
run writes is then read as raw bytes (the SQLite index included, so a deleted page cannot hide a path) and must not
hold that folder. Console output to the operator may still name a path; it is not swept.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path

import pytest

from auditex import cli

REPO_ROOT = Path(__file__).resolve().parents[1]
M365_SAMPLE = REPO_ROOT / "examples" / "demo_tenant" / "demo_tenant.json"
GOOGLE_SAMPLE = REPO_ROOT / "examples" / "google_workspace_sample.json"


def _files_holding(run_dir: Path, needles: tuple[str, ...]) -> list[str]:
    hits = []
    for path in sorted(run_dir.rglob("*")):
        if path.is_file():
            content = path.read_bytes()
            if any(needle.encode("utf-8") in content for needle in needles):
                hits.append(str(path.relative_to(run_dir)))
    return hits


@pytest.fixture
def operator_root(tmp_path: Path) -> Path:
    """An absolute folder on the operator's machine, with a space so a split path cannot pass either."""
    root = tmp_path / "operator place"
    (root / "inputs").mkdir(parents=True)
    return root


def _waiver(root: Path, rule_id: str) -> Path:
    path = root / "inputs" / "waivers.json"
    path.write_text(json.dumps({"waivers": [{"rule_id": rule_id, "owner": "o", "reason": "r",
                                             "expires_on": "2099-01-01"}]}), encoding="utf-8")
    return path


def _run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> int:
    try:
        rc = cli.main(argv)
    except SystemExit as exc:  # a parser refusal would end the test with no bundle; keep the code
        rc = exc.code
    capsys.readouterr()
    return rc


def _assert_clean(run_dir: Path, root: Path) -> None:
    assert (run_dir / "run-manifest.json").is_file() and (run_dir / "index" / "evidence.sqlite").is_file()
    assert _files_holding(run_dir, (str(root), str(root.resolve()))) == []
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    # The documented field stays, as the run folder name (output-contract.md, "Run directory").
    assert manifest["run_dir"] == run_dir.name
    conn = sqlite3.connect(run_dir / "index" / "evidence.sqlite")
    try:
        assert dict(conn.execute("SELECT key, value FROM run_meta"))["run_dir"] == run_dir.name
    finally:
        conn.close()


def test_an_offline_microsoft_365_run_writes_no_absolute_local_path(operator_root: Path, capsys) -> None:
    sample = operator_root / "inputs" / M365_SAMPLE.name
    shutil.copyfile(M365_SAMPLE, sample)
    out = operator_root / "out"
    rc = _run(["run", "--offline", "--as-of", "2026-11-11", "--sample", str(sample), "--tenant-name", "T",
               "--run-name", "offline", "--out", str(out)], capsys)
    assert rc in (0, 1)
    run_dir = out / "T-offline"
    _assert_clean(run_dir, operator_root)
    checkpoint = json.loads((run_dir / "checkpoints" / "checkpoint-state.json").read_text(encoding="utf-8"))
    assert checkpoint["run_dir"] == run_dir.name


def test_a_failed_microsoft_365_probe_writes_no_absolute_local_path(operator_root: Path, capsys) -> None:
    out = operator_root / "out"
    rc = _run(["probe", "live", "--tenant-name", "T", "--run-name", "probe",
               "--tenant-id", "11111111-2222-3333-4444-555555555555",
               "--client-id", "11111111-2222-3333-4444-666666666666",
               "--certificate-path", str(operator_root / "inputs" / "reader.pem"),
               "--certificate-thumbprint", "A" * 40, "--out", str(out)], capsys)
    assert rc != 0
    _assert_clean(out / "T-probe", operator_root)


def test_an_offline_google_run_with_a_waiver_writes_no_absolute_local_path(operator_root: Path, capsys) -> None:
    sample = operator_root / "inputs" / GOOGLE_SAMPLE.name
    shutil.copyfile(GOOGLE_SAMPLE, sample)
    waiver = _waiver(operator_root, "google.org_2sv_policy_not_enforced")
    out = operator_root / "out"
    rc = _run(["google", "run", "--offline", "--sample", str(sample), "--domain", "example.com",
               "--tenant-name", "G", "--run-name", "offline", "--out", str(out), "--waiver-file", str(waiver)], capsys)
    assert rc in (0, 1)
    run_dir = out / "G-offline"
    _assert_clean(run_dir, operator_root)
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["waiver_path"] == "<local-path>/waivers.json"


@pytest.mark.parametrize("auth", ["oauth", "domain-delegation"])
@pytest.mark.parametrize("libraries", ["missing", "present"])
def test_a_blocked_or_failed_google_probe_writes_no_absolute_local_path(operator_root: Path, monkeypatch, capsys,
                                                                        auth: str, libraries: str) -> None:
    from auditex.google_workspace import auth as google_auth

    if libraries == "missing":
        monkeypatch.setattr(google_auth, "_module_available", lambda module: False)
    else:
        pytest.importorskip("google_auth_oauthlib.flow")
        pytest.importorskip("google.oauth2.service_account")
    inputs = operator_root / "inputs"
    credentials = (["--auth", "oauth", "--oauth-client", str(inputs / "client.json"),
                    "--token-cache", str(inputs / "token.json")] if auth == "oauth" else
                   ["--subject", "admin@example.com", "--service-account-key", str(inputs / "sa.json")])
    out = operator_root / "out"
    rc = _run(["google", "probe", "--domain", "example.com", "--customer-id", "C123", "--tenant-name", "G",
               "--run-name", "probe", "--collectors", "google_directory", *credentials, "--out", str(out)], capsys)
    assert rc == 2
    run_dir = out / "G-probe"
    assert (run_dir / "probe-result.json").is_file()
    _assert_clean(run_dir, operator_root)


def test_a_missing_oauth_client_is_named_without_its_path(operator_root: Path) -> None:
    pytest.importorskip("google_auth_oauthlib.flow")
    from auditex.google_workspace.auth import GoogleAuthConfig, build_google_credentials

    client = operator_root / "inputs" / "client.json"
    with pytest.raises(ValueError) as exc:
        build_google_credentials(GoogleAuthConfig(auth_mode="oauth", oauth_client=client,
                                                  token_cache=operator_root / "inputs" / "token.json"))
    assert str(operator_root) not in str(exc.value)
    assert str(exc.value).startswith("oauth_client_missing:")


def test_a_failed_google_probe_keeps_no_path_from_any_file_error(operator_root: Path, monkeypatch, capsys) -> None:
    """A file error raised anywhere in the sign-in names its path; the probe rows keep only the reason."""
    pytest.importorskip("google.oauth2.service_account")
    from auditex.google_workspace import run as google_run

    missing = operator_root / "inputs" / "token.json"

    def refuse(_config):
        raise PermissionError(13, "Permission denied", str(missing))

    monkeypatch.setattr(google_run, "build_google_credentials", refuse)
    out = operator_root / "out"
    rc = _run(["google", "probe", "--auth", "oauth", "--oauth-client", str(operator_root / "inputs" / "client.json"),
               "--token-cache", str(missing), "--domain", "example.com", "--customer-id", "C123", "--tenant-name", "G",
               "--run-name", "probe", "--collectors", "google_directory", "--out", str(out)], capsys)
    assert rc == 2
    run_dir = out / "G-probe"
    _assert_clean(run_dir, operator_root)
    result = json.loads((run_dir / "probe-result.json").read_text(encoding="utf-8"))
    assert result["preflight"][0]["error"] == "Permission denied"
    assert result["preflight_error"]["message"] == "Permission denied"


# Repair round 1 of PR #194: every writer of the bundle passes one normaliser (azure_tenant_audit/local_paths.py).
# These runs carry the command line the operator typed (sys.argv, with an absolute program path, --out and
# --waiver-file), an absolute PowerShell executable, a resumed folder, a lab seed path in an offline sample's
# provenance and a Python library file error, and must still leave no absolute local path in any file.


def _operator_argv(monkeypatch: pytest.MonkeyPatch, root: Path, argv: list[str]) -> list[str]:
    monkeypatch.setattr("sys.argv", [str(root / "bin" / "auditex"), *argv])
    return argv


def _fake_pwsh(monkeypatch: pytest.MonkeyPatch, root: Path) -> Path:
    """A PowerShell on an absolute PATH entry that answers every readiness check with a failure."""
    bin_dir = root / "bin"
    bin_dir.mkdir(exist_ok=True)
    pwsh = bin_dir / "pwsh"
    pwsh.write_text("#!/bin/sh\necho 'module missing' >&2\nexit 3\n", encoding="utf-8")
    pwsh.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    return pwsh


def _m365_live(monkeypatch: pytest.MonkeyPatch, root: Path, *extra: str) -> int:
    from support import FAKE_CERTIFICATE_ARGS, use_fake_certificate
    from test_resume_and_offline_replay import _Collector, _FakeClient

    from azure_tenant_audit import cli as engine_cli

    argv = _operator_argv(monkeypatch, root, [
        "--tenant-name", "T", "--tenant-id", "t-123", "--client-id", "constructed-app", *FAKE_CERTIFICATE_ARGS,
        "--collectors", "identity", "--out", str(root / "out"), "--run-name", "live",
        "--waiver-file", str(_waiver(root, "entra.mfa.users_not_registered")), *extra,
    ])
    monkeypatch.setattr(engine_cli, "GraphClient", _FakeClient)
    monkeypatch.setattr(engine_cli, "REGISTRY", {"identity": _Collector("identity", "ok")})
    use_fake_certificate(monkeypatch)
    return engine_cli.run_live(engine_cli.build_parser().parse_args(argv))


def test_a_mocked_live_microsoft_365_run_and_its_resume_write_no_absolute_local_path(
        operator_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert _m365_live(monkeypatch, operator_root) in (0, 1)
    run_dir = operator_root / "out" / "T-live"
    _assert_clean(run_dir, operator_root)
    assert _m365_live(monkeypatch, operator_root, "--resume-from", str(run_dir)) in (0, 1)
    _assert_clean(run_dir, operator_root)
    events = [json.loads(line) for line in (run_dir / "audit-log.jsonl").read_text(encoding="utf-8").splitlines()]
    resumed = [event["details"] for event in events if event["event"] == "run.resume"]
    assert resumed and all(details.get("resume_from") == run_dir.name for details in resumed)


def test_a_microsoft_365_probe_with_an_absolute_powershell_writes_no_absolute_local_path(
        operator_root: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    pwsh = _fake_pwsh(monkeypatch, operator_root)
    out = operator_root / "out"
    argv = _operator_argv(monkeypatch, operator_root, [
        "probe", "live", "--tenant-name", "T", "--run-name", "probe",
        "--tenant-id", "11111111-2222-3333-4444-555555555555", "--client-id", "11111111-2222-3333-4444-666666666666",
        "--certificate-path", str(operator_root / "inputs" / "reader.pem"),
        "--certificate-thumbprint", "A" * 40, "--out", str(out)])
    assert _run(argv, capsys) != 0
    run_dir = out / "T-probe"
    _assert_clean(run_dir, operator_root)
    readiness = json.loads((run_dir / "toolchain-readiness.json").read_text(encoding="utf-8"))
    commands = [row.get("command") for row in json.dumps(readiness) and _rows(readiness) if row.get("command")]
    assert commands and all(command.startswith("pwsh ") for command in commands), (pwsh, commands)


def _rows(payload: object) -> list[dict]:
    if isinstance(payload, dict):
        found = [payload] if "command" in payload else []
        return found + [row for value in payload.values() for row in _rows(value)]
    if isinstance(payload, list):
        return [row for value in payload for row in _rows(value)]
    return []


def test_an_offline_microsoft_365_replay_drops_a_lab_seed_path_from_its_provenance(
        operator_root: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    sample = json.loads(M365_SAMPLE.read_text(encoding="utf-8"))
    lab_seed = "/srv/lab-machine/tenant-bootstrap/runs/seed-0001"
    sample["_fixture_provenance"] = {"bootstrap_seed": {"run_dir": lab_seed, "seeded_at": "2026-11-01"}}
    sample_path = operator_root / "inputs" / "seeded.json"
    sample_path.write_text(json.dumps(sample), encoding="utf-8")
    out = operator_root / "out"
    argv = _operator_argv(monkeypatch, operator_root, [
        "run", "--offline", "--as-of", "2026-11-11", "--sample", str(sample_path), "--tenant-name", "T",
        "--run-name", "seeded", "--out", str(out)])
    assert _run(argv, capsys) in (0, 1)
    run_dir = out / "T-seeded"
    _assert_clean(run_dir, operator_root)
    assert _files_holding(run_dir, ("/srv/lab-machine",)) == []
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["fixture_provenance"]["bootstrap_seed"]["run_dir"] == "seed-0001"


def _library_file_error() -> tuple[str, type]:
    """A file error from inside the installed Google API client: its path is in Python's library folder."""
    import sysconfig

    library = sysconfig.get_paths()["purelib"]
    path = f"{library}/googleapiclient/discovery_cache/documents/admin.directory_v1.json"

    class _Client:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def __getattr__(self, name):
            if name == "for_scopes":  # the collector's narrowed client is this one
                return lambda *_args, **_kwargs: self

            def refuse(*_args, **_kwargs):
                raise PermissionError(13, "Permission denied", path)
            return refuse

    return library, _Client


@pytest.mark.parametrize("command", ["run", "probe"])
def test_a_google_library_file_error_writes_no_absolute_local_path(
        operator_root: Path, monkeypatch: pytest.MonkeyPatch, capsys, command: str) -> None:
    from auditex.google_workspace import run as google_run

    library, client = _library_file_error()
    monkeypatch.setattr(google_run, "google_dependency_status",
                        lambda: {"available": True, "missing": [], "install_hint": ""})
    monkeypatch.setattr(google_run, "build_google_credentials", lambda _config: object())
    monkeypatch.setattr(google_run, "GoogleWorkspaceClient", client)
    out = operator_root / "out"
    argv = _operator_argv(monkeypatch, operator_root, [
        "google", command, "--domain", "example.com", "--customer-id", "C123", "--tenant-name", "G",
        "--run-name", command, "--collectors", "google_directory", "--subject", "admin@example.com",
        "--service-account-key", str(operator_root / "inputs" / "sa.json"), "--out", str(out)])
    _run(argv, capsys)
    run_dir = out / f"G-{command}"
    _assert_clean(run_dir, operator_root)
    assert _files_holding(run_dir, (library,)) == []
    holding = _files_holding(run_dir, ("admin.directory_v1.json",))
    assert holding, "the error keeps the file name, so the operator can still see what failed"


# The normaliser itself: the three forms, Windows-style paths, and tenant paths it must leave alone.

def test_the_normaliser_makes_run_paths_relative_home_paths_tilde_and_others_a_bare_name() -> None:
    from azure_tenant_audit.local_paths import LocalPathScrubber

    scrub = LocalPathScrubber("/w/op place/out/T-run", home="/home/op", others=["/opt/tools"],
                              argv=["/x/auditex/__main__.py", "--out=/data/a b/out", "/srv/k.pem"])
    assert scrub("/w/op place/out/T-run") == "T-run"
    assert scrub({"f": ["/w/op place/out/T-run/raw/a.json"]}) == {"f": ["raw/a.json"]}
    assert scrub("/home/op/audits/waivers.json") == "~/audits/waivers.json"
    assert scrub("/opt/tools/bin/pwsh -NoLogo") == "pwsh -NoLogo"
    assert scrub("Permission denied: '/opt/tools/lib/x y/doc.json'") == "Permission denied: 'doc.json'"
    assert scrub("see /home/op/a.json.") == "see ~/a.json."
    assert scrub(["--out=/data/a b/out", "/srv/k.pem", "/x/auditex/__main__.py"]) == ["--out=out", "k.pem",
                                                                                      "__main__.py"]
    for tenant in ("/users/abc", "https://graph.microsoft.com/v1.0/users", "/tmpfoo", "/Library/Preferences/x",
                   "C:\\Temp\\exclusion", "/opt/toolsets/x"):
        assert scrub(tenant) == tenant


def test_the_normaliser_reads_windows_style_paths() -> None:
    from azure_tenant_audit.local_paths import LocalPathScrubber

    scrub = LocalPathScrubber("C:\\Profiles\\op\\out\\T-run", home="C:\\Profiles\\op", others=["D:\\tools"], argv=[])
    assert scrub("C:\\Profiles\\op\\out\\T-run\\raw\\a.json") == "raw/a.json"
    assert scrub("C:/Profiles/op/out/T-run") == "T-run"
    assert scrub("C:\\Profiles\\op\\inputs\\client.json") == "~/inputs/client.json"
    assert scrub("D:\\tools\\pwsh.exe -NoLogo") == "pwsh.exe -NoLogo"
    assert scrub("C:\\Temp\\exclusion") == "C:\\Temp\\exclusion"


# A PowerShell found at a system path (outside every folder the normaliser knows) is still recorded by name only.

SYSTEM_PWSH = "/usr/local/microsoft/powershell/7/pwsh"


def test_the_powershell_adapter_logs_the_executable_name_only(monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    from azure_tenant_audit.adapters.powershell_graph import PowerShellGraphAdapter

    events: list[dict] = []
    monkeypatch.setattr("shutil.which", lambda name: SYSTEM_PWSH if name == "pwsh" else None)
    monkeypatch.setattr("subprocess.run", lambda cmd, **_kw: subprocess.CompletedProcess(cmd, 0, "[]", ""))
    PowerShellGraphAdapter().run("Get-Mailbox", log_event=lambda _event, _message, details: events.append(details or {}))
    started = [details for details in events if "executable" in details]
    assert started and all(details["executable"] == "pwsh" for details in started)


def test_the_probe_records_powershell_checks_by_executable_name(monkeypatch: pytest.MonkeyPatch) -> None:
    from azure_tenant_audit import probe

    monkeypatch.setattr(probe.shutil, "which", lambda name: SYSTEM_PWSH if name == "pwsh" else None)
    monkeypatch.setattr(probe, "_subprocess_probe", lambda command, **_kw: (3, "", "module missing"))
    rows = probe._probe_toolchain_statuses(include_response=True, log_event=None)
    commands = [row["command"] for row in rows if row.get("command")]
    assert len(commands) == 2 and all(command.startswith("pwsh -NoLogo") for command in commands)
    assert SYSTEM_PWSH not in json.dumps(rows)
