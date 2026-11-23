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
    assert manifest["waiver_path"] == "waivers.json"


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
