"""Lab populator app scripts: named-tenant check, credential handling and secret file modes."""
from __future__ import annotations

import importlib.util
import json
import shutil
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
LAB_TENANT = "11111111-1111-1111-1111-111111111111"
OTHER_TENANT = "99999999-9999-9999-9999-999999999999"
APP_ID = "33333333-3333-3333-3333-333333333333"
SECRET_VALUE = "lab-secret-value-for-tests"


def load_module(name: str):
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def _permissive_umask():
    """Run under the common 022 umask so file modes prove the scripts' own choices."""
    import os

    previous = os.umask(0o022)
    yield
    os.umask(previous)


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.fixture
def populator_config(tmp_path: Path) -> Path:
    configs = tmp_path / "configs"
    configs.mkdir()
    target = configs / "lab-populator-permissions.json"
    shutil.copy(ROOT / "configs" / "lab-populator-permissions.json", target)
    return target


@pytest.fixture
def fake_az(monkeypatch):
    """Answer az calls as a tenant whose id is state['tenant']; record every argv."""
    state = {"tenant": LAB_TENANT, "calls": []}

    def run(argv, *args, **kwargs):
        argv = list(argv)
        state["calls"].append(argv)
        joined = " ".join(argv)
        if joined.startswith("az account show"):
            out = state["tenant"] + "\n"
        elif joined.startswith("az ad app list"):
            out = ""
        elif joined.startswith("az ad app create") or joined.startswith("az ad app show"):
            out = json.dumps({"appId": APP_ID, "requiredResourceAccess": []})
        elif joined.startswith("az ad sp show"):
            out = json.dumps({"appRoles": [], "oauth2PermissionScopes": []})
        elif joined.startswith("az ad app credential reset"):
            out = json.dumps({"password": SECRET_VALUE, "endDateTime": "2027-01-01T00:00:00Z"})
        else:
            out = "{}"
        return SimpleNamespace(returncode=0, stdout=out, stderr="")

    module = load_module("create-lab-populator-app.py")
    monkeypatch.setattr(module.subprocess, "run", run)
    state["module"] = module
    return state


def test_create_app_requires_tenant_id(populator_config, fake_az):
    with pytest.raises(SystemExit) as exc:
        fake_az["module"].main(["--config", str(populator_config)])
    assert exc.value.code == 2
    assert fake_az["calls"] == []


def test_create_app_refuses_another_tenant_before_any_directory_call(populator_config, fake_az, capsys):
    fake_az["tenant"] = OTHER_TENANT
    result = fake_az["module"].main([
        "--config", str(populator_config), "--tenant-id", LAB_TENANT, "--admin-consent", "--create-secret",
    ])
    assert result != 0
    assert "tenant_mismatch" in capsys.readouterr().err
    assert [argv[:3] for argv in fake_az["calls"]] == [["az", "account", "show"]]


def test_create_app_refuses_placeholder_tenant(populator_config, fake_az):
    result = fake_az["module"].main([
        "--config", str(populator_config), "--tenant-id", "00000000-0000-0000-0000-000000000000",
    ])
    assert result != 0
    assert fake_az["calls"] == []


def test_create_app_appends_secret_and_stores_it_owner_only(populator_config, fake_az):
    result = fake_az["module"].main([
        "--config", str(populator_config), "--tenant-id", LAB_TENANT, "--create-secret",
    ])
    assert result == 0
    reset = [argv for argv in fake_az["calls"] if argv[:5] == ["az", "ad", "app", "credential", "reset"]]
    assert reset and "--append" in reset[0]
    secrets_dir = populator_config.parent.parent / ".secrets"
    secret_file = secrets_dir / "lab-populator-app-secret.json"
    assert json.loads(secret_file.read_text(encoding="utf-8"))["password"] == SECRET_VALUE
    assert mode(secret_file) == 0o600
    assert mode(secrets_dir) == 0o700


def test_create_app_tightens_existing_secret_file_and_folder(populator_config, fake_az):
    secrets_dir = populator_config.parent.parent / ".secrets"
    secrets_dir.mkdir(mode=0o755)
    secrets_dir.chmod(0o755)
    secret_file = secrets_dir / "lab-populator-app-secret.json"
    secret_file.write_text("{}", encoding="utf-8")
    secret_file.chmod(0o644)
    assert fake_az["module"].main(["--config", str(populator_config), "--tenant-id", LAB_TENANT, "--create-secret"]) == 0
    assert mode(secret_file) == 0o600
    assert mode(secrets_dir) == 0o700


def _token(claims: dict) -> str:
    import base64

    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"e30.{body}.sig"


def test_auth_app_secret_never_reaches_a_subprocess_argv(tmp_path, monkeypatch):
    module = load_module("auth-lab-populator.py")
    argvs: list[list[str]] = []
    posts: list[dict] = []

    def fake_run(argv, *args, **kwargs):
        argvs.append(list(argv))
        return SimpleNamespace(returncode=0, stdout=json.dumps({"access_token": _token({"tid": LAB_TENANT})}), stderr="")

    class FakeResponse:
        status_code = 200
        ok = True

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {"access_token": _token({"tid": LAB_TENANT}), "token_type": "Bearer"}

    def fake_post(url, data=None, timeout=None, **kwargs):
        posts.append({"url": url, "data": data, "timeout": timeout})
        return FakeResponse()

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    monkeypatch.setattr(module.requests, "post", fake_post, raising=False)
    secret_file = tmp_path / "secret.json"
    secret_file.write_text(json.dumps({"appId": APP_ID, "password": SECRET_VALUE, "tenantId": LAB_TENANT}), encoding="utf-8")
    result = module.main([
        "--app-secret-file", str(secret_file), "--out", str(tmp_path / "claims.json"),
    ])
    assert result == 0
    assert not any(SECRET_VALUE in arg or "client_secret=" in arg for argv in argvs for arg in argv)
    assert posts and posts[0]["data"]["client_secret"] == SECRET_VALUE and posts[0]["timeout"]


def test_auth_env_file_is_created_owner_only(tmp_path, monkeypatch):
    module = load_module("auth-lab-populator.py")
    token = _token({"tid": LAB_TENANT})
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: SimpleNamespace(
        returncode=0, stdout=json.dumps({"accessToken": token}), stderr=""))
    env_dir = tmp_path / ".secrets"
    env_file = env_dir / "lab-populator-token.env"
    import os

    opened: list[tuple[int, int]] = []
    real_open = os.open

    def spy_open(path, flags, mode_arg=0o777, *args, **kwargs):
        if Path(path) == env_file:
            opened.append((flags, mode_arg))
        return real_open(path, flags, mode_arg, *args, **kwargs)

    monkeypatch.setattr(os, "open", spy_open)
    assert module.main([
        "--tenant-id", LAB_TENANT, "--out", str(tmp_path / "claims.json"), "--write-env", str(env_file),
    ]) == 0
    assert env_file.read_text(encoding="utf-8") == f"AZURE_ACCESS_TOKEN={token}\n"
    assert mode(env_file) == 0o600
    assert mode(env_dir) == 0o700
    # Created owner-only from the first byte, never through a symlink.
    assert opened and all(m == 0o600 and flags & os.O_NOFOLLOW for flags, m in opened)


def test_create_app_refuses_when_the_az_tenant_changes_after_the_start_check(populator_config, fake_az, capsys):
    """Every az ad call checks the signed-in tenant again, so a later switch stops before any write."""
    module = fake_az["module"]
    real_run = module.subprocess.run
    seen_show = {"count": 0}

    def switching_run(argv, *args, **kwargs):
        result = real_run(argv, *args, **kwargs)
        if list(argv)[:3] == ["az", "account", "show"]:
            seen_show["count"] += 1
            if seen_show["count"] == 1:
                fake_az["tenant"] = OTHER_TENANT
        return result

    module.subprocess.run = switching_run
    result = module.main(["--config", str(populator_config), "--tenant-id", LAB_TENANT, "--admin-consent", "--create-secret"])
    assert result != 0
    assert "tenant_mismatch" in capsys.readouterr().err
    writes = [argv for argv in fake_az["calls"] if argv[:3] == ["az", "ad", "app"] and argv[3] != "list"]
    assert writes == []


def test_create_app_rejects_abbreviated_flags(populator_config, fake_az):
    with pytest.raises(SystemExit) as exc:
        fake_az["module"].main(["--config", str(populator_config), "--tenant-id", LAB_TENANT, "--create-s"])
    assert exc.value.code == 2
    assert fake_az["calls"] == []


def test_create_app_refuses_a_symlinked_secret_file_before_issuing_a_credential(populator_config, fake_az, tmp_path):
    secrets_dir = populator_config.parent.parent / ".secrets"
    secrets_dir.mkdir()
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_text("untouched", encoding="utf-8")
    (secrets_dir / "lab-populator-app-secret.json").symlink_to(elsewhere)
    result = fake_az["module"].main(["--config", str(populator_config), "--tenant-id", LAB_TENANT, "--create-secret"])
    assert result != 0
    assert not any(argv[:5] == ["az", "ad", "app", "credential", "reset"] for argv in fake_az["calls"])
    assert elsewhere.read_text(encoding="utf-8") == "untouched"


def test_auth_app_token_request_never_follows_a_redirect(tmp_path, monkeypatch):
    module = load_module("auth-lab-populator.py")
    posts: list[dict] = []

    class Redirect:
        status_code = 307
        ok = True
        is_redirect = True
        headers = {"Location": "https://elsewhere.example/token"}

        def json(self) -> dict:
            return {}

    def fake_post(url, data=None, timeout=None, **kwargs):
        posts.append({"url": url, **kwargs})
        return Redirect()

    monkeypatch.setattr(module.requests, "post", fake_post)
    secret_file = tmp_path / "secret.json"
    secret_file.write_text(json.dumps({"appId": APP_ID, "password": SECRET_VALUE, "tenantId": LAB_TENANT}), encoding="utf-8")
    with pytest.raises(RuntimeError):
        module.main(["--app-secret-file", str(secret_file), "--out", str(tmp_path / "claims.json")])
    assert len(posts) == 1 and posts[0].get("allow_redirects") is False


def test_auth_tightens_an_existing_secrets_folder(tmp_path, monkeypatch):
    module = load_module("auth-lab-populator.py")
    token = _token({"tid": LAB_TENANT})
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: SimpleNamespace(
        returncode=0, stdout=json.dumps({"accessToken": token}), stderr=""))
    env_dir = tmp_path / ".secrets"
    env_dir.mkdir()
    env_dir.chmod(0o755)
    assert module.main([
        "--tenant-id", LAB_TENANT, "--out", str(env_dir / "claims.json"), "--write-env", str(env_dir / "t.env"),
    ]) == 0
    assert mode(env_dir) == 0o700


def test_auth_rejects_abbreviated_flags(tmp_path):
    module = load_module("auth-lab-populator.py")
    with pytest.raises(SystemExit) as exc:
        module.main(["--app-secret", str(tmp_path / "x.json")])
    assert exc.value.code == 2
