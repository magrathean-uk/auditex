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


def test_create_app_requires_tenant_id(populator_config, directory):
    with pytest.raises(SystemExit) as exc:
        directory["module"].main(["--config", str(populator_config)])
    assert exc.value.code == 2
    assert directory["az"] == [] and directory["graph"] == []


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


def test_create_app_rejects_abbreviated_flags(populator_config, directory):
    with pytest.raises(SystemExit) as exc:
        directory["module"].main(["--config", str(populator_config), "--tenant-id", LAB_TENANT, "--create-s"])
    assert exc.value.code == 2
    assert directory["az"] == [] and directory["graph"] == []


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


GRAPH_SP_ID = "44444444-4444-4444-4444-444444444444"
APP_OBJECT_ID = "55555555-5555-5555-5555-555555555555"
APP_SP_ID = "66666666-6666-6666-6666-666666666666"
ROLE_ID = "77777777-7777-7777-7777-777777777777"
SCOPE_ID = "88888888-8888-8888-8888-888888888888"


class FakeGraphResponse:
    def __init__(self, status: int, body: dict | None = None) -> None:
        self.status_code = status
        self.ok = 200 <= status < 300
        self._body = body or {}
        self.text = json.dumps(self._body)

    def json(self) -> dict:
        return self._body


@pytest.fixture
def directory(monkeypatch):
    """A fake Azure CLI plus Graph in which the CLI default is OTHER_TENANT while every
    'az account show' answers LAB_TENANT: the context switch lands between check and use.
    Graph and 'az ad' writes are recorded with the tenant they would land in."""
    import requests

    state: dict = {"az": [], "graph": [], "org_override": None, "default": OTHER_TENANT, "token_fails": False}

    def run(argv, *args, **kwargs):
        argv = list(argv)
        state["az"].append(argv)
        joined = " ".join(argv)
        if joined.startswith("az account show"):
            return SimpleNamespace(returncode=0, stdout=LAB_TENANT + "\n", stderr="")
        if joined.startswith("az account get-access-token"):
            if state["token_fails"]:
                return SimpleNamespace(returncode=1, stdout="", stderr="no account in that tenant")
            tenant = argv[argv.index("--tenant") + 1] if "--tenant" in argv else state["default"]
            return SimpleNamespace(returncode=0, stdout=_token({"tid": tenant}) + "\n", stderr="")
        if joined.startswith("az ad app list"):
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

    def graph(session, method, url, json=None, timeout=None, **kwargs):  # noqa: A002
        method = method.upper()
        auth = str(session.headers.get("Authorization", ""))
        tid = _claims(auth.removeprefix("Bearer ").strip()).get("tid")
        state["graph"].append({"method": method, "url": url, "tid": tid, "json": json, "kwargs": kwargs})
        path = url.split("/v1.0", 1)[-1]
        if method == "GET":
            if path.startswith("/organization"):
                return FakeGraphResponse(200, {"value": [{"id": state["org_override"] or tid}]})
            if path.startswith("/servicePrincipals(appId="):
                return FakeGraphResponse(200, {
                    "id": GRAPH_SP_ID,
                    "appRoles": [{"value": "Directory.ReadWrite.All", "id": ROLE_ID, "allowedMemberTypes": ["Application"]}],
                    "oauth2PermissionScopes": [{"value": "User.Read", "id": SCOPE_ID}],
                })
            return FakeGraphResponse(200, {"value": []})
        if method == "POST" and path == "/applications":
            return FakeGraphResponse(201, {"id": APP_OBJECT_ID, "appId": APP_ID, "requiredResourceAccess": []})
        if method == "POST" and path == "/servicePrincipals":
            return FakeGraphResponse(201, {"id": APP_SP_ID, "appId": APP_ID})
        if method == "POST" and path.endswith("/addPassword"):
            return FakeGraphResponse(200, {"secretText": SECRET_VALUE, "endDateTime": "2027-01-01T00:00:00Z"})
        if method == "PATCH":
            return FakeGraphResponse(204)
        return FakeGraphResponse(201, {"id": "99999999-0000-0000-0000-000000000001"})

    module = load_module("create-lab-populator-app.py")
    monkeypatch.setattr(module.subprocess, "run", run)
    monkeypatch.setattr(requests.Session, "request", graph)
    state["module"] = module
    state["az_ad_writes"] = lambda: [a for a in state["az"] if a[:2] == ["az", "ad"] and a[3:4] != ["list"] and a[2:3] != ["sp"]]
    state["graph_writes"] = lambda: [c for c in state["graph"] if c["method"] != "GET"]
    return state


def _claims(token: str) -> dict:
    import base64

    parts = token.split(".")
    if len(parts) < 2:
        return {}
    try:
        return json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except ValueError:
        return {}


def test_create_app_writes_only_with_a_token_pinned_to_the_named_tenant(populator_config, directory):
    """No check-then-act window: every directory write carries a token issued for the named tenant,
    so an Azure CLI context switch at any moment cannot move a write to another tenant."""
    result = directory["module"].main([
        "--config", str(populator_config), "--tenant-id", LAB_TENANT, "--admin-consent", "--create-secret",
    ])
    assert directory["az_ad_writes"]() == []
    assert result == 0
    writes = directory["graph_writes"]()
    assert writes and all(call["tid"] == LAB_TENANT for call in writes)
    assert any(call["url"].endswith("/applications") for call in writes)
    token_calls = [a for a in directory["az"] if a[:3] == ["az", "account", "get-access-token"]]
    assert token_calls and all(a[a.index("--tenant") + 1] == LAB_TENANT for a in token_calls)


@pytest.mark.parametrize("problem", ["organization", "token"])
def test_create_app_refuses_an_unproven_tenant_before_any_directory_write(populator_config, directory, capsys, problem):
    if problem == "organization":
        directory["org_override"] = OTHER_TENANT
    else:
        directory["token_fails"] = True
    result = directory["module"].main([
        "--config", str(populator_config), "--tenant-id", LAB_TENANT, "--admin-consent", "--create-secret",
    ])
    assert result == 3
    assert ("tenant_mismatch" if problem == "organization" else "tenant_check_failed") in capsys.readouterr().err
    assert directory["graph_writes"]() == [] and directory["az_ad_writes"]() == []
    assert not (populator_config.parent.parent / ".secrets" / "lab-populator-app-secret.json").exists()


def test_create_app_appends_secret_and_stores_it_owner_only(populator_config, directory):
    result = directory["module"].main([
        "--config", str(populator_config), "--tenant-id", LAB_TENANT, "--create-secret",
    ])
    assert result == 0
    add = [c for c in directory["graph_writes"]() if c["url"].endswith("/addPassword")]
    assert add and add[0]["tid"] == LAB_TENANT
    assert not any(c["method"] == "POST" and "removePassword" in c["url"] for c in directory["graph"])
    secrets_dir = populator_config.parent.parent / ".secrets"
    secret_file = secrets_dir / "lab-populator-app-secret.json"
    assert json.loads(secret_file.read_text(encoding="utf-8"))["password"] == SECRET_VALUE
    assert mode(secret_file) == 0o600
    assert mode(secrets_dir) == 0o700


def test_create_app_tightens_existing_secret_file_and_folder(populator_config, directory):
    secrets_dir = populator_config.parent.parent / ".secrets"
    secrets_dir.mkdir(mode=0o755)
    secrets_dir.chmod(0o755)
    secret_file = secrets_dir / "lab-populator-app-secret.json"
    secret_file.write_text("{}", encoding="utf-8")
    secret_file.chmod(0o644)
    assert directory["module"].main(["--config", str(populator_config), "--tenant-id", LAB_TENANT, "--create-secret"]) == 0
    assert mode(secret_file) == 0o600
    assert mode(secrets_dir) == 0o700


def test_create_app_refuses_a_symlinked_secret_file_before_issuing_a_credential(populator_config, directory, tmp_path):
    secrets_dir = populator_config.parent.parent / ".secrets"
    secrets_dir.mkdir()
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_text("untouched", encoding="utf-8")
    (secrets_dir / "lab-populator-app-secret.json").symlink_to(elsewhere)
    result = directory["module"].main(["--config", str(populator_config), "--tenant-id", LAB_TENANT, "--create-secret"])
    assert result == 4
    assert directory["graph_writes"]() == []
    assert elsewhere.read_text(encoding="utf-8") == "untouched"


def test_create_app_grants_consent_for_the_configured_permissions_only_in_the_named_tenant(populator_config, directory):
    assert directory["module"].main([
        "--config", str(populator_config), "--tenant-id", LAB_TENANT, "--admin-consent",
    ]) == 0
    writes = directory["graph_writes"]()
    patch = [c for c in writes if c["method"] == "PATCH" and "/applications/" in c["url"]]
    assert patch
    graph_entry = [e for e in patch[0]["json"]["requiredResourceAccess"] if e["resourceAppId"] == "00000003-0000-0000-c000-000000000000"]
    assert {"id": ROLE_ID, "type": "Role"} in graph_entry[0]["resourceAccess"]
    roles = [c for c in writes if c["url"].endswith("/appRoleAssignedTo")]
    assert roles and roles[0]["json"]["appRoleId"] == ROLE_ID
    assert all(c["tid"] == LAB_TENANT and c["kwargs"].get("allow_redirects") is False for c in directory["graph"])


def test_create_app_dry_run_makes_no_tenant_call(populator_config, directory):
    assert directory["module"].main(["--config", str(populator_config), "--tenant-id", LAB_TENANT, "--dry-run", "--create-secret"]) == 0
    assert directory["az"] == [] and directory["graph"] == []


def test_a_failed_run_never_removes_a_secret_another_run_saved(populator_config, directory, monkeypatch):
    """Run 1 fails after its destination check; meanwhile run 2 saved its credential at the same path.
    Run 1's cleanup must leave run 2's file alone."""
    import requests

    secret_file = populator_config.parent.parent / ".secrets" / "lab-populator-app-secret.json"
    other_run = json.dumps({"password": "run-2-credential"})
    real_request = requests.Session.request

    def interleaved(session, method, url, *args, **kwargs):
        if method.upper() == "POST" and url.endswith("/applications"):
            secret_file.write_text(other_run, encoding="utf-8")
            return FakeGraphResponse(500)
        return real_request(session, method, url, *args, **kwargs)

    monkeypatch.setattr(requests.Session, "request", interleaved)
    with pytest.raises(RuntimeError):
        directory["module"].main(["--config", str(populator_config), "--tenant-id", LAB_TENANT, "--create-secret"])
    assert secret_file.exists(), "a failed run removed the credential another run had saved"
    assert secret_file.read_text(encoding="utf-8") == other_run
    assert sorted(path.name for path in secret_file.parent.iterdir()) == [secret_file.name]


def test_auth_never_changes_the_mode_of_a_folder_it_did_not_create(tmp_path, monkeypatch):
    module = load_module("auth-lab-populator.py")
    token = _token({"tid": LAB_TENANT})
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: SimpleNamespace(
        returncode=0, stdout=json.dumps({"accessToken": token}), stderr=""))
    work = tmp_path / "work"
    work.mkdir()
    work.chmod(0o755)
    monkeypatch.chdir(work)
    assert module.main([
        "--tenant-id", LAB_TENANT, "--out", "claims.json", "--write-env", "token.env",
    ]) == 0
    assert mode(work) == 0o755
    assert mode(work / "token.env") == 0o600
