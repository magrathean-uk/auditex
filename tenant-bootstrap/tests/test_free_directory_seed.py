from __future__ import annotations

import copy
import importlib.util
import json
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit
from uuid import UUID

import pytest
import requests


ROOT = Path(__file__).resolve().parents[1]
TENANT = "11111111-2222-3333-4444-555555555555"
DOMAIN = "freefixture.onmicrosoft.com"
PREFIX = "auditex-lab-unit"
TOKEN = "fake-token-only-for-unit-tests"
OLD_ID = "99999999-2222-3333-4444-555555555555"
PASSWORD = "Aa1!" + "x" * 36


@pytest.fixture
def seed(monkeypatch):
    spec = importlib.util.spec_from_file_location("seed_free_directory", ROOT / "scripts" / "seed-free-directory.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    def no_external_calls(*args, **kwargs):
        pytest.fail("A test attempted a real subprocess or network call")

    monkeypatch.setattr(module.subprocess, "run", no_external_calls)
    monkeypatch.setattr(module.requests.sessions.Session, "request", no_external_calls)
    return module


class Response:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code = status
        self.body = body if body is not None else {}
        self.headers = headers or {}

    def json(self):
        if isinstance(self.body, Exception):
            raise self.body
        return self.body

    def close(self):
        pass


class Session:
    def __init__(self, *, pages=None, post_failure=None, manifest_path=None):
        self.calls = []
        self.pages = pages or {}
        self.post_failure = post_failure
        self.manifest_path = manifest_path
        self.closed = False
        self.counter = 0
        self.default_pages = {
            "/organization": {"value": [{
                "id": TENANT,
                "verifiedDomains": [{"name": DOMAIN, "isInitial": True, "isDefault": True, "type": "Managed"}],
            }]},
            "/users": {"value": []}, "/groups": {"value": []},
            "/applications": {"value": []}, "/servicePrincipals": {"value": []},
        }

    def request(self, method, url, **kwargs):
        assert kwargs["allow_redirects"] is False
        assert kwargs["headers"]["Authorization"] == f"Bearer {TOKEN}"
        assert kwargs["timeout"] == 60
        assert url.startswith("https://graph.microsoft.com/v1.0/")
        path = urlsplit(url).path.removeprefix("/v1.0")
        self.calls.append((method, url, copy.deepcopy(kwargs.get("json"))))
        if self.manifest_path:
            data = json.loads(self.manifest_path.read_text())
            assert data["requests"][-1] == {
                **data["requests"][-1], "method": method, "path": path, "status": None, "outcome": "pending",
            }
            assert len(data["created"]) == self.counter
        if method == "GET":
            page = self.pages.get(url, self.pages.get(path, self.default_pages.get(path)))
            if page is None and path.endswith("/owners"):
                page = {"value": [
                    {"id": payload["@odata.id"].rsplit("/", 1)[1]}
                    for verb, reference_url, payload in self.calls
                    if verb == "POST" and urlsplit(reference_url).path == "/v1.0" + path + "/$ref"
                ]}
            if isinstance(page, Response):
                return page
            assert page is not None, f"Unexpected GET: {path}"
            return Response(body=page)
        assert method == "POST"
        if self.post_failure:
            failure = self.post_failure(self, path)
            if failure is not None:
                if isinstance(failure, BaseException):
                    raise failure
                return failure
        if path.endswith("/$ref"):
            return Response(204)
        assert path in {"/users", "/groups", "/applications", "/servicePrincipals"}
        self.counter += 1
        body = {"id": str(UUID(int=self.counter))}
        if path == "/applications":
            body["appId"] = str(UUID(int=1000 + self.counter))
        return Response(201, body)

    def close(self):
        self.closed = True


def arguments(output):
    return ["--tenant-id", TENANT, "--domain", DOMAIN, "--prefix", PREFIX, "--output-dir", str(output)]


def execute(seed, monkeypatch, tmp_path, session):
    output = tmp_path / "run"
    session.manifest_path = output / "manifest.json"
    monkeypatch.setattr(seed, "access_token", lambda tenant: TOKEN if tenant == TENANT else pytest.fail("Wrong tenant"))
    monkeypatch.setattr(seed.requests, "Session", lambda: session)
    result = seed.main([*arguments(output), "--execute"])
    return result, json.loads(session.manifest_path.read_text()), output


def existing_group(**changes):
    return {"id": OLD_ID, "displayName": "Existing group", "mailNickname": "old-group",
            "groupTypes": [], "assignedLicenses": [], **changes}


def test_default_plan_is_offline_private_and_does_not_generate_passwords(seed, monkeypatch, tmp_path):
    monkeypatch.setattr(seed, "random_password", lambda: pytest.fail("Password generated in offline plan"))
    monkeypatch.setattr(seed.requests, "Session", lambda: pytest.fail("Session created in offline plan"))
    output = tmp_path / "plan"
    assert seed.main(arguments(output)) == 0
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["mode"] == "plan" and manifest["state"] == "planned"
    assert manifest["complete"] is False and manifest["preflightComplete"] is False
    assert manifest["requests"] == manifest["created"] == []
    assert len(manifest["fixtures"]) == 14
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert stat.S_IMODE((output / "manifest.json").stat().st_mode) == 0o600
    original = (output / "manifest.json").read_bytes()
    assert seed.main(arguments(output)) == 1
    assert (output / "manifest.json").read_bytes() == original


@pytest.mark.parametrize("option,value", [
    ("--tenant-id", "not-a-uuid"), ("--tenant-id", "common"),
    ("--domain", "example.com"), ("--domain", "x.mail.onmicrosoft.com"),
    ("--domain", "x.onmicrosoft.com/elsewhere"),
    ("--prefix", "production"), ("--prefix", "auditex-lab-"),
    ("--prefix", "auditex-lab-upperCase"), ("--prefix", "auditex-lab-' or true"),
])
def test_arguments_reject_unsafe_or_ambiguous_values(seed, tmp_path, option, value):
    args = arguments(tmp_path / "invalid")
    args[args.index(option) + 1] = value
    with pytest.raises(SystemExit) as error:
        seed.main(args)
    assert error.value.code == 2
    assert not (tmp_path / "invalid").exists()


def test_token_command_pins_tenant_and_never_exposes_output(seed, monkeypatch, capsys):
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout=TOKEN + "\n", stderr="private-cli-diagnostic")

    monkeypatch.setattr(seed.subprocess, "run", run)
    assert seed.access_token(TENANT) == TOKEN
    argv, kwargs = calls[0]
    assert argv[:3] == ["az", "account", "get-access-token"]
    assert argv[argv.index("--tenant") + 1] == TENANT
    assert argv[argv.index("--resource") + 1] == "https://graph.microsoft.com"
    assert kwargs == {"check": False, "capture_output": True, "text": True, "timeout": 60}
    assert TOKEN not in " ".join(argv)
    monkeypatch.setattr(seed.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=1, stdout=TOKEN, stderr=TOKEN))
    with pytest.raises(seed.SeedError, match="^token_acquisition_failed$"):
        seed.access_token(TENANT)
    monkeypatch.setattr(seed.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(
        subprocess.TimeoutExpired("az", 60, output=TOKEN, stderr=TOKEN)
    ))
    with pytest.raises(seed.SeedError, match="^token_acquisition_failed$"):
        seed.access_token(TENANT)
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("organization,reason", [
    ({"id": OLD_ID, "verifiedDomains": [{"name": DOMAIN, "isVerified": True, "isInitial": True}]}, "tenant_mismatch"),
    ({"id": TENANT, "verifiedDomains": [{"name": DOMAIN, "isVerified": False, "isInitial": True}]}, "verified_initial_domain_required"),
    ({"id": TENANT, "verifiedDomains": [{"name": DOMAIN, "isVerified": True, "isInitial": False}]}, "verified_initial_domain_required"),
    ({"id": TENANT, "verifiedDomains": [{"name": "other.onmicrosoft.com", "isVerified": True, "isInitial": True}]}, "verified_initial_domain_required"),
])
def test_identity_mismatch_stops_before_writes(seed, monkeypatch, tmp_path, organization, reason):
    session = Session(pages={"/organization": {"value": [organization]}})
    result, manifest, _ = execute(seed, monkeypatch, tmp_path, session)
    assert result == 1 and manifest["error"] == reason and manifest["state"] == "failed"
    assert manifest["created"] == [] and manifest["preflightComplete"] is False
    assert all(method == "GET" for method, _, _ in session.calls)


@pytest.mark.parametrize("group,reason", [
    (existing_group(groupTypes=["DynamicMembership"], assignedLicenses=[{"skuId": OLD_ID}]), "licensed_dynamic_group_present"),
    (existing_group(groupTypes=["DynamicMembership"], assignedLicenses=[{"skuId": OLD_ID}], membershipRuleProcessingState="Paused"), "licensed_dynamic_group_present"),
    (existing_group(assignedLicenses=None), "incomplete_license_inspection"),
    (existing_group(groupTypes=None), "incomplete_license_inspection"),
])
def test_dynamic_licensing_or_incomplete_inspection_stops_before_writes(seed, monkeypatch, tmp_path, group, reason):
    next_url = seed.GRAPH_ROOT + "/groups?$skiptoken=second-page"
    session = Session(pages={
        "/groups": {"value": [], "@odata.nextLink": next_url}, next_url: {"value": [group]},
    })
    result, manifest, _ = execute(seed, monkeypatch, tmp_path, session)
    assert result == 1 and manifest["error"] == reason
    assert manifest["created"] == []
    assert all(method == "GET" for method, _, _ in session.calls)


@pytest.mark.parametrize("kind,item", [
    ("groups", existing_group(displayName=f"{PREFIX}-direct-members".upper())),
    ("groups", existing_group(mailNickname=f"{PREFIX}-empty")),
    ("users", {"id": OLD_ID, "displayName": "other", "mailNickname": "other", "userPrincipalName": f"{PREFIX}-user-01@{DOMAIN}".upper()}),
    ("users", {"id": OLD_ID, "displayName": f"{PREFIX}-user-04", "mailNickname": "other", "userPrincipalName": f"other@{DOMAIN}"}),
    ("applications", {"id": OLD_ID, "appId": OLD_ID, "displayName": f"{PREFIX}-app-ownerless"}),
    ("servicePrincipals", {"id": OLD_ID, "appId": OLD_ID, "displayName": f"{PREFIX}-app-owned"}),
])
def test_collision_in_any_collection_or_later_page_stops_before_writes(seed, monkeypatch, tmp_path, kind, item):
    next_url = f"{seed.GRAPH_ROOT}/{kind}?$skiptoken=next"
    session = Session(pages={
        f"/{kind}": {"value": [], "@odata.nextLink": next_url}, next_url: {"value": [item]},
    })
    result, manifest, _ = execute(seed, monkeypatch, tmp_path, session)
    assert result == 1 and manifest["error"] == "fixture_collision"
    assert manifest["created"] == [] and all(method == "GET" for method, _, _ in session.calls)


@pytest.mark.parametrize("next_url", [
    "https://attacker.example/v1.0/groups", "https://graph.microsoft.com.attacker.example/v1.0/groups",
    "https://graph.microsoft.com@attacker.example/v1.0/groups", "http://graph.microsoft.com/v1.0/groups",
    "https://graph.microsoft.com:443/v1.0/groups", "https://graph.microsoft.com/beta/groups",
    "//attacker.example/v1.0/groups", "https://graph.microsoft.com/v1.0/groups/../users",
    "https://graph.microsoft.com/v1.0/%67roups", "https://graph.microsoft.com/v1.0/users",
    "https://graph.microsoft.com/v1.0/groups#fragment", "https://graph.microsoft.com/v1.0/groups\n",
    "https://graph.microsoft.com/v1.0/groups?$select=id,displayName,mailNickname,groupTypes,assignedLicenses",
    42, "",
])
def test_unsafe_cross_collection_or_cyclic_pagination_never_receives_token(seed, monkeypatch, tmp_path, next_url):
    session = Session(pages={"/groups": {"value": [], "@odata.nextLink": next_url}})
    result, manifest, _ = execute(seed, monkeypatch, tmp_path, session)
    assert result == 1 and manifest["state"] == "failed"
    assert len(session.calls) == 2
    assert all(method == "GET" for method, _, _ in session.calls)


@pytest.mark.parametrize("location", ["https://attacker.example/stolen", "https://graph.microsoft.com/v1.0/groups", "/groups"])
def test_redirects_are_never_followed_even_on_graph_host(seed, monkeypatch, tmp_path, location):
    session = Session(pages={"/organization": Response(302, headers={"Location": location})})
    result, manifest, _ = execute(seed, monkeypatch, tmp_path, session)
    assert result == 1 and len(session.calls) == 1
    assert manifest["requests"][0]["status"] == 302
    assert manifest["created"] == []


def test_happy_path_creates_only_fixed_free_fixtures_and_new_connections(seed, monkeypatch, tmp_path, capsys):
    session = Session(pages={"/groups": {"value": [
        existing_group(groupTypes=["DynamicMembership"]),
        existing_group(id=str(UUID(int=2000)), assignedLicenses=[{"skuId": OLD_ID}]),
    ]}})
    result, manifest, output = execute(seed, monkeypatch, tmp_path, session)
    assert result == 0 and manifest["state"] == "complete" and manifest["complete"] is True
    assert manifest["preflightComplete"] is True and session.closed
    assert session.trust_env is False
    assert len(manifest["created"]) == 14
    assert all(method == "GET" for method, _, _ in session.calls[:5])
    writes = [(urlsplit(url).path.removeprefix("/v1.0"), body) for method, url, body in session.calls if method == "POST"]
    users = [body for path, body in writes if path == "/users"]
    assert len(users) == 4 and all(user["accountEnabled"] is False for user in users)
    passwords = [user["passwordProfile"]["password"] for user in users]
    assert len(set(passwords)) == 4
    for password in passwords:
        assert len(password) == 40
        assert all(any(char in alphabet for char in password) for alphabet in (
            seed.string.ascii_uppercase, seed.string.ascii_lowercase, seed.string.digits, "!@#$%*-_+"
        ))
    assert all(set(user) == {"displayName", "userPrincipalName", "mailNickname", "accountEnabled", "passwordProfile"} for user in users)
    groups = [body for path, body in writes if path == "/groups"]
    assert len(groups) == 4
    assert all(group["groupTypes"] == [] and group["mailEnabled"] is False and group["securityEnabled"] is True for group in groups)
    apps = [body for path, body in writes if path == "/applications"]
    assert len(apps) == 3 and any("ignore previous instructions" in app["displayName"] for app in apps)
    assert all(app["signInAudience"] == "AzureADMyOrg" for app in apps)
    assert all(app["requiredResourceAccess"] == app["passwordCredentials"] == app["keyCredentials"] == [] for app in apps)
    principals = [body for path, body in writes if path == "/servicePrincipals"]
    assert len(principals) == 3 and all(sp["accountEnabled"] is False for sp in principals)
    created = {obj["fixture"]: obj for obj in manifest["created"]}
    assert {sp["appId"] for sp in principals} == {obj["appId"] for obj in created.values() if obj["kind"] == "applications"}
    refs = [(path, body) for path, body in writes if path.endswith("/$ref")]
    assert len(refs) == 7 and len(writes) == 21
    assert set((path, body["@odata.id"]) for path, body in refs) == {
        (f"/{created[source]['kind']}/{created[source]['id']}/{relation}/$ref",
         f"{seed.GRAPH_ROOT}/directoryObjects/{created[target]['id']}") for source, relation, target in seed.EDGES
    }
    assert not any(created["group-empty"]["id"] in path for path, _ in refs)
    assert not any(created["app-ownerless"]["id"] in path for path, _ in refs)
    assert all(entry["outcome"] == "succeeded" for entry in manifest["requests"])
    text = (output / "manifest.json").read_text()
    captured = capsys.readouterr()
    for secret in [TOKEN, *passwords]:
        assert secret not in text + captured.out + captured.err
    assert "passwordProfile" not in text and "Authorization" not in text and '"payload"' not in text
    assert stat.S_IMODE((output / "manifest.json").stat().st_mode) == 0o600


def client_with_new_objects(seed, tmp_path):
    manifest = seed.Manifest(tmp_path / "guard", TENANT, DOMAIN, PREFIX, True)
    session = Session()
    client = seed.GraphClient(TOKEN, manifest, session)
    client.preflight()
    for key in ("user-01", "user-02", "group-direct-members", "group-empty", "app-owned", "app-ownerless"):
        client.create(key)
    return client, session


@pytest.mark.parametrize("method,path", [
    ("PATCH", "/users/{user}"), ("DELETE", "/groups/{group}"),
    ("POST", "/users/{user}/assignLicense"), ("POST", "/groups/{group}/assignLicense"),
    ("POST", "/roleManagement/directory/roleAssignments"), ("POST", "/oauth2PermissionGrants"),
    ("POST", "/applications/{app}/addPassword"), ("POST", "/subscriptions"),
    ("POST", "/invitations"), ("POST", "/teams"), ("POST", "/users/{user}/sendMail"),
    ("POST", "/$batch"), ("POST", "/groups?anything=1"),
    ("POST", "https://management.azure.com/subscriptions"),
])
def test_endpoint_allowlist_blocks_unrelated_writes(seed, tmp_path, method, path):
    client, session = client_with_new_objects(seed, tmp_path)
    path = path.format(user=client.created["user-01"]["id"], group=client.created["group-direct-members"]["id"], app=client.created["app-owned"]["id"])
    before = len(session.calls)
    with pytest.raises(seed.SeedError):
        client.request(method, path, payload={})
    assert len(session.calls) == before


@pytest.mark.parametrize("case", ["existing-source", "existing-target", "foreign-reference", "extra-field", "empty-group", "ownerless-app", "wrong-owner", "duplicate-edge"])
def test_references_allow_only_fixed_new_to_new_edges(seed, tmp_path, case):
    client, session = client_with_new_objects(seed, tmp_path)
    source = client.created["group-direct-members"]["id"]
    target = client.created["user-01"]["id"]
    path = f"/groups/{source}/members/$ref"
    body = {"@odata.id": f"{seed.GRAPH_ROOT}/directoryObjects/{target}"}
    if case == "existing-source":
        path = f"/groups/{OLD_ID}/members/$ref"
    elif case == "existing-target":
        body["@odata.id"] = f"{seed.GRAPH_ROOT}/directoryObjects/{OLD_ID}"
    elif case == "foreign-reference":
        body["@odata.id"] = f"https://attacker.example/v1.0/directoryObjects/{target}"
    elif case == "extra-field":
        body["other"] = "value"
    elif case == "empty-group":
        path = f"/groups/{client.created['group-empty']['id']}/members/$ref"
    elif case == "ownerless-app":
        path = f"/applications/{client.created['app-ownerless']['id']}/owners/$ref"
    elif case == "wrong-owner":
        path = f"/groups/{source}/owners/$ref"
    elif case == "duplicate-edge":
        client.request("POST", path, payload=body)
    before = len(session.calls)
    with pytest.raises(seed.SeedError, match="write_not_allowed"):
        client.request("POST", path, payload=body)
    assert len(session.calls) == before


@pytest.mark.parametrize("key,changes", [
    ("user-03", {"accountEnabled": True}),
    ("user-03", {"assignedLicenses": [{"skuId": OLD_ID}]}),
    ("group-nested-inner", {"groupTypes": ["DynamicMembership"]}),
    ("group-nested-inner", {"groupTypes": ["Unified"], "mailEnabled": True}),
    ("group-nested-inner", {"isAssignableToRole": True}),
    ("group-nested-inner", {"members@odata.bind": [f"https://graph.microsoft.com/v1.0/users/{OLD_ID}"]}),
    ("app-prompt-like", {"signInAudience": "AzureADMultipleOrgs"}),
    ("app-prompt-like", {"requiredResourceAccess": [{"resourceAppId": OLD_ID}]}),
    ("app-prompt-like", {"passwordCredentials": [{"displayName": "secret"}]}),
    ("sp-owned", {"appId": OLD_ID}),
    ("sp-owned", {"accountEnabled": True}),
])
def test_create_payload_allowlist_prevents_scope_expansion(seed, tmp_path, key, changes):
    client, session = client_with_new_objects(seed, tmp_path)
    body = client.payload(key)
    if key.startswith("user-"):
        body["passwordProfile"] = {"password": PASSWORD, "forceChangePasswordNextSignIn": True}
    body.update(changes)
    before = len(session.calls)
    with pytest.raises(seed.SeedError, match="write_not_allowed"):
        client.request("POST", "/" + client.plan[key]["kind"], payload=body)
    assert len(session.calls) == before


def test_creates_need_complete_preflight_and_cannot_be_repeated(seed, tmp_path):
    manifest = seed.Manifest(tmp_path / "guard", TENANT, DOMAIN, PREFIX, True)
    session = Session()
    client = seed.GraphClient(TOKEN, manifest, session)
    with pytest.raises(seed.SeedError, match="write_not_allowed"):
        client.create("group-empty")
    assert session.calls == []
    client.preflight()
    client.create("group-empty")
    before = len(session.calls)
    with pytest.raises(seed.SeedError, match="write_not_allowed"):
        client.create("group-empty")
    assert len(session.calls) == before


@pytest.mark.parametrize("failure", [
    requests.ConnectionError(f"private request content {TOKEN} {PASSWORD}"),
    Response(503, {"error": {"message": f"private {TOKEN} {PASSWORD}"}}),
    Response(429, {"error": {"message": TOKEN}}, {"Retry-After": "0"}),
    Response(201, ValueError(TOKEN)),
    Response(201, {"id": TOKEN}),
    KeyboardInterrupt(),
])
def test_uncertain_partial_failure_is_incremental_secret_free_and_not_retried(seed, monkeypatch, tmp_path, capsys, failure):
    monkeypatch.setattr(seed, "random_password", lambda: PASSWORD)
    session = Session(post_failure=lambda s, path: failure if s.counter == 1 else None)
    result, manifest, output = execute(seed, monkeypatch, tmp_path, session)
    assert result == 1 and manifest["state"] == "partial" and manifest["complete"] is False
    assert len(manifest["created"]) == 1
    assert sum(method == "POST" for method, _, _ in session.calls) == 2
    assert manifest["requests"][-1]["outcome"] == "outcome_unknown"
    assert manifest["requests"][-1]["fixture"] == "user-02"
    assert session.closed
    captured = capsys.readouterr()
    output_text = "".join(path.read_text() for path in output.iterdir())
    for secret in (TOKEN, PASSWORD, "private request content"):
        assert secret not in captured.out + captured.err + output_text


def test_application_id_is_saved_even_if_app_id_response_is_missing(seed, monkeypatch, tmp_path):
    session = Session(post_failure=lambda s, path: Response(201, {"id": str(UUID(int=9000))}) if path == "/applications" else None)
    result, manifest, _ = execute(seed, monkeypatch, tmp_path, session)
    assert result == 1 and manifest["error"] == "created_app_id_unknown"
    assert len(manifest["created"]) == 9
    assert manifest["created"][-1] == {"fixture": "app-owned", "kind": "applications", "id": str(UUID(int=9000))}
    assert manifest["state"] == "partial"


def test_implicit_existing_owner_is_reported_without_removing_or_modifying_it(seed, monkeypatch, tmp_path):
    path = f"/applications/{UUID(int=11)}/owners"
    session = Session(pages={path: {"value": [{"id": OLD_ID}]}})
    result, manifest, _ = execute(seed, monkeypatch, tmp_path, session)
    assert result == 1 and manifest["state"] == "partial"
    assert manifest["error"] == "unexpected_fixture_owners" and manifest["complete"] is False
    assert len(manifest["created"]) == 14
    assert sum(method == "POST" for method, _, _ in session.calls) == 21
    assert all(method in {"GET", "POST"} for method, _, _ in session.calls)
    assert not any(OLD_ID in url or OLD_ID in json.dumps(body) for method, url, body in session.calls)


def test_owner_inspection_is_restricted_to_created_objects(seed, tmp_path):
    client, session = client_with_new_objects(seed, tmp_path)
    before = len(session.calls)
    with pytest.raises(seed.SeedError, match="read_not_allowed"):
        client.request("GET", f"/applications/{OLD_ID}/owners?$select=id")
    assert len(session.calls) == before
