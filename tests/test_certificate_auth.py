"""Certificate credentials for app-only tokens: loading, msal minting, refusals and secret hygiene.

Offline only: key material is generated per session by the conftest fixture, and the Entra token
endpoint is a fake msal http client that verifies each client assertion against the certificate.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import pickle
import time
from pathlib import Path

import jwt
import pytest

from azure_tenant_audit import certificate_auth
from azure_tenant_audit.certificate_auth import (
    CERTIFICATE_ERRORS,
    CertificateAuthError,
    CertificateCredential,
    load_certificate_credential,
    refuse_sources_in_output,
)
from azure_tenant_audit.config import AuthConfig
from azure_tenant_audit.graph import GraphClient, GraphError

TENANT = "constructed.onmicrosoft.com"
CLIENT_ID = "00000000-0000-0000-0000-0000000000c1"
TEAMS_SCOPE = "48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default"
EXCHANGE_SCOPE = "https://outlook.office365.com/.default"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
PASSWORD_ENV = "AUDITEX_TEST_CERTIFICATE_PASSWORD"
_PEM_MARKERS = ("PRIVATE KEY-----", "BEGIN ENCRYPTED")


def _b64(payload: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")


def constructed_token(scope: str, *, appidacr: str = "2") -> str:
    """A constructed (unsigned) access token whose claims match what Entra issues for a certificate."""
    audience = scope.removesuffix("/.default")
    return f"{_b64({'alg': 'none'})}.{_b64({'aud': audience, 'appidacr': appidacr, 'tid': TENANT})}.constructed"


class _Response:
    def __init__(self, status: int, body: dict) -> None:
        self.status_code = status
        self.text = json.dumps(body)
        self.headers: dict[str, str] = {}

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}: {self.text}")


class FakeEntra:
    """msal http client: OIDC discovery plus a token endpoint that checks every client assertion."""

    def __init__(self, material, *, fail_with: dict | None = None, expires_in: int = 3599) -> None:
        self.material = material
        self.fail_with = fail_with
        self.expires_in = expires_in
        self.discovery: list[str] = []
        self.token_requests: list[dict] = []
        self.assertion_headers: list[dict] = []

    def get(self, url, **kwargs):
        self.discovery.append(url)
        tenant = url.split("/")[3]
        base = f"https://login.microsoftonline.com/{tenant}"
        return _Response(200, {
            "authorization_endpoint": f"{base}/oauth2/v2.0/authorize",
            "token_endpoint": f"{base}/oauth2/v2.0/token",
            "issuer": f"{base}/v2.0",
        })

    def post(self, url, data=None, **kwargs):
        assert "client_secret" not in data
        assertion = data["client_assertion"]
        header = jwt.get_unverified_header(assertion)
        claims = jwt.decode(assertion, self.material.certificate.public_key(),
                            algorithms=[header["alg"]], audience=url)
        assert claims["iss"] == claims["sub"] == data["client_id"]
        self.assertion_headers.append(header)
        self.token_requests.append({"url": url, "scope": data["scope"], "grant_type": data["grant_type"]})
        if self.fail_with is not None:
            return _Response(401, self.fail_with)
        return _Response(200, {"access_token": constructed_token(data["scope"]),
                               "expires_in": self.expires_in, "token_type": "Bearer"})

    def close(self) -> None:
        return None


@pytest.fixture(autouse=True)
def no_key_material_in_diagnostics(caplog, capsys, certificate_material, monkeypatch):
    monkeypatch.delenv(PASSWORD_ENV, raising=False)
    caplog.set_level(logging.DEBUG)
    yield
    captured = capsys.readouterr()
    text = caplog.text + captured.out + captured.err
    for secret in (certificate_material.password, certificate_material.key_pem_text[40:120], *_PEM_MARKERS):
        assert secret not in text


@pytest.fixture
def entra(monkeypatch, certificate_material):
    fake = FakeEntra(certificate_material)
    real = certificate_auth.build_confidential_client

    def build(credential, **kwargs):
        kwargs["http_client"] = fake
        return real(credential, **kwargs)

    monkeypatch.setattr(certificate_auth, "build_confidential_client", build)
    return fake


def credential(material, path=None, **kwargs) -> CertificateCredential:
    return load_certificate_credential(path or material.pem, material.thumbprint, **kwargs)


def certificate_client(material, events=None, **auth) -> GraphClient:
    config = AuthConfig(tenant_id=TENANT, client_id=CLIENT_ID, certificate=credential(material), **auth)
    return GraphClient(config, audit_event=(lambda *event: events.append(event)) if events is not None else None)


# Loading -----------------------------------------------------------------------------------------

@pytest.mark.parametrize("source", ["pem", "pem_key_only", "pfx_plain"])
def test_loads_unencrypted_key_files(certificate_material, source):
    loaded = credential(certificate_material, getattr(certificate_material, source))
    assert loaded.thumbprint == certificate_material.thumbprint
    assert loaded.private_key.public_key().public_numbers() == certificate_material.key.public_key().public_numbers()


@pytest.mark.parametrize("source", ["pem_encrypted", "pfx"])
def test_password_environment_variable_is_consumed_once(certificate_material, monkeypatch, source):
    monkeypatch.setenv(PASSWORD_ENV, certificate_material.password)
    loaded = credential(certificate_material, getattr(certificate_material, source), password_env=PASSWORD_ENV)
    assert loaded.thumbprint == certificate_material.thumbprint
    # Removed, so PowerShell and any other child process never inherit it.
    assert PASSWORD_ENV not in os.environ


@pytest.mark.parametrize("source", ["pem_encrypted", "pfx"])
def test_password_file(certificate_material, source):
    loaded = credential(certificate_material, getattr(certificate_material, source),
                        password_file=certificate_material.password_file)
    assert loaded.thumbprint == certificate_material.thumbprint


def test_thumbprint_is_case_insensitive(certificate_material):
    loaded = load_certificate_credential(certificate_material.pem, certificate_material.thumbprint.lower())
    assert loaded.thumbprint == certificate_material.thumbprint


def _refused(code, call):
    with pytest.raises(CertificateAuthError) as caught:
        call()
    assert caught.value.error_code == code
    assert str(caught.value) == CERTIFICATE_ERRORS[code]
    # Raised outside any handler: no vendor exception or frame locals travel with it.
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    return caught.value


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o660])
def test_refuses_key_readable_by_others(certificate_material, tmp_path, mode):
    path = tmp_path / "shared.pem"
    path.write_bytes(certificate_material.pem.read_bytes())
    path.chmod(mode)
    error = _refused("certificate_file_refused", lambda: credential(certificate_material, path))
    assert str(path) not in str(error)


def test_refuses_directory_fifo_symlink_missing_and_oversized_key(certificate_material, tmp_path):
    fifo = tmp_path / "pipe.pem"
    os.mkfifo(fifo, 0o600)
    link = tmp_path / "link.pem"
    link.symlink_to(certificate_material.pem)
    big = tmp_path / "big.pem"
    big.write_bytes(b"-" * (certificate_material_limit() + 1))
    big.chmod(0o600)
    for path in (tmp_path, fifo, link, tmp_path / "missing.pem", big):
        _refused("certificate_file_refused", lambda path=path: credential(certificate_material, path))


def _private_copy(source: Path, target: Path) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(source.read_bytes())
    target.chmod(0o600)
    return target


@pytest.mark.parametrize("case", ["inside", "dotdot_spelling", "linked_parent", "hard_link", "file_symlink", "folder_symlink"])
def test_refuses_sources_inside_or_linked_from_an_output_root(certificate_material, tmp_path, case):
    out = tmp_path / "runs"
    run = out / "constructed-run1"
    run.mkdir(parents=True)
    outside = _private_copy(certificate_material.pem, tmp_path / "keys" / "key.pem")
    source = outside
    root = out
    if case == "inside":
        source = _private_copy(certificate_material.pem, run / "summary.json")
    elif case == "dotdot_spelling":
        _private_copy(certificate_material.pem, run / "raw" / "key.pem")
        source = tmp_path / "keys" / ".." / "runs" / "constructed-run1" / "raw" / "key.pem"
    elif case == "linked_parent":
        _private_copy(certificate_material.pem, run / "key.pem")
        (tmp_path / "alias").symlink_to(run, target_is_directory=True)
        source = tmp_path / "alias" / "key.pem"
    elif case == "hard_link":
        os.link(outside, run / "evidence.json")
    elif case == "file_symlink":
        (run / "raw").mkdir()
        (run / "raw" / "token.json").symlink_to(outside)
    else:
        (out / "keys-alias").symlink_to(outside.parent, target_is_directory=True)
    error = _refused("certificate_source_in_output", lambda: refuse_sources_in_output((source,), (root,)))
    assert str(source) not in str(error) and str(outside) not in str(error)


def test_password_file_and_resume_folder_are_checked_too(certificate_material, tmp_path):
    resume = tmp_path / "elsewhere" / "constructed-run1"
    password = _private_copy(certificate_material.password_file, resume / "summary.json")
    _refused("certificate_source_in_output", lambda: refuse_sources_in_output(
        (certificate_material.pem_encrypted, password), (tmp_path / "runs", resume)))


def test_sources_outside_every_root_pass_and_leave_the_files_alone(certificate_material, tmp_path):
    out = tmp_path / "runs"
    (out / "constructed-run1").mkdir(parents=True)
    key = _private_copy(certificate_material.pem, tmp_path / "keys" / "key.pem")
    before = key.read_bytes()
    refuse_sources_in_output((key, None, tmp_path / "keys" / "absent.txt"), (out, None, tmp_path / "not-yet"))
    (tmp_path / "keys" / "runs").mkdir()
    refuse_sources_in_output((key,), (tmp_path / "keys" / "runs",))
    assert key.read_bytes() == before


def certificate_material_limit() -> int:
    return certificate_auth.MAX_KEY_FILE_BYTES


@pytest.mark.parametrize("case", ["missing_env", "empty_env", "bad_env_name", "both", "group_readable_file", "empty_file"])
def test_refuses_unavailable_password(certificate_material, monkeypatch, tmp_path, case):
    kwargs: dict = {}
    if case == "missing_env":
        kwargs["password_env"] = PASSWORD_ENV
    elif case == "empty_env":
        monkeypatch.setenv(PASSWORD_ENV, "")
        kwargs["password_env"] = PASSWORD_ENV
    elif case == "bad_env_name":
        kwargs["password_env"] = "NOT A NAME"
    elif case == "both":
        monkeypatch.setenv(PASSWORD_ENV, certificate_material.password)
        kwargs.update(password_env=PASSWORD_ENV, password_file=certificate_material.password_file)
    else:
        path = tmp_path / "password.txt"
        path.write_text("" if case == "empty_file" else certificate_material.password)
        path.chmod(0o600 if case == "empty_file" else 0o640)
        kwargs["password_file"] = path
    _refused("certificate_password_unavailable",
             lambda: credential(certificate_material, certificate_material.pem_encrypted, **kwargs))


@pytest.mark.parametrize("case", ["wrong_password", "no_password", "password_for_plain_key", "small_key", "ec_key", "not_a_key"])
def test_refuses_unreadable_or_unsuitable_keys(certificate_material, monkeypatch, tmp_path, case):
    path, kwargs = certificate_material.pem_encrypted, {}
    if case == "wrong_password":
        monkeypatch.setenv(PASSWORD_ENV, "constructed-wrong-password")
        kwargs["password_env"] = PASSWORD_ENV
    elif case == "password_for_plain_key":
        path = certificate_material.pem
        kwargs["password_file"] = certificate_material.password_file
    elif case == "small_key":
        path = certificate_material.pem_small
    elif case == "ec_key":
        path = certificate_material.pem_ec
    elif case == "not_a_key":
        path = tmp_path / "junk.pfx"
        path.write_bytes(b"constructed junk that is neither PEM nor PFX")
        path.chmod(0o600)
    _refused("certificate_key_unreadable", lambda: credential(certificate_material, path, **kwargs))


@pytest.mark.parametrize("thumbprint", ["", "abc", "Z" * 40, "A" * 64, None])
def test_refuses_malformed_thumbprint(certificate_material, thumbprint):
    _refused("certificate_thumbprint_invalid",
             lambda: load_certificate_credential(certificate_material.pem, thumbprint))


def test_refuses_thumbprint_or_certificate_mismatch(certificate_material):
    wrong = "0" * 40
    for path, thumbprint in ((certificate_material.pem, wrong), (certificate_material.pfx_plain, wrong),
                             (certificate_material.pem_other_cert, certificate_material.thumbprint)):
        _refused("certificate_thumbprint_mismatch", lambda p=path, t=thumbprint: load_certificate_credential(p, t))


def test_refuses_expired_certificate(certificate_material):
    _refused("certificate_not_valid", lambda: load_certificate_credential(
        certificate_material.pem_expired, certificate_material.expired_thumbprint))


def test_credential_never_renders_or_serialises_the_key(certificate_material):
    loaded = credential(certificate_material)
    config = AuthConfig(tenant_id=TENANT, client_id=CLIENT_ID, certificate=loaded)
    for text in (repr(loaded), str(loaded), repr(config), repr(GraphClient(config))):
        assert "PRIVATE" not in text and certificate_material.thumbprint not in text
    with pytest.raises(TypeError):
        pickle.dumps(loaded)


# Mixed credentials -------------------------------------------------------------------------------

@pytest.mark.parametrize("client_id", [None, " ", ""])
def test_certificate_needs_the_reader_app_client_id(certificate_material, client_id):
    with pytest.raises(ValueError) as caught:
        AuthConfig(tenant_id=TENANT, client_id=client_id, certificate=credential(certificate_material))
    assert "client ID" in str(caught.value)


@pytest.mark.parametrize("removed", ["client_secret", "access_token", "auth_mode", "interactive_scopes"])
def test_auth_config_has_no_other_credential(certificate_material, removed):
    with pytest.raises(TypeError):
        AuthConfig(tenant_id=TENANT, client_id=CLIENT_ID, certificate=credential(certificate_material),
                   **{removed: "constructed"})


# Minting through msal ----------------------------------------------------------------------------

def test_every_app_token_is_minted_from_the_certificate_through_msal(certificate_material, entra):
    events: list[tuple] = []
    client = certificate_client(certificate_material, events)
    graph = client.ensure_token()
    teams = client.app_token_for(TEAMS_SCOPE)
    exchange = client.app_token_for(EXCHANGE_SCOPE)
    assert [request["scope"] for request in entra.token_requests] == [GRAPH_SCOPE, TEAMS_SCOPE, EXCHANGE_SCOPE]
    assert all(request["grant_type"] == "client_credentials" for request in entra.token_requests)
    assert {request["url"] for request in entra.token_requests} == {
        f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"}
    # The assertion names the certificate by its SHA-1 thumbprint (x5t), signed with the key.
    expected_x5t = base64.urlsafe_b64encode(bytes.fromhex(certificate_material.thumbprint)).decode().rstrip("=")
    assert {header["x5t"].rstrip("=") for header in entra.assertion_headers} == {expected_x5t}
    from azure_tenant_audit.adapters.teams_admin_rest import certificate_token

    assert certificate_token(teams)
    assert graph and exchange and len({graph, teams, exchange}) == 3
    names = [event[0] for event in events]
    assert names.count("graph.token.requested") == names.count("graph.token.succeeded") == 3
    assert all(event[2]["mode"] == "certificate" for event in events)
    rendered = json.dumps(events)
    for token in (graph, teams, exchange):
        assert token not in rendered
    assert "assertion" not in rendered and certificate_material.thumbprint not in rendered


def test_tokens_are_cached_until_their_refresh_deadline(certificate_material, entra, monkeypatch):
    client = certificate_client(certificate_material)
    first = client.app_token_for(TEAMS_SCOPE)
    assert client.app_token_for(TEAMS_SCOPE) == first
    client.ensure_token()
    client.ensure_token()
    assert len(entra.token_requests) == 2
    later = time.monotonic() + entra.expires_in
    monkeypatch.setattr("azure_tenant_audit.graph.time.monotonic", lambda: later)
    client.app_token_for(TEAMS_SCOPE)
    client.ensure_token()
    # msal's own in-memory cache may answer; no token is ever written to disk by this path.
    assert client._certificate_tokens[TEAMS_SCOPE][1] > later


def test_token_endpoint_refusal_is_a_fixed_error_without_the_body(certificate_material, monkeypatch):
    canary = "constructed-diagnostic-canary-zz9"
    fake = FakeEntra(certificate_material, fail_with={
        "error": "invalid_client", "error_description": f"AADSTS700027: {canary}"})
    real = certificate_auth.build_confidential_client
    monkeypatch.setattr(certificate_auth, "build_confidential_client",
                        lambda credential, **kwargs: real(credential, **{**kwargs, "http_client": fake}))
    events: list[tuple] = []
    client = certificate_client(certificate_material, events)
    assert client.app_token_for(TEAMS_SCOPE) is None
    assert client.app_token_for(EXCHANGE_SCOPE) is None
    with pytest.raises(GraphError) as caught:
        client.ensure_token()
    assert str(caught.value) == CERTIFICATE_ERRORS["certificate_token_failed"]
    assert caught.value.error_code == "certificate_token_failed"
    assert caught.value.__context__ is None
    failed = [event for event in events if event[0] == "graph.token.failed"]
    assert len(failed) == 3 and {event[2]["error_code"] for event in failed} == {"invalid_client"}
    assert canary not in json.dumps(events) + str(caught.value)


@pytest.mark.parametrize("authority", ["https://login.example.test/", "http://login.microsoftonline.com/",
                                       "https://login.microsoftonline.com/tenant/", "https://login.microsoftonline.com:8443/"])
def test_assertion_goes_only_to_an_entra_authority(certificate_material, entra, authority):
    client = certificate_client(certificate_material, authority=authority)
    assert client.app_token_for(TEAMS_SCOPE) is None
    with pytest.raises(GraphError) as caught:
        client.ensure_token()
    assert caught.value.error_code == "certificate_authority_refused"
    assert entra.discovery == [] and entra.token_requests == []


def test_msal_exception_text_never_escapes(certificate_material, monkeypatch):
    canary = "constructed-msal-canary-zz9"

    class Broken:
        def acquire_token_for_client(self, scopes):
            raise RuntimeError(canary)

    monkeypatch.setattr(certificate_auth, "build_confidential_client", lambda *a, **k: Broken())
    events: list[tuple] = []
    client = certificate_client(certificate_material, events)
    with pytest.raises(GraphError) as caught:
        client.ensure_token()
    assert canary not in str(caught.value) + json.dumps(events)
    assert caught.value.__context__ is None and caught.value.__cause__ is None


# Without the certificate there is no token -------------------------------------------------------

class _NoTokenSession:
    def __init__(self) -> None:
        self.posts: list[dict] = []

    def post(self, url, data=None, timeout=None):
        self.posts.append(dict(data or {}))
        raise AssertionError("no token request without the certificate")


@pytest.mark.parametrize("scope", [GRAPH_SCOPE, TEAMS_SCOPE, EXCHANGE_SCOPE,
                                   "https://contoso-admin.sharepoint.com/.default"])
def test_a_client_without_the_certificate_mints_no_token(scope):
    session = _NoTokenSession()
    client = GraphClient(AuthConfig(tenant_id=TENANT, client_id=CLIENT_ID), session=session)
    assert client.app_token_for(scope) is None
    with pytest.raises(GraphError) as caught:
        client.ensure_token()
    assert caught.value.error_code == "certificate_required"
    assert "reader app with a certificate" in str(caught.value)
    assert session.posts == []


def test_password_file_and_key_paths_stay_out_of_the_module_state(certificate_material):
    loaded = credential(certificate_material, certificate_material.pem_encrypted,
                        password_file=certificate_material.password_file)
    state = json.dumps({key: repr(value) for key, value in vars(loaded).items()}, default=str)
    assert str(certificate_material.root) not in state and certificate_material.password not in state
    assert not any(Path(certificate_material.root).glob("*.tmp"))


SHAREPOINT_ADMIN_ORIGIN = "https://contoso-admin.sharepoint.com"


def test_the_sharepoint_admin_token_is_minted_from_the_certificate(certificate_material, entra):
    from azure_tenant_audit.collectors.sharepoint_admin import token_fits

    client = certificate_client(certificate_material)
    token = client.app_token_for(SHAREPOINT_ADMIN_ORIGIN + "/.default")
    assert [request["scope"] for request in entra.token_requests] == [SHAREPOINT_ADMIN_ORIGIN + "/.default"]
    assert entra.token_requests[0]["grant_type"] == "client_credentials"
    assert token_fits(token, SHAREPOINT_ADMIN_ORIGIN)


# ---- bot review wave 2 (item 14): a malformed authority is the fixed refusal, never urllib's ValueError ------------


@pytest.mark.parametrize("authority", ["https://login.microsoftonline.com:abc/", "https://login.microsoftonline.com:99999/",
                                       "https://[login.microsoftonline.com/", "https://login.microsoftonline.com]/"])
def test_malformed_authority_is_the_fixed_refusal(authority):
    with pytest.raises(CertificateAuthError) as caught:
        certificate_auth.certificate_authority(authority, TENANT)
    assert caught.value.error_code == "certificate_authority_refused"
    assert caught.value.__cause__ is None and caught.value.__context__ is None


@pytest.mark.parametrize("host", sorted(certificate_auth.CERTIFICATE_AUTHORITY_HOSTS))
def test_every_entra_authority_is_still_accepted(host):
    assert certificate_auth.certificate_authority(f"https://{host}/", TENANT) == f"https://{host}/{TENANT}"


def test_malformed_authority_port_stops_the_engine_before_the_run_folder(monkeypatch, tmp_path, caplog):
    from support import FAKE_CERTIFICATE_ARGS, use_fake_certificate

    from azure_tenant_audit import cli

    use_fake_certificate(monkeypatch)
    monkeypatch.setenv("AZURE_AUTHORITY", "https://login.microsoftonline.com:private-marker/")
    monkeypatch.setattr(cli, "GraphClient", lambda *_a, **_k: pytest.fail("no client"))
    out = tmp_path / "out"
    args = cli.build_parser().parse_args([
        "--tenant-name", "acme", "--tenant-id", TENANT, "--client-id", CLIENT_ID, *FAKE_CERTIFICATE_ARGS, "--out", str(out),
    ])
    with caplog.at_level("INFO"):
        assert cli.run_live(args) == 2
    assert "private-marker" not in caplog.text
    assert not out.exists()
