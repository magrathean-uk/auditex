"""Entirely synthetic certificate tests: keys/PFX/assertions exist in memory only."""
from __future__ import annotations

import base64
import http.client
import json
import logging
import time
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from azure_tenant_audit import certificate_auth, keychain_signing
from azure_tenant_audit.certificate_auth import (
    CertificateAuthError, KeychainCertificate, PfxCertificate, client_assertion,
)
from azure_tenant_audit.config import AuthConfig
from azure_tenant_audit.graph import GraphClient
from azure_tenant_audit.auth_runtime import scrub_command_line
from azure_tenant_audit.secret_hygiene import deep_sanitize, redact_argv, redact_text


TEAMS_SCOPE = "48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default"
TOKEN_URL = "https://login.microsoftonline.com/test-only-tenant/oauth2/v2.0/token"
PASSWORD = b"throwaway-test-only-password"


def _decode(segment):
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


def _encode(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()


def _access_token(**overrides):
    # Deliberately synthetic unsigned token, consumed only by mocked transports.
    return _encode({"alg": "none"}) + "." + _encode({
        "aud": TEAMS_SCOPE.removesuffix("/.default"), "azpacr": "2",
        "exp": int(time.time()) + 600, **overrides,
    }) + ".test-only-not-a-signature"


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("A certificate test attempted an unmocked transport.")
    monkeypatch.setattr(requests.Session, "request", forbidden)
    # Real keychain access is forbidden in this test module too.
    monkeypatch.setattr(keychain_signing, "_Security", forbidden)


@pytest.fixture(scope="module")
def material():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "throwaway-test-only")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
            .sign(key, hashes.SHA256()))
    return key, cert


def _pfx(monkeypatch, material, *, key_present=True):
    key, cert = material
    raw = pkcs12.serialize_key_and_certificates(
        b"throwaway-test-only", key if key_present else None, cert, None,
        serialization.BestAvailableEncryption(PASSWORD),
    )
    def read_bytes(path):
        assert str(path) == "test-only-memory.pfx"
        return raw
    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    return PfxCertificate("test-only-memory.pfx", password_provider=lambda: PASSWORD)


def _client(credential, post, **kwargs):
    events = []
    client = GraphClient(AuthConfig("test-only-tenant", "test-only-app", certificate=credential, **kwargs),
                         audit_event=lambda *event: events.append(event))
    client.session.post = post
    return client, events


class Response:
    def __init__(self, status=200, token=None, expires_in=600):
        self.status_code = status
        self.token = token or _access_token()
        self.expires_in = expires_in
        self.closed = False

    def json(self):
        return {"access_token": self.token, "expires_in": self.expires_in}

    def close(self):
        self.closed = True


def _verify_assertion(assertion, public, audience=TOKEN_URL):
    header, payload, signature = assertion.split(".")
    public.verify(base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)),
                  (header + "." + payload).encode(), padding.PKCS1v15(), hashes.SHA256())
    claims = _decode(payload)
    assert claims["aud"] == audience
    assert claims["iss"] == claims["sub"] == "test-only-app"
    assert claims["nbf"] <= int(time.time()) < claims["exp"]
    assert claims["exp"] - claims["iat"] == 300
    assert claims["jti"]
    return _decode(header), claims


@pytest.mark.parametrize("password_source", ["callable", "env"])
def test_pfx_success_and_teams_reader_contract(monkeypatch, material, password_source):
    credential = _pfx(monkeypatch, material)
    if password_source == "env":
        monkeypatch.setenv("TEST_ONLY_PFX_PASSWORD", PASSWORD.decode())
        credential = PfxCertificate("test-only-memory.pfx", password_env="TEST_ONLY_PFX_PASSWORD")
    response = Response()
    def post(url, *, data, timeout, allow_redirects):
        assert url == TOKEN_URL and timeout == 60 and allow_redirects is False
        assert data["scope"] == TEAMS_SCOPE
        assert data["grant_type"] == "client_credentials"
        assert data["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        assert "client_secret" not in data
        header, _ = _verify_assertion(data["client_assertion"], material[0].public_key())
        assert header == {"alg": "RS256", "typ": "JWT", "x5t#S256":
                          base64.urlsafe_b64encode(material[1].fingerprint(hashes.SHA256())).rstrip(b"=").decode()}
        return response
    client, events = _client(credential, post)
    token = client.app_token_for(TEAMS_SCOPE)
    # These are the precise reader gates inspected in collect-teams-3's
    # certificate_token(): aud, certificate marker '2', and absence of scp.
    claims = _decode(token.split(".")[1])
    assert claims.get("azpacr", claims.get("appidacr")) == "2"
    assert claims["aud"] == TEAMS_SCOPE.removesuffix("/.default")
    assert not claims.get("scp")
    assert response.closed
    assert [event[0] for event in events] == ["graph.token.requested", "graph.token.succeeded"]


def test_certificate_cache_reuses_graph_and_resource_tokens(monkeypatch, material, caplog):
    credential = _pfx(monkeypatch, material)
    assertions, scopes = [], []
    def post(url, *, data, **kwargs):
        assertions.append(data["client_assertion"])
        scopes.append(data["scope"])
        return Response(token="test-only-opaque-graph-token") if data["scope"] != TEAMS_SCOPE else Response()
    client, events = _client(credential, post, throttle_mode="fast")
    client.session.request = lambda *a, **k: SimpleNamespace(status_code=200, text="{}", json=lambda: {})
    caplog.set_level(logging.DEBUG)
    assert client.get_json("/users") == {}
    assert client.get_json("/groups") == {}
    assert client.app_token_for(client.auth.graph_scope) == "test-only-opaque-graph-token"
    token = client.app_token_for(TEAMS_SCOPE)
    assert client.app_token_for(TEAMS_SCOPE) == token
    assert scopes == [client.auth.graph_scope, TEAMS_SCOPE]
    assert client._token == "test-only-opaque-graph-token"
    assert _decode(assertions[0].split(".")[1])["jti"] != _decode(assertions[1].split(".")[1])["jti"]
    rendered = repr(client) + repr(events) + caplog.text
    assert "test-only-opaque-graph-token" not in rendered and token not in rendered
    assert "_certificate_tokens" not in repr(client)
    assert all(assertion not in rendered for assertion in assertions)


@pytest.mark.parametrize("scope", ["https://graph.microsoft.com/.default", TEAMS_SCOPE])
@pytest.mark.parametrize("elapsed", [540, 601])
def test_certificate_cache_refreshes_before_or_after_expiry(monkeypatch, material, scope, elapsed):
    clock = [1000.0]
    monkeypatch.setattr("azure_tenant_audit.graph.time.monotonic", lambda: clock[0])
    assertions = []
    def post(url, *, data, **kwargs):
        assertions.append(data["client_assertion"])
        return Response(token=_access_token(test_only_generation=len(assertions)))
    client, _ = _client(_pfx(monkeypatch, material), post)
    acquire = client.ensure_token if scope == client.auth.graph_scope else lambda: client.app_token_for(scope)
    first = acquire()
    clock[0] += 539
    assert acquire() == first
    clock[0] = 1000.0 + elapsed
    assert acquire() != first
    assert len(assertions) == 2
    assert _decode(assertions[0].split(".")[1])["jti"] != _decode(assertions[1].split(".")[1])["jti"]


def test_certificate_cache_invalidated_on_401(monkeypatch, material):
    requests_seen = []
    def post(*args, **kwargs):
        requests_seen.append(kwargs["data"]["scope"])
        return Response()
    client, _ = _client(_pfx(monkeypatch, material), post, throttle_mode="fast")
    client.app_token_for(TEAMS_SCOPE)
    client.session.request = lambda *a, **k: SimpleNamespace(status_code=401, text="{}")
    assert client._request("GET", "https://graph.microsoft.com/v1.0/users").status_code == 401
    assert not client._certificate_tokens and client._token is None and client._token_claims is None
    client.ensure_token()
    client.app_token_for(TEAMS_SCOPE)
    assert requests_seen == [TEAMS_SCOPE, client.auth.graph_scope, client.auth.graph_scope, TEAMS_SCOPE]


def test_failed_cache_fill_discards_tokens_and_rechecks_teams_claims(monkeypatch, material):
    requests_seen = []
    clock = [1000.0]
    monkeypatch.setattr("azure_tenant_audit.graph.time.monotonic", lambda: clock[0])
    def post(*args, **kwargs):
        requests_seen.append(kwargs["data"]["scope"])
        return Response(token=_access_token(azpacr="1") if len(requests_seen) == 3 else _access_token())
    client, _ = _client(_pfx(monkeypatch, material), post)
    client.app_token_for(TEAMS_SCOPE)
    clock[0] += 540
    client.ensure_token()
    with pytest.raises(CertificateAuthError):
        client.app_token_for(TEAMS_SCOPE)
    assert not client._certificate_tokens and client._token is None and client._token_claims is None
    client.app_token_for(TEAMS_SCOPE)
    assert requests_seen == [TEAMS_SCOPE, client.auth.graph_scope, TEAMS_SCOPE, TEAMS_SCOPE]


@pytest.mark.parametrize("case", ["password", "missing_key", "missing_file", "missing_env", "provider_failure"])
def test_pfx_failures_are_typed_and_secret_free(monkeypatch, material, caplog, case):
    credential = _pfx(monkeypatch, material, key_present=case != "missing_key")
    if case == "password":
        credential = PfxCertificate("test-only-memory.pfx", password_provider=lambda: b"test-only-wrong-password")
    elif case == "missing_file":
        def missing(path):
            raise OSError(PASSWORD.decode())
        monkeypatch.setattr(Path, "read_bytes", missing)
    elif case == "missing_env":
        monkeypatch.delenv("TEST_ONLY_MISSING_PASSWORD", raising=False)
        credential = PfxCertificate("test-only-memory.pfx", password_env="TEST_ONLY_MISSING_PASSWORD")
    elif case == "provider_failure":
        def provider():
            raise ValueError(PASSWORD.decode())
        credential = PfxCertificate("test-only-memory.pfx", password_provider=provider)
    def forbidden(*args, **kwargs):
        pytest.fail("Failed PFX must not reach a token endpoint.")
    client, events = _client(credential, forbidden)
    with pytest.raises(CertificateAuthError) as caught:
        client.app_token_for(TEAMS_SCOPE)
    assert caught.value.__context__ is None and caught.value.__cause__ is None
    rendered = "".join(traceback.format_exception(caught.value)) + caplog.text + repr(events) + repr(client) + repr(credential)
    assert PASSWORD.decode() not in rendered
    assert "test-only-memory.pfx" not in rendered
    assert caught.value.error_code == "certificate_auth_failed"


@pytest.mark.parametrize("rejection", ["expired", "audience"])
def test_mock_endpoint_rejects_invalid_assertion(monkeypatch, material, rejection):
    credential = _pfx(monkeypatch, material)
    real_assertion = certificate_auth.client_assertion
    def invalid(*args):
        assertion = real_assertion(*args)
        header, payload, _ = assertion.split(".")
        claims = _decode(payload)
        claims.update({"exp": 1} if rejection == "expired" else {"aud": "https://wrong.test/token"})
        message = (header + "." + _encode(claims)).encode()
        signature = material[0].sign(message, padding.PKCS1v15(), hashes.SHA256())
        return message.decode() + "." + base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    monkeypatch.setattr("azure_tenant_audit.graph.client_assertion", invalid)
    captured = []
    def post(url, *, data, **kwargs):
        captured.append((url, _decode(data["client_assertion"].split(".")[1])))
        return Response(status=400)
    client, _ = _client(credential, post)
    with pytest.raises(CertificateAuthError):
        client.app_token_for(TEAMS_SCOPE)
    assert len(captured) == 1
    url, claims = captured[0]
    if rejection == "expired":
        assert claims["exp"] < time.time()
    else:
        assert claims["aud"] != url


@pytest.mark.parametrize("overrides", [
    {"aud": "wrong"}, {"exp": 1}, {"azpacr": "1"}, {"azpacr": "2", "scp": "test-only-scope"},
    *({"exp": value} for value in [float("nan"), float("inf"), float("-inf"), True, False, "9999999999", None]),
])
def test_rejects_invalid_returned_teams_token(monkeypatch, material, overrides):
    client, _ = _client(_pfx(monkeypatch, material), lambda *a, **k: Response(token=_access_token(**overrides)))
    with pytest.raises(CertificateAuthError):
        client.app_token_for(TEAMS_SCOPE)


@pytest.mark.parametrize("lifetime", [float("nan"), float("inf"), True, "600", 0, -1, None])
def test_rejects_invalid_certificate_cache_lifetime(monkeypatch, material, lifetime):
    client, _ = _client(_pfx(monkeypatch, material), lambda *a, **k: Response(expires_in=lifetime))
    with pytest.raises(CertificateAuthError):
        client.ensure_token()
    assert not client._certificate_tokens and client._token is None


def test_keychain_signs_without_export(monkeypatch, material):
    key, cert = material
    def sign(thumbprint, message):
        assert thumbprint == cert.fingerprint(hashes.SHA256())
        return cert.public_bytes(serialization.Encoding.DER), key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    monkeypatch.setattr(keychain_signing, "sign_rs256", sign)
    credential = KeychainCertificate(cert.fingerprint(hashes.SHA256()).hex())
    assertion = client_assertion(credential, "test-only-app", TOKEN_URL)
    _verify_assertion(assertion, key.public_key())


def test_keychain_unavailable_is_safe(monkeypatch, material, caplog):
    def unavailable(*args):
        raise OSError(PASSWORD.decode())
    monkeypatch.setattr(keychain_signing, "sign_rs256", unavailable)
    credential = KeychainCertificate(material[1].fingerprint(hashes.SHA256()).hex())
    with pytest.raises(CertificateAuthError) as caught:
        client_assertion(credential, "test-only-app", TOKEN_URL)
    assert caught.value.__context__ is None
    assert PASSWORD.decode() not in "".join(traceback.format_exception(caught.value)) + caplog.text


def test_expired_certificate_is_rejected_locally(monkeypatch, material):
    key, cert = material
    now = datetime.now(timezone.utc)
    expired = (x509.CertificateBuilder().subject_name(cert.subject).issuer_name(cert.issuer)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(days=2)).not_valid_after(now - timedelta(days=1))
               .sign(key, hashes.SHA256()))
    credential = _pfx(monkeypatch, (key, expired))
    client, _ = _client(credential, lambda *a, **k: pytest.fail("Expired certificate must not be sent"))
    with pytest.raises(CertificateAuthError):
        client.app_token_for(TEAMS_SCOPE)


def test_keychain_certificate_or_signature_mismatch_is_rejected(monkeypatch, material):
    key, cert = material
    monkeypatch.setattr(keychain_signing, "sign_rs256", lambda *args:
                        (cert.public_bytes(serialization.Encoding.DER), b"test-only-invalid-signature"))
    credential = KeychainCertificate(cert.fingerprint(hashes.SHA256()).hex())
    with pytest.raises(CertificateAuthError):
        client_assertion(credential, "test-only-app", TOKEN_URL)
    with pytest.raises(CertificateAuthError):
        client_assertion(KeychainCertificate("00" * 32), "test-only-app", TOKEN_URL)


def test_secret_path_preserved_and_teams_never_falls_back():
    seen = []
    def post(url, *, data, timeout):
        seen.append(data)
        return Response(token="test-only-secret-auth-token")
    client, _ = _client(None, post, client_secret="test-only-client-secret")
    assert client.app_token_for(TEAMS_SCOPE) is None
    assert not seen
    assert client.app_token_for("https://other.test/.default") == "test-only-secret-auth-token"
    assert seen[0] == {"client_id": "test-only-app", "client_secret": "test-only-client-secret",
                       "scope": "https://other.test/.default", "grant_type": "client_credentials"}


@pytest.mark.parametrize("mode", ["interactive", "access_token", "azure_cli"])
def test_certificate_resource_token_requires_app_mode(mode):
    client, _ = _client(KeychainCertificate("00" * 32), lambda *a, **k: pytest.fail("Must not authenticate"), auth_mode=mode)
    assert client.app_token_for(TEAMS_SCOPE) is None


def test_transport_and_event_exceptions_do_not_leak(monkeypatch, material, caplog):
    credential = _pfx(monkeypatch, material)
    def post(*args, **kwargs):
        # Simulate a library that echoes the credential payload in an exception.
        raise requests.RequestException(PASSWORD.decode() + kwargs["data"]["client_assertion"])
    client, events = _client(credential, post)
    def callback(*args):
        raise ValueError(PASSWORD.decode())
    client.audit_event = callback
    caplog.set_level(logging.DEBUG)
    with pytest.raises(CertificateAuthError) as caught:
        client.app_token_for(TEAMS_SCOPE)
    text = caplog.text + repr(events) + "".join(traceback.format_exception(caught.value))
    assert PASSWORD.decode() not in text and "eyJ" not in text
    assert caught.value.__context__ is None


@pytest.mark.parametrize("unsafe", ["authority", "wire_debug"])
def test_refuses_credential_exfiltration(monkeypatch, unsafe):
    client, _ = _client(KeychainCertificate("00" * 32), lambda *a, **k: pytest.fail("Must not send"))
    if unsafe == "authority":
        client.auth.authority = "https://wrong.test/"
    else:
        monkeypatch.setattr(http.client.HTTPConnection, "debuglevel", 1)
    with pytest.raises(CertificateAuthError):
        client.app_token_for(TEAMS_SCOPE)


def test_certificate_inputs_are_redacted():
    keys = ["certificate", "certificate_pfx", "certificate_password_env", "certificate_keychain_sha256",
            "pfx_path", "password_env", "password_provider", "thumbprint_sha256", "private_key", "client_assertion"]
    payload = {key: "test-only-sensitive-value" for key in keys}
    assert set(deep_sanitize(payload).values()) == {"***redacted***"}
    assert set(GraphClient._safe_payload(payload).values()) == {"***redacted***"}
    for key in keys:
        assert "test-only-sensitive-value" not in redact_text(f'{key}="test-only-sensitive-value"')
    for flag in ["--certificate-pfx", "--certificate-password-env", "--certificate-keychain-sha256"]:
        assert "test-only-sensitive-value" not in repr(redact_argv([flag, "test-only-sensitive-value"]))
        assert "test-only-sensitive-value" not in repr(scrub_command_line([flag, "test-only-sensitive-value"]))
    # Construct markers so no committed fixture resembles private key material.
    pem = "-----BEGIN " + "PRIVATE KEY-----\ntest-only-not-a-key\n-----END " + "PRIVATE KEY-----"
    assert "test-only-not-a-key" not in redact_text(pem)


def test_native_keychain_handle_cleanup_without_access(monkeypatch, material):
    key, cert = material
    der = cert.public_bytes(serialization.Encoding.DER)
    message = b"test-only-signing-input"
    signature = key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    released, values = [], {4: der, 7: signature}
    def copy(handle):
        def function(*args):
            args[-1]._obj.value = handle
            return 0
        return function
    constants = {}
    def constant(name):
        constants.setdefault(name, len(constants) + 100)
        return constants[name]
    cf = SimpleNamespace(
        CFDictionaryCreateMutable=lambda *a: 1, CFDictionarySetValue=lambda *a: None,
        CFArrayGetCount=lambda *a: 1, CFArrayGetValueAtIndex=lambda *a: 10,
        CFDataCreate=lambda *a: 6, CFRelease=released.append,
    )
    sec = SimpleNamespace(
        SecItemCopyMatching=copy(2), SecIdentityCopyCertificate=copy(3),
        SecCertificateCopyData=lambda *a: 4, SecIdentityCopyPrivateKey=copy(5),
        SecKeyIsAlgorithmSupported=lambda key, operation, alg: operation == 0,
        SecKeyCreateSignature=lambda *a: 7,
    )
    monkeypatch.setattr(keychain_signing, "_Security", lambda: SimpleNamespace(
        cf=cf, sec=sec, constant=constant, data=values.__getitem__))
    assert keychain_signing.sign_rs256(cert.fingerprint(hashes.SHA256()), message) == (der, signature)
    assert released == [7, 6, 5, 4, 3, 2, 1]
    released.clear()
    sec.SecIdentityCopyPrivateKey = lambda *args: -1
    with pytest.raises(RuntimeError, match="Keychain operation failed"):
        keychain_signing.sign_rs256(cert.fingerprint(hashes.SHA256()), message)
    assert released == [4, 3, 2, 1]
    assert "kSecUseAuthenticationUIFail" in constants


def test_certificate_cli_selects_without_reading_secret_env(monkeypatch, tmp_path):
    from azure_tenant_audit import cli
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "test-only-environment-secret")
    # Intercept the live-run boundary, so neither tenant nor keychain is read.
    captured = []
    monkeypatch.setattr(cli, "run_live", lambda args, *a, **k: captured.append(args) or 0)
    assert cli.main(["--tenant-id", "test-only-tenant", "--client-id", "test-only-app",
                     "--certificate-pfx", "test-only-memory.pfx", "--certificate-password-env", "TEST_ONLY_PASSWORD",
                     "--out", str(tmp_path)]) == 0
    assert captured[0].client_secret is None
    assert captured[0].certificate_pfx == "test-only-memory.pfx"


def test_certificate_cache_never_enters_persisted_run_state(monkeypatch, tmp_path, caplog):
    from azure_tenant_audit import cli, output
    from azure_tenant_audit.collectors.base import CollectorResult

    token = _access_token(aud="https://graph.microsoft.com", test_only_cache_marker="test-only-private-cache")
    assertion = "test-only-in-memory-assertion"
    monkeypatch.setattr("azure_tenant_audit.graph.client_assertion", lambda *a: assertion)
    clients, fills = [], []
    def make_client(auth, **kwargs):
        client = GraphClient(auth, **kwargs)
        def post(*a, **k):
            fills.append(k["data"]["scope"])
            return Response(token=token)
        client.session.post = post
        clients.append(client)
        return client

    class Collector:
        name = "identity"

        def run(self, context):
            # token_claims() has already filled the real client's Graph cache.
            clients[0].ensure_token()
            return CollectorResult(self.name, "ok", {"users": {"value": []}}, 0)

    def assert_safe(text):
        assert token not in text and assertion not in text
        assert "test-only-private-cache" not in text and "_certificate_tokens" not in text

    # Check before these persistence boundaries as well as checking the saved artefacts.
    real_log = output.AuditLogger.log
    real_write = output.AuditWriter._write_text_atomic
    def safe_log(self, event, message, details=None):
        assert_safe(json.dumps([event, message, details], default=str))
        return real_log(self, event, message, details)
    def safe_write(self, path, content):
        assert_safe(content)
        return real_write(self, path, content)
    monkeypatch.setattr(output.AuditLogger, "log", safe_log)
    monkeypatch.setattr(output.AuditWriter, "_write_text_atomic", safe_write)
    monkeypatch.setattr(cli, "GraphClient", make_client)
    monkeypatch.setattr(cli, "REGISTRY", {"identity": Collector()})
    caplog.set_level(logging.DEBUG)
    assert cli.main(["--tenant-name", "test-only", "--tenant-id", "test-only-tenant",
                     "--client-id", "test-only-app", "--certificate-keychain-sha256", "00" * 32,
                     "--collectors", "identity", "--throttle-mode", "fast", "--out", str(tmp_path)]) == 0
    assert fills == [clients[0].auth.graph_scope]
    assert clients[0]._certificate_tokens
    assert_safe(repr(clients[0]) + caplog.text)
    persisted = [path for path in tmp_path.rglob("*") if path.is_file()]
    assert any(path.name == "run-manifest.json" for path in persisted)
    assert any(path.name == "auth_context.json" for path in persisted)
    for path in persisted:
        assert_safe(path.read_bytes().decode("utf-8", errors="replace"))


@pytest.mark.parametrize("args", [
    ["--certificate-pfx", "test-only-memory.pfx", "--client-secret", "test-only-secret"],
    ["--certificate-password-env", "TEST_ONLY_PASSWORD"],
    ["--certificate-pfx", "test-only-memory.pfx", "--interactive"],
])
def test_certificate_cli_rejects_ambiguous_credentials(args):
    from azure_tenant_audit.cli import main
    with pytest.raises(SystemExit) as caught:
        main(args)
    assert caught.value.code == 2


@pytest.mark.parametrize("flag", ["--certificate-pf", "--certificate-password-en", "--certificate-keychain-sha25"])
@pytest.mark.parametrize("joined", [False, True])
def test_certificate_cli_rejects_abbreviations_before_run(monkeypatch, flag, joined):
    from azure_tenant_audit import cli
    called = []
    monkeypatch.setattr(cli, "run_live", lambda *a, **k: called.append(True))
    args = [flag + "=test-only-selector"] if joined else [flag, "test-only-selector"]
    with pytest.raises(SystemExit) as caught:
        cli.main(args)
    assert caught.value.code == 2
    assert not called
