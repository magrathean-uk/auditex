"""Shared pytest fixtures.

The single most important guardrail here: redirect every auditex
secrets path (``.secrets/m365-auth.env`` and friends) to an
isolated tmp directory for the duration of every test session.

Without this, a test that exercises the guided flow (or any code
path that once reached the removed local auth env writer)
silently overwrites the developer's real credentials with the
test's fixture values. Discovered live on 2026-05-09 when ``make test``
clobbered a working app-registration secret with
``AZURE_CLIENT_ID=app-id, AZURE_CLIENT_SECRET=app-secret`` from
``test_guided_run_requires_exchange_login_when_requested``.

The fixture is ``autouse=True`` and ``session``-scoped so:
- every test inherits the redirect by default
- per-test ``monkeypatch`` calls inside individual tests still work
  (they shadow the session env)
- the real ``.secrets/`` directory in the repo is never touched
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture(autouse=True, scope="session")
def _isolate_auditex_secrets():
    """Redirect AUDITEX_LOCAL_AUTH_ENV, AUDITEX_AUTH_CONTEXTS_PATH,
    AUDITEX_M365_HOME and the operator tenant key (AUDITEX_TENANT_KEY_PATH)
    to a session-scoped tmp directory before any test imports auditex code."""
    tmp_dir = tempfile.mkdtemp(prefix="auditex-test-secrets-")
    auth_env_path = Path(tmp_dir) / "m365-auth.env"
    contexts_path = Path(tmp_dir) / "auditex-auth-contexts.json"

    previous: dict[str, str | None] = {}
    for key, value in (
        ("AUDITEX_LOCAL_AUTH_ENV", str(auth_env_path)),
        ("AUDITEX_AUTH_CONTEXTS_PATH", str(contexts_path)),
        ("AUDITEX_M365_HOME", str(Path(tmp_dir) / "m365-home")),
        ("AUDITEX_MODEL_DIR", str(Path(tmp_dir) / "model-cache")),
        ("AUDITEX_TENANT_KEY_PATH", str(Path(tmp_dir) / "tenant-pseudonym.key")),
    ):
        previous[key] = os.environ.get(key)
        os.environ[key] = value

    try:
        yield tmp_dir
    finally:
        for key, prev in previous.items():
            if prev is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = prev


MODEL_HUBS = ("https://huggingface.co/", "http://huggingface.co/", "https://hf.co/", "http://hf.co/")


@pytest.fixture(autouse=True)
def _no_model_download(monkeypatch: pytest.MonkeyPatch) -> None:
    """No test downloads a local answer model: any request to the model hub fails the test, so a test whose guard
    stops working cannot fall through to a multi-gigabyte download. A test that fakes the download replaces
    ``requests.get`` itself; the opt-in real model test reads a model folder the operator names and downloads
    nothing. The session fixture above points the model cache at a temp folder."""
    import requests

    real = requests.Session.request

    def guarded(self, method, url, *args, **kwargs):
        if str(url).lower().startswith(MODEL_HUBS):
            pytest.fail(f"a test reached the model hub ({method} {url}); fake the download instead")
        return real(self, method, url, *args, **kwargs)

    monkeypatch.setattr(requests.Session, "request", guarded)


@pytest.fixture(autouse=True)
def _no_operator_lists_from_the_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    """An operator's lists must not reach tests that expect no list."""
    monkeypatch.delenv("AUDITEX_BREAK_GLASS_ACCOUNTS", raising=False)
    monkeypatch.delenv("AUDITEX_SENSITIVE_USERS_FILE", raising=False)
    monkeypatch.delenv("AUDITEX_PARTNER_DOMAINS_FILE", raising=False)


@pytest.fixture(autouse=True)
def _no_stale_sync_threshold_from_the_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    """An operator's AUDITEX_STALE_SYNC_DAYS must not change the 14-day default a test expects."""
    monkeypatch.delenv("AUDITEX_STALE_SYNC_DAYS", raising=False)


@pytest.fixture(scope="session")
def certificate_material(_isolate_auditex_secrets):
    """Throwaway certificate credentials, generated per session under the isolated secrets directory.

    Never real key material: a fresh 2048-bit RSA key and a self-signed certificate for a constructed
    subject, written owner-only (mode 600) as PEM and PFX files with and without a password.
    """
    import datetime as _dt
    from types import SimpleNamespace

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import NameOID

    root = Path(_isolate_auditex_secrets) / "certificates"
    root.mkdir(mode=0o700)
    password = "constructed-key-password-zz9"

    def certificate(key, *, days_valid: int = 5, expired: bool = False):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "constructed-auditex-test")])
        now = _dt.datetime.now(_dt.UTC)
        start = now - _dt.timedelta(days=10 if expired else 1)
        end = now - _dt.timedelta(days=1) if expired else now + _dt.timedelta(days=days_valid)
        return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(end)
                .sign(key, hashes.SHA256()))

    def write(name: str, data: bytes, mode: int = 0o600) -> Path:
        path = root / name
        path.write_bytes(data)
        path.chmod(mode)
        return path

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = certificate(key)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    plain = serialization.NoEncryption()
    locked = serialization.BestAvailableEncryption(password.encode())
    pkcs8 = serialization.PrivateFormat.PKCS8
    pem = serialization.Encoding.PEM
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    small_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expired_cert = certificate(expired_key, expired=True)
    paths = SimpleNamespace(
        pem=write("key-and-cert.pem", key.private_bytes(pem, pkcs8, plain) + cert_pem),
        pem_encrypted=write("key-and-cert-encrypted.pem", cert_pem + key.private_bytes(pem, pkcs8, locked)),
        pem_key_only=write("key-only.pem", key.private_bytes(pem, pkcs8, plain)),
        pfx=write("credential.pfx", pkcs12.serialize_key_and_certificates(b"constructed", key, cert, None, locked)),
        pfx_plain=write("credential-plain.pfx", pkcs12.serialize_key_and_certificates(b"constructed", key, cert, None, plain)),
        pem_other_cert=write("key-with-other-cert.pem", key.private_bytes(pem, pkcs8, plain)
                             + certificate(other_key).public_bytes(pem)),
        pem_expired=write("expired.pem", expired_key.private_bytes(pem, pkcs8, plain) + expired_cert.public_bytes(pem)),
        pem_small=write("small.pem", small_key.private_bytes(pem, pkcs8, plain)),
        pem_ec=write("ec.pem", ec_key.private_bytes(pem, pkcs8, plain)),
        password_file=write("password.txt", (password + "\n").encode()),
    )
    return SimpleNamespace(
        root=root,
        key=key,
        certificate=cert,
        thumbprint=cert.fingerprint(hashes.SHA1()).hex().upper(),
        password=password,
        key_pem_text=key.private_bytes(pem, pkcs8, plain).decode(),
        expired_thumbprint=expired_cert.fingerprint(hashes.SHA1()).hex().upper(),
        **vars(paths),
    )
