"""In-memory certificate assertions; no token cache, discovery, logging or key export.

Uses cryptography already required by MSAL. Protocol reference (not fetched):
https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials
RS256 support is inferred from the identity platform's established RSA flow.
"""
from __future__ import annotations

import base64
import json
import os
import stat
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12


_MAX_PFX_BYTES = 64 * 1024


class CertificateAuthError(RuntimeError):
    """Only fixed codes may cross the credential boundary, never vendor diagnostics."""

    def __init__(self) -> None:
        super().__init__("Certificate authentication failed.")
        self.error_code = "certificate_auth_failed"


@dataclass(frozen=True, repr=False)
class PfxCertificate:
    pfx_path: str | Path = field(repr=False)
    password_env: str | None = field(default=None, repr=False)
    password_provider: Callable[[], str | bytes | None] | None = field(default=None, repr=False)
    allow_unencrypted: bool = False

    def __post_init__(self) -> None:
        if self.password_env:
            # Consume once before collectors/children start. Never restore it:
            # refreshes use only this process-local closure.
            password = os.environ.pop(self.password_env, None)
            if self.password_provider is not None:
                return  # The conflicting sources still fail at the safe boundary.

            def provider() -> str:
                if password is None:
                    raise CertificateAuthError()
                return password

            object.__setattr__(self, "password_provider", provider)
            object.__setattr__(self, "password_env", None)

    def __repr__(self) -> str:
        return "PfxCertificate(<redacted>)"


@dataclass(frozen=True, repr=False)
class KeychainCertificate:
    """Select a macOS keychain identity by its public certificate's SHA-256 hex."""

    thumbprint_sha256: str = field(repr=False)

    def __repr__(self) -> str:
        return "KeychainCertificate(<redacted>)"


CertificateCredential = PfxCertificate | KeychainCertificate


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _check_certificate(cert: x509.Certificate) -> rsa.RSAPublicKey:
    now = datetime.now(timezone.utc)
    public = cert.public_key()
    # Older cryptography versions permitted by MSAL expose naive UTC dates.
    start = getattr(cert, "not_valid_before_utc", None)
    end = getattr(cert, "not_valid_after_utc", None)
    if start is None:
        start = cert.not_valid_before.replace(tzinfo=timezone.utc)
        end = cert.not_valid_after.replace(tzinfo=timezone.utc)
    if (not isinstance(public, rsa.RSAPublicKey) or public.key_size < 2048
            or not start <= now < end):
        raise CertificateAuthError()
    return public


def _read_pfx(path: str | Path) -> bytes:
    # Non-blocking open also lets fstat refuse FIFOs without waiting for a writer.
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                or info.st_size > _MAX_PFX_BYTES):
            raise CertificateAuthError()
        raw = bytearray()
        while len(raw) <= _MAX_PFX_BYTES:
            chunk = os.read(descriptor, _MAX_PFX_BYTES + 1 - len(raw))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) > _MAX_PFX_BYTES:
            raise CertificateAuthError()
        return bytes(raw)
    finally:
        os.close(descriptor)


def _assertion(credential: CertificateCredential, client_id: str, audience: str) -> str:
    # This private frame never escapes the public error boundary below.
    if isinstance(credential, PfxCertificate):
        if credential.password_env and credential.password_provider:
            raise CertificateAuthError()
        password = credential.password_provider() if credential.password_provider else None
        if isinstance(password, str):
            password = password.encode("utf-8")
        if password is not None and not isinstance(password, bytes):
            raise CertificateAuthError()
        raw = _read_pfx(credential.pfx_path)
        if not credential.allow_unencrypted:
            try:
                pkcs12.load_key_and_certificates(raw, None)
            except ValueError:
                pass  # Encrypted PFX requires its supplied password below.
            else:
                raise CertificateAuthError()
        key, cert, _ = pkcs12.load_key_and_certificates(raw, password)
        if not isinstance(key, rsa.RSAPrivateKey) or cert is None:
            raise CertificateAuthError()
        public = _check_certificate(cert)
        thumbprint = cert.fingerprint(hashes.SHA256())
    elif isinstance(credential, KeychainCertificate):
        thumbprint = bytes.fromhex(credential.thumbprint_sha256)
        if len(thumbprint) != 32:
            raise CertificateAuthError()
    else:
        raise CertificateAuthError()
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "x5t#S256": _b64(thumbprint)}
    claims = {"aud": audience, "iss": client_id, "sub": client_id,
              "jti": str(uuid.uuid4()), "nbf": now - 30, "iat": now, "exp": now + 300}
    message = ".".join(_b64(json.dumps(part, separators=(",", ":")).encode("utf-8"))
                       for part in (header, claims)).encode("ascii")
    if isinstance(credential, PfxCertificate):
        signature = key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    else:
        from .keychain_signing import sign_rs256

        der, signature = sign_rs256(thumbprint, message)
        cert = x509.load_der_x509_certificate(der)
        public = _check_certificate(cert)
        if cert.fingerprint(hashes.SHA256()) != thumbprint:
            raise CertificateAuthError()
    # Also catches a mismatched key/certificate before any credential is sent.
    public.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
    return message.decode("ascii") + "." + _b64(signature)


def client_assertion(credential: CertificateCredential, client_id: str, audience: str) -> str:
    failed = False
    try:
        return _assertion(credential, client_id, audience)
    except Exception:
        # Raise outside the handler: no exception context, vendor traceback or
        # private-frame locals survive into the caller's traceback.
        failed = True
    if failed:
        raise CertificateAuthError()
