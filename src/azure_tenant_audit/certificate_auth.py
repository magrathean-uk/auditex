"""Certificate credentials for app-only tokens, minted through msal.ConfidentialClientApplication.

The operator names a private key file (PEM or PFX) and the certificate's SHA-1 thumbprint, as the
app registration shows it. A key password comes only from an environment variable (consumed once)
or a file, never from argv. The key is read once into process memory before any request and is
never written, logged or copied into the bundle; every failure crosses this boundary as a fixed
code with a fixed message, never a path, a password, a vendor diagnostic or a traceback context.

Protocol reference (not fetched): https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials
msal signs the client assertion (RS256 with the x5t SHA-1 thumbprint header when only a thumbprint
is given) and keeps its token cache in memory only.
"""
from __future__ import annotations

import os
import re
import stat
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

MAX_KEY_FILE_BYTES = 64 * 1024
MAX_PASSWORD_FILE_BYTES = 4 * 1024
MIN_RSA_KEY_BITS = 2048
# Certificate assertions go only to Entra token endpoints over HTTPS.
CERTIFICATE_AUTHORITY_HOSTS = frozenset({
    "login.microsoftonline.com",
    "login.microsoftonline.us",
    "login.chinacloudapi.cn",
    "login.partner.microsoftonline.cn",
})
_THUMBPRINT_RE = re.compile(r"^[0-9A-Fa-f]{40}$")
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_OAUTH_ERROR_RE = re.compile(r"^[a-z_]{1,64}$")

# Fixed codes and messages: nothing operator- or vendor-supplied is ever interpolated.
CERTIFICATE_ERRORS: dict[str, str] = {
    "certificate_file_refused": (
        "The certificate key file could not be used: it must be a regular file of at most 64 KiB "
        "readable only by its owner (mode 600)."
    ),
    "certificate_password_unavailable": (
        "The certificate key password could not be read: name one environment variable that is set, "
        "or one password file readable only by its owner, not both."
    ),
    "certificate_key_unreadable": (
        "The certificate key could not be loaded: check the password and that the file holds an RSA "
        "private key of at least 2048 bits (PEM or PFX)."
    ),
    "certificate_thumbprint_invalid": "The certificate thumbprint must be the 40-character SHA-1 hex value.",
    "certificate_thumbprint_mismatch": "The certificate in the key file does not match the thumbprint given.",
    "certificate_not_valid": "The certificate in the key file is expired or not yet valid.",
    "certificate_authority_refused": (
        "Certificate authentication sends its assertion only to an HTTPS Microsoft Entra authority."
    ),
    "certificate_token_failed": "A certificate app token could not be acquired.",
    "certificate_source_in_output": (
        "The certificate key and password files must sit outside the output and resume folders, with no "
        "link to them inside either folder."
    ),
}


class CertificateAuthError(RuntimeError):
    """A certificate failure with a fixed code; the message never carries a path, value or diagnostic."""

    def __init__(self, code: str = "certificate_token_failed") -> None:
        if code not in CERTIFICATE_ERRORS:
            code = "certificate_token_failed"
        super().__init__(CERTIFICATE_ERRORS[code])
        self.error_code = code


@dataclass(frozen=True, repr=False, eq=False)
class CertificateCredential:
    """A loaded certificate credential: the private key in memory and the SHA-1 thumbprint."""

    thumbprint: str = field(repr=False)
    private_key: Any = field(repr=False)

    def __repr__(self) -> str:
        return "CertificateCredential(<redacted>)"

    def __reduce__(self) -> Any:
        # Never pickle or deep-copy key material into another object graph or process.
        raise TypeError("CertificateCredential cannot be serialised.")

    def __deepcopy__(self, memo: dict[int, Any]) -> CertificateCredential:
        return self

    def msal_client_credential(self) -> dict[str, Any]:
        return {"private_key": self.private_key, "thumbprint": self.thumbprint}


def _read_private_file(path: str | Path, limit: int, code: str) -> bytes:
    """Read a small owner-only regular file through one descriptor, refusing anything else."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(os.fspath(path), flags)
    except (OSError, TypeError, ValueError):
        raise CertificateAuthError(code) from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise CertificateAuthError(code)
        if os.name == "posix" and info.st_mode & 0o077:
            raise CertificateAuthError(code)
        raw = bytearray()
        while len(raw) <= limit:
            chunk = os.read(descriptor, limit + 1 - len(raw))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) > limit:
            raise CertificateAuthError(code)
        return bytes(raw)
    except OSError:
        raise CertificateAuthError(code) from None
    finally:
        os.close(descriptor)


def _password(password_env: str | None, password_file: str | Path | None, environ: Any) -> bytes | None:
    code = "certificate_password_unavailable"
    if password_env and password_file:
        raise CertificateAuthError(code)
    if password_env:
        if not isinstance(password_env, str) or not _ENV_NAME_RE.match(password_env):
            raise CertificateAuthError(code)
        # Consumed once, so child processes (PowerShell, az) never inherit it.
        value = environ.pop(password_env, None)
        if not value:
            raise CertificateAuthError(code)
        return value.encode("utf-8")
    if password_file:
        raw = _read_private_file(password_file, MAX_PASSWORD_FILE_BYTES, code)
        if raw.endswith(b"\r\n"):
            raw = raw[:-2]
        elif raw.endswith(b"\n"):
            raw = raw[:-1]
        if not raw:
            raise CertificateAuthError(code)
        return raw
    return None


def normalise_thumbprint(thumbprint: Any) -> str:
    if not isinstance(thumbprint, str) or not _THUMBPRINT_RE.match(thumbprint.strip()):
        raise CertificateAuthError("certificate_thumbprint_invalid")
    return thumbprint.strip().upper()


def _sha1_thumbprint(cert: Any) -> str:
    from cryptography.hazmat.primitives import hashes

    # SHA-1 here is Entra's key identifier for the certificate, not a signature.
    return cert.fingerprint(hashes.SHA1()).hex().upper()


def _currently_valid(cert: Any) -> bool:
    now = datetime.now(UTC)
    return cert.not_valid_before_utc <= now < cert.not_valid_after_utc


def _load_key(raw: bytes, password: bytes | None) -> tuple[Any, list[Any]]:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12

    if raw.lstrip().startswith(b"-----BEGIN"):
        key = serialization.load_pem_private_key(raw, password)
        try:
            certificates = list(x509.load_pem_x509_certificates(raw))
        except ValueError:
            certificates = []
        return key, certificates
    key, cert, extra = pkcs12.load_key_and_certificates(raw, password)
    return key, [item for item in (cert, *(extra or ())) if item is not None]


def _load(path: str | Path, thumbprint: str, password: bytes | None) -> CertificateCredential:
    from cryptography.hazmat.primitives.asymmetric import rsa

    raw = _read_private_file(path, MAX_KEY_FILE_BYTES, "certificate_file_refused")
    failed = False
    try:
        key, certificates = _load_key(raw, password)
    except Exception:  # noqa: BLE001 - vendor messages never cross this boundary
        failed = True
    if failed:
        raise CertificateAuthError("certificate_key_unreadable")
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < MIN_RSA_KEY_BITS:
        raise CertificateAuthError("certificate_key_unreadable")
    if certificates:
        # A file that carries certificates must carry the one the thumbprint names, for this key.
        matching = [cert for cert in certificates if _matches(cert, key) and _sha1_thumbprint(cert) == thumbprint]
        if not matching:
            raise CertificateAuthError("certificate_thumbprint_mismatch")
        if not _currently_valid(matching[0]):
            raise CertificateAuthError("certificate_not_valid")
    return CertificateCredential(thumbprint=thumbprint, private_key=key)


def _matches(cert: Any, key: Any) -> bool:
    from cryptography.hazmat.primitives import serialization

    der = serialization.Encoding.DER
    info = serialization.PublicFormat.SubjectPublicKeyInfo
    try:
        return cert.public_key().public_bytes(der, info) == key.public_key().public_bytes(der, info)
    except Exception:  # noqa: BLE001
        return False


def load_certificate_credential(
    path: str | Path,
    thumbprint: str,
    *,
    password_env: str | None = None,
    password_file: str | Path | None = None,
    environ: Any = None,
) -> CertificateCredential:
    """Load and check a certificate credential before any request; raise CertificateAuthError on any failure."""
    failure: CertificateAuthError | None = None
    try:
        normalised = normalise_thumbprint(thumbprint)
        password = _password(password_env, password_file, os.environ if environ is None else environ)
        return _load(path, normalised, password)
    except CertificateAuthError as exc:
        failure = CertificateAuthError(exc.error_code)
    except Exception:  # noqa: BLE001
        failure = CertificateAuthError("certificate_key_unreadable")
    # Raised outside the handler: no exception context or frame locals reach the caller.
    raise failure


def _identity(path: str | Path) -> tuple[int, int] | None:
    """The (device, inode) a path resolves to, following links; None when it cannot be read."""
    try:
        info = os.stat(os.path.expanduser(os.fspath(path)))
    except (OSError, TypeError, ValueError):
        return None
    return info.st_dev, info.st_ino


def refuse_sources_in_output(
    sources: Iterable[str | Path | None], output_roots: Iterable[str | Path | None],
) -> None:
    """Refuse a key or password file inside an output root, or linked from one, before the run folder exists.

    A source inside the folder a run writes to would be swept into the bundle, or replaced by an output of
    the same name (summary.json, say). Containment is decided by directory identity rather than spelling,
    so case, ``..`` or a linked parent cannot hide it; a hard or symbolic link to a source, or to a folder
    above it, anywhere below a root counts as an alias. A source that cannot be read is left to the loader.
    """
    files: set[tuple[int, int]] = set()
    above: set[tuple[int, int]] = set()
    for source in sources:
        identity = _identity(source) if source else None
        if identity is None:
            continue
        files.add(identity)
        resolved = Path(os.path.expanduser(os.fspath(source))).resolve()
        above.update(filter(None, (_identity(parent) for parent in resolved.parents)))
    roots: dict[tuple[int, int], str] = {}
    for root in output_roots:
        identity = _identity(root) if root else None
        if identity is not None:
            roots.setdefault(identity, os.path.expanduser(os.fspath(root)))
    if not files or not roots:
        return
    if above & roots.keys():
        raise CertificateAuthError("certificate_source_in_output")
    for top in roots.values():
        for current, directories, names in os.walk(top, followlinks=False):
            for name in (*directories, *names):
                identity = _identity(os.path.join(current, name))
                if identity is not None and (identity in files or identity in above):
                    raise CertificateAuthError("certificate_source_in_output")


def certificate_authority(authority: str, tenant_id: str) -> str:
    """The msal authority URL for a certificate run; only HTTPS Entra hosts and a plain tenant segment."""
    tenant = str(tenant_id or "")
    try:
        # urllib raises ValueError, with the authority's own text, for a malformed port or bracket; that is the
        # same fixed refusal as any other authority outside the allowlist, raised outside this handler so no
        # library diagnostic is chained to it.
        parsed = urlparse(str(authority or ""))
        port = parsed.port
    except ValueError:
        parsed, port = None, None
    if (
        parsed is None
        or parsed.scheme != "https"
        or parsed.hostname not in CERTIFICATE_AUTHORITY_HOSTS
        or port is not None
        or parsed.username is not None
        or parsed.query
        or parsed.fragment
        or parsed.path.strip("/")
        or not tenant
        or tenant in {"common", "organizations", "consumers"}
        or not re.match(r"^[A-Za-z0-9.-]{1,253}$", tenant)
    ):
        raise CertificateAuthError("certificate_authority_refused")
    return f"https://{parsed.hostname}/{tenant}"


def build_confidential_client(
    credential: CertificateCredential,
    *,
    client_id: str,
    authority: str,
    timeout: int | float | None = None,
    http_client: Any = None,
) -> Any:
    """One msal.ConfidentialClientApplication per GraphClient; its token cache lives in memory only."""
    import msal

    # The authority is already pinned to an Entra host (certificate_authority), so msal's instance
    # discovery adds only a network call; client credentials have no refresh tokens to find by alias.
    options: dict[str, Any] = {"token_cache": msal.TokenCache(), "instance_discovery": False}
    if http_client is not None:
        options["http_client"] = http_client
    else:
        options["timeout"] = timeout
    return msal.ConfidentialClientApplication(
        client_id,
        client_credential=credential.msal_client_credential(),
        authority=authority,
        **options,
    )


def safe_oauth_error(result: Any) -> str:
    """The OAuth error code from an msal result when it is a plain code; never its description."""
    error = result.get("error") if isinstance(result, dict) else None
    return error if isinstance(error, str) and _OAUTH_ERROR_RE.match(error) else "certificate_token_failed"
