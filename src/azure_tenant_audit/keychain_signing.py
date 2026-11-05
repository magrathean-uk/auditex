"""macOS Security.framework RSA signing using opaque SecKeyRef handles only.

No subprocesses, credential export APIs, temporary files or third-party bridge.
All CoreFoundation objects owned by this call are released, including on failure.
Native ABI integration is unverified live; tests replace the native libraries.
"""
from __future__ import annotations

import ctypes as ct
import hashlib
import sys


class _Security:
    def __init__(self) -> None:
        if sys.platform != "darwin":
            raise RuntimeError("Keychain unavailable.")
        self.cf = ct.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        self.sec = ct.CDLL("/System/Library/Frameworks/Security.framework/Security")
        pointer = ct.c_void_p
        signatures = {
            "CFDictionaryCreateMutable": (pointer, [pointer, ct.c_long, pointer, pointer]),
            "CFDictionarySetValue": (None, [pointer, pointer, pointer]),
            "CFRelease": (None, [pointer]),
            "CFArrayGetCount": (ct.c_long, [pointer]),
            "CFArrayGetValueAtIndex": (pointer, [pointer, ct.c_long]),
            "CFDataCreate": (pointer, [pointer, pointer, ct.c_long]),
            "CFDataGetLength": (ct.c_long, [pointer]),
            "CFDataGetBytePtr": (pointer, [pointer]),
        }
        for name, (result, args) in signatures.items():
            function = getattr(self.cf, name)
            function.restype, function.argtypes = result, args
        signatures = {
            "SecItemCopyMatching": (ct.c_int32, [pointer, ct.POINTER(pointer)]),
            "SecIdentityCopyCertificate": (ct.c_int32, [pointer, ct.POINTER(pointer)]),
            "SecCertificateCopyData": (pointer, [pointer]),
            "SecIdentityCopyPrivateKey": (ct.c_int32, [pointer, ct.POINTER(pointer)]),
            "SecKeyIsAlgorithmSupported": (ct.c_bool, [pointer, ct.c_long, pointer]),
            "SecKeyCreateSignature": (pointer, [pointer, pointer, pointer, ct.POINTER(pointer)]),
        }
        for name, (result, args) in signatures.items():
            function = getattr(self.sec, name)
            function.restype, function.argtypes = result, args

    def constant(self, name: str) -> int:
        library = self.cf if name.startswith("kCF") else self.sec
        return ct.c_void_p.in_dll(library, name).value

    def data(self, handle: int) -> bytes:
        return ct.string_at(self.cf.CFDataGetBytePtr(handle), self.cf.CFDataGetLength(handle))


def sign_rs256(thumbprint: bytes, message: bytes) -> tuple[bytes, bytes]:
    api = _Security()
    cf, sec = api.cf, api.sec
    owned = []

    def own(handle):
        value = handle.value if isinstance(handle, ct.c_void_p) else handle
        if value:
            owned.append(value)
        return value

    def copied(function, *args):
        result = ct.c_void_p()
        status = function(*args, ct.byref(result))
        handle = own(result)
        if status != 0 or not handle:
            raise RuntimeError("Keychain operation failed.")
        return handle

    try:
        # NULL callbacks are safe here: the dictionary contains only framework
        # constants, whose lifetimes exceed the dictionary's lifetime.
        query = own(cf.CFDictionaryCreateMutable(None, 0, None, None))
        if not query:
            raise RuntimeError("Keychain unavailable.")
        for key, value in (
            ("kSecClass", "kSecClassIdentity"),
            ("kSecReturnRef", "kCFBooleanTrue"),
            ("kSecMatchLimit", "kSecMatchLimitAll"),
            ("kSecUseAuthenticationUI", "kSecUseAuthenticationUIFail"),
        ):
            cf.CFDictionarySetValue(query, api.constant(key), api.constant(value))
        identities = copied(sec.SecItemCopyMatching, query)
        for index in range(cf.CFArrayGetCount(identities)):
            identity = cf.CFArrayGetValueAtIndex(identities, index)  # borrowed
            cert = copied(sec.SecIdentityCopyCertificate, identity)
            cert_data = own(sec.SecCertificateCopyData(cert))
            if not cert_data:
                raise RuntimeError("Keychain certificate unavailable.")
            der = api.data(cert_data)
            if hashlib.sha256(der).digest() != thumbprint:
                continue
            key = copied(sec.SecIdentityCopyPrivateKey, identity)
            algorithm = api.constant("kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256")
            if not sec.SecKeyIsAlgorithmSupported(key, 0, algorithm):  # kSecKeyOperationTypeSign (SecKey.h)
                raise RuntimeError("Keychain RSA signing unavailable.")
            data = own(cf.CFDataCreate(None, message, len(message)))
            if not data:
                raise RuntimeError("Keychain signing failed.")
            error = ct.c_void_p()
            signature = own(sec.SecKeyCreateSignature(key, algorithm, data, ct.byref(error)))
            own(error)  # CFError diagnostics are never read or rendered.
            if not signature or error.value:
                raise RuntimeError("Keychain signing failed.")
            return der, api.data(signature)
        raise RuntimeError("Keychain identity unavailable.")
    finally:
        for handle in reversed(owned):
            cf.CFRelease(handle)
