#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import requests

GRAPH_RESOURCE = "https://graph.microsoft.com"
TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def write_owner_only(path: Path, text: str) -> None:
    """Write a secret file as 0600 from the first byte; never follow a symlink at the final path."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(text)


SECRETS_DIR_NAME = ".secrets"


def ensure_private_dir(path: Path) -> None:
    """Create a missing folder owner-only. An existing folder is tightened only when it is a kit
    secrets folder (`.secrets`); any other folder the operator chose, such as the working directory,
    keeps its mode."""
    existed = path.exists()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not existed or path.name == SECRETS_DIR_NAME:
        os.chmod(path, 0o700)


def decode_claims(token: str) -> dict:
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except Exception:
        return {}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Inspect the current lab-populator Graph token and claims.",
        allow_abbrev=False,
    )
    parser.add_argument("--tenant-id", default=None)
    parser.add_argument("--out", type=Path, default=Path(".secrets/lab-populator-token-claims.json"))
    parser.add_argument("--app-secret-file", type=Path, default=None)
    parser.add_argument("--write-env", type=Path, default=None, help="Write an env file containing AZURE_ACCESS_TOKEN for a short-lived app-token run.")
    args = parser.parse_args(argv)

    if args.app_secret_file:
        secret = json.loads(args.app_secret_file.read_text(encoding="utf-8"))
        tenant_id = args.tenant_id or secret.get("tenantId")
        if not tenant_id:
            raise RuntimeError("tenant id is required for app secret token flow.")
        # The secret travels in the request body only, never in a process argv that ps can read.
        response = requests.post(
            TOKEN_URL.format(tenant_id=tenant_id),
            data={
                "client_id": secret["appId"],
                "client_secret": secret["password"],
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            },
            timeout=120,
            # A redirect would resend the client secret to another host; never follow one.
            allow_redirects=False,
        )
        if response.status_code != 200:
            raise RuntimeError(f"app token request failed with HTTP {response.status_code}.")
        payload = response.json()
        payload["tokenType"] = payload.get("token_type")
    else:
        command = [
            "az",
            "account",
            "get-access-token",
            "--resource",
            GRAPH_RESOURCE,
            "--output",
            "json",
        ]
        if args.tenant_id:
            command.extend(["--tenant", args.tenant_id])

        proc = subprocess.run(command, check=False, capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or proc.stdout).strip() or "Azure CLI Graph token request failed.")

        payload = json.loads(proc.stdout)
    token = payload.get("accessToken") or payload.get("access_token") or ""
    claims = decode_claims(token)
    if args.write_env:
        # The env file holds a bearer token: a new folder, or an existing .secrets folder, is made owner-only.
        ensure_private_dir(args.write_env.parent)
        write_owner_only(args.write_env, f"AZURE_ACCESS_TOKEN={token}\n")
    result = {
        "generatedAt": utc_now(),
        "tenantId": args.tenant_id,
        "tokenType": payload.get("tokenType"),
        "expiresOn": payload.get("expiresOn"),
        "envFile": str(args.write_env) if args.write_env else None,
        "claims": {
            "aud": claims.get("aud"),
            "appid": claims.get("appid"),
            "oid": claims.get("oid"),
            "upn": claims.get("upn"),
            "scp": claims.get("scp"),
            "roles": claims.get("roles", []),
            "wids": claims.get("wids", []),
        },
    }
    if not args.out.parent.exists():
        ensure_private_dir(args.out.parent)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
