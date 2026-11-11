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

GRAPH_RESOURCE = "https://graph.microsoft.com"
TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


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
    parser = argparse.ArgumentParser(description="Inspect the current lab-populator Graph token and claims.")
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
        response = subprocess.run(
            [
                "curl",
                "-sS",
                "-X",
                "POST",
                TOKEN_URL.format(tenant_id=tenant_id),
                "-H",
                "Content-Type: application/x-www-form-urlencoded",
                "--data-urlencode",
                f"client_id={secret['appId']}",
                "--data-urlencode",
                f"client_secret={secret['password']}",
                "--data-urlencode",
                "scope=https://graph.microsoft.com/.default",
                "--data-urlencode",
                "grant_type=client_credentials",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if response.returncode != 0:
            raise RuntimeError(response.stderr.strip() or "app token request failed.")
        payload = json.loads(response.stdout)
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
        args.write_env.parent.mkdir(parents=True, exist_ok=True)
        args.write_env.write_text(f"AZURE_ACCESS_TOKEN={token}\n", encoding="utf-8")
        os.chmod(args.write_env, 0o600)
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
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
