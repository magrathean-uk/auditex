#!/usr/bin/env python3
"""Create or update the lab-only Microsoft Graph tenant populator app.

Every directory call goes to Microsoft Graph with one access token that the Azure CLI issues for the
named lab tenant (`az account get-access-token --tenant`). The token's tenant and the Graph
organisation are both checked before the first write, and since a Graph write always lands in the
token's tenant, switching the Azure CLI default account mid-run cannot move a write elsewhere.
"""
from __future__ import annotations

import argparse
import errno
import json
import os
import subprocess
import sys
import tempfile
import uuid
from collections import OrderedDict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
import identity_seed_az as tenant_guard  # noqa: E402

GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
GRAPH_RESOURCE = "https://graph.microsoft.com"
GRAPH_ROOT = "https://graph.microsoft.com/v1.0"
PLACEHOLDER_TENANT_ID = "00000000-0000-0000-0000-000000000000"
SECRET_DISPLAY_NAME = "codex-lab-populator"


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


class TenantRefused(RuntimeError):
    """The named lab tenant could not be proven for the token that would make the writes."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def stage_secret_file(path: Path) -> tuple[int, Path]:
    """Check the secret destination and open a private staging file beside it.

    The destination must be absent or a regular file (never a symlink). The staging file has a unique
    name, is created 0600 with O_EXCL, and only ever replaces the destination by an atomic rename once
    the credential is written, so this run never deletes or truncates a file another run saved.
    """
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise OSError(errno.EPERM, "the destination is not a regular file")
    fd, staged = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    os.fchmod(fd, 0o600)
    return fd, Path(staged)


def commit_secret_file(fd: int, staged: Path, path: Path, text: str) -> None:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(staged, path)


def ensure_private_dir(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def named_tenant_id(raw: str) -> str | None:
    """Return the lab tenant GUID, or None for a malformed or all-zero placeholder value."""
    try:
        tenant_id = str(uuid.UUID(raw.strip()))
    except ValueError:
        return None
    if tenant_id != raw.strip().lower() or tenant_id == PLACEHOLDER_TENANT_ID:
        return None
    return tenant_id


def tenant_token(tenant_id: str) -> str:
    """Ask the Azure CLI for a Graph token issued for the named tenant, whatever its default account."""
    proc = subprocess.run(
        [
            "az", "account", "get-access-token",
            "--tenant", tenant_id,
            "--resource", GRAPH_RESOURCE,
            "--query", "accessToken",
            "--output", "tsv",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    token = proc.stdout.strip() if proc.returncode == 0 else ""
    if not token:
        raise TenantRefused("tenant_check_failed")
    return token


class Directory:
    """Microsoft Graph calls with one token pinned to the named tenant; error bodies are never surfaced."""

    def __init__(self, token: str) -> None:
        self.token = token
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {token}", "Content-Type": "application/json"})

    def call(self, method: str, path: str, payload: dict | None = None) -> dict:
        response = self.session.request(
            method,
            f"{GRAPH_ROOT}{path}",
            json=payload,
            timeout=120,
            # The bearer token never follows a redirect to another host.
            allow_redirects=False,
        )
        if not 200 <= response.status_code < 300:
            raise RuntimeError(f"Graph {method} {path.split('?', 1)[0]} failed with HTTP {response.status_code}.")
        if response.status_code == 204:
            return {}
        try:
            body = response.json()
        except ValueError:
            return {}
        return body if isinstance(body, dict) else {}

    def verify_tenant(self, tenant_id: str) -> None:
        try:
            tenant_guard.verify_named_tenant(tenant_id, self.token, lambda: self.call("GET", "/organization?$select=id"))
        except tenant_guard.TenantGuardError as exc:
            raise TenantRefused(exc.reason) from None
        except (RuntimeError, requests.RequestException):
            raise TenantRefused("tenant_check_failed") from None


def odata_literal(value: str) -> str:
    return quote(value.replace("'", "''"), safe="")


def graph_permission_map(directory: Directory) -> tuple[str, dict[tuple[str, str], dict[str, str]]]:
    sp = directory.call(
        "GET", f"/servicePrincipals(appId='{GRAPH_APP_ID}')?$select=id,appRoles,oauth2PermissionScopes"
    )
    mapping: dict[tuple[str, str], dict[str, str]] = {}
    for role in sp.get("appRoles", []):
        value = role.get("value")
        role_id = role.get("id")
        if value and role_id and "Application" in role.get("allowedMemberTypes", []):
            mapping[(value, "Role")] = {"id": role_id, "type": "Role"}
    for scope in sp.get("oauth2PermissionScopes", []):
        value = scope.get("value")
        scope_id = scope.get("id")
        if value and scope_id:
            mapping[(value, "Scope")] = {"id": scope_id, "type": "Scope"}
    return str(sp.get("id") or ""), mapping


def grant_admin_consent(directory: Directory, app_id: str, graph_sp_id: str, roles: list[str], scopes: list[str]) -> None:
    """Tenant-wide consent for the app's Graph permissions, as az ad app permission admin-consent does."""
    found = directory.call("GET", f"/servicePrincipals?$filter=appId eq '{odata_literal(app_id)}'&$select=id")
    existing_sp = (found.get("value") or [None])[0]
    app_sp_id = (existing_sp or {}).get("id") or directory.call("POST", "/servicePrincipals", {"appId": app_id}).get("id")
    if not app_sp_id or not graph_sp_id:
        raise RuntimeError("admin consent needs the app and Graph service principals.")
    assigned = directory.call("GET", f"/servicePrincipals/{app_sp_id}/appRoleAssignments?$select=appRoleId,resourceId")
    held = {
        str(row.get("appRoleId"))
        for row in assigned.get("value", [])
        if str(row.get("resourceId")) == graph_sp_id
    }
    for role_id in roles:
        if role_id in held:
            continue
        directory.call(
            "POST",
            f"/servicePrincipals/{graph_sp_id}/appRoleAssignedTo",
            {"principalId": app_sp_id, "resourceId": graph_sp_id, "appRoleId": role_id},
        )
    if not scopes:
        return
    grants = directory.call(
        "GET",
        f"/oauth2PermissionGrants?$filter=clientId eq '{app_sp_id}' and resourceId eq '{graph_sp_id}'",
    ).get("value", [])
    if grants:
        current = str(grants[0].get("scope") or "").split()
        merged = " ".join(dict.fromkeys([*current, *scopes]))
        if merged != " ".join(current):
            directory.call("PATCH", f"/oauth2PermissionGrants/{grants[0]['id']}", {"scope": merged})
    else:
        directory.call(
            "POST",
            "/oauth2PermissionGrants",
            {"clientId": app_sp_id, "consentType": "AllPrincipals", "resourceId": graph_sp_id, "scope": " ".join(scopes)},
        )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Create or update the lab-only Microsoft Graph tenant populator app.",
        allow_abbrev=False,
    )
    parser.add_argument("--config", type=Path, default=Path("configs/lab-populator-permissions.json"))
    parser.add_argument(
        "--tenant-id",
        required=True,
        help="Lab tenant GUID. Every directory call uses a Graph token issued for it and checked against it.",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--admin-consent", action="store_true", help="Grant tenant-wide admin consent for the Graph permissions after adding them.")
    parser.add_argument("--create-secret", action="store_true", help="Create a client secret and store it under .secrets for lab automation.")
    args = parser.parse_args(argv)

    tenant_id = named_tenant_id(args.tenant_id)
    if tenant_id is None:
        print("tenant_id_required: --tenant-id must be the lab tenant GUID (the all-zero placeholder is refused).", file=sys.stderr)
        return 2
    args.tenant_id = tenant_id
    directory = None
    if not args.dry_run:
        # One token for the named tenant makes every directory call; prove its tenant before the first write.
        try:
            directory = Directory(tenant_token(tenant_id))
            directory.verify_tenant(tenant_id)
        except TenantRefused as exc:
            print(
                f"{exc.reason}: could not prove a Graph token for tenant {tenant_id}. "
                f"Run 'az login --tenant {tenant_id}' and retry. Nothing was changed.",
                file=sys.stderr,
            )
            return 3

    pending: dict = {}
    try:
        return populate(args, directory, pending)
    finally:
        # A run that staged a secret file but never committed it removes only its own staging file.
        if pending.get("fd") is not None:
            os.close(pending["fd"])
        if pending.get("staged") is not None:
            pending["staged"].unlink(missing_ok=True)


def populate(args: argparse.Namespace, directory: Directory | None, pending: dict) -> int:
    cfg = json.loads(args.config.read_text(encoding="utf-8"))
    app_name = cfg["appDisplayName"]
    manifest_path = args.config.parent.parent / ".secrets" / "lab-populator-app.json"
    ensure_private_dir(manifest_path.parent)
    secret_path = args.config.parent.parent / ".secrets" / "lab-populator-app-secret.json"
    if args.create_secret and not args.dry_run:
        # Check the local destination before any directory write, so a refused destination never
        # leaves an issued credential unstored.
        try:
            secret_fd, staged = stage_secret_file(secret_path)
            pending.update(fd=secret_fd, staged=staged)
        except OSError as exc:
            print(f"secret_path_refused: cannot store the secret at {secret_path.name}: {exc.strerror}. Nothing was changed.", file=sys.stderr)
            return 4

    permission_requests = [
        (permission, "Role")
        for permission in cfg.get("applicationPermissions", [])
    ] + [
        (permission, "Scope")
        for permission in cfg.get("delegatedPermissions", [])
    ]
    if args.dry_run or directory is None:
        planned_permissions = [
            {"permission": permission, "id": "DRY-RUN", "type": requested_type, "available": True}
            for permission, requested_type in permission_requests
        ]
        return finish(args, manifest_path, secret_path, app_name, "DRY-RUN-APP-ID", planned_permissions, False)

    found = directory.call(
        "GET",
        f"/applications?$filter=displayName eq '{odata_literal(app_name)}'&$select=id,appId,requiredResourceAccess&$top=1",
    )
    app = (found.get("value") or [None])[0]
    if not app:
        app = directory.call(
            "POST",
            "/applications",
            {
                "displayName": app_name,
                "signInAudience": "AzureADMyOrg",
                "isFallbackPublicClient": True,
                "publicClient": {"redirectUris": cfg.get("redirectUris", ["http://localhost"])},
            },
        )
    app_object_id = str(app.get("id") or "")
    app_id = str(app.get("appId") or "")
    if not app_object_id or not app_id:
        raise RuntimeError("Graph did not return the populator app's ids.")

    # Some prior runs added duplicate requiredResourceAccess entries, which can hit Graph object size
    # limits; deduplicate the Graph entry while adding the requested permissions.
    required_access: list[dict] = []
    graph_access: OrderedDict = OrderedDict()
    changed = False
    for entry in app.get("requiredResourceAccess", []):
        if entry.get("resourceAppId") != GRAPH_APP_ID:
            required_access.append(entry)
            continue
        for permission in entry.get("resourceAccess", []):
            permission_id = permission.get("id")
            permission_type = permission.get("type")
            if not permission_id or not permission_type:
                continue
            if (permission_id, permission_type) in graph_access:
                changed = True
            graph_access[(permission_id, permission_type)] = permission

    graph_sp_id, permission_map = graph_permission_map(directory)
    planned_permissions = []
    consent_roles: list[str] = []
    consent_scopes: list[str] = []
    for permission, requested_type in permission_requests:
        permission_ref = permission_map.get((permission, requested_type))
        if permission_ref is None:
            planned_permissions.append({"permission": permission, "id": "", "type": requested_type, "available": False})
            continue
        planned_permissions.append({"permission": permission, **permission_ref, "available": True})
        if requested_type == "Role":
            consent_roles.append(permission_ref["id"])
        else:
            consent_scopes.append(permission)
        key = (permission_ref["id"], permission_ref["type"])
        if key not in graph_access:
            graph_access[key] = {"id": permission_ref["id"], "type": permission_ref["type"]}
            changed = True
    if changed:
        required_access.append({"resourceAppId": GRAPH_APP_ID, "resourceAccess": list(graph_access.values())})
        directory.call("PATCH", f"/applications/{app_object_id}", {"requiredResourceAccess": required_access})

    if args.admin_consent:
        grant_admin_consent(directory, app_id, graph_sp_id, consent_roles, consent_scopes)

    secret_stored = False
    if args.create_secret:
        # addPassword always adds a credential; existing ones on the app are kept.
        secret = directory.call(
            "POST",
            f"/applications/{app_object_id}/addPassword",
            {
                "passwordCredential": {
                    "displayName": SECRET_DISPLAY_NAME,
                    "endDateTime": (datetime.now(UTC) + timedelta(days=365)).isoformat(),
                }
            },
        )
        secret_payload = {
            "createdAt": utc_now(),
            "tenantId": args.tenant_id,
            "appId": app_id,
            "password": secret.get("secretText"),
            "endDateTime": secret.get("endDateTime"),
        }
        secret_fd, staged = pending.pop("fd"), pending["staged"]
        commit_secret_file(secret_fd, staged, secret_path, json.dumps(secret_payload, indent=2, sort_keys=True))
        pending.pop("staged")
        secret_stored = True

    return finish(args, manifest_path, secret_path, app_name, app_id, planned_permissions, secret_stored)


def finish(
    args: argparse.Namespace,
    manifest_path: Path,
    secret_path: Path,
    app_name: str,
    app_id: str,
    planned_permissions: list[dict],
    secret_stored: bool,
) -> int:
    manifest = {
        "generatedAt": utc_now(),
        "dryRun": args.dry_run,
        "appDisplayName": app_name,
        "appId": app_id,
        "tenantId": args.tenant_id,
        "permissions": planned_permissions,
        "adminConsentAttempted": bool(args.admin_consent),
        "secretStored": secret_stored,
        "secretPath": str(secret_path.relative_to(args.config.parent.parent)) if secret_stored else None,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
