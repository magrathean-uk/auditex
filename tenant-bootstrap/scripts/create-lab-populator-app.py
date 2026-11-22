#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import uuid
from collections import OrderedDict
from datetime import UTC, datetime
from pathlib import Path

GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
PLACEHOLDER_TENANT_ID = "00000000-0000-0000-0000-000000000000"


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


class TenantChanged(RuntimeError):
    """The signed-in Azure CLI tenant is no longer the named lab tenant."""


def open_owner_only(path: Path) -> int:
    """Open a secret file as 0600 without truncating it; never follow a symlink at the final path."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    os.fchmod(fd, 0o600)
    return fd


def write_owner_only_fd(fd: int, text: str) -> None:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.truncate(0)
        handle.write(text)


def ensure_private_dir(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def run_az(args: list[str], *, dry_run: bool, tenant_id: str | None = None) -> dict:
    command = ["az", *args]
    if dry_run:
        return {"dryRun": True, "command": command}
    # az ad commands take no --tenant and act in whatever tenant is signed in at that moment, so
    # check it again right before every call: a switch after the start check stops the run.
    if tenant_id is not None and signed_in_tenant_id() != tenant_id:
        raise TenantChanged(tenant_id)
    proc = subprocess.run(command, check=False, capture_output=True, text=True, timeout=180)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout).strip() or f"az command failed: {' '.join(command)}")
    if not proc.stdout.strip():
        return {}
    return json.loads(proc.stdout)


def graph_permission_map(*, dry_run: bool, tenant_id: str | None = None) -> dict[tuple[str, str], dict[str, str]]:
    sp = run_az(["ad", "sp", "show", "--id", GRAPH_APP_ID, "--output", "json"], dry_run=dry_run, tenant_id=tenant_id)
    if dry_run:
        return {}
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
    return mapping


def named_tenant_id(raw: str) -> str | None:
    """Return the lab tenant GUID, or None for a malformed or all-zero placeholder value."""
    try:
        tenant_id = str(uuid.UUID(raw.strip()))
    except ValueError:
        return None
    if tenant_id != raw.strip().lower() or tenant_id == PLACEHOLDER_TENANT_ID:
        return None
    return tenant_id


def signed_in_tenant_id() -> str:
    proc = subprocess.run(
        ["az", "account", "show", "--query", "tenantId", "--output", "tsv"],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return proc.stdout.strip().lower() if proc.returncode == 0 else ""


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Create or update the lab-only Microsoft Graph tenant populator app.",
        allow_abbrev=False,
    )
    parser.add_argument("--config", type=Path, default=Path("configs/lab-populator-permissions.json"))
    parser.add_argument(
        "--tenant-id",
        required=True,
        help="Lab tenant GUID. Every az call runs only when the signed-in Azure CLI tenant equals it.",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--admin-consent", action="store_true", help="Run az ad app permission admin-consent after adding permissions.")
    parser.add_argument("--create-secret", action="store_true", help="Create a client secret and store it under .secrets for lab automation.")
    args = parser.parse_args(argv)

    tenant_id = named_tenant_id(args.tenant_id)
    if tenant_id is None:
        print("tenant_id_required: --tenant-id must be the lab tenant GUID (the all-zero placeholder is refused).", file=sys.stderr)
        return 2
    args.tenant_id = tenant_id
    # az ad commands act in the signed-in tenant and take no --tenant, so refuse any other tenant
    # before the first directory call.
    if not args.dry_run and signed_in_tenant_id() != tenant_id:
        print(
            f"tenant_mismatch: the Azure CLI is not signed in to tenant {tenant_id}. "
            f"Run 'az login --tenant {tenant_id}' and retry. Nothing was changed.",
            file=sys.stderr,
        )
        return 3

    try:
        return populate(args, tenant_id)
    except TenantChanged:
        print(
            f"tenant_mismatch: the Azure CLI is no longer signed in to tenant {tenant_id}; "
            "stopped before the next directory call.",
            file=sys.stderr,
        )
        return 3


def populate(args: argparse.Namespace, tenant_id: str) -> int:
    pinned = None if args.dry_run else tenant_id
    cfg = json.loads(args.config.read_text(encoding="utf-8"))
    app_name = cfg["appDisplayName"]
    manifest_path = args.config.parent.parent / ".secrets" / "lab-populator-app.json"
    ensure_private_dir(manifest_path.parent)
    secret_path = args.config.parent.parent / ".secrets" / "lab-populator-app-secret.json"
    secret_fd: int | None = None
    if args.create_secret and not args.dry_run:
        # Check the local destination before any directory write, so a refused destination never
        # leaves an issued credential unstored.
        try:
            secret_fd = open_owner_only(secret_path)
        except OSError as exc:
            print(f"secret_path_refused: cannot store the secret at {secret_path.name}: {exc.strerror}. Nothing was changed.", file=sys.stderr)
            return 4

    existing = run_az(
        ["ad", "app", "list", "--display-name", app_name, "--query", "[0]", "--output", "json"],
        dry_run=args.dry_run,
        tenant_id=pinned,
    )
    if args.dry_run or not existing:
        app = run_az(
            [
                "ad",
                "app",
                "create",
                "--display-name",
                app_name,
                "--sign-in-audience",
                "AzureADMyOrg",
                "--is-fallback-public-client",
                "true",
                "--public-client-redirect-uris",
                *cfg.get("redirectUris", ["http://localhost"]),
                "--output",
                "json",
            ],
            dry_run=args.dry_run,
            tenant_id=pinned,
        )
    else:
        app = existing

    app_id = app.get("appId") or "DRY-RUN-APP-ID"
    if not args.dry_run:
        # Some prior runs added duplicate requiredResourceAccess entries, which can cause
        # Graph object size limits to be hit when updating permissions. Deduplicate once
        # before processing incremental permission additions.
        normalized_resource_access = []
        changed = False
        for entry in app.get("requiredResourceAccess", []):
            resource_app_id = entry.get("resourceAppId")
            if resource_app_id != GRAPH_APP_ID:
                normalized_resource_access.append(entry)
                continue
            unique = OrderedDict()
            for permission in entry.get("resourceAccess", []):
                permission_id = permission.get("id")
                permission_type = permission.get("type")
                if not permission_id or not permission_type:
                    continue
                unique[(permission_id, permission_type)] = permission
            normalized = list(unique.values())
            if len(normalized) != len(entry.get("resourceAccess", [])):
                changed = True
            normalized_resource_access.append({
                "resourceAppId": resource_app_id,
                "resourceAccess": normalized,
            })
        if changed:
            run_az(
                [
                    "ad",
                    "app",
                    "update",
                    "--id",
                    app_id,
                    "--required-resource-access",
                    json.dumps(normalized_resource_access),
                ],
                dry_run=False,
                tenant_id=pinned,
            )
            app = run_az(["ad", "app", "show", "--id", app_id, "--output", "json"], dry_run=False, tenant_id=pinned)
    permission_map = graph_permission_map(dry_run=args.dry_run, tenant_id=pinned)
    existing_permissions = set()
    if not args.dry_run:
        for resource_access in app.get("requiredResourceAccess", []):
            if resource_access.get("resourceAppId") != GRAPH_APP_ID:
                continue
            for permission in resource_access.get("resourceAccess", []):
                permission_id = permission.get("id")
                permission_type = permission.get("type")
                if permission_id and permission_type:
                    existing_permissions.add((permission_id, permission_type))
    planned_permissions = []
    permission_requests = [
        (permission, "Role")
        for permission in cfg.get("applicationPermissions", [])
    ] + [
        (permission, "Scope")
        for permission in cfg.get("delegatedPermissions", [])
    ]
    for permission, requested_type in permission_requests:
        permission_ref = permission_map.get((permission, requested_type))
        if permission_ref is None:
            permission_ref = {"id": "DRY-RUN" if args.dry_run else "", "type": requested_type, "available": args.dry_run}
        else:
            permission_ref = {**permission_ref, "available": True}
        planned_permissions.append({"permission": permission, **permission_ref})
        if not permission_ref.get("available"):
            continue
        if (permission_ref["id"], permission_ref["type"]) in existing_permissions:
            continue
        if not args.dry_run:
            run_az(
                [
                    "ad",
                    "app",
                    "permission",
                    "add",
                    "--id",
                    app_id,
                    "--api",
                    GRAPH_APP_ID,
                    "--api-permissions",
                    f"{permission_ref['id']}={permission_ref['type']}",
                    "--output",
                    "json",
                ],
                dry_run=False,
                tenant_id=pinned,
            )

    if args.admin_consent and not args.dry_run:
        run_az(["ad", "app", "permission", "admin-consent", "--id", app_id, "--output", "json"], dry_run=False, tenant_id=pinned)

    secret_stored = False
    if args.create_secret:
        if args.dry_run:
            secret_stored = False
        else:
            secret = run_az(
                [
                    "ad",
                    "app",
                    "credential",
                    "reset",
                    "--id",
                    app_id,
                    "--display-name",
                    "codex-lab-populator",
                    "--append",
                    "--years",
                    "1",
                    "--output",
                    "json",
                ],
                dry_run=False,
                tenant_id=pinned,
            )
            secret_payload = {
                "createdAt": utc_now(),
                "tenantId": args.tenant_id,
                "appId": app_id,
                "password": secret.get("password"),
                "endDateTime": secret.get("endDateTime"),
            }
            write_owner_only_fd(secret_fd, json.dumps(secret_payload, indent=2, sort_keys=True))
            secret_fd = None
            secret_stored = True

    manifest = {
        "generatedAt": utc_now(),
        "dryRun": args.dry_run,
        "appDisplayName": app_name,
        "appId": app_id,
        "tenantId": args.tenant_id,
        "permissions": planned_permissions,
        "adminConsentAttempted": bool(args.admin_consent),
        "secretStored": secret_stored,
        "secretPath": str(secret_path.relative_to(args.config.parent.parent)) if secret_stored else None
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
