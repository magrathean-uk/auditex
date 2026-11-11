#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import OrderedDict
from datetime import UTC, datetime
from pathlib import Path

GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def run_az(args: list[str], *, dry_run: bool) -> dict:
    command = ["az", *args]
    if dry_run:
        return {"dryRun": True, "command": command}
    proc = subprocess.run(command, check=False, capture_output=True, text=True, timeout=180)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout).strip() or f"az command failed: {' '.join(command)}")
    if not proc.stdout.strip():
        return {}
    return json.loads(proc.stdout)


def graph_permission_map(*, dry_run: bool) -> dict[tuple[str, str], dict[str, str]]:
    sp = run_az(["ad", "sp", "show", "--id", GRAPH_APP_ID, "--output", "json"], dry_run=dry_run)
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


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Create or update the lab-only Microsoft Graph tenant populator app.")
    parser.add_argument("--config", type=Path, default=Path("configs/lab-populator-permissions.json"))
    parser.add_argument("--tenant-id", default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--admin-consent", action="store_true", help="Run az ad app permission admin-consent after adding permissions.")
    parser.add_argument("--create-secret", action="store_true", help="Create a client secret and store it under .secrets for lab automation.")
    args = parser.parse_args(argv)

    cfg = json.loads(args.config.read_text(encoding="utf-8"))
    app_name = cfg["appDisplayName"]
    manifest_path = args.config.parent.parent / ".secrets" / "lab-populator-app.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)

    existing = run_az(
        ["ad", "app", "list", "--display-name", app_name, "--query", "[0]", "--output", "json"],
        dry_run=args.dry_run,
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
            )
            app = run_az(["ad", "app", "show", "--id", app_id, "--output", "json"], dry_run=False)
    permission_map = graph_permission_map(dry_run=args.dry_run)
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
            )

    if args.admin_consent and not args.dry_run:
        run_az(["ad", "app", "permission", "admin-consent", "--id", app_id, "--output", "json"], dry_run=False)

    secret_path = args.config.parent.parent / ".secrets" / "lab-populator-app-secret.json"
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
                    "--years",
                    "1",
                    "--output",
                    "json",
                ],
                dry_run=False,
            )
            secret_payload = {
                "createdAt": utc_now(),
                "tenantId": args.tenant_id,
                "appId": app_id,
                "password": secret.get("password"),
                "endDateTime": secret.get("endDateTime"),
            }
            secret_path.write_text(json.dumps(secret_payload, indent=2, sort_keys=True), encoding="utf-8")
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
