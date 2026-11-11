from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path

GRAPH_ROOT = "https://graph.microsoft.com/v1.0"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _truncate(value: str, limit: int = 8000) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 20] + "...[truncated]"


def _safe_graph_filter_value(value: str) -> str:
    return str(value).replace("'", "''")


def _safe_graph_mail_nickname(display_name: str) -> str:
    value = "".join(ch for ch in display_name.lower() if ch.isalnum())
    return (value or f"group{datetime.now().strftime('%Y%m%d%H%M%S')}")[:56]


def _first_value(client, path: str) -> dict | None:
    body = client.request("GET", path)
    values = body.get("value", [])
    return values[0] if values else None


def build_windows365_plan(cfg: dict) -> dict:
    windows365_cfg = cfg.get("windows365", {})
    licenses_cfg = cfg.get("licenses", {})
    return {
        "enabled": bool(windows365_cfg.get("enabled", False)),
        "pilotUserAlias": windows365_cfg.get("phase1PilotUser")
        or licenses_cfg.get("cloudPcBusinessUser")
        or cfg.get("actors", {}).get("dailyUser"),
        "preferredSkuPattern": licenses_cfg.get("cloudPcEnterprise", ""),
        "fallbackSkuPattern": licenses_cfg.get("cloudPcBusiness", ""),
        "joinType": windows365_cfg.get("joinType", "entraHosted"),
        "networkType": windows365_cfg.get("networkType", "microsoftHosted"),
        "allowBusinessEnrollment": bool(windows365_cfg.get("allowBusinessEnrollment", False)),
        "policyDisplayName": windows365_cfg.get("policyDisplayName", "W365-Enterprise-Pilot"),
        "policyDescription": windows365_cfg.get(
            "policyDescription",
            "Windows 365 Enterprise pilot policy created by tenant bootstrap.",
        ),
        "pilotGroupName": windows365_cfg.get("pilotGroupName", "GG-W365-Enterprise-Pilot"),
        "regionName": windows365_cfg.get("regionName", "eastus"),
        "locale": windows365_cfg.get("locale", "en-US"),
        "imageType": windows365_cfg.get("imageType", "gallery"),
        "imageId": windows365_cfg.get("imageId", "microsoftwindowsdesktop_windows-ent-cpc_win11-24H2-ent-cpc"),
        "imageDisplayName": windows365_cfg.get("imageDisplayName", "Windows 11 Enterprise 24H2"),
        "cloudPcNamingTemplate": windows365_cfg.get("cloudPcNamingTemplate", "CPC-%USERNAME:4%"),
        "provisioningType": windows365_cfg.get("provisioningType", "dedicated"),
        "pollTimeoutSeconds": int(windows365_cfg.get("pollTimeoutSeconds", 180)),
        "pollIntervalSeconds": int(windows365_cfg.get("pollIntervalSeconds", 30)),
        "managedDeviceTarget": _resolve_windows365_device_target(cfg),
        "managedDeviceTargets": {
            "phase1": _resolve_windows365_device_target(cfg, phase="phase1"),
            "phase2": _resolve_windows365_device_target(cfg, phase="phase2"),
            "final": _resolve_windows365_device_target(cfg, phase="final"),
        },
    }


def _resolve_windows365_device_target(cfg: dict, *, phase: str = "phase1") -> int:
    devices_cfg = cfg.get("devices", {})
    key_map = {
        "phase1": "managedTargetPhase1",
        "phase2": "managedTargetPhase2",
        "final": "managedTargetFinal",
    }
    key = key_map.get(phase, key_map["phase1"])
    fallback = {
        "managedTargetPhase1": 1,
        "managedTargetPhase2": 10,
        "managedTargetFinal": int(devices_cfg.get("windows11Seed", 0))
        + int(devices_cfg.get("macosSeed", 0))
        + int(devices_cfg.get("iosSeed", 0))
        + int(devices_cfg.get("androidSeed", 0)),
    }
    return int(devices_cfg.get(key, fallback[key]))


def _sku_availability_rows(client) -> list[dict]:
    rows = []
    for sku in client.request("GET", "/subscribedSkus").get("value", []):
        prepaid = sku.get("prepaidUnits", {}) or {}
        enabled = int(prepaid.get("enabled") or 0)
        consumed = int(sku.get("consumedUnits") or 0)
        rows.append(
            {
                "skuPartNumber": sku.get("skuPartNumber"),
                "skuId": sku.get("skuId"),
                "enabled": enabled,
                "consumed": consumed,
                "available": max(enabled - consumed, 0),
            }
        )
    return rows


def _select_windows365_sku(client, cfg: dict) -> dict | None:
    plan = build_windows365_plan(cfg)
    sku_rows = _sku_availability_rows(client)
    preferred = str(plan.get("preferredSkuPattern") or "").lower()
    fallback = str(plan.get("fallbackSkuPattern") or "").lower()

    def _match(pattern: str) -> dict | None:
        if not pattern:
            return None
        for row in sku_rows:
            if pattern in str(row.get("skuPartNumber", "")).lower():
                return row
        return None

    preferred_row = _match(preferred)
    if preferred_row and int(preferred_row.get("available", 0)) > 0:
        return preferred_row
    if bool(plan.get("allowBusinessEnrollment")):
        fallback_row = _match(fallback)
        if fallback_row and int(fallback_row.get("available", 0)) > 0:
            return fallback_row
    return preferred_row or (_match(fallback) if fallback else None)


def _build_windows365_policy_payload(plan: dict) -> dict:
    return {
        "@odata.type": "#microsoft.graph.cloudPcProvisioningPolicy",
        "description": plan["policyDescription"],
        "displayName": plan["policyDisplayName"],
        "cloudPcNamingTemplate": plan["cloudPcNamingTemplate"],
        "domainJoinConfigurations": [
            {
                "domainJoinType": "azureADJoin",
                "regionName": plan["regionName"],
            }
        ],
        "enableSingleSignOn": True,
        "imageDisplayName": plan["imageDisplayName"],
        "imageId": plan["imageId"],
        "imageType": plan["imageType"],
        "windowsSetting": {
            "locale": plan["locale"],
        },
        "provisioningType": plan["provisioningType"],
    }


def _build_windows365_assignment_payload(group_id: str) -> dict:
    return {
        "assignments": [
            {
                "target": {
                    "@odata.type": "microsoft.graph.cloudPcManagementGroupAssignmentTarget",
                    "groupId": group_id,
                }
            }
        ]
    }


def _ensure_security_group(
    client,
    logger,
    *,
    display_name: str,
    dry_run: bool,
) -> dict:
    existing = _first_value(client, f"/groups?$filter=displayName eq '{_safe_graph_filter_value(display_name)}'&$select=id,displayName")
    if existing:
        logger.event("group.exists", "success", group=display_name, id=existing.get("id"))
        return existing

    payload = {
        "displayName": display_name,
        "mailEnabled": False,
        "mailNickname": _safe_graph_mail_nickname(display_name),
        "securityEnabled": True,
    }
    if dry_run:
        logger.event("group.wouldCreate", "success", group=display_name)
        return {"id": f"DRY-RUN-{display_name}", "displayName": display_name}

    created = client.request("POST", "/groups", payload=payload)
    logger.event("group.created", "success", group=display_name, id=created.get("id"))
    return created


def assign_direct_cloud_pc_license(
    client,
    logger,
    cfg: dict,
    dry_run: bool,
) -> dict:
    plan = build_windows365_plan(cfg)
    sku = _select_windows365_sku(client, cfg)
    sku_pattern = sku.get("skuPartNumber") if sku else plan.get("preferredSkuPattern")
    target_alias = plan.get("pilotUserAlias")
    summary = {
        "pilotUserAlias": target_alias,
        "selectedSku": sku_pattern,
        "selectedSkuId": sku.get("skuId") if sku else None,
        "licenseAssigned": False,
        "reason": "",
    }
    if not sku_pattern or not target_alias:
        logger.event("license.cloudpc.skip", "success", reason="not-configured")
        summary["reason"] = "not-configured"
        return summary

    domain = cfg.get("tenant", {}).get("tenantDomain")
    target_upn = target_alias if "@" in str(target_alias) else f"{target_alias}@{domain}"
    user = _first_value(
        client,
        f"/users?$filter=userPrincipalName eq '{_safe_graph_filter_value(target_upn)}'&$select=id,userPrincipalName,assignedLicenses",
    )
    if not user:
        logger.event("license.cloudpc.skip", "warn", reason="target-user-missing", userPrincipalName=target_upn)
        if dry_run:
            summary["reason"] = "dry-run"
            summary["licenseAssigned"] = False
            return summary
        summary["reason"] = "target-user-missing"
        return summary
    if not sku:
        logger.event("license.cloudpc.skip", "warn", reason="sku-not-found", sku=sku_pattern, userPrincipalName=target_upn)
        summary["reason"] = "sku-not-found"
        return summary
    sku_id = sku["skuId"]
    if any(assigned.get("skuId") == sku_id for assigned in user.get("assignedLicenses", []) or []):
        logger.event("license.cloudpc.alreadyAssigned", "success", userPrincipalName=target_upn, sku=sku_pattern)
        summary["licenseAssigned"] = True
        summary["reason"] = "already-assigned"
        return summary

    available = int(sku.get("available", 0))
    if available < 1:
        logger.event("license.cloudpc.skip", "warn", reason="no-available-seats", userPrincipalName=target_upn, sku=sku_pattern)
        summary["reason"] = "no-available-seats"
        return summary

    if dry_run:
        logger.event("license.cloudpc.wouldAssign", "success", userPrincipalName=target_upn, sku=sku_pattern)
        summary["reason"] = "dry-run"
        return summary

    payload = {"addLicenses": [{"skuId": sku_id, "disabledPlans": []}], "removeLicenses": []}
    client.request("POST", f"/users/{user['id']}/assignLicense", payload=payload)
    logger.event("license.cloudpc.assigned", "success", userPrincipalName=target_upn, sku=sku_pattern)
    summary["licenseAssigned"] = True
    summary["reason"] = "assigned"
    return summary


def _resolve_windows365_pilot_user(client, cfg: dict, plan: dict) -> dict | None:
    alias = plan.get("pilotUserAlias")
    domain = cfg.get("tenant", {}).get("tenantDomain")
    if not alias or not domain:
        return None
    upn = alias if "@" in str(alias) else f"{alias}@{domain}"
    return _first_value(
        client,
        f"/users?$filter=userPrincipalName eq '{_safe_graph_filter_value(upn)}'&$select=id,userPrincipalName,displayName,assignedLicenses",
    )


def _select_windows365_gallery_image(client, logger, plan: dict) -> dict:
    configured_id = str(plan.get("imageId") or "").strip()
    configured_name = str(plan.get("imageDisplayName") or "").strip()
    body = client.request(
        "GET",
        "/deviceManagement/virtualEndpoint/galleryImages?$select=id,displayName,status,expirationDate",
        allow_failure=True,
    )
    if body.get("error"):
        logger.event("windows365.galleryImages.lookup.failed", "warn", reason="graph-access-denied")
        return {
            "id": configured_id,
            "displayName": configured_name,
            "selectionReason": "configured-fallback",
        }

    images = [item for item in body.get("value", []) if str(item.get("status", "")).lower() == "supported"]
    if configured_id:
        for image in images:
            if str(image.get("id")) == configured_id:
                logger.event("windows365.galleryImages.selected", "success", imageId=configured_id, reason="configured")
                return {
                    "id": configured_id,
                    "displayName": str(image.get("displayName") or configured_name),
                    "selectionReason": "configured",
                }

    if not images:
        logger.event("windows365.galleryImages.selected", "warn", imageId=configured_id, reason="configured-fallback-no-gallery")
        return {
            "id": configured_id,
            "displayName": configured_name,
            "selectionReason": "configured-fallback",
        }

    images.sort(
        key=lambda item: (
            str(item.get("expirationDate") or ""),
            str(item.get("displayName") or ""),
        ),
        reverse=True,
    )
    selected = images[0]
    logger.event(
        "windows365.galleryImages.selected",
        "success",
        imageId=selected.get("id"),
        displayName=selected.get("displayName"),
        reason="latest-supported",
    )
    return {
        "id": str(selected.get("id") or configured_id),
        "displayName": str(selected.get("displayName") or configured_name),
        "selectionReason": "latest-supported",
    }


def _ensure_windows365_provisioning_policy(
    client,
    logger,
    plan: dict,
    *,
    dry_run: bool,
) -> dict:
    display_name = plan["policyDisplayName"]
    existing = _first_value(
        client,
        f"/deviceManagement/virtualEndpoint/provisioningPolicies?$filter=displayName eq '{_safe_graph_filter_value(display_name)}'&$select=id,displayName,description",
    )
    if existing:
        logger.event("windows365.policy.exists", "success", policy=display_name, id=existing.get("id"))
        return {"policy": existing, "created": False}

    payload = _build_windows365_policy_payload(plan)
    if dry_run:
        logger.event("windows365.policy.wouldCreate", "success", policy=display_name)
        return {
            "policy": {
                "id": f"DRY-RUN-POLICY-{display_name}",
                "displayName": display_name,
            },
            "created": False,
        }

    created = client.request("POST", "/deviceManagement/virtualEndpoint/provisioningPolicies", payload=payload)
    logger.event("windows365.policy.created", "success", policy=display_name, id=created.get("id"))
    return {"policy": created, "created": True}


def _ensure_windows365_policy_assignment(
    client,
    logger,
    *,
    policy_id: str,
    policy_name: str,
    group_id: str,
    group_name: str,
    dry_run: bool,
) -> dict:
    existing = client.request(
        "GET",
        f"/deviceManagement/virtualEndpoint/provisioningPolicies/{policy_id}/assignments?$expand=target",
        allow_failure=True,
    )
    if not existing.get("error"):
        for assignment in existing.get("value", []):
            target = assignment.get("target", {}) or {}
            if str(target.get("groupId")) == group_id:
                logger.event("windows365.assignment.exists", "success", policy=policy_name, group=group_name)
                return {"assigned": True, "reason": "already-assigned"}

    if dry_run:
        logger.event("windows365.assignment.wouldCreate", "success", policy=policy_name, group=group_name)
        return {"assigned": True, "reason": "dry-run"}

    client.request(
        "POST",
        f"/deviceManagement/virtualEndpoint/provisioningPolicies/{policy_id}/assign",
        payload=_build_windows365_assignment_payload(group_id),
    )
    logger.event("windows365.assignment.created", "success", policy=policy_name, group=group_name)
    return {"assigned": True, "reason": "assigned"}


def _find_windows365_cloud_pc(client, user_principal_name: str) -> dict | None:
    return _first_value(
        client,
        f"/deviceManagement/virtualEndpoint/cloudPCs?$filter=userPrincipalName eq '{_safe_graph_filter_value(user_principal_name)}'&$select=id,displayName,userPrincipalName,provisioningPolicyId,managedDeviceId,managedDeviceName,status,servicePlanName",
    )


def _poll_windows365_cloud_pc(
    client,
    logger,
    *,
    user_principal_name: str,
    timeout_seconds: int,
    interval_seconds: int,
    dry_run: bool,
) -> dict:
    if dry_run:
        logger.event("windows365.cloudpc.poll.skipped", "success", reason="dry-run", userPrincipalName=user_principal_name)
        return {"cloudPc": None, "pollState": "dry-run", "attempts": 0}

    deadline = time.monotonic() + max(timeout_seconds, 0)
    attempts = 0
    while True:
        attempts += 1
        cloud_pc = _find_windows365_cloud_pc(client, user_principal_name)
        if cloud_pc:
            status = str(cloud_pc.get("status") or "unknown")
            logger.event(
                "windows365.cloudpc.discovered",
                "success",
                userPrincipalName=user_principal_name,
                status=status,
                id=cloud_pc.get("id"),
            )
            return {"cloudPc": cloud_pc, "pollState": "found", "attempts": attempts}
        if time.monotonic() >= deadline:
            logger.event("windows365.cloudpc.pending", "warn", userPrincipalName=user_principal_name, attempts=attempts)
            return {"cloudPc": None, "pollState": "pending", "attempts": attempts}
        time.sleep(max(interval_seconds, 1))


def emit_windows365_provisioning_artifact(run_dir: Path, logger, payload: dict) -> str:
    artifact = run_dir / "windows365-provisioning-manifest.json"
    artifact.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    logger.event("windows365.provisioning.artifact", "success", artifact=str(artifact))
    return str(artifact)


def emit_windows365_diagnostic(
    client,
    logger,
    cfg: dict,
    run_dir: Path,
    claims: dict,
    *,
    dry_run: bool,
) -> dict:
    artifact = run_dir / "windows365-readiness-manifest.json"
    required_scope_hints = [
        "CloudPC.Read.All",
        "CloudPC.ReadWrite.All",
        "DeviceManagementManagedDevices.Read.All",
        "DeviceManagementConfiguration.Read.All",
    ]
    plan = build_windows365_plan(cfg)
    payload = {
        "generatedAt": _utc_now(),
        "plan": plan,
        "token": {
            "appId": claims.get("appid"),
            "user": claims.get("upn") or claims.get("unique_name"),
            "scopes": str(claims.get("scp") or ""),
            "roles": claims.get("roles"),
        },
        "requiredScopeHints": required_scope_hints,
        "skuAvailability": _sku_availability_rows(client) if not dry_run else [],
        "checks": [],
    }
    if dry_run:
        payload["checks"].append({"name": "cloudPCs", "status": "skipped", "reason": "dry-run"})
        payload["checks"].append({"name": "provisioningPolicies", "status": "skipped", "reason": "dry-run"})
    else:
        for name, path in [
            ("cloudPCs", "/deviceManagement/virtualEndpoint/cloudPCs?$top=10"),
            (
                "provisioningPolicies",
                "/deviceManagement/virtualEndpoint/provisioningPolicies?$top=20",
            ),
            ("userSettings", "/deviceManagement/virtualEndpoint/userSettings?$top=20"),
        ]:
            body = client.request("GET", path, allow_failure=True)
            if body.get("error"):
                payload["checks"].append({"name": name, "status": "warn", "error": body.get("error")})
                logger.event("windows365.visibility.blocked", "warn", check=name, reason="graph-access-denied")
            else:
                payload["checks"].append({"name": name, "status": "success", "count": len(body.get("value", []))})
                logger.event("windows365.visibility", "success", check=name, count=len(body.get("value", [])))
    artifact.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    logger.event("windows365.readiness.artifact", "success", artifact=str(artifact))
    return payload


def emit_windows365_blocker_artifact(run_dir: Path, logger, payload: dict) -> str:
    artifact = run_dir / "windows365-blocker-manifest.json"
    artifact.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    logger.event("windows365.blocker.artifact", "warn", artifact=str(artifact))
    return str(artifact)


def _ensure_directory_object_member(
    client,
    logger,
    group_id: str,
    group_name: str,
    object_id: str,
    *,
    dry_run: bool,
) -> None:
    if not group_id or not object_id:
        return
    try:
        member_check = client.request(
            "GET",
            f"/groups/{group_id}/members/$count?$filter=id eq '{object_id}'",
        )
        if member_check.get("@odata.count") == 1 or member_check.get("value") == 1:
            logger.event("device.group_member.exists", "success", group=group_name, objectId=object_id)
            return
    except Exception as exc:  # noqa: BLE001
        logger.event("device.group_member.check.skipped", "warn", group=group_name, objectId=object_id, reason=str(exc)[:200])

    if dry_run:
        logger.event("device.group_member.wouldCreate", "success", group=group_name, objectId=object_id)
        return

    payload = {"@odata.id": f"{GRAPH_ROOT}/directoryObjects/{object_id}"}
    try:
        client.request("POST", f"/groups/{group_id}/members/$ref", payload=payload)
        logger.event("device.group_member.added", "success", group=group_name, objectId=object_id)
    except Exception as exc:  # noqa: BLE001
        msg = str(exc).lower()
        if "already exists" in msg or "one or more added objects" in msg:
            logger.event("device.group_member.exists", "success", group=group_name, objectId=object_id)
        else:
            logger.event("device.group_member.failed", "warn", group=group_name, objectId=object_id, reason=msg[:240])


def seed_windows365(
    client,
    logger,
    cfg: dict,
    run_dir: Path,
    claims: dict,
    *,
    dry_run: bool,
) -> dict:
    plan = build_windows365_plan(cfg)
    summary = {
        "enabled": bool(plan.get("enabled")),
        "managedDeviceTarget": int(plan.get("managedDeviceTarget", 0)),
        "pilotUserAlias": plan.get("pilotUserAlias"),
        "selectedSku": None,
        "licenseAssigned": False,
        "artifact": "windows365-readiness-manifest.json",
        "provisioningArtifact": None,
        "blockerArtifact": None,
        "status": "skipped",
        "blockers": [],
        "pilotUserPrincipalName": None,
        "pilotGroupName": plan.get("pilotGroupName"),
        "pilotGroupId": None,
        "policyDisplayName": plan.get("policyDisplayName"),
        "policyId": None,
        "policyAssigned": False,
        "cloudPcId": None,
        "cloudPcStatus": None,
        "managedDeviceId": None,
    }
    if not summary["enabled"]:
        logger.event("windows365.skip", "success", reason="not-configured")
        summary["status"] = "disabled"
        return summary

    readiness = emit_windows365_diagnostic(client, logger, cfg, run_dir, claims, dry_run=dry_run)
    sku = _select_windows365_sku(client, cfg) if not dry_run else None
    summary["selectedSku"] = sku.get("skuPartNumber") if sku else plan.get("preferredSkuPattern")
    blocked_checks = [
        check
        for check in readiness.get("checks", [])
        if check.get("status") not in {"success", "skipped"} and check.get("name") in {"cloudPCs", "provisioningPolicies"}
    ]
    if blocked_checks:
        summary["status"] = "blocked"
        summary["blockers"] = [check.get("name") for check in blocked_checks]
        summary["blockerArtifact"] = emit_windows365_blocker_artifact(
            run_dir,
            logger,
            {
                "generatedAt": _utc_now(),
                "plan": plan,
                "selectedSku": summary["selectedSku"],
                "checks": blocked_checks,
                "reason": "windows365-api-not-ready",
            },
        )
        return summary

    license_summary = assign_direct_cloud_pc_license(client, logger, cfg, dry_run)
    summary["licenseAssigned"] = bool(license_summary.get("licenseAssigned"))
    summary["selectedSku"] = license_summary.get("selectedSku") or summary["selectedSku"]
    if not summary["licenseAssigned"] and str(license_summary.get("reason") or "") not in {"already-assigned", "dry-run"}:
        summary["status"] = "blocked"
        summary["blockers"] = ["license"]
        summary["blockerArtifact"] = emit_windows365_blocker_artifact(
            run_dir,
            logger,
            {
                "generatedAt": _utc_now(),
                "plan": plan,
                "selectedSku": summary["selectedSku"],
                "license": license_summary,
                "reason": "windows365-license-not-ready",
            },
        )
        return summary

    user = _resolve_windows365_pilot_user(client, cfg, plan)
    if not user:
        if dry_run:
            domain = cfg.get("tenant", {}).get("tenantDomain") or ""
            if plan.get("pilotUserAlias"):
                pilot_alias = str(plan["pilotUserAlias"])
                summary["pilotUserPrincipalName"] = (
                    pilot_alias
                    if "@" in pilot_alias
                    else f"{pilot_alias}@{domain}" if domain else pilot_alias
                )
            logger.event("windows365.pilotUser.skipped", "warn", reason="dry-run", userPrincipalName=summary["pilotUserPrincipalName"])
            user = {"id": "", "userPrincipalName": summary["pilotUserPrincipalName"], "displayName": ""}
        else:
            summary["status"] = "blocked"
            summary["blockers"] = ["pilot-user"]
            summary["blockerArtifact"] = emit_windows365_blocker_artifact(
                run_dir,
                logger,
                {
                    "generatedAt": _utc_now(),
                    "plan": plan,
                    "selectedSku": summary["selectedSku"],
                    "reason": "windows365-pilot-user-missing",
                },
            )
            return summary
    else:
        summary["pilotUserPrincipalName"] = user.get("userPrincipalName")

    if str(plan.get("joinType")) != "entraHosted" or str(plan.get("networkType")) != "microsoftHosted":
        summary["status"] = "blocked"
        summary["blockers"] = ["unsupported-join-plan"]
        summary["blockerArtifact"] = emit_windows365_blocker_artifact(
            run_dir,
            logger,
            {
                "generatedAt": _utc_now(),
                "plan": plan,
                "selectedSku": summary["selectedSku"],
                "reason": "windows365-join-plan-not-implemented",
            },
        )
        return summary

    pilot_group = _ensure_security_group(client, logger, display_name=plan["pilotGroupName"], dry_run=dry_run)
    summary["pilotGroupId"] = pilot_group.get("id")
    _ensure_directory_object_member(
        client,
        logger,
        pilot_group.get("id", ""),
        plan["pilotGroupName"],
        user.get("id", ""),
        dry_run=dry_run,
    )

    image = _select_windows365_gallery_image(client, logger, plan)
    effective_plan = dict(plan)
    if image.get("id"):
        effective_plan["imageId"] = image["id"]
    if image.get("displayName"):
        effective_plan["imageDisplayName"] = image["displayName"]

    try:
        policy_result = _ensure_windows365_provisioning_policy(client, logger, effective_plan, dry_run=dry_run)
        policy = policy_result["policy"]
        summary["policyId"] = policy.get("id")
        assign_result = _ensure_windows365_policy_assignment(
            client,
            logger,
            policy_id=policy.get("id", ""),
            policy_name=effective_plan["policyDisplayName"],
            group_id=pilot_group.get("id", ""),
            group_name=plan["pilotGroupName"],
            dry_run=dry_run,
        )
        summary["policyAssigned"] = bool(assign_result.get("assigned"))
        cloud_pc_result = _poll_windows365_cloud_pc(
            client,
            logger,
            user_principal_name=str(user.get("userPrincipalName") or ""),
            timeout_seconds=int(plan.get("pollTimeoutSeconds", 180)),
            interval_seconds=int(plan.get("pollIntervalSeconds", 30)),
            dry_run=dry_run,
        )
    except RuntimeError as exc:
        summary["status"] = "blocked"
        summary["blockers"] = ["provisioning"]
        summary["blockerArtifact"] = emit_windows365_blocker_artifact(
            run_dir,
            logger,
            {
                "generatedAt": _utc_now(),
                "plan": effective_plan,
                "selectedSku": summary["selectedSku"],
                "pilotUserPrincipalName": summary["pilotUserPrincipalName"],
                "pilotGroupId": summary["pilotGroupId"],
                "reason": "windows365-provisioning-failed",
                "error": str(exc),
            },
        )
        return summary

    cloud_pc = cloud_pc_result.get("cloudPc") or {}
    summary["cloudPcId"] = cloud_pc.get("id")
    summary["cloudPcStatus"] = cloud_pc.get("status")
    summary["managedDeviceId"] = cloud_pc.get("managedDeviceId")
    summary["provisioningArtifact"] = Path(
        emit_windows365_provisioning_artifact(
            run_dir,
            logger,
            {
                "generatedAt": _utc_now(),
                "plan": effective_plan,
                "selectedSku": summary["selectedSku"],
                "license": license_summary,
                "pilotUser": {
                    "id": user.get("id"),
                    "userPrincipalName": user.get("userPrincipalName"),
                    "displayName": user.get("displayName"),
                },
                "pilotGroup": pilot_group,
                "policy": policy,
                "assignment": {
                    "groupId": pilot_group.get("id"),
                    "groupName": plan["pilotGroupName"],
                    "assigned": summary["policyAssigned"],
                },
                "galleryImage": image,
                "cloudPc": cloud_pc_result,
            },
        )
    ).name

    if dry_run:
        summary["status"] = "ready"
    elif summary["managedDeviceId"]:
        summary["status"] = "provisioned"
    elif summary["cloudPcId"]:
        summary["status"] = "provisioning"
    else:
        summary["status"] = "prepared"
    return summary
