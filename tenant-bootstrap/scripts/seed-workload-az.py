#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
import subprocess
import sys
import time
import uuid
import shlex
import shutil
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path
from random import Random
from urllib.parse import quote

import requests


_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

import windows365_workload as windows365_workload


def _m365_subprocess_kwargs(command: list[str]) -> dict:
    """Run m365 with the private HOME that scripts/tenant-audit-login signs it in under.

    The rule lives in src/azure_tenant_audit/m365_home.py. It is loaded by path because importing the
    azure_tenant_audit package would pull in the whole audit runtime. Without that file, m365 runs unchanged.
    """
    helper = Path(__file__).resolve().parents[2] / "src" / "azure_tenant_audit" / "m365_home.py"
    if not helper.is_file():
        return {}
    spec = importlib.util.spec_from_file_location("auditex_m365_home", helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.m365_subprocess_kwargs(command)


GRAPH_ROOT = "https://graph.microsoft.com/v1.0"
GRAPH_RESOURCE = "https://graph.microsoft.com"
DEVICE_GROUPS = {
    "all": "GG-Endpoint-AllDevices",
    "windows": "GG-Endpoint-Windows11",
    "macos": "GG-Endpoint-macOS",
    "ios": "GG-Endpoint-iOS",
    "android": "GG-Endpoint-Android",
}
DEFAULT_INTERACTIVE_SCOPES = [
    "User.Read",
    "Directory.AccessAsUser.All",
    "User.Invite.All",
    "Directory.ReadWrite.All",
    "Policy.Read.All",
    "Policy.ReadWrite.SecurityDefaults",
    "Policy.ReadWrite.ConditionalAccess",
    "DeviceManagementConfiguration.ReadWrite.All",
    "DeviceManagementManagedDevices.Read.All",
    "Team.Create",
    "Team.ReadBasic.All",
    "Channel.Create",
    "Channel.ReadBasic.All",
    "Files.ReadWrite.All",
    "Sites.ReadWrite.All",
]


def _safe_graph_filter_value(value: str) -> str:
    return str(value).replace("'", "''")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _truncate(value: str, limit: int = 8000) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 20] + "...[truncated]"


def normalize_top(path: str, top: int | None) -> str:
    if top is None:
        return path
    if "$top=" in path or "&$top=" in path:
        return path
    if "?" in path:
        return f"{path}&$top={top}"
    return f"{path}?$top={top}"


def mail_nickname(display_name: str) -> str:
    value = "".join(ch for ch in display_name.lower() if ch.isalnum())
    return (value or f"group{datetime.now().strftime('%Y%m%d%H%M%S')}")[:56]


def _drop_empty_values(value):
    if isinstance(value, dict):
        cleaned = {}
        for key, child in value.items():
            normalized = _drop_empty_values(child)
            if normalized in ("", None):
                continue
            if isinstance(normalized, (dict, list)) and not normalized:
                continue
            cleaned[key] = normalized
        return cleaned
    if isinstance(value, list):
        cleaned = []
        for child in value:
            normalized = _drop_empty_values(child)
            if normalized in ("", None):
                continue
            if isinstance(normalized, (dict, list)) and not normalized:
                continue
            cleaned.append(normalized)
        return cleaned
    return value


class JsonlLogger:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def event(self, message: str, status: str, **details: object) -> None:
        entry = {
            "time": utc_now(),
            "message": message,
            "status": status,
            "details": details,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")


class DebugLogger:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def event(self, stage: str, **details: object) -> None:
        entry = {
            "time": utc_now(),
            "stage": stage,
            "details": details,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")


def run_command(
    logger: JsonlLogger,
    command: list[str],
    *,
    name: str,
    step: str,
    dry_run: bool,
    allow_failure: bool = False,
    timeout: int = 120,
    cwd: Path | None = None,
    debug_logger: DebugLogger | None = None,
) -> int:
    command_repr = " ".join(shlex.quote(token) for token in command)
    if debug_logger:
        debug_logger.event(
            "command.invoked",
            command=command_repr,
            name=name,
            step=step,
            dry_run=dry_run,
            allow_failure=allow_failure,
            timeout=timeout,
        )
    if dry_run:
        logger.event("command.wouldRun", "success", name=name, step=step, command=command_repr)
        if debug_logger:
            debug_logger.event(
                "command.skipped",
                command=command_repr,
                reason="dry-run",
                name=name,
                step=step,
            )
        return 0

    logger.event("command.started", "started", name=name, step=step, command=command_repr)
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False, cwd=str(cwd) if cwd else None)
    except FileNotFoundError as exc:
        logger.event("command.failed", "warn", name=name, step=step, command=command_repr, reason=str(exc))
        if debug_logger:
            debug_logger.event(
                "command.failed",
                command=command_repr,
                name=name,
                step=step,
                reason="missing-executable",
                error=str(exc),
            )
        if allow_failure:
            return 127
        raise
    except subprocess.TimeoutExpired as exc:
        logger.event("command.failed", "warn", name=name, step=step, command=command_repr, reason="timeout", timeout=timeout)
        if debug_logger:
            debug_logger.event(
                "command.finished",
                command=command_repr,
                name=name,
                step=step,
                status="timeout",
                return_code=124,
                timeout=timeout,
                error=str(exc),
            )
        if allow_failure:
            return 124
        raise

    if proc.stdout:
        logger.event("command.stdout", "info", name=name, step=step, command=command_repr, output=proc.stdout[:2000])
        if debug_logger:
            debug_logger.event(
                "command.stdout",
                command=command_repr,
                name=name,
                step=step,
                output=_truncate(proc.stdout),
            )
    if proc.stderr:
        logger.event("command.stderr", "info", name=name, step=step, command=command_repr, output=proc.stderr[:2000])
        if debug_logger:
            debug_logger.event(
                "command.stderr",
                command=command_repr,
                name=name,
                step=step,
                output=_truncate(proc.stderr),
            )

    rc = proc.returncode
    logger.event("command.completed", "success" if rc == 0 else "error", name=name, step=step, command=command_repr, return_code=rc)
    if debug_logger:
        debug_logger.event(
            "command.finished",
            command=command_repr,
            name=name,
            step=step,
            status="ok" if rc == 0 else "failed",
            return_code=rc,
        )
    if rc != 0 and not allow_failure:
        raise RuntimeError(f"Command failed ({rc}): {command_repr}")
    return rc


def _run_command_capture(
    logger: JsonlLogger,
    debug_logger: DebugLogger | None,
    command: list[str],
    *,
    name: str,
    step: str,
    dry_run: bool,
    allow_failure: bool = False,
    timeout: int = 120,
    cwd: Path | None = None,
) -> tuple[int, str, str]:
    if dry_run:
        command_repr = " ".join(shlex.quote(token) for token in command)
        logger.event("command.wouldRun", "success", name=name, step=step, command=command_repr)
        if debug_logger:
            debug_logger.event(
                "command.skipped",
                command=command_repr,
                reason="dry-run",
                name=name,
                step=step,
            )
        return 0, "", ""

    command_repr = " ".join(shlex.quote(token) for token in command)
    logger.event("command.started", "started", name=name, step=step, command=command_repr)
    if debug_logger:
        debug_logger.event(
            "command.invoked",
            command=command_repr,
            name=name,
            step=step,
            dry_run=dry_run,
            allow_failure=allow_failure,
            timeout=timeout,
        )

    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            cwd=str(cwd) if cwd else None,
            **_m365_subprocess_kwargs(command),
        )
    except FileNotFoundError as exc:
        logger.event("command.failed", "warn", name=name, step=step, command=command_repr, reason=str(exc))
        if debug_logger:
            debug_logger.event(
                "command.failed",
                command=command_repr,
                name=name,
                step=step,
                reason="missing-executable",
                error=str(exc),
            )
        if allow_failure:
            return 127, "", str(exc)
        raise
    except subprocess.TimeoutExpired as exc:
        logger.event("command.failed", "warn", name=name, step=step, command=command_repr, reason="timeout", timeout=timeout)
        if debug_logger:
            debug_logger.event(
                "command.finished",
                command=command_repr,
                name=name,
                step=step,
                status="timeout",
                return_code=124,
                timeout=timeout,
                error=str(exc),
            )
        if allow_failure:
            return 124, "", str(exc)
        raise

    if proc.stdout:
        logger.event("command.stdout", "info", name=name, step=step, command=command_repr, output=proc.stdout[:2000])
        if debug_logger:
            debug_logger.event(
                "command.stdout",
                command=command_repr,
                name=name,
                step=step,
                output=_truncate(proc.stdout),
            )
    if proc.stderr:
        logger.event("command.stderr", "info", name=name, step=step, command=command_repr, output=proc.stderr[:2000])
        if debug_logger:
            debug_logger.event(
                "command.stderr",
                command=command_repr,
                name=name,
                step=step,
                output=_truncate(proc.stderr),
            )

    rc = proc.returncode
    logger.event("command.completed", "success" if rc == 0 else "error", name=name, step=step, command=command_repr, return_code=rc)
    if debug_logger:
        debug_logger.event(
            "command.finished",
            command=command_repr,
            name=name,
            step=step,
            status="ok" if rc == 0 else "failed",
            return_code=rc,
        )
    if rc != 0 and not allow_failure:
        raise RuntimeError(f"Command failed ({rc}): {command_repr}")

    return rc, proc.stdout, proc.stderr


class GraphClient:
    def __init__(
        self,
        logger: JsonlLogger,
        dry_run: bool,
        *,
        debug_logger: DebugLogger | None = None,
        auth_mode: str = "azure_cli",
        client_id: str | None = None,
        browser_command: str | None = None,
        interactive_scopes: list[str] | None = None,
    ) -> None:
        self.logger = logger
        self.dry_run = dry_run
        self.debug_logger = debug_logger
        self.auth_mode = auth_mode
        self.client_id = client_id
        self.browser_command = browser_command
        self.interactive_scopes = interactive_scopes or []
        self.session = requests.Session()
        if self.dry_run:
            return
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self._access_token()}",
                "Content-Type": "application/json",
            }
        )

    def _access_token(self) -> str:
        env_token = os.environ.get("AZURE_ACCESS_TOKEN")
        if env_token:
            if self.debug_logger:
                self.debug_logger.event("auth.token.source", source="AZURE_ACCESS_TOKEN")
            self.logger.event("auth.token.source", "success", source="AZURE_ACCESS_TOKEN")
            return env_token
        if self.auth_mode == "interactive":
            if self.debug_logger:
                self.debug_logger.event("auth.token.source", source="interactive", mode=self.auth_mode, client_id=self.client_id, scopes=self.interactive_scopes)
            self.logger.event(
                "auth.token.source",
                "success",
                source="interactive",
                client_id=self.client_id,
                scopes=self.interactive_scopes,
            )
            return self._interactive_access_token()
        if self.debug_logger:
            self.debug_logger.event("auth.token.source", source="azure_cli", mode=self.auth_mode)
        self.logger.event("auth.token.source", "success", source="azure_cli", mode=self.auth_mode)
        proc = subprocess.run(
            [
                "az",
                "account",
                "get-access-token",
                "--resource",
                GRAPH_RESOURCE,
                "--query",
                "accessToken",
                "--output",
                "tsv",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        token = proc.stdout.strip()
        if not token:
            raise RuntimeError("Azure CLI did not return a Graph access token.")
        if self.debug_logger:
            self.debug_logger.event("auth.token.source", source="azure_cli", command="az account get-access-token")
        self.logger.event("auth.token.source", "success", source="azure_cli", command="az account get-access-token")
        return token

    def _interactive_access_token(self) -> str:
        if not self.client_id:
            raise RuntimeError("Interactive auth requested without a client ID.")
        try:
            import msal
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"Interactive auth requires msal: {exc}") from exc

        scopes = list(dict.fromkeys(self.interactive_scopes or ["User.Read"]))
        if self.browser_command:
            os.environ["BROWSER"] = self.browser_command
        app = msal.PublicClientApplication(
            client_id=self.client_id,
            authority="https://login.microsoftonline.com/organizations",
            token_cache=None,
        )
        result = app.acquire_token_interactive(scopes=scopes)
        if not result or "access_token" not in result:
            error = result.get("error_description") if isinstance(result, dict) else "interactive auth canceled"
            raise RuntimeError(str(error or "Interactive auth did not return an access token."))
        if self.debug_logger:
            self.debug_logger.event("auth.token.source", source="interactive", client_id=self.client_id, scopes=scopes)
        return str(result["access_token"])

    def access_token(self) -> str:
        return self.session.headers.get("Authorization", "").removeprefix("Bearer ").strip() if not self.dry_run else ""

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict | None = None,
        top: int | None = None,
        allow_failure: bool = False,
    ) -> dict:
        if not path.startswith("http://") and not path.startswith("https://"):
            request_path = normalize_top(path, top)
            path = f"{GRAPH_ROOT}{request_path}" if not request_path.startswith("http") else request_path
        if self.dry_run:
            self.logger.event("graph.would_request", "success", method=method, path=path)
            if self.debug_logger:
                self.debug_logger.event("graph.request", method=method, path=path, mode="dry-run")
            if method.upper() != "GET":
                return {}
            return {"value": []}

        for attempt in range(5):
            if self.debug_logger:
                self.debug_logger.event("graph.request", method=method, path=path, payloadType=type(payload).__name__, attempt=attempt + 1)
            start = time.monotonic()
            response = self.session.request(method, path, json=payload, timeout=120)
            duration_ms = int((time.monotonic() - start) * 1000)
            self.logger.event(
                "graph.request",
                "success" if response.ok else "error",
                method=method,
                path=path,
                status_code=response.status_code,
                duration_ms=duration_ms,
            )
            if response.status_code == 204:
                return {}
            try:
                body = response.json()
            except ValueError:
                body = {"raw": response.text}
            if response.status_code in {429, 503} and attempt < 4:
                retry_after = response.headers.get("Retry-After")
                try:
                    delay = max(1, int(retry_after)) if retry_after else 5
                except ValueError:
                    delay = 5
                self.logger.event("graph.retry", "warn", method=method, path=path, status_code=response.status_code, attempt=attempt + 1, delaySeconds=delay)
                time.sleep(delay)
                continue
            if not response.ok:
                if self.debug_logger:
                    self.debug_logger.event(
                        "graph.response",
                        method=method,
                        path=path,
                        status_code=response.status_code,
                        duration_ms=duration_ms,
                        state="error",
                        body_preview=_truncate(str(body) if not isinstance(body, dict) else json.dumps(body)),
                    )
                if allow_failure:
                    return {
                        "statusCode": response.status_code,
                        "error": body,
                    }
                raise RuntimeError(f"{method} {path} failed: {response.status_code} {body}")
            if self.debug_logger:
                self.debug_logger.event(
                    "graph.response",
                    method=method,
                    path=path,
                    status_code=response.status_code,
                    duration_ms=duration_ms,
                    state="success",
                )
            return body
        raise RuntimeError(f"{method} {path} failed after retries")

    def iter_pages(self, path: str, *, top: int | None = None):
        next_url = path
        if not next_url.startswith("http://") and not next_url.startswith("https://"):
            if top is not None:
                next_url = normalize_top(next_url, top)
            next_url = f"{GRAPH_ROOT}{next_url}"
        while next_url:
            body = self.request("GET", next_url, top=None)
            for item in body.get("value", []):
                yield item
            next_url = body.get("@odata.nextLink")


def ensure_mapping(cfg: dict) -> dict[str, str]:
    return {
        "identity": cfg["groupNames"]["allUsers"],
        "copilot": cfg["groupNames"]["copilotPilot"],
        "reporting": cfg["groupNames"]["reporting"],
        "entraP2": cfg["groupNames"]["entraP2"],
    }


def resolve_group_ids(client: GraphClient, logger: JsonlLogger, top: int = 999) -> dict[str, str]:
    ids: dict[str, str] = {}
    for group in client.iter_pages("/groups?$select=id,displayName", top=top):
        ids[group["displayName"]] = group["id"]
    logger.event("groups.resolved", "success", count=len(ids))
    return ids


def policy_files_in_dir(path: Path, *, pattern: str = "*.json") -> list[Path]:
    return sorted((path / "").glob(pattern))


PLACEHOLDER_PATTERN = re.compile(r"\{\{([A-Za-z0-9_]+)\}\}")


def resolve_users_in_group(
    client: GraphClient,
    group_id: str,
    logger: JsonlLogger,
    *,
    select: str = "id,displayName,userPrincipalName,userType",
) -> list[dict]:
    users = []
    for member in client.iter_pages(f"/groups/{group_id}/members?$select={quote(select, safe=',')}" ):
        if "userPrincipalName" in member and member.get("userType") != "Guest":
            users.append(member)
    logger.event("group.members.resolved", "success", group_id=group_id, count=len(users))
    return users


def first_value(client: GraphClient, path: str) -> dict | None:
    body = client.request("GET", path)
    values = body.get("value", [])
    return values[0] if values else None


def resolve_sku_map(client: GraphClient) -> dict[str, dict]:
    skus = client.request("GET", "/subscribedSkus").get("value", [])
    return {str(sku["skuPartNumber"]).lower(): sku for sku in skus}


def resolve_managed_device_target(cfg: dict, *, phase: str = "phase1") -> int:
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


def build_windows365_plan(cfg: dict) -> dict:
    windows365_cfg = cfg.get("windows365", {})
    licenses_cfg = cfg.get("licenses", {})
    return {
        "enabled": bool(windows365_cfg.get("enabled", False)),
        "pilotUserAlias": windows365_cfg.get("phase1PilotUser") or licenses_cfg.get("cloudPcBusinessUser") or cfg.get("actors", {}).get("dailyUser"),
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
        "managedDeviceTarget": resolve_managed_device_target(cfg),
        "managedDeviceTargets": {
            "phase1": resolve_managed_device_target(cfg, phase="phase1"),
            "phase2": resolve_managed_device_target(cfg, phase="phase2"),
            "final": resolve_managed_device_target(cfg, phase="final"),
        },
    }


def _sku_availability_rows(client: GraphClient) -> list[dict]:
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


def _select_windows365_sku(client: GraphClient, cfg: dict) -> dict | None:
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


def _decode_jwt_payload(token: str) -> dict:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload.encode("ascii")).decode("utf-8"))
    except Exception:
        return {}


def graph_token_claims(
    logger: JsonlLogger,
    debug_logger: DebugLogger | None = None,
    access_token: str | None = None,
    token_source: str = "azure_cli",
) -> dict:
    if access_token:
        claims = _decode_jwt_payload(access_token)
        logger.event(
            "token.claims",
            "success",
            source=token_source,
            appid=claims.get("appid"),
            upn=claims.get("upn") or claims.get("unique_name"),
            scopes=str(claims.get("scp") or ""),
            roles=claims.get("roles"),
        )
        return claims
    proc = subprocess.run(
        [
            "az",
            "account",
            "get-access-token",
            "--resource-type",
            "ms-graph",
            "--query",
            "accessToken",
            "--output",
            "tsv",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if debug_logger:
        debug_logger.event(
            "token.claims.command",
            returncode=proc.returncode,
            stderr=_truncate(proc.stderr),
        )
    if proc.returncode != 0 or not proc.stdout.strip():
        logger.event(
            "token.claims.unavailable",
            "warn",
            source=token_source,
            reason="az-token-failed",
        )
        return {}
    claims = _decode_jwt_payload(proc.stdout.strip())
    logger.event(
        "token.claims",
        "success",
        source=token_source,
        appid=claims.get("appid"),
        upn=claims.get("upn") or claims.get("unique_name"),
        scopes=str(claims.get("scp") or ""),
        roles=claims.get("roles"),
    )
    return claims


def emit_license_readiness_artifact(
    client: GraphClient,
    logger: JsonlLogger,
    cfg: dict,
    run_dir: Path,
    *,
    dry_run: bool,
) -> dict:
    artifact = run_dir / "license-readiness-manifest.json"
    if dry_run:
        payload = {
            "mode": "dry-run",
            "notes": ["Live subscribed SKU and mailbox readiness checks skipped."],
        }
        artifact.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        logger.event("license.readiness.artifact", "success", artifact=str(artifact), dryRun=True)
        return payload

    skus = client.request("GET", "/subscribedSkus").get("value", [])
    users = client.request(
        "GET",
        "/users?$select=id,displayName,userPrincipalName,mail,assignedLicenses,licenseAssignmentStates&$top=999",
    ).get("value", [])
    mail_enabled = [user for user in users if user.get("mail")]
    count_violations = []
    for user in users:
        for state in user.get("licenseAssignmentStates", []) or []:
            if state.get("error") and state.get("error") != "None":
                count_violations.append(
                    {
                        "userPrincipalName": user.get("userPrincipalName"),
                        "skuId": state.get("skuId"),
                        "state": state.get("state"),
                        "error": state.get("error"),
                        "assignedByGroup": state.get("assignedByGroup"),
                    }
                )

    sku_rows = []
    for sku in skus:
        prepaid = sku.get("prepaidUnits", {}) or {}
        enabled = int(prepaid.get("enabled") or 0)
        consumed = int(sku.get("consumedUnits") or 0)
        sku_rows.append(
            {
                "skuPartNumber": sku.get("skuPartNumber"),
                "skuId": sku.get("skuId"),
                "enabled": enabled,
                "consumed": consumed,
                "available": max(enabled - consumed, 0),
            }
        )

    payload = {
        "tenantId": cfg.get("tenant", {}).get("tenantId"),
        "tenantDomain": cfg.get("tenant", {}).get("tenantDomain"),
        "generatedAt": utc_now(),
        "skuSummary": sku_rows,
        "mailEnabledUsers": [
            {
                "displayName": user.get("displayName"),
                "userPrincipalName": user.get("userPrincipalName"),
                "mail": user.get("mail"),
            }
            for user in mail_enabled
        ],
        "mailEnabledUserCount": len(mail_enabled),
        "licenseAssignmentErrors": count_violations,
        "diagnosis": [],
    }
    exchange_capable_ids = {
        sku.get("skuId")
        for sku in skus
        if any(
            str(plan.get("servicePlanName", "")).upper() == "EXCHANGE_S_STANDARD"
            for plan in sku.get("servicePlans", []) or []
        )
    }
    exchange_like = [row for row in sku_rows if row.get("skuId") in exchange_capable_ids]
    if exchange_like and all(int(row["available"]) == 0 for row in exchange_like):
        payload["diagnosis"].append(
            "No spare Exchange-capable seats are available; newly seeded users will not receive mailboxes."
        )
    if count_violations:
        payload["diagnosis"].append(
            "One or more group-based license assignments are in CountViolation; reduce group scope or add seats."
        )
    artifact.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    logger.event(
        "license.readiness.artifact",
        "success",
        artifact=str(artifact),
        skuCount=len(sku_rows),
        mailEnabledUsers=len(mail_enabled),
        assignmentErrors=len(count_violations),
    )
    return payload


def mailbox_seed_aliases(cfg: dict) -> list[str]:
    aliases = [
        cfg.get("actors", {}).get("dailyUser"),
        cfg.get("actors", {}).get("namedAdmin"),
    ]
    for department in cfg.get("departments", []):
        for index in range(1, int(cfg.get("departmentDistribution", {}).get(department, 0)) + 1):
            aliases.append(f"{str(department).lower()}.{index:02d}.staff")
    excluded = {str(alias).lower() for alias in cfg.get("licenses", {}).get("mailboxSeedExcludeAliases", [])}
    excluded.update(str(alias).lower() for alias in cfg.get("actors", {}).get("breakGlassUsers", []))
    seen: set[str] = set()
    result: list[str] = []
    for alias in aliases:
        if not alias:
            continue
        key = str(alias).lower()
        if key in excluded or key in seen:
            continue
        seen.add(key)
        result.append(str(alias))
    return result


def assign_mailbox_seed_licenses(
    client: GraphClient,
    logger: JsonlLogger,
    cfg: dict,
    dry_run: bool,
) -> None:
    license_cfg = cfg.get("licenses", {})
    sku_pattern = license_cfg.get("mailboxSeed")
    if not sku_pattern:
        logger.event("license.mailboxSeed.skip", "success", reason="not-configured")
        return

    skus = resolve_sku_map(client)
    matched = [sku for key, sku in skus.items() if str(sku_pattern).lower() in key]
    if not matched:
        logger.event("license.mailboxSeed.skip", "warn", reason="sku-not-found", sku=sku_pattern)
        return
    sku = matched[0]
    sku_id = sku["skuId"]
    prepaid = sku.get("prepaidUnits", {}) or {}
    available = max(int(prepaid.get("enabled") or 0) - int(sku.get("consumedUnits") or 0), 0)
    max_users = int(license_cfg.get("mailboxSeedMaxUsers") or available)
    target_aliases = mailbox_seed_aliases(cfg)[:max_users]
    if available < 1:
        logger.event("license.mailboxSeed.skip", "warn", reason="no-available-seats", sku=sku_pattern)
        return

    domain = cfg.get("tenant", {}).get("tenantDomain")
    assigned = 0
    already_assigned = 0
    skipped = 0
    for alias in target_aliases:
        if assigned >= available:
            skipped += 1
            logger.event("license.mailboxSeed.skipUser", "warn", reason="seat-limit-reached", alias=alias, sku=sku_pattern)
            continue
        target_upn = alias if "@" in alias else f"{alias}@{domain}"
        user = first_value(
            client,
            f"/users?$filter=userPrincipalName eq '{_safe_graph_filter_value(target_upn)}'&$select=id,userPrincipalName,assignedLicenses",
        )
        if not user:
            skipped += 1
            logger.event("license.mailboxSeed.skipUser", "warn", reason="target-user-missing", userPrincipalName=target_upn)
            continue
        if any(assigned_license.get("skuId") == sku_id for assigned_license in user.get("assignedLicenses", []) or []):
            already_assigned += 1
            logger.event("license.mailboxSeed.alreadyAssigned", "success", userPrincipalName=target_upn, sku=sku_pattern)
            continue
        if dry_run:
            assigned += 1
            logger.event("license.mailboxSeed.wouldAssign", "success", userPrincipalName=target_upn, sku=sku_pattern)
            continue
        payload = {"addLicenses": [{"skuId": sku_id, "disabledPlans": []}], "removeLicenses": []}
        client.request("POST", f"/users/{user['id']}/assignLicense", payload=payload)
        assigned += 1
        logger.event("license.mailboxSeed.assigned", "success", userPrincipalName=target_upn, sku=sku_pattern)

    logger.event(
        "license.mailboxSeed.summary",
        "success",
        sku=sku_pattern,
        targeted=len(target_aliases),
        assigned=assigned,
        alreadyAssigned=already_assigned,
        skipped=skipped,
        availableAtStart=available,
    )


def assign_direct_cloud_pc_license(
    client: GraphClient,
    logger: JsonlLogger,
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
    user = first_value(
        client,
        f"/users?$filter=userPrincipalName eq '{_safe_graph_filter_value(target_upn)}'&$select=id,userPrincipalName,assignedLicenses",
    )
    if not user:
        logger.event("license.cloudpc.skip", "warn", reason="target-user-missing", userPrincipalName=target_upn)
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
    client: GraphClient,
    logger: JsonlLogger,
    *,
    display_name: str,
    dry_run: bool,
) -> dict:
    display_value = _safe_graph_filter_value(display_name)
    existing = first_value(client, f"/groups?$filter=displayName eq '{display_value}'&$select=id,displayName")
    if existing:
        logger.event("group.exists", "success", group=display_name, id=existing.get("id"))
        return existing

    payload = {
        "displayName": display_name,
        "mailEnabled": False,
        "mailNickname": mail_nickname(display_name),
        "securityEnabled": True,
    }
    if dry_run:
        logger.event("group.wouldCreate", "success", group=display_name)
        return {"id": f"DRY-RUN-{display_name}", "displayName": display_name}

    created = client.request("POST", "/groups", payload=payload)
    logger.event("group.created", "success", group=display_name, id=created.get("id"))
    return created


def _resolve_windows365_pilot_user(client: GraphClient, cfg: dict, plan: dict) -> dict | None:
    alias = plan.get("pilotUserAlias")
    domain = cfg.get("tenant", {}).get("tenantDomain")
    if not alias or not domain:
        return None
    upn = alias if "@" in str(alias) else f"{alias}@{domain}"
    return first_value(
        client,
        f"/users?$filter=userPrincipalName eq '{_safe_graph_filter_value(upn)}'&$select=id,userPrincipalName,displayName,assignedLicenses",
    )


def _select_windows365_gallery_image(client: GraphClient, logger: JsonlLogger, plan: dict) -> dict:
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
    client: GraphClient,
    logger: JsonlLogger,
    plan: dict,
    *,
    dry_run: bool,
) -> dict:
    display_name = plan["policyDisplayName"]
    existing = first_value(
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
    client: GraphClient,
    logger: JsonlLogger,
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


def _find_windows365_cloud_pc(client: GraphClient, user_principal_name: str) -> dict | None:
    return first_value(
        client,
        f"/deviceManagement/virtualEndpoint/cloudPCs?$filter=userPrincipalName eq '{_safe_graph_filter_value(user_principal_name)}'&$select=id,displayName,userPrincipalName,provisioningPolicyId,managedDeviceId,managedDeviceName,status,servicePlanName",
    )


def _poll_windows365_cloud_pc(
    client: GraphClient,
    logger: JsonlLogger,
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
            logger.event("windows365.cloudpc.discovered", "success", userPrincipalName=user_principal_name, status=status, id=cloud_pc.get("id"))
            return {"cloudPc": cloud_pc, "pollState": "found", "attempts": attempts}
        if time.monotonic() >= deadline:
            logger.event("windows365.cloudpc.pending", "warn", userPrincipalName=user_principal_name, attempts=attempts)
            return {"cloudPc": None, "pollState": "pending", "attempts": attempts}
        time.sleep(max(interval_seconds, 1))


def emit_windows365_provisioning_artifact(run_dir: Path, logger: JsonlLogger, payload: dict) -> str:
    artifact = run_dir / "windows365-provisioning-manifest.json"
    artifact.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    logger.event("windows365.provisioning.artifact", "success", artifact=str(artifact))
    return str(artifact)


def emit_windows365_diagnostic(
    client: GraphClient,
    logger: JsonlLogger,
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
        "generatedAt": utc_now(),
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
    else:
        for name, path in [
            ("cloudPCs", "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/cloudPCs?$top=10"),
            (
                "provisioningPolicies",
                "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/provisioningPolicies?$top=20",
            ),
            ("userSettings", "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/userSettings?$top=20"),
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


def emit_windows365_blocker_artifact(run_dir: Path, logger: JsonlLogger, payload: dict) -> str:
    artifact = run_dir / "windows365-blocker-manifest.json"
    artifact.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    logger.event("windows365.blocker.artifact", "warn", artifact=str(artifact))
    return str(artifact)


def seed_windows365(
    client: GraphClient,
    logger: JsonlLogger,
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
        if check.get("status") != "success" and check.get("name") in {"cloudPCs", "provisioningPolicies"}
    ]
    if blocked_checks:
        summary["status"] = "blocked"
        summary["blockers"] = [check.get("name") for check in blocked_checks]
        summary["blockerArtifact"] = emit_windows365_blocker_artifact(
            run_dir,
            logger,
            {
                "generatedAt": utc_now(),
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
                "generatedAt": utc_now(),
                "plan": plan,
                "selectedSku": summary["selectedSku"],
                "license": license_summary,
                "reason": "windows365-license-not-ready",
            },
        )
        return summary

    user = _resolve_windows365_pilot_user(client, cfg, plan)
    if not user:
        summary["status"] = "blocked"
        summary["blockers"] = ["pilot-user"]
        summary["blockerArtifact"] = emit_windows365_blocker_artifact(
            run_dir,
            logger,
            {
                "generatedAt": utc_now(),
                "plan": plan,
                "selectedSku": summary["selectedSku"],
                "reason": "windows365-pilot-user-missing",
            },
        )
        return summary

    summary["pilotUserPrincipalName"] = user.get("userPrincipalName")

    if str(plan.get("joinType")) != "entraHosted" or str(plan.get("networkType")) != "microsoftHosted":
        summary["status"] = "blocked"
        summary["blockers"] = ["unsupported-join-plan"]
        summary["blockerArtifact"] = emit_windows365_blocker_artifact(
            run_dir,
            logger,
            {
                "generatedAt": utc_now(),
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
                "generatedAt": utc_now(),
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
                "generatedAt": utc_now(),
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


# Backward-compatible entry points now delegate to windows365_workload.py to keep
# orchestration here and move Windows 365 implementation to a dedicated module.
build_windows365_plan = windows365_workload.build_windows365_plan
_sku_availability_rows = windows365_workload._sku_availability_rows
_select_windows365_sku = windows365_workload._select_windows365_sku
_build_windows365_policy_payload = windows365_workload._build_windows365_policy_payload
_build_windows365_assignment_payload = windows365_workload._build_windows365_assignment_payload
_ensure_security_group = windows365_workload._ensure_security_group
_resolve_windows365_pilot_user = windows365_workload._resolve_windows365_pilot_user
_select_windows365_gallery_image = windows365_workload._select_windows365_gallery_image
_ensure_windows365_provisioning_policy = windows365_workload._ensure_windows365_provisioning_policy
_ensure_windows365_policy_assignment = windows365_workload._ensure_windows365_policy_assignment
_find_windows365_cloud_pc = windows365_workload._find_windows365_cloud_pc
_poll_windows365_cloud_pc = windows365_workload._poll_windows365_cloud_pc
emit_windows365_diagnostic = windows365_workload.emit_windows365_diagnostic
emit_windows365_blocker_artifact = windows365_workload.emit_windows365_blocker_artifact
emit_windows365_provisioning_artifact = windows365_workload.emit_windows365_provisioning_artifact
assign_direct_cloud_pc_license = windows365_workload.assign_direct_cloud_pc_license
seed_windows365 = windows365_workload.seed_windows365


def assign_licenses(client: GraphClient, logger: JsonlLogger, cfg: dict, group_ids: dict[str, str], dry_run: bool) -> None:
    skus = resolve_sku_map(client)
    assignments = [
        (cfg["groupNames"]["allUsers"], cfg["licenses"]["base"]),
        (cfg["groupNames"]["copilotPilot"], cfg["licenses"]["copilotPilot"]),
        (cfg["groupNames"]["reporting"], cfg["licenses"]["powerBi"]),
        (cfg["groupNames"]["entraP2"], cfg["licenses"]["entraP2"]),
    ]
    for group_name, sku_pattern in assignments:
        group_id = group_ids.get(group_name)
        if not group_id:
            logger.event("license.skip", "warn", reason="group-missing", group=group_name)
            continue
        matched = [sku for key, sku in skus.items() if sku_pattern.lower() in key]
        if not matched:
            logger.event("license.skip", "warn", reason="sku-not-found", sku=sku_pattern, group=group_name)
            continue
        sku_id = matched[0]["skuId"]
        payload = {"addLicenses": [{"skuId": sku_id, "disabledPlans": []}], "removeLicenses": []}
        if dry_run:
            logger.event("license.wouldAssign", "success", group=group_name, sku=sku_pattern)
            continue
        try:
            client.request("POST", f"/groups/{group_id}/assignLicense", payload=payload)
            logger.event("license.assigned", "success", group=group_name, sku=sku_pattern)
        except RuntimeError as exc:
            msg = str(exc).lower()
            if "already" in msg or "assigned" in msg or "no update in the group licenses" in msg:
                logger.event("license.alreadyAssigned", "success", group=group_name, sku=sku_pattern)
            else:
                raise


def build_team_body(group_id: str) -> dict:
    return {}


def seed_teams(client: GraphClient, logger: JsonlLogger, cfg: dict, group_ids: dict[str, str], dry_run: bool) -> list[str]:
    team_groups = cfg.get(
        "teamGroups",
        [cfg["groupNames"]["itM365"], cfg["groupNames"]["salesM365"], cfg["groupNames"]["financeM365"]],
    )
    team_ids: list[str] = []
    for group_name in team_groups:
        group_id = group_ids.get(group_name)
        if not group_id:
            logger.event("team.skip", "warn", reason="group-missing", group=group_name)
            continue
        try:
            team_state = client.request("GET", f"/groups/{group_id}/team")
            team_id = team_state.get("id") or group_id
            if not team_id:
                raise RuntimeError("no team id yet")
        except RuntimeError:
            if dry_run:
                logger.event("team.wouldCreate", "success", group=group_name)
                continue
            body = build_team_body(group_id)
            try:
                client.request("PUT", f"/groups/{group_id}/team", payload=body)
            except RuntimeError as exc:
                msg = str(exc).lower()
                if "method not allowed" in msg or "unknownerror" in msg or "forbidden" in msg:
                    logger.event("team.create.skipped", "warn", group=group_name, reason="api-not-available-or-restricted")
                    continue
                raise
            team_id = group_id
            logger.event("team.create.pending", "info", group=group_name, teamId=team_id)
            for _ in range(12):
                try:
                    team_state = client.request("GET", f"/groups/{group_id}/team")
                    team_id = team_state.get("id") or group_id
                except RuntimeError:
                    team_id = None
                if team_id:
                    break
                time.sleep(8)
            if not team_id:
                logger.event("team.create.timeout", "error", group=group_name)
                continue

        team_ids.append(team_id)
        existing = client.request("GET", f"/teams/{team_id}/channels?$select=id,displayName")
        existing_names = {item["displayName"].lower() for item in existing.get("value", []) if "displayName" in item}
        for channel in cfg["teamChannels"]:
            if channel.lower() in existing_names:
                continue
            if dry_run:
                logger.event("team.channel.wouldCreate", "success", team=team_id, channel=channel)
                continue
            client.request(
                "POST",
                f"/teams/{team_id}/channels",
                payload={"displayName": channel, "description": "Seed channel", "membershipType": "standard"},
            )
            logger.event("team.channel.created", "success", team=team_id, channel=channel)
    return team_ids


def _endpoint_for_intune_policy(policy_json: dict) -> str | None:
    odata_type = str(policy_json.get("@odata.type", "")).lower()
    if "devicecompliance" in odata_type or "compliance" in odata_type:
        return "/deviceManagement/deviceCompliancePolicies"
    if "windowsautopilotdeploymentprofile" in odata_type:
        return "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles"
    if "deviceenrollment" in odata_type:
        return "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations"
    if "devicecategory" in odata_type:
        return "/deviceManagement/deviceCategories"
    if "iosmanagedappprotection" in odata_type:
        return "/deviceAppManagement/iosManagedAppProtections"
    if "androidmanagedappprotection" in odata_type:
        return "/deviceAppManagement/androidManagedAppProtections"
    if "deviceconfiguration" in odata_type:
        return "/deviceManagement/deviceConfigurations"
    return "/deviceManagement/deviceConfigurations"


def _is_intune_permission_denied(message: str, *, endpoint: str = "") -> bool:
    msg = message.lower()
    if "forbidden" not in msg:
        return False

    text = f"{msg} {endpoint}".lower()
    permission_patterns = [
        "devicemanagementconfiguration",
        "devicemanagementserviceconfiguration",
        "devicemanagementserviceconfig",
        "devicemanagementapps",
        "devicecategories",
        "deviceappmanagement",
        "deviceenrollment",
        "devicecompliance",
        "deviceconfigurations",
        "windowsautopilot",
        "virtualendpoint",
    ]
    return any(pattern in text for pattern in permission_patterns)


def _normalize_ca_policy(policy_json: dict) -> dict:
    policy = json.loads(json.dumps(policy_json))
    if policy.get("state") == "reportOnly":
        policy["state"] = "enabledForReportingButNotEnforced"
    return _drop_empty_values(policy)


def build_security_defaults_payload(is_enabled: bool) -> dict:
    return {"isEnabled": bool(is_enabled)}


def get_security_defaults_state(client: GraphClient, logger: JsonlLogger) -> dict | None:
    try:
        state = client.request("GET", "/policies/identitySecurityDefaultsEnforcementPolicy")
        logger.event("security.defaults.detected", "success", isEnabled=state.get("isEnabled"))
        return state
    except RuntimeError as exc:
        logger.event("security.defaults.detect.failed", "warn", reason=str(exc)[:360])
        return None


def disable_security_defaults(client: GraphClient, logger: JsonlLogger, dry_run: bool) -> bool:
    payload = build_security_defaults_payload(False)
    if dry_run:
        logger.event("security.defaults.wouldDisable", "success", payload=payload)
        return True
    try:
        client.request("PATCH", "/policies/identitySecurityDefaultsEnforcementPolicy", payload=payload)
        logger.event("security.defaults.disabled", "success")
        return True
    except RuntimeError as exc:
        logger.event("security.defaults.disable.failed", "warn", reason=str(exc)[:360])
        return False


def ca_policy_requires_defaults_off(policy: dict) -> bool:
    return str(policy.get("state", "")).lower() not in {"", "disabled", "enabledforreportingbutnotenforced"}


def _sanitize_intune_policy(policy_json: dict) -> dict:
    policy = json.loads(json.dumps(policy_json))
    odata_type = str(policy.get("@odata.type", "")).lower()
    for field in ["id", "version", "createdDateTime", "lastModifiedDateTime"]:
        policy.pop(field, None)
    if "compliancepolicy" in odata_type or "compliance" in odata_type:
        policy.setdefault(
            "scheduledActionsForRule",
            [
                {
                    "ruleName": "PasswordRequired",
                    "scheduledActionConfigurations": [
                        {
                            "actionType": "block",
                            "gracePeriodHours": 0,
                            "notificationTemplateId": "",
                            "notificationMessageCCList": [],
                        }
                    ],
                }
            ],
        )
        policy.pop("earlyLaunchAntimalwareDriverEnabled", None)
    if "windows10generalconfiguration" in odata_type:
        policy.pop("edgeSearchEngine", None)
        for field in [
            "passwordBlockSimple",
            "passwordRequiredType",
            "passwordMinimumLength",
            "passwordSecondsOfInactivityBeforeScreenTimeout",
            "passwordMinutesOfInactivityBeforeScreenTimeout",
            "passwordMinimumCharacterSetCount",
        ]:
            policy.pop(field, None)
    if "managedappprotection" in odata_type:
        for field in ["isAssigned", "deployedAppCount"]:
            policy.pop(field, None)
    if "devicecategory" in odata_type:
        policy.setdefault("description", "Seeded endpoint inventory category.")
    return _drop_empty_values(policy)


def seed_intune(client: GraphClient, logger: JsonlLogger, dry_run: bool) -> None:
    policy_root = Path(__file__).resolve().parent.parent / "policies" / "intune"
    policy_files = policy_files_in_dir(policy_root)
    if not policy_files:
        logger.event("intune.skip", "warn", reason="no-policy-files", path=str(policy_root))
        return

    seeded_count = 0
    skipped_count = 0
    for policy_file in policy_files:
        if not policy_file.is_file():
            logger.event("intune.skip", "warn", reason="policy-file-missing", file=str(policy_file))
            continue
        try:
            policy = json.loads(policy_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            logger.event("intune.parse-failed", "warn", file=policy_file.name, error=str(exc))
            skipped_count += 1
            continue
        policy = _sanitize_intune_policy(policy)

        display_name = policy.get("displayName", policy_file.stem)
        endpoint = _endpoint_for_intune_policy(policy)
        if not endpoint:
            logger.event("intune.skip", "warn", reason="policy-type-unknown", file=str(policy_file), display_name=display_name)
            skipped_count += 1
            continue

        safe_display_name = display_name.replace("'", "''")
        query = quote(f"displayName eq '{safe_display_name}'")
        try:
            existing = client.request("GET", f"{endpoint}?$filter={query}&$select=id,displayName")
        except RuntimeError as exc:
            msg = str(exc)
            if _is_intune_permission_denied(msg, endpoint=endpoint):
                logger.event("intune.skip", "warn", reason="insufficient-permissions", policy=display_name)
                continue
            raise
        if existing.get("value"):
            logger.event("intune.exists", "success", display_name=display_name)
            skipped_count += 1
            continue
        if dry_run:
            logger.event("intune.wouldCreate", "success", display_name=display_name, endpoint=endpoint)
            skipped_count += 1
            continue
        try:
            client.request("POST", endpoint, payload=policy)
            logger.event("intune.created", "success", display_name=display_name, endpoint=endpoint)
            seeded_count += 1
        except RuntimeError as exc:
            msg = str(exc).lower()
            if _is_intune_permission_denied(msg, endpoint=endpoint) and "conflict" not in msg and "already exists" not in msg:
                logger.event("intune.create.skipped", "warn", reason="insufficient-permissions", policy=display_name, endpoint=endpoint)
                skipped_count += 1
                continue
            if "already exists" in msg or "conflict" in msg:
                logger.event("intune.exists", "success", display_name=display_name, endpoint=endpoint)
                skipped_count += 1
                continue
            logger.event("intune.create.failed", "warn", display_name=display_name, endpoint=endpoint, reason=msg[:240])
            skipped_count += 1

    logger.event("intune.seed.complete", "success", seeded=seeded_count, skipped=skipped_count, file_count=len(policy_files))


def _ca_policy_replacements(template_text: str, group_ids: dict[str, str], cfg: dict) -> tuple[str, list[str]]:
    replacements: dict[str, str] = {
        "{{ALL_USERS_GROUP_ID}}": group_ids.get(cfg["groupNames"]["allUsers"], ""),
        "{{ADMINS_GROUP_ID}}": group_ids.get(cfg["groupNames"]["admins"], ""),
        "{{BREAKGLASS_GROUP_ID}}": group_ids.get(cfg["groupNames"]["breakGlass"], ""),
    }
    replacements["{{COPILOT_PILOT_GROUP_ID}}"] = group_ids.get(cfg["groupNames"]["copilotPilot"], "")
    replacements["{{REPORTING_GROUP_ID}}"] = group_ids.get(cfg["groupNames"]["reporting"], "")
    replacements["{{ENTRA_P2_GROUP_ID}}"] = group_ids.get(cfg["groupNames"]["entraP2"], "")
    replacements["{{IT_M365_GROUP_ID}}"] = group_ids.get(cfg["groupNames"]["itM365"], "")
    replacements["{{SALES_M365_GROUP_ID}}"] = group_ids.get(cfg["groupNames"]["salesM365"], "")
    replacements["{{FINANCE_M365_GROUP_ID}}"] = group_ids.get(cfg["groupNames"]["financeM365"], "")

    for group_name, group_id in group_ids.items():
        safe = re.sub(r"[^A-Z0-9_]", "_", group_name.upper())
        safe = re.sub(r"_+", "_", safe).strip("_")
        if safe:
            replacements[f"{{{{GROUP_{safe}}}}}"] = group_id

    for known in [
        "DG-GUEST-ACCOUNTS",
        "DG-HIGH-RISK-IT-ADMIN",
        "DG-PERMIT-ALL-DEVICES",
        "DG-EXTERNAL-PARTNER-OVERPRIV",
    ]:
        replacements[f"{{{{{known.replace('-', '_')}}}}}"] = group_ids.get(known, "")

    detected = [f"{{{{{match}}}}}" for match in PLACEHOLDER_PATTERN.findall(template_text)]
    missing = [token for token in sorted(set(detected)) if not replacements.get(token)]

    for placeholder, replacement in replacements.items():
        template_text = template_text.replace(placeholder, replacement)
    return template_text, missing


def seed_security(
    client: GraphClient,
    logger: JsonlLogger,
    cfg: dict,
    group_ids: dict[str, str],
    dry_run: bool,
    *,
    disable_security_defaults_flag: bool = False,
) -> dict:
    policy_root = Path(__file__).resolve().parent.parent / "policies" / "entra"
    policy_files = policy_files_in_dir(policy_root)
    if not policy_files:
        logger.event("security.skip", "warn", reason="no-policy-files", path=str(policy_root))
        return {"seeded": 0, "skipped": 0, "securityDefaultsInitialState": None, "securityDefaultsFinalState": None, "securityDefaultsAction": "not-applicable"}

    seeded_count = 0
    skipped_count = 0
    loaded_policies: list[tuple[Path, dict]] = []
    for policy_file in policy_files:
        if not policy_file.is_file():
            continue
        raw_text = policy_file.read_text(encoding="utf-8")
        raw_text, missing = _ca_policy_replacements(raw_text, group_ids, cfg)
        if missing:
            logger.event(
                "security.policy.token-missing",
                "warn",
                reason="missing-required-group-id",
                file=policy_file.name,
                missing=missing,
            )

        try:
            payload = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            logger.event("security.policy.parse-failed", "warn", file=policy_file.name, error=str(exc))
            skipped_count += 1
            continue
        loaded_policies.append((policy_file, _normalize_ca_policy(payload)))

    requires_defaults_off = any(ca_policy_requires_defaults_off(payload) for _, payload in loaded_policies)
    defaults_state = get_security_defaults_state(client, logger) if requires_defaults_off else None
    defaults_initial = defaults_state.get("isEnabled") if defaults_state else None
    defaults_final = defaults_initial
    defaults_action = "not-needed"
    if requires_defaults_off and defaults_initial is True:
        if disable_security_defaults_flag:
            defaults_action = "disable-requested"
            if disable_security_defaults(client, logger, dry_run):
                defaults_final = False
            else:
                defaults_action = "disable-failed"
        else:
            defaults_action = "blocked"
            logger.event("security.defaults.blocking", "warn", reason="enabled-ca-policies-require-security-defaults-off")

    for policy_file, payload in loaded_policies:
        display_name = payload.get("displayName", policy_file.stem)
        if not display_name:
            logger.event("security.policy.skip", "warn", reason="missing-display-name", file=policy_file.name)
            skipped_count += 1
            continue

        if defaults_initial is True and defaults_final is not False and ca_policy_requires_defaults_off(payload):
            logger.event("security.policy.skipped.securityDefaultsEnabled", "warn", policy=display_name, file=policy_file.name)
            skipped_count += 1
            continue

        escaped_name = _safe_graph_filter_value(display_name)
        try:
            existing = first_value(client, f"/identity/conditionalAccess/policies?$filter=displayName eq '{escaped_name}'&$select=id,displayName")
        except RuntimeError as exc:
            existing = None
            logger.event("security.policy.lookup.failed", "warn", policy=display_name, reason=str(exc)[:360])
        if existing:
            logger.event("security.policy.exists", "success", policy=display_name)
            skipped_count += 1
            continue

        if dry_run:
            logger.event("security.policy.wouldCreate", "success", policy=display_name, file=policy_file.name)
            continue

        try:
            client.request("POST", "/identity/conditionalAccess/policies", payload=payload)
            logger.event("security.policy.created", "success", policy=display_name, file=policy_file.name)
            seeded_count += 1
        except RuntimeError as exc:
            msg = str(exc).lower()
            if "conflict" in msg or "already exists" in msg:
                logger.event("security.policy.exists", "success", policy=display_name)
            else:
                logger.event("security.policy.create.failed", "warn", policy=display_name, file=policy_file.name, reason=msg[:240])
                skipped_count += 1

    logger.event("security.seed.complete", "success", seeded=seeded_count, skipped=skipped_count, file_count=len(policy_files))
    return {
        "seeded": seeded_count,
        "skipped": skipped_count,
        "securityDefaultsInitialState": defaults_initial,
        "securityDefaultsFinalState": defaults_final,
        "securityDefaultsAction": defaults_action,
    }


def seed_sample_data(client: GraphClient, logger: JsonlLogger, cfg: dict, group_ids: dict[str, str], team_ids: list[str], *, max_days: int | None, dry_run: bool) -> None:
    all_users_group = group_ids.get(cfg["groupNames"]["allUsers"])
    if not all_users_group:
        logger.event("sample.skip", "error", reason="all-users-group-missing")
        return
    all_users = resolve_users_in_group(
        client,
        all_users_group,
        logger,
        select="id,displayName,userPrincipalName,userType,mail",
    )
    if not all_users:
        logger.event("sample.skip", "error", reason="no-users")
        return

    mailbox_users = [user for user in all_users if user.get("mail")]
    if not mailbox_users:
        logger.event("sample.mailboxAware", "warn", reason="no-mailbox-users")
    all_users_with_mailbox = mailbox_users
    can_seed_onedrive = True

    rng = Random(42)
    subject_samples = [
        "Budget Check-in",
        "Customer Escalation",
        "Quarterly Ops",
        "Proposal Draft",
        "Follow-up and Open Actions",
    ]
    days = min(int(cfg["counts"]["daysOfHistory"]), max_days or int(cfg["counts"]["daysOfHistory"]))
    sample_counts = {
        "mailCreated": 0,
        "mailSkipped": 0,
        "eventsCreated": 0,
        "eventsSkipped": 0,
        "contactsCreated": 0,
        "contactsSkipped": 0,
        "oneDriveCreated": 0,
        "oneDriveSkipped": 0,
        "teamMessagesCreated": 0,
        "teamMessagesSkipped": 0,
    }

    for offset in range(days):
        day = (datetime.now(timezone.utc) - timedelta(days=days - offset - 1)).replace(microsecond=0).date().strftime("%Y-%m-%d")
        subject = f"{rng.choice(subject_samples)} - {day}"
        sender = rng.choice(all_users_with_mailbox) if all_users_with_mailbox else rng.choice(all_users)
        to_user = rng.choice([u for u in all_users if u["id"] != sender["id"]] or all_users)

        if dry_run:
            logger.event("sample.mail.wouldCreate", "success", sender=sender.get("userPrincipalName"), day=day)
        else:
            if sender not in all_users_with_mailbox:
                logger.event("sample.mail.skipped", "warn", reason="sender-no-mailbox", sender=sender.get("userPrincipalName"), day=day)
            else:
                body = {
                    "message": {
                        "subject": subject,
                        "body": {"contentType": "Text", "content": f"Operational context for {day}. Include blockers, owners, and due dates."},
                        "toRecipients": [{"emailAddress": {"address": to_user["userPrincipalName"]}}],
                    },
                    "saveToSentItems": True,
                }
                try:
                    client.request("POST", f"/users/{sender['id']}/sendMail", payload=body)
                    sample_counts["mailCreated"] += 1
                except RuntimeError as exc:
                    sample_counts["mailSkipped"] += 1
                    logger.event(
                        "sample.mail.skipped",
                        "warn",
                        reason="mailbox-rest-not-ready-or-scope-blocked",
                        sender=sender.get("userPrincipalName"),
                        day=day,
                        error=str(exc)[:360],
                    )

        event_owner = rng.choice(all_users_with_mailbox) if all_users_with_mailbox else rng.choice(all_users)
        if dry_run:
            logger.event("sample.event.wouldCreate", "success", owner=event_owner.get("userPrincipalName"), day=day)
        else:
            if event_owner not in all_users_with_mailbox:
                logger.event("sample.event.skipped", "warn", reason="owner-no-mailbox", owner=event_owner.get("userPrincipalName"), day=day)
            else:
                event_payload = {
                    "subject": f"Ops Sync - {day}",
                    "body": {"contentType": "Text", "content": "Status, blockers, action owners, and dependencies."},
                    "start": {"dateTime": f"{day}T09:00:00.0000000", "timeZone": cfg["tenant"]["timeZone"]},
                    "end": {"dateTime": f"{day}T10:00:00.0000000", "timeZone": cfg["tenant"]["timeZone"]},
                    "attendees": [{"emailAddress": {"address": event_owner["userPrincipalName"]}, "type": "required"}],
                    "isReminderOn": False,
                }
                try:
                    client.request("POST", f"/users/{event_owner['id']}/events", payload=event_payload)
                    sample_counts["eventsCreated"] += 1
                except RuntimeError as exc:
                    sample_counts["eventsSkipped"] += 1
                    logger.event(
                        "sample.event.skipped",
                        "warn",
                        reason="mailbox-rest-not-ready-or-scope-blocked",
                        owner=event_owner.get("userPrincipalName"),
                        day=day,
                        error=str(exc)[:360],
                    )

        contact_owner = rng.choice(all_users_with_mailbox) if all_users_with_mailbox else rng.choice(all_users)
        if dry_run:
            logger.event("sample.contact.wouldCreate", "success", owner=contact_owner.get("userPrincipalName"), day=day)
        else:
            if contact_owner not in all_users_with_mailbox:
                logger.event("sample.contact.skipped", "warn", reason="owner-no-mailbox", owner=contact_owner.get("userPrincipalName"), day=day)
            else:
                contact_payload = {
                    "givenName": "Vendor",
                    "surname": "Ops",
                    "emailAddresses": [
                        {"address": f"vendor.{offset + 1}@contoso-partner.com", "name": "Vendor Ops"},
                    ],
                    "companyName": "Contoso Partner",
                    "mobilePhone": f"+1-555-{offset + 1:04d}",
                }
                try:
                    client.request("POST", f"/users/{contact_owner['id']}/contacts", payload=contact_payload)
                    sample_counts["contactsCreated"] += 1
                except RuntimeError as exc:
                    sample_counts["contactsSkipped"] += 1
                    logger.event(
                        "sample.contact.skipped",
                        "warn",
                        reason="mailbox-rest-not-ready-or-scope-blocked",
                        owner=contact_owner.get("userPrincipalName"),
                        day=day,
                        error=str(exc)[:360],
                    )

        drive_owner = rng.choice(all_users)
        if dry_run:
            logger.event("sample.onedrive.wouldCreate", "success", owner=drive_owner.get("userPrincipalName"), day=day)
        else:
            if not can_seed_onedrive:
                logger.event("sample.onedrive.skipped", "warn", owner=drive_owner.get("userPrincipalName"), day=day, reason="service-unavailable")
            else:
                content = f"Seeded document from {day}. Topic: {subject}. Contains business context."
                path = f"Documents/proposal-{offset + 1}.md"
                target = f"{GRAPH_ROOT}/users/{drive_owner['id']}/drive/root:/{quote(path, safe='/')}:/content"
                response = client.session.put(target, data=content.encode("utf-8"), headers={"Authorization": client.session.headers["Authorization"], "Content-Type": "text/plain"})
                status_code = response.status_code
                if status_code in (200, 201):
                    sample_counts["oneDriveCreated"] += 1
                    logger.event(
                        "graph.request",
                        "success",
                        method="PUT",
                        path=f"/users/{drive_owner['id']}/drive/root:/{path}:/content",
                        status_code=status_code,
                    )
                else:
                    sample_counts["oneDriveSkipped"] += 1
                    logger.event(
                        "sample.onedrive.failed",
                        "warn",
                        owner=drive_owner.get("userPrincipalName"),
                        day=day,
                        status_code=status_code,
                        reason=response.text,
                    )
                    lower_message = response.text.lower()
                    if status_code == 404 and "mysite not found" in lower_message:
                        can_seed_onedrive = False

        for team_id in team_ids:
            channels_payload = client.request("GET", f"/teams/{team_id}/channels?$select=id,displayName").get("value", [])
            channels_to_seed = [c for c in channels_payload if c.get("displayName") in {"General", "Incidents", "Projects"}]
            for channel in channels_to_seed:
                if dry_run:
                    logger.event("sample.teamsmessage.wouldCreate", "success", team=team_id, channel=channel["displayName"], day=day)
                else:
                    message = {
                        "body": {
                            "contentType": "html",
                            "content": f"<p>Seed activity from {day} with context and action points.</p>",
                        }
                    }
                    try:
                        client.request(
                            "POST",
                            f"/teams/{team_id}/channels/{channel['id']}/messages",
                            payload=message,
                        )
                        sample_counts["teamMessagesCreated"] += 1
                    except RuntimeError as exc:
                        sample_counts["teamMessagesSkipped"] += 1
                        logger.event(
                            "sample.teamsmessage.skipped",
                            "warn",
                            reason="teams-message-write-blocked",
                            team=team_id,
                            channel=channel["displayName"],
                            day=day,
                            error=str(exc)[:360],
                        )

    logger.event("sample.seed.done", "success", users=len(all_users), days=days, mailboxUsers=len(all_users_with_mailbox), **sample_counts)


def _device_platform_meta(platform: str, cfg: dict) -> dict[str, str]:
    os_map = {
        "windows11": ("Windows", "10.0.22631"),
        "macos": ("macOS", "13.6"),
        "ios": ("iOS", "17.4"),
        "android": ("Android", "14"),
    }
    default_os = ("Unknown", "1.0")
    base_name = cfg.get("tenant", {}).get("tenantName", "Seed Tenant").replace(" ", "")
    serial_prefix = str(cfg.get("devices", {}).get("deviceSerialPrefix", "SEED-"))
    os_name, os_version = os_map.get(platform, default_os)
    return {
        "operatingSystem": os_name,
        "operatingSystemVersion": os_version,
        "manufacturer": "Contoso",
        "model": f"{platform.title()}-Profile",
        "deviceIdSeed": f"{base_name}:{serial_prefix}:{platform}",
    }


def _build_device_payload(device: dict, cfg: dict) -> dict:
    meta = _device_platform_meta(device["platform"], cfg)
    device_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, f"{meta['deviceIdSeed']}:{device['name']}")
    identity_provider = f"https://sts.windows.net/{cfg['tenant']['tenantId']}/"
    return {
        "accountEnabled": True,
        "displayName": device["name"],
        "deviceId": device_uuid.hex,
        "alternativeSecurityIds": [
            {
                "type": 2,
                "identityProvider": identity_provider,
                "key": base64.b64encode(device_uuid.bytes).decode("ascii"),
            }
        ],
        "operatingSystem": meta["operatingSystem"],
        "operatingSystemVersion": meta["operatingSystemVersion"],
        "deviceOwnership": "Company",
        "isManaged": True,
        "trustType": "AzureAD",
    }


def _ensure_directory_object_member(
    client: GraphClient,
    logger: JsonlLogger,
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
    except RuntimeError as exc:
        msg = str(exc).lower()
        # In some tenants / counts endpoints can be denied. Fall back to permissive behavior.
        logger.event("device.group_member.check.skipped", "warn", group=group_name, objectId=object_id, reason=msg[:200])

    if dry_run:
        logger.event("device.group_member.wouldCreate", "success", group=group_name, objectId=object_id)
        return

    payload = {"@odata.id": f"{GRAPH_ROOT}/directoryObjects/{object_id}"}
    try:
        client.request("POST", f"/groups/{group_id}/members/$ref", payload=payload)
        logger.event("device.group_member.added", "success", group=group_name, objectId=object_id)
    except RuntimeError as exc:
        msg = str(exc).lower()
        if "already exists" in msg or "one or more added objects" in msg:
            logger.event("device.group_member.exists", "success", group=group_name, objectId=object_id)
        else:
            logger.event("device.group_member.failed", "warn", group=group_name, objectId=object_id, reason=msg[:240])


def _ensure_device(
    client: GraphClient,
    logger: JsonlLogger,
    device: dict,
    cfg: dict,
    *,
    dry_run: bool,
) -> dict | None:
    if not device.get("name"):
        return None
    safe_name = _safe_graph_filter_value(device["name"])
    existing = first_value(client, f"/devices?$filter=displayName eq '{safe_name}'&$select=id,displayName,deviceId")
    if existing:
        logger.event("device.directory.exists", "success", device=device["name"], id=existing.get("id"))
        return existing

    payload = _build_device_payload(device, cfg)
    if dry_run:
        logger.event("device.directory.wouldCreate", "success", device=device["name"])
        return {
            "id": f"DRY-RUN-DEVICE-{device['name']}",
            "displayName": device["name"],
        }
    try:
        created = client.request("POST", "/devices", payload=payload)
        logger.event("device.directory.created", "success", device=device["name"], id=created.get("id"))
        return created
    except RuntimeError as exc:
        logger.event("device.directory.create.failed", "warn", device=device["name"], reason=str(exc)[:240])
        return None


def build_device_inventory(cfg: dict) -> list[dict]:
    device_cfg = cfg.get("devices", {})
    windows_count = int(device_cfg.get("windows11Seed", 0))
    macos_count = int(device_cfg.get("macosSeed", 0))
    ios_count = int(device_cfg.get("iosSeed", 0))
    android_count = int(device_cfg.get("androidSeed", 0))
    apple_serials = list(device_cfg.get("appleDeviceSerials", []))
    prefix = str(device_cfg.get("deviceSerialPrefix", "SEED-"))

    devices: list[dict] = []
    for index in range(1, windows_count + 1):
        devices.append(
            {
                "name": f"{prefix}WIN-{index:03d}",
                "platform": "windows11",
                "type": "virtual-lab",
                "plan": "intune-managed",
                "compliance_state": "compliant" if index % 2 == 0 else "noncompliant",
                "ownerRole": "corp_user",
            }
        )
    for index in range(1, macos_count + 1):
        serial = apple_serials[index - 1] if index - 1 < len(apple_serials) else f"{prefix}MAC-{index:03d}"
        devices.append(
            {
                "name": serial,
                "platform": "macos",
                "type": "lab-mac",
                "plan": "intune-managed",
                "compliance_state": "compliant",
                "ownerRole": "admin_device",
            }
        )
    for index in range(1, ios_count + 1):
        serial = f"{prefix}IOS-{index:03d}"
        devices.append(
            {
                "name": serial,
                "platform": "ios",
                "type": "device-mobile",
                "plan": "mdm-mobile",
                "compliance_state": "compliant",
                "ownerRole": "mobile_user",
            }
        )
    for index in range(1, android_count + 1):
        serial = f"{prefix}AND-{index:03d}"
        devices.append(
            {
                "name": serial,
                "platform": "android",
                "type": "device-mobile",
                "plan": "mdm-mobile",
                "compliance_state": "compliant" if index % 3 else "noncompliant",
                "ownerRole": "mobile_user",
            }
        )
    return devices


def ensure_device_group(client: GraphClient, logger: JsonlLogger, display_name: str) -> dict[str, str] | None:
    display_value = _safe_graph_filter_value(display_name)
    existing = first_value(client, f"/groups?$filter=displayName eq '{display_value}'")
    if existing:
        logger.event("device_group.exists", "success", group=display_name)
        return existing

    payload = {
        "displayName": display_name,
        "mailEnabled": False,
        "mailNickname": mail_nickname(display_name),
        "securityEnabled": True,
    }
    if client.dry_run:
        logger.event("device_group.wouldCreate", "success", group=display_name)
        return {
            "id": f"DRY-RUN-{display_name}",
            "displayName": display_name,
        }

    created = client.request("POST", "/groups", payload=payload)
    logger.event("device_group.created", "success", group=display_name)
    return created


def _has_target_assignment(existing: dict, target_type: str) -> bool:
    for assignment in existing.get("value", []):
        target = assignment.get("target", {})
        if target.get("@odata.type") == target_type:
            return True
    return False


def _target_device_group(platform: str) -> str:
    if platform.startswith("windows"):
        return DEVICE_GROUPS["windows"]
    if platform.startswith("mac"):
        return DEVICE_GROUPS["macos"]
    if platform.startswith("ios"):
        return DEVICE_GROUPS["ios"]
    if platform.startswith("android"):
        return DEVICE_GROUPS["android"]
    return DEVICE_GROUPS["all"]


def build_scenario_plan(cfg: dict) -> dict:
    scenario_cfg = cfg.get("scenarioEngine", {})
    names = scenario_cfg.get(
        "scenarios",
        [
            "Payroll data overshared",
            "Executive impersonation",
            "Vendor invoice fraud",
            "HR onboarding",
            "Security incident response",
            "Lost device",
            "Conditional Access rollout",
            "Finance close",
            "Customer escalation",
            "Procurement renewal",
            "Legal hold request",
            "Copilot oversharing discovery",
            "DLP near miss",
            "Malware attachment simulation",
            "Phishing report exercise",
        ],
    )
    days = int(scenario_cfg.get("days", cfg.get("counts", {}).get("daysOfHistory", 90)))
    events_per_day = int(scenario_cfg.get("eventsPerDay", 3))
    planned = []
    for day_index in range(days):
        for event_index in range(events_per_day):
            scenario = names[(day_index + event_index) % len(names)]
            planned.append(
                {
                    "dayOffset": day_index,
                    "sequence": event_index + 1,
                    "scenario": scenario,
                    "workloads": ["mail", "calendar", "teams", "sharepoint", "onedrive"],
                    "artifactOnlyAllowed": True,
                }
            )
    return {
        "name": "enterprise-lab-scenario-plan",
        "days": days,
        "eventsPerDay": events_per_day,
        "scenarios": names,
        "plannedEvents": planned,
    }


def _read_catalog(root: Path) -> dict:
    catalog_path = root / "configs" / "enterprise-policy-artifact-catalog.json"
    if not catalog_path.exists():
        return {"exchange": [], "entra": [], "intune": [], "purview": [], "defender": [], "windows365": []}
    return json.loads(catalog_path.read_text(encoding="utf-8"))


def build_policy_artifact_plan(root: Path) -> dict:
    catalog = _read_catalog(root)
    counts = {
        "exchange": len(catalog.get("exchange", [])),
        "entra": len(catalog.get("entra", [])),
        "intune": len(catalog.get("intune", [])),
        "purview": len(catalog.get("purview", [])),
        "defender": len(catalog.get("defender", [])),
        "windows365": len(catalog.get("windows365", [])),
    }
    return {
        "generatedAt": utc_now(),
        "catalog": catalog,
        "counts": counts,
        "total": sum(counts.values()),
    }


def _policy_command_template(command: str, cfg: dict) -> str:
    tenant_domain = cfg.get("tenant", {}).get("tenantDomain", "tenant.domain")
    return command.replace("tenant.domain", tenant_domain)


def _exchange_command_type(command: str) -> str:
    front = _extract_command_front(command).lower()
    if front == "m365":
        return "m365"
    if re.match(r"^(New|Set|Get|Remove|Enable|Disable)-", front):
        return "powershell"
    return "other"


def _extract_command_front(command: str) -> str:
    try:
        cmd_parts = shlex.split(command.strip())
    except ValueError:
        cmd_parts = command.strip().split()
    return cmd_parts[0] if cmd_parts else ""


def _classify_exchange_policy_error(
    return_code: int,
    stdout: str,
    stderr: str,
    command_type: str,
) -> str | None:
    if return_code == 0:
        return None
    combined = f"{stdout}\n{stderr}".lower()
    if command_type == "m365":
        unsupported_phrases = [
            "command \"m365",
            "command 'm365",
            "command was not found",
            "unknown command",
            "error: command not found",
            "does not match any",
        ]
        if any(phrase in combined for phrase in unsupported_phrases):
            return "unsupported-m365-command"
    if command_type == "powershell":
        if "is not recognized as the name of a cmdlet" in combined:
            return "unsupported-powershell-cmdlet"
        if "is not recognized as a cmdlet" in combined:
            return "unsupported-powershell-cmdlet"
    if "command not found" in combined and "command" in combined:
        return "unsupported-command"
    if "module 'exchangeonlinemanagement' was not found" in combined:
        return "missing-exchange-module"
    return None


def _run_exchange_policy_commands(
    logger: JsonlLogger,
    debug_logger: DebugLogger | None,
    cfg: dict,
    policy_specs: list[dict],
    *,
    dry_run: bool,
) -> tuple[int, int, int, list[dict]]:
    m365_executable = shutil.which("m365")
    pwsh_executable = shutil.which("pwsh")
    if not m365_executable and not pwsh_executable:
        logger.event("exchange.seed.tool_missing", "warn", reason="m365-cli-missing")
        return 0, 0, 0, []

    planned = 0
    executed = 0
    failed = 0
    command_results: list[dict] = []
    for policy in policy_specs:
        policy_name = str(policy.get("name", "policy"))
        for raw_command in policy.get("commands", []):
            planned += 1
            command = _policy_command_template(str(raw_command), cfg)
            command_type = _exchange_command_type(command)
            if command_type == "m365" and not m365_executable:
                command_results.append(
                    {
                        "policy": policy_name,
                        "command": command,
                        "status": "skipped",
                        "reason": "m365-cli-missing",
                    }
                )
                continue
            if command_type == "powershell" and not pwsh_executable:
                command_results.append(
                    {
                        "policy": policy_name,
                        "command": command,
                        "status": "skipped",
                        "reason": "powershell-missing",
                    }
                )
                continue
            cmd_parts = _build_exchange_command(
                command,
                m365_executable=m365_executable,
                pwsh_executable=pwsh_executable,
            )
            if not cmd_parts:
                command_results.append(
                    {
                        "policy": policy_name,
                        "command": command,
                        "status": "skipped",
                        "reason": "empty-command",
                    }
                )
                continue
            if cmd_parts[0] == "m365":
                cmd_parts[0] = m365_executable
            rc, command_stdout, command_stderr = _run_command_capture(
                logger,
                debug_logger,
                cmd_parts,
                name=f"exchange.cmd.{policy.get('name', 'policy')}",
                step="exchange",
                dry_run=dry_run,
                allow_failure=True,
                timeout=180,
            )
            executed += 1
            if dry_run:
                status = "would-run"
                reason = None
            else:
                reason = _classify_exchange_policy_error(
                    return_code=rc,
                    stdout=command_stdout,
                    stderr=command_stderr,
                    command_type=command_type,
                )
                if reason:
                    status = "skipped"
                else:
                    status = "ok" if rc == 0 else "failed"
                    if rc != 0:
                        failed += 1
            command_entry = {
                "policy": policy_name,
                "command": command,
                "status": status,
                "returnCode": rc,
            }
            if reason:
                command_entry["reason"] = reason
            command_results.append(command_entry)
    return planned, executed, failed, command_results


def _build_exchange_command(command: str, *, m365_executable: str | None, pwsh_executable: str | None) -> list[str]:
    stripped = command.strip()
    if not stripped:
        return []
    cmd_parts = shlex.split(stripped)
    if not cmd_parts:
        return []
    if cmd_parts[0] == "m365" and m365_executable:
        cmd_parts[0] = m365_executable
        return cmd_parts
    if re.match(r"^(New|Set|Get|Remove|Enable|Disable)-", cmd_parts[0]) and pwsh_executable:
        script = (
            "$ErrorActionPreference='Stop'; "
            "Import-Module ExchangeOnlineManagement; "
            f"{stripped}"
        )
        return [pwsh_executable, "-NoLogo", "-NoProfile", "-Command", script]
    return cmd_parts


def _assign_to_all_devices(
    client: GraphClient,
    logger: JsonlLogger,
    *,
    policy_type: str,
    policy_id: str,
    policy_name: str,
    dry_run: bool,
) -> None:
    assign_endpoint = f"/deviceManagement/{policy_type}/{policy_id}/assign"
    existing_endpoint = f"/deviceManagement/{policy_type}/{policy_id}/assignments"

    try:
        existing = client.request("GET", existing_endpoint)
    except RuntimeError as exc:
        msg = str(exc).lower()
        if "not found" in msg or "does not exist" in msg:
            existing = {"value": []}
        else:
            logger.event("device_policy.assign.skipped", "warn", policy=policy_name, reason="assignments-read-failed", error=msg)
            return

    if _has_target_assignment(existing, "#microsoft.graph.allDevicesAssignmentTarget"):
        logger.event("device_policy.assign.exists", "success", policy=policy_name, target="allDevices")
        return

    if dry_run:
        logger.event("device_policy.assign.would", "success", policy=policy_name, policyType=policy_type, target="allDevices")
        return

    payload = {"assignments": [{"target": {"@odata.type": "#microsoft.graph.allDevicesAssignmentTarget"}}]}
    try:
        client.request("POST", assign_endpoint, payload=payload)
        logger.event("device_policy.assigned", "success", policy=policy_name, policyType=policy_type, target="allDevices")
    except RuntimeError as exc:
        message = str(exc).lower()
        logger.event("device_policy.assign.failed", "warn", policy=policy_name, policyType=policy_type, reason=message[:240])


def seed_devices(
    client: GraphClient,
    logger: JsonlLogger,
    cfg: dict,
    *,
    dry_run: bool,
) -> None:
    devices = build_device_inventory(cfg)
    if not devices:
        logger.event("device.skip", "warn", reason="no-devices-configured")
        return

    device_group_ids = {
        DEVICE_GROUPS["all"]: ensure_device_group(client, logger, DEVICE_GROUPS["all"]),
        DEVICE_GROUPS["windows"]: ensure_device_group(client, logger, DEVICE_GROUPS["windows"]),
        DEVICE_GROUPS["macos"]: ensure_device_group(client, logger, DEVICE_GROUPS["macos"]),
        DEVICE_GROUPS["ios"]: ensure_device_group(client, logger, DEVICE_GROUPS["ios"]),
    }
    device_group_id_lookup = {name: (entry.get("id") if isinstance(entry, dict) else None) for name, entry in device_group_ids.items()}
    logger.event("device_group.plan", "success", groups=list(DEVICE_GROUPS.values()), count=len(DEVICE_GROUPS))

    logger.event(
        "device.plan",
        "success",
        planned=len(devices),
        windows=sum(1 for d in devices if d["platform"] == "windows11"),
        macos=sum(1 for d in devices if d["platform"] == "macos"),
        ios=sum(1 for d in devices if d["platform"] == "ios"),
    )
    logger.event("device.inventory", "success", devices=devices)

    if dry_run:
        # No tenant writes; provide the exact object set that would be created.
        logger.event(
            "device.seed.complete",
            "success",
            mode="dry-run",
            plannedDeviceCount=len(devices),
            endpointPolicyAssignments="would",
        )
        return

    created_devices = []
    for device in devices:
        created = _ensure_device(client, logger, device, cfg, dry_run=dry_run)
        if not created:
            continue
        created_devices.append(created)

        platform_group_name = _target_device_group(device["platform"])
        _ensure_directory_object_member(
            client,
            logger,
            device_group_id_lookup.get(DEVICE_GROUPS["all"], ""),
            DEVICE_GROUPS["all"],
            created.get("id", ""),
            dry_run=dry_run,
        )
        _ensure_directory_object_member(
            client,
            logger,
            device_group_id_lookup.get(platform_group_name, ""),
            platform_group_name,
            created.get("id", ""),
            dry_run=dry_run,
        )

    # Assign existing Intune policies where the current token has Intune configuration scope.
    try:
        compliance_policies = client.request("GET", "/deviceManagement/deviceCompliancePolicies?$select=id,displayName").get("value", [])
    except RuntimeError as exc:
        compliance_policies = []
        logger.event("device.intune_policy_lookup.skipped", "warn", policyType="deviceCompliancePolicies", reason=str(exc)[:240])

    try:
        config_policies = client.request("GET", "/deviceManagement/deviceConfigurations?$select=id,displayName").get("value", [])
    except RuntimeError as exc:
        config_policies = []
        logger.event("device.intune_policy_lookup.skipped", "warn", policyType="deviceConfigurations", reason=str(exc)[:240])

    for policy in compliance_policies:
        _assign_to_all_devices(
            client,
            logger,
            policy_type="deviceCompliancePolicies",
            policy_id=policy["id"],
            policy_name=policy.get("displayName", policy["id"]),
            dry_run=dry_run,
        )

    for policy in config_policies:
        _assign_to_all_devices(
            client,
            logger,
            policy_type="deviceConfigurations",
            policy_id=policy["id"],
            policy_name=policy.get("displayName", policy["id"]),
            dry_run=dry_run,
        )

    logger.event(
        "device.seed.complete",
        "success",
        plannedDeviceCount=len(devices),
        createdDeviceCount=len(created_devices),
        windowsProfiles=len([d for d in devices if d["platform"] == "windows11"]),
        macProfiles=len([d for d in devices if d["platform"] == "macos"]),
        iosProfiles=len([d for d in devices if d["platform"] == "ios"]),
        compliancePolicies=len(compliance_policies),
        configurationPolicies=len(config_policies),
    )


def _build_mdm_enrollment_plan(cfg: dict, devices: list[dict]) -> dict:
    windows_count = sum(1 for device in devices if device["platform"] == "windows11")
    macos_count = sum(1 for device in devices if device["platform"] == "macos")
    ios_count = sum(1 for device in devices if device["platform"] == "ios")
    tenant_domain = cfg.get("tenant", {}).get("tenantDomain", "tenant")
    tenant_name = cfg.get("tenant", {}).get("tenantName", tenant_domain)
    windows365_plan = build_windows365_plan(cfg)

    return {
        "tenantName": tenant_name,
        "tenantDomain": tenant_domain,
        "generatedAt": utc_now(),
        "summary": {
            "plannedDevices": len(devices),
            "windows11": windows_count,
            "macos": macos_count,
            "ios": ios_count,
            "deviceGroups": list(DEVICE_GROUPS.values()),
            "managedTargets": windows365_plan["managedDeviceTargets"],
        },
        "windows365": windows365_plan,
        "readiness": {
            "tenant": tenant_domain,
            "managedDeviceEndpoint": "/deviceManagement/managedDevices",
            "commands": [
                "az rest --method GET --url https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=10 --output json",
                "az rest --method GET --url https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies?$top=10 --output json",
                "az rest --method GET --url https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations?$top=10 --output json",
                "az rest --method GET --url https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/cloudPCs?$top=10 --output json",
                "az rest --method GET --url https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/provisioningPolicies?$top=10 --output json",
            ],
        },
        "playbook": {
            "phase1_inventory": [
                {
                    "name": "Validate Entra device objects and target groups",
                    "commands": [
                        f"Get-MgDevice -Filter \"startswith(displayName,'{cfg.get('devices', {}).get('deviceSerialPrefix', 'SEED-')}')\"",
                        f"Get-MgGroup -Filter \"displayName eq '{DEVICE_GROUPS['all']}'\"",
                        f"Get-MgGroup -Filter \"displayName eq '{DEVICE_GROUPS['windows']}'\"",
                        f"Get-MgGroup -Filter \"displayName eq '{DEVICE_GROUPS['macos']}'\"",
                        f"Get-MgGroup -Filter \"displayName eq '{DEVICE_GROUPS['ios']}'\"",
                    ],
                    "notes": "Use for pre-enrollment validation before endpoint connectivity is active.",
                }
            ],
            "phase2_policies": [
                {
                    "name": "Verify seeded compliance and configuration policy state",
                    "commands": [
                        "Get-MgDeviceManagementDeviceCompliancePolicy -All",
                        "Get-MgDeviceManagementDeviceConfiguration -All",
                        "Get-MgDeviceManagementDeviceEnrollmentConfiguration -All",
                    ],
                    "notes": "The Python seed writes policies and assignments; command output should show those in real fleet state.",
                }
            ],
            "phase3_enrollment": [
                {
                    "name": "Windows 365 Enterprise pilot",
                    "commands": [
                        f"Assign {windows365_plan['preferredSkuPattern']} to {windows365_plan['pilotUserAlias']}",
                        "Validate virtualEndpoint visibility and existing provisioning policies",
                        "Confirm the pilot Cloud PC resolves to a managedDeviceId in Intune",
                    ],
                    "notes": "Phase 1 success is one real Intune-managed Cloud PC, not synthetic /devices writes.",
                },
                {
                    "name": "Windows 11 enrollment (pilot)",
                    "commands": [
                        f"Create {windows_count} Windows 11 managed onboarding slots (pilot ring)",
                        "Distribute Autopilot profile metadata and enrollment status tracking",
                        "Assign all Windows profile policies to GG-Endpoint-Windows11 and GG-Endpoint-AllDevices",
                    ],
                    "notes": "Placeholder for actual onboarding mechanism (Intune/Azure Virtual Desktop/Autopilot pipeline).",
                },
                {
                    "name": "macOS enrollment (pilot)",
                    "commands": [
                        f"Create {macos_count} macOS managed onboarding slots",
                        "Bind macOS serials to company ownership records",
                        "Assign endpoint profiles and compliance policy checks",
                    ],
                    "notes": "Placeholder for Apple MDM profile upload and supervised flow.",
                },
                {
                    "name": "iOS/iPadOS enrollment (pilot)",
                    "commands": [
                        f"Create {ios_count} mobile endpoint onboarding slots",
                        "Define MDM app-protection and conditional-access placement",
                    ],
                    "notes": "Placeholder for Apple iOS enrollment profile and device ownership mapping.",
                },
            ],
            "phase4_reporting": [
                {
                    "name": "Post-enrollment managed-device checks",
                    "commands": [
                        "Get-MgDeviceManagementManagedDevice -All | Select-Object deviceName,complianceState,operatingSystem,deviceType,managementState,azureADDeviceId",
                    ],
                    "notes": "Expected output for an actually onboarded managed-device fleet.",
                }
            ],
        },
    }


def emit_mdm_artifact(
    run_dir: Path,
    logger: JsonlLogger,
    cfg: dict,
    devices: list[dict],
    *,
    dry_run: bool,
) -> str:
    artifact_path = run_dir / "mdm-fleet-manifest.json"
    artifact_payload = _build_mdm_enrollment_plan(cfg, devices)
    artifact_path.write_text(json.dumps(artifact_payload, indent=2, sort_keys=True), encoding="utf-8")
    logger.event(
        "device.mdm_artifact.written" if not dry_run else "device.mdm_artifact.wouldWrite",
        "success",
        path=str(artifact_path),
        dryRun=dry_run,
    )
    return str(artifact_path)


def seed_exchange_baseline(
    logger: JsonlLogger,
    debug_logger: DebugLogger | None,
    cfg: dict,
    run_dir: Path,
    *,
    dry_run: bool,
) -> list[dict]:
    policy_root = Path(__file__).resolve().parent.parent / "policies" / "exchange"
    policy_specs: list[dict] = []
    for policy_file in policy_files_in_dir(policy_root):
        if not policy_file.is_file():
            continue
        try:
            policy_spec = json.loads(policy_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            logger.event("exchange.policy.parse-failed", "warn", file=policy_file.name, error=str(exc))
            continue
        policy_spec.setdefault("name", policy_file.stem)
        policy_spec.setdefault("source", policy_file.name)
        policy_spec.setdefault("state", "artifact-only")
        logger.event("exchange.policy.loaded", "success", file=policy_file.name, name=policy_spec.get("name"))
        policy_specs.append(policy_spec)

    if not policy_specs:
        logger.event("exchange.seed.policies.empty", "warn", reason="no-exchange-policy-files", path=str(policy_root))
        policy_specs = [
            {
                "name": "DEF-Standard-SafeLinks",
                "description": "Safe Links baseline preset (strict mode intent).",
                "policyType": "SafeLinks",
                "state": "enabled",
                "template": "New-SafeLinksPolicy/Set-SafeLinksRule equivalents",
                "commands": ["New-SafeLinksPolicy", "Set-SafeLinksRule", "Get-SafeLinksPolicy"],
            },
            {
                "name": "DEF-Standard-SafeAttachment",
                "description": "Safe Attachments baseline preset (protect mode).",
                "policyType": "SafeAttachment",
                "state": "enabled",
                "template": "New-SafeAttachmentPolicy",
                "commands": ["New-SafeAttachmentPolicy", "Get-SafeAttachmentPolicy"],
            },
            {
                "name": "DEF-Standard-AntiPhish",
                "description": "Anti-phishing baseline with mailbox intelligence.",
                "policyType": "AntiPhish",
                "state": "enabled",
                "template": "New-AntiPhishPolicy",
                "commands": ["New-AntiPhishPolicy", "Get-AntiPhishPolicy"],
            },
        ]
        for policy in policy_specs:
            logger.event("exchange.policy.fallback", "success", name=policy["name"])

    for policy in policy_specs:
        policy["commands"] = [
            _policy_command_template(str(command), cfg)
            for command in policy.get("commands", [])
        ]

    command_plans = []
    exchange_payload = {
        "tenant": cfg["tenant"]["tenantDomain"],
        "seededPolicies": policy_specs,
        "plannedMailboxes": [
            "it.helpdesk",
            "finance.request",
            "conf-bridge-1",
            "conf-bridge-2",
        ],
        "generatedAt": utc_now(),
        "mode": "dry-run" if dry_run else "artifact-only",
        "commandCatalog": [
            {
                "name": policy["name"],
                "policyType": policy.get("policyType"),
                "commands": policy.get("commands", []),
                "notes": policy.get("notes", ""),
            }
            for policy in policy_specs
        ],
    }
    artifact = run_dir / "exchange-baseline-manifest.json"
    artifact.write_text(json.dumps(exchange_payload, indent=2, sort_keys=True), encoding="utf-8")
    logger.event("exchange.artifact.written", "success", path=str(artifact))

    # If the environment has Microsoft 365 CLI, verify connectivity as a read-only readiness check.
    m365_executable = shutil.which("m365")
    if not m365_executable:
        logger.event("exchange.seed.skipped", "warn", reason="m365-cli-missing")
        logger.event("exchange.command_summary", "success", planned=0, executed=0, failed=0, mode="artifact-only")
        return policy_specs

    status_rc = 127
    if m365_executable:
        status_rc = run_command(
            logger,
            [m365_executable, "status", "--output", "json"],
            name="exchange.readiness.status",
            step="exchange",
            dry_run=dry_run,
            allow_failure=True,
            timeout=180,
            debug_logger=debug_logger,
        )
        if status_rc != 0:
            logger.event(
                "exchange.connectivity.skipped",
                "warn",
                reason="m365-cli-not-authenticated-or-network-issue",
                path=str(m365_executable),
            )
    else:
        logger.event("exchange.connectivity.skipped", "warn", reason="m365-cli-missing")

    # Collect a small mailbox count hint when available; failures here should not block tenant build.
    status_mailbox = 127
    if m365_executable:
        status_mailbox = run_command(
            logger,
            [m365_executable, "outlook", "report", "mailboxusagemailboxcount", "--period", "D30", "--output", "json"],
            name="exchange.readiness.mailboxcount",
            step="exchange",
            dry_run=dry_run,
            allow_failure=True,
            timeout=300,
            debug_logger=debug_logger,
        )

    policy_command_count, executed_count, failed_count, policy_command_results = _run_exchange_policy_commands(
        logger,
        debug_logger,
        cfg,
        policy_specs,
        dry_run=dry_run,
    )
    command_plans.extend(
        {
            "policy": item.get("policy", "unknown"),
            "name": item.get("policy", "unknown"),
            "command": item.get("command", ""),
            "status": item.get("status", "unknown"),
            "returnCode": item.get("returnCode"),
            **({"reason": item["reason"]} if "reason" in item else {}),
        }
        for item in policy_command_results
    )
    command_plans.extend(
        [
            {
                "name": "mailboxUsage",
                "command": "outlook report mailboxusagemailboxcount --period D30",
                "status": "ok" if status_mailbox == 0 else "failed",
            },
            {
                "name": "m365-status",
                "command": "m365 status --output json",
                "status": "ok" if status_rc == 0 else "failed",
            },
        ]
    )
    exchange_payload["commandSummary"] = {
        "plannedPolicyCommands": policy_command_count,
        "executedPolicyCommands": 0 if dry_run else executed_count,
        "failedPolicyCommands": 0 if dry_run else failed_count,
        "skippedPolicyCommands": 0 if dry_run else sum(
            1
            for item in policy_command_results
            if item.get("status") in {"skipped", "would-run"}
        ),
        "unsupportedPolicyCommands": 0
        if dry_run
        else sum(1 for item in policy_command_results if str(item.get("reason", "")).startswith("unsupported-")),
        "commandPlans": command_plans,
    }
    exchange_payload["diagnostics"] = {
        "commandLog": "workload-seed-az-debug.log",
        "commandCount": len(command_plans),
    }
    exchange_payload["mode"] = "artifact-and-command-attempts"
    artifact.write_text(json.dumps(exchange_payload, indent=2, sort_keys=True), encoding="utf-8")
    logger.event("exchange.command_summary", "success", planned=policy_command_count, executed=executed_count, failed=failed_count, dryRun=dry_run)
    logger.event("exchange.seed.artifact-only", "warn", reason="command-only-baseline-ready")
    return policy_specs


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Azure CLI + Graph enterprise bootstrap workload seed.")
    parser.add_argument("--config", type=Path, default=Path("tenant-bootstrap/config.example.json"))
    parser.add_argument("--run-name", default=f"az-workload-{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    parser.add_argument("--steps", default="licenses,windows365,teams,intune,security,devices,exchange,sample")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--days", type=int, default=None)
    parser.add_argument("--disable-security-defaults", action="store_true")
    parser.add_argument("--interactive", action="store_true", help="Use delegated interactive Graph auth with a public client app.")
    parser.add_argument("--client-id", default=None, help="Public client app ID used for interactive Graph auth.")
    parser.add_argument("--browser-command", default="firefox", help="Browser command for interactive auth.")
    parser.add_argument("--scopes", default=",".join(DEFAULT_INTERACTIVE_SCOPES), help="Comma-separated delegated Graph scopes for interactive auth.")
    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.interactive and not args.client_id:
        raise ValueError("--interactive requires --client-id")

    cfg = json.loads(args.config.read_text(encoding="utf-8"))
    run_dir = args.config.parent / "runs" / args.run_name
    run_dir.mkdir(parents=True, exist_ok=True)
    logger = JsonlLogger(run_dir / "workload-seed-az-log.jsonl")
    debug_logger = DebugLogger(run_dir / "workload-seed-az-debug.log")
    manifest_path = run_dir / "workload-seed-az-manifest.json"

    selected_steps = [step.strip().lower() for step in args.steps.split(",") if step.strip()]
    allowed = {"licenses", "windows365", "teams", "intune", "security", "sample", "devices", "exchange"}
    unknown = [step for step in selected_steps if step not in allowed]
    if unknown:
        raise ValueError(f"Unknown step(s): {', '.join(unknown)}")

    logger.event("workload_seed.started", "started", runName=args.run_name, steps=selected_steps, dry_run=args.dry_run)
    interactive_scopes = [scope.strip() for scope in str(args.scopes).split(",") if scope.strip()]
    token_source = "azure_cli"
    if args.interactive:
        token_source = "interactive"
    elif os.environ.get("AZURE_ACCESS_TOKEN"):
        token_source = "AZURE_ACCESS_TOKEN"
    client = GraphClient(
        logger,
        args.dry_run,
        debug_logger=debug_logger,
        auth_mode="interactive" if args.interactive else "azure_cli",
        client_id=args.client_id,
        browser_command=args.browser_command,
        interactive_scopes=interactive_scopes,
    )
    token_claims = graph_token_claims(
        logger,
        debug_logger,
        access_token=client.access_token() if not args.dry_run else None,
        token_source=token_source,
    )
    group_ids = resolve_group_ids(client, logger, top=999)
    team_ids: list[str] = []
    readiness_artifacts: dict[str, str] = {}
    root = Path(__file__).resolve().parent.parent
    policy_artifact_plan = build_policy_artifact_plan(root)
    scenario_plan = build_scenario_plan(cfg)
    policy_artifact_path = run_dir / "enterprise-policy-artifact-plan.json"
    scenario_artifact_path = run_dir / "enterprise-scenario-plan.json"
    policy_artifact_path.write_text(json.dumps(policy_artifact_plan, indent=2, sort_keys=True), encoding="utf-8")
    scenario_artifact_path.write_text(json.dumps(scenario_plan, indent=2, sort_keys=True), encoding="utf-8")
    logger.event(
        "enterprise.policy_artifact_plan.written",
        "success",
        path=str(policy_artifact_path),
        total=policy_artifact_plan["total"],
        counts=policy_artifact_plan["counts"],
    )
    logger.event(
        "enterprise.scenario_plan.written",
        "success",
        path=str(scenario_artifact_path),
        plannedEvents=len(scenario_plan["plannedEvents"]),
    )

    if "licenses" in selected_steps:
        assign_licenses(client, logger, cfg, group_ids, args.dry_run)
        assign_mailbox_seed_licenses(client, logger, cfg, args.dry_run)
        emit_license_readiness_artifact(client, logger, cfg, run_dir, dry_run=args.dry_run)
        readiness_artifacts["licenseReadiness"] = "license-readiness-manifest.json"
    if "windows365" in selected_steps:
        windows365_summary = seed_windows365(client, logger, cfg, run_dir, token_claims, dry_run=args.dry_run)
        readiness_artifacts["windows365Readiness"] = "windows365-readiness-manifest.json"
        if windows365_summary.get("provisioningArtifact"):
            readiness_artifacts["windows365Provisioning"] = str(windows365_summary["provisioningArtifact"])
        if windows365_summary.get("blockerArtifact"):
            readiness_artifacts["windows365Blockers"] = Path(str(windows365_summary["blockerArtifact"])).name
    else:
        windows365_summary = {
            "enabled": False,
            "managedDeviceTarget": resolve_managed_device_target(cfg),
            "pilotUserAlias": build_windows365_plan(cfg).get("pilotUserAlias"),
            "selectedSku": None,
            "licenseAssigned": False,
            "artifact": None,
            "provisioningArtifact": None,
            "blockerArtifact": None,
            "status": "not-run",
            "blockers": [],
            "pilotUserPrincipalName": None,
            "pilotGroupName": build_windows365_plan(cfg).get("pilotGroupName"),
            "pilotGroupId": None,
            "policyDisplayName": build_windows365_plan(cfg).get("policyDisplayName"),
            "policyId": None,
            "policyAssigned": False,
            "cloudPcId": None,
            "cloudPcStatus": None,
            "managedDeviceId": None,
        }
    if "teams" in selected_steps:
        team_ids = seed_teams(client, logger, cfg, group_ids, args.dry_run)
    if "intune" in selected_steps:
        seed_intune(client, logger, args.dry_run)
    if "security" in selected_steps:
        security_summary = seed_security(
            client,
            logger,
            cfg,
            group_ids,
            args.dry_run,
            disable_security_defaults_flag=args.disable_security_defaults,
        )
    else:
        security_summary = {
            "seeded": 0,
            "skipped": 0,
            "securityDefaultsInitialState": None,
            "securityDefaultsFinalState": None,
            "securityDefaultsAction": "not-run",
        }
    planned_devices = []
    mdm_artifact_path = None
    if "devices" in selected_steps:
        seed_devices(client, logger, cfg, dry_run=args.dry_run)
        planned_devices = build_device_inventory(cfg)
        if planned_devices:
            mdm_artifact_path = emit_mdm_artifact(run_dir=run_dir, logger=logger, cfg=cfg, devices=planned_devices, dry_run=args.dry_run)
    if "exchange" in selected_steps:
        exchange_policies = seed_exchange_baseline(
            logger=logger,
            debug_logger=debug_logger,
            cfg=cfg,
            run_dir=run_dir,
            dry_run=args.dry_run,
        )
    else:
        exchange_policies = []
    if "sample" in selected_steps:
        seed_sample_data(client, logger, cfg, group_ids, team_ids, max_days=args.days, dry_run=args.dry_run)

    manifest = {
        "runName": args.run_name,
        "tenantId": cfg["tenant"]["tenantId"],
        "tenantDomain": cfg["tenant"]["tenantDomain"],
        "dryRun": args.dry_run,
        "steps": selected_steps,
        "artifacts": {
            "jsonlLog": "workload-seed-az-log.jsonl",
            "debugLog": "workload-seed-az-debug.log",
            "policyArtifactPlan": "enterprise-policy-artifact-plan.json",
            "scenarioPlan": "enterprise-scenario-plan.json",
            **readiness_artifacts,
        },
        "status": "completed",
        "startedAt": utc_now(),
        "completedAt": utc_now(),
        "teamIds": team_ids,
        "tenantName": cfg["tenant"]["tenantName"],
        "security": {
            "plansEnabled": "security" in selected_steps,
            "artifactPoliciesPlanned": policy_artifact_plan["counts"].get("entra", 0),
            **security_summary,
        },
        "exchange": {
            "plansEnabled": "exchange" in selected_steps,
            "policiesPlanned": len(exchange_policies),
            "artifactPoliciesPlanned": policy_artifact_plan["counts"].get("exchange", 0),
        },
        "intune": {
            "plansEnabled": "intune" in selected_steps,
            "artifactPoliciesPlanned": policy_artifact_plan["counts"].get("intune", 0),
        },
        "scenarioEngine": {
            "plansEnabled": "sample" in selected_steps,
            "plannedEvents": len(scenario_plan["plannedEvents"]),
            "days": scenario_plan["days"],
        },
        "devices": {
            "planEnabled": "devices" in selected_steps,
            "planned": planned_devices,
            "mdmArtifact": mdm_artifact_path,
        },
        "windows365": windows365_summary,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    logger.event("workload_seed.completed", "success", runName=args.run_name)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
