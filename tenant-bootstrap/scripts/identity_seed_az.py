#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import secrets
import string
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

import requests

GRAPH_ROOT = "https://graph.microsoft.com/v1.0"


@dataclass(frozen=True)
class GroupDef:
    display_name: str
    kind: str
    category: str


@dataclass(frozen=True)
class UserDef:
    alias: str
    display_name: str
    department: str
    job_title: str
    is_guest: bool = False
    guest_email: str | None = None


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


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


class GraphClient:
    def __init__(self, logger: JsonlLogger, dry_run: bool) -> None:
        self.logger = logger
        self.dry_run = dry_run
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
            self.logger.event("auth.token.source", "success", source="AZURE_ACCESS_TOKEN", hint="env")
            return env_token
        proc = subprocess.run(
            [
                "az",
                "account",
                "get-access-token",
                "--resource",
                "https://graph.microsoft.com",
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
        self.logger.event("auth.token.source", "success", source="azure_cli", command="az account get-access-token")
        return token

    def request(self, method: str, path: str, *, payload: dict | None = None) -> dict:
        if self.dry_run:
            self.logger.event("graph.would_request", "success", method=method, path=path)
            if method.upper() != "GET":
                return {}
            return {"value": []}
        if path.startswith("http://") or path.startswith("https://"):
            url = path
        else:
            url = f"{GRAPH_ROOT}{path}"

        start = time.monotonic()
        response = self.session.request(method, url, json=payload, timeout=60)
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
        if not response.ok:
            raise RuntimeError(f"{method} {path} failed: {response.status_code} {body}")
        return body

    def iter_pages(self, path: str):
        next_url = path
        while next_url:
            body = self.request("GET", next_url)
            yield from body.get("value", [])
            next_url = body.get("@odata.nextLink")


def group_token(value: str) -> str:
    token = "".join(ch for ch in value.upper() if ch.isalnum())
    return token or "GEN"


def mail_nickname(display_name: str) -> str:
    value = "".join(ch for ch in display_name.lower() if ch.isalnum())
    return (value or f"group{secrets.token_hex(4)}")[:56]


def sample_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "P@ssw0rd-" + "".join(secrets.choice(alphabet) for _ in range(14))


def build_users(cfg: dict) -> list[UserDef]:
    users = [
        UserDef(cfg["actors"]["dailyUser"], "Daily Operations", "IT", "Cloud Operator"),
        UserDef(cfg["actors"]["namedAdmin"], "Named Admin", "IT", "Security Lead"),
    ]
    users.extend(
        UserDef(alias, f"Break Glass {alias}", "Exec", "Emergency Account")
        for alias in cfg["actors"]["breakGlassUsers"]
    )
    roles = cfg.get("enterpriseScale", {}).get(
        "jobTitles",
        [
            "Director",
            "Manager",
            "Senior Analyst",
            "Specialist",
            "Security Lead",
            "Cloud Operator",
            "Engineer",
            "Compliance Analyst",
            "Support Specialist",
            "Account Executive",
            "Data Analyst",
            "SRE",
        ],
    )
    staff_index = 0
    for department in cfg["departments"]:
        for index in range(1, int(cfg["departmentDistribution"].get(department, 0)) + 1):
            role = roles[staff_index % len(roles)]
            users.append(
                UserDef(
                    f"{department.lower()}.{index:02d}.staff",
                    f"{department} {role} {index}",
                    department,
                    role,
                )
            )
            staff_index += 1
    guest_cfg = cfg.get("guestSeed", {})
    guest_addresses = guest_cfg.get("addresses", [])
    guest_domains = guest_cfg.get("domains", ["partner.example"])
    for index in range(1, int(cfg["counts"]["targetGuests"]) + 1):
        alias = f"guest.{index}.partner"
        guest_email = guest_addresses[index - 1] if index - 1 < len(guest_addresses) else f"{alias}@{guest_domains[(index - 1) % len(guest_domains)]}"
        users.append(UserDef(alias, f"Partner Guest {index}", "External", "Contractor", True, guest_email))
    return users


def build_guest_invitation_payload(cfg: dict, user: UserDef) -> dict:
    guest_email = user.guest_email
    if not guest_email:
        guest_domains = cfg.get("guestSeed", {}).get("domains", ["partner.example"])
        guest_email = f"{user.alias}@{guest_domains[0]}"
    return {
        "invitedUserEmailAddress": guest_email,
        "invitedUserDisplayName": user.display_name,
        "inviteRedirectUrl": cfg.get("guestSeed", {}).get("inviteRedirectUrl", "https://myapplications.microsoft.com"),
        "sendInvitationMessage": False,
    }


def add_group(groups: list[GroupDef], seen: set[str], display_name: str, kind: str, category: str) -> None:
    if display_name not in seen:
        groups.append(GroupDef(display_name, kind, category))
        seen.add(display_name)


def build_groups(cfg: dict) -> list[GroupDef]:
    groups: list[GroupDef] = []
    seen: set[str] = set()
    for key, kind in {
        "allUsers": "security",
        "admins": "security",
        "breakGlass": "security",
        "copilotPilot": "security",
        "reporting": "security",
        "entraP2": "security",
        "itM365": "m365",
        "salesM365": "m365",
        "financeM365": "m365",
    }.items():
        add_group(groups, seen, cfg["groupNames"][key], kind, "core")

    if not cfg.get("enterpriseScale", {}).get("enabled", False):
        return groups

    profile = cfg["enterpriseScale"]["profile"]
    for department in cfg["departments"]:
        token = group_token(department)
        for index in range(1, profile["departmentSecurityGroupsPerDepartment"] + 1):
            add_group(groups, seen, f"SG-{token}-APP-{index:02d}", "security", "department-security")
        for index in range(1, profile["departmentM365GroupsPerDepartment"] + 1):
            add_group(groups, seen, f"MG-{token}-COLLAB-{index:02d}", "m365", "department-collab")
        for index in range(1, profile["departmentServiceGroupsPerDepartment"] + 1):
            add_group(groups, seen, f"SG-{token}-SVC-{index:02d}", "security", "department-service")

    for family in cfg["enterpriseScale"]["functionFamilies"]:
        token = group_token(family)
        for index in range(1, profile["functionGroupsPerFunction"] + 1):
            kind = "security" if index % 2 == 0 else "m365"
            prefix = "SG" if kind == "security" else "MG"
            add_group(groups, seen, f"{prefix}-FUNC-{token}-WORK-{index:02d}", kind, "function")

    for index in range(1, profile["resourceOwnerGroups"] + 1):
        kind = "security" if index % 2 == 0 else "m365"
        prefix = "SG" if kind == "security" else "MG"
        add_group(groups, seen, f"{prefix}-OWNER-RSRC-{index:02d}", kind, "resource-owner")

    for index in range(1, profile["policyAndProgramGroups"] + 1):
        if index % 2 == 0:
            add_group(groups, seen, f"SG-PROG-POLICY-{index:02d}", "security", "policy-program")
        else:
            add_group(groups, seen, f"MG-PROG-GOV-{index:02d}", "m365", "policy-program")

    for index in range(1, profile["overshareSignalGroups"] + 1):
        if index % 2 == 0:
            add_group(groups, seen, f"MG-RISK-MISSHARE-{index:02d}", "m365", "overshare")
        else:
            add_group(groups, seen, f"SG-RISK-OVERSHARE-{index:02d}", "security", "overshare")

    geos = cfg["enterpriseScale"]["geoCodes"]
    for zero_index in range(profile["geoRegionGroups"]):
        region = geos[zero_index % len(geos)]
        index = zero_index + 1
        if zero_index % 3 == 0:
            add_group(groups, seen, f"SG-GEO-{region}-OPS-{index:02d}", "security", "geo-region")
        elif zero_index % 3 == 1:
            add_group(groups, seen, f"MG-GEO-{region}-INT-{index:02d}", "m365", "geo-region")
        else:
            add_group(groups, seen, f"SG-GEO-{region}-POLICY-{index:02d}", "security", "geo-region")
    return groups


def build_dynamic_groups(cfg: dict) -> list[dict]:
    if not cfg.get("enterpriseScale", {}).get("enabled", False):
        return []
    seen: set[str] = set()

    def add_dynamic(display_name: str, membership_rule: str) -> None:
        if display_name in seen:
            return
        seen.add(display_name)
        groups.append({"displayName": display_name, "membershipRule": membership_rule})

    groups = [
        {"displayName": "DG-GUEST-ACCOUNTS", "membershipRule": 'user.userType -eq "Guest"'},
        {
            "displayName": "DG-HIGH-RISK-IT-ADMIN",
            "membershipRule": '(user.department -eq "IT") -or (user.jobTitle -eq "Security Lead")',
        },
        {"displayName": "DG-PERMIT-ALL-DEVICES", "membershipRule": 'user.jobTitle -eq "Cloud Operator"'},
        {
            "displayName": "DG-EXTERNAL-PARTNER-OVERPRIV",
            "membershipRule": '(user.userType -eq "Guest") -and (user.jobTitle -eq "Contractor")',
        },
    ]
    for department in cfg["departments"]:
        groups.append(
            {
                "displayName": f"DG-DEPT-{group_token(department)}-USERS",
                "membershipRule": f'user.department -eq "{department}"',
            }
        )
    title_rules = cfg.get("enterpriseScale", {}).get(
        "dynamicTitleRules",
        ["Manager", "Director", "Lead", "Analyst", "Specialist", "Architect", "Engineer", "Coordinator", "Advisor"],
    )
    for title in title_rules:
        add_dynamic(f"DG-TITLE-{group_token(title)}", f'user.jobTitle -eq "{title}"')
    for definition in cfg.get("enterpriseScale", {}).get("dynamicGroupRules", []):
        display_name = definition.get("displayName")
        membership_rule = definition.get("membershipRule")
        if display_name and membership_rule:
            add_dynamic(display_name, membership_rule)
    deduped: list[dict] = []
    seen.clear()
    for group in groups:
        display_name = group["displayName"]
        if display_name in seen:
            continue
        seen.add(display_name)
        deduped.append(group)
    return deduped


def get_group_id_map(client: GraphClient) -> dict[str, str]:
    group_ids: dict[str, str] = {}
    for group in client.iter_pages("/groups?$select=id,displayName&$top=999"):
        group_ids[group["displayName"]] = group["id"]
    return group_ids


def add_group_member(
    client: GraphClient,
    group_id: str,
    group_display: str,
    user_id: str,
    user_upn: str,
) -> None:
    if not group_id or not user_id:
        client.logger.event("group.member.skipped", "warn", group=group_display, upn=user_upn, reason="missing_id")
        return
    try:
        client.request(
            "POST",
            f"/groups/{group_id}/members/$ref",
            payload={"@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{user_id}"},
        )
        client.logger.event("group.member.added", "success", group=group_display, upn=user_upn)
    except RuntimeError as err:
        msg = str(err).lower()
        if "one or more added object references already exist" in msg or "already exists" in msg or "conflict" in msg:
            client.logger.event("group.member.exists", "success", group=group_display, upn=user_upn)
            return
        raise


def add_group_owner(
    client: GraphClient,
    group_id: str,
    group_display: str,
    user_id: str,
    user_upn: str,
) -> None:
    if not group_id or not user_id:
        client.logger.event("group.owner.skipped", "warn", group=group_display, upn=user_upn, reason="missing_id")
        return
    try:
        client.request(
            "POST",
            f"/groups/{group_id}/owners/$ref",
            payload={"@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{user_id}"},
        )
        client.logger.event("group.owner.added", "success", group=group_display, upn=user_upn)
    except RuntimeError as err:
        msg = str(err).lower()
        if "one or more added object references already exist" in msg or "already exists" in msg or "conflict" in msg:
            client.logger.event("group.owner.exists", "success", group=group_display, upn=user_upn)
            return
        raise


def first_value(client: GraphClient, path: str) -> dict | None:
    body = client.request("GET", path)
    values = body.get("value", [])
    return values[0] if values else None


def find_existing_guest(client: GraphClient, guest_email: str) -> dict | None:
    encoded_email = guest_email.replace("'", "''")
    queries = [
        "/users?$filter=" + quote("mail eq '" + encoded_email + "'"),
        "/users?$filter=" + quote("otherMails/any(c:c eq '" + encoded_email + "')"),
    ]
    for query in queries:
        try:
            existing = first_value(client, query)
        except RuntimeError:
            existing = None
        if existing:
            return existing
    return None


def ensure_user(client: GraphClient, cfg: dict, user: UserDef) -> dict | None:
    upn = f"{user.alias}@{cfg['tenant']['tenantDomain']}"
    existing = None if user.is_guest else first_value(client, f"/users?$filter={quote(f'userPrincipalName eq {upn!r}')}")
    if existing:
        client.logger.event("user.exists", "success", upn=upn)
        return existing
    if user.is_guest:
        if not user.guest_email:
            client.logger.event("guest.invitation.failed", "warn", alias=user.alias, reason="missing-guest-email")
            return None
        existing_guest = find_existing_guest(client, user.guest_email)
        if existing_guest:
            client.logger.event("guest.exists", "success", alias=user.alias, email=user.guest_email)
            return existing_guest
        payload = build_guest_invitation_payload(cfg, user)
        if client.dry_run:
            client.logger.event("guest.invitation.would_create", "success", alias=user.alias, email=user.guest_email, redirectUrl=payload["inviteRedirectUrl"])
            return {"id": f"dry-run-{user.alias}", "userPrincipalName": upn, "mail": user.guest_email}
        try:
            invited = client.request("POST", "/invitations", payload=payload)
        except RuntimeError as exc:
            client.logger.event("guest.invitation.failed", "warn", alias=user.alias, email=user.guest_email, reason=str(exc)[:360])
            return None
        invited_user = invited.get("invitedUser") if isinstance(invited, dict) else None
        if invited_user and invited_user.get("id"):
            client.logger.event("guest.invitation.created", "success", alias=user.alias, email=user.guest_email)
            return invited_user
        if invited.get("invitedUser", {}).get("id"):
            guest_id = invited["invitedUser"]["id"]
            record = client.request("GET", f"/users/{guest_id}")
            client.logger.event("guest.invitation.created", "success", alias=user.alias, email=user.guest_email)
            return record
        client.logger.event("guest.invitation.created", "success", alias=user.alias, email=user.guest_email, note="invitation-returned-no-user-record")
        return None
    payload = {
        "accountEnabled": True,
        "displayName": user.display_name,
        "givenName": user.display_name.split()[0],
        "surname": user.display_name.split()[-1],
        "userPrincipalName": upn,
        "mailNickname": user.alias.replace(".", ""),
        "usageLocation": cfg["tenant"]["usageLocation"],
        "department": user.department,
        "jobTitle": user.job_title,
        "passwordProfile": {
            "forceChangePasswordNextSignIn": True,
            "password": sample_password(),
        },
    }
    created = client.request("POST", "/users", payload=payload)
    client.logger.event("user.created", "success", upn=upn)
    return created


def ensure_group(client: GraphClient, group: GroupDef) -> dict | None:
    existing = first_value(client, f"/groups?$filter={quote(f'displayName eq {group.display_name!r}')}")
    if existing:
        client.logger.event("group.exists", "success", group=group.display_name)
        return existing
    payload = {
        "displayName": group.display_name,
        "mailEnabled": group.kind == "m365",
        "mailNickname": mail_nickname(group.display_name),
        "securityEnabled": group.kind == "security",
    }
    if group.kind == "m365":
        payload["groupTypes"] = ["Unified"]
    created = client.request("POST", "/groups", payload=payload)
    client.logger.event("group.created", "success", group=group.display_name, kind=group.kind)
    return created


def ensure_dynamic_group(client: GraphClient, definition: dict) -> dict | None:
    display_name = definition["displayName"]
    existing = first_value(client, f"/groups?$filter={quote(f'displayName eq {display_name!r}')}")
    if existing:
        client.logger.event("dynamic_group.exists", "success", group=display_name)
        return existing
    payload = {
        "displayName": display_name,
        "mailEnabled": False,
        "mailNickname": mail_nickname(display_name),
        "securityEnabled": True,
        "groupTypes": ["DynamicMembership"],
        "membershipRule": definition["membershipRule"],
        "membershipRuleProcessingState": "On",
    }
    try:
        created = client.request("POST", "/groups", payload=payload)
        client.logger.event("dynamic_group.created", "success", group=display_name)
        return created
    except RuntimeError as exc:
        client.logger.event("dynamic_group.create.failed", "warn", group=display_name, reason=str(exc)[:360])
        return None


def seed_group_memberships(
    client: GraphClient,
    cfg: dict,
    users_by_alias: dict[str, dict],
    resolved_users: list[UserDef],
) -> dict[str, int]:
    counts: dict[str, int] = {}
    group_ids = get_group_id_map(client)
    internal_users = [record for record in resolved_users if not record.is_guest]
    total_members = 0
    total_owners = 0

    def add(member_plan: str, alias: str) -> None:
        nonlocal total_members
        if alias not in users_by_alias:
            return
        user_record = users_by_alias[alias]
        group_id = group_ids.get(member_plan)
        upn = f"{alias}@{cfg['tenant']['tenantDomain']}"
        add_group_member(client, group_id or "", member_plan, user_record["id"], upn)
        counts[member_plan] = counts.get(member_plan, 0) + 1
        total_members += 1

    def add_owner(group_plan: str, alias: str) -> None:
        nonlocal total_owners
        if alias not in users_by_alias:
            return
        user_record = users_by_alias[alias]
        group_id = group_ids.get(group_plan)
        upn = f"{alias}@{cfg['tenant']['tenantDomain']}"
        add_group_owner(client, group_id or "", group_plan, user_record["id"], upn)
        total_owners += 1

    # Core security groups
    all_users_group = cfg["groupNames"]["allUsers"]
    for user in internal_users:
        add(all_users_group, user.alias)

    admins_group = cfg["groupNames"]["admins"]
    add(admins_group, cfg["actors"]["namedAdmin"])

    break_glass_group = cfg["groupNames"]["breakGlass"]
    for alias in cfg["actors"]["breakGlassUsers"]:
        add(break_glass_group, alias)

    entra_p2_group = cfg["groupNames"]["entraP2"]
    add(entra_p2_group, cfg["actors"]["namedAdmin"])

    for alias in cfg["actors"]["reportingUsers"]:
        add(cfg["groupNames"]["reporting"], alias)
    for alias in cfg["actors"]["copilotPilotUsers"]:
        add(cfg["groupNames"]["copilotPilot"], alias)

    # Department-local membership pattern
    for department in cfg["departments"]:
        dept_users = [u for u in internal_users if u.department == department]
        if not dept_users:
            continue
        token = group_token(department)
        primary_security = f"SG-{token}-APP-01"
        service_group = f"SG-{token}-SVC-01"
        collab_group = f"MG-{token}-COLLAB-01"
        for index, user in enumerate(dept_users):
            add(primary_security, user.alias)
            if index % 2 == 0:
                add(service_group, user.alias)
            if index < 2:
                add(collab_group, user.alias)

    # Functional cross-pollination
    function_families = cfg["enterpriseScale"]["functionFamilies"]
    for index, user in enumerate(internal_users):
        function_token = group_token(function_families[index % len(function_families)])
        add(f"MG-FUNC-{function_token}-WORK-01", user.alias)
        if index % 2 == 0:
            add(f"SG-FUNC-{function_token}-WORK-02", user.alias)

    # Overshare/risk seed
    if internal_users:
        overshare_seed = internal_users[0]
        for target in ["SG-RISK-OVERSHARE-01", "MG-RISK-MISSHARE-02", "SG-OWNER-RSRC-02", "MG-PROG-GOV-01", "SG-GEO-NA-OPS-01"]:
            add(target, overshare_seed.alias)

    team_owner_aliases = cfg.get("actors", {}).get("teamOwnerUsers", [cfg["actors"]["namedAdmin"], cfg["actors"]["dailyUser"]])
    for team_group in cfg.get("teamGroups", []):
        for alias in team_owner_aliases:
            add_owner(team_group, alias)

    counts["totalMembers"] = total_members
    counts["totalOwners"] = total_owners
    return counts


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Seed tenant identity/groups through Azure CLI Graph token.")
    parser.add_argument("--config", type=Path, default=Path("tenant-bootstrap/config.example.json"))
    parser.add_argument("--run-name", default=f"az-identity-{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--days",
        type=int,
        default=None,
        help="Compatibility placeholder for workflow parity; not used for identity seeding.",
    )
    args = parser.parse_args(argv)

    cfg = json.loads(args.config.read_text(encoding="utf-8"))
    run_dir = args.config.parent / "runs" / args.run_name
    logger = JsonlLogger(run_dir / "identity-seed-az-log.jsonl")
    manifest_path = run_dir / "identity-seed-az-manifest.json"
    users = build_users(cfg)
    groups = build_groups(cfg)
    dynamic_groups = build_dynamic_groups(cfg)
    manifest = {
        "runName": args.run_name,
        "tenantId": cfg["tenant"]["tenantId"],
        "tenantDomain": cfg["tenant"]["tenantDomain"],
        "dryRun": args.dry_run,
        "plannedUsers": len(users),
        "plannedStaticGroups": len(groups),
        "plannedDynamicGroups": len(dynamic_groups),
        "startedAt": utc_now(),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    logger.event("identity_seed.started", "started", **manifest)

    client = GraphClient(logger, args.dry_run)
    resolved_users = []
    users_by_alias: dict[str, dict] = {}
    for user in users:
        record = ensure_user(client, cfg, user)
        resolved_users.append(user)
        if record and record.get("id"):
            users_by_alias[user.alias] = record
    for group in groups:
        ensure_group(client, group)
    for dynamic_group in dynamic_groups:
        ensure_dynamic_group(client, dynamic_group)

    membership_summary: dict[str, int] | None = None
    if not args.dry_run and users_by_alias:
        membership_summary = seed_group_memberships(client, cfg, users_by_alias, resolved_users)

    manifest["completedAt"] = utc_now()
    manifest["status"] = "completed"
    manifest["resolvedUsers"] = len(users_by_alias)
    manifest["resolvedInternalUsers"] = len([user.alias for user in resolved_users if not user.is_guest and user.alias in users_by_alias])
    manifest["resolvedGuestUsers"] = len([user.alias for user in resolved_users if user.is_guest and user.alias in users_by_alias])
    if membership_summary is not None:
        manifest["membershipAssignments"] = membership_summary
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    logger.event("identity_seed.completed", "success", manifest=manifest)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
