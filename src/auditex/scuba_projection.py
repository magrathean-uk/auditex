"""Read-only, fail-closed bundle projection into ScubaGear ProviderExport shapes.

Provenance and privacy metadata stay on ``Projection.report``, outside evidence.
No collection, network calls, defaults for unread settings or sidecar writes.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from typing import Any

from azure_tenant_audit.chunk_reader import _open_chunk
from azure_tenant_audit.external_sharing import ENUM_NAME_KEYS, annotate_enum_names
from azure_tenant_audit.model_assessment import safe_projection_enum_value
from azure_tenant_audit.model_evidence import NOT_COLLECTED
from azure_tenant_audit.resources import open_text_resource
from azure_tenant_audit.tenant_identity import canonical_tenant_uuid

PROJECTION_VERSION = "2026-10-29"
DEFAULT_MAX_ITEMS = 40
DEFAULT_MAX_CHARS = 12_000


class Projection(dict):
    """Evidence mapping with a separate local projection report."""

    report: dict[str, Any]


class Unavailable(ValueError):
    def __init__(self, reason: str = "incomplete_shape", unsupported: list[str] | None = None,
                 *, field: str = "$", kind: str = "unseen_shape", value: Any = None):
        self.unsupported = unsupported or []
        self.reason = reason
        self.detail = {"field": field, "kind": kind}
        if kind == "unseen_enum_value" and safe_projection_enum_value(field, value):
            self.detail["value"] = value
        super().__init__(reason)


def _require(condition: bool, field: str = "$", kind: str = "unseen_shape") -> None:
    if not condition:
        raise Unavailable(field=field, kind=kind)


def _known_fields(row: Any, allowed: set[str], path: str = "") -> None:
    _require(isinstance(row, dict), path or "$", "invalid_type")
    # Never echo arbitrary keys: even a single identifier can be a person's name.
    _require(set(row) <= allowed, path + ".unrecognisedField" if path else "unrecognisedField",
             "unexpected_field")


def _enum(value: Any, domain: set[str], field: str) -> None:
    _require(isinstance(value, str), field, "invalid_type")
    if value not in domain:
        raise Unavailable(field=field, kind="unseen_enum_value", value=value)


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _strings(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(v, str) for v in value)


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _boolean(value: Any) -> bool:
    return type(value) is bool


def _nullable_text(value: Any) -> bool:
    return value is None or isinstance(value, str)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise Unavailable()


def _fields(row: Any, spec: dict[str, Any], *, graph: bool = False, path: str = "") -> dict[str, Any]:
    _require(isinstance(row, dict), path or "$", "invalid_type")
    for key in ("error", "error_class", "read_state", "collection_status"):
        valid = not row.get(key) if key in {"error", "error_class"} else row.get(key, "collected") == "collected"
        _require(valid, path + "." + key if path else key)
    result = {}
    for key, check in spec.items():
        source = key[0].lower() + key[1:] if graph else key
        field = path + "." + key if path else key
        _require(source in row, field, "missing_field")
        value = row[source]
        if isinstance(check, dict):
            result[key] = _fields(value, check, graph=graph, path=field)
        else:
            _require(check(value), field, "invalid_type")
            result[key] = deepcopy(value)
    return result


def _healthy(value: Any, *, recursive: bool = True) -> None:
    """Reject failure markers anywhere in an endpoint or normalised record."""
    if isinstance(value, dict):
        for key in ("error", "error_class", "resolver_error", "collection_truncated",
                    "bounded_sample", "@odata.nextLink", "truncation_reason", "incomplete", "partial"):
            _require(not value.get(key), "odata.nextLink" if key == "@odata.nextLink" else key)
        if "complete" in value:
            _require(value["complete"] is True, "complete")
        if "status" in value:
            _enum(value["status"], {"ok", "success", "collected", "complete"}, "status")
        for key in ("read_state", "collection_status"):
            _require(key not in value or value[key] == "collected", key)
        if recursive:
            for child in value.values():
                _healthy(child)
    elif recursive and isinstance(value, list):
        for child in value:
            _healthy(child)


def _shape(value: Any) -> Any:
    if isinstance(value, dict) and value and all(k.startswith("User") and k[4:].isdigit() for k in value):
        return {"users": sorted({_json(_shape(v)) for v in value.values()})}
    if isinstance(value, dict):
        return {"object": {k: _shape(v) for k, v in value.items()}}
    if isinstance(value, list):
        return {"array": sorted({_json(_shape(v)) for v in value})}
    return type(value).__name__


def _seen_shape(section: str, value: Any) -> None:
    # Empty collections need both explicit completeness and an observed empty shape.
    _require(sha256(_json(_shape(value)).encode()).hexdigest() in PACK_SHAPE_DIGESTS.get(section, []))
    def validate(item: Any, path: str = "", field: str = "") -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                domain = PACK_ENUM_DOMAINS.get(section, {}).get(path + "." + key)
                child_field = field + "." + key if field else key
                if domain is not None:
                    for v in (child if isinstance(child, list) else [child]):
                        if _json(v) not in domain:
                            raise Unavailable(field=child_field, kind="unseen_enum_value", value=v)
                validate(child, path + "." + key, child_field)
        elif isinstance(item, list):
            for child in item:
                validate(child, path + "[]", field)
    validate(value)


class Bundle:
    def __init__(self, root: Path, max_items: int, max_chars: int):
        self.root = root
        self.max_items, self.max_chars = max_items, max_chars
        self.sources: list[str] = []
        self.complete = False
        self.manifest: dict[str, Any] = {}

    def read(self, relative: str) -> Any:
        # Reuse no-symlink, regular-file, beneath-root bundle opens.
        try:
            with _open_chunk(self.root, relative) as handle:
                value = json.load(handle, object_pairs_hook=_unique_pairs, parse_constant=_invalid_constant)
        except FileNotFoundError:
            raise Unavailable("missing_artifact") from None
        except (OSError, ValueError, UnicodeError):
            raise Unavailable() from None
        if relative not in self.sources:
            self.sources.append(relative)
        return value

    def normalised(self, name: str) -> list[dict[str, Any]]:
        data = self.read(f"normalized/{name}.json")
        _require(isinstance(data, dict), kind="invalid_type")
        _require("records" in data, "records", "missing_field")
        _require(isinstance(data["records"], list), "records", "invalid_type")
        _require(not data.get("error"), "error")
        _require(data.get("collection_status", "collected") == "collected", "collection_status")
        _require(all(isinstance(row, dict) for row in data["records"]), "records", "invalid_type")
        _healthy(data)
        self.complete = data.get("complete") is True or data.get("collection_status") == "collected" or data.get("status") in {"ok", "collected", "complete"}
        _require(bool(data["records"]) or self.complete, "records")
        return data["records"]

    def coverage(self, collector: str, operation: str | None = None) -> bool:
        complete = False
        gaps = self.manifest.get("coverage_gaps", [])
        _require(isinstance(gaps, (list, dict)), "coverage_gaps", "invalid_type")
        # Manifest collector gaps may be broad or carry per-list truncations.
        def relevant(value: Any) -> bool:
            if isinstance(value, dict):
                if value.get("collector") == collector or value.get("source") == f"{collector}.{operation}":
                    return True
                return any(relevant(v) for v in value.values())
            if isinstance(value, list):
                return any(relevant(v) for v in value)
            return value == collector or value == f"{collector}.{operation}"
        _require(not relevant(gaps), "coverage_gaps")
        for path in ("coverage.json", "normalized/coverage_ledger.json", "normalized/collection_gaps.json"):
            try:
                data = self.read(path)
            except Unavailable as exc:
                if exc.reason == "missing_artifact":
                    continue
                raise
            _healthy(data, recursive=False)
            rows = data.get("records") if isinstance(data, dict) else data
            _require(isinstance(rows, list))
            for row in rows:
                _require(isinstance(row, dict))
                source = row.get("source", "")
                matches_source = isinstance(source, str) and (source == f"{collector}.{operation}" if operation
                                                               else source.startswith(collector + "."))
                if row.get("collector") != collector and not matches_source:
                    continue
                name = row.get("list", row.get("name"))
                if operation is not None and name and name != operation:
                    continue
                _healthy(row)
                if path.endswith("collection_gaps.json"):
                    raise Unavailable()
                _require("actual_status" not in row or row["actual_status"] == "ok", "actual_status")
                status = row.get("coverage_status", row.get("status"))
                _require(status in {"ok", "complete_exact_scope", "complete_effective_role",
                                   "complete_equivalent_scope", "complete_offline_sample"},
                         "coverage_status" if "coverage_status" in row else "status")
                complete = True
        return complete

    def collector_health(self, collector: str) -> None:
        self.coverage(collector)
        try:
            payload = self.read(f"raw/{collector}.json")
        except Unavailable as exc:
            if exc.reason != "missing_artifact":
                raise
            try:
                sample = self.read("raw/sample_input.json")
            except Unavailable as sample_exc:
                if sample_exc.reason != "missing_artifact":
                    raise
                return
            _require(isinstance(sample, dict))
            payload = sample.get(collector, {})
        _require(isinstance(payload, dict))
        _healthy(payload)

    def operation(self, collector: str, operation: str) -> list[dict[str, Any]]:
        try:
            payload = self.read(f"raw/{collector}.json")
        except Unavailable as exc:
            if exc.reason != "missing_artifact":
                raise
            try:
                sample = self.read("raw/sample_input.json")
            except Unavailable as sample_exc:
                if sample_exc.reason != "missing_artifact":
                    raise
                section = self.read(f"raw/{collector}/{operation}/summary.json")
            else:
                _require(isinstance(sample, dict))
                payload = sample.get(collector, {})
                _require(isinstance(payload, dict))
                _healthy(payload, recursive=False)
                if operation not in payload:
                    raise Unavailable("missing_artifact")
                section = payload[operation]
        else:
            _require(isinstance(payload, dict))
            _healthy(payload, recursive=False)
            if operation not in payload:
                raise Unavailable("missing_artifact")
            section = payload[operation]
        complete = self.coverage(collector, operation)
        _require(isinstance(section, dict))
        self.complete = complete or section.get("complete") is True or section.get("collection_status") == "collected" or section.get("status") in {"ok", "collected", "success"}
        _healthy(section)
        _require(not any(section.get(k) for k in (
            "error", "error_class", "collection_truncated", "bounded_sample", "@odata.nextLink",
            "truncation_reason", "incomplete", "partial")))
        _require(section.get("status", "ok") in {"ok", "success", "collected"})
        if not any(k in section for k in ("value", "chunk_files")):
            _require(bool(section) and not any(k in section for k in ("item_count", "sample_truncated")))
            return [section]
        chunks = section.get("chunk_files", [])
        _require(isinstance(chunks, list) and all(isinstance(p, str) for p in chunks), "chunk_files", "invalid_type")
        _require(all(p.startswith((f"raw/{collector}/{operation}/", f"chunks/{collector}/")) for p in chunks), "chunk_files")
        _require(all(not any(part == ".secrets" or part.startswith(".env") for part in Path(p).parts) for p in chunks), "chunk_files")
        _require(len(set(chunks)) == len(chunks), "chunk_files")
        if len(chunks) > self.max_items:
            raise Unavailable("oversize")
        _require("chunk_count" not in section or type(section["chunk_count"]) is int
                 and section["chunk_count"] == len(chunks), "chunk_count")
        rows = []
        size = 0
        def append(row: Any) -> None:
            nonlocal size
            _require(isinstance(row, dict), "value", "invalid_type")
            _healthy(row)
            size += len(_json(row))
            if len(rows) >= self.max_items or size > self.max_chars:
                raise Unavailable("oversize")
            rows.append(row)
        if chunks:
            seen = set()
            consumed_bytes = 0
            byte_budget = self.max_chars * 4
            for path in chunks:
                try:
                    with _open_chunk(self.root, path) as handle:
                        stat = os.fstat(handle.fileno())
                        _require((stat.st_dev, stat.st_ino) not in seen)
                        seen.add((stat.st_dev, stat.st_ino))
                        if path not in self.sources:
                            self.sources.append(path)
                        while True:
                            # Never materialise an unbounded line or the full collection.
                            line = handle.readline(byte_budget - consumed_bytes + 1)
                            if not line:
                                break
                            consumed_bytes += len(line)
                            if consumed_bytes > byte_budget:
                                raise Unavailable("oversize")
                            if not line.strip():
                                continue
                            if len(rows) >= self.max_items:
                                raise Unavailable("oversize")
                            append(json.loads(line, object_pairs_hook=_unique_pairs, parse_constant=_invalid_constant))
                except Unavailable:
                    raise
                except (OSError, ValueError, UnicodeError):
                    raise Unavailable(field="chunk_files") from None
        else:
            _require("value" in section, "value", "missing_field")
            _require(isinstance(section["value"], list), "value", "invalid_type")
            _require(not section.get("sample_truncated"), "sample_truncated")
            for row in section["value"]:
                append(row)
        if "item_count" in section:
            _require(type(section["item_count"]) is int, "item_count", "invalid_type")
            _require(section["item_count"] == len(rows), "item_count")
        _require(not section.get("sample_truncated") or "item_count" in section, "item_count", "missing_field")
        if not rows:
            _require(complete or section.get("complete") is True
                     or section.get("collection_status") == "collected" or section.get("status") in {"ok", "collected", "success"})

        return rows

    def alternatives(self, operations: list[tuple[str, str]]) -> list[dict[str, Any]]:
        found = []
        for collector, operation in operations:
            try:
                rows = self.operation(collector, operation)
            except Unavailable as exc:
                if exc.reason != "missing_artifact":
                    raise
            else:
                found.append(rows)
        if not found:
            raise Unavailable("missing_artifact")
        _require(all(rows == found[0] for rows in found))
        return found[0]


def _spo(bundle: Bundle) -> Any:
    normal = bundle.normalised("sharepoint_tenant_settings")
    rows = bundle.alternatives([("sharepoint_access", "sharePointSettings"), ("onedrive_posture", "sharePointSettings")])
    _require(len(rows) == 1)
    raw, result = rows[0], {}
    canonical = {"SharingCapability": "sharing_capability", "ODBSharingCapability": "onedrive_sharing_capability"}
    for key, names in ENUM_NAME_KEYS.items():
        value = raw.get(key, raw.get(key[0].lower() + key[1:]))
        if key == "ODBSharingCapability":
            value = raw.get(key, raw.get("oneDriveSharingCapability", raw.get("odbSharingCapability")))
        if key in canonical:
            values = [r[canonical[key]] for r in normal if r.get("read_state") == "collected" and canonical[key] in r]
            _require(bool(values), key, "missing_field")
            _require(all(v == values[0] for v in values), key)
            reverse = {str(v).split(" (")[0]: n for n, v in names.items()}
            _require(isinstance(values[0], str), key, "invalid_type")
            if values[0] not in reverse:
                raise Unavailable(field=key, kind="unseen_enum_value", value=values[0])
            number = reverse[values[0]]
            if value is not None:
                _require(type(value) in (int, str), key, "invalid_type")
                _require((type(value) is int and value == number) or value == values[0], key)
        else:
            _require(key in raw or key[0].lower() + key[1:] in raw, key, "missing_field")
            _require(type(value) in (int, str), key, "invalid_type")
            reverse = {v: n for n, v in names.items()}
            number = value if type(value) is int else reverse.get(value) if isinstance(value, str) else None
            if type(number) is not int or number not in names:
                raise Unavailable(field=key, kind="unseen_enum_value", value=value)
        result[key] = number
    for key, allowed in {"DefaultLinkPermission": {1, 2}, "DefaultSharingLinkType": {1, 2},
                         "SharingDomainRestrictionMode": {0, 1}}.items():
        if result[key] not in allowed:
            raise Unavailable(field=key, kind="unseen_enum_value", value=result[key])
    for key in ("RequireAnonymousLinksExpireInDays", "EmailAttestationRequired", "EmailAttestationReAuthDays"):
        value = raw.get(key, raw.get(key[0].lower() + key[1:]))
        _require(key in raw or key[0].lower() + key[1:] in raw, key, "missing_field")
        _require(type(value) is (bool if key == "EmailAttestationRequired" else int), key, "invalid_type")
        if key != "EmailAttestationRequired":
            _require(value >= (-1 if key == "RequireAnonymousLinksExpireInDays" else 0), key)
        result[key] = value
    return [result]


def _ca(bundle: Bundle) -> Any:
    # Whitelists describe representable fields, not a union used to authorise shapes.
    spec = {
        "DisplayName": _text, "State": _text,
        "Conditions": {
            "Applications": {k: _strings for k in ("IncludeApplications", "ExcludeApplications", "IncludeUserActions")},
            "AuthenticationFlows": {"TransferMethods": _nullable_text},
            "ClientAppTypes": _strings,
            "ClientApplications": {"IncludeAgentIdServicePrincipals": _strings},
            "SignInRiskLevels": _strings, "UserRiskLevels": _strings, "AgentIdRiskLevels": _nullable_text,
            "Users": {**{k: _strings for k in ("IncludeUsers", "ExcludeUsers", "IncludeRoles", "ExcludeRoles", "ExcludeGroups")},
                      "ExcludeGuestsOrExternalUsers": {"GuestOrExternalUserTypes": _text,
                                                       "ExternalTenants": {"MembershipKind": _text}}}},
        "GrantControls": {"BuiltInControls": _strings, "Operator": _nullable_text,
                          "AuthenticationStrength": {"AllowedCombinations": lambda v: v is None or _strings(v)}}}
    unsupported = set()
    # Only schema field names enter diagnostics; unknown keys can themselves contain PII.
    restriction_names = {"locations", "devices", "platforms", "sessionControls", "includeGroups",
                         "includeGuestsOrExternalUsers", "authenticationContextClassReferences",
                         "servicePrincipalRiskLevels", "customAuthenticationFactors", "termsOfUse",
                         "applicationFilter", "includeServicePrincipals", "excludeServicePrincipals",
                         "servicePrincipalFilter", "id", "displayName"}
    def convert(row: Any, fields: dict, path: str = "", field_path: str = "") -> dict:
        _require(isinstance(row, dict), field_path or "$", "invalid_type")
        output = {}
        for key, value in row.items():
            if path == "" and key in {"id", "createdDateTime", "modifiedDateTime", "@odata.context", "@odata.type"}:
                continue
            target = key[0].upper() + key[1:] if key else ""
            if target not in fields:
                unsupported.add(path + (key if key in restriction_names else "unrecognisedField"))
                continue
            field = field_path + "." + target if field_path else target
            _require(key == target[0].lower() + target[1:] and target not in output,
                     field, "unexpected_field")
            check = fields[target]
            if isinstance(check, dict):
                output[target] = None if value is None else convert(value, check, path + key + ".", field)
            else:
                _require(check(value), field, "invalid_type")
                if target == "State":
                    _enum(value, {"enabled", "disabled", "enabledForReportingButNotEnforced"}, "State")
                output[target] = deepcopy(value)
        return output
    result = [convert(row, spec) for row in bundle.operation("conditional_access", "conditionalAccessPolicies")]
    if unsupported:
        raise Unavailable(unsupported=sorted(unsupported), field=sorted(unsupported)[0], kind="unexpected_field")
    return result


def _authorization(bundle: Bundle) -> Any:
    rows = bundle.alternatives([("external_identity", "authorizationPolicy"), ("consent_policy", "authorizationPolicy")])
    _require(len(rows) == 1)
    row = rows[0]
    result = _fields(row, {"Id": _text, "AllowInvitesFrom": _text, "GuestUserRoleId": _text}, graph=True)
    _require("defaultUserRolePermissions" in row, "DefaultUserRolePermissions", "missing_field")
    permissions = row.get("defaultUserRolePermissions")
    _known_fields(permissions, {
        "allowedToCreateApps", "permissionGrantPoliciesAssigned", "permissionGrantPolicyIdsAssignedToDefaultUserRole",
        "allowedToCreateSecurityGroups", "allowedToReadOtherUsers"}, "DefaultUserRolePermissions")
    # These two Graph settings are not read by the dependent SCuBA policies and
    # have no corresponding field in the frozen ProviderExport shape.
    result["DefaultUserRolePermissions"] = _fields(
        permissions, {"AllowedToCreateApps": _boolean}, graph=True, path="DefaultUserRolePermissions")
    if "permissionGrantPoliciesAssigned" in permissions and "permissionGrantPolicyIdsAssignedToDefaultUserRole" in permissions:
        _require(permissions["permissionGrantPoliciesAssigned"] == permissions["permissionGrantPolicyIdsAssignedToDefaultUserRole"],
                 "PermissionGrantPolicyIdsAssignedToDefaultUserRole")
    _require(any(k in permissions for k in ("permissionGrantPoliciesAssigned", "permissionGrantPolicyIdsAssignedToDefaultUserRole")),
             "PermissionGrantPolicyIdsAssignedToDefaultUserRole", "missing_field")
    assigned = permissions.get("permissionGrantPoliciesAssigned", permissions.get("permissionGrantPolicyIdsAssignedToDefaultUserRole"))
    _require(_strings(assigned), "PermissionGrantPolicyIdsAssignedToDefaultUserRole", "invalid_type")
    result["PermissionGrantPolicyIdsAssignedToDefaultUserRole"] = assigned
    return [result]


def _plans(bundle: Bundle) -> Any:
    result = {}
    for row in bundle.operation("licensing", "subscribedSkus"):
        _require("servicePlans" in row, "servicePlans", "missing_field")
        _require(isinstance(row.get("servicePlans"), list), "servicePlans", "invalid_type")
        for plan in row["servicePlans"]:
            _known_fields(plan, {"servicePlanId", "servicePlanName", "provisioningStatus", "appliesTo"}, "servicePlans")
            if "provisioningStatus" in plan:
                _enum(plan["provisioningStatus"], {
                    "Success", "Disabled", "Error", "PendingInput", "PendingActivation", "PendingProvisioning"},
                    "servicePlans.provisioningStatus")
            if "appliesTo" in plan:
                _enum(plan["appliesTo"], {"User", "Company"}, "servicePlans.appliesTo")
            item = _fields(plan, {"ServicePlanId": _text, "ServicePlanName": _text}, graph=True)
            key = item["ServicePlanId"]
            _require(key not in result or result[key] == item, "ServicePlanId")
            result[key] = item
    return list(result.values())


def _users(bundle: Bundle) -> Any:
    for collector in ("identity", "identity_governance"):
        bundle.collector_health(collector)
    admins = bundle.normalised("effective_admin_set")
    summaries = [r for r in admins if r.get("kind") == "effective_admin_set_summary"]
    _require(len(summaries) == 1)
    _require("state" in summaries[0], "state", "missing_field")
    _require(summaries[0]["state"] == "complete", "state")
    _require("unresolved_principal_count" in summaries[0], "unresolved_principal_count", "missing_field")
    _require(summaries[0]["unresolved_principal_count"] == 0, "unresolved_principal_count")
    admin_rows = [r for r in admins if r.get("is_user") is True]
    _require("admin_count" in summaries[0], "admin_count", "missing_field")
    _require(type(summaries[0]["admin_count"]) is int, "admin_count", "invalid_type")
    _require(summaries[0]["admin_count"] == len(admin_rows), "admin_count")
    _require(len({r.get("principal_id") for r in admin_rows}) == len(admin_rows), "principal_id")
    users = bundle.operation("identity", "users")
    index = {r.get("id"): r for r in users}
    _require(len(index) == len(users) and all(_text(k) for k in index), "id")
    result = {}
    for admin in sorted(admin_rows, key=lambda r: r.get("principal_id", "")):
        _require("state" in admin, "state", "missing_field")
        _require(admin["state"] == "complete", "state")
        _require("principal_id" in admin, "principal_id", "missing_field")
        _require(admin["principal_id"] in index, "principal_id")
        row = index[admin["principal_id"]]
        item = _fields(row, {"DisplayName": _text, "OnPremisesImmutableId": _nullable_text}, graph=True)
        _require("role_names" in admin, "role_names", "missing_field")
        _require(_strings(admin["role_names"]), "role_names", "invalid_type")
        _require(bool(admin["role_names"]), "role_names")
        item["roles"] = list(admin["role_names"])
        result[f"User{len(result) + 1}"] = item
    return result


def _role_date(value: Any) -> bool:
    return value is None or isinstance(value, str) and re.fullmatch(r"/Date\(-?[0-9]+\)/", value) is not None


def _roles(bundle: Bundle) -> Any:
    # No current collector obtains PIM policy Rules. Only an existing complete
    # ProviderExport-shaped artefact can supply them, never policy defaults.
    bundle.collector_health("identity_governance")
    result = []
    for row in bundle.normalised("privileged_roles"):
        _known_fields(row, {"DisplayName", "RoleTemplateId", "Assignments", "Rules"})
        item = _fields(row, {"DisplayName": _text, "RoleTemplateId": _text})
        for key in ("Assignments", "Rules"):
            _require(key in row, key, "missing_field")
            _require(isinstance(row[key], list), key, "invalid_type")
        _require(bool(row["Rules"]), "Rules")
        item["Assignments"] = []
        assignment_fields = {"PrincipalId": _text, "StartDateTime": _role_date, "EndDateTime": _role_date}
        for assignment in row["Assignments"]:
            _known_fields(assignment, set(assignment_fields), "Assignments")
            _require("PrincipalId" in assignment, "Assignments.PrincipalId", "missing_field")
            item["Assignments"].append(_fields(assignment, {k: assignment_fields[k] for k in assignment}, path="Assignments"))
        item["Rules"] = []
        rule_fields = {"Id": _text, "RuleSource": _text, "RuleSourceType": _text,
                       "IsExpirationRequired": _boolean, "MaximumDuration": _text,
                       "NotificationRecipients": _strings, "NotificationType": _nullable_text,
                       "Setting": {"IsApprovalRequired": _boolean}}
        for rule in row["Rules"]:
            _known_fields(rule, set(rule_fields), "Rules")
            for key in ("Id", "RuleSource", "RuleSourceType"):
                _require(key in rule, "Rules." + key, "missing_field")
            _require(_text(rule["Id"]), "Rules.Id", "invalid_type")
            if rule["Id"].startswith("Expiration_"):
                for key in ("IsExpirationRequired", "MaximumDuration"):
                    _require(key in rule, "Rules." + key, "missing_field")
            elif rule["Id"].startswith("Notification_"):
                _require("NotificationRecipients" in rule, "Rules.NotificationRecipients", "missing_field")
            elif rule["Id"].startswith("Approval_"):
                _require("Setting" in rule, "Rules.Setting", "missing_field")
            else:
                raise Unavailable(field="Rules.Id", kind="unseen_enum_value")
            if "Setting" in rule:
                _known_fields(rule["Setting"], {"IsApprovalRequired"}, "Rules.Setting")
                _require("IsApprovalRequired" in rule["Setting"], "Rules.Setting.IsApprovalRequired", "missing_field")
            item["Rules"].append(_fields(rule, {k: rule_fields[k] for k in rule}, path="Rules"))
        result.append(item)
    return result


def _tenant(bundle: Bundle, manifest: dict[str, Any]) -> Any:
    identity = manifest.get("tenant_identity", {})
    _require(isinstance(identity, dict), "tenant_identity", "invalid_type")
    _require(identity.get("status") != "conflict", "tenant_identity.status")
    _require(not identity.get("conflicts"), "tenant_identity.conflicts")
    observed = set()
    for collector in ("identity", "domains_hybrid"):
        try:
            rows = bundle.operation(collector, "organization")
        except Unavailable as exc:
            if exc.reason != "missing_artifact":
                raise
            continue
        for row in rows:
            tenant = canonical_tenant_uuid(row.get("id"))
            _require("id" in row, "id", "missing_field")
            _require(tenant is not None, "id", "invalid_type")
            observed.add(tenant)
    recorded = canonical_tenant_uuid(manifest.get("tenant_id"))
    if recorded:
        observed.add(recorded)
    _require(len(observed) == 1, "tenant_id")
    return next(iter(observed))




PS_SECTIONS = {
    "accepted_domains": ("exchange_policy", "acceptedDomains", {"Name": _text, "DomainName": _text}),
    "dkim_config": ("exchange_policy", "dkimSigningConfig", {"Domain": _text, "Enabled": _boolean}),
    "transport_config": ("exchange_policy", "transportConfig", {"Name": _text, "SmtpClientAuthenticationDisabled": _boolean}),
    "org_config": ("exchange_policy", "organizationAuditConfig", {"Identity": _text, "Name": _text, "AuditDisabled": _boolean}),
    "meeting_policies": ("teams_policy", "meetingPolicies", {
        "Identity": _text, "AllowAnonymousUsersToStartMeeting": _boolean, "AllowCloudRecording": _boolean,
        "AllowExternalParticipantGiveRequestControl": _boolean, "AllowPSTNUsersToBypassLobby": _boolean,
        "AutoAdmittedUsers": _text}),
}


def _powershell(bundle: Bundle, section: str) -> Any:
    collector, operation, fields = PS_SECTIONS[section]
    try:
        rows = bundle.operation(collector, operation)
    except Unavailable as exc:
        if exc.reason == "missing_artifact":
            try:
                normal = bundle.normalised("teams_policy_objects" if collector == "teams_policy" else "exchange_policy_objects")
            except Unavailable as normal_exc:
                if normal_exc.reason != "missing_artifact":
                    raise
                raise Unavailable("powershell_only") from None
            bundle.coverage(collector, operation)
            rows = [r for r in normal if r.get("source_name") == operation]
            if not rows:
                raise Unavailable("powershell_only") from None
        else:
            raise
    result = []
    for row in rows:
        item = _fields(row, fields)
        _known_fields(row, set(fields) | {"source_name", "key", "kind", "@odata.context", "@odata.type"})
        result.append(item)
    return result


def _dns(bundle: Bundle, section: str) -> Any:
    # Parsed dns_posture summaries cannot reconstruct all TXT answers.
    result = []
    for row in bundle.operation("dns_posture", section):
        allowed = {"domain": _text, "doamin": _text, "rdata": _strings, "compliant": _boolean, "message": _text}
        _known_fields(row, set(allowed))
        item = _fields(row, {k: allowed[k] for k in row})
        result.append(item)
    return result


def _oversize(value: Any, max_items: int, max_chars: int) -> bool:
    def exceeds(item: Any) -> bool:
        if isinstance(item, list):
            return len(item) > max_items or any(exceeds(v) for v in item)
        if isinstance(item, dict):
            return any(exceeds(v) for v in item.values())
        return False
    return (exceeds(value) or isinstance(value, dict) and len(value) > max_items or len(_json(value)) > max_chars)


_EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")


def _redact(projection: Projection, salt: str, enabled: bool) -> dict[str, Any]:
    counts = {"user_display_names": 0, "email_addresses": 0, "immutable_ids": 0}
    def pseudonym(text: str) -> str:
        return sha256((salt + "\0" + text).encode()).hexdigest()[:16]
    def emails(value: Any) -> Any:
        if isinstance(value, str):
            def mask(match: re.Match) -> str:
                counts["email_addresses"] += 1
                return "***@" + match[1]
            return _EMAIL.sub(mask, value)
        if isinstance(value, list):
            return [emails(v) for v in value]
        if isinstance(value, dict):
            return {k: emails(v) for k, v in value.items()}
        return value
    if enabled:
        users = projection.get("privileged_users", {})
        if users != NOT_COLLECTED:
            for item in users.values():
                item["DisplayName"] = "User " + pseudonym(item["DisplayName"])
                counts["user_display_names"] += 1
                if item["OnPremisesImmutableId"] is not None:
                    item["OnPremisesImmutableId"] = "Id " + pseudonym(item["OnPremisesImmutableId"])
                    counts["immutable_ids"] += 1
        for key in projection:
            projection[key] = emails(projection[key])
    return {"enabled": enabled, "strategy": "run-salted-sha256-v1", **counts}


def project_run(run_dir: str | Path, *, redact: bool = True,
                max_items: int = DEFAULT_MAX_ITEMS, max_chars: int = DEFAULT_MAX_CHARS) -> Projection:
    """Read a bundle without writes; manifest digest supplies a stable per-run salt.

    The salt stays in memory and is never persisted. Size bounds apply
    before and after redaction, including nested lists and user dictionaries.
    """
    if type(max_items) is not int or max_items < 1 or type(max_chars) is not int or max_chars < 1:
        raise ValueError("Projection bounds must be positive integers")
    bundle = Bundle(Path(run_dir).resolve(), max_items, max_chars)
    manifest_invalid = False
    try:
        manifest = bundle.read("run-manifest.json")
        _require(isinstance(manifest, dict))
    except Unavailable as exc:
        manifest_invalid = exc.reason != "missing_artifact"
        manifest = {}
    bundle.manifest = manifest
    sections = sorted({s for p in json.loads(open_text_resource("configs/scuba-policy-sections.json"))["policies"].values()
                       for s in p["sections"]})
    result = Projection()
    report = {}
    adapters = {"SPO_tenant": _spo, "conditional_access_policies": _ca, "authorization_policies": _authorization,
                "service_plans": _plans, "privileged_users": _users, "privileged_roles": _roles}
    for section in sections:
        bundle.sources = []
        bundle.complete = False
        try:
            _require(not manifest_invalid)
            if manifest.get("platform", "m365") != "m365":
                raise Unavailable("not_applicable_to_platform")
            if section in {"scuba_config", "sharing_policy"}:
                raise Unavailable()
            if section == "tenant_id":
                bundle.sources.append("run-manifest.json")
                value = _tenant(bundle, manifest)
            elif section in adapters:
                value = adapters[section](bundle)
            elif section in PS_SECTIONS:
                value = _powershell(bundle, section)
            elif section in {"dmarc_records", "spf_records", "dkim_records"}:
                value = _dns(bundle, section)
            else:
                raise Unavailable("missing_artifact")
            # A complete, explicitly empty source collection is known empty.
            # Missing/failed sources have already raised and cannot reach here.
            _require(value is not None)
            if value in ([], {}):
                _require(bundle.complete)
            _seen_shape(section, value)
            if _oversize(value, max_items, max_chars):
                raise Unavailable("oversize")
        except (Unavailable, ValueError, TypeError, KeyError, OverflowError) as exc:
            result[section] = dict(NOT_COLLECTED)
            report[section] = {"status": "not_collected", "reason": getattr(exc, "reason", "incomplete_shape"),
                               "source": list(bundle.sources)}
            if report[section]["reason"] == "incomplete_shape":
                report[section]["detail"] = getattr(exc, "detail", {"field": "$", "kind": "unseen_shape"})
            if getattr(exc, "unsupported", None):
                report[section]["unsupported_conditions"] = exc.unsupported
        else:
            result[section] = value
            report[section] = {"status": "projected", "reason": None, "source": list(bundle.sources)}
    redaction = _redact(result, sha256(_json(manifest).encode()).hexdigest(), redact)
    for section, value in result.items():
        if value != NOT_COLLECTED and _oversize(annotate_enum_names(section, value), max_items, max_chars):
            result[section] = dict(NOT_COLLECTED)
            report[section].update(status="not_collected", reason="oversize")
    result.report = {"schema_version": PROJECTION_VERSION, "sections": report, "redaction": redaction,
                     "bounds": {"max_items": max_items, "max_chars": max_chars}}
    return result


# Generated from complete v7 train/test objects; the fixture pins each digest
# to a source file hash, row number and evidence ID. Never union sparse paths.
PACK_SHAPE_DIGESTS = {'SPO_tenant': ['0431dbf090672152543d23384d46908c3a61402eb96cdab7f7196e19a7f6e51d',
                '047f3c221dd7b73d95d5c060aaabe80c3b96e2eed3d2996e8bfecc45162c33ba',
                '09ed20ece76dbe2ca2118fea9e6bf24de0657416f42678a2b2c8063cc8fe74b2',
                '0de38489604e0d66c66a7cb7a5426cde8fc13ab0032e301fa44f2d4ef28933b1',
                '52c3e827ed5d2682e0de163c3f130e3941df2ebed94cc580275c1a3b35672df1',
                '6e59c69226f3b212dff62231168516863c08fd75dc09ef75c9ccf9c51adb9442',
                '718222e62485098065163aa1c5f5e7412b145c3b763d11b7924d53746d986f06',
                '74e3bd6f36eb9cd41aa1971d538ab134048cfb30d9d7647580c8f2fed52f57c0',
                '8290e17678d11cbaaeb40d06ba64673ad4e379615ece9259c1cd4ded0291939e',
                '86b2382049fd823a68677dffadb5913cc0ff50c072d1e2baedc6481c2ff0081f',
                'a496895d274b1867e2b98f00219b75f1eb6aed717de5a1f50c71415a815490ae',
                'b2822f7835e9ec73fe8dc3bf731d8d0dbb4a3b246814634499399aa4aa72b47f',
                'bba8990d77dd449ec537975d16c26f6f3adcca460aafdf68c2e288e438f8e6c4',
                'c14f2e997d976371b33d12e711febed9be05218a051a5df03f820a35ae346482',
                'e300fb59bf985850acccb24e13f34450215ed0e8f631ebdc736638422e9d6fcc',
                'eac1565e041bd480423f09a9fb0ec4341fb2cbb2c9e92c0b6ed1e5182df28d3f'],
 'accepted_domains': ['49f477bb14284f2dc7b68efe2242d2ec4be1f5e6ca864bd52d62f1a2e50bc48b'],
 'authorization_policies': ['015eb674092ed1463dbc8e1f86bd0851bd204f870d00fc6cdcdb842a625ecd92',
                            '068b8e0b4cdaa3faa9e1c0605e947e46396789b61dbfd0cb228ea25f03bbbf58'],
 'conditional_access_policies': ['01b39c4c1e3a5f0e28288d6175580170ece3185c5bc0db7f192d8dbc631b666d',
                                 '025acfac75b10f2d2e5e30634558299a88109bf5029fc98f6d1857a9987657a4',
                                 '04cbc6ea5ca205d53fc2d389b8dcafbd399fdca15e86ca571f23eb47b9d7ecf6',
                                 '05faa53dd245a34bf4c452262531bcb23bd42362770e0efee5f9fce2daf30bce',
                                 '062555d577cd1ca56724cbe87441e727d4d51fd0a4ec793fec5e2d3897225fb6',
                                 '0640a5a30bfaf724bff4ee035ea03fd07225c2fb2d328ca28abf708708991163',
                                 '075cd3128a9f80c9f3ffd9ad947a2d50a1461b9466ff4138d9c46a12ebdd84b7',
                                 '07fd467dc40b7a81cf6e1c1107ad30771e4b2ef8271380dc93f24e3948382b1b',
                                 '0875c0f8a4fe0e5671e6eb674896a39ebead43142ad46b507b5454b8a2ede236',
                                 '0a14117f25dce0e0383301158dfb4cfb6638b887a7deac2accea47f8eff1511b',
                                 '0ab34c147d904448cdd03b51f49785a32815bdc0c59744f656b8d9d7fed6c260',
                                 '0ae8026975ac872c52e0880e503016a5dbe71d3dfceca1496fc281959bba0c49',
                                 '0b296ea2625fa0e9dbd80c86ff31a991ef826934d26376276d3fcf311e59facc',
                                 '0da721ca0767e5d960e12aa855cd606e3139955c7aa92fb2c8fb034c43c136ac',
                                 '0e79f8d612d46a0e8326477f01b9f36f9d4f37822011293350611397a90e0001',
                                 '10c1a3ec8d50a04bed4221c18b7828516f46f064be0155dfae1b3a2be938e82e',
                                 '10c288239dbe668971b7db4e55050949426ec5c0cdbf76286dab4700d588ac34',
                                 '1201718f354646036c49ea02ba6595c722c0c9099d7976de326791b96f235d8f',
                                 '12fbd5edf70052ec0cc64072bfb5d11c294ac76551464308926dc35a4c293eef',
                                 '132e9dd02c56c7cefe5abdecfbbce0a3ec1520284884865949e14d2e45a3b67d',
                                 '14c124497154649df31bde9ad45fc6ba925dbab308d55ad9250effb40b1f21ed',
                                 '153504a8d1ea0e3e17ddc407654886c36ecaff57b41f8d5a820dbbaade9b4939',
                                 '156a343969452e1729b8f41f15f8ddefebeb1ee25ee414f589ec9bd2a2f72222',
                                 '15d2ab9e1a10f36d7cec0523d98efc4e6314c09e1eabcc663dfe309405404111',
                                 '164ad45a085b64e70b68314670f5048713a90ae3ad7568a98760c056b336a701',
                                 '17b1b9f8a5eb252e164d56fdaf3eea85767adffdc8614f87bc237a8bab96a2dd',
                                 '17e850d79d7b2e81f1b6d5f7f3e63a6d3d2a84cb61a2d57bac3743c48b907e17',
                                 '18e1183793c1539e255b89acf036c8bd5fe3a5d092103738634e5211c7d29a8e',
                                 '1adcbc0cfbaf7fc742051e05cc4b1de33d8236eb50d45919893909b6ef7b77d0',
                                 '1c70bb4897f422c6e4266d686f5de83992c760c985dfff3b771facdfa039220f',
                                 '1da2653146ff3c21ec25fb9eb58bc10e187ca6e8a07260858706ba36f68a5e68',
                                 '1e6b805e5556afa6afcc067027cde36fe7fea702ea435628cc923c4b5a28a32d',
                                 '22b3a683404dcbc0143210720573904768e0ec5f3c010c2f444ca9fce85f4e7d',
                                 '23af47e609ad53896ffcd0b6ab1b78b3ed80cf96af11ca540687dc363696a920',
                                 '2960a620f6c44a158becc7574d04b591c847257587de96fd84e6f0571f89ef16',
                                 '2ab5d02bd108d5103abaf56662cb89f4a9ba6597d414793ec8aed56dc0954192',
                                 '2b57c0b4f6a9e6da8e0b8e6ed67cb0b182e5630c13831f5ce17572c557fdaa60',
                                 '2c80e62eba201143e972ebd19113a0b12e26f93efb44e4cc71d6924b23461b32',
                                 '2f4ab3b89874a8d54cd6a572d8df2754da0f5eabac2d62156ccd1e2fd535441c',
                                 '2fa9234e33a6a477f6f71a3f227b9f2252e7617e65b9f13a0cb0afc8eef0f8f3',
                                 '2ff3013133bf8de1bd73082a70269542a19a2fb98308ef657552167ea3cdd6d2',
                                 '30af91e42a2bf175492299efa1d1761706c97f6efde4c6638ae0bbb6afda2795',
                                 '330d0c2e4cb7f1a762e63ff94e9ee3f14718b3918920417849d57a6d886145ff',
                                 '33b681f1e91220b8ef9226fca18e082b83a5d046daa832877de90ed4c3f5b2df',
                                 '3453e0dad3b51a87d7af1af0ee72daba3ad04eed754f978b36a98436c5c1e9a9',
                                 '34f2cbd0293d7bcf97eeca254e46a735c907c04b0cb531a70121c08b40e9e2c3',
                                 '3a6db640dc9cd9a62874f85b0582f7f99b36155ef9574db64b98fa4436223bfc',
                                 '3ba5eb79b18f7ccd635becd594f132e1f89a13ee4879e1622bcb787a5f0e7453',
                                 '3c81ac1df51ce9602380c58fc2e862fdbde84311758b9b4681b1c3cc2ba28838',
                                 '3d6400e71fa42aaffa24e0278e8c9c15ad90e839ef42e746dc7fa53b64ccda61',
                                 '3e084183dda700a81b400c7d75cf0b890fd980b63df0ac8ee1420bfbb3291076',
                                 '3f7588b5016b754c54457dedd7a7cfa2c144724f7c69450367005cc370e6904d',
                                 '3fbfcabfc4df31142d48bc8532c4b53d7bfa2b5bc9685a4c6fc87789e0000dcc',
                                 '3ff71a63412f2148451770c804d06eef8015557bfbb1644010ec7f7e207b9ffd',
                                 '41097905308c8e125f6d23ff289ee890697af1fc492560d3d7a3bbb750617ed3',
                                 '42e1b5cb6a14984272a932aea8adba69ecaaf3db33e6bdad8b841543288197aa',
                                 '4442bb136b7443e9b206ef631ea9a5d0752448bf88b3376fd66d6fa9aca18675',
                                 '44c564ec0ddcca34a888e0f4f6f685fa8b93d9f9e5a2897aa6f550198f6b7ce9',
                                 '49450e5a2be4e7c3263494b3812defa22f6ea3bf4e7c32c5ded16619fa591493',
                                 '4b79cf7c0d58c9d0795d922e73584511d8fd3701fe59d63cd0f95403cd2909d9',
                                 '4c4b885f0c0030eea16fac8c3ca79ca9299503a16d7380b63ec951d4110ecdca',
                                 '4efcb3b6aed645ab9b3218e3000bf475bc09e87901457b69cca49c80a2649094',
                                 '4fa32d0126213d2c8b51ba3467c3dda601f35f7b7737948240a598a46917c5b5',
                                 '5007da18b0c2e415baf1a02eedb7519afe6ab999b448c68a60bfce7ef9599770',
                                 '51544443b6f0a8ffe0f755dd075a82cac2a67d3528ea18ce4015ac73dfaa6be3',
                                 '52348fc1fcf836e30b1a8167b48d5d5cb2ea4aeef34896887938b101a35826dd',
                                 '5331cf461a98df528d2c431a7b208bbe799ee765b309be93377ba2f9de1e515f',
                                 '53ea58bbf2c0405919c41f835395ac5fc645dd1f536b5f87b39abf32f2bd5639',
                                 '55eb900d6d5f84adca0355dae5a1c767c5804dae2c8fc87c69cd96b4e504b6f3',
                                 '5678e3b0971ac1de446f2ad0f46fcda4644173c7f86fb52acde012d9c2cf2766',
                                 '56eab463268240f94a2601605d75b93348e89a3024f9aee230702172eeeb5ac9',
                                 '5725ed7a7193a00c414e33960bfa5570ee3187208e556cc5a1d65e5a8830590d',
                                 '5968fd59c774f360677227fd6c7ab0a78f5bed5cfd309f0f9439871e4e071a80',
                                 '59f66b291371a75a5d42ff07f3d51767ba757db94ab983272a776284cb049fbe',
                                 '5bb429b7b5b250f0709b5512e4bb871321dff2454294ffb13a8c9bcf8eb57be3',
                                 '5c271268057d4d33f569d8facaa4dbd335de5828f9f68d4556f71a970deca03f',
                                 '5d52d525bc5847c269eefeecf7425ad5703df399bad6b92c17378e9954532475',
                                 '5d83188931175a2b93e18cb0a06cdf0c8992414e25d713d149b1d82ab7355964',
                                 '5e543a11a113b989d7ce5f1cb450f63716f4a8bd66fd9dbf1bec31e3b08007fa',
                                 '5e9c0b438eca0dfb552fa4fdff7356202d8729dcfc40597c02b35023480d587c',
                                 '5eb2fc89f10d2886773f7acabc39d45c4fbafc3351d8aabd277afe1f4af3053e',
                                 '5f1653091add8d17e322c058f413fa80813079e266f1a1e389421e17a20bd98b',
                                 '5fcce409bf760ba7c07c7ad8e30710d8d545b78c56790e95a47e9846ba952e4d',
                                 '5fe0895262149a97d2e876d6da5ecfa865084d63a8687446799077a77ad37023',
                                 '60732f0bd0c0bcc9c86585ca37241f25f08177c476a18300a82e6b936c8cd032',
                                 '6092cd804a51081bd7df2c1a1d8e78e2db0868171c17b069e8395aa5bd86d470',
                                 '621495a8d8b455d8a59ec3470647453304caa0681d444972f4a2c05b5e5a34d5',
                                 '63158a3d30409a2c3d3fef705ec0764f0a6486582071ecd3e85be7c671ff7e16',
                                 '6348917b3a1b95542be65d62c94c964fa15301d8bc75cfbf5a03eb53e7bfee1f',
                                 '635ff80766cb66c53ca74d8b51623229f3f28ae4070437008537910f406ede72',
                                 '63997d48e995012e22d5ad7c67e691318e9ccea234e6a9bb57b1ead2b69096d4',
                                 '659ac893678e9c6695006741458cb08ad3bc14669d5b017baa3cfb537d12b852',
                                 '65da2cc7e78c1f365e25b731d392bcc512705518d3ebb341549af239b3eee7da',
                                 '66f1e785eb33839a3ca4d6a9a7cedbbaaf4dc3765ee82f60f5530dce28efdb7a',
                                 '6742f7f3252f3936065a99b6aba207f3e33f5c20c00eb42ada2b1a4003b81226',
                                 '67c572e388285b21990c4db9248c28be8a17d4f6cb1b2cf32428ae1faf39e76c',
                                 '683a3ea553ffa2bc05b0678d780970ecec84ba0b17de8d216a784c62e1b67313',
                                 '68612bc65d8031aa7ff5038a758fdbb9695d4641a8b96058c210f28b7824f10a',
                                 '68c7f742a8d7134168adebc828c15289231b85b9f48bf8f5d5c56e71aa7ce06b',
                                 '6c8c67f8e5ce1a5b035c23f283e928dcb408e10bc9dc6c4e238eed892d9acafd',
                                 '6c9314a3604342fba89ec7d3c479eb6d13b87d7a73df9d0cc5752403720b41c3',
                                 '6e59c69226f3b212dff62231168516863c08fd75dc09ef75c9ccf9c51adb9442',
                                 '71b8e0baa1151f01b697a3294255f67768cab2279692b36f64218ab20e1df84e',
                                 '72927cb8c851d4bdad756dda9e448354d9e0bdf5fcd2113fac561715e238b888',
                                 '73c515fd9ebfe517df241615fdd2e3e10d1e7d485a230c2bf344604cce87cda5',
                                 '73df4b36c9deba1c6eb8117a0f122508f8383ed6d66d9d3bac4a366276b94574',
                                 '7484173e5bb4f15b02b8ae99207f359bee8d09c42754f19de4575959bfbe5d57',
                                 '77f9bb35c8554cabb0853cc1dc095f451a4b0a88ea086b3549e2130500ecb3a2',
                                 '785e72a9405ed089f502a6448406de899d81797e54393c24db9ef5473589f2bb',
                                 '7888041d6958892c68fa7f2db3f4c0c0e60e1ce0c1261dc83b9d2c918c522d40',
                                 '79fdca83608b0d9bcaca4144abe026d59b72825ae3a45d1f21f47c09a5da2966',
                                 '7afe4068112bdcfe9da065897e9a56e539480ac1449ea649262d5c585b53f89b',
                                 '7c0d93b6a6600ad4322392e148532e47356c379017ba4736987dc91ecd531c23',
                                 '7c3b529c0aa28f318635024e76903e7e53b59f8985f2562d81d649f4fc1fbf66',
                                 '7d85809afa741e9a138ece2a371d274ec853091bfe6d5a23bdadfb455304ee52',
                                 '7e6fbf097b7b2f9d5e38a973aeeb2b067cefb840aa132ecef7e06473d89e25b1',
                                 '8039d5ece6cf3b957ded5c9ec59a5ba0fd30ff0346dec068d404ffa9e49c993b',
                                 '82ad5a41cf61559877efcd6575a86a5aa0e0bed7c39930423e308a782c811eca',
                                 '83d5bfd94c8b26e9c6cb7497145200cecfe6b177fc3645690d4ec067421b144c',
                                 '87914a81e28c271057724ce40f63d4192be1126e44bf5f6e9fa1bec4254681da',
                                 '87fab97adda841fdb8614614daeb5dfee452ff5d5601f6816e4bce009a05b132',
                                 '8a0973295ec332adca6cebc6080f6c40619d8fad99676c89dd0680f24debfba4',
                                 '8a25fe8af889d2fdd66e5a3524da72f1a5f353f397a4f6a3b60eb0269f6b413c',
                                 '8b6194125b3726fb81c0a275a2e901a563698a7e65e43f3b83e5cd1abbbc359a',
                                 '8bf9d2f62362fb83b06aa2d25972ed502e805179aba4d71842694c22b4be55cb',
                                 '8fb74fa14bee9d67a0e5a954fd15e3c3fb0bf9b437963a4d7dfb78b424b06f18',
                                 '8fd18e3e196904338501790fe205977bce83f43182e4778c277703532afabfc6',
                                 '92500ef24fc8bc3e83d6b8230ee1ff4854866aeb758b2b7d86c16b6dc1004073',
                                 '92d4871f7b174eea0938a5a1e0e8a2fb3d664f59e28e599cd8795059504b5376',
                                 '935c0f57c9e68552876824fd7df2c6a4b28499883f9f7bbfbb642c4cd26973b0',
                                 '943f633ab9ca431d38e9cf05c98ac007e7da39f92b969950e5854a5c6595f464',
                                 '95955e6c3d4e01c25a6636fd373a88ec10a7a6dc4a23dfdd4c104ef83e734471',
                                 '9600cfa5165847f1f2b6f2917b07520aacdc77687d8e807e6b9eb275677fc32a',
                                 '966048ff2c91470f00ae3fec3d9f3639ccd7d724478704ad8092a4d9e42cf91e',
                                 '96b1d9bf34b44176fc984cc4114ad870c366c7223cf9f28d2f4168f1cc510de2',
                                 '98d9792a445237e19a0c7c96fb719ded0ff428fc232c8424c2b1ab7efd8bd817',
                                 '9aac1f6ac1f04abfc31122811b5a299ee2c798c110641b73f0707c41a89b00d5',
                                 '9bbe325801682fb78677ed07e9e926945e172641cc912b59f8e9e28f1dc9dd77',
                                 '9d1c4b5d89d57bb0a36c42da0308f796ed484bd88adffdb0b4ddbd6fa5977c1e',
                                 '9d2838f7b8bd360488b37d3dc348f12dc462479a7315bb0bdc2edb4a11997340',
                                 '9fde3f3495a74d03c5df3459ed852854f7fd17f6bc1c106068fcf90652101894',
                                 'a07ec0ef0617bf067bc89478819bf654c2131d2a14652b4ae4b680a05eb1ee56',
                                 'a0e3853ce627b9b5ce92dcb25ab418062c9de0cf005146f9f16c16eddf48d266',
                                 'a2306f644085f3b12c70d80ed8c35253c605020cb9439701380250274a38e586',
                                 'a23b2aab0730d4fbbc90a8c53f5329ca282e5cc96ec77c5dfef0c0caaf4bd056',
                                 'a3477ece05aaa0787815e3efb183b13dea7d805261d97236700364e3716ff3e4',
                                 'a38db72971b316f5e31d715057d95a6348fc2ea499210e06fa2a19e17938d708',
                                 'a43aef961fa3cf0e096108a830357b8ddade1272a68b22b059a2432a92f7479d',
                                 'a733b52e477f56669dd8b18ced6c4dd4fa0aa63e764e80b7644a69677280b745',
                                 'a778bf5f9425b5f044e2995779458aa6994608b7c6fe5cc076ddea04d7d49efe',
                                 'a788a3859833a885f10d133b01197c6de151438cd7a61072134dc132d677b04e',
                                 'a78b3628247a9aef9581f193871ca1b27f05e77eb8db2b2624a82bdcf071934a',
                                 'a886dedb34414fd4c27273539066d4cca7eef151f926aecf47663952297ec5d1',
                                 'a91ede2e568ad96b73eef69e28669bc312b3103615759650c2513672e008c080',
                                 'a9f1094ffe6cba7ae790513feec340544234639936a44e127a73565d68710d8a',
                                 'aa158336b6c8a5bebed7a2bb64a629972be9e80c311baa29f1b704efad90a8af',
                                 'aae6564a9f36d1aea93c83e24f19e4377ee15a6b55bcaa2f90eb041a6b574441',
                                 'acee491004e52f01cab1df8f9d872cc08a90995adec61388cd99b5532c56c0a3',
                                 'addfa95d189080d8f61ad242a5b6002896362702406980c1704929334ae8902e',
                                 'ae5c3de1c61c81b02b3e2c7784c008fe4f604843271fd55fb267aaeba69b9ed6',
                                 'aff76b5db3f67d7c83e445d120aa11325044e176173fcfc0daaa7cd1f7e9e560',
                                 'b0be9b6d1ff88f2f3082443a1939e2342ce79187b98450bd26655eff2944ace0',
                                 'b0d96d84962dbee97f3149f9415a5d6a1e66742687ae9927ea9f80e77f229918',
                                 'b1d39a271423056d16f513243f6fbf9adc588abd8976e02d1b75b2490f0f621a',
                                 'b23c36fca54ebaf1bfaac2db53390b28edfe202170fd20c0f770e93d68fd5dbc',
                                 'b31f1223246f032decb412cc92337c1f331744bbeef99c48e4d42d31b94cdfc4',
                                 'b37c884aae3c0992df6b948fd2365b773f3e95f6740917239444c47d7130ac8e',
                                 'b3f9eeafc108c61e580e2921ff666090416819151f7bea0ec5215769e3691324',
                                 'b62b89008a976e97165de226f062294f36e1546dbe21371043b4e48c93866c8b',
                                 'b7e01180bfdef6f793e75f5e6314253689d5a99d908e34bca72ee7627700a5d5',
                                 'b7f911e2f81f52d193dae6ab42ab068b4c4ae2bed100380176887be1a3938863',
                                 'b84f0f5ab50a66ce13ff0d763fbc78441e62cca8b230d2b1b1b4cbfb2ba83e26',
                                 'b8f1d36af16d11a921c14ce1b8f88f9a063fe514a81837edbe0ef279bd25b4e3',
                                 'bda6eb19fb7b76156694ceb611656ece9e99076ef17ff9855da40c62328ed3fe',
                                 'beae340c7bc81049f42fe4f2a8c16cbf69b0217da0e91def553797f335ae8d47',
                                 'beda6a3892bdc36964f72bf2a99613967b548b4a8caf29d379287129d9eb7c34',
                                 'bf1d8bc8c43e47ad2fd56d7a9ffe8d8972fe3f50a5adc66bc36c0b37411a5450',
                                 'c1ce9dce9534559d61cc6d035537506b998105e727ba4333c14c6d2a54a1a182',
                                 'c584f5738820c17480bb499a3da6d2167236f8126837cdb8b0a77f4c5b0a7b5c',
                                 'c5dca94871edd4462202324f7125ddd454c9214ca52a3712cec480d65f5f4932',
                                 'c6b45743d0e647f5445b98ca50891c1165c216771802f13eb92a6934fcd50d09',
                                 'c721d29143720c928bef40476b1790715d65531206256de2d189b1e3fa73ef26',
                                 'c79c0ec5365993cf0bef2499cb47f635072acd5fa1babf96c5f816e517461a22',
                                 'c857bd9566d29a36b7d188bb7c6b5654c49b653033370d15983fde5070b42cfb',
                                 'c8852ae9efeb2d5cb0f561a1347b27057fcd676abc270113734c85636b33314e',
                                 'c94c6cb9d48635188ce8984908cb175658bb8ee919b1cbd0b48f98ebb4abf785',
                                 'ca365f9b990e95da985ab724f6e72f0f38894b7e590250baf726fd453fe02295',
                                 'cbe92a5bec75b89e73e54838b4a23c1f7924f596fd913c3c6007003d23d57f57',
                                 'ccd4d2d08c1684b546bf898a017c73a42a2ed517a8af1ab62663354e4fbb564c',
                                 'cf802e27adf563df38c7771f295a22496c8f451bf7d689b66f27951799ad4f57',
                                 'd09b234e9d60eb7499ddcec298e7b03c8ec1b66da15c0185f9c766bedd63394b',
                                 'd1f647754324125a01602e50e22dfce9320fe5d9a4d9073e9b9c1e24eb04f8a6',
                                 'd27b59565496f7d1d2226793fc22bcab5e77788c02f891581bf9f60f9c128e4d',
                                 'd407494b6952057f50dc6cc827f65cbedeaaddbf1854dd0c55cc69742aa42113',
                                 'd4cdcbc9a50eed5ac00aa2bf0896242b81e28f19e494655c7439ced82eccda44',
                                 'd5806778998f5638b8d4c737f91e677b757ed57cb38c7015849811343c00f10d',
                                 'd74203842739844e0c3107abb1930f52686fa6b7b26d7ad5a2a87d383f8c4d2a',
                                 'd74af292900eec3afd4ba2ca1aa19fdb824b7efb1e6f22251f37372965c2a1e7',
                                 'd7c7af79949603e08a1283b409e49c419b39cad7fc025d0981a2f7e205c82fe6',
                                 'd91db4b33808dcb9a233a124358f16353ab4f4c49695ff51b2a9d0e10a5db46f',
                                 'd9201da948dbfa3c68501eed71dd65de755ae952880a8a17ee0ccf946aec3474',
                                 'd9c40743ef59438f408a609682029975df0fc4e532b1ecb4b813d641b6d79792',
                                 'da5a3f0e651dbba239abe9cc3473362b97d4a5739de9864fb9a3ffbd47c0bf73',
                                 'de0ce38ba92132d1a116f5257537d5c1d78e3898f3f8a48b73f300652e057156',
                                 'de645eae5a9465ed2845f947f9ff8e13579f5ad7d1d00010eead29aa56625817',
                                 'df6cfd1563933d9b1b2a515f1d54fabedc095092d2e63eeb6ddd6a227a7e61ee',
                                 'e03259dc61cf2687dccc38e2b31ef302edaab7ef10808d68962da2cf312dad53',
                                 'e0d2bf336e7d5ef503c96e7951e29d5e3ab4ce2b3e346d8ec31d9b8dbe2be378',
                                 'e1b6796a261a0aabf76a897fa1a91a620384f7c6381604a6aa129c69a268220d',
                                 'e24c73f4dd8a01018d33ea381be46f5a29bc1e9b4327e8ea746529b85093dfe6',
                                 'e2918e61d4bbd8aa325ab1407604c49661d3db4908eb810920c18d53b2e1fb0a',
                                 'e4d775112f99a72802d9c4fc231c314a6e56bcfe9b2c345bbeb86efb54e490bb',
                                 'e4e55547eefaa799c3c81355823ddc9d934cdce07fb0a5bc2940b3f25a187603',
                                 'e5752d337efef0ede8944fe597b1b74f733fdf9bebeb277c31a7195c9a13f92b',
                                 'e58188440807520641f61ef85b3cc615cb013bbf6e7fd9c7a2472395ed3c3bb1',
                                 'e5f21277dcee02a37596f78b455e5ba039d8b6b1ee3f935da54884a810d29e45',
                                 'e6d18849a1f503cbace17d0b2c45670ffedba0608f6aa89785039fb26bf3dea0',
                                 'e6e367c48c0d7c731021282dbe5b18d01eb62dd78fb41fdd9829c4525c1c3ec9',
                                 'e701ad73144831549e51150fd70eeab37893e41376c694f63758f1edb74ea560',
                                 'e823a170dbba4d99067e102bfbcbffce34b339d4e33b03531f58aeb9abf4a313',
                                 'e8a28c59d3c870e2d9f1e8545c7a62e59c14e5db8eecfce99fcbc9cea68b645e',
                                 'ebf27d3d516e92478f5d8830b1ad6b511439a6e3165eb844db5317ebcea47027',
                                 'ef10f5a096aab84c5414a69c70f07efd07a2342c9abd4a7b9c431b9eb71f7698',
                                 'eff1a1d388cab2294f64783fa8a97f2a65daddc62b4e51507dbaf5f95f01e5e9',
                                 'f01e0769c8ae7a7394a6a7e477694e59b6ea733762477070b67da6f7b62d68d8',
                                 'f18c25c36feb686d868be1a62157bb654eda46856d618cb2da06d7ad8c8f2002',
                                 'f259f58ea8c091fae9e42caddebc05a6509a509ab2c9c3755a9c2e6c72c33c20',
                                 'f426a3f54b093708eff8655a0714ba30df8009c2495a53f8a0181d15566fe980',
                                 'f5be178c5c704ca9ec63cb40036fe2fbc771f3d34a7e45fc6176a5d4a6ed7546',
                                 'f7fc26499f5253a9043bfd6b46a76bbf50782fcd4f9d09fecb3fd3fd146eca32',
                                 'f889354bd71743341ffb65a3ddd9da5aeeda776f7fb1eb88b80425dec2f1fd90',
                                 'fc0f4e271acede800bd35ac721204343e0f630c99c746b32552b5463338961fe',
                                 'fd287cba6f5acd529b7ef80296d3410c47c0bddb0369173ba4695def0b7d26ff',
                                 'fdb95fb8e65ee3ea48fa33bed4c11dadfe50659a0fe0d81bcb3a892716ed0c26',
                                 'ff63ffd151a253b21816dd79aa1462eee204c3bf15adef6e5c0ebe93e16cae01'],
 'dkim_config': ['b4715763adf12dac6cd00659871e45e1a7b36d404fd90fe8a3915546ad6b416e'],
 'dkim_records': ['c2f173118e0cdc35bfdca803e8977ad30e69e445982ed1d3aaf7ee12fe4542a2',
                  'e03cc99f636135a39f79f4197b675a291359af0ace70058b9382d508982a6044',
                  'fa625b913b519e515872c690a135dea5b4f810a6c24d98cf400b2c94ce8310aa'],
 'dmarc_records': ['c2f173118e0cdc35bfdca803e8977ad30e69e445982ed1d3aaf7ee12fe4542a2',
                   'e03cc99f636135a39f79f4197b675a291359af0ace70058b9382d508982a6044',
                   'fa625b913b519e515872c690a135dea5b4f810a6c24d98cf400b2c94ce8310aa'],
 'meeting_policies': ['9c7bd6483405412350f21331f8d56f65c475f851dbea154230df9691171058b2'],
 'org_config': ['cf5dc663de9a2855d91ea339aea4f1a37ce0665c683ab873e0ef4bc118db91a1'],
 'privileged_roles': ['004a3256613c0ab5c25f0c4aadf840ac9faa89e8a4b030071a68d43f32b9f417',
                      '1d8230786c6ad12de687035ff2e4a7f33cd75efa09be797999ba7b60f04fee80',
                      '1f34459aac58b5f1653e0b9abddb01d5cb3ab25df10ecf6612d670dc4b5e677e',
                      '2dde676ccd93538cf5a6d8a647295c565ddd3bdbee2a9dd44cea50c830453d25',
                      '30a5f60f1e300c45daf881ef55db01e3ed6346cb4fe67b2cdf8b0459f5500a28',
                      '31bdcad27c60abceb9f7af6c0f3c584bbb078f1c34ae1574581c0f24b5f1c6e0',
                      '35be6e6f1c54fc2c8fe40791cd03f0afce6c43a7eb6283dec1de0d9d9aebc89a',
                      '3a5ba1492424eac8dcbb8b59101e544db754fedb311fdb79990c1543ab8c47cc',
                      '3c57c69e824b86c14b849d148c4aa468c8f01e9d7209447fae18e5aeb98e8593',
                      '3e05d4f8ba462ba59909c004013d6fc1808bea207b8747fbc0ac2bb7d94acdd3',
                      '45351929174fed565f0afd7ea735ce82dfad8297861475cccc5da38fff39bdd8',
                      '495505d4ae1eda653fcadae6442f42f809d4e924e4ea7e114565acdf18bf145b',
                      '514457a887b86d405aa017c7462cf76cbbc55fa2b4ced58a7e79bac097ec42cf',
                      '5b0b15d7a9aa9b0c4a491c99020048b3db71ae5a9ab21ef68f0a3a2011c68862',
                      '6f180b49e613cd9ccd412f015a20b6ffd5023b9ef190cc61b79532f21514702b',
                      '71b2d7dbfffd378d9928a33949652a6b38969fa1b6face042d18c4e3d611d935',
                      '797a9c2a6d24536bf2039a6b94c62fcb1eb19eded0b1da8bf70d9fc21e065e6f',
                      '843fe5439387e681ac11091c627c6f5bf09bf655816e28d4fc36cf02cb469828',
                      '861fdeb5a12348a35884547c90d6996104ddc144cb5449f21b583168736b5d8a',
                      '92e3a6acf44a42e1fb0c9a7f7f197f5ddd7c7ab94dd3054a0bbee73a51e370fe',
                      '95a3468ff7af66d8897cca4b03a07571f966c9d46ac6754a03824f904f2a1e7d',
                      '969de120d186fac63ca9a9d05431ec00692a0d43bd2748809e418afc892e4b81',
                      '97507c7a57130ef057db6348938408e4e2776d39e49b3c325322ab284a65d6dc',
                      'a24913132eac9640311bf8cbc0691e3783c465c2bd181e6db59a7541f6737f58',
                      'a6c44da9968929df9850fff3584e80372961b0300ac86630114ae1961b17a53d',
                      'adfa3e58d530156e3cd67d9ff26595cbd47b020b6fcc303d5ab4f41f448c6662',
                      'af6947851f7bd9170d574e84960c627502ba2cd6a4e27755f4d7ffa59b1dfecc',
                      'b9641bcf1f50206369249627f86a9c1da6dcfddfa0dd68a94719616590f7383a',
                      'bf3cff0fb11155bf3ed8bdd6f4f4cce1b3ac1c2627e464336dd980751a86470c',
                      'c80c7b204139f0230146412246bb544468126fcaf04d24f04ef5752f02fd37c6',
                      'caff3cceba08885fab6c71d773e04e688f583c8bebf8fc58b4bf68834d493cd7',
                      'cdfd50b6807412bbec540159b77e37ac4b4e859f3b80a496383e158849000379',
                      'ce79d4481198ca664d22cacf17d0193922d54dc78ae4af455cccb94ea6355ef9',
                      'da3b406710e6e52b39a4af193cd2c59e4e7f87fc554d478aec7ea1209fbe6fa4',
                      'eaccb61ee4439a1b1b2a6e132ed164d00f52c2318f33eec86ec554c3771b7ac2',
                      'f9c36b729d927b8bf191a3d90229ff6b67a1adbd9db0988209a170469cf728d9'],
 'privileged_users': ['44e39708ed06eb88e2c3f2a8ea0b308ccbace1ea322d3f402f85e8ce81ff538f',
                      'bea85c55b042f7b4464603d0bd58802aa4291b60dc503e791e2c02ae628d81be',
                      'dd66b0cfb44813443ce8bd68853ca8723479008f84e1cfe5e8a499d756d8629e',
                      'f5c3a92a6fc765186485f64fb69e543f27eb5bc4e34ee0713bb25941567a3c35'],
 'service_plans': ['6e59c69226f3b212dff62231168516863c08fd75dc09ef75c9ccf9c51adb9442',
                   '7f4e7214c6bec7aca5bf3044b58af79df9eda6943a20dcc8c7e1f06cce6152ad'],
 'spf_records': ['0c84e58beeae24d667350e9a88e652ac29446e40ff04acb2f4c77afb08012411',
                 '0d26945509efd098c92358a3d3e1e87842d524f69968eebf2e7a7ea24d0f1690',
                 '6346eea42ec45a8bcf70e5b313251e6bbfb240862ba43c96d24ed14ad96f384f'],
 'tenant_id': ['05cd36160012e63e40f492d24df581fc56bc97a3a327652ed6d4ecd85006159c',
               '72495b0e1f3c6c961f46d3f249ce968ac758c43b88e50d32aa138681f8a38804'],
 'transport_config': ['af192c8cd9f202145aa1beec820592b5733dc700737b45eb6d7fda6c6f3d2f4e']}


PACK_ENUM_DOMAINS = {'SPO_tenant': {'[].DefaultLinkPermission': ['1', '2'],
                '[].DefaultSharingLinkType': ['1', '2'],
                '[].FileAnonymousLinkType': ['1', '2'],
                '[].FolderAnonymousLinkType': ['1', '2', '3'],
                '[].ODBSharingCapability': ['0', '1', '2', '3'],
                '[].SharingCapability': ['0', '1', '2', '3'],
                '[].SharingDomainRestrictionMode': ['0', '1']},
 'accepted_domains': {},
 'authorization_policies': {'[].AllowInvitesFrom': ['"Bad value"', '"adminsAndGuestInviters"']},
 'conditional_access_policies': {'[].Conditions.AgentIdRiskLevels': ['"high"',
                                                                     '"medium"',
                                                                     '"medium,high"',
                                                                     'null'],
                                 '[].Conditions.Applications.IncludeUserActions': ['"urn:user:registersecurityinfo"'],
                                 '[].Conditions.AuthenticationFlows.TransferMethods': ['"deviceCodeFlow"',
                                                                                       'null'],
                                 '[].Conditions.ClientAppTypes': ['""',
                                                                  '"all"',
                                                                  '"exchangeActiveSync"',
                                                                  '"other"'],
                                 '[].Conditions.SignInRiskLevels': ['""', '"high"', '"medium"'],
                                 '[].Conditions.UserRiskLevels': ['""', '"high"', '"medium"'],
                                 '[].Conditions.Users.ExcludeGuestsOrExternalUsers.ExternalTenants.MembershipKind': ['"all"'],
                                 '[].Conditions.Users.ExcludeGuestsOrExternalUsers.GuestOrExternalUserTypes': ['"b2bCollaborationGuest"',
                                                                                                               '"b2bCollaborationGuest,internalGuest"'],
                                 '[].GrantControls.AuthenticationStrength.AllowedCombinations': ['"SuperStrength"',
                                                                                                 '"deviceBasedPush"',
                                                                                                 '"federatedMultiFactor"',
                                                                                                 '"fido2"',
                                                                                                 '"hardwareOath,federatedSingleFactor"',
                                                                                                 '"microsoftAuthenticatorPush,federatedSingleFactor"',
                                                                                                 '"password"',
                                                                                                 '"password,hardwareOath"',
                                                                                                 '"password,microsoftAuthenticatorPush"',
                                                                                                 '"password,sms"',
                                                                                                 '"password,softwareOath"',
                                                                                                 '"password,voice"',
                                                                                                 '"sms,federatedSingleFactor"',
                                                                                                 '"softwareOath,federatedSingleFactor"',
                                                                                                 '"temporaryAccessPassMultiUse"',
                                                                                                 '"temporaryAccessPassOneTime"',
                                                                                                 '"voice,federatedSingleFactor"',
                                                                                                 '"windowsHelloForBusiness"',
                                                                                                 '"x509CertificateMultiFactor"',
                                                                                                 'null'],
                                 '[].GrantControls.BuiltInControls': ['""',
                                                                      '"block"',
                                                                      '"compliantDevice"',
                                                                      '"domainJoinedDevice"',
                                                                      '"mfa"',
                                                                      'null'],
                                 '[].GrantControls.Operator': ['""', '"OR"', 'null'],
                                 '[].State': ['"disabled"',
                                              '"enabled"',
                                              '"enabledForReportingButNotEnforced"']},
 'dkim_config': {},
 'dkim_records': {},
 'dmarc_records': {},
 'meeting_policies': {'[].AutoAdmittedUsers': ['"Everyone"',
                                               '"EveryoneInCompany"',
                                               '"EveryoneInCompanyExcludingGuests"',
                                               '"EveryoneInSameAndFederatedCompany"',
                                               '"InvitedUsers"',
                                               '"OrganizerOnly"']},
 'org_config': {},
 'privileged_roles': {'[].Rules[].NotificationType': ['""', '"Email"', 'null'],
                      '[].Rules[].RuleSourceType': ['"Directory Role"', '"PIM Group"']},
 'privileged_users': {},
 'service_plans': {},
 'spf_records': {},
 'tenant_id': {},
 'transport_config': {}}
