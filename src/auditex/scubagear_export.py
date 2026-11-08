"""Internal, experimental, read-only ScubaGear export projection.

No tenant connection, command execution or public CLI surface lives here.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
import json
import math
from pathlib import Path
import re
from typing import Any
from uuid import UUID

from azure_tenant_audit.external_sharing import annotate_enum_names
from azure_tenant_audit.guarded_io import read_guarded_bytes
from azure_tenant_audit.model_evidence import NOT_COLLECTED
from azure_tenant_audit.scuba_scope import ScopeOversize, scope_entries, scope_summary
from azure_tenant_audit.tenant_identity import canonical_tenant_uuid

from .scuba_projection import (
    ASSIGNMENT_HARMLESS, PACK_SHAPE_DIGESTS, PROJECTION_VERSION, ROLE_HARMLESS,
    SCUBA_CAP_EXCLUSION_POLICIES, SCUBA_CONFIG_EXCLUSION_KEYS, SCUBA_ENVIRONMENT_POLICIES,
    SCUBA_ROLE_EXCLUSION_POLICIES, RULE_ONLY_SECTIONS, _EMPTY_CAP, _EMPTY_ROLE, _FIELD_NAME, _annotation,
    _blank, _oversize, _redact, _rule_target, _seen_shape, _user_entries, _json,
    Bundle, Projection, Unavailable,
)
from .scubagear_prune_proof import PINNED_REVISION, PROOF_VERSION, PRUNE_PROOF, verdict_of
from .scope_postcheck import ScopeEvidence, _mask_email

_MAX_EXPORT_BYTES = 64 * 1024 * 1024
_REPAIR = re.compile(r'("[^"]+"\s*:\s*)(?=,|\})')
_VERSION = re.compile(r'\d+(?:\.\d+){1,3}')
_POLICY = re.compile(r'MS\.[A-Z]+\.\d+\.\d+v\d+')
_INVALID = "Invalid ScubaGear export"

VERDICT_MAP = {"Pass": "pass", "Fail": "fail", "Warning": "fail", "N/A": "not_assessed"}
NOT_ASSESSED_REASONS = ("error", "manual", "third_party", "not_implemented", "warning", "other",
                        "ledger_unavailable")
UNMAPPABLE_REGO_POLICIES = (
    "MS.AAD.2.2v1", "MS.AAD.4.1v1", "MS.AAD.8.3v1", "MS.POWERPLATFORM.3.2v1",
    "MS.POWERPLATFORM.4.1v1", "MS.SECURITYSUITE.3.5v1", "MS.SECURITYSUITE.4.2v1",
    "MS.SECURITYSUITE.5.2v1",
)

_PROVIDER_SECTIONS = {
    "aad": ("conditional_access_policies", "authorization_policies", "privileged_users", "privileged_roles",
            "service_plans", "directory_settings", "authentication_method", "domain_settings",
            "default_app_management_policy", "app_management_policies", "risky_delegated_permission_classifications"),
    "exo": ("remote_domains", "accepted_domains", "spf_records", "dkim_config", "dkim_records", "dmarc_records",
            "transport_config", "sharing_policy", "transport_rule", "org_config"),
    "SharePoint": ("SPO_tenant",),
    "teams": ("meeting_policies", "federation_configuration", "client_configuration", "app_policies",
              "broadcast_policies", "tenant_app_settings"),
    "securitysuite": ("protection_policy_rules", "atp_policy_rules", "dlp_compliance_policies",
                      "dlp_compliance_rules", "anti_phish_policies", "anti_phish_rules", "safe_attachment_policies",
                      "safe_attachment_rules", "safe_links_policies", "safe_links_rules", "anti_malware_policies",
                      "anti_malware_rules", "hosted_content_filter_policies", "hosted_content_filter_rules",
                      "built_in_protection_rules", "protection_alerts", "admin_audit_log_config", "conn_filter",
                      "defender_license", "defender_dlp_license", "atp_policy_for_o365", "accepted_domains"),
    "powerplatform": ("environment_creation", "dlp_policies", "tenant_isolation", "environment_list", "tenant_id"),
    "powerbi": ("powerbi_tenant_settings", "powerbi_license_found", "powerbi_access_denied_reason"),
}
SECTION_LEDGERS: dict[str, tuple[str, ...]] = {
    section: tuple(prefix for prefix, sections in _PROVIDER_SECTIONS.items() if section in sections)
    for section in {section for sections in _PROVIDER_SECTIONS.values() for section in sections}
}
_SAFE_REPAIRED_KEYS = frozenset(SECTION_LEDGERS) | frozenset(
    f"{prefix}_{suffix}_commands"
    for prefix in _PROVIDER_SECTIONS for suffix in ("successful", "unsuccessful")
) | {"Results"}


class _Pairs(dict):
    def __init__(self, pairs: list[tuple[str, Any]]):
        super().__init__()
        self.duplicates: dict[str, list[Any]] = {}
        for key, value in pairs:
            if key in self:
                self.duplicates.setdefault(key, [self[key]]).append(value)
            else:
                self[key] = value


@dataclass(frozen=True)
class LoadedExport:
    raw: dict[str, Any]
    results: Any
    kind: str
    sha256: str
    bytes: int
    repaired: bool
    repaired_keys: list[str]
    repaired_masked_count: int
    duplicate_keys: list[str]
    differing_accepted_domains: bool
    module_version: str | None
    report_uuid: str | None
    whole_digest: str


def _canonical_export(value: Any) -> str:
    """Canonicalise the entire parsed export for an in-memory salt input."""
    if isinstance(value, _Pairs):
        return "P[" + ",".join(json.dumps(key, ensure_ascii=False) + ":[" + ",".join(sorted(
            _canonical_export(item) for item in value.duplicates.get(key, [value[key]]))) + "]"
            for key in sorted(value)) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(key, ensure_ascii=False) + ":" + _canonical_export(child)
                              for key, child in sorted(value.items())) + "}"
    if isinstance(value, list):
        return "[" + ",".join(sorted(_canonical_export(child) for child in value)) + "]"
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def _repair_locations(value: Any, marker: str, root: str | None = None) -> set[str]:
    if value == marker:
        return {root or "unrecognisedField"}
    if isinstance(value, dict):
        return set().union(*(_repair_locations(child, marker, root or key) for key, child in value.items()))
    if isinstance(value, list):
        return set().union(*(_repair_locations(child, marker, root) for child in value))
    return set()


def _matches_inside_strings(text: str, matches: list[re.Match[str]]) -> bool:
    """Inspect all repair candidates in one forward scan of the source."""
    quoted = escaped = False
    position = 0
    for match in matches:
        while position < match.start():
            char = text[position]
            if escaped:
                escaped = False
            elif char == "\\" and quoted:
                escaped = True
            elif char == '"':
                quoted = not quoted
            position += 1
        if quoted:
            return True
    return False


def _reject_constant(_value: str) -> None:
    raise ValueError(_INVALID)


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(_INVALID)
    return number


def _shallow_and_clean(value: Any) -> None:
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if depth > 64:
            raise ValueError(_INVALID)
        if isinstance(item, dict):
            for key, child in item.items():
                if any(0xD800 <= ord(c) <= 0xDFFF for c in key):
                    raise ValueError(_INVALID)
                stack.append((child, depth + 1))
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, str) and any(0xD800 <= ord(c) <= 0xDFFF for c in item):
            raise ValueError(_INVALID)


def _parse(text: str) -> Any:
    return json.loads(text, object_pairs_hook=_Pairs, parse_constant=_reject_constant, parse_float=_finite_float)


def _canonical_uuid(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = UUID(value)
        return str(parsed) if str(parsed) == value.lower() else None
    except (ValueError, AttributeError):
        return None


def load_export(path: str | Path) -> LoadedExport:
    """Strictly parse at most 64 MiB; one ScubaGear null-array repair is allowed."""
    try:
        payload = read_guarded_bytes(path, field="input", max_bytes=_MAX_EXPORT_BYTES)
        if len(payload) > _MAX_EXPORT_BYTES:
            raise ValueError(_INVALID)
        text = payload.decode("utf-8-sig")
        repaired_count = 0
        repaired_masked_count = 0
        repaired_sections: set[str] = set()
        try:
            document = _parse(text)
        except json.JSONDecodeError:
            def replace(match: re.Match[str]) -> str:
                nonlocal repaired_count, repaired_masked_count
                name = match[1].split('"', 2)[1]
                repaired_count += 1
                repaired_masked_count += name not in _SAFE_REPAIRED_KEYS
                return match[1] + "[]"
            matches = list(_REPAIR.finditer(text))
            if _matches_inside_strings(text, matches):
                raise ValueError(_INVALID)
            repaired = _REPAIR.sub(replace, text)
            if repaired == text:
                raise ValueError(_INVALID) from None
            document = _parse(repaired)
            marker = "__scubagear_repair_marker_4f10__"
            if marker in text:
                raise ValueError(_INVALID)
            marked = _parse(_REPAIR.sub(lambda match: match[1] + json.dumps(marker), text))
            if isinstance(marked, dict):
                root = marked.get("Raw", marked)
                repaired_sections = _repair_locations(root, marker)
                if "Results" in marked and _repair_locations(marked["Results"], marker):
                    repaired_sections.add("Results")
                if "MetaData" in marked and _repair_locations(marked["MetaData"], marker):
                    raise ValueError(_INVALID)
            if "unrecognisedField" in repaired_sections:
                raise ValueError(_INVALID)
        _shallow_and_clean(document)
        if not isinstance(document, dict):
            raise ValueError(_INVALID)
        if isinstance(document.get("Raw"), dict) and "MetaData" in document:
            raw, kind, results = document["Raw"], "scubaresults", document.get("Results")
        elif "Raw" not in document and "MetaData" not in document:
            raw, kind, results = document, "provider_export", None
        else:
            raise ValueError(_INVALID)
        if not any(section in raw for section in SECTION_LEDGERS):
            raise ValueError(_INVALID)
        duplicate_names = []
        differing = False
        stack: list[tuple[Any, bool]] = [(document, document is raw)]
        while stack:
            item, is_export = stack.pop()
            if isinstance(item, _Pairs):
                for name, values in item.duplicates.items():
                    if not (is_export and name == "accepted_domains"):
                        raise ValueError(_INVALID)
                    duplicate_names.append(name)
                    if len({_json(v) for v in values}) != 1:
                        differing = True
                stack.extend((child, item is document and child is raw) for child in item.values())
            elif isinstance(item, list):
                stack.extend((child, False) for child in item)
        metadata = document.get("MetaData") if kind == "scubaresults" else document
        metadata = metadata if isinstance(metadata, dict) else {}
        version = metadata.get("ToolVersion", metadata.get("module_version"))
        report_uuid = metadata.get("ReportUUID", metadata.get("report_uuid"))
        return LoadedExport(raw=raw, results=results, kind=kind, sha256=sha256(payload).hexdigest(),
                            bytes=len(payload), repaired=bool(repaired_count),
                            repaired_keys=sorted(repaired_sections & _SAFE_REPAIRED_KEYS),
                            repaired_masked_count=repaired_masked_count,
                            duplicate_keys=sorted(set(duplicate_names)),
                            differing_accepted_domains=differing,
                            module_version=version if isinstance(version, str) and _VERSION.fullmatch(version) else None,
                            report_uuid=_canonical_uuid(report_uuid),
                            whole_digest=sha256(_canonical_export(raw).encode()).hexdigest())
    except (UnicodeError, json.JSONDecodeError, RecursionError, KeyError, TypeError, OverflowError, ValueError):
        raise ValueError(_INVALID) from None


def load_results(path: str | Path) -> tuple[Any, str]:
    """Read only the structural verdict fields of an optional local results file."""
    try:
        payload = read_guarded_bytes(path, field="input", max_bytes=_MAX_EXPORT_BYTES)
        if len(payload) > _MAX_EXPORT_BYTES:
            raise ValueError(_INVALID)
        node = _parse(payload.decode("utf-8-sig"))
        _shallow_and_clean(node)
        if isinstance(node, list):
            return node, "testresults"
        if isinstance(node, dict) and {"PolicyId", "RequirementMet"} <= set(node):
            return [node], "testresults"
        if isinstance(node, dict) and isinstance(node.get("Results"), dict):
            return node["Results"], "scubaresults"
        raise ValueError(_INVALID)
    except (UnicodeError, json.JSONDecodeError, RecursionError, KeyError, TypeError, OverflowError, ValueError):
        raise ValueError(_INVALID) from None


def redaction_salt(users: Any, object_ids: list[str] | None = None, whole_digest: str | None = None) -> str:
    if isinstance(users, dict) and users and all(isinstance(entry, dict) for entry in users.values()):
        basis = {"entries": sorted(_json(entry) for entry in users.values()), "object_ids": object_ids}
    else:
        basis = None
    return sha256(_json({"purpose": "scubagear-adapter-redaction-v1", "privileged_users": basis,
                         "whole_export": whole_digest}).encode()).hexdigest()


# Canonicalisation is the only evidence reshaping in this adapter. All checks apply to every entry before any conversion.
def canonicalise_privileged_users(value: Any, whole_digest: str | None = None) -> tuple[Any, bool, list[str] | None]:
    if not isinstance(value, dict) or not value:
        return value, False, None
    lowered: set[str] = set()
    entries = []
    for key, entry in value.items():
        canonical = _canonical_uuid(key)
        if canonical is None or canonical in lowered or not isinstance(entry, dict) or set(entry) != {
            "id", "DisplayName", "OnPremisesImmutableId", "roles"
        } or entry["id"] != key or not isinstance(entry["id"], str) or not isinstance(entry["DisplayName"], str) \
                or entry["OnPremisesImmutableId"] is not None and not isinstance(entry["OnPremisesImmutableId"], str) \
                or not isinstance(entry["roles"], list) or not entry["roles"] \
                or not all(isinstance(role, str) for role in entry["roles"]):
            return value, False, None
        lowered.add(canonical)
        entries.append({"DisplayName": entry["DisplayName"],
                        "OnPremisesImmutableId": entry["OnPremisesImmutableId"], "roles": sorted(entry["roles"])})
    object_ids = sorted(lowered)
    salt = redaction_salt({str(index): entry for index, entry in enumerate(entries)}, object_ids, whole_digest)
    entries.sort(key=lambda entry: sha256((salt + "\0" + _json(entry)).encode()).hexdigest())
    return {f"User{index}": entry for index, entry in enumerate(entries, 1)}, True, object_ids


CA_RESTRICTION_NAMES = {"locations", "devices", "platforms", "sessionControls", "includeGroups",
                        "includeGuestsOrExternalUsers", "authenticationContextClassReferences",
                        "servicePrincipalRiskLevels", "customAuthenticationFactors", "termsOfUse",
                        "applicationFilter", "includeServicePrincipals", "excludeServicePrincipals",
                        "servicePrincipalFilter", "id", "displayName"}


def qualifier_check(section: str, value: Any) -> dict[str, str] | None:
    """Mirror the bundle's restrictions before a proof-gated prune; type faults stay with the gate."""
    if section == "conditional_access_policies" and isinstance(value, list):
        validated = set(PRUNE_PROOF[section]["validated"])
        for row in value:
            if not isinstance(row, dict):
                continue
            state = row.get("State")
            if isinstance(state, str) and state in {"disabled", "enabledForReportingButNotEnforced"}:
                continue
            stack = [(row, "[]", True)]
            while stack:
                node, path, root = stack.pop()
                if not isinstance(node, dict):
                    continue
                for key, child in node.items():
                    if _annotation(key):
                        continue
                    field = path + "." + key
                    if field in validated:
                        if isinstance(child, dict):
                            stack.append((child, field, False))
                        continue
                    name = key[:1].lower() + key[1:]
                    restricted = name in CA_RESTRICTION_NAMES and (not root or name != "id")
                    if restricted and not _blank(child) or not restricted and not root and child not in (None, [], {}, ""):
                        return {"field": "$", "kind": "unexpected_field"}
    elif section == "privileged_roles" and isinstance(value, list):
        bundle = Bundle(Path("."), 1, 1, 1)
        for row in value:
            if not isinstance(row, dict):
                continue
            template = row.get("RoleTemplateId")
            def same_role(item: Any) -> bool:
                return isinstance(item, str) and isinstance(template, str) and item.lower() == template.lower()
            checks = [(row, {"DisplayName", "RoleTemplateId", "Assignments", "Rules", "key"}, "",
                       {**ROLE_HARMLESS, "TemplateId": same_role})]
            for assignment in row.get("Assignments", []) if isinstance(row.get("Assignments"), list) else []:
                if isinstance(assignment, dict):
                    checks.append((assignment, {"PrincipalId", "StartDateTime", "EndDateTime"}, "Assignments",
                                   {**ASSIGNMENT_HARMLESS, "RoleDefinitionId": same_role}))
            for rule in row.get("Rules", []) if isinstance(row.get("Rules"), list) else []:
                if not isinstance(rule, dict):
                    continue
                parts = rule.get("Id").split("_") if isinstance(rule.get("Id"), str) else []
                checks.append((rule, {"Id", "RuleSource", "RuleSourceType", "IsExpirationRequired",
                                      "MaximumDuration", "NotificationRecipients", "NotificationType", "Setting"},
                               "Rules", {"Target": _rule_target(rule.get("Id")),
                                         "RecipientType": lambda item, p=parts: len(p) == 4 and isinstance(item, str)
                                         and item.lower() == p[1].lower()}))
                if isinstance(rule.get("Setting"), dict):
                    checks.append((rule["Setting"], {"IsApprovalRequired"}, "Rules.Setting", {}))
            for node, allowed, path, harmless in checks:
                try:
                    bundle.qualified_fields(node, allowed, path, harmless)
                except Unavailable as exc:
                    if exc.detail.get("kind") == "unexpected_field":
                        return {"field": "$", "kind": "unexpected_field"}
            for rule in row.get("Rules", []) if isinstance(row.get("Rules"), list) else []:
                if isinstance(rule, dict) and isinstance(rule.get("Id"), str) and not rule["Id"].startswith(
                    ("Expiration_", "Notification_", "Approval_")
                ):
                    return {"field": "Rules.Id", "kind": "unseen_enum_value"}
    return None


def _prune(value: Any, validated: set[str], path: str, removed: list[tuple[str, ...]],
           segments: tuple[str, ...] = ()) -> Any:
    if isinstance(value, list):
        return [_prune(item, validated, path + "[]", removed, segments) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, child in value.items():
            field = path + "." + key if path else key
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) and field in validated:
                result[key] = _prune(child, validated, field, removed, segments + (key,))
            else:
                removed.append(segments + (key,))
        return result
    return value


def prune_section(section: str, value: Any, proof: dict[str, dict] = PRUNE_PROOF,
                  removed_paths: list[tuple[str, ...]] | None = None) -> tuple[Any, int]:
    row = proof.get(section)
    if not row or section not in PACK_SHAPE_DIGESTS or row.get("verdict") != "prunable" or verdict_of(row) != "prunable":
        return value, 0
    removed: list[tuple[str, ...]] = []
    try:
        result = _prune(value, set(row["validated"]), "", removed)
    except (RecursionError, KeyError, TypeError):
        return value, 0
    if removed_paths is not None:
        removed_paths.extend(removed)
    return result, len(removed)


def _ignored_names(paths: list[tuple[str, ...]]) -> list[str]:
    names = set()
    for segments in paths:
        if any("@odata." in piece for piece in segments):
            continue
        names.add(".".join(piece if _FIELD_NAME.fullmatch(piece) else "unrecognisedField" for piece in segments))
    return sorted(names)[:64]


def _config_view(raw: Any, catalogue: dict[str, Any], max_items: int, max_chars: int,
                 *, rule_view: bool = False) -> tuple[Any, dict, dict]:
    if not isinstance(raw, dict):
        raise Unavailable()
    aad = raw.get("Aad")
    cap = raw.get("CapExclusions", _EMPTY_CAP)
    role = raw.get("RoleExclusions", _EMPTY_ROLE)
    declared = aad not in (None, {}) or cap != _EMPTY_CAP or role != _EMPTY_ROLE
    entries = 0
    for node in (aad, cap, role):
        stack = [node]
        while stack:
            item = stack.pop()
            if isinstance(item, str):
                entries += 1
            elif isinstance(item, list):
                stack.extend(item)
            elif isinstance(item, dict):
                stack.extend(item.values())
    environment = raw.get("M365Environment", "commercial")
    # The model path must retain its existing withholding until its environment gate lands.
    environments = {"commercial", "gcc", "gcchigh", "dod"} if rule_view else {"commercial"}
    environment = environment if isinstance(environment, str) and environment in environments else None
    base = {"Aad": None, "CapExclusions": deepcopy(_EMPTY_CAP), "RoleExclusions": deepcopy(_EMPTY_ROLE)}
    views, outcomes = {}, {}
    for policy_id in sorted(pid for pid, data in catalogue.items() if "scuba_config" in data["sections"]):
        family = policy_id.split(".")[1]
        try:
            if family == "AAD":
                view = deepcopy(base)
                if policy_id in SCUBA_ENVIRONMENT_POLICIES:
                    if environment is None:
                        raise Unavailable()
                    view["M365Environment"] = environment
                if policy_id in SCUBA_CAP_EXCLUSION_POLICIES | SCUBA_ROLE_EXCLUSION_POLICIES and declared:
                    outcomes[policy_id] = "break_glass_unresolved"
                    continue
            elif policy_id == "MS.EXO.1.1v2":
                view = None
            elif family == "TEAMS":
                if environment is None:
                    raise Unavailable()
                view = {"M365Environment": environment}
            elif family == "SECURITYSUITE":
                outcomes[policy_id] = "operator_input_required"
                continue
            else:
                raise Unavailable()
            _seen_shape("scuba_config", view)
            if _oversize(view, max_items, max_chars):
                raise Unavailable("oversize")
            views[policy_id] = view
            outcomes[policy_id] = "projected"
        except Unavailable:
            outcomes[policy_id] = "environment_ambiguous" if environment is None else "unseen_shape"
    if "projected" not in outcomes.values():
        raise Unavailable()
    synthesis = {"source": "synthesised:default-config", "basis": "scubagear_default_config",
                 "m365_environment": {"value": environment, "basis": "assumed_default" if environment else "ambiguous"},
                 "break_glass": {"source": "operator", "entries": entries, "state": "identity_unreadable"} if declared
                                else {"source": "none"}, "policies": outcomes}
    return base, views, synthesis


def project_export(loaded: LoadedExport, catalogue: dict[str, Any], *, redact: bool = True,
                   max_items: int = 40, max_chars: int = 12000,
                   proof: dict[str, dict] = PRUNE_PROOF) -> tuple[Projection, dict[str, Any]]:
    if any(type(v) is not int or v < 1 for v in (max_items, max_chars)):
        raise ValueError("Projection bounds must be positive integers")
    try:
        raw = loaded.raw
        sections = sorted({section for item in catalogue.values() for section in item["sections"]})
        projection = Projection()
        projection.views = {}
        projection.rule_sections = {section: dict(NOT_COLLECTED) for section in set(sections) | RULE_ONLY_SECTIONS}
        projection.rule_views = {}
        # The ledger itself is evidence even when it names a failed command. Such a failure still
        # withholds every Security Suite section below; never mistake its empty output for success.
        ledger_keys = ("securitysuite_successful_commands", "securitysuite_unsuccessful_commands")
        if all(key not in loaded.repaired_keys and isinstance(raw.get(key), list)
               and all(isinstance(command, str) for command in raw[key]) for key in ledger_keys):
            projection.rule_sections["securitysuite_unsuccessful_commands"] = raw[ledger_keys[1]]
        report: dict[str, dict] = {}
        pruning = {s: {"verdict": r["verdict"], "pruned_keys": 0, "outcome": "absent", "qualifier_withheld": False}
                   for s, r in proof.items()}
        canonicalised = {"applied": False, "entries": 0}
        object_ids = None
        raw_ca = None
        for section in sections:
            present = section in raw
            source = ["raw/scubagear-export/" + section] if present else []
            removed: list[tuple[str, ...]] = []
            try:
                if section == "sharing_policy":
                    raise Unavailable()
                if not present:
                    raise Unavailable("missing_artifact")
                if section in loaded.repaired_keys or any(
                    prefix + "_successful_commands" in loaded.repaired_keys or
                    prefix + "_unsuccessful_commands" in loaded.repaired_keys for prefix in SECTION_LEDGERS.get(section, ())
                ) or section == "accepted_domains" and loaded.differing_accepted_domains:
                    raise Unavailable()
                if section == "scuba_config":
                    value, views, synthesis = _config_view(raw[section], catalogue, max_items, max_chars)
                    rule_value, rule_views, rule_synthesis = _config_view(
                        raw[section], catalogue, max_items, max_chars, rule_view=True)
                else:
                    failed = False
                    for prefix in SECTION_LEDGERS[section]:
                        bad = raw.get(prefix + "_unsuccessful_commands")
                        if isinstance(bad, list) and bad:
                            failed = True
                    if failed:
                        exc = Unavailable("collector_error")
                        exc.detail = {"error_class": "command_error"}
                        raise exc
                    if any(not isinstance(raw.get(prefix + "_successful_commands"), list)
                           or not all(isinstance(v, str) for v in raw[prefix + "_successful_commands"])
                           or not isinstance(raw.get(prefix + "_unsuccessful_commands"), list)
                           or not all(isinstance(v, str) for v in raw[prefix + "_unsuccessful_commands"])
                           for prefix in SECTION_LEDGERS[section]):
                        raise Unavailable()
                    value = raw[section]
                    if section == "tenant_id":
                        value = canonical_tenant_uuid(value)
                        other = raw.get("tenant_details")
                        other = canonical_tenant_uuid(other.get("TenantId")) if isinstance(other, dict) else None
                        if value is None or other is not None and other != value:
                            raise Unavailable()
                    if section == "privileged_users":
                        value, applied, object_ids = canonicalise_privileged_users(value, loaded.whole_digest)
                        canonicalised = {"applied": applied, "entries": len(value) if applied else 0}
                    if section == "conditional_access_policies" and isinstance(value, list):
                        raw_ca = value
                    if section in {"conditional_access_policies", "privileged_roles"}:
                        marker = qualifier_check(section, value)
                        if marker:
                            if section in pruning:
                                pruning[section]["qualifier_withheld"] = True
                            exc = Unavailable(field=marker["field"], kind=marker["kind"])
                            raise exc
                    users_ok = True
                    if section == "privileged_users":
                        try:
                            _user_entries(value)
                        except Unavailable:
                            users_ok = False
                    # A provider export is literal evidence, never a producer of run-bound membership proofs.
                    # Ignore reserved run-only keys without mutating the loaded source rows.
                    if section == "anti_phish_policies" and isinstance(value, list):
                        value = [{key: item for key, item in row.items()
                                  if key not in {"TargetedUsersCoverage", "TargetedUsersCoverageBinding"}}
                                 if isinstance(row, dict) else row for row in value]
                    # Serving copies a policy's read set; only privileged users need
                    # a capture copy because model redaction rewrites them in place.
                    if users_ok:
                        projection.rule_sections[section] = deepcopy(value) if section == "privileged_users" else value
                    if section in proof:
                        value, pruning[section]["pruned_keys"] = prune_section(
                            section, value, proof, removed_paths=removed)
                if section == "scuba_config":
                    projection.rule_sections[section] = rule_value
                    for policy_id, outcome in rule_synthesis["policies"].items():
                        view = rule_views[policy_id] if outcome == "projected" else dict(NOT_COLLECTED)
                        projection.rule_views.setdefault(policy_id, {})[section] = view
                _seen_shape(section, value)
                if section == "privileged_users":
                    _user_entries(value)
                if _oversize(value, max_items, max_chars):
                    raise Unavailable("oversize")
            except Unavailable as exc:
                projection[section] = dict(NOT_COLLECTED)
                info = {"status": "not_collected", "reason": exc.reason, "source": source}
                if exc.reason in {"incomplete_shape", "collector_error"}:
                    info["detail"] = exc.detail
                report[section] = info
                if section in pruning:
                    pruning[section]["outcome"] = "absent" if not present else "withheld"
            else:
                projection[section] = value
                info = {"status": "projected", "reason": None, "source": source}
                if removed:
                    names = _ignored_names(removed)
                    if names:
                        info["ignored_fields"] = names
                if section == "scuba_config":
                    info["synthesis"] = synthesis
                    for policy_id in synthesis["policies"]:
                        projection.views.setdefault(policy_id, {})[section] = (
                            views[policy_id] if synthesis["policies"][policy_id] == "projected"
                            else dict(NOT_COLLECTED))
                report[section] = info
                if section in pruning:
                    pruning[section]["outcome"] = "projected"
        users = projection.get("privileged_users")
        salt = redaction_salt(users if users != NOT_COLLECTED else None,
                              object_ids if users != NOT_COLLECTED else None, loaded.whole_digest)
        redaction = _redact(projection, salt, redact)
        for section, value in projection.items():
            if value != NOT_COLLECTED and _oversize(annotate_enum_names(section, value), max_items, max_chars):
                projection[section] = dict(NOT_COLLECTED)
                report[section].update(status="not_collected", reason="oversize")
                report[section].pop("ignored_fields", None)
                if section in pruning:
                    pruning[section]["outcome"] = "withheld"
        projection.report = {"schema_version": PROJECTION_VERSION, "sections": report, "redaction": redaction,
                             "bounds": {"max_items": max_items, "max_chars": max_chars}}
        return projection, {"canonicalised": {"privileged_users": canonicalised}, "pruning": pruning,
                            "raw_ca": raw_ca}
    except (RecursionError, KeyError, TypeError):
        raise ValueError(_INVALID) from None


def scope_from_export(projection: Projection, raw_ca: Any, *, redact: bool, max_items: int) -> ScopeEvidence:
    section = projection.report["sections"]["conditional_access_policies"]
    projected = section["status"] == "projected"
    source = "projection" if projected else "raw"
    if not projected and raw_ca is None:
        reason = section["reason"]
        if reason not in {"missing_artifact", "incomplete_shape", "oversize"}:
            reason = "incomplete_shape"
        return ScopeEvidence(None, {"status": "not_evaluated", "source": None, "reason": reason,
                                    "count": 0, "policies": []})
    if not projected and (not isinstance(raw_ca, list) or any(
        not isinstance(row, dict) or not isinstance(row.get("State"), str)
        or not isinstance(row.get("DisplayName"), str)
        or not isinstance(row.get("Conditions"), dict)
        or not isinstance(row.get("GrantControls"), dict) for row in raw_ca
    )):
        return ScopeEvidence(None, {"status": "not_evaluated", "source": None, "reason": "incomplete_shape",
                                    "count": 0, "policies": []})
    try:
        entries = scope_entries(projection["conditional_access_policies"] if projected else raw_ca,
                                mask=None if projected or not redact else _mask_email)
        return ScopeEvidence(entries, {"status": "evaluated", "source": source, "reason": None,
                                       **scope_summary(entries, max_items=max_items)})
    except ScopeOversize:
        reason = "oversize"
    except (ValueError, TypeError, KeyError, OverflowError):
        reason = "incomplete_shape"
    return ScopeEvidence(None, {"status": "not_evaluated", "source": None, "reason": reason,
                                "count": 0, "policies": []})


def _valid_map(verdict_map: dict[str, str]) -> None:
    if (not isinstance(verdict_map, dict) or set(verdict_map) != set(VERDICT_MAP)
            or any(value not in ("pass", "fail", "not_assessed") for value in verdict_map.values())):
        raise ValueError("Invalid ScubaGear verdict map")


def _product_prefix(policy_id: str) -> str | None:
    if not _POLICY.fullmatch(policy_id):
        return None
    return {"AAD": "aad", "EXO": "exo", "SHAREPOINT": "SharePoint", "TEAMS": "teams",
            "SECURITYSUITE": "securitysuite", "POWERPLATFORM": "powerplatform", "POWERBI": "powerbi"}.get(
                policy_id.split(".")[1])


def scubaresults_layout_ok(rows: Any) -> bool:
    return isinstance(rows, dict) and all(
        isinstance(groups, list) and all(
            isinstance(group, dict) and isinstance(group.get("Controls"), list)
            and all(isinstance(control, dict) for control in group["Controls"])
            for group in groups
        ) for groups in rows.values()
    )


def build_baseline(rows: Any, raw: dict[str, Any], *, kind: str,
                   repaired_keys: list[str] = (), verdict_map: dict[str, str] = VERDICT_MAP,
                   catalogue_ids: set[str] | None = None) -> tuple[dict[str, str], dict[str, str], list[str]]:
    _valid_map(verdict_map)
    if kind == "scubaresults" and not scubaresults_layout_ok(rows):
        return {}, {}, []
    baseline, reasons, unmappable = {}, {}, set()
    def put(pid: Any, status: str, reason: str | None) -> None:
        if not isinstance(pid, str) or not _POLICY.fullmatch(pid):
            return
        if catalogue_ids is not None and pid not in catalogue_ids:
            unmappable.add(pid)
            return
        prefix = _product_prefix(pid)
        if prefix and (prefix + "_successful_commands" in repaired_keys or
                       prefix + "_unsuccessful_commands" in repaired_keys or
                       not isinstance(raw.get(prefix + "_successful_commands"), list) or
                       not all(isinstance(item, str) for item in raw.get(prefix + "_successful_commands", []))):
            status, reason = "not_assessed", "ledger_unavailable"
        baseline[pid] = status
        if status == "not_assessed" and reason:
            reasons[pid] = reason
        else:
            reasons.pop(pid, None)
    if kind == "scubaresults" and isinstance(rows, dict):
        for product in rows.values():
            if not isinstance(product, list):
                continue
            for group in product:
                controls = group.get("Controls") if isinstance(group, dict) else None
                if not isinstance(controls, list):
                    continue
                for control in controls:
                    if not isinstance(control, dict):
                        continue
                    label = control.get("Result")
                    status = verdict_map.get(label, "not_assessed") if isinstance(label, str) else "not_assessed"
                    reason = {"Error": "error", "N/A": "manual"}.get(label, "other") if status == "not_assessed" else None
                    if label == "Warning" and status == "not_assessed":
                        reason = "warning"
                    put(control.get("Control ID"), status, reason)
    elif kind == "testresults" and isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            pid = row.get("PolicyId")
            prefix = _product_prefix(pid) if isinstance(pid, str) else None
            commands = row.get("Commandlet")
            successful = raw.get(prefix + "_successful_commands") if prefix else None
            if not isinstance(commands, list) or not all(isinstance(v, str) for v in commands) or not isinstance(
                successful, list) or not all(isinstance(v, str) for v in successful) or not set(commands) <= set(successful):
                put(pid, "not_assessed", "error")
                continue
            if row.get("RequirementMet") is True:
                put(pid, "pass", None)
            elif row.get("RequirementMet") is False:
                criticality = row.get("Criticality")
                if criticality == "Shall":
                    put(pid, "fail", None)
                elif criticality == "Should":
                    status = verdict_map["Warning"]
                    put(pid, status, "warning" if status == "not_assessed" else None)
                else:
                    status = verdict_map["N/A"]
                    reason = ("third_party" if isinstance(criticality, str) and criticality.endswith("3rd Party")
                              else "not_implemented" if isinstance(criticality, str)
                              and criticality.endswith("Not-Implemented") else "manual")
                    put(pid, status, reason if status == "not_assessed" else None)
    return baseline, reasons, sorted(unmappable)


def resolve_output_directory(path: str | Path) -> Path:
    """Refuse run bundles, links and non-empty destinations before any writes."""
    target = Path(path).expanduser()
    if target.is_symlink() or target.exists() and (not target.is_dir() or any(target.iterdir())):
        raise ValueError("Model output directory must be new or empty")
    current = target.resolve()
    if not target.parent.is_dir():
        raise ValueError("Model output directory parent must exist")
    for parent in (current, *current.parents):
        if (parent / "run-manifest.json").exists():
            raise ValueError("Model output directory must be outside a run bundle")
    return target


def build_sidecar(loaded: LoadedExport, projection: Projection, extras: dict[str, Any],
                  catalogue: dict[str, Any], selected: list[str], baseline: dict[str, str],
                  reasons: dict[str, str], unmappable: list[str], verdict_source: str, verdict_state: str,
                  verdict_map: dict[str, str], generated_at: str, scope: ScopeEvidence | None) -> dict[str, Any]:
    disposition, ceiling = {}, {}
    for policy_id, item in catalogue.items():
        failures = {}
        for section in item["sections"]:
            section_report = projection.report["sections"][section]
            if section_report["status"] != "projected":
                failures[section] = {"reason": section_report["reason"],
                                     "detail_kind": section_report.get("detail", {}).get("kind")}
            elif section == "scuba_config":
                outcome = section_report["synthesis"]["policies"].get(policy_id)
                if outcome != "projected":
                    failures[section] = {"outcome": outcome}
        disposition[policy_id] = {"status": "withheld", "sections": failures} if failures else {
            "status": "assessed", "sections": {}}
        family = policy_id.split(".")[1]
        bucket = ceiling.setdefault(family, {"assessed": 0, "total": 0})
        bucket["total"] += 1
        bucket["assessed"] += not failures
    ceiling["overall"] = {"assessed": sum(item["assessed"] for item in ceiling.values()),
                          "total": sum(item["total"] for item in ceiling.values())}
    ceiling["claim"] = ("ceiling set by the validated shape gate (16 of 58 sections) after proof-gated pruning; "
                        "a plumbing figure, not a coverage claim")
    pruning = extras["pruning"]
    pruning_block = {"proof_version": PROOF_VERSION, "pinned_revision": PINNED_REVISION,
                     "sections": pruning,
                     "totals": {"sections_pruned": sum(v["pruned_keys"] > 0 for v in pruning.values()),
                                "pruned_keys": sum(v["pruned_keys"] for v in pruning.values())}}
    ledger = {}
    for prefix in _PROVIDER_SECTIONS:
        failed = loaded.raw.get(prefix + "_unsuccessful_commands")
        failed = failed if isinstance(failed, list) else []
        # Ledger strings are untrusted evidence, even when they resemble command identifiers.
        ledger[prefix] = {"unsuccessful_count": len(failed)}
    return {
        "adapter_report_version": 1, "generated_at": generated_at,
        "input": {"kind": loaded.kind, "sha256": loaded.sha256, "bytes": loaded.bytes,
                  "module_version": loaded.module_version, "report_uuid": loaded.report_uuid},
        "parse": {"repaired": loaded.repaired, "repaired_keys": loaded.repaired_keys[:64],
                  "masked_repaired_keys": loaded.repaired_masked_count,
                  "duplicate_keys": loaded.duplicate_keys},
        "ledger": ledger,
        "verdicts": {"source": verdict_source, "state": verdict_state, "counts": dict(Counter(baseline.values())),
                     "map": dict(verdict_map), "not_assessed_reasons": reasons},
        "canonicalised": extras["canonicalised"], "pruning": pruning_block,
        "disposition": disposition, "ceiling": ceiling,
        "unmappable": {"ids": sorted(set(UNMAPPABLE_REGO_POLICIES) | set(unmappable)),
                       "note": "not in the shipped catalogue (no model row, no trained shape)"},
        "pinned_reference": {"scubagear_revision": PINNED_REVISION, "module_version": "2.0.0"},
        "notes": ["not a validated run bundle", "auditex validate does not apply",
                  "post-check " + (scope.summary["status"] if scope else "not_evaluated")],
    }
