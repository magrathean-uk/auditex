"""Emergency-access exclusions in Conditional Access (CE+ product review, action 8).

The check judges enabled policies that require MFA or block, takes the operator's list of accounts
when there is one, and says which policies lack the exclusion. Report-only policies, policies that
grant on a device or session control alone, and policies that cannot reach the accounts are not judged.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from azure_tenant_audit import break_glass
from azure_tenant_audit.baselines import rule_inputs_gap
from azure_tenant_audit.cli import main as audit_main
from azure_tenant_audit.cli import run_offline
from azure_tenant_audit.findings import build_findings
from azure_tenant_audit.normalize import build_normalized_snapshot

BG1, BG2, USER, SALES = "u-bg1", "u-bg2", "u-alice", "g-sales"
BG_GROUP = "g-bg"
GLOBAL_ADMIN_ROLE = "62e90394-69f5-4237-9190-012177145e10"
RULE = "ca.break_glass_exclusion_missing"


def _policy(policy_id: str, *, state: str = "enabled", users: dict[str, Any] | None = None, grant: dict[str, Any] | None = None, **conditions: Any) -> dict[str, Any]:
    return {
        "id": policy_id,
        "displayName": f"Policy {policy_id}",
        "state": state,
        "conditions": {"users": users if users is not None else {"includeUsers": ["All"]}, "applications": {"includeApplications": ["All"]}, **conditions},
        "grantControls": grant if grant is not None else {"operator": "OR", "builtInControls": ["mfa"]},
    }


def _payloads(policies: list[dict[str, Any]], *, groups: list[dict[str, Any]] | None = None, admins: list[str] | None = None) -> dict[str, Any]:
    return {
        "identity": {
            "users": {
                "value": [
                    {"id": BG1, "displayName": "Emergency One", "userPrincipalName": "bg1@example.com"},
                    {"id": BG2, "displayName": "Emergency Two", "userPrincipalName": "bg2@example.com"},
                    {"id": USER, "displayName": "Alice", "userPrincipalName": "alice@example.com"},
                ]
            },
            "groups": {"value": groups if groups is not None else [{"id": SALES, "displayName": "Sales"}]},
            "roleDefinitions": {"value": [{"id": GLOBAL_ADMIN_ROLE, "displayName": "Global Administrator"}]},
            "roleAssignments": {"value": [{"id": f"ra-{p}", "roleDefinitionId": GLOBAL_ADMIN_ROLE, "principalId": p} for p in (admins or [])]},
        },
        "conditional_access": {"conditionalAccessPolicies": {"value": policies}},
    }


def _snapshot(policies: list[dict[str, Any]], *, accounts: list[str] | None = None, **kwargs: Any) -> dict[str, Any]:
    return build_normalized_snapshot(
        tenant_name="acme",
        run_id="r",
        collector_payloads=_payloads(policies, **kwargs),
        break_glass_accounts=accounts,
    )


def _finding(snapshot: dict[str, Any]) -> dict[str, Any] | None:
    found = [item for item in build_findings([], normalized_snapshot=snapshot) if item["rule_id"] == RULE]
    assert len(found) <= 1, "one finding for the tenant, naming the policies"
    return found[0] if found else None


def _names(finding: dict[str, Any]) -> list[str]:
    return sorted(finding["affected_objects"])


# ---- which policies are judged -----------------------------------------------------------------------


def test_only_enabled_mfa_device_or_block_policies_that_reach_the_accounts_are_judged() -> None:
    session_only = _policy("session-only")
    session_only["grantControls"] = None
    snapshot = _snapshot(
        [
            _policy("mfa-all"),
            _policy("block-all", grant={"builtInControls": ["block"]}),
            _policy("report-only", state="enabledForReportingButNotEnforced"),
            _policy("disabled", state="disabled"),
            _policy("password-change", grant={"builtInControls": ["passwordChange"]}),
            session_only,
            _policy("narrow-group", users={"includeGroups": [SALES]}),
            _policy("excluded", users={"includeUsers": ["All"], "excludeUsers": [BG1]}),
        ],
        accounts=["bg1@example.com", "bg2@example.com"],
    )

    finding = _finding(snapshot)

    assert finding is not None
    assert _names(finding) == ["Policy block-all", "Policy mfa-all"]
    assessment = snapshot["break_glass_assessment"]["records"][0]
    assert assessment["policies_in_scope"] == 3 and assessment["policies_missing_exclusion"] == 2
    assert assessment["account_source"] == "operator" and assessment["state"] == "assessed"


def test_a_policy_that_names_an_account_is_judged_even_when_it_does_not_target_everyone() -> None:
    snapshot = _snapshot([_policy("named", users={"includeUsers": [BG1, USER]})], accounts=["bg1@example.com"])

    finding = _finding(snapshot)

    assert finding is not None and _names(finding) == ["Policy named"]
    assert finding["evidence"]["policies"][0]["reach"] == "names_account"


def test_a_policy_aimed_at_a_role_the_accounts_hold_is_judged() -> None:
    snapshot = _snapshot(
        [_policy("admins", users={"includeRoles": [GLOBAL_ADMIN_ROLE]})], accounts=["bg1@example.com"], admins=[BG1]
    )

    finding = _finding(snapshot)

    assert finding is not None and finding["evidence"]["policies"][0]["reach"] == "administrator_roles"
    assert finding["evidence"]["policies"][0]["broad"] is True and finding["severity"] == "high"


def test_an_exclusion_by_user_or_group_satisfies_the_check() -> None:
    group = [{"id": BG_GROUP, "displayName": "Break Glass Accounts"}]
    by_user = _snapshot([_policy("p", users={"includeUsers": ["All"], "excludeUsers": [BG2]})], accounts=["bg1@example.com", "bg2@example.com"])
    by_group = _snapshot(
        [_policy("p", users={"includeUsers": ["All"], "excludeGroups": [BG_GROUP]})],
        accounts=["Break Glass Accounts"],
        groups=group,
    )

    assert _finding(by_user) is None
    assert _finding(by_group) is None
    for snapshot in (by_user, by_group):
        record = snapshot["break_glass_assessment"]["records"][0]
        assert record["state"] == "assessed" and record["policies_in_scope"] == 1 and record["policies_missing_exclusion"] == 0
    assert by_group["break_glass_assessment"]["records"][0]["accounts"] == ["Break Glass Accounts"]


def test_a_policy_that_excludes_only_some_listed_accounts_passes_and_records_the_gap() -> None:
    snapshot = _snapshot([_policy("p", users={"includeUsers": ["All"], "excludeUsers": [BG1]})], accounts=["bg1@example.com", "bg2@example.com"])

    assert _finding(snapshot) is None
    (policy,) = snapshot["conditional_access_graph"]["records"]
    assert policy["break_glass_excluded_accounts"] == ["bg1@example.com"]
    assert policy["break_glass_not_excluded_accounts"] == ["bg2@example.com"]


# ---- device requirements ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "grant",
    [
        {"operator": "OR", "builtInControls": ["compliantDevice"]},
        {"operator": "OR", "builtInControls": ["domainJoinedDevice"]},
        {"operator": "OR", "builtInControls": ["compliantDevice", "domainJoinedDevice"]},
        {"operator": "AND", "builtInControls": ["compliantDevice", "approvedApplication"]},
    ],
)
def test_a_device_requirement_with_no_mfa_alternative_is_judged_at_medium(grant: dict[str, Any]) -> None:
    finding = _finding(_snapshot([_policy("managed-only", grant=grant)], accounts=["bg1@example.com"]))

    assert finding is not None and _names(finding) == ["Policy managed-only"]
    assert finding["severity"] == "medium", "a device requirement is judged but never broad, even for an operator list"
    assert finding["evidence"]["policies"][0]["enforces"] == "device" and finding["evidence"]["policies"][0]["broad"] is False


def test_a_device_requirement_with_an_mfa_or_other_alternative_is_not_a_device_policy() -> None:
    mfa_alternative = _policy("either", grant={"operator": "OR", "builtInControls": ["compliantDevice", "mfa"]})
    other_alternative = _policy("app-or-device", grant={"operator": "OR", "builtInControls": ["compliantDevice", "approvedApplication"]})

    finding = _finding(_snapshot([mfa_alternative, other_alternative], accounts=["bg1@example.com"]))

    assert finding is not None and _names(finding) == ["Policy either"]
    assert finding["evidence"]["policies"][0]["enforces"] == "mfa" and finding["severity"] == "high"


def test_a_device_policy_that_excludes_the_account_passes() -> None:
    policy = _policy("managed-only", users={"includeUsers": ["All"], "excludeUsers": [BG1]}, grant={"builtInControls": ["compliantDevice"]})

    assert _finding(_snapshot([policy], accounts=["bg1@example.com"])) is None


# ---- severity ----------------------------------------------------------------------------------------


def test_an_operator_list_and_a_policy_that_can_lock_every_administrator_out_is_high() -> None:
    finding = _finding(_snapshot([_policy("mfa-all")], accounts=["bg1@example.com"]))

    assert finding is not None and finding["severity"] == "high"
    assert finding["evidence"]["account_source"] == "operator" and finding["evidence"]["policies"][0]["broad"] is True
    assert finding["evidence"]["accounts"] == ["bg1@example.com"]
    assert "policy requires MFA or a managed device, or blocks sign-ins" in finding["evidence"]["description"]


def test_a_legacy_protocol_block_or_a_narrow_policy_is_medium() -> None:
    legacy = _policy("legacy", grant={"builtInControls": ["block"]}, clientAppTypes=["exchangeActiveSync", "other"])
    named = _policy("named", users={"includeUsers": [BG1]})

    assert _finding(_snapshot([legacy], accounts=["bg1@example.com"]))["severity"] == "medium"  # type: ignore[index]
    assert _finding(_snapshot([named], accounts=["bg1@example.com"]))["severity"] == "medium"  # type: ignore[index]


def test_inferred_accounts_never_rate_above_medium_and_say_how_they_were_found() -> None:
    snapshot = _snapshot([_policy("mfa-all")], admins=[BG1])

    finding = _finding(snapshot)

    assert finding is not None and finding["severity"] == "medium"
    assert finding["evidence"]["account_source"] == "inferred"
    assert "--break-glass-accounts" in finding["evidence"]["account_basis"] and break_glass.ENV_VAR in finding["evidence"]["account_basis"]
    assert finding["evidence"]["accounts"] == ["bg1@example.com"]


def test_inference_uses_global_administrators_and_names_but_not_other_roles() -> None:
    snapshot = _snapshot(
        [_policy("mfa-all")],
        groups=[{"id": BG_GROUP, "displayName": "Break Glass Accounts"}, {"id": SALES, "displayName": "Sales"}],
        admins=[BG1],
    )

    accounts = snapshot["break_glass_assessment"]["records"][0]["accounts"]

    assert sorted(accounts) == ["Break Glass Accounts", "bg1@example.com"]
    # A user whose name says emergency access is inferred even with no role at all.
    named_payload = _payloads([_policy("mfa-all")])
    named_payload["identity"]["users"]["value"].append({"id": "u-ea", "displayName": "Emergency Access 1", "userPrincipalName": "ea1@example.com"})
    named = build_normalized_snapshot(tenant_name="acme", run_id="r", collector_payloads=named_payload)
    assert "ea1@example.com" in named["break_glass_assessment"]["records"][0]["accounts"]


def test_an_inferred_account_excluded_through_the_global_administrator_role_counts() -> None:
    policy = _policy("mfa-all", users={"includeUsers": ["All"], "excludeRoles": [GLOBAL_ADMIN_ROLE]})

    assert _finding(_snapshot([policy], admins=[BG1])) is None


# ---- when nothing can be judged ----------------------------------------------------------------------


def test_no_identifiable_account_raises_nothing_and_is_not_assessed() -> None:
    snapshot = _snapshot([_policy("mfa-all")])

    assert _finding(snapshot) is None
    assert snapshot["break_glass_assessment"]["records"][0]["state"] == "no_accounts_identified"
    assert rule_inputs_gap(RULE, snapshot) == "break_glass_accounts_not_identified"


def test_listed_accounts_that_are_not_in_the_collected_data_are_not_assessed() -> None:
    snapshot = _snapshot([_policy("mfa-all")], accounts=["ghost@example.com"])

    assert _finding(snapshot) is None
    record = snapshot["break_glass_assessment"]["records"][0]
    assert record["state"] == "operator_accounts_unresolved" and record["unresolved_accounts"] == ["ghost@example.com"]
    assert rule_inputs_gap(RULE, snapshot) == "break_glass_accounts_unresolved"


def test_an_object_id_that_was_not_collected_still_matches_the_policy_exclusions() -> None:
    object_id = "0d3e1a7f-0000-4000-8000-0000000000aa"
    excluded = _policy("p", users={"includeUsers": ["All"], "excludeUsers": [object_id.upper()]})

    assert _finding(_snapshot([excluded], accounts=[object_id])) is None
    assert _finding(_snapshot([_policy("p")], accounts=[object_id])) is not None


def test_an_assessed_run_has_no_input_gap_and_no_policies_means_nothing_to_assess() -> None:
    assert rule_inputs_gap(RULE, _snapshot([_policy("mfa-all")], accounts=["bg1@example.com"])) is None
    assert rule_inputs_gap(RULE, _snapshot([])) is None
    assert "break_glass_assessment" not in _snapshot([])


# ---- the finding says which policies, and cites them -------------------------------------------------


def test_the_finding_cites_the_policies_and_the_assessment() -> None:
    finding = _finding(_snapshot([_policy("one"), _policy("two", grant={"builtInControls": ["block"]})], accounts=["bg1@example.com"]))

    assert finding is not None
    assert finding["id"] == "conditional_access:ca_break_glass_exclusion:tenant"
    assert _names(finding) == ["Policy one", "Policy two"]
    cited = {ref["record_key"] for ref in finding["evidence_refs"]}
    assert {"conditional_access_policy:one", "conditional_access_policy:two", "break_glass_assessment:tenant"} <= cited
    assert finding["returned_value"]["policies_without_exclusion"] == 2


# ---- configuring the list ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("a@x.com,b@x.com", ["a@x.com", "b@x.com"]),
        ("a@x.com; b@x.com\nc@x.com", ["a@x.com", "b@x.com", "c@x.com"]),
        (" A@X.COM , a@x.com ", ["A@X.COM"]),
        ("'a@x.com'  # the first account\n\"b@x.com\"", ["a@x.com", "b@x.com"]),
        ("bg1@x.com, Break Glass Accounts", ["bg1@x.com", "Break Glass Accounts"]),
        ("guest_gmail.com#EXT#@t.onmicrosoft.com,bg1@x.com", ["guest_gmail.com#EXT#@t.onmicrosoft.com", "bg1@x.com"]),
        ("bg1@x.com # first\n# whole line\nbg2@x.com #trailing", ["bg1@x.com", "bg2@x.com"]),
        ("", []),
    ],
)
def test_the_account_list_accepts_the_usual_separators(text: str, expected: list[str]) -> None:
    assert break_glass.parse_accounts(text) == expected


def test_the_environment_supplies_the_list_and_an_explicit_list_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(break_glass.ENV_VAR, raising=False)
    assert break_glass.configured_accounts() == []
    monkeypatch.setenv(break_glass.ENV_VAR, "bg1@example.com")
    assert break_glass.configured_accounts() == ["bg1@example.com"]
    assert break_glass.configured_accounts(["bg2@example.com"]) == ["bg2@example.com"]
    snapshot = build_normalized_snapshot(tenant_name="acme", run_id="r", collector_payloads=_payloads([_policy("mfa-all")]))
    assert snapshot["break_glass_assessment"]["records"][0]["account_source"] == "operator"
    assert snapshot["break_glass_assessment"]["records"][0]["accounts"] == ["bg1@example.com"]


def test_a_file_argument_reads_one_account_per_line(tmp_path: Path) -> None:
    path = tmp_path / "accounts.txt"
    path.write_text("# emergency access\nbg1@example.com\nbg2@example.com\n", encoding="utf-8")

    assert break_glass.load_accounts_argument(f"@{path}") == ["bg1@example.com", "bg2@example.com"]
    assert break_glass.load_accounts_argument("bg1@example.com,bg2@example.com") == ["bg1@example.com", "bg2@example.com"]
    assert break_glass.load_accounts_argument(None) == []
    with pytest.raises(OSError):
        break_glass.load_accounts_argument(f"@{tmp_path / 'missing.txt'}")


def test_there_is_no_limit_on_the_number_of_accounts() -> None:
    entries = [f"bg{index}@example.com" for index in range(200)]

    assert break_glass.parse_accounts(",".join(entries)) == entries


def test_an_accounts_file_that_is_not_text_stops_the_run_before_anything_is_written(tmp_path: Path) -> None:
    from types import SimpleNamespace

    from azure_tenant_audit.cli import run_live

    binary = tmp_path / "accounts.bin"
    binary.write_bytes(b"\xff\xfe\x00bg1@example.com")
    with pytest.raises(UnicodeError):
        break_glass.load_accounts_argument(f"@{binary}")
    sample = _sample(tmp_path)
    out = tmp_path / "out"

    offline = audit_main(["--offline", "--sample", str(sample), "--tenant-name", "t", "--out", str(out), "--break-glass-accounts", f"@{binary}"])
    live = run_live(SimpleNamespace(waiver_file=None, break_glass_accounts=f"@{binary}", out=str(out)))
    missing = run_live(SimpleNamespace(waiver_file=None, break_glass_accounts=f"@{tmp_path / 'missing.txt'}", out=str(out)))

    assert (offline, live, missing) == (2, 2, 2)
    assert not out.exists(), "the run stops before any output directory is made"


def _sample(tmp_path: Path) -> Path:
    path = tmp_path / "sample.json"
    path.write_text(json.dumps(_payloads([_policy("mfa-all")])), encoding="utf-8")
    return path


def test_an_offline_run_takes_the_accounts_from_the_option_and_the_finding_reaches_the_bundle(tmp_path: Path) -> None:
    assert run_offline(_sample(tmp_path), tmp_path / "out", "t", "r", break_glass_accounts=["bg1@example.com"]) in {0, 1}

    findings = json.loads((tmp_path / "out" / "t-r" / "findings" / "findings.json").read_text(encoding="utf-8"))
    (finding,) = [item for item in findings if item["rule_id"] == RULE]
    assert finding["severity"] == "high" and finding["evidence"]["account_source"] == "operator"
    assert json.loads((tmp_path / "out" / "t-r" / "validation.json").read_text(encoding="utf-8"))["valid"] is True


def test_the_command_line_option_reaches_the_run_and_a_missing_file_stops_it(tmp_path: Path) -> None:
    sample = _sample(tmp_path)
    base = ["--offline", "--sample", str(sample), "--tenant-name", "t", "--out", str(tmp_path / "out")]

    assert audit_main([*base, "--run-name", "a", "--break-glass-accounts", "bg1@example.com,bg2@example.com"]) in {0, 1}
    findings = json.loads((tmp_path / "out" / "t-a" / "findings" / "findings.json").read_text(encoding="utf-8"))
    (finding,) = [item for item in findings if item["rule_id"] == RULE]
    assert finding["evidence"]["accounts"] == ["bg1@example.com", "bg2@example.com"]
    assert audit_main([*base, "--run-name", "b", "--break-glass-accounts", f"@{tmp_path / 'missing.txt'}"]) == 2
    assert not (tmp_path / "out" / "t-b").exists(), "the run stops before anything is written"


# ---- reach: roles, user actions, group exclusions (CE+ review 2026-10-22) ---------------------------------

HELPDESK_ROLE = "729827e3-9c14-49f7-bb1b-9608f156bbb8"


def _role_payloads(policies: list[dict[str, Any]], *, held: dict[str, list[str]], groups_members: dict[str, list[str]] | None = None) -> dict[str, Any]:
    """Payloads where each listed user holds the given roles; ``groups_members`` are role-assignable groups and their members."""
    payloads = _payloads(policies)
    identity = payloads["identity"]
    identity["roleDefinitions"] = {
        "value": [
            {"id": GLOBAL_ADMIN_ROLE, "displayName": "Global Administrator"},
            {"id": HELPDESK_ROLE, "displayName": "Helpdesk Administrator"},
        ]
    }
    identity["roleAssignments"] = {
        "value": [
            {"id": f"ra-{user}-{role}", "roleDefinitionId": role, "principalId": user}
            for user, roles in held.items()
            for role in roles
        ]
    }
    if groups_members:
        identity["groups"] = {"value": [{"id": group, "displayName": f"Group {group}"} for group in groups_members]}
        identity["roleAssignableGroupMembers"] = {
            "value": [
                {"groupId": group, "displayName": f"Group {group}", "members": [{"id": member} for member in members]}
                for group, members in groups_members.items()
            ],
            "fanout": {"fanout_complete": True},
        }
    return payloads


def _role_snapshot(policies: list[dict[str, Any]], *, held: dict[str, list[str]], accounts: list[str], **kwargs: Any) -> dict[str, Any]:
    return build_normalized_snapshot(
        tenant_name="acme",
        run_id="r",
        collector_payloads=_role_payloads(policies, held=held, **kwargs),
        break_glass_accounts=accounts,
    )


def test_a_policy_for_a_role_none_of_the_accounts_holds_is_not_judged() -> None:
    policy = _policy("helpdesk", users={"includeRoles": [HELPDESK_ROLE]})

    snapshot = _role_snapshot([policy], held={BG1: [GLOBAL_ADMIN_ROLE]}, accounts=["bg1@example.com"])

    assert _finding(snapshot) is None
    assert snapshot["break_glass_assessment"]["records"][0]["policies_in_scope"] == 0


def test_a_policy_for_another_administrator_role_the_account_holds_is_judged_but_never_high() -> None:
    policy = _policy("helpdesk", users={"includeRoles": [HELPDESK_ROLE]})

    finding = _finding(_role_snapshot([policy], held={BG1: [HELPDESK_ROLE]}, accounts=["bg1@example.com"]))

    assert finding is not None
    assert finding["evidence"]["policies"][0]["reach"] == "administrator_roles"
    assert finding["evidence"]["policies"][0]["broad"] is False, "Helpdesk Administrator cannot lock a Global Administrator out"
    assert finding["severity"] == "medium"


def test_a_role_policy_is_judged_at_medium_when_the_roles_of_the_accounts_cannot_be_listed() -> None:
    policy = _policy("helpdesk", users={"includeRoles": [HELPDESK_ROLE]})
    group = [{"id": BG_GROUP, "displayName": "Break Glass Accounts"}]

    snapshot = build_normalized_snapshot(
        tenant_name="acme",
        run_id="r",
        collector_payloads=_payloads([policy], groups=group),
        break_glass_accounts=["Break Glass Accounts"],
    )
    finding = _finding(snapshot)

    assert finding is not None, "a group has unknown roles, so the policy is judged rather than dropped"
    assert finding["evidence"]["policies"][0]["reach"] == "administrator_roles_unverified"
    assert finding["evidence"]["policies"][0]["broad"] is False and finding["severity"] == "medium"


def test_policies_for_a_user_action_or_an_authentication_context_are_not_judged() -> None:
    register = _policy("register-security-info")
    register["conditions"]["applications"] = {"includeUserActions": ["urn:user:registersecurityinfo"]}
    context = _policy("auth-context")
    context["conditions"]["applications"] = {"includeAuthenticationContextClassReferences": ["c1"]}

    snapshot = _snapshot([register, context], accounts=["bg1@example.com"])

    assert _finding(snapshot) is None
    assert snapshot["break_glass_assessment"]["records"][0]["policies_in_scope"] == 0


def test_an_excluded_group_whose_members_the_run_read_covers_the_accounts_in_it() -> None:
    members = {"g-members": [BG1, BG2]}
    policy = _policy("mfa-all", users={"includeUsers": ["All"], "excludeGroups": ["g-members"]})

    covered = _role_snapshot([policy], held={}, accounts=["bg1@example.com", "bg2@example.com"], groups_members=members)
    other_group = _policy("mfa-all", users={"includeUsers": ["All"], "excludeGroups": ["g-other"]})
    not_covered = _role_snapshot([other_group], held={}, accounts=["bg1@example.com"], groups_members=members)

    assert _finding(covered) is None
    assert _finding(not_covered) is not None
