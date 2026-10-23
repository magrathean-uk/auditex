"""Baseline status per rule: a rule passes only when it was actually evaluated."""
from __future__ import annotations

from typing import Any

import pytest

from azure_tenant_audit import baselines
from azure_tenant_audit.baselines import (
    build_baseline_alignment,
    rule_evidence_collector,
    rule_evidence_collectors,
    unmapped_findings,
)

FRAMEWORK = "cis_m365_v7"


def _ledger(*collectors: str, status: str = "complete_exact_scope") -> list[dict[str, str]]:
    return [{"collector": name, "coverage_status": status} for name in collectors]


def _section(*records: dict[str, Any]) -> dict[str, Any]:
    return {"records": list(records)}


def _alignment(rule_id: str, *, findings=None, ledger=None, snapshot=None) -> dict[str, Any]:
    mappings = {rule_id: {FRAMEWORK: ["T.1"]}}
    return build_baseline_alignment(
        findings or [], normalized_snapshot=snapshot, coverage_ledger=ledger, mappings=mappings
    )


def _rule(alignment: dict[str, Any], rule_id: str) -> dict[str, Any]:
    controls = alignment["frameworks"][FRAMEWORK]["controls"]
    (row,) = [status for control in controls for status in control["rule_statuses"] if status["rule_id"] == rule_id]
    return row


def _control_status(alignment: dict[str, Any]) -> str:
    (control,) = alignment["frameworks"][FRAMEWORK]["controls"]
    return control["status"]


def _admin_set(
    state: str = "complete", reasons: tuple[str, ...] = (), licence_state: str = "known", licence_reasons: tuple[str, ...] = ()
) -> dict[str, Any]:
    """A normalized snapshot holding only the effective administrator set summary."""
    summary = {
        "kind": "effective_admin_set_summary",
        "id": "summary",
        "key": "effective_admin_set_summary:summary",
        "state": state,
        "reasons": list(reasons),
        "licence_state": licence_state,
        "licence_reasons": list(licence_reasons),
    }
    return {"effective_admin_set": _section(summary)}


def _signed_in_users() -> dict[str, Any]:
    """A normalized snapshot whose users all have sign-in data (a tenant with Microsoft Entra ID P1)."""
    return {"users": _section({"id": "u1", "enabled": True, "user_type": "member", "signin_data_available": True})}


def _domain(**fields: Any) -> dict[str, Any]:
    return {
        "domain": "contoso.com",
        "resolver_error": None,
        "mta_sts_dns_present": True,
        "mta_sts_policy_fetch_status": "ok",
        "tls_rpt_present": True,
        **fields,
    }


def _signal(name: str, status: str, reason: str = "test") -> dict[str, Any]:
    return {"name": name, "status": status, "reason": reason}


# ---- pass needs evaluation, not just an absent finding -------------------------------------------------


def test_a_rule_with_a_completed_collector_and_no_finding_passes_and_says_it_was_evaluated() -> None:
    alignment = _alignment("identity.stale_enabled_account", ledger=_ledger("identity"), snapshot=_signed_in_users())

    assert _rule(alignment, "identity.stale_enabled_account") == {
        "rule_id": "identity.stale_enabled_account",
        "status": "pass",
        "evaluated": True,
    }
    assert _control_status(alignment) == "pass"


@pytest.mark.parametrize("status", ["blocked_permission", "partial_success", "failed_runtime", "not_run", "not_applicable"])
def test_a_rule_whose_collector_did_not_complete_is_not_assessed(status: str) -> None:
    alignment = _alignment("identity.stale_enabled_account", ledger=_ledger("identity", status=status))

    assert _rule(alignment, "identity.stale_enabled_account") == {
        "rule_id": "identity.stale_enabled_account",
        "status": "not_assessed",
        "evaluated": False,
        "reason": "collector_not_complete:identity",
    }
    assert _control_status(alignment) == "not_assessed"


def test_a_rule_with_no_coverage_ledger_is_not_assessed() -> None:
    assert _rule(_alignment("identity.stale_enabled_account"), "identity.stale_enabled_account")["evaluated"] is False


def test_a_rule_in_an_unknown_namespace_is_not_assessed() -> None:
    row = _rule(_alignment("brand_new.rule", ledger=_ledger("identity")), "brand_new.rule")

    assert row["status"] == "not_assessed" and row["reason"] == "no_collector_mapping"


def test_a_control_passes_only_when_every_mapped_rule_was_evaluated() -> None:
    mappings = {
        "identity.stale_enabled_account": {FRAMEWORK: ["T.1"]},
        "intune.policy_without_assignment": {FRAMEWORK: ["T.1"]},
    }

    alignment = build_baseline_alignment(
        [], normalized_snapshot=_signed_in_users(), coverage_ledger=_ledger("identity"), mappings=mappings
    )

    (control,) = alignment["frameworks"][FRAMEWORK]["controls"]
    assert control["status"] == "not_assessed"
    assert {row["rule_id"]: row["status"] for row in control["rule_statuses"]} == {
        "identity.stale_enabled_account": "pass",
        "intune.policy_without_assignment": "not_assessed",
    }


def test_findings_decide_fail_and_accepted_risk_and_count_as_evaluated() -> None:
    open_alignment = _alignment("identity.stale_enabled_account", findings=[{"id": "f1", "rule_id": "identity.stale_enabled_account", "status": "open"}])
    accepted = _alignment("identity.stale_enabled_account", findings=[{"id": "f1", "rule_id": "identity.stale_enabled_account", "status": "accepted_risk"}])

    assert _rule(open_alignment, "identity.stale_enabled_account") == {"rule_id": "identity.stale_enabled_account", "status": "fail", "evaluated": True}
    assert _rule(accepted, "identity.stale_enabled_account")["status"] == "accepted_risk"


@pytest.mark.parametrize(
    "status,expected",
    [("waived", "accepted_risk"), ("accepted", "accepted_risk"), ("needs-review", "fail"), ("", "fail"), (None, "fail")],
)
def test_finding_statuses_are_read_with_the_accepted_status_helper_and_unknown_means_open(status, expected) -> None:
    findings = [{"id": "f1", "rule_id": "identity.stale_enabled_account", "status": status}]

    alignment = _alignment("identity.stale_enabled_account", findings=findings, ledger=_ledger("identity"))

    assert _rule(alignment, "identity.stale_enabled_account")["status"] == expected


@pytest.mark.parametrize("status", ["resolved", "closed"])
def test_a_resolved_finding_with_its_waiver_neither_fails_nor_counts_as_accepted(status: str) -> None:
    waiver = {"rule_id": "identity.stale_enabled_account", "reason": "approved", "owner": "ops", "expires_on": "2099-01-01"}
    findings = [{"id": "f1", "rule_id": "identity.stale_enabled_account", "status": status, "waiver": waiver}]

    passing = _alignment(
        "identity.stale_enabled_account", findings=findings, ledger=_ledger("identity"), snapshot=_signed_in_users()
    )
    unassessed = _alignment("identity.stale_enabled_account", findings=findings)

    assert _rule(passing, "identity.stale_enabled_account")["status"] == "pass"
    assert _rule(unassessed, "identity.stale_enabled_account")["status"] == "not_assessed"


@pytest.mark.parametrize("status", ["resolved", "closed", "Closed"])
def test_a_resolved_or_closed_finding_without_a_matching_waiver_stays_open_as_in_the_gate(status: str) -> None:
    """The engine never writes these statuses, so one with no waiver behind it is an edit (``auditex.gate``)."""
    unwaived = {"id": "f1", "rule_id": "identity.stale_enabled_account", "status": status}
    other_rule = {**unwaived, "waiver": {"rule_id": "identity.stale_guest", "reason": "x", "owner": "o"}}

    for finding in (unwaived, other_rule):
        alignment = _alignment(
            "identity.stale_enabled_account", findings=[finding], ledger=_ledger("identity"), snapshot=_signed_in_users()
        )
        assert _rule(alignment, "identity.stale_enabled_account")["status"] == "fail"
    assert unmapped_findings([{"id": "x", "status": status}])["open_count"] == 1


# ---- detection rules read their own collector ---------------------------------------------------------


def test_a_detection_rule_needs_the_collector_that_actually_supplies_its_signal() -> None:
    rule = "detection.no_risk_based_policies"
    snapshot = {"detection_signal_objects": _section(_signal("risk_based_conditional_access", "on"))}

    only_exchange = _alignment(rule, ledger=_ledger("exchange_policy"), snapshot=snapshot)
    with_ca = _alignment(rule, ledger=_ledger("conditional_access"), snapshot=snapshot)

    assert _rule(only_exchange, rule)["status"] == "not_assessed"
    assert _rule(only_exchange, rule)["reason"] == "collector_not_complete:conditional_access"
    assert _rule(with_ca, rule)["status"] == "pass"


def test_the_sign_in_log_rule_needs_the_security_collector() -> None:
    rule = "detection.signin_logs_unavailable"
    snapshot = {"detection_signal_objects": _section(_signal("signin_logs", "on"))}

    assert _rule(_alignment(rule, ledger=_ledger("exchange_policy"), snapshot=snapshot), rule)["status"] == "not_assessed"
    assert _rule(_alignment(rule, ledger=_ledger("security"), snapshot=snapshot), rule)["status"] == "pass"


def test_a_detection_rule_is_not_assessed_while_its_signal_is_unknown() -> None:
    rule = "detection.unified_audit_log_disabled"
    snapshot = {"detection_signal_objects": _section(_signal("unified_audit_log", "unknown", "blocked_by_permissions"))}

    row = _rule(_alignment(rule, ledger=_ledger("exchange_policy"), snapshot=snapshot), rule)

    assert row["status"] == "not_assessed"
    assert row["reason"] == "signal_unknown:blocked_by_permissions"


def test_a_detection_rule_with_no_signal_record_or_no_snapshot_is_not_assessed() -> None:
    rule = "detection.mailbox_audit_disabled"

    missing = _alignment(rule, ledger=_ledger("exchange_policy"), snapshot={"detection_signal_objects": _section()})
    no_snapshot = _alignment(rule, ledger=_ledger("exchange_policy"))

    assert _rule(missing, rule)["reason"] == "signal_not_collected"
    assert _rule(no_snapshot, rule)["reason"] == "inputs_not_available"


def test_a_detection_rule_with_an_off_signal_and_finding_fails() -> None:
    rule = "detection.no_alert_policies"
    findings = [{"id": "detection_coverage:alert_policies", "rule_id": rule, "status": "open"}]

    alignment = _alignment(rule, findings=findings, ledger=_ledger("exchange_policy"))

    assert _rule(alignment, rule)["status"] == "fail"


def test_detection_rule_signals_match_the_rules_the_findings_engine_emits() -> None:
    from azure_tenant_audit.findings import _DETECTION_SIGNAL_RULES

    engine = {spec["rule_id"]: name for name, spec in _DETECTION_SIGNAL_RULES.items()}

    assert baselines._DETECTION_RULE_SIGNALS == engine


def test_detection_rule_collectors_match_the_collector_that_feeds_each_signal() -> None:
    from azure_tenant_audit.detection_coverage import _SIGNAL_BUILDERS

    for rule_id, signal in baselines._DETECTION_RULE_SIGNALS.items():
        assert rule_evidence_collectors(rule_id) == (_SIGNAL_BUILDERS[signal][0],), rule_id


def test_every_shipped_detection_rule_has_its_own_collector_entry() -> None:
    mapped = {rule for rule in baselines._shipped_control_mappings() if rule.startswith("detection.")}

    assert mapped <= set(baselines._RULE_COLLECTORS)
    assert "detection" not in baselines._NAMESPACE_COLLECTORS
    assert rule_evidence_collectors("detection.not_a_shipped_rule") == ()


def test_the_attack_path_mfa_rule_needs_identity_and_auth_methods() -> None:
    rule = "attack_path.no_mfa_to_tier0"

    assert rule_evidence_collectors(rule) == ("identity", "auth_methods")
    assert _rule(_alignment(rule, ledger=_ledger("identity")), rule)["reason"] == "collector_not_complete:auth_methods"
    assert _rule(_alignment(rule, ledger=_ledger("identity", "auth_methods"), snapshot=_admin_set()), rule)["status"] == "pass"


def test_rule_evidence_collector_keeps_returning_the_first_collector() -> None:
    assert rule_evidence_collector("identity.user_mfa_not_registered") == "auth_methods"
    assert rule_evidence_collector("attack_path.no_mfa_to_tier0") == "identity"
    assert rule_evidence_collector("dns_posture.spf_missing") == "dns_posture"
    assert rule_evidence_collector("unknown.rule") is None


# ---- DNS and public-footprint rules need their inputs --------------------------------------------------


def test_the_mta_sts_policy_rule_is_not_assessed_when_the_policy_was_never_fetched() -> None:
    rule = "dns_posture.mta_sts_policy_invalid"
    snapshot = {"dns_posture_objects": _section(_domain(mta_sts_policy_fetch_status="skipped"))}

    row = _rule(_alignment(rule, ledger=_ledger("dns_posture"), snapshot=snapshot), rule)

    assert row["status"] == "not_assessed"
    assert row["reason"] == "mta_sts_policy_not_fetched"


def test_the_mta_sts_policy_rule_passes_when_the_policy_was_fetched_or_none_is_published() -> None:
    rule = "dns_posture.mta_sts_policy_invalid"
    fetched = {"dns_posture_objects": _section(_domain())}
    unpublished = {"dns_posture_objects": _section(_domain(mta_sts_dns_present=False, mta_sts_policy_fetch_status=None))}

    assert _rule(_alignment(rule, ledger=_ledger("dns_posture"), snapshot=fetched), rule)["status"] == "pass"
    assert _rule(_alignment(rule, ledger=_ledger("dns_posture"), snapshot=unpublished), rule)["status"] == "pass"


def test_one_domain_with_an_unfetched_policy_keeps_the_rule_unassessed() -> None:
    rule = "dns_posture.mta_sts_testing_mode"
    snapshot = {"dns_posture_objects": _section(_domain(), _domain(domain="b.com", mta_sts_policy_fetch_status=None))}

    assert _rule(_alignment(rule, ledger=_ledger("dns_posture"), snapshot=snapshot), rule)["status"] == "not_assessed"


def test_dns_rules_are_not_assessed_after_a_resolver_error_or_without_domains() -> None:
    rule = "dns_posture.dmarc_missing"
    errored = {"dns_posture_objects": _section(_domain(), _domain(domain="b.com", resolver_error="SERVFAIL"))}
    empty = {"dns_posture_objects": _section()}

    assert _rule(_alignment(rule, ledger=_ledger("dns_posture"), snapshot=errored), rule)["reason"] == "resolver_error"
    assert _rule(_alignment(rule, ledger=_ledger("dns_posture"), snapshot=empty), rule)["reason"] == "no_domain_records"
    assert _rule(_alignment(rule, ledger=_ledger("dns_posture")), rule)["reason"] == "inputs_not_available"


def test_dns_rules_pass_when_every_domain_was_resolved() -> None:
    rule = "dns_posture.dmarc_missing"
    snapshot = {"dns_posture_objects": _section(_domain(), _domain(domain="b.com"))}

    assert _rule(_alignment(rule, ledger=_ledger("dns_posture"), snapshot=snapshot), rule)["status"] == "pass"


def test_a_dns_finding_still_fails_the_rule_when_another_domain_errored() -> None:
    rule = "dns_posture.dmarc_missing"
    # a.com published no DMARC record; b.com could not be resolved. The finding on a.com is evidence and still fails.
    snapshot = {"dns_posture_objects": _section(_domain(dmarc_present=False), _domain(domain="b.com", resolver_error="SERVFAIL"))}
    findings = [{"id": "dns_posture:a.com:dmarc_missing", "rule_id": rule, "status": "open"}]

    assert _rule(_alignment(rule, findings=findings, ledger=_ledger("dns_posture"), snapshot=snapshot), rule)["status"] == "fail"


def test_the_tls_rpt_rule_is_not_assessed_for_bundles_that_never_collected_tls_rpt() -> None:
    rule = "dns_posture.tls_rpt_missing"
    snapshot = {"dns_posture_objects": _section(_domain(tls_rpt_present=None))}

    assert _rule(_alignment(rule, ledger=_ledger("dns_posture"), snapshot=snapshot), rule)["reason"] == "tls_rpt_not_collected"


def test_the_public_footprint_rule_needs_footprint_records() -> None:
    rule = "exposure.federated_domain_metadata_public"
    present = {"public_footprint_objects": _section({"domain": "contoso.com", "authentication_type": "Managed"})}
    absent = {"public_footprint_objects": _section()}

    assert _rule(_alignment(rule, ledger=_ledger("dns_posture"), snapshot=present), rule)["status"] == "pass"
    assert _rule(_alignment(rule, ledger=_ledger("dns_posture"), snapshot=absent), rule)["reason"] == "public_footprint_not_collected"
    assert _rule(_alignment(rule, ledger=_ledger("dns_posture")), rule)["reason"] == "inputs_not_available"


# ---- findings without a rule_id stay visible ----------------------------------------------------------


def test_findings_without_a_rule_id_are_counted_in_the_unmapped_bucket() -> None:
    findings = [
        {"id": "ca:1", "status": "open", "collector": "conditional_access"},
        {"id": "ca:2", "rule_id": "", "status": "open", "collector": "conditional_access"},
        {"id": "fwd:1", "rule_id": None, "status": "accepted_risk", "collector": "mailbox_forwarding"},
        {"id": "old:1", "status": "resolved", "collector": "teams", "waiver": {"finding_id": "old:1", "reason": "x", "owner": "o"}},
        {"id": "mapped:1", "rule_id": "identity.stale_enabled_account", "status": "open", "collector": "identity"},
    ]

    result = unmapped_findings(findings)

    assert result == {
        "count": 4,
        "open_count": 2,
        "accepted_count": 1,
        "collectors": [
            {"collector": "conditional_access", "count": 2},
            {"collector": "mailbox_forwarding", "count": 1},
            {"collector": "teams", "count": 1},
        ],
        "finding_ids": ["ca:1", "ca:2", "fwd:1", "old:1"],
    }


def test_the_unmapped_bucket_is_empty_not_missing_when_every_finding_has_a_rule() -> None:
    assert unmapped_findings([]) == {"count": 0, "open_count": 0, "accepted_count": 0, "collectors": [], "finding_ids": []}
    assert unmapped_findings([{"id": "f", "rule_id": "r"}])["count"] == 0


def test_the_unmapped_bucket_caps_the_listed_ids() -> None:
    findings = [{"id": f"f{index:03d}", "status": "open"} for index in range(40)]

    result = unmapped_findings(findings)

    assert result["count"] == 40 and len(result["finding_ids"]) == 20


def test_an_open_finding_without_a_rule_id_is_visible_next_to_a_passing_control() -> None:
    # Mailbox forwarding findings carry no rule_id, so the control mapped to the forwarding rules still
    # reads pass; the unmapped bucket is where that open finding is counted.
    rule = "mailbox_forwarding.external_inbox_rule"
    findings = [{"id": "mailbox_forwarding:smtp", "status": "open", "severity": "high", "collector": "mailbox_forwarding"}]

    alignment = _alignment(rule, findings=findings, ledger=_ledger("mailbox_forwarding"))

    assert _control_status(alignment) == "pass"
    assert alignment["unmapped_findings"]["open_count"] == 1
    assert alignment["unmapped_findings"]["finding_ids"] == ["mailbox_forwarding:smtp"]
    controls = alignment["frameworks"][FRAMEWORK]["controls"]
    assert all("mailbox_forwarding:smtp" not in control["finding_ids"] for control in controls)


def test_the_report_pack_carries_the_unmapped_bucket() -> None:
    from azure_tenant_audit.findings import build_report_pack

    findings = [
        {"id": "ca:1", "title": "Policy gap", "severity": "high", "status": "open", "collector": "conditional_access"},
    ]

    pack = build_report_pack(tenant_name="acme", overall_status="ok", findings=findings, evidence_paths=[])

    assert pack["baseline_alignment"]["unmapped_findings"]["open_count"] == 1
    assert pack["baseline_alignment"]["schema_version"] == baselines.BASELINE_ALIGNMENT_SCHEMA_VERSION


def test_the_unmapped_bucket_never_uses_collector_names_as_object_keys() -> None:
    # Collector names such as app_credentials would trip the bundle's sensitive-key scan as keys.
    from azure_tenant_audit.contracts import _walk_sensitive_ai_safe
    from azure_tenant_audit.findings import build_report_pack

    findings = [{"id": "x:1", "title": "No rule", "severity": "high", "status": "open", "collector": "app_credentials"}]
    pack = build_report_pack(tenant_name="acme", overall_status="ok", findings=findings, evidence_paths=[])

    hits: list[dict[str, Any]] = []
    _walk_sensitive_ai_safe(pack["baseline_alignment"], "", hits)

    assert hits == []
    assert pack["baseline_alignment"]["unmapped_findings"]["collectors"] == [{"collector": "app_credentials", "count": 1}]


# ---- identity control verdict rules need a known verdict ---------------------------------------------

_VERDICT_RULES = [
    # rule, controls whose verdict must be known, collector that feeds the verdict
    ("ca.mfa_not_enforced", ("effective_mfa",), "conditional_access"),
    ("ca.admin_mfa_not_enforced", ("administrator_mfa",), "conditional_access"),
    ("ca.admin_phishing_resistant_mfa_not_enforced", ("administrator_mfa",), "conditional_access"),
    ("ca.legacy_auth_not_blocked", ("legacy_authentication_block",), "conditional_access"),
    ("ca.enforcement_unverified", ("effective_mfa", "administrator_mfa", "legacy_authentication_block"), "conditional_access"),
    ("consent_policy.user_consent_unrestricted", ("user_consent",), "consent_policy"),
    ("consent_policy.user_consent_limited", ("user_consent",), "consent_policy"),
    ("consent_policy.user_consent_unverified", ("user_consent",), "consent_policy"),
]
_KNOWN_VERDICT = {
    "effective_mfa": "enforced",
    "administrator_mfa": "enforced",
    "legacy_authentication_block": "blocked",
    "user_consent": "restricted",
}


def _verdict_snapshot(**verdicts: str) -> dict[str, Any]:
    """A snapshot whose identity_control_verdicts section holds one record per given control."""
    return {
        "identity_control_verdicts": _section(
            *(
                {
                    "kind": "identity_control_verdict",
                    "key": f"identity_control_verdict:{control}",
                    "id": control,
                    "control": control,
                    "verdict": verdict,
                }
                for control, verdict in verdicts.items()
            )
        )
    }


def _known(*controls: str) -> dict[str, str]:
    return {control: _KNOWN_VERDICT[control] for control in controls}


@pytest.mark.parametrize(("rule", "controls", "collector"), _VERDICT_RULES)
def test_a_verdict_rule_is_evaluated_when_every_verdict_it_reads_is_known(rule, controls, collector) -> None:
    snapshot = _verdict_snapshot(**_known(*controls))

    alignment = _alignment(rule, ledger=_ledger(collector), snapshot=snapshot)

    assert _rule(alignment, rule) == {"rule_id": rule, "status": "pass", "evaluated": True}
    assert _control_status(alignment) == "pass"


@pytest.mark.parametrize(("rule", "controls", "collector"), _VERDICT_RULES)
def test_a_verdict_rule_is_evaluated_for_a_negative_verdict_too(rule, controls, collector) -> None:
    negative = {
        "effective_mfa": "not_enforced",
        "administrator_mfa": "not_enforced",
        "legacy_authentication_block": "not_blocked",
        "user_consent": "unrestricted",
    }
    snapshot = _verdict_snapshot(**{control: negative[control] for control in controls})

    assert _rule(_alignment(rule, ledger=_ledger(collector), snapshot=snapshot), rule)["evaluated"] is True


@pytest.mark.parametrize(
    ("rule", "controls", "collector", "unknown_control"),
    [(rule, controls, collector, control) for rule, controls, collector in _VERDICT_RULES for control in controls],
)
def test_an_unknown_verdict_leaves_the_rule_not_assessed(rule, controls, collector, unknown_control) -> None:
    verdicts = _known(*controls) | {unknown_control: "unknown"}

    row = _rule(_alignment(rule, ledger=_ledger(collector), snapshot=_verdict_snapshot(**verdicts)), rule)

    assert row == {
        "rule_id": rule,
        "status": "not_assessed",
        "evaluated": False,
        "reason": f"verdict_unknown:{unknown_control}",
    }


@pytest.mark.parametrize(("rule", "controls", "collector"), _VERDICT_RULES)
def test_a_missing_verdict_record_leaves_the_rule_not_assessed(rule, controls, collector) -> None:
    verdicts = _known(*controls[:-1])  # the last control the rule reads has no record

    row = _rule(_alignment(rule, ledger=_ledger(collector), snapshot=_verdict_snapshot(**verdicts)), rule)

    assert row["status"] == "not_assessed"
    assert row["reason"] == f"verdict_not_collected:{controls[-1]}"


@pytest.mark.parametrize(("rule", "controls", "collector"), _VERDICT_RULES)
def test_a_verdict_rule_without_a_snapshot_is_not_assessed(rule, controls, collector) -> None:
    row = _rule(_alignment(rule, ledger=_ledger(collector)), rule)

    assert row["status"] == "not_assessed" and row["reason"] == "inputs_not_available"


@pytest.mark.parametrize(("rule", "controls", "collector"), _VERDICT_RULES)
def test_a_verdict_rule_needs_its_collector_to_complete_first(rule, controls, collector) -> None:
    snapshot = _verdict_snapshot(**_known(*controls))

    row = _rule(_alignment(rule, ledger=_ledger("identity"), snapshot=snapshot), rule)

    assert row["status"] == "not_assessed" and row["reason"] == f"collector_not_complete:{collector}"
    assert rule_evidence_collectors(rule) == (collector,)


def test_the_unrestricted_consent_rule_no_longer_passes_while_the_verdict_is_unknown() -> None:
    rule = "consent_policy.user_consent_unrestricted"
    snapshot = _verdict_snapshot(user_consent="unknown")

    row = _rule(_alignment(rule, ledger=_ledger("consent_policy"), snapshot=snapshot), rule)

    assert row["status"] == "not_assessed"
    # The unverified rule is what the unknown verdict raises, so it fails instead of passing.
    findings = [{"id": "consent_policy:user_consent:unverified", "rule_id": "consent_policy.user_consent_unverified", "status": "open"}]
    unverified = _alignment(
        "consent_policy.user_consent_unverified", findings=findings, ledger=_ledger("consent_policy"), snapshot=snapshot
    )
    assert _rule(unverified, "consent_policy.user_consent_unverified")["status"] == "fail"


def test_a_negative_verdict_finding_fails_its_rule_and_an_accepted_one_is_accepted() -> None:
    rule = "ca.mfa_not_enforced"
    snapshot = _verdict_snapshot(effective_mfa="not_enforced")
    finding = {"id": "conditional_access:mfa_not_enforced", "rule_id": rule, "status": "open"}

    failed = _alignment(rule, findings=[finding], ledger=_ledger("conditional_access"), snapshot=snapshot)
    accepted = _alignment(rule, findings=[{**finding, "status": "accepted_risk"}], ledger=_ledger("conditional_access"), snapshot=snapshot)

    assert _rule(failed, rule)["status"] == "fail"
    assert _rule(accepted, rule)["status"] == "accepted_risk"


def test_the_enforcement_unverified_rule_fails_when_either_verdict_is_unknown_and_raised() -> None:
    rule = "ca.enforcement_unverified"
    snapshot = _verdict_snapshot(effective_mfa="enforced", legacy_authentication_block="unknown")
    findings = [{"id": "conditional_access:legacy_authentication_block:unverified", "rule_id": rule, "status": "open"}]

    alignment = _alignment(rule, findings=findings, ledger=_ledger("conditional_access"), snapshot=snapshot)

    assert _rule(alignment, rule)["status"] == "fail"


def test_verdict_rule_controls_match_the_rules_the_findings_engine_raises() -> None:
    from azure_tenant_audit.findings import _UNVERIFIED_CONTROL_RULES

    for control, spec in _UNVERIFIED_CONTROL_RULES.items():
        assert control in baselines._RULE_VERDICT_CONTROLS[spec["rule_id"]], control
    negative_rules = {
        "ca.mfa_not_enforced",
        "ca.admin_mfa_not_enforced",
        "ca.admin_phishing_resistant_mfa_not_enforced",
        "ca.admin_mfa_role_set_incomplete",
        "ca.legacy_auth_not_blocked",
        "consent_policy.user_consent_unrestricted",
        "consent_policy.user_consent_limited",
    }
    assert set(baselines._RULE_VERDICT_CONTROLS) == negative_rules | {spec["rule_id"] for spec in _UNVERIFIED_CONTROL_RULES.values()}


def test_verdict_rules_read_real_normalized_verdict_records() -> None:
    from azure_tenant_audit.normalize import build_normalized_snapshot

    def snapshot(assigned: list[str] | None) -> dict[str, Any]:
        defaults = {} if assigned is None else {"permissionGrantPoliciesAssigned": assigned}
        return build_normalized_snapshot(
            tenant_name="acme",
            run_id="run-1",
            collector_payloads={
                "consent_policy": {
                    "authorizationPolicy": {"id": "authorizationPolicy", "defaultUserRolePermissions": defaults},
                    "permissionGrantPolicies": {"value": []},
                }
            },
        )

    rule = "consent_policy.user_consent_unrestricted"
    unknown = snapshot(None)
    restricted = snapshot([])

    assert unknown["identity_control_verdicts"]["records"][0]["verdict"] == "unknown"
    assert _rule(_alignment(rule, ledger=_ledger("consent_policy"), snapshot=unknown), rule)["reason"] == "verdict_unknown:user_consent"
    assert restricted["identity_control_verdicts"]["records"][0]["verdict"] == "restricted"
    assert _rule(_alignment(rule, ledger=_ledger("consent_policy"), snapshot=restricted), rule)["status"] == "pass"


# ---- MFA registration rules need role assignments as well as registration ------------------------------


def test_the_global_admin_mfa_rule_needs_registration_and_role_assignments() -> None:
    rule = "identity.global_admin_mfa_not_registered"
    assert rule_evidence_collectors(rule) == ("auth_methods", "identity")

    registration_only = _rule(_alignment(rule, ledger=_ledger("auth_methods")), rule)
    roles_only = _rule(_alignment(rule, ledger=_ledger("identity")), rule)
    both = _alignment(rule, ledger=_ledger("auth_methods", "identity"), snapshot=_admin_set())

    assert registration_only["reason"] == "collector_not_complete:identity"
    assert roles_only["reason"] == "collector_not_complete:auth_methods"
    assert _rule(both, rule) == {"rule_id": rule, "status": "pass", "evaluated": True}


PRIVILEGED = "identity.privileged_mfa_not_registered"


def test_the_privileged_mfa_rule_also_needs_identity_governance_for_pim_eligible_admins() -> None:
    assert rule_evidence_collectors(PRIVILEGED) == ("auth_methods", "identity", "identity_governance")

    without_governance = _rule(_alignment(PRIVILEGED, ledger=_ledger("auth_methods", "identity")), PRIVILEGED)
    complete = _alignment(PRIVILEGED, ledger=_ledger("auth_methods", "identity", "identity_governance"), snapshot=_admin_set())

    assert without_governance == {
        "rule_id": PRIVILEGED,
        "status": "not_assessed",
        "evaluated": False,
        "reason": "collector_not_complete:identity_governance",
    }
    assert _rule(complete, PRIVILEGED) == {"rule_id": PRIVILEGED, "status": "pass", "evaluated": True}


def test_the_privileged_mfa_rule_names_every_missing_collector() -> None:
    row = _rule(_alignment(PRIVILEGED, ledger=_ledger("auth_methods")), PRIVILEGED)

    assert row["reason"] == "collector_not_complete:identity,identity_governance"


def test_identity_governance_may_be_not_applicable_but_not_blocked_partial_or_failed() -> None:
    base = _ledger("auth_methods", "identity")

    not_applicable = _alignment(
        PRIVILEGED, ledger=[*base, *_ledger("identity_governance", status="not_applicable")], snapshot=_admin_set()
    )
    assert _rule(not_applicable, PRIVILEGED)["status"] == "pass"
    for status in ("blocked_permission", "partial_success", "failed_runtime", "not_run"):
        gap = _alignment(PRIVILEGED, ledger=[*base, *_ledger("identity_governance", status=status)])
        assert _rule(gap, PRIVILEGED)["reason"] == "collector_not_complete:identity_governance", status


def test_not_applicable_never_satisfies_a_collector_that_is_not_tolerant() -> None:
    row = _rule(_alignment("identity.user_mfa_not_registered", ledger=_ledger("auth_methods", status="not_applicable")), "identity.user_mfa_not_registered")

    assert row["reason"] == "collector_not_complete:auth_methods"


def test_unmet_rule_collectors_reports_what_is_missing() -> None:
    from azure_tenant_audit.baselines import unmet_rule_collectors

    assert unmet_rule_collectors(PRIVILEGED, complete={"auth_methods", "identity"}) == ["identity_governance"]
    assert unmet_rule_collectors(PRIVILEGED, complete={"auth_methods", "identity"}, not_applicable={"identity_governance"}) == []
    assert unmet_rule_collectors("identity.user_mfa_not_registered", complete=set(), not_applicable={"auth_methods"}) == ["auth_methods"]
    assert unmet_rule_collectors("brand_new.rule", complete=set()) == []


def test_a_privileged_mfa_finding_fails_its_rule() -> None:
    rule = "identity.privileged_mfa_not_registered"
    findings = [{"id": "identity:privileged_mfa_not_registered:u1", "rule_id": rule, "status": "open"}]

    assert _rule(_alignment(rule, findings=findings), rule)["status"] == "fail"


def test_the_plain_user_mfa_rule_still_needs_only_registration() -> None:
    assert rule_evidence_collectors("identity.user_mfa_not_registered") == ("auth_methods",)


# ---- rules added for previously rule-less findings: each namespace maps to the collector that feeds it ----

_FORMERLY_RULELESS_COLLECTORS = [
    # rule, collector that supplies the evidence it reads and the collector coverage ledger name it needs
    ("onedrive.external_sharing_enabled", "onedrive_posture"),
    ("teams.external_federation_open", "teams_policy"),
    ("identity_governance.standing_privilege_only", "identity_governance"),
    ("intune_depth.policies_without_assignments", "intune_depth"),
    ("ca.policy_report_only", "conditional_access"),
    ("ca.break_glass_exclusion_missing", "conditional_access"),
    ("sharepoint.site_orphaned", "sharepoint_access"),
    ("sharepoint.site_weak_ownership", "sharepoint_access"),
    ("exchange.mailbox_forwarding_configured", "exchange_policy"),
]


@pytest.mark.parametrize(("rule", "collector"), _FORMERLY_RULELESS_COLLECTORS)
def test_a_formerly_ruleless_rule_maps_to_a_real_collector(rule: str, collector: str) -> None:
    import json
    from pathlib import Path

    definitions = json.loads(Path("configs/collector-definitions.json").read_text(encoding="utf-8"))["collectors"]

    assert rule_evidence_collectors(rule) == (collector,)
    assert collector in definitions


def _read_in_full(*sources: str) -> dict[str, Any]:
    return {"normalization_coverage": {"records": [
        {"source": source, "collection_status": "collected", "complete": True, "record_count": 3} for source in sources
    ]}}


# Rules that read their own inputs from the normalized snapshot, so a clean run needs those inputs too.
_CLEAN_RUN_SNAPSHOTS = {
    "intune_depth.policies_without_assignments": _read_in_full(
        "intune_depth.deviceConfigurations", "intune_depth.deviceConfigurationAssignments"
    ),
    "onedrive.external_sharing_enabled": {
        "sharepoint_tenant_settings": {
            "records": [{"collector": "onedrive_posture", "read_state": "collected", "sharing_capability": "disabled"}]
        }
    },
    "teams.external_federation_open": {
        "teams_policy_objects": {
            "records": [{"source_name": "tenantFederationConfiguration", "allow_federated_users": False}]
        }
    },
    "ca.break_glass_exclusion_missing": {"break_glass_assessment": {"records": [{"state": "assessed"}]}},
}


@pytest.mark.parametrize(("rule", "collector"), _FORMERLY_RULELESS_COLLECTORS)
def test_a_formerly_ruleless_rule_is_evaluated_on_a_clean_run(rule: str, collector: str) -> None:
    alignment = _alignment(rule, ledger=_ledger(collector), snapshot=_CLEAN_RUN_SNAPSHOTS.get(rule))

    assert _rule(alignment, rule) == {"rule_id": rule, "status": "pass", "evaluated": True}
    assert _control_status(alignment) == "pass"


@pytest.mark.parametrize("status", ["blocked_permission", "partial_success", "not_applicable"])
@pytest.mark.parametrize(("rule", "collector"), _FORMERLY_RULELESS_COLLECTORS)
def test_a_formerly_ruleless_rule_is_not_assessed_when_its_collector_did_not_complete(rule: str, collector: str, status: str) -> None:
    alignment = _alignment(rule, ledger=_ledger(collector, status=status))

    assert _rule(alignment, rule) == {
        "rule_id": rule,
        "status": "not_assessed",
        "evaluated": False,
        "reason": f"collector_not_complete:{collector}",
    }
    assert _control_status(alignment) == "not_assessed"


@pytest.mark.parametrize(("rule", "collector"), _FORMERLY_RULELESS_COLLECTORS)
def test_a_formerly_ruleless_rule_is_not_assessed_when_its_collector_never_ran(rule: str, collector: str) -> None:
    other = "identity" if collector != "identity" else "security"

    assert _rule(_alignment(rule, ledger=_ledger(other)), rule)["reason"] == f"collector_not_complete:{collector}"
    assert _rule(_alignment(rule), rule)["evaluated"] is False


@pytest.mark.parametrize(("rule", "collector"), _FORMERLY_RULELESS_COLLECTORS)
def test_a_formerly_ruleless_rule_with_an_open_finding_fails_and_an_accepted_one_is_accepted(rule: str, collector: str) -> None:
    open_finding = [{"id": f"{collector}:1", "rule_id": rule, "status": "open"}]
    accepted = [{"id": f"{collector}:1", "rule_id": rule, "status": "accepted_risk"}]

    assert _rule(_alignment(rule, findings=open_finding, ledger=_ledger(collector)), rule)["status"] == "fail"
    assert _rule(_alignment(rule, findings=accepted, ledger=_ledger(collector)), rule)["status"] == "accepted_risk"


def test_each_formerly_ruleless_builder_reports_under_the_collector_its_namespace_maps_to() -> None:
    from azure_tenant_audit.findings import build_findings

    snapshot = {
        "ca_findings": {"records": [
            {"id": "p1", "finding_type": "ca_reporting_only", "policy_id": "p1", "severity": "medium"},
            {"id": "p2:x", "finding_type": "ca_break_glass_exclusion", "policy_id": "p2", "severity": "high"},
        ]},
        "sharepoint_site_posture_objects": {"records": [
            {"id": "s1", "site_name": "Orphan", "ownership_state": "orphaned"},
            {"id": "s2", "site_name": "Weak", "ownership_state": "weak"},
        ]},
        "onedrive_posture_objects": {"records": [{"id": "o1", "site_kind": "personal", "sharing_capability": "ExternalUserSharingOnly"}]},
        "exchange_policy_objects": {"records": [
            {"id": "m1", "source_name": "mailboxForwarding", "forwarding_smtp_address": "x@example.net", "display_name": "Box"}
        ]},
        "teams_policy_objects": {"records": [
            {"id": "t1", "source_name": "tenantFederationConfiguration", "allow_federated_users": True, "allowed_domains_state": "open"}
        ]},
        "governance_objects": {"records": [{"kind": "role_assignment_schedule"}]},
        "intune_assignment_objects": {"records": []},
        **_read_in_full(
            "identity_governance.roleAssignmentSchedules",
            "identity_governance.roleEligibilitySchedules",
            "intune_depth.deviceConfigurations",
            "intune_depth.deviceConfigurationAssignments",
        ),
    }

    emitted = {finding["rule_id"]: finding["collector"] for finding in build_findings([], normalized_snapshot=snapshot)}

    # The OneDrive site's copied capability stands in for the tenant setting in a bundle that has no
    # sharepoint_tenant_settings section, so the SharePoint capability rule reads it as well (new guests: low).
    assert emitted == {**dict(_FORMERLY_RULELESS_COLLECTORS), "sharepoint.external_sharing_broad": "sharepoint_access"}
    for rule, collector in emitted.items():
        assert rule_evidence_collector(rule) == collector, rule


def test_every_shipped_rule_with_a_mapping_has_an_evidence_collector() -> None:
    # Collector and coverage diagnostics describe the run itself and have no evidence collector.
    missing = sorted(
        rule
        for rule in baselines._shipped_control_mappings()
        if rule.split(".", 1)[0] not in {"collector", "coverage"} and not rule_evidence_collectors(rule)
    )

    assert missing == [], f"add these rules' namespaces to _NAMESPACE_COLLECTORS or list them in _RULE_COLLECTORS: {missing}"
