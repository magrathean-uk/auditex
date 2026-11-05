"""Performance and adversarial-input sweep of the stage 1, 3, 4, 6 and 8 value rules (synthetic, offline only).

Valid but large evidence (5,000 to 10,000 entries), adversarial shapes that drove a quadratic path, deeply nested values and
megabyte strings must finish within a generous wall-clock bound and without an exception. The four rewritten paths keep their
old implementation here as a test-local reference and are compared on small random inputs.
"""
from __future__ import annotations

import inspect
import json
from pathlib import Path
import random
import re
import time

import pytest

from azure_tenant_audit.value_rules import assess
from azure_tenant_audit.value_rules import defender_resolution, dns, power_platform
from azure_tenant_audit.value_rules.catalogue import catalogue, row_for
from azure_tenant_audit.value_rules.defender_spam import KINDS as SPAM_KINDS

ROOT = Path(__file__).resolve().parents[1]
HELD = json.loads((ROOT / "tests/fixtures/value-rules/held-rows-s4.json").read_text())
N = 6000
BOUND = 5.0
MB = 1024 * 1024
ENV = {"M365Environment": "commercial"}
IN_SCOPE_KINDS = {"any_flag", "two_flag", "flag_and_empty_list", "list_count", "bool_list", "substring_pair",
                  "any_true_is_met", "global_record", "setting_cascade", "list_exists", "parser", "safelinks_resolution",
                  "pp_flag", "pp_isolation", "pp_dlp", "pp_constant", "sp_scalar", "sp_gated", "aad_3_4"}


def _in_scope(row):
    return row["kind"] in IN_SCOPE_KINDS or row["kind"].startswith("powerbi.")


POLICIES = {pid: row for pid, row in catalogue()["policies"].items() if _in_scope(row)}


def _timed(call):
    start = time.perf_counter()
    result = call()
    elapsed = time.perf_counter() - start
    assert elapsed < BOUND, f"took {elapsed:.2f}s"
    return result


def _deep_list(depth=1000):
    value = []
    for _ in range(depth):
        value = [value]
    return value


def _deep_dict(depth=1000):
    value = {}
    for _ in range(depth):
        value = {"a": value}
    return value


# ---- compliant builders: n entries of valid evidence per kind ----
def _fill(row, sections):
    """Every section the row reads must be present (a missing one is the not-collected cell, not the rule)."""
    for name in row["sections"]:
        if name == "scuba_config":
            sections.setdefault(name, dict(ENV))
        else:
            sections.setdefault(name, [])
    return sections


def _nested(path, value):
    for key in reversed(path):
        value = {key: value}
    return value


def _build(pid, n):
    row = POLICIES[pid]
    kind, params = row["kind"], row["params"]
    name = params.get("section")
    if kind in ("any_flag", "two_flag"):
        items = [{params["label"]: f"o{i}", **{f: not params["bad"] for f in params["fields"]}} for i in range(n)]
        return _fill(row, {name: items})
    if kind == "flag_and_empty_list":
        return _fill(row, {name: [{params["label"]: f"o{i}", params["flag"]: False, params["list_field"]: []} for i in range(n)]})
    if kind == "list_count":
        return _fill(row, {name: [{params["label"]: f"o{i}", params["list_field"]: []} for i in range(n)]})
    if kind == "bool_list":
        return _fill(row, {name: [{"domain": f"d{i}.example", "message": "ok", params["flag"]: True} for i in range(n)]})
    if kind == "substring_pair":
        return _fill(row, {name: [{params["label"]: f"o{i}", "Domains": [f"d{i}.example:Other"]} for i in range(n)]})
    if kind == "any_true_is_met":
        items = [{params["label"]: f"o{i}", params["field"]: False} for i in range(n)]
        items.append({params["label"]: "last", params["field"]: True})
        return _fill(row, {name: items})
    if kind == "global_record":
        good = {c["field"]: (False if c["how"] == "flag_false" else c["good"][0]) for c in params["checks"]}
        items = [{"Identity": f"Tag:p{i}", **good} for i in range(n)] + [{"Identity": "Global", **good}]
        return _fill(row, {name: items})
    if kind == "setting_cascade":
        return _fill(row, {"tenant_app_settings": [{"SettingName": f"s{i}", "SettingValue": "None"} for i in range(n)],
                           "app_policies": [{params["label"]: f"p{i}", params["legacy"]: "AllowedAppList"} for i in range(n)]})
    if kind == "list_exists" and params["variant"] == "transport_rule":
        rules = [{"State": "Disabled", "Mode": "Enforce", "FromScope": "NotInOrganization", "PrependSubject": "w"} for _ in range(n)]
        rules.append({"State": "Enabled", "Mode": "Enforce", "FromScope": "NotInOrganization", "PrependSubject": "warn"})
        return _fill(row, {name: rules})
    if kind == "list_exists":
        alerts = [{"Name": f"noise {i}", "Disabled": False} for i in range(n)]
        alerts += [{"Name": required, "Disabled": False} for required in __import__(
            "azure_tenant_audit.value_rules.lookups", fromlist=["REQUIRED_ALERTS"]).REQUIRED_ALERTS]
        return _fill(row, {name: alerts})
    if kind == "parser":
        need = params["need"]
        if need == "dkim_enabled":
            domains = [f"d{i}.example" for i in range(n)]
            return {"spf_records": [{"domain": d} for d in domains],
                    "dkim_config": [{"Domain": d, "Enabled": True} for d in reversed(domains)],
                    "dkim_records": [{"domain": d, "rdata": ["v=DKIM1; k=rsa; p=QUJD"]} for d in reversed(domains)]}
        record = {"dmarc_published": "v=DMARC1; p=reject", "dmarc_reject": "v=DMARC1; p=reject",
                  "dmarc_dhs_rua": "v=DMARC1; p=reject; rua=mailto:reports@dmarc.cyber.dhs.gov",
                  "dmarc_agency_contacts": "v=DMARC1; p=reject; rua=mailto:reports@dmarc.cyber.dhs.gov,mailto:a@agency.example; "
                                           "ruf=mailto:b@agency.example"}[need]
        return {"dmarc_records": [{"domain": f"d{i}.example", "rdata": [record]} for i in range(n)]}
    if kind == "safelinks_resolution":
        policy = {"Identity": "Built-In Protection Policy", **{f: True for f in params["flags"]}}
        return {"defender_license": True, "protection_policy_rules": [],
                "atp_policy_rules": [], "safe_links_rules": [{"State": "Disabled"} for _ in range(n)],
                "safe_links_policies": [{"Identity": f"p{i}", **{f: True for f in params["flags"]}} for i in range(n)] + [policy]}
    if kind == "pp_flag":
        return {"environment_creation": [_nested(params["path"], True) for _ in range(n)]}
    if kind == "pp_isolation":
        return {"tenant_isolation": [{"properties": {"isDisabled": False}} for _ in range(n)]}
    if kind == "pp_constant":
        return {"dlp_policies": [], "tenant_id": "t"}
    if kind == "pp_dlp":
        policies = [{"environmentType": "OnlyEnvironments", "displayName": f"d{i}", "name": f"n{i}",
                     "environments": [{"name": f"e{i}"}, {"name": "Default-t"}]} for i in range(n)]
        sections = {"dlp_policies": [{"value": policies}], "tenant_id": "t"}
        if params["variant"] == "coverage":
            sections["environment_list"] = [{"EnvironmentName": f"e{i}", "IsDefault": False} for i in range(n)]
        return sections
    if kind == "sp_scalar":
        return {"SPO_tenant": [{params["field"]: params["good"][0]}]}
    if kind == "sp_gated":
        return {"SPO_tenant": [{"SharingCapability": 2, "SharingDomainRestrictionMode": 1, "RequireAnonymousLinksExpireInDays": 30,
                                "FileAnonymousLinkType": 1, "FolderAnonymousLinkType": 1, "EmailAttestationRequired": True,
                                "EmailAttestationReAuthDays": 30}]}
    if kind.startswith("powerbi."):
        enabled = kind == "powerbi.on"
        settings = [{"settingName": f"other{i}", "enabled": True, "enabledSecurityGroups": [{"graphId": "x"}]} for i in range(n)]
        settings.append({"settingName": params["setting_name"], "enabled": enabled,
                         **({"enabledSecurityGroups": []} if enabled is False else {})})
        return {"powerbi_license_found": True, "powerbi_access_denied_reason": "", "powerbi_tenant_settings": settings}
    if kind == "aad_3_4":
        return {"authentication_method": [{"authentication_method_policy": {"PolicyMigrationState": "migrationComplete"}}]}
    raise AssertionError(f"no builder for {kind}")


def _first_per_kind():
    seen, picked = set(), []
    for pid, row in POLICIES.items():
        if row["kind"] not in seen or row["kind"] in ("parser", "sp_gated", "sp_scalar", "global_record", "list_exists"):
            seen.add(row["kind"])
            picked.append(pid)
    return picked


def test_every_in_scope_policy_has_a_builder():
    assert len(POLICIES) >= 55
    for pid in POLICIES:
        assert _build(pid, 2)


# ---- 1. the compliant large input: every in-scope policy, N entries, one verdict, bounded time ----
@pytest.mark.parametrize("pid", sorted(POLICIES))
def test_compliant_large_input(pid):
    sections = _build(pid, N)
    record = _timed(lambda: assess(pid, sections))
    row = POLICIES[pid]
    if row["kind"] == "pp_constant":
        assert record["verdict"] == "not_assessed"
    elif row["kind"] in ("sp_scalar", "sp_gated"):
        assert record["verdict"] in ("met", "not_met", "not_applicable")
    elif row["kind"] == "pp_isolation":
        assert record["cell"] == "all_clear"
    else:
        assert record["verdict"] == "met", record


# ---- 2. adversarial shapes that maximised a quadratic path ----
def test_dkim_many_domains_reversed_orders():
    pid = "MS.EXO.3.1v1"
    sections = _build(pid, 10000)
    sections["dkim_config"][100]["Enabled"] = False       # one domain with the flag off still answers after the full scan
    assert _timed(lambda: assess(pid, sections))["cell"] == "domain_noncompliant.dkim_not_enabled"


def test_dkim_repeated_domain_and_coexistence_entries():
    pid = "MS.EXO.3.1v1"
    sections = {"spf_records": [{"domain": "a.example"} for _ in range(N)] + [{"domain": f"t{i}.mail.onmicrosoft.com"} for i in range(N)],
                "dkim_config": [{"Domain": "a.example", "Enabled": i % 2 == 0} for i in range(N)]
                               + [{"Domain": f"t{i}.mail.onmicrosoft.com", "Enabled": False} for i in range(N)],
                "dkim_records": [{"domain": "a.example", "rdata": ["v=DKIM1; p=QUJD"]} for _ in range(N)]}
    assert _timed(lambda: assess(pid, sections))["verdict"] == "met"


def test_dmarc_uri_with_a_long_run_of_at_signs_is_linear():
    """The reference pattern backtracked quadratically over a run of '@' with a failing tail."""
    pid = "MS.EXO.4.3v1"
    # " z" and "!x" make the address unreadable; ";" ends the tag, leaving the readable address "@...@" that is not the CISA one.
    for tail, verdict in ((" z", "not_assessed"), ("!x", "not_assessed"), (";", "not_met")):
        rua = "mailto:" + "@" * (MB // 2) + tail
        sections = {"dmarc_records": [{"domain": "a.example", "rdata": [f"v=DMARC1; p=reject; rua={rua}"]}]}
        record = _timed(lambda: assess(pid, sections))
        assert record["verdict"] == verdict


def test_dmarc_very_long_strings():
    pid = "MS.EXO.4.4v1"
    rdata = ["v=DMARC1; p=reject; rua=" + ",".join(f"mailto:a{i}@agency.example" for i in range(60000)) + "; ruf=mailto:b@agency.example"]
    assert len(rdata[0]) > MB
    assert _timed(lambda: assess(pid, {"dmarc_records": [{"domain": "a.example", "rdata": rdata}]}))["verdict"] == "met"
    many_tags = ["v=DMARC1; " + "; ".join(f"t{i}=x" for i in range(100000))]
    assert _timed(lambda: assess("MS.EXO.4.1v1", {"dmarc_records": [{"domain": "a.example", "rdata": many_tags}]}))["cell"] == "domain_noncompliant.p_absent"
    spaced = ["v" + " " * MB + "x"]
    assert _timed(lambda: assess("MS.EXO.4.1v1", {"dmarc_records": [{"domain": "a.example", "rdata": spaced}]}))["verdict"] == "not_met"
    many_chunks = ["v=DMARC1; p=reject"] + ["x"] * 200000
    assert _timed(lambda: assess("MS.EXO.4.1v1", {"dmarc_records": [{"domain": "a.example", "rdata": many_chunks}]}))["verdict"] == "met"


def test_safelinks_many_partial_rules_each_with_a_policy():
    pid = "MS.SECURITYSUITE.7.3v1"
    rules = [{"State": "Enabled", "SentTo": ["a"], "SentToMemberOf": None, "RecipientDomainIs": None,
              "Priority": i, "SafeLinksPolicy": f"p{i}"} for i in range(N)]
    policies = [{"Identity": f"p{i}", "TrackClicks": True} for i in range(N)] + [{"Identity": "Built-In Protection Policy", "TrackClicks": True}]
    sections = {"defender_license": True, "protection_policy_rules": [], "atp_policy_rules": [], "safe_links_rules": rules,
                "safe_links_policies": policies}
    assert _timed(lambda: assess(pid, sections))["verdict"] == "met"
    policies[N - 1]["TrackClicks"] = False                # the last partial rule's policy is non-compliant: found after the full pass
    assert _timed(lambda: assess(pid, sections))["cell"] == "partial_rule_noncompliant"


def test_safelinks_many_covering_rules_and_duplicated_policy():
    pid = "MS.SECURITYSUITE.7.3v1"
    rules = [{"State": "Enabled", "SentTo": None, "SentToMemberOf": None, "RecipientDomainIs": None, "Priority": i + 1,
              "SafeLinksPolicy": f"p{i}"} for i in range(N)]
    sections = {"defender_license": True, "protection_policy_rules": [], "atp_policy_rules": [], "safe_links_rules": rules,
                "safe_links_policies": [{"Identity": f"p{i}", "TrackClicks": True} for i in range(N)] * 2}
    assert _timed(lambda: assess(pid, sections))["cell"] == "policy_duplicated"


def test_safelinks_preset_rules_scan_is_linear():
    pid = "MS.SECURITYSUITE.7.1v1"
    flags = {f: True for f in POLICIES[pid]["params"]["flags"]}
    noise = [{"Identity": f"Custom {i}", "State": "Enabled", "SentTo": None, "SentToMemberOf": None, "RecipientDomainIs": None}
             for i in range(N)]
    preset = {"Identity": "Standard Preset Security Policy", "State": "Enabled", "SentTo": None, "SentToMemberOf": None,
              "RecipientDomainIs": None}
    sections = {"defender_license": True, "protection_policy_rules": noise + [preset], "atp_policy_rules": noise + [preset],
                "safe_links_rules": [], "safe_links_policies": [{"Identity": "Built-In Protection Policy", **flags}]}
    assert _timed(lambda: assess(pid, sections))["cell"] == "preset_covers"


def test_spam_cascade_many_custom_rules_and_policies():
    row = HELD["MS.SECURITYSUITE.6.1v1"]
    ok = {"SpamAction": "MoveToJmf", "HighConfidenceSpamAction": "Quarantine", "PhishSpamAction": "Quarantine",
          "HighConfidencePhishAction": "Quarantine"}
    policies = [{"Identity": f"c{i}", "IsDefault": False, "RecommendedPolicyType": "Custom", **ok} for i in range(N)]
    policies.append({"Identity": "Default", "IsDefault": True, "RecommendedPolicyType": "Custom", **ok})
    rules = [{"Identity": f"r{i}", "State": "Enabled", "HostedContentFilterPolicy": f"c{i}", "SentTo": ["a"],
              "SentToMemberOf": None, "RecipientDomainIs": None} for i in range(N)]
    sections = {"accepted_domains": [{"DomainName": "a.example"}], "hosted_content_filter_policies": policies,
                "hosted_content_filter_rules": rules, "protection_policy_rules": [{"Identity": f"Other {i}"} for i in range(N)]}
    record = _timed(lambda: SPAM_KINDS["spam_cascade"]("MS.SECURITYSUITE.6.1v1", row, sections))
    assert record["verdict"] == "met"


def test_power_platform_coverage_many_environments_and_except_policies():
    pid = "MS.POWERPLATFORM.2.2v1"
    envs = [{"EnvironmentName": f"e{i}", "IsDefault": False} for i in range(10000)] + [{"EnvironmentName": "dflt", "IsDefault": True}]
    excepts = [{"environmentType": "ExceptEnvironments", "displayName": f"d{i}", "name": f"n{i}", "environments": [{"name": f"e{i}"}]}
               for i in range(10000)]
    sections = {"dlp_policies": [{"value": excepts}], "environment_list": envs, "tenant_id": "t"}
    assert _timed(lambda: assess(pid, sections))["cell"] == "all_environments_covered"
    excepts.append({"environmentType": "ExceptEnvironments", "displayName": "x", "name": "x", "environments": [{"name": "e5"}]})
    sections = {"dlp_policies": [{"value": [excepts[-1]] + excepts[:-1]}], "environment_list": envs, "tenant_id": "t"}
    assert _timed(lambda: assess(pid, sections))["cell"] == "all_environments_covered"
    sections["dlp_policies"] = [{"value": [excepts[-1]]}]       # one Except policy names only e5: every other environment is covered, e5 is not
    assert _timed(lambda: assess(pid, sections))["cell"] == "environment_without_policy"


def test_power_platform_default_and_wrapper_shapes():
    pid = "MS.POWERPLATFORM.2.1v1"
    policies = [{"environmentType": "ExceptEnvironments", "displayName": "d", "name": f"n{i}",
                 "environments": [{"name": f"Default-t"} for _ in range(3)]} for i in range(N)]
    sections = {"dlp_policies": [{"value": policies} for _ in range(50)], "tenant_id": "t"}
    assert _timed(lambda: assess(pid, sections))["cell"] == "default_environment_not_covered"
    sections["dlp_policies"] = [{"value": [{"environmentType": "AllEnvironments", "displayName": "d", "name": "n"}] * N}]
    assert _timed(lambda: assess(pid, sections))["cell"] == "default_environment_covered"


def test_power_bi_many_groups_and_duplicates():
    pid = "MS.POWERBI.2.1v1"
    groups = [{"graphId": f"{i:08x}-0000-0000-0000-000000000000"} for i in range(10000)]
    settings = [{"settingName": "AllowGuestUserToAccessSharedContent", "enabled": True, "enabledSecurityGroups": groups}]
    sections = {"powerbi_license_found": True, "powerbi_access_denied_reason": "", "powerbi_tenant_settings": settings}
    assert _timed(lambda: assess(pid, sections))["cell"] == "og.enabled_groups_listed"
    sections["powerbi_tenant_settings"] = settings * N
    assert _timed(lambda: assess(pid, sections))["cell"] == "setting_entry_duplicated"
    groups[-1] = {"graphId": "0" * MB}
    sections["powerbi_tenant_settings"] = settings
    assert _timed(lambda: assess(pid, sections))["cell"] == "og.enabled_groups_unusable"


def test_teams_setting_cascade_duplicates_and_global_duplicates():
    sections = {"tenant_app_settings": [{"SettingName": "DefaultApp", "SettingValue": "None"} for _ in range(N)], "app_policies": []}
    assert _timed(lambda: assess("MS.TEAMS.5.1v2", sections))["cell"] == "setting_duplicated"
    sections = {"meeting_policies": [{"Identity": "Global", "AllowCloudRecording": False} for _ in range(N)]}
    assert _timed(lambda: assess("MS.TEAMS.1.6v1", sections))["cell"] == "global_duplicated"


def test_alerts_many_duplicate_required_entries_and_substring_megabyte_domains():
    from azure_tenant_audit.value_rules.lookups import REQUIRED_ALERTS
    alerts = [{"Name": name, "Disabled": i % 2 == 0} for i in range(N) for name in REQUIRED_ALERTS]
    assert _timed(lambda: assess("MS.SECURITYSUITE.4.1v1", {"protection_alerts": alerts}))["verdict"] == "not_assessed"
    sharing = [{"Name": "p", "Domains": ["*" * MB, "Contacts" * 100000, "a" * MB + "*"]}]
    assert _timed(lambda: assess("MS.EXO.6.1v1", {"sharing_policy": sharing}))["verdict"] == "met"
    sharing = [{"Name": "p", "Domains": ["*" * MB + "Contacts"]}]
    assert _timed(lambda: assess("MS.EXO.6.1v1", {"sharing_policy": sharing}))["verdict"] == "not_met"


def test_sharepoint_and_single_object_rules_with_many_entries():
    sections = {"SPO_tenant": [{"SharingCapability": 0}] * N}
    assert _timed(lambda: assess("MS.SHAREPOINT.1.1v1", sections))["cell"] == "spo_not_singleton"
    sections = {"authentication_method": [{}] * N}
    assert _timed(lambda: assess("MS.AAD.3.4v1", sections))["cell"] == "section_not_singleton"


def test_unlabelled_and_unusable_items_scan_is_linear():
    items = [{"AuditDisabled": True} for _ in range(N * 2)]
    assert _timed(lambda: assess("MS.EXO.13.1v1", {"org_config": items}))["cell"] == "flag_bad_unlabelled"
    items = [{"Name": f"o{i}"} for i in range(N * 2)]
    assert _timed(lambda: assess("MS.EXO.13.1v1", {"org_config": items}))["cell"] == "flag_unusable"
    items = [{"Identity": f"i{i}", "UnifiedAuditLogIngestionEnabled": None} for i in range(N * 2)]
    assert _timed(lambda: assess("MS.SECURITYSUITE.5.1v1", {"admin_audit_log_config": items}))["cell"] == "flag_unusable"


# ---- 3. nested depth and megabyte strings: every in-scope kind, one field replaced at a time ----
def _variants():
    return {"deep_list": _deep_list(), "deep_dict": _deep_dict(), "big_string": "x" * MB, "big_string_list": ["x" * MB],
            "deep_in_list": [_deep_dict()]}


def _sites(value, path=(), depth=3):
    """Every dict key and list index down to ``depth`` levels, as paths."""
    if depth == 0:
        return
    if isinstance(value, dict):
        for key in value:
            yield path + (key,)
            yield from _sites(value[key], path + (key,), depth - 1)
    elif isinstance(value, list):
        for index in range(min(len(value), 2)):
            yield path + (index,)
            yield from _sites(value[index], path + (index,), depth - 1)


def _replace(value, path, new):
    """Shallow copies along ``path`` only: deepcopy would itself recurse on the 1,000-deep replacements."""
    if not path:
        return new
    head, rest = path[0], path[1:]
    if isinstance(value, dict):
        copy = dict(value)
    else:
        copy = list(value)
    copy[head] = _replace(value[head], rest, new)
    return copy


@pytest.mark.parametrize("pid", _first_per_kind())
def test_deep_nesting_and_huge_strings_never_raise(pid):
    base = _build(pid, 3)
    variants = _variants()
    start = time.perf_counter()
    calls = 0
    for path in _sites(base):
        for new in variants.values():
            sections = _replace(base, path, new)
            record = assess(pid, sections)
            assert record is not None and record["policy_id"] == pid
            calls += 1
    for name in base:
        for new in variants.values():
            record = assess(pid, {**base, name: new})
            assert record is not None
            calls += 1
    assert calls > 10
    assert time.perf_counter() - start < 20


# ---- 4. the rewritten paths against their old implementation, on small random inputs ----
_OLD_URI = re.compile(r"^mailto:([^\s,!;]+@[^\s,!;]+?)(?:![0-9]+[kKmMgGtT]?)?$", re.I)


def _old_parse_uris(value):
    addrs, junk = [], 0
    for piece in value.split(","):
        match = _OLD_URI.match(piece.strip())
        if match:
            addrs.append(match.group(1).lower())
        else:
            junk += 1
    return addrs, junk


def test_uri_pattern_is_the_old_language():
    rng = random.Random(20261105)
    atoms = ["mailto:", "MAILTO:", "@", "a", "B", " ", "\t", ",", "!", ";", "1", "k", "K", "K", "\n", ".", "!10m", "!5", "!x",
             "mailto:a@b", " ", " ", "İ"]
    for _ in range(20000):
        text = "".join(rng.choice(atoms) for _ in range(rng.randint(0, 9)))
        assert dns.parse_uris(text) == _old_parse_uris(text), repr(text)
    for text in ("mailto:a@b", "mailto:@b", "mailto:a@", "mailto:@@", "mailto:@@@", " MAILTO:A@EXAMPLE.INVALID!10m, mailto:r@d.gov!2G ",
                 "mailto:a@b!", "mailto:a@b!5kk", "mailto:a b@c", "mailto:a@b c"):
        assert dns.parse_uris(text) == _old_parse_uris(text), repr(text)


def _old_dkim(sections, sp):
    """The DKIM branch of ``dns._parser`` as it was, with the per-domain list scans."""
    cfg = [e for e in sections["dkim_config"] if isinstance(e, dict)]
    recs = [e for e in sections["dkim_records"] if isinstance(e, dict)]
    coexist = {c["Domain"] for c in cfg if type(c.get("Domain")) is str and c["Domain"].endswith(".mail.onmicrosoft.com")}
    res, seen = [], set()
    for e in (x for x in sections["spf_records"] if isinstance(x, dict)):
        d = e.get("domain")
        if type(d) is not str:
            res.append(("unusable", "spf_domain_absent", True))
            continue
        if d in seen or d in coexist:
            continue
        seen.add(d)
        mine = [c for c in cfg if c.get("Domain") == d]
        if not mine:
            res.append(("bad", "no_signing_config", True))
            continue
        flags = [c.get("Enabled") for c in mine]
        if not any(f is True for f in flags):
            res.append(("bad", "dkim_not_enabled", True) if all(f is False for f in flags) else ("unusable", "enabled_flag_unusable", True))
            continue
        rr = [r for r in recs if r.get("domain") == d]
        if not rr:
            res.append(("bad", "no_dkim_record_entry", True))
            continue
        verdicts, unusable, empty = [], False, False
        for r in rr:
            rd = r.get("rdata", None) if "rdata" in r else None
            if not isinstance(rd, list) or any(type(x) is not str for x in rd):
                unusable = True
            elif not rd:
                empty = True
            else:
                verdicts += [dns._dkim_string(x) for x in rd]
        if "valid" in verdicts:
            res.append(("ok", "", True))
        elif unusable or "syntax" in verdicts:
            res.append(("unusable", "dkim_rdata_unusable", True))
        elif empty:
            res.append(("unusable", "dkim_rdata_empty", True))
        else:
            res.append(("bad", "key_not_published", True))
    return dns._scan_domains("MS.EXO.3.1v1", "spf_records", res, sp["what"], ["dkim_config", "dkim_records", "spf_records"], sp["need"])


def test_dkim_index_matches_the_scan_on_random_inputs():
    rng = random.Random(3)
    pool = ["a.com", "b.com", "c.com", "t.mail.onmicrosoft.com", None, 5, "A.com"]
    rdata = [None, [], ["v=DKIM1; p=abc"], ["junk"], [1], ["v=DKIM1; p="], ["v=DKIM1; p=a; bad"], ["v=DKIM1; p=a", "x"], "str"]
    row = POLICIES["MS.EXO.3.1v1"]
    for _ in range(1500):
        spf = [{"domain": rng.choice(pool)} if rng.random() < 0.9 else rng.choice([None, "x", 3])
               for _ in range(rng.randint(1, 5))]
        cfg = [{"Domain": rng.choice(pool), "Enabled": rng.choice([True, False, None, "yes"])} if rng.random() < 0.95 else 7
               for _ in range(rng.randint(0, 6))]
        recs = []
        for _ in range(rng.randint(0, 6)):
            entry = {"domain": rng.choice(pool)}
            choice = rng.choice(rdata)
            if choice is not None:
                entry["rdata"] = choice
            recs.append(entry)
        sections = {"spf_records": spf, "dkim_config": cfg, "dkim_records": recs}
        if not any(isinstance(e, dict) for e in spf) or not any(isinstance(e, dict) for e in cfg) or not any(isinstance(e, dict) for e in recs):
            continue
        assert dns._parser("MS.EXO.3.1v1", row["params"], sections) == _old_dkim(sections, row["params"])


def _old_safelinks_core():
    source = inspect.getsource(defender_resolution._safelinks_core)
    scan = 'pp = [e for e in sections["safe_links_policies"] if isinstance(e, dict) and type(name) is str and e.get("Identity") == name]'
    applied = 'pols = [e for e in sections["safe_links_policies"] if isinstance(e, dict) and e.get("Identity") == applied]'
    new_scan = "pp = by_identity.get(name, []) if type(name) is str else []"
    new_applied = "pols = by_identity.get(applied, [])"
    assert new_scan in source and new_applied in source
    namespace = dict(vars(defender_resolution))
    exec(source.replace(new_scan, scan).replace(new_applied, applied), namespace)       # noqa: S102 (test-local reference)
    return namespace["_safelinks_core"]


def test_safelinks_policy_index_matches_the_scan_on_random_inputs():
    old = _old_safelinks_core()
    rng = random.Random(7)
    names = ["p1", "p2", "Built-In Protection Policy", None, 3, "P1"]
    for _ in range(3000):
        rules = []
        for _ in range(rng.randint(0, 5)):
            scope = rng.choice([{"SentTo": ["a"]}, {"SentTo": None}, {"SentTo": [], "SentToMemberOf": []}])
            rule = {"State": rng.choice(["Enabled", "Enabled", "Disabled"]), "SentToMemberOf": None, "RecipientDomainIs": None, **scope}
            if rng.random() < 0.8:
                rule["Priority"] = rng.choice([1, 2, 2, 5, 1.5, True, "x"])
            if rng.random() < 0.9:
                rule["SafeLinksPolicy"] = rng.choice(names)
            rules.append(rule if rng.random() < 0.95 else rng.choice([None, "x", []]))
        policies = []
        for _ in range(rng.randint(0, 5)):
            entry = {"Identity": rng.choice(names), "TrackClicks": rng.choice([True, False, None, True])}
            policies.append(entry if rng.random() < 0.95 else rng.choice([None, "x", []]))
        sections = {"defender_license": True, "protection_policy_rules": [], "atp_policy_rules": [], "safe_links_rules": rules,
                    "safe_links_policies": policies, "accepted_domains": [{"DomainName": "a.example"}]}
        if not rules:
            continue
        sp = {"flags": ["TrackClicks"], "what": "user click tracking"}
        trace_new, trace_old = {}, {}
        new = defender_resolution._safelinks_core("MS.SECURITYSUITE.7.3v1", sp, sections, trace_new)
        assert new == old("MS.SECURITYSUITE.7.3v1", sp, sections, trace_old)
        assert trace_new == trace_old


def _old_dlp_coverage(policy_id, row, sections):
    record, policies, unreadable = power_platform._dlp_policies(policy_id, sections)
    if record:
        return record
    if any(kind == "AllEnvironments" for kind, _ in policies):
        return power_platform._answer(policy_id, row, "all_environments_policy")
    record, environments = power_platform._list_state(policy_id, sections, "environment_list")
    if record:
        return record
    if any(type(item.get("EnvironmentName")) is not str or type(item.get("IsDefault")) is not bool for item in environments):
        return power_platform._answer(policy_id, row, "environment_list_unusable", ["environment_list"])
    nondefault = {item["EnvironmentName"] for item in environments if item["IsDefault"] is False}
    covered = set()
    for kind, names in policies:
        covered |= names if kind == "OnlyEnvironments" else nondefault - names
    if not nondefault - covered:
        return power_platform._answer(policy_id, row, "all_environments_covered" if nondefault else "no_nondefault_environments")
    if unreadable:
        return power_platform._answer(policy_id, row, "dlp_structure_unusable", ["dlp_policies"])
    return power_platform._answer(policy_id, row, "environment_without_policy")


def test_dlp_coverage_matches_the_set_subtraction_on_random_inputs():
    rng = random.Random(11)
    pid = "MS.POWERPLATFORM.2.2v1"
    row = row_for(pid)
    envs = ["e1", "e2", "e3", "e4", "e5"]
    for _ in range(4000):
        policies = []
        for _ in range(rng.randint(0, 5)):
            kind = rng.choice(["OnlyEnvironments", "ExceptEnvironments", "ExceptEnvironments", "OnlyEnvironments", "AllEnvironments"]
                              if rng.random() < 0.97 else ["Bogus"])
            policy = {"environmentType": kind, "displayName": "d", "name": "n"}
            if kind != "AllEnvironments" or rng.random() < 0.3:
                policy["environments"] = [{"name": rng.choice(envs)} for _ in range(rng.randint(0, 4))]
            policies.append(policy)
        environments = [{"EnvironmentName": e, "IsDefault": rng.random() < 0.15} for e in rng.sample(envs, rng.randint(0, 5))]
        sections = {"dlp_policies": [{"value": policies}], "environment_list": environments, "tenant_id": "t"}
        assert power_platform.pp_dlp(pid, row, sections) == _old_dlp_coverage(pid, row, sections)


def test_the_rule_modules_stay_free_of_unbounded_recursion():
    """No module of this sweep calls itself or copies evidence recursively; a RecursionError would reach the engine's
    ``rule_evaluation_failed`` path (``auditex.model_precheck``), but none of these rules can raise one."""
    import azure_tenant_audit.value_rules as package
    for module in (dns, power_platform, defender_resolution):
        source = inspect.getsource(module)
        assert "deepcopy" not in source and "json.dumps" not in source
    assert package.assess is assess
