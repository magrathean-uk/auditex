"""Exercise unreadable evidence and catalogue changes against the GWS replay vectors."""
from __future__ import annotations

import json
from copy import deepcopy

import pytest
from test_gws_value_rules_replay import VECTORS

from azure_tenant_audit.value_rules import gws

_ANSWERED_VECTORS = [v for v in VECTORS if v["verdict"] in {"met", "not_met"}]
_TWO_STEP_PREFIX = "security_two_step_verification_"
_TWO_STEP_PREDICATES = {
    "GWS.COMMONCONTROLS.1.1v1": "enforcement_factor",
    "GWS.COMMONCONTROLS.1.2v1": None,
    "GWS.COMMONCONTROLS.1.3v1": "enforcement_factor",
    "GWS.COMMONCONTROLS.1.4v1": "grace_period",
    "GWS.COMMONCONTROLS.1.5v1": "device_trust",
}
_TWO_STEP_EXTRA_SECTIONS = {"enforcement_factor", "grace_period", "device_trust"}

# The cited vectors deliberately carry extra evidence. Pin the precise paths whose malformed values can leave
# the independent proof intact, including off services, unused branches and lower-ranked settings (design §8.2).
_IGNORED_POLICY_PATHS = {
    "lists-c131-sub-ou-ignored": ((7, "sort_order"), (7, "value")),
    "lists-c131-user-rule-ignored": ((7, "value", "state"),),
    "lists-g14-sub-ou-ignored": ((2, "sort_order"), (2, "value")),
    "lists-g17-sub-ou-off": ((3, "sort_order"), (3, "value"), (4, "sort_order"), (4, "value")),
    "lists-g181-bypass-off": ((1, "sort_order"), (1, "value"), (2, "value", "ruleStates", 1, "enabled")),
    "lists-g181-list-disabled": ((1, "value", "emailAddressList", 0, "domain_entry_count"),
                                 (1, "value", "emailAddressList", 0, "entry_count"),
                                 (2, "value", "ruleStates", 1, "enabled")),
    "lists-g181-max-map-merge": ((1, "sort_order"), (1, "value"), (2, "value", "ruleStates", 1, "enabled"),
                                 (4, "value", "spamOverride", 0, "bypassSelectedSenders")),
    "lists-g181-met": ((1, "value", "emailAddressList", 1, "domain_entry_count"),
                       (1, "value", "emailAddressList", 1, "entry_count"), (2, "value", "ruleStates", 2, "enabled")),
    "lists-g181-override-disabled": ((1, "sort_order"), (1, "value"), (2, "value", "ruleStates", 1, "enabled"),
                                    (2, "value", "ruleStates", 2, "enabled")),
    "lists-g182-bypass-only": ((1, "sort_order"), (1, "value"), (2, "value", "ruleStates", 1, "enabled"),
                               (3, "value", "spamOverride", 0, "bypassSelectedSenders"),
                               (3, "value", "spamOverride", 0, "bypassSenderAllowlist")),
    "lists-g182-flag-off": ((1, "sort_order"), (1, "value"), (2, "value", "ruleStates", 1, "enabled")),
    "lists-g182-met": ((1, "value", "emailAddressList", 1, "domain_entry_count"),
                       (1, "value", "emailAddressList", 1, "entry_count")),
    "multi-drive12-own-not-inherited": ((2, "value", "allowReceivingFilesOutsideAllowlistedDomains"),),
    "multi-drive13-disallowed": ((1, "value", "warnForExternalSharing"),
                                (1, "value", "warnForSharingOutsideAllowlistedDomains")),
    "multi-drive13-other-branch": ((1, "value", "warnForExternalSharing"),),
    "multi-drive13-sub-off": ((2, "sort_order"), (2, "value", "warnForExternalSharing")),
    "multi-drive13-sub-wrong-branch": ((2, "value", "warnForExternalSharing"),),
    "multi-drive14-merge-max": ((2, "value", "allowNonGoogleInvites"),),
    "multi-drive15-sub-field-disallowed": ((2, "value", "allowPublishingFiles"),),
    "multi-drive31-top-off-explicit-good": ((2, "sort_order"), (2, "value", "allowUsersToManageUpdate")),
    "multi-gmail55-sub-off": ((3, "sort_order"), (3, "value", "encryptedAttachmentProtectionConsequence")),
    "multi-groups41-other-field": ((1, "value", "collaborationCapability"),),
    "setting-GMAIL.1.1-default-is-not-applied-to-a-sub-ou": ((2, "value", "note"),),
    "setting-GMAIL.5.1-sub-ou-with-service-off-is-skipped": ((3, "sort_order"),
                                                          (3, "value", "enableEncryptedAttachmentProtection")),
    "setting-GMAIL.7.5-d4-groups-field-compliant": ((1, "value", "detectDomainSpoofingFromUnauthenticatedSenders"),),
}


def _outside_proof(vector, path):
    policy, case = vector["policy"], vector["vector_id"]
    if path == ("gws_tenant", "as_of"):
        return policy not in _TWO_STEP_PREDICATES
    if path[:2] == ("gws_policies", "policies") and len(path) >= 4 and path[3] != "section":
        if policy in _TWO_STEP_PREDICATES:
            row = vector["sections"]["gws_policies"]["policies"][path[2]]
            return (row["section"].startswith(_TWO_STEP_PREFIX)
                    and row["section"].removeprefix(_TWO_STEP_PREFIX) in
                    _TWO_STEP_EXTRA_SECTIONS - {_TWO_STEP_PREDICATES[policy]})
        return any(path[2:2 + len(prefix)] == prefix for prefix in _IGNORED_POLICY_PATHS.get(case, ()))
    if path[:2] == ("gws_dns", "domains") and len(path) >= 4:
        if policy in {"GWS.GMAIL.2.1v1", "GWS.GMAIL.3.1v1"}:
            domain = vector["sections"]["gws_dns"]["domains"][path[2]]
            if domain["alias"] is True and path[3] != "alias":
                return True
        return policy == "GWS.GMAIL.2.1v1" and path[3] == "spf"
    if policy == "GWS.COMMONCONTROLS.6.2v1":
        return path in {("gws_admins", "privileged"), ("gws_admins", "memberships_complete")}
    if case in {"sso-group-off-over-ou-saml", "sso-nearest-ancestor-off", "sso-other-group-ignored",
                "sso-own-ou-wins", "sso-sibling-ou-ignored"}:
        return path == ("gws_sso", "assignments", 0, "sso_mode")
    if case == "events-cc-2-1-met":
        # This tenant-wide event is keyed by event name rather than a setting or OU identifier.
        return path[:3] == ("gws_setting_events", "events", 0) and path[3:] in {("setting",), ("unit",)}
    if case == "events-gemini-1-1-off-leaf-unreadable":
        return path in {("gws_setting_events", "events", 1, "new_value"), ("gws_setting_events", "events", 1, "time")}
    return False


def _leaves(value, path=()):
    if isinstance(value, dict) and value:
        for key, item in value.items():
            yield from _leaves(item, (*path, key))
    elif isinstance(value, list) and value:
        for index, item in enumerate(value):
            yield from _leaves(item, (*path, index))
    else:
        yield path, value


def _mutations(value):
    for label, replacement in (
        ("null", None), ("wrong type", False if value is None or isinstance(value, str) else "unreadable"),
        ("blank string", " "), ("empty container", {} if isinstance(value, list) else []),
    ):
        if type(replacement) is not type(value) or replacement != value:
            yield label, replacement


@pytest.mark.parametrize("vector", _ANSWERED_VECTORS, ids=[v["vector_id"] for v in _ANSWERED_VECTORS])
def test_unreadable_leaf_cannot_create_or_sustain_met_on_affected_evidence(vector):
    sections = deepcopy(vector["sections"])
    survived = []
    for path, value in _leaves(vector["sections"]):
        parent = sections
        for key in path[:-1]:
            parent = parent[key]
        for label, replacement in _mutations(value):
            parent[path[-1]] = replacement
            answer = gws.assess(vector["policy"], sections)
            if answer["verdict"] == "met" and (vector["verdict"] == "not_met" or not _outside_proof(vector, path)):
                survived.append((path, label))
        parent[path[-1]] = value
    assert not survived


# Mutate one real row per fragment. Each selected replay vector must distinguish the mutant from the shipped rule.
@pytest.mark.parametrize(("fragment", "vector_id", "change"), [
    ("dns", "dns-4-1-25", lambda params: params.update(domains="primary_and_secondary")),
    ("events", "events-gemini-1-1-off-everywhere", lambda params: params.pop("service")),
    ("identity", "twosv-11-factor-no-telephony", lambda params: params.update(check="no_telephony")),
    ("lists", "lists-c102-not-met", lambda params: params["scopes"].remove("CHAT_HIGH_RISK")),
    ("multi", "multi-gmail55-off", lambda params: params.update(service=None)),
    ("setting-collab", "setting-collab-DRIVEDOCS.1.1-met", lambda params: params["value"].remove("DISALLOWED")),
    ("setting-core", "setting-GMAIL.1.1-not-applicable", lambda params: params.update(service=None)),
], ids=["dns", "events", "identity", "lists", "multi", "setting-collab", "setting-core"])
def test_fragment_mutant_breaks_a_replay_expectation(fragment, vector_id, change, monkeypatch):
    [vector] = [v for v in VECTORS if v["vector_id"] == vector_id]
    policy, sections = vector["policy"], vector["sections"]
    assert gws.assess(policy, deepcopy(sections))["verdict"] == vector["verdict"]
    config = gws.catalogue
    path = f"configs/scuba-gws-rules-{fragment}.json"

    def read(name):
        text = config.open_text_resource(name)
        if name != path:
            return text
        payload = json.loads(text)
        change(payload["policies"][policy]["params"])
        return json.dumps(payload)

    mutated = config._load(read)
    monkeypatch.setattr(config, "catalogue", lambda: mutated)
    assert gws.assess(policy, deepcopy(sections))["verdict"] != vector["verdict"]
