"""v3.9.1 vectors replay: the product engine against the spec's expected answers for all 102 policies.

Each vector's evidence goes through the whole value-rule precheck order (closed gate, absent section, kind) and the
product answer is compared with the spec's expected verdict, cell, reason code, reason text and cited sections. The
pack response is compared with the vector's gold. The default run replays a bounded, deterministic sample
(``vectors-v391-sample.jsonl.xz``: 2,233 of the 26,898 vectors built by ``scripts/build-value-rule-sample-v391.py``,
plus the nine review R003 Built-In vectors, every one of the 1,090 cells; review lane rules-followup relabelled the
rows its rulings moved, see ``review_relabel``); the full replay is the explicit acceptance job:

    AUDITEX_TEST_VALUE_RULE_VECTORS_V391=<value-rules-v391>/vectors.jsonl \\
        .venv/bin/python -B -I -m pytest tests/test_value_rules_replay.py -m value_rule_acceptance -o addopts= -q

Expected divergence classes (vectors-check.md section 1, exactly as the spec's check.py treats them):

* verdict differs from the Rego gold: the vector's ``disagreement`` starts ``expected: Dnn``; the rule's verdict is
  the spec's (a documented decision), and the product must reproduce the spec's rule verdict, never the gold's.
  7,780 vectors; every other vector (19,118) has the rule verdict equal to the gold's.
* S2 vocabulary: pack gold keeps the pre-A1 limitation and recommendation ids for collected but unusable evidence;
  the legacy response (``legacy=True``, the offline pack form) equals the gold, the modern one differs from it only
  in those two lists (claims identical). 966 vectors.
* D94 and D90 evidence ids: the gold of AAD 3.3v2 (D94, 7 vectors) and SS 3.2 (D90, 1 vector) cites sections the
  rules no longer read. ADDENDUM-A2's 190 exact label overrides replace the AAD 3.3v2 claim's evidence ids first;
  D90 and the A2 unchanged controls compare claim status and value, limitations and recommendations only.
* licensed twins (``packlic-train``, 45 vectors with a gold response): the gold cites the pack row's sections
  without the added licence section, so the spec compares no response for them; only the rule fields are compared.
* A2 constructed vectors have no Rego gold ("NO GOLD (constructed A2 contract expectation)"); only the rule fields
  are compared.

Anything else is a product fault (or a spec fault) and fails the replay.
"""
from __future__ import annotations

import json
import lzma
import os
import re
from collections import Counter
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

import pytest

from azure_tenant_audit.resources import open_text_resource
from azure_tenant_audit.scuba_precheck import precheck_policy, precheck_response
from azure_tenant_audit.value_rules import as_pack_response, assess, rule_policies
from azure_tenant_audit.value_rules.catalogue import cells_for, row_for
from azure_tenant_audit.value_rules.record import checked

FIXTURES = Path(__file__).parent / "fixtures/value-rules"
SAMPLE = FIXTURES / "vectors-v391-sample.jsonl.xz"
OVERRIDES = FIXTURES / "label-overrides-a2-v391-sample.jsonl"
MANIFEST = FIXTURES / "manifest-v391-sample.json"
POLICY_ITEMS = json.loads(open_text_resource("configs/scuba-policy-sections.json"))["policies"]
FULL_ENV = "AUDITEX_TEST_VALUE_RULE_VECTORS_V391"
ANSWER = ("verdict", "cell", "reason_code", "reason_text", "cited_sections")
# M08-T10 reverses spec ruling D29 for DMARC (an all-NXDomain tree walk reads no record). An entry without step
# outcomes, as every v3.9.1 vector is, keeps the spec's verdict, cell and reason code; only the shared reason text
# gains the note on the reversal. This is the one documented reason-text class.
D29_REASON_CODE = "data_unavailable_dns_answer_empty"
D29_V391_TEXT = ("Data unavailable: a DNS answer (rdata) is empty and the export does not say whether the lookup "
                 "succeeded or failed; the policy was not assessed.")
D29_PRODUCT_TEXT = ("Data unavailable: a DNS answer (rdata) is empty and the export does not say whether the lookup "
                    "succeeded or failed (a DMARC entry whose every lookup step is a recorded NXDomain reads no record "
                    "instead); the policy was not assessed.")


# M08-T10 (DEC-068, defect D4) reads an empty Get-DkimSigningConfig answer as an empty list, so the DKIM rule answers "no
# signing configuration" (not met), where v3.9.1 answered not assessed (divergence D15). The product now agrees with
# the gold (OPA replay). This is the one vector of that class; it is checked against the gold, not the v3.9.1 rule.
D4_VECTOR = "constructed:MS.EXO.3.1v1:dkim_config_empty"
D4_PRODUCT = ("not_met", "domain_noncompliant.no_signing_config", "domain_noncompliant",
              "Requirement not met: at least one domain has no DKIM signing configuration.", ["dkim_config"])

def _lines(path: Path):
    with (lzma.open(path, "rt") if path.suffix == ".xz" else path.open()) as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


# ---- Review lane rules-followup: product answers that depart from the frozen v3.9.1 kit ----
# The shipped fixtures (s4, s7 and this sample) carry these rows relabelled (bot review wave 2 adds W59 in s4); the
# full kit keeps the spec's labels, so every full-kit replay maps them through ``review_relabel`` (a documented class,
# like D29 and A2 above).
REVIEW_BI_POLICIES = frozenset(f"MS.SECURITYSUITE.7.{n}v1" for n in (1, 2, 3))
REVIEW_R027_POLICIES = frozenset({"MS.AAD.1.1v1", "MS.AAD.2.1v1", "MS.AAD.2.3v1", "MS.AAD.3.1v1", "MS.AAD.3.2v2",
                                  "MS.AAD.3.6v1", "MS.AAD.3.7v1", "MS.AAD.3.8v1", "MS.AAD.3.9v1"})
REVIEW_BI_ROW = {"ExceptIfRecipientDomainIs": None, "ExceptIfSentTo": None, "ExceptIfSentToMemberOf": None,
                 "Identity": "ATP Built-In Protection Rule", "RecipientDomainIs": None, "SentTo": None, "SentToMemberOf": None}
REVIEW_W59_TEXT = ("Data unusable: a partly scoped Safe Links rule whose policy turns off a flag the policy reads has no "
                   "numeric Priority, so it may apply before the covering rule; the policy was not assessed.")
REVIEW_D24 = ("expected: D24 Safe Links resolution cannot be established from the export (domain-scoped or excepted "
              "rule, tie, unexported or duplicated policy, null flag)")
REVIEW_SS7 = ("MS.SECURITYSUITE.7.1v1", "MS.SECURITYSUITE.7.2v1", "MS.SECURITYSUITE.7.3v1")
# The kit vectors whose labels the review rulings moved, as independently reviewed fixed overrides: (class, policies,
# vector name, the kit's cell, the reviewed cell). The new answer comes from this table and the spec's cell catalogue,
# never from the engine under test, so a product change on any of these vectors fails the replay.
_REVIEW_RELABELS = (
    ("R027", sorted(REVIEW_R027_POLICIES), "two_partial_no_role_excl", "union_possible", "no_policy_meets"),
    ("R100", REVIEW_SS7, "v37_partial_bad_policy_not_exported", "policy_flags_ok", "policy_not_in_export"),
    ("R100", REVIEW_SS7, "v37_partial_bad_policy_name_absent", "policy_flags_ok", "policy_not_in_export"),
    ("R100", REVIEW_SS7, "v37_partial_bad_policy_duplicated", "policy_flags_ok", "policy_duplicated"),
    ("R100", REVIEW_SS7, "v37_partial_flag_null_policy", "policy_flags_ok", "policy_flag_unusable"),
    ("R099", REVIEW_SS7, "nopreset_builtin_duplicated", "no_rules_configured", "policy_duplicated"),
    ("R099", REVIEW_SS7, "nopreset_builtin_flag_absent", "no_rules_configured", "policy_flag_unusable"),
    ("R099", REVIEW_SS7, "nopreset_builtin_flag_null", "no_rules_configured", "policy_flag_unusable"),
    ("R099", REVIEW_SS7, "nopreset_builtin_flag_string", "no_rules_configured", "policy_flag_unusable"),
    ("R099", REVIEW_SS7, "nopreset_builtin_missing_from_export", "no_rules_configured", "policy_not_in_export"),
    ("R099", REVIEW_SS7, "nopreset_policies_empty", "no_rules_configured", "policy_not_in_export"),
    ("R099", REVIEW_SS7, "nopreset_builtin_off", "no_rules_configured", "policy_flag_off"),
    ("R099", REVIEW_SS7[:2], "nopreset_builtin_one_off_one_null", "no_rules_configured", "policy_flag_off"),
    ("R099", REVIEW_SS7[2:], "nopreset_builtin_one_off_one_null", "no_rules_configured", "policy_flag_unusable"),
    ("R099", REVIEW_SS7, "v37_eop_empty_atp_ok_builtin_off", "no_rules_configured", "policy_flag_off"),
    ("R099", REVIEW_SS7, "nopreset_builtin_ok", "no_rules_configured", "policy_flags_ok"),
    ("R099", REVIEW_SS7, "nopreset_builtin_ok_junk_policy_elements", "no_rules_configured", "policy_flags_ok"),
    ("R099", REVIEW_SS7, "rules_both_empty_with_accepted_domains", "no_rules_configured", "policy_flags_ok"),
    ("R099", REVIEW_SS7, "v37_eop_empty_atp_ok_builtin_ok", "no_rules_configured", "policy_flags_ok"),
    ("R099", REVIEW_SS7, "v37_licence_true_rules_empty_all", "no_rules_configured", "policy_flags_ok"),
    ("W59", REVIEW_SS7, "v37_partial_bad_priority_absent_covering_ok", "policy_flags_ok", "rule_unusable"),
    ("W59", REVIEW_SS7, "v37_partial_bad_priority_string_covering_ok", "policy_flags_ok", "rule_unusable"),
)
# The reviewed reason text for a class whose cell has several in the catalogue (rule_unusable has three).
REVIEW_RELABEL_TEXTS = {"W59": REVIEW_W59_TEXT}
REVIEW_RELABELS = {f"constructed:{policy}:{name}": (label, was, now)
                   for label, policies, name, was, now in _REVIEW_RELABELS for policy in policies}


def review_relabel(vector: dict) -> tuple[dict, str | None, int]:
    """The kit vector as the product labels it after review lane rules-followup: (vector, class or None, change in
    agreement with the gold: -1, 0 or +1).

    R003: SS 7.x rows read built_in_protection_rules; a row without it gains a Built-In rule that excludes no one (what
    every v3.9.1 vector assumed), and its pack gold, which predates the section, is not compared (as licensed twins).
    R099 (a no_rules_configured label follows the Built-In policy), R100 (a met label where a partly scoped rule with an
    unreadable policy applies first is not assessed), W59 (bot review wave 2, item 59: a met label where a partly scoped
    rule of unknown Priority has a policy flag off is not assessed, since that rule may apply first) and R027
    (union_possible where every policy excludes the same role is no_policy_meets) move exactly the vectors in
    ``REVIEW_RELABELS``, each only from its original kit label (a row that already carries the reviewed label, as the
    shipped sample and s4 do, is left as it is; any other label is an error), to the reviewed cell and, where that cell
    has several reason texts, the reviewed text in ``REVIEW_RELABEL_TEXTS``. Every other vector keeps the kit's label,
    so any product difference fails the caller's own assertion."""
    policy = vector["policy"]
    override = REVIEW_RELABELS.get(vector["vector_id"])
    if policy not in REVIEW_BI_POLICIES and override is None:
        return vector, None, 0
    v, label = deepcopy(vector), None
    if policy in REVIEW_BI_POLICIES and "built_in_protection_rules" not in v["sections"]:
        v["sections"]["built_in_protection_rules"] = [dict(REVIEW_BI_ROW)]
        v.pop("pack_response_matches", None)
        v["flags"] = sorted({*v.get("flags", []), "built_in_section_added"})
        label = "R003"
    if override is None:
        return v, label, 0
    label, was_cell, now_cell = override
    if v["rule_cell"] == now_cell:
        return v, None, 0
    if v["rule_cell"] != was_cell:
        raise ValueError(f"review relabel precondition mismatch for {v['vector_id']}: {v['rule_cell']}")
    cell = row_for(policy)["cells"][now_cell]
    text = REVIEW_RELABEL_TEXTS.get(label)
    if text is None:
        assert len(cell["reason_texts"]) == 1, v["vector_id"]
        text = cell["reason_texts"][0]
    assert text in cell["reason_texts"], v["vector_id"]
    was = v["rule_verdict"] == v.get("gold_verdict")
    v.update(rule_verdict=cell["verdict"], rule_cell=now_cell, rule_reason_code=cell["reason_code"],
             rule_reason_text=text, rule_cited_sections=list(cell["cited"]))
    now = cell["verdict"] == v.get("gold_verdict")
    if now:
        v["disagreement"] = None
        v.pop("divergence_id", None)
    else:
        assert cell["verdict"] == "not_assessed", v["vector_id"]
        v["disagreement"], v["divergence_id"] = REVIEW_D24, "D24"
    return v, label, int(now) - int(was)


def review_vectors() -> list[dict]:
    """The constructed vectors review lane rules-followup added for the new SS 7.x Built-In cells (in the sample)."""
    return [v for v in _lines(SAMPLE) if ":review_r003_" in v["vector_id"]]


def override_gold(vector: dict, entry: dict | None):
    """The gold with ADDENDUM-A2's exact precondition-checked citation overlay: only the requirement_met ids change."""
    gold = deepcopy(vector.get("gold_response"))
    if entry is None:
        return gold
    claims = [c for c in (gold or {}).get("claims", []) if c["id"] == "requirement_met"]
    if (vector["policy"] != "MS.AAD.3.3v2" or entry["policy"] != vector["policy"] or gold is None
            or vector.get("disagreement") is not None or entry["claim_id"] != "requirement_met"
            or entry["evidence_section_order"] != ["authentication_method"] or entry["new_cited"] != ["e0", "e1"]
            or len(claims) != 1 or claims[0]["evidence_ids"] != entry["old_cited"]):
        raise ValueError("A2 override precondition mismatch for " + vector["vector_id"])
    claims[0]["evidence_ids"] = deepcopy(entry["new_cited"])
    return gold


def replay_one(vector: dict, entry: dict | None, tally: Counter, reached: set) -> None:
    """Replay one vector; raise AssertionError on any difference outside the documented classes."""
    policy, sections, vid = vector["policy"], vector["sections"], vector["vector_id"]
    row = row_for(policy)
    assert row is not None, vid
    # A2: the response ids use the current read-set projection, the override's section order, for the 190 AAD 3.3v2
    # labels whose source sections hold sections the rule no longer reads; the evidence itself is unchanged.
    order = list(entry["evidence_section_order"]) if entry is not None else list(sections)
    detail = precheck_policy(policy, sections, list(sections), value_rules=True, absent_fields=True, empty_lists=True)
    record = assess(policy, sections)
    checked(record)
    got = (record["verdict"], record["cell"], record["reason_code"], record["reason_text"],
           record["cited_sections"] or list(row["sections"]))
    want_text = vector["rule_reason_text"]
    if vector["rule_reason_code"] == D29_REASON_CODE and want_text == D29_V391_TEXT:
        want_text = D29_PRODUCT_TEXT
        tally["reason_text_d29"] += 1
    want = (vector["rule_verdict"], vector["rule_cell"], vector["rule_reason_code"], want_text,
            vector["rule_cited_sections"] or list(row["sections"]))
    if vid == D4_VECTOR:
        assert vector["divergence_id"] == "D15" and vector["gold_verdict"] == "not_met", vid
        want = D4_PRODUCT[:4] + (D4_PRODUCT[4] if record["cited_sections"] else list(row["sections"]),)
    assert got == want, vid
    assert detail["class"] == "value_rule" and detail["rule_id"] == row["rule_id"], vid
    assert (detail["cell"], detail["reason_code"], detail["reason_text"], detail["section"]) == (
        got[1], got[2], got[3], got[4]), vid
    assert row["cells"][got[1]]["verdict"] == got[0], vid
    reached.add((policy, got[1]))
    item = {"policy_id": policy, "criticality": vector.get("criticality") or POLICY_ITEMS[policy]["policy_item"]["criticality"]}
    legacy = precheck_response(detail, item, order, named_limitations=False)
    assert legacy == as_pack_response(record, item["criticality"], order, legacy=True), vid
    modern = precheck_response(detail, item, order)
    assert modern["claims"] == legacy["claims"], vid
    assert modern == {**as_pack_response(record, item["criticality"], order),
                      "limitations": modern["limitations"]}, vid
    disagreement = vector.get("disagreement")
    if vector["origin"] == "a2-constructed":
        assert disagreement == "NO GOLD (constructed A2 contract expectation)" and vector.get("gold_verdict") is None, vid
        tally["a2_constructed"] += 1
        return
    assert disagreement is None or disagreement.startswith("expected:"), vid
    if vid == D4_VECTOR:
        assert got[0] == vector["gold_verdict"], vid
        tally["d4_dkim_empty_equals_gold"] += 1
        return
    assert (disagreement is None) is (got[0] == vector["gold_verdict"]), vid
    tally["rule_equals_gold" if disagreement is None else "expected_divergence:" + vector["divergence_id"]] += 1
    gold = override_gold(vector, entry)
    if entry is not None:
        tally["a2_override_applied"] += 1
    if gold is None or disagreement is not None or vector.get("pack_response_matches") is None:
        # Licensed twins (packlic-train) keep the original pack gold, which predates the added licence section:
        # the spec compares no response for them (no pack_response_matches), only the rule fields above.
        tally["response_not_compared"] += 1
        return
    exempt = vector.get("parity_exempt", "")
    if legacy == gold:
        tally["response_equals_gold"] += 1
    elif exempt.startswith("D90") or exempt.startswith("D94"):
        # D90 (SS 3.2 no longer reads scuba_config) and the A2 unchanged AAD 3.3v2 controls: evidence ids only.
        assert [(c["id"], c["status"], c["value"]) for c in legacy["claims"]] == [
            (c["id"], c["status"], c["value"]) for c in gold["claims"]], vid
        assert (legacy["limitations"], legacy["recommendations"]) == (gold["limitations"], gold["recommendations"]), vid
        tally["parity_exempt:" + exempt[:3]] += 1
    else:
        raise AssertionError("response differs from gold outside a documented class: " + vid)


def replay(vectors, overrides: dict[str, dict]) -> tuple[Counter, set]:
    tally, reached = Counter(), set()
    for vector in vectors:
        vector, label, delta = review_relabel(vector)
        if label is not None:
            tally["review:" + label] += 1
            tally["review_gold_delta"] += delta
        replay_one(vector, overrides.get(vector["vector_id"]), tally, reached)
        tally["vectors"] += 1
    return tally, reached


def _overrides(path: Path) -> dict[str, dict]:
    entries = list(_lines(path))
    by_id = {entry["vector_id"]: entry for entry in entries}
    if len(by_id) != len(entries):
        raise ValueError("duplicate A2 override")
    return by_id


@pytest.fixture(scope="module")
def sample():
    return list(_lines(SAMPLE))


def test_sample_is_the_bounded_deterministic_selection_and_pinned(sample):
    manifest = json.loads(MANIFEST.read_text())
    assert sha256(SAMPLE.read_bytes()).hexdigest() == manifest["sample_sha256"]
    assert sha256(OVERRIDES.read_bytes()).hexdigest() == manifest["overrides_sha256"]
    assert len(sample) == manifest["rows"] == 2242 and 0 < len(sample) < 26898
    assert manifest["spec_version"] == "v3.9.1+A2" and manifest["source_vectors"] == 26898
    assert manifest["source_vectors_sha256"] == "3515b6facbac73091ef43bfa51b746e9265ac508909103ffcc016a5dab92cf4e"
    assert manifest["a2_vectors_sha256"] == "0351259550c0a87d27d65cfac8f98b8547334cbd1d94321af244ad06b622ac0b"
    assert manifest["a2_label_overrides_sha256"] == "74639d1775267bb7d8e3d7cdf777b5eac4449e636ec383c16e21f79b3d8e1fa1"
    assert len({v["vector_id"] for v in sample}) == len(sample)
    # No held-out test, pilot or sealed freeze row is ever carried.
    assert {v["source_kind"] for v in sample} <= {"constructed", "pack-train", "pack-validation", "packlic-train",
                                                  "pbi-pack-train", "pbi-pack-validation", "aad-pack-train",
                                                  "a2-constructed"}
    assert Counter(v["source_kind"] for v in sample) == manifest["by_source"]
    assert manifest["cells_reached"] == 1090 and manifest["policies"] == 102


def test_sample_replay_agrees_with_the_spec_on_every_cell(sample):
    overrides = _overrides(OVERRIDES)
    tally, reached = replay(sample, overrides)
    expected = {(policy, cell) for policy in rule_policies() for cell in cells_for(policy)}
    assert reached == expected and len(reached) == 1090
    assert tally["vectors"] == len(sample) == 2242
    assert not any(k.startswith("review:") for k in tally), "the shipped sample already carries the review labels"
    assert tally["a2_constructed"] == 3
    assert tally["a2_override_applied"] == len(overrides) == 3
    assert tally["reason_text_d29"] == 10
    assert tally["rule_equals_gold"] + tally["a2_constructed"] + sum(
        n for k, n in tally.items() if k.startswith("expected_divergence:")) == len(sample)
    assert {k for k in tally if k.startswith("expected_divergence:")}, "no documented divergence class was exercised"


def test_a2_constructed_vectors_are_exact_and_unmodified(sample):
    a2 = [v for v in sample if v["origin"] == "a2-constructed"]
    assert sorted(v["vector_id"] for v in a2) == [
        "a2-constructed:MS.SECURITYSUITE.1.3v1:built_in_protection_rule_non_object",
        "a2-constructed:MS.SECURITYSUITE.6.1v1:preset_scope_keys_absent",
        "a2-constructed:MS.SECURITYSUITE.6.2v1:preset_scope_keys_absent"]
    for vector in a2:
        before = deepcopy(vector)
        record = assess(vector["policy"], vector["sections"])
        assert (record["verdict"], record["cell"], record["reason_code"], record["reason_text"],
                record["cited_sections"]) == tuple(vector["rule_" + k] for k in (
                    "verdict", "cell", "reason_code", "reason_text", "cited_sections"))
        assert vector == before


def test_override_preconditions_reject_wrong_ids_policy_and_ids():
    vector = {"policy": "MS.AAD.3.3v2", "vector_id": "v", "disagreement": None,
              "gold_response": {"claims": [{"id": "requirement_met", "evidence_ids": ["e0", "e1", "e2"], "status": "unknown",
                                            "value": None}]}}
    entry = {"policy": "MS.AAD.3.3v2", "claim_id": "requirement_met", "evidence_section_order": ["authentication_method"],
             "new_cited": ["e0", "e1"], "old_cited": ["e0", "e1", "e2"]}
    assert override_gold(vector, entry)["claims"][0]["evidence_ids"] == ["e0", "e1"]
    assert vector["gold_response"]["claims"][0]["evidence_ids"] == ["e0", "e1", "e2"]
    for change in ({"old_cited": ["e0", "e9"]}, {"policy": "MS.AAD.3.5v2"}, {"new_cited": ["e0"]},
                   {"claim_id": "policy_criticality"}, {"evidence_section_order": ["scuba_config"]}):
        with pytest.raises(ValueError, match="A2 override"):
            override_gold(vector, {**entry, **change})
    with pytest.raises(ValueError, match="A2 override"):
        override_gold({**vector, "policy": "MS.AAD.1.1v1"}, entry)


KIT_HASHES = {
    "vectors.jsonl": "3515b6facbac73091ef43bfa51b746e9265ac508909103ffcc016a5dab92cf4e",
    "a2-vectors.jsonl": "0351259550c0a87d27d65cfac8f98b8547334cbd1d94321af244ad06b622ac0b",
    "a2-label-overrides.jsonl": "74639d1775267bb7d8e3d7cdf777b5eac4449e636ec383c16e21f79b3d8e1fa1",
}


def check_kit_hashes(vectors: Path, pins: dict[str, str] | None = None) -> None:
    """Fail (never skip) unless every kit file exists and matches its pinned sha256.

    `vectors` is the exact file that will be replayed; it is hashed against the vectors pin and
    the A2 companions are resolved beside it. `pins` defaults to the module-level `KIT_HASHES`,
    read at call time so a test can substitute it.
    """
    for name, pin in (KIT_HASHES if pins is None else pins).items():
        file = vectors if name == "vectors.jsonl" else vectors.parent / name
        if not file.is_file():
            raise AssertionError(f"replay kit file missing: {name}")
        digest = sha256(file.read_bytes()).hexdigest()
        if digest != pin:
            raise AssertionError(f"replay kit hash mismatch for {name}: {digest} != {pin}")


def _fake_kit(directory: Path) -> dict[str, str]:
    pins = {}
    for name in KIT_HASHES:
        data = name.encode()
        (directory / name).write_bytes(data)
        pins[name] = sha256(data).hexdigest()
    return pins


def test_kit_hashes_accept_matching_files(tmp_path):
    check_kit_hashes(tmp_path / "vectors.jsonl", _fake_kit(tmp_path))


@pytest.mark.parametrize("name", sorted(KIT_HASHES))
def test_kit_hashes_wrong_hash_in_any_file_fails(tmp_path, name):
    pins = _fake_kit(tmp_path)
    (tmp_path / name).write_bytes(b"changed")
    with pytest.raises(AssertionError, match="hash mismatch for " + re.escape(name)):
        check_kit_hashes(tmp_path / "vectors.jsonl", pins)


@pytest.mark.parametrize("name", sorted(KIT_HASHES))
def test_kit_hashes_missing_file_fails_and_never_skips(tmp_path, name):
    pins = _fake_kit(tmp_path)
    (tmp_path / name).unlink()
    with pytest.raises(AssertionError, match="missing: " + re.escape(name)):
        check_kit_hashes(tmp_path / "vectors.jsonl", pins)


def test_kit_hashes_selected_file_is_the_one_hashed(tmp_path):
    pins = _fake_kit(tmp_path)
    other = tmp_path / "other-vectors.jsonl"
    other.write_bytes(b"different")
    with pytest.raises(AssertionError, match="hash mismatch for vectors.jsonl"):
        check_kit_hashes(other, pins)


def _stop_after_hashing(monkeypatch):
    def reached(*args, **kwargs):
        raise RuntimeError("hashing passed")

    monkeypatch.setitem(globals(), "_overrides", reached)


def test_full_replay_hashes_the_selected_file_against_the_pins(tmp_path, monkeypatch):
    monkeypatch.setitem(globals(), "KIT_HASHES", _fake_kit(tmp_path))
    _stop_after_hashing(monkeypatch)
    monkeypatch.setenv(FULL_ENV, str(tmp_path / "vectors.jsonl"))
    with pytest.raises(RuntimeError, match="hashing passed"):
        test_full_v391_replay_acceptance()


def test_full_replay_rejects_a_different_selected_file_beside_a_valid_kit(tmp_path, monkeypatch):
    monkeypatch.setitem(globals(), "KIT_HASHES", _fake_kit(tmp_path))
    _stop_after_hashing(monkeypatch)
    other = tmp_path / "other-vectors.jsonl"
    other.write_bytes(b"different")
    monkeypatch.setenv(FULL_ENV, str(other))
    with pytest.raises(AssertionError, match="hash mismatch for vectors.jsonl"):
        test_full_v391_replay_acceptance()


def test_kit_hashes_pins_cover_all_three_files():
    assert sorted(KIT_HASHES) == ["a2-label-overrides.jsonl", "a2-vectors.jsonl", "vectors.jsonl"]


@pytest.mark.value_rule_acceptance
def test_full_v391_replay_acceptance():
    """The 26,898 vectors and ADDENDUM-A2's 3 constructed vectors and 190 overrides, one process, streamed."""
    path = os.getenv(FULL_ENV)
    if not path:
        pytest.skip(FULL_ENV + " unset (explicit acceptance job)")
    vectors = Path(path)
    directory = vectors.parent
    check_kit_hashes(vectors)
    overrides = _overrides(directory / "a2-label-overrides.jsonl")
    assert len(overrides) == 190

    def stream():
        yield from _lines(vectors)
        yield from _lines(directory / "a2-vectors.jsonl")
        yield from review_vectors()

    tally, reached = replay(stream(), overrides)
    expected = {(policy, cell) for policy in rule_policies() for cell in cells_for(policy)}
    assert reached == expected and len(reached) == 1090
    review = len(review_vectors())
    assert tally["vectors"] == 26898 + 3 + review and tally["a2_constructed"] == 3
    # The kit's own agreement counts, before review lane rules-followup moved some labels (review_relabel).
    review_equal = sum(v["disagreement"] is None for v in review_vectors())
    assert tally["rule_equals_gold"] - review_equal - tally["review_gold_delta"] == 19118
    assert sum(n for k, n in tally.items() if k.startswith("expected_divergence:")) - (review - review_equal) + tally[
        "review_gold_delta"] == 7779
    assert tally["d4_dkim_empty_equals_gold"] == 1
    assert tally["a2_override_applied"] == 190
    print("replay tally", json.dumps(dict(sorted(tally.items())), sort_keys=True))


# ---- Wave 2 bot review (items 49, 64): the relabel never copies the engine's answer ----

def _kit_label(vector_id, policy, cell, sections):
    spec = row_for(policy)["cells"][cell]
    return {"vector_id": vector_id, "policy": policy, "sections": sections, "rule_verdict": spec["verdict"],
            "rule_cell": cell, "rule_reason_code": spec["reason_code"], "rule_reason_text": spec["reason_texts"][0],
            "rule_cited_sections": list(spec["cited"]), "gold_verdict": spec["verdict"], "disagreement": None,
            "origin": "constructed", "source_kind": "constructed"}


def test_review_relabel_does_not_follow_a_wrong_shared_role_gap(monkeypatch):
    """A union_possible vector with different role exclusions keeps its kit label when the engine wrongly finds a
    shared-role gap, so the replay fails instead of accepting the engine's no_policy_meets."""
    from test_value_rules_aad_review import MFA, ca, ca_sections

    import azure_tenant_audit.value_rules.conditional_access as ca_rules
    sections = ca_sections(ca(MFA, users={"ExcludeRoles": ["synthetic-role-a"]}),
                           ca(MFA, users={"ExcludeRoles": ["synthetic-role-b"]}))
    vector = _kit_label("constructed:MS.AAD.3.2v2:synthetic_different_roles", "MS.AAD.3.2v2", "union_possible", sections)
    replay_one(review_relabel(vector)[0], None, Counter(), set())
    monkeypatch.setattr(ca_rules, "_shared_gap", lambda *args: "role")
    relabelled, label, delta = review_relabel(vector)
    assert (relabelled["rule_cell"], label, delta) == ("union_possible", None, 0)
    with pytest.raises(AssertionError):
        replay_one(relabelled, None, Counter(), set())


def test_review_relabel_takes_the_reviewed_cell_not_the_engine_cell(monkeypatch):
    """A listed R100 vector moves to its reviewed cell (policy_duplicated) even when the engine answers another
    not-assessed cell with the same verdict (policy_not_in_export), so that engine fault fails the replay."""
    policy = "MS.SECURITYSUITE.7.1v1"
    vector = _kit_label(f"constructed:{policy}:v37_partial_bad_policy_duplicated", policy, "policy_flags_ok",
                        {"built_in_protection_rules": [dict(REVIEW_BI_ROW)]})
    wrong = {**assess(policy, {}), "verdict": "not_assessed", "cell": "policy_not_in_export", "detail": {"partial_scope": True}}
    monkeypatch.setitem(globals(), "assess", lambda *args: wrong)
    relabelled, label, _ = review_relabel(vector)
    spec = row_for(policy)["cells"]["policy_duplicated"]
    assert label == "R100"
    assert (relabelled["rule_verdict"], relabelled["rule_cell"], relabelled["rule_reason_code"], relabelled["rule_reason_text"],
            relabelled["rule_cited_sections"]) == (spec["verdict"], "policy_duplicated", spec["reason_code"],
                                                   spec["reason_texts"][0], spec["cited"])


def test_review_relabel_checks_the_original_label():
    policy = "MS.SECURITYSUITE.7.1v1"
    vid = f"constructed:{policy}:v37_partial_bad_policy_duplicated"
    sections = {"built_in_protection_rules": [dict(REVIEW_BI_ROW)]}
    already = _kit_label(vid, policy, "policy_duplicated", sections)
    assert review_relabel(already) == (already, None, 0)
    with pytest.raises(ValueError, match="review relabel precondition mismatch"):
        review_relabel(_kit_label(vid, policy, "policy_flag_off", sections))


def test_review_relabel_w59_takes_the_reviewed_reason_text(monkeypatch):
    """A listed W59 vector moves to rule_unusable with the reviewed partly scoped Priority text, from the fixed table,
    even when the engine answers rule_unusable with another of the cell's texts."""
    policy = "MS.SECURITYSUITE.7.2v1"
    vector = _kit_label(f"constructed:{policy}:v37_partial_bad_priority_string_covering_ok", policy, "policy_flags_ok",
                        {"built_in_protection_rules": [dict(REVIEW_BI_ROW)]})
    spec = row_for(policy)["cells"]["rule_unusable"]
    other = next(t for t in spec["reason_texts"] if t != REVIEW_W59_TEXT)
    monkeypatch.setitem(globals(), "assess", lambda *args: {"cell": "rule_unusable", "reason_text": other})
    relabelled, label, delta = review_relabel(vector)
    assert (label, delta) == ("W59", -1)
    assert (relabelled["rule_verdict"], relabelled["rule_cell"], relabelled["rule_reason_code"],
            relabelled["rule_reason_text"], relabelled["rule_cited_sections"], relabelled["divergence_id"]) == (
        "not_assessed", "rule_unusable", spec["reason_code"], REVIEW_W59_TEXT, spec["cited"], "D24")
