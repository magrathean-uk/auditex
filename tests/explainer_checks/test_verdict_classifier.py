"""The 115 inherited classifier rows and seven focused controls, ported from S/C."""
import pytest
from . import verdict_classifier as vc
from .chk_a import check_a
from .chk_s import Output

class Stub:
    def __init__(self, verdict, requirement="", reason_text=""):
        self.verdict, self.requirement, self.reason_text = verdict, requirement, reason_text
        self.approved_lines_full, self.approved_lines_prompt = [], []
        self.shared = None  # real Context: res.shared.get(reason_code) is None for ordinary records


def run(verdict, text, steps=(), requirement="", reason_text=""):
    out = Output(obj={"explanation": text, "remediation_steps": list(steps), "evidence_refs": ["e0"]})
    return check_a(Stub(verdict, requirement, reason_text), out)


P, F = True, False
# (verdict, text, expected a-pass, note)
CASES = [
    # ---- the four tricky cases of the brief, per verdict
    ("not_met", "The tenant is not compliant.", P, "not compliant on not_met"),
    ("met", "The tenant is not compliant.", F, "not compliant on met"),
    ("met", "The tenant does not fail the requirement.", P, "does not fail on met (double negation)"),
    ("not_met", "The tenant does not fail the requirement.", F, "does not fail on not_met"),
    ("met", "There is no evidence of non-compliance.", P, "no evidence of non-compliance on met"),
    ("not_met", "There is no evidence of non-compliance.", F, "no evidence of non-compliance on not_met"),
    ("not_met", "The tenant would be compliant if EnableAdminConsentRequests were set to true.", P, "would be compliant if on not_met"),
    ("met", "The tenant would not be compliant if the setting were removed.", P, "would not be compliant if on met"),
    ("not_assessed", "The tenant would be compliant if the evidence were collected. No conclusion was reached either way.", F, "counterfactual hint on not_assessed"),
    # ---- met
    ("met", "The tenant is compliant with the requirement.", P, ""),
    ("met", "The requirement is met.", P, ""),
    ("met", "So the requirement is met and the tenant complies.", P, ""),
    ("met", "The evidence is consistent with the baseline requirement.", P, "consistent with"),
    ("met", "The evidence is not consistent with the baseline requirement.", F, ""),
    ("met", "That is inconsistent with the requirement.", F, ""),
    ("met", "This differs from the baseline requirement.", F, ""),
    ("met", "The requirement is not met.", F, ""),
    ("met", "This does not meet the requirement.", F, ""),
    ("met", "The tenant doesn't meet the requirement.", F, "contraction"),
    ("met", "The tenant isn't compliant.", F, "contraction"),
    ("met", "The setting fails to meet the baseline.", F, "fails to"),
    ("met", "The tenant does not fail to meet the baseline.", P, "does not fail to"),
    ("met", "The tenant never fails to comply.", P, "never fails to"),
    ("met", "The evidence shows the tenant fails the requirement.", F, ""),
    ("met", "The tenant violates the requirement.", F, ""),
    ("met", "No violations were found.", P, "no + violations"),
    ("met", "There are no issues with this setting.", P, ""),
    ("met", "This falls short of the requirement.", F, ""),
    ("met", "The tenant is out of compliance.", F, ""),
    ("met", "The tenant is not in compliance.", F, ""),
    ("met", "The tenant is in compliance.", P, ""),
    ("met", "The policy does not pass.", F, ""),
    ("met", "The policy passes.", P, ""),
    ("met", "It cannot be said that the tenant is compliant.", F, "cannot ... compliant across fillers"),
    ("met", "The tenant is no longer compliant.", F, "no longer"),
    ("met", "The tenant is not yet compliant.", F, "not yet"),
    ("met", "The tenant is not necessarily non-compliant.", P, "not necessarily non-compliant"),
    ("met", "The tenant is not non-compliant.", P, "not non-compliant"),
    ("met", "The tenant is mostly compliant.", F, "hedged positive on met"),
    ("met", "The tenant is probably compliant.", F, "hedged positive on met"),
    ("met", "The tenant appears to be compliant.", F, "appears to be compliant"),
    ("met", "The tenant may be compliant.", F, "may be compliant"),
    ("met", "The tenant is probably non-compliant.", F, "hedged negative on met"),
    ("met", "The control is secure and correctly configured.", P, ""),
    ("met", "The control is not secure.", F, ""),
    ("met", "The control is insecure.", F, ""),
    ("met", "The control is vulnerable to abuse.", F, ""),
    ("met", "Users may not consent to applications on their own behalf.", P, "'may not' is permission, not a hedge on a predicate"),
    ("met", "To be compliant the tenant needs to block legacy authentication.", P, "purposive 'to be compliant' is not an assertion"),
    ("met", "This policy was not assessed.", F, "no-conclusion wording on met"),
    ("met", "No conclusion was reached.", F, ""),
    ("met", "This policy does not apply here.", F, "not-applicable wording on met"),
    ("met", "The evidence shows the setting is enabled.", P, "no compliance words"),
    ("met", "The tenant is compliant, but the setting fails to apply to guests.", P, "'fail to' followed by a non-lexicon verb is not a compliance assertion"),
    # ---- unicode and spacing evasions
    ("met", "The tenant is non‑compliant.", F, "non-breaking hyphen"),
    ("met", "The tenant is non\u2013compliant.", F, "en dash"),
    ("met", "The tenant is non​-compliant.", F, "zero width space"),
    ("met", "The tenant is non compliant.", F, "space instead of hyphen"),
    ("met", "The tenant is n\u043et compliant.", F, "Cyrillic o in 'not'"),
    ("met", "The tenant is not complіant.", F, "Cyrillic i in 'compliant' (folded)"),
    ("met", "The tenant is ｎｏｔ compliant.", F, "full-width letters"),
    ("met", "The tenant is NOT COMPLIANT.", F, "capitals"),
    ("met", "The tenant isn’t compliant.", F, "curly apostrophe"),
    ("not_met", "The tenant is NON-COMPLIANT.", P, "capitals"),
    ("not_met", "The tenant is noncompliant.", P, "joined"),
    # ---- not_met
    ("not_met", "The requirement is not met.", P, ""),
    ("not_met", "The tenant does not meet the requirement.", P, ""),
    ("not_met", "The tenant fails the requirement.", P, ""),
    ("not_met", "That differs from the baseline requirement.", P, ""),
    ("not_met", "The tenant is compliant.", F, ""),
    ("not_met", "The tenant complies.", F, ""),
    ("not_met", "The tenant meets the requirement.", F, ""),
    ("not_met", "The requirement is met.", F, ""),
    ("not_met", "That is consistent with the baseline requirement.", F, ""),
    ("not_met", "No violations were found.", F, ""),
    ("not_met", "There is nothing to fix.", F, ""),
    ("not_met", "No further action is required.", F, ""),
    ("not_met", "The control is secure.", F, ""),
    ("not_met", "The control is not secure.", P, ""),
    ("not_met", "The tenant is mostly compliant.", F, ""),
    ("not_met", "The tenant probably fails the requirement.", F, "hedged negative softens a fixed verdict"),
    ("not_met", "The tenant may not meet the requirement.", F, ""),
    ("not_met", "The tenant largely satisfies the requirement.", F, ""),
    ("not_met", "The setting is not compliant and the policy fails.", P, "nearest-predicate negation binding"),
    ("not_met", "It fails to meet the requirement.", P, ""),
    ("not_met", "It does not fail to meet the requirement.", F, ""),
    ("not_met", "To be compliant, enable the setting.", P, "purposive"),
    ("not_met", "In order to meet the requirement, enable the setting.", P, "purposive"),
    ("not_met", "It would be compliant once the setting is changed.", P, ""),
    ("not_met", "If the setting were enabled, the tenant would comply.", P, "sentence-initial if"),
    ("not_met", "The tenant is compliant if the setting is enabled.", P, "right-context if"),
    ("not_met", "The tenant should be compliant.", P, "should: irrealis"),
    ("not_met", "The requirement says the tenant must be compliant.", P, "must: irrealis"),
    ("not_met", "This policy was not assessed.", F, ""),
    ("not_met", "This policy is not applicable.", F, ""),
    ("not_met", "The exemption does not apply to guests.", P, "'does not apply' without a policy subject is not a verdict word"),
    # ---- not_assessed
    ("not_assessed", "No conclusion was reached either way, so this policy was not assessed.", P, ""),
    ("not_assessed", "The evidence is missing. This policy cannot be assessed.", P, ""),
    ("not_assessed", "The tenant is compliant.", F, ""),
    ("not_assessed", "The tenant is not compliant.", F, ""),
    ("not_assessed", "The tenant probably fails. No conclusion was reached.", F, ""),
    ("not_assessed", "The policy might pass. No conclusion was reached.", F, ""),
    ("not_assessed", "The evidence seems fine. No conclusion was reached.", F, "'seems fine'"),
    ("not_assessed", "The evidence is missing and the tenant is probably secure. No conclusion was reached.", F, ""),
    ("not_assessed", "Evidence is missing, so the result is unknown.", F, "no explicit no-conclusion phrase"),
    ("not_assessed", "No conclusion was reached; the tenant likely does what the policy asks.", F, "guess words"),
    ("not_assessed", "No conclusion was reached; it is not possible to say whether the tenant complies.", F, "mentions compliance in any form: conservative by design"),
    ("not_assessed", "This policy does not apply here. No conclusion was reached.", F, "not-applicable wording on not_assessed"),
    ("not_assessed", "The data is unavailable: domain_settings holds no domains. No conclusion was reached either way, so this policy was not assessed.", P, ""),
    # ---- not_applicable
    ("not_applicable", "This policy does not apply here because the environment is GCC.", P, ""),
    ("not_applicable", "Not applicable: the policy covers commercial tenants only.", P, ""),
    ("not_applicable", "This policy does not apply, so the tenant is compliant.", F, ""),
    ("not_applicable", "This policy does not apply and the tenant is not compliant.", F, ""),
    ("not_applicable", "The policy covers commercial tenants only.", F, "missing phrase"),
    ("not_applicable", "This policy does not apply here. No conclusion was reached.", F, "no-conclusion wording"),
]


@pytest.mark.parametrize("verdict,text,want,note", CASES)
def test_classifier(verdict, text, want, note):
    result = run(verdict, text)
    assert result["pass"] is want, (note, result)


def test_quoted_requirement_exempt_and_reported():
    req = "The tenant is compliant with the policy if X is less than or equal to one."
    result = run("not_met", "What the evidence shows: x is wrong. That differs from the baseline requirement: " + req, requirement=req)
    assert result["pass"]
    assert any("exempt_quote" in note for note in result["notes"])


def test_conditional_without_quote_exemption():
    assert run("not_met", "The tenant is compliant with the policy if X is less than or equal to one.")["pass"]


@pytest.mark.parametrize("text,sign,negs,lemma", [
    ("The tenant is not non-compliant.", 1, 1, None),
    ("The tenant does not fail to meet the baseline.", 1, None, "meet"),
    ("The tenant is not enabled for guests but complies.", 1, 0, None),
    ("The tenant is not compliant at all in the current state of the tenant.", -1, None, None),
    ("The setting is not enabled in the tenant after all so the tenant complies.", 1, None, None),
])
def test_classifier_scope(text, sign, negs, lemma):
    result = vc.analyse(text)
    assert len(result) == 1
    assert (result[0].sign > 0) == (sign > 0)
    if negs is not None:
        assert result[0].negs == negs
    if lemma is not None:
        assert result[0].lemma == lemma
