"""Inherited 75 checker cases, plus strict contract negative controls."""
import copy
import json

import pytest

from .chk_b import check_b
from .chk_c import check_c
from .chk_d import check_d
from .chk_e import check_e, nav_targets, paraphrase_eval, tok_key, verbatim_cover
from .chk_e2 import check_e2
from .chk_e3 import check_e3
from .chk_s import Output, check_s
from .context import Context
from .corpus import base_pairs as local_pairs
from .driver import run_pair
from .fault_fixtures import fault_pair
from .specifics import extract, identifiers
from .support import local_resources, wordlist


def out(o):
    return Output(obj=o)


def codes(result):
    return sorted({f["code"] for f in result["failures"]})


def inherited_cases():
    PAIRS = {}
    for p in local_pairs():
        PAIRS.setdefault(p["prompt"]["record"]["verdict"], []).append(p)
    RES = local_resources()
    RESULTS = []

    def ok(name, cond, detail=""):
        RESULTS.append((name, bool(cond), detail))

    def mk(verdict, pred=lambda p: True, nth=0):
        p = [p for p in PAIRS[verdict] if pred(p)][nth]
        return p, Context(p, RES)

    # ---------------------------------------------------------------- specifics tokenisation rules
    def classes(t):
        return sorted((s.cls, s.key) for s in extract(t))


    ok("guid", ("guid", "11111111-2222-3333-4444-555555555555") in classes("Group 11111111-2222-3333-4444-555555555555 here"))
    ok("masked email is one email token", ("email", "***@contoso.com") in classes("Contact ***@contoso.com now") and not any(c == "domain" for c, _ in classes("Contact ***@contoso.com")))
    ok("email domain added as identifier", "contoso.com" in identifiers("a@contoso.com"))
    ok("domain", ("domain", "mail.contoso.com") in classes("the host mail.contoso.com"))
    ok("url", any(c == "url" for c, _ in classes("see https://example.org/x")))
    ok("ipv4 with prefix", ("ipv4", "10.0.0.0/8") in classes("range 10.0.0.0/8"))
    ok("policy id is not a number or a domain", classes("see MS.AAD.3.2v1 now") == [("policy_id", "ms.aad.3.2v1")], classes("see MS.AAD.3.2v1 now"))
    ok("cmdlet", ("cmdlet", "get-mguser") in classes("Run Get-MgUser first"))
    ok("Sign-in and Set-up are not cmdlets", not any(c == "cmdlet" for c, _ in classes("Sign-in and Set-up and Check-in")))
    ok("parameter with en dash is folded", ("parameter", "-auditdisabled") in classes("use \u2013AuditDisabled"))
    ok("snake and camel", ("snake", "domain_settings") in classes("the domain_settings section") and ("camel", "enableadminconsentrequests") in classes("EnableAdminConsentRequests is false"))
    ok("M365Environment is camel", ("camel", "m365environment") in classes("M365Environment is commercial"))
    ok("quoted string", ("quoted", "magic mode") in classes('the setting "Magic Mode" is on'))
    ok("numbers: digits, thousands, decimal", sorted(k for c, k in classes("30 days, 1,200 users, 2.5 hours") if c == "number") == ["1200", "2.5", "30"])
    ok("number words two and above, compound", [k for c, k in classes("twenty-one policies and seven groups") if c == "number"] == ["21", "7"])
    ok("'one' is not extracted (documented limit)", not any(c == "number" for c, _ in classes("one policy")))
    ok("Microsoft 365, e1, v37 are not numbers", not any(c == "number" for c, _ in classes("Microsoft 365 evidence e1 in v37 and M365")))
    ok("hex needs a digit and a letter", ("hex", "3fa85f64a1b2") in classes("object 3fa85f64a1b2") and not any(c == "hex" for c, _ in classes("the decaded face")))
    ok("case folding: FALSE equals false", classes("FALSE") == classes("false"))

    # ---------------------------------------------------------------- S
    p, c = mk("met")
    o = p["output"]
    ok("S passes a clean output", check_s(c, out(o))["pass"])
    ok("S fails extra key", "keys" in codes(check_s(c, out(dict(o, x=1)))))
    ok("S fails refs not in prompt", "refs_not_in_prompt" in codes(check_s(c, out(dict(o, evidence_refs=["e0", "e77"])))))
    ok("S fails empty refs", "refs_empty" in codes(check_s(c, out(dict(o, evidence_refs=[])))))
    ok("S fails steps on met", "steps_for_met" in codes(check_s(c, out(dict(o, remediation_steps=["Do it."])))))
    ok("S strict parse: fenced JSON fails", not check_s(c, Output(text="```json\n" + json.dumps(o) + "\n```"))["pass"])
    ok("S strict parse: duplicate keys fail", not check_s(c, Output(text='{"explanation":"a","explanation":"b","remediation_steps":[],"evidence_refs":["e0"]}'))["pass"])
    ok("S fails em dash, passes en dash", "em_dash" in codes(check_s(c, out(dict(o, explanation="Fine \u2014 really."))))
       and check_s(c, out(dict(o, explanation="Range 2\u20133 items.")))["pass"])
    ok("S counts sentences: abbreviation e.g. is protected", check_s(c, out(dict(o, explanation="First, e.g. this one. Second here. Third one.")))["pass"])

    # ---------------------------------------------------------------- b
    ok("b passes the template render", check_b(c, out(o))["pass"])
    ok("b: invented number fails, exact class", (lambda r: not r["pass"] and r["klass"] == "exact")(check_b(c, out(dict(o, explanation=o["explanation"] + " Set 4242.")))))
    numeric_pair = copy.deepcopy(p)
    numeric_pair["prompt"]["data"]["evidence"][1]["observed"] = {"days": 30}
    numeric_ctx = Context(numeric_pair, RES)
    ok("b: a number present in the view passes", check_b(numeric_ctx, out(dict(o, explanation="The evidence records 30 days.")))["pass"])
    numeric_pair["prompt"]["data"]["evidence"][1]["observed"] = [{}, {}, {}, {}, {}, {}, {}]
    count_result = check_b(Context(numeric_pair, RES), out(dict(o, explanation="The evidence contains 7 items.")))
    ok("b: derived count equal to a list length is allowed and noted", count_result["pass"] and any("derived count" in note for note in count_result["notes"]))
    ok("b: case-insensitive match of a name in the view", check_b(c, out(dict(o, explanation="The CONDITIONAL_ACCESS_POLICIES evidence is present.")))["pass"])

    # ---------------------------------------------------------------- c
    na, cna = mk("not_assessed", lambda p: p["prompt"]["record"]["cited_sections"])
    oa = na["output"]
    ok("c passes the template not_assessed render", check_c(cna, out(oa))["pass"], check_c(cna, out(oa))["failures"][:2])
    ok("c fails when a cited section is not named", "section_not_named" in codes(check_c(cna, out(dict(oa, explanation=oa["explanation"].replace(cna.cited[0], "the data"), remediation_steps=[s.replace(cna.cited[0], "the data") for s in oa["remediation_steps"]])))))
    ok("c fails without steps", "no_steps" in codes(check_c(cna, out(dict(oa, remediation_steps=[])))))
    ok("c fails a tenant-changing step", "tenant_changing_step" in codes(check_c(cna, out(dict(oa, remediation_steps=["Delete the policy and check the evidence."])))))
    ok("c fails a guess", not check_c(cna, out(dict(oa, explanation="No conclusion was reached; the tenant is probably compliant. " + cna.cited[0])))["pass"])
    ok("c passes trivially for met", check_c(c, out(o))["pass"])

    # ---------------------------------------------------------------- d
    ok("d passes the template render", check_d(c, out(o))["pass"])
    ok("d fails an e-mail absent from the prompt", "invented_identifier" in codes(check_d(c, out(dict(o, explanation="Contact x@nowhere.example.")))))
    ok("d fails a GUID absent from the prompt", not check_d(c, out(dict(o, explanation="Group 11111111-2222-3333-4444-555555555555.")))["pass"])
    ok("d fails an infrastructure word", "infrastructure_word" in codes(check_d(c, out(dict(o, explanation="The Rego said so.")))))
    ok("d fails a canary marker", not check_d(c, out(dict(o, explanation="zqcanaryfield")))["pass"])
    ok("d reports a builder canary leak", "builder_canary_leak" in codes(check_d(c, out(o), canary={"ok": False, "leaks": ["P"]})))
    withterms = [q for q in PAIRS["met"] + PAIRS["not_met"] + PAIRS["not_assessed"] if q["prompt"]["full_record_terms"]]
    if withterms:
        q = withterms[0]
        cq = Context(q, RES)
        t = q["prompt"]["full_record_terms"][0]
        ok("d fails a full-record term absent from the view", "leak_full_record_term" in codes(check_d(cq, out(dict(q["output"], explanation="The value is " + t + ".")))), t)
    else:
        raise AssertionError("unit sample must include a full-record term")

    # ---------------------------------------------------------------- e
    nmp, cnm = mk("not_met", lambda p: len(p["output"]["remediation_steps"]) >= 2 and not p["output"]["remediation_steps"][-1].startswith("The baseline Instructions"))
    on = nmp["output"]
    ok("e passes the template not_met render (verbatim)", check_e(cnm, out(on))["pass"], check_e(cnm, out(on))["failures"][:2])
    s0 = on["remediation_steps"][0]
    toks = s0.split()
    ok("e: verbatim cover finds the whole step", verbatim_cover(cnm.stream_prompt, [tok_key(t) for t in toks if tok_key(t)]) is not None)
    clause = "Select the sharing policy, then select Save."
    from .context import Stream
    ok("e: a truncation at a clause boundary is verbatim", verbatim_cover(Stream([(clause, False)]), [tok_key(t) for t in "Select the sharing policy,".split()]) is not None)
    ok("e: reordering two steps' words fails the cover", verbatim_cover(cnm.stream_prompt, [tok_key(t) for t in reversed(toks) if tok_key(t)]) is None)
    ok("e: invented step fails", not check_e(cnm, out(dict(on, remediation_steps=on["remediation_steps"] + ["Restart the mail flow service on every server."])))["pass"])
    ok("e: navigation target outside vocabulary is exact failure", any(f["klass"] == "exact" for f in check_e(cnm, out(dict(on, remediation_steps=["Open the Imaginary Blade and select Fix Everything."])))["failures"]))
    ok("e: nav_targets splits a '>' path and keeps a lower-case tail (descriptor words stop it)", nav_targets("Select Meetings > Meeting policies. Click Save.") == [("Meetings", "Meetings"), ("Meeting", "Meeting"), ("Save", "Save")] and nav_targets("Select Reports > Quarterly numbers view.") == [("Reports", "Reports"), ("Quarterly", "Quarterly numbers view")], nav_targets("Select Meetings > Meeting policies. Click Save."))
    long_unit = "Under the Content sharing section, ensure External participants can give or request control is set to the Off position and select Save."
    ok("e: paraphrase rule rejects a state flip", not paraphrase_eval(long_unit.replace("Off", "On"), [long_unit])[0], paraphrase_eval(long_unit.replace("Off", "On"), [long_unit]))
    ok("e: paraphrase rule accepts a light reword", paraphrase_eval(long_unit.replace("Under", "Beneath"), [long_unit])[0], paraphrase_eval(long_unit.replace("Under", "Beneath"), [long_unit]))
    ok("e: paraphrase rule rejects a dropped negation", not paraphrase_eval("Turn on the sharing policy for external participants in the global meeting policy now.", ["Do not turn on the sharing policy for external participants in the global meeting policy now."])[0])
    ok("e: paraphrase rule rejects short non-verbatim steps", not paraphrase_eval("Click Save quickly.", ["Click Save."])[0])
    ok("e: met with a step fails", not check_e(c, out(dict(o, remediation_steps=["Review settings."])))["pass"])

    # ---------------------------------------------------------------- DF-1: markdown in customer text (S)
    ok("S fails single-asterisk emphasis in a step", "markdown_emphasis" in codes(check_s(cnm, out(dict(on, remediation_steps=["For Allow use, select *No*."])))))
    ok("S fails a backtick and bold in the explanation", {"markdown_backtick", "markdown_bold_or_underscore"} <= set(codes(check_s(cnm, out(dict(on, explanation="Use `p=reject` and **this**."))))))
    ok("S passes the shipped not_met render (no markdown)", check_s(cnm, out(on))["pass"], check_s(cnm, out(on))["failures"][:2])

    # ---------------------------------------------------------------- e2: a not_met item carries a remediation step
    ok("e2 passes the template not_met render", check_e2(cnm, out(on))["pass"])
    ok("e2 fails an empty list", codes(check_e2(cnm, out(dict(on, remediation_steps=[])))) == ["not_met_without_steps"])
    cont = f"The baseline Instructions for {cnm.policy_id} continue with further steps; follow them in order after these."
    ok("e2 fails a list holding only the continue sentence", codes(check_e2(cnm, out(dict(on, remediation_steps=[cont])))) == ["not_met_only_continue_step"])
    ok("e2 passes one real step plus the continue sentence", check_e2(cnm, out(dict(on, remediation_steps=[on["remediation_steps"][0], cont])))["pass"])
    ok("e2 is silent for the other verdicts", check_e2(c, out(o))["pass"] and check_e2(cna, out(oa))["pass"])

    # ---------------------------------------------------------------- e3: a step is a full sentence or command
    ok("e3 passes the template not_met render", check_e3(cnm, out(on))["pass"], check_e3(cnm, out(on))["failures"][:2])
    longstep = next((x for x in on["remediation_steps"] if len(x.split()) >= 12 and x.rstrip().endswith(".")), None)
    if longstep:
        w = longstep.split()
        ok("e3 fails a tail fragment standing alone", not check_e3(cnm, out(dict(on, remediation_steps=[" ".join(w[-2:])])))["pass"])
        ok("e3 fails a step that starts mid-sentence in lower case", not check_e3(cnm, out(dict(on, remediation_steps=[" ".join(w[4:])[0].lower() + " ".join(w[4:])[1:]])))["pass"])
        ok("e3 fails a step cut off without a sentence end", not check_e3(cnm, out(dict(on, remediation_steps=[" ".join(w[:-4]).rstrip(",;:")])))["pass"])
    ok("e3 fails the old tail 'and applications.'", not check_e3(cnm, out(dict(on, remediation_steps=["and applications."])))["pass"])
    ok("e3 fails a one-word paraphrase step", not check_e3(cnm, out(dict(on, remediation_steps=["Groups."])))["pass"])
    ok("e3 accepts the fixed continue sentence", check_e3(cnm, out(dict(on, remediation_steps=[on["remediation_steps"][0], cont])))["pass"])
    ok("e3 accepts a command line as a step (no sentence end needed)", check_e3(cnm, out(dict(on, remediation_steps=["Resolve-DnsName _dmarc.example.com txt"])))["pass"])
    forced_pair = next((q for q in PAIRS["not_met"] if any(len(x.split()) >= 5 and x[:1].islower() for x in q["output"]["remediation_steps"])), None)
    if forced_pair:
        ok("e3 accepts the continuation piece of a sentence that cannot fit 30 words", check_e3(Context(forced_pair, RES), out(forced_pair["output"]))["pass"], check_e3(Context(forced_pair, RES), out(forced_pair["output"]))["failures"][:2])
    else:
        raise AssertionError("unit sample must include a forced long-unit split")
    return RESULTS


@pytest.mark.parametrize("name,passed,detail", inherited_cases(), ids=lambda x: x if isinstance(x,str) else None)
def test_inherited_checkers(name, passed, detail):
    assert passed, (name, detail)


@pytest.mark.parametrize("field,value", [
    ("evidence_refs", ["e0", "e0"]),
    ("evidence_refs", ["e2", "e0"]),
    ("explanation", "Visit https://unapproved.example/path."),
    ("explanation", "**Bold** is markdown."),
    ("explanation", "Bad\x01control."),
    ("explanation", "The tenant is c\u043empliant."),
    ("explanation", "One. Two. Three. Four."),
    ("explanation", " ".join(["word"] * 81)),
    ("remediation_steps", ["Word " * 31]),
    ("remediation_steps", ["Do this."] * 7),
])
def test_structure_negative_controls(field, value):
    pair = fault_pair()
    pair["output"][field] = value
    assert run_pair(pair, local_resources())["S"]["pass"] is False


@pytest.mark.parametrize("text", [
    '{"explanation":"a","explanation":"b"}', '{"x":NaN}', '{"x":Infinity}',
    '[]', 'null', 'true', '\ufeff{}', '{} trailing', '```json\n{}\n```',
])
def test_invalid_json_only_s_fails_others_explicitly_skip(text):
    pair = fault_pair()
    pair["output_text"] = text  # raw candidate cannot be bypassed by the output object
    result = run_pair(pair, local_resources())
    assert result["S"]["pass"] is False
    assert all(value["pass"] is None for key, value in result.items() if key != "S")


def test_shared_fault_all_eight_pass():
    pair = fault_pair()
    original = copy.deepcopy(pair)
    result = run_pair(pair, local_resources())
    assert all(value["pass"] is True for value in result.values()), result
    assert pair == original


@pytest.mark.parametrize("field,value", [
    ("verdict", "met"), ("verdict", "not_met"), ("cell", "rule_evaluation_failed"),
    ("reason_text", "Data unavailable: missing evidence."),
    ("cited_sections", ["default_app_management_policy", "app_management_policies"]),
    ("cited_sections", ["app_management_policies"]),
    ("policy_id", "MS.UNKNOWN.1.1v1"),
])
def test_shared_invalid_metadata_rejected_by_a_c_e(field, value):
    pair = fault_pair()
    pair["prompt"]["record"][field] = value
    pair["prompt"]["data"][field] = value
    result = run_pair(pair, local_resources())
    assert all(result[check]["pass"] is False for check in ("a", "c", "e")), result


@pytest.mark.parametrize("field,value", [
    ("explanation", "The evidence is missing. No conclusion was reached."),
    ("explanation", "Not assessed: Auditex could not evaluate this policy on the collected evidence. This is a product fault, not a tenant setting. Exception: diagnostic."),
    ("remediation_steps", []),
    ("remediation_steps", ["Collect the app_management_policies evidence."]),
    ("remediation_steps", ["Enable the baseline setting."]),
    ("remediation_steps", ["Report this fault to the product team at contact+auditex@magrathean.uk.", "Print the exception diagnostic."]),
])
def test_fault_hostile_output(field, value):
    pair = fault_pair()
    pair["output"][field] = value
    result = run_pair(pair, local_resources())
    checks = ("a", "c", "e") if field == "remediation_steps" else ("a", "c")
    assert all(result[check]["pass"] is False for check in checks), result


@pytest.mark.parametrize("code", ["rule_evaluation_failed_counterfeit", "data_unusable_section_not_a_list", "unknown"])
def test_counterfeit_fault_does_not_bypass_missing_evidence(code):
    pair = fault_pair()
    pair["prompt"]["record"]["reason_code"] = code
    pair["prompt"]["data"]["reason_code"] = code
    result = run_pair(pair, local_resources())
    assert result["a"]["pass"] is False
    assert result["c"]["pass"] is False
    assert result["e"]["pass"] is False


def test_missing_or_empty_wordlist_fails_setup(tmp_path):
    with pytest.raises(FileNotFoundError):
        wordlist(tmp_path / "missing")
    empty = tmp_path / "empty"
    empty.write_text("")
    with pytest.raises(ValueError):
        wordlist(empty)
    from .context import Resources
    resources = local_resources()
    with pytest.raises(ValueError):
        Resources(resources.bl, resources.template, resources.collection, set(), set())


def test_dictionary_independent_proper_name_detection(monkeypatch):
    # No code path may open /usr/share/dict/words, even when it exists.
    import builtins
    original = builtins.open
    def guarded(path, *args, **kwargs):
        assert str(path) != "/usr/share/dict/words"
        return original(path, *args, **kwargs)
    monkeypatch.setattr(builtins, "open", guarded)
    pair = fault_pair()
    pair["output"]["explanation"] = "Zorblax has evidence."
    assert "proper_noun_not_in_view" in codes(run_pair(pair, local_resources())["b"])
    pair["output"]["explanation"] = "Evidence was collected."
    assert run_pair(pair, local_resources())["b"]["pass"]


def test_training_and_raw_record_leaks_are_classified():
    pair = fault_pair()
    pair["output"]["explanation"] = "Contact training-only.example."
    assert "memorised_training_identifier" in codes(run_pair(pair, local_resources())["d"])
    pair["prompt"]["full_record_terms"] = ["hidden-record.example"]
    pair["output"]["explanation"] = "Contact hidden-record.example."
    assert "leak_full_record_identifier" in codes(run_pair(pair, local_resources())["d"])


def test_ordinary_not_assessed_keeps_missing_evidence_rules():
    pair = next(p for p in local_pairs() if p["prompt"]["record"]["verdict"] == "not_assessed")
    pair["output"] = fault_pair()["output"]
    result = run_pair(pair, local_resources())
    assert not result["a"]["pass"] and not result["c"]["pass"] and not result["e"]["pass"]


def test_independent_baseline_own_text_and_all_xref_ranges():
    import re

    from . import baseline_text
    from .support import LOCAL, raw_baselines, read_json
    raw = {name: text for name, text in raw_baselines().items() if re.search(r'^#{2,4}\s+MS\.', text, re.M)}
    assert raw, "the pinned raw baseline fixtures are required"
    parsed = baseline_text.load(raw)["policies"]
    expected = read_json(LOCAL / "baseline-expectations.json.gz")
    def alnum(text):
        return re.sub(r"[^a-z0-9]", "", text.casefold())
    assert len(parsed) == len(expected["policies"]) == 109
    for pid, policy in expected["policies"].items():
        own = [u["text"] for u in policy["instructions"] if u["policy_id"] == pid]
        assert alnum(" ".join(own)) == alnum(" ".join(parsed[pid]["lines"])), pid
        assert alnum(policy["requirement"]) == alnum(parsed[pid]["statement"]), pid
    assert len(expected["xrefs"]) == 16
    for xref in expected["xrefs"]:
        pid, target, labels = xref["policy_id"], xref["target"], xref["labels"]
        source = next(text for text in raw.values() if f"{target} Instructions" in text)
        selected = baseline_text.instruction_range(source, target, labels)
        target_units = [u["text"] for u in expected["policies"][pid]["instructions"] if u["policy_id"] == target]
        assert selected and target_units, pid
        assert alnum(" ".join(selected)) == alnum(" ".join(target_units)), (pid, labels)


def test_independent_range_keeps_nested_children_and_preamble():
    from .baseline_text import instruction_range
    raw = '''## MS.TEST.1.1v1
A requirement.
### MS.TEST.1.1v1 Instructions
Count the entries first.
1. First step.
   1. Nested first.
2. Second step.
   - Nested second.
3. Last step.
'''
    assert instruction_range(raw, "MS.TEST.1.1v1", ["2"]) == ["Second step.", "Nested second."]
    assert instruction_range(raw, "MS.TEST.1.1v1")[0] == "Count the entries first."


def test_resource_injection_and_cache_do_not_hide_edited_evidence():
    pair = fault_pair()
    resources = local_resources()
    pair["output"]["explanation"] = "Contact allowed.example."
    first = run_pair(pair, resources)
    assert "invented_identifier" in codes(first["d"])
    pair["prompt"]["data"]["evidence"][1]["observed"] = {"host": "allowed.example"}
    second = run_pair(pair, resources)
    assert second["d"]["pass"] is True
    pair["prompt"]["data"]["evidence"][1]["observed"] = []
    assert run_pair(pair, resources) == first


def test_wordlist_and_data_hashes():
    import hashlib

    from .support import LOCAL, read_bytes, read_json
    manifest = read_json(LOCAL / "manifest.json")
    for filename, expected in manifest["files"].items():
        assert hashlib.sha256(read_bytes(LOCAL / filename)).hexdigest() == expected, filename


def test_independent_baselines_are_the_pinned_raw_sources():
    import hashlib

    from .support import LOCAL, raw_baselines, read_json
    expected = read_json(LOCAL / "source-pins.json")["baseline_sha256"]
    files = raw_baselines()
    assert set(expected) == set(files)
    for filename, digest in expected.items():
        assert hashlib.sha256(files[filename].encode("utf-8")).hexdigest() == digest, filename


@pytest.mark.parametrize("index", [0, 1])
def test_constructed_malformed_lifetime_fault_records(index):
    """Checker controls only; never rely on the interpreter digit-limit trigger."""
    from .support import FIXTURES, read_rows
    vector = list(read_rows(FIXTURES / "renderer" / "fault-vectors.jsonl"))[index]
    pair = fault_pair()
    record = dict(vector["expected_record"], reason_text=fault_pair()["prompt"]["record"]["reason_text"])
    pair["prompt"]["record"] = record
    pair["prompt"]["full_record_terms"] = ["SYNTHETIC_FAULT_INPUT_DO_NOT_ECHO"]
    data = pair["prompt"]["data"]
    for key in ("policy_id", "verdict", "cell", "reason_code", "reason_text"):
        data[key] = record[key]
    data["evidence"][0]["observed"]["policy_id"] = record["policy_id"]
    for item in data["evidence"][1:]:
        value = vector["sections"][item["section"]]
        item["observed"] = {"not_shown": "size"} if len(json.dumps(value, sort_keys=True, separators=(",", ":"))) > 6000 else value
    result = run_pair(pair, local_resources())
    assert all(value["pass"] is True for value in result.values()), result
    pair["output"]["explanation"] += " SYNTHETIC_FAULT_INPUT_DO_NOT_ECHO"
    result = run_pair(pair, local_resources())
    assert all(result[check]["pass"] is False for check in ("a", "c", "d"))


def test_fault_does_not_treat_record_detail_as_customer_text():
    pair = fault_pair()
    original = run_pair(pair, local_resources())
    pair["prompt"]["record"]["detail"] = {"exception": "SYNTHETIC_FAULT_INPUT_DO_NOT_ECHO"}
    assert run_pair(pair, local_resources()) == original


@pytest.mark.parametrize("change", ["no_policy", "wrong_policy", "not_collected"])
def test_fault_requires_public_policy_and_collected_evidence(change):
    pair = fault_pair()
    evidence = pair["prompt"]["data"]["evidence"]
    if change == "no_policy":
        evidence.pop(0)
    elif change == "wrong_policy":
        evidence[0]["observed"]["policy_id"] = "MS.UNKNOWN.1.1v1"
    else:
        evidence[1]["observed"] = {"collection_status": "not_collected"}
    result = run_pair(pair, local_resources())
    assert all(result[check]["pass"] is False for check in ("a", "c", "e"))
