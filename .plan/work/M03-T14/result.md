## RESULT M03-T14
status: done
summary: Round 4 (review-3.md, DEC-106): hard checks in checks/qa.py rebuilt as the fail-closed answer form (exact refusal; every sentence ends with a citation of a value; every value token equals its citations; number words and negations beside values refused; plain-ASCII parse), not patched. Two independent pre-review probes found 15 more passing classes; all closed structurally (attribution, relevance to gold and context, strict group binding, separator-blind field names, signs and quote bounds, qualifier and scope words). Baseline regenerated in the form (708/708 pass); pass rule and runbook section 16 rewritten; every review probe plus a generated adversarial set pinned as failing tests. Details: .plan/work/M03-T14/notes.md (round 4), evidence.md, adversarial-counts.txt.
changes: AIRR kit: checks/qa.py, checks/tests/test_check_qa_form.py (new), checks/tests/test_check_qa.py (old hard-check classes removed), checks/SHA256SUMS (recomputed from disk last), runs/qa/baseline/{answerer.py,validation-answers.jsonl,pass-rule.md,README.md,SHA256SUMS}, runbook/README.md (section 16 only); qa-data/v1 untouched. Work dir: .plan/work/M03-T14/{notes.md,evidence.md,progress.md,adversarial-counts.txt,count_adversarial.py,rehearse_round4.sh,pilot-rehearsal-round4.txt,verification-round4.txt}
verification: through hostload (slot acquired): qa tests 31/31 PASS; kit-check qa --set qa-data/v1 PASS; kit-check selftest PASS. Verify line tested against a scratch copy under $TMPDIR: selftest, then qa --set --result on a scratch result.md, then grep 'qa-set: ready', all PASS; a tampered qa-baseline line FAILS. M03-T15 chain rehearsed on a throwaway kit copy: GPU-hours claim 14 and 14.0000 PASS; 14.5, 999999999, 13.9999 and no line FAIL. Set, split manifest, held-out rows and seal unchanged.
risks: The form is strict, so the M03-T15 writer prompt must teach it closely or the 0.95 hard-check rate will be hard to reach. By design the checks don't read free words outside the listed vocabularies (hedges, units after a correct value, paraphrases, misspelt field names); the judge weighs those. checks/SHA256SUMS records dataround.py as on disk at recompute (M03-T11 is editing it, 4a798fb7...).
questions_for_g: none
### Findings
qa-set: ready
qa-set-sha256: 63ded654f635d50521fa7ac2da1d2118e8f63e7e319ec117f6dd1ffad886375b
qa-heldout-sha256: 6f36bb756e742f035700136ba0fb451cabbb1e715fdff6b118287c6583baceb2
qa-questions: total 1037 train 477 validation 231 heldout 329
qa-kinds: why-verdict 330 setting-value 318 what-changed 192 area-checks 78 unanswerable 119
qa-split-train: why-verdict 152 setting-value 156 what-changed 77 area-checks 32 unanswerable 60
qa-split-validation: why-verdict 76 setting-value 67 what-changed 47 area-checks 18 unanswerable 23
qa-split-heldout: why-verdict 102 setting-value 95 what-changed 68 area-checks 28 unanswerable 36
qa-runs: lab 4 synthetic 6
qa-baseline: hard-checks 708/708 train-and-validation heldout-answered 0 validation-answers 231
qa-pass-rule-sha256: bfcc1a4cf54b3c61522bf5fda198531d6c324d635fc0b052f2af62b8e039f3fc
Review probes: rounds 1 and 2 (6 answer probes) plus 35 earlier neighbours all fail on their named check (test_check_qa_form.py ReviewProbes).
Adversarial set (every way applied to every validation question it fits; all fail on their targeted check):
rule 1 (refusal, citations, attribution, relevance): 26 ways, 2523 answers
rule 2 (values, fields, verdicts, number words): 42 ways, 2519 answers
rule 3 (negation, qualifiers, scope, signs): 38 ways, 2662 answers
rule 4 (parse and plain-text form): 18 ways, 1578 answers
total: 124 ways, 9282 answers, 9282 failing
Pass rule: written verbatim in runbook section 16 and runs/qa/baseline/pass-rule.md (sha256 above, pinned in checks/qa.py) before any GPU job.
