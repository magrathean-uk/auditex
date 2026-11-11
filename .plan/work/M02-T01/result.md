## RESULT M02-T01
status: done
summary: The review 13 fix ran clean. selftest.py passes 21 of 21 probes, including the new repeated-observation probes. recount.py passes the soundness check (0 of 3648 keys conflict over 5260 rows). Its output is byte-identical to the pre-change recount, so the counts stand: 137 against train, 144 against train plus validation (72 against validation alone), 291 twin-free. The 318 counts shared system-prompt wording and the 298 is 435 minus 137. No code change was needed.
changes: kit/20261111-airr-v4/heldout/notes/twin-reconciliation.md (probe count 16 to 21; the "not re-run" status line replaced with the run results). No repository changes.
verification: syntax check (py_compile) of twin_definition.py and notes/*.py pass; selftest.py pass (21 of 21, 0 FAIL); recount.py pass, diff against pre-change recount-result.json identical; verify greps pass against a scratch copy of the Findings lines under $TMPDIR, not result.md. The load was above 12 during these short runs, which the brief allows.
risks: Five policies use exact values, so a held-out row that differs from a training row only by a name or wording counts as twin-free there. | The 17 policies whose Rego sections the AST walk missed were found only by the soundness check; M02-T02 must run `accept()` on its own labelled rows. | The reads file comes from the curation record, so OPA and ScubaGear are not re-run.
questions_for_g: none

### Findings
twin-definition: same policy id, same decisive evidence and same typed verdict; evidence is the Rego-read fields of read sections, whole sections where the Rego depends on them but the read paths are unreliable, unread sections dropped, then abstracted (exact values for 5 policies that compare names or wording); repeated identical observations collapse to one; explainer inputs must carry a valid verdict
twin-counts: reconciled
gpu-hours: heldout 0
review-3: fixed; the old key merged 5 keys (20 train rows) holding both met and not_met because abstraction dropped names the Rego compares; those policies now use exact values and `accept()` refuses any key with two typed verdicts (0 of 3648 conflict)
review-7: fixed; `normalise` takes oracle chat rows and explainer inputs, requires a valid verdict for explainer rows, and `twin_key` and `are_twins` take an optional `verdict=`
review-8: fixed; unread sections are dropped, unknown dependencies are kept whole and recorded; adding an unrelated section leaves the key unchanged (selftest)
review-9: fixed; verdicts derive from validated expected claims, all saved row shapes run (5227 chat rows with an oracle outcome, 33 claims-only rows with no policy id), and the rows and reads sha256 are in recount-result.json
review-13: fixed and now run; a repeated identical observation no longer changes the key (5227 of 5227 oracle rows and explainer inputs keep their key, repeat count does not matter, a repeat with another value still changes it); selftest 21 of 21, recount unchanged
count 137: test rows with a twin in train (203 classes in test); reproduced under the new key
count 144: test rows with a twin in train or validation (72 against validation alone)
count 318: longest-text match; the longest message is the system prompt for all 318 rows, so it compares shared template wording only
count 298: 435 minus 137, twin-free against train only
count 291: 435 minus 144, twin-free against train and validation
overlap: both methods 144, longest-text only 174, twin only 0, neither 117
other keys: exact user message 0, exact system message 435
twin-free policies: all 12 keep at least 4 rows; the 171-row policy (39 per cent) keeps 161
notes: kit/20261111-airr-v4/heldout/notes/twin-reconciliation.md
