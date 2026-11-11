## RESULT M02-T01
status: partial
summary: Review item 13 is fixed in the code and the notes, but I did not re-run `selftest.py` or `recount.py` afterwards. The machine load stayed above 12 through my 10-minute wait (15.99 on the last check), and the brief allows local runs only below 12. The recount figures below are from the run before this fix. They should not change, because I expect the pack to hold no repeated observations, but that is not yet confirmed.
changes: kit/20261111-airr-v4/heldout/twin_definition.py (`_collapse`, claims-only signature, docstring); kit/20261111-airr-v4/heldout/notes/selftest.py (new probes); kit/20261111-airr-v4/heldout/notes/twin-reconciliation.md (review 13 and known limits). No repository changes.
verification: verify greps pass against a scratch copy of the Findings lines under $TMPDIR, not `result.md`. `selftest.py` and `recount.py` were not run after the fix (load). The new probes have never run, and I did not run even a syntax check.
risks: Re-run `selftest.py` and `recount.py` when load is below 12; `recount-result.json` and the 137/144/72 counts predate the fix. | The notes file says so in its review 13 section. | Known limits (empty versus absent section, list versus separate observations) are written in `heldout/notes/twin-reconciliation.md`; I left `bin/README.md` alone because it is outside my `files:` line and hashed in `bin/SHA256SUMS`.
questions_for_g: none

### Findings
twin-definition: same policy id, same decisive evidence and same typed verdict; evidence is the Rego-read fields of read sections, whole sections where the Rego depends on them but the read paths are unreliable, unread sections dropped, then abstracted with the distinct observations of a section taken as a set (exact values for 5 policies that compare names or wording); explainer inputs must carry a valid verdict
twin-counts: reconciled
gpu-hours: heldout 0
review-13: fixed in code; each observation is abstracted first, then the distinct ones are taken as a set, so repeating identical evidence with a fresh reference id keeps the key; the same repeat in claims-only rows is deduplicated; probes added, not yet run
count 137: test rows with a twin in train (203 classes in test); from the pre-fix recount
count 144: test rows with a twin in train or validation (72 against validation alone); pre-fix
count 318: longest-text match; the longest message is the system prompt for all 318 rows, so it compares shared template wording only
count 298: 435 minus 137, twin-free against train only
count 291: 435 minus 144, twin-free against train and validation
overlap: both methods 144, longest-text only 174, twin only 0, neither 117
other keys: exact user message 0, exact system message 435
notes: kit/20261111-airr-v4/heldout/notes/twin-reconciliation.md
