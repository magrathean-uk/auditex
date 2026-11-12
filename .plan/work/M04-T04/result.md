## RESULT M04-T04
status: done
summary: B1 variant fixed in _NameMatcher.mask. Where a phrase that took an initial is only a prefix of a longer key (john a smith of john.a.smith.adm), the form without the initials is held. It is probed after the walk, longest first, only where no longer hit was found and only while the start has probes left. At most 6 probes per start, window at most 6.
Review item B1-variant: fixed with the reviewer's two tests, but not in the reviewer's literal form (cap minus one, commit 90ee78b). That form regressed against b2a69ae: "Ana M. de la Cruz Silva" fully readable, and "John A. Smith Jones" split into John Smith's pseudonym plus "Jones". The deferred form (0adcc49) keeps the b2a69ae walk unchanged, and a regression test pins both cases.
Nothing else changed: exempt list, advisories and note wording untouched; budget tests only added to.
changes: src/azure_tenant_audit/output_redaction.py, tests/test_redaction_person_names.py, tests/test_redaction_scan_budget.py (commits 90ee78b, 0adcc49)
verification: PYTHONPATH=<worktree>/src .venv/bin/python -m pytest on the four focused files at 0adcc49: pass (284 passed)
Reviewer probes from evidence.md and evidence-2.md (.plan/work/M04-T04/probes-b1-variant.py): 67 of 67 mask at 0adcc49, 43 of 67 at b2a69ae
Differential b2a69ae vs 0adcc49 over the documented-limit and over-masking texts: 104 same, 0 differ
Adversarial budget at 26x40 people: at most 6 probes per start, widest at most 6, peak 2.00 probes per token, linear from 1k to 16k repetitions
Negative on b2a69ae: new tests fail ("Report by John A. Smith, today." left readable; "AssertionError: Ab X Cd")
Negative on 90ee78b: regression and budget tests fail ("by Ana M. de...la Cruz Silva" left readable)
Negative without the probes-left guard: budget test fails ("AssertionError: Ab X Cd Ef Gh Zz")
make lint: pass
not run (the brief excludes them): make test, html_peak 90,000-record benchmark
risks: The fix is a deferred form of the reviewer's fallback, not their literal form; the Codex review should check it against the reasons in evidence-3.md.
Residual, also readable at b2a69ae: when the walk uses all six probes on the longer path, the held form is not tried, so "John A. B. Smith wrote" next to john.a.smith.x<n> sign-in names stays readable.
html_peak benchmark not run on this head.
questions_for_g: none
### Findings
B1-variant: fixed tests/test_redaction_person_names.py::test_initial_on_a_key_that_runs_on_past_the_name_still_masks_it (own UPN john.a.smith.adm, recorded John A. Smith-Jones), ::test_a_longer_name_with_an_initial_still_wins_over_the_form_without_it, tests/test_redaction_scan_budget.py::test_d5_initial_fallback_on_a_running_key_stays_at_six_probes
probes: 67 of 67 mask
focused-tests: 284 passed (person_names 107, scan_budget 26, profiles_d3 61, keyed_pseudonyms 90)
evidence: .plan/work/M04-T04/evidence-3.md, probes-b1-variant.py/.out, probes-regression.py
