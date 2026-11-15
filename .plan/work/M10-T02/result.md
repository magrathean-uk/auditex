## RESULT M10-T02
status: done
summary: Round 4 addresses review-3.md under DEC-119; the model selects and Auditex writes every word. Item 1 fixed: each item has a bank of fixed frames from src/auditex/answer_frames.json, each with a precondition on verdict, catalogue severity, values held or catalogue sentences held. The bank also holds the shipped baseline requirement and, for not met items only, the explainer's remediation steps; no tenant text enters a bank.
Item 2 fixed: the answer is {"use", "show"} per item and {"summary", "highlight"} for the run. The checks are form, empty, limit, duplicate, precondition, unknown and reference; any other answer shows the fixed text. Item 3 fixed: answer_vocabulary.txt and all word-list checks are removed; the digest, the quoting and the fallback stay.
Item 4 fixed: every probe from rounds 1 to 3 and from the kit fails in all ten places an answer could carry free text. For the round 3 items, every combination of bank ids renders only bank text of the item's own verdict. Item 5 fixed: answer_form(item, digest) and summary_form(digest) return JSON schemas with the id enums, and every answer the schema accepts passes the checks.
Criteria met: the digest is ordered by the rules, the checks fail closed to fixed text, the code is pure and deterministic, and hostile tenant data stays quoted with order, verdicts and fixed text unchanged.
changes: src/auditex/answer_checks.py, src/auditex/answer_digest.py, src/auditex/answer_frames.json (new), src/auditex/answer_vocabulary.txt (removed), pyproject.toml (package data now lists the frames file instead of the vocabulary), tests/test_answer_checks.py, tests/test_answer_digest.py, .plan/work/M10-T02/result.md
verification: `make lint && .venv/bin/python -m pytest -q tests/test_answer_digest.py tests/test_answer_checks.py && grep -qx 'answer-checks: ready' .plan/work/M10-T02/result.md`: pass (exit 0) on head 6fac8a3 after rebasing onto main. Lint ran once and passed.
tests/test_architecture_modules.py: pass after the rebase. Before the rebase it failed because its subprocess imported main's newer src; the failure was not caused by this change.
gitleaks over main..HEAD: no leaks. CI sample digest (ci-projection-demo, read only): 102 items, bank sizes 3 to 13, every bank passes the checks.
Negative cases (.plan/work/M10-T02/negative-cases-4.txt): "form: the answer's keys are ['say', 'show'], not use and show"; "precondition: step-1 is not in this item's bank (verdict met)"; "unknown: use holds "The passwords expire.", not a sentence id of this item"; "precondition: item 2 is not an item the summary may highlight". A broken frames file is refused with FramesError (24 broken files in the tests).
risks: Whether the chosen sentences are useful is left to the M10-T04 judge; correctness no longer depends on the model's wording.
Severity counts as catalogue when the row's confirmed criticality is Shall or Should, as before. A forged bundle could therefore unlock the fixed severity frame, but only that frame's fixed text.
questions_for_g: none
### Findings
answer-checks: ready
Details are in .plan/work/M10-T02/notes.md under "Round 4". Shipped content is unchanged; the frames file is package data like the vocabulary was, and the parity test passes.
