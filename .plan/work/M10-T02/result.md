## RESULT M10-T02
status: done
summary: Round 4 addresses review-3.md under DEC-119: the model selects, Auditex writes every word. Item 1 fixed: per-item banks of fixed frames (src/auditex/answer_frames.json, each with a verdict, severity, value or catalogue precondition) plus the shipped baseline requirement and, for not met only, the explainer's remediation steps; no tenant text enters a bank. Item 2 fixed: answers are {"use", "show"} per item and {"summary", "highlight"} for the run; checks are form, empty, limit, duplicate, precondition, unknown and reference; anything else shows the fixed text.
Item 3 fixed: answer_vocabulary.txt and all lexical checks removed; digest, quoting and fallback kept. Item 4 fixed: every round 1 to 3 and kit probe fails in ten positions, and every bank combination of the round 3 items renders only bank text of its own verdict. Item 5 fixed: answer_form(item, digest) and summary_form(digest) return JSON schemas with the id enums; every schema-valid answer passes.
Criteria met: digest ordered by the rules; fail-closed checks with fixed-text fallback; pure and deterministic; hostile tenant data quoted, never in a bank or an answer; order, verdicts and fixed text unchanged. Details: .plan/work/M10-T02/notes.md.
changes: src/auditex/answer_checks.py, src/auditex/answer_digest.py, src/auditex/answer_frames.json, src/auditex/answer_vocabulary.txt (removed), pyproject.toml, tests/test_answer_checks.py, tests/test_answer_digest.py, .plan/work/M10-T02/result.md
verification: make lint && .venv/bin/python -m pytest -q tests/test_answer_digest.py tests/test_answer_checks.py && grep -qx 'answer-checks: ready' .plan/work/M10-T02/result.md: pass. tests/test_architecture_modules.py: pass. CI sample digest: 102 items, every bank passes. Negative cases (.plan/work/M10-T02/negative-cases-4.txt): "form: the answer's keys are ['say', 'show'], not use and show"; "precondition: step-1 is not in this item's bank (verdict met)"; "precondition: item 2 is not an item the summary may highlight".
risks: Usefulness of the selection is M10-T04's judge; correctness no longer depends on model wording.
questions_for_g: none
### Findings
answer-checks: ready
