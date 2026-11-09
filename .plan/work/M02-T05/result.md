## RESULT M02-T05
status: done
summary: Repair round 2 is committed as a new commit on top of a178773. The adapter doc and the output contract no longer claim current prompts, an endpoint, dry-run or a switchable redaction. Redaction is stated as unconditional, and `--no-redaction` is stated as rejected with exit 2.
changes: docs/development/scubagear-export-adapter.md, docs/reference/output-contract.md
verification: M02-T05 verify command with PYTHONPATH=$PWD/src - pass (grep checks, `tests/test_docs_paths.py`, `tests/test_architecture_modules.py`); `git status --porcelain` empty
risks: 1) Historical sections of output-contract.md that describe prompt hashes and attempts for pre-rules records are kept deliberately; they are already labelled historical. 2) "model catalogue" and "model projection" remain where they name the retained projection and shape gate, which is still in the code.
questions_for_g: none

### Findings
Adapter doc:
1. Item 1, `:48` redaction disabled: now says redaction is unconditional.
2. Item 1, `:81` export model prompts: now refers to the export projection.
3. Item 1, `:88` prompt-output claim: now "assessment cases".
4. Item 1, `:94` prompt-equality clause: now "assessment cases".
5. Also reworded "export model views" to "projection views".

Output contract:
6. Item 2, `:540`: now says redaction is unconditional and `--no-redaction` is rejected.
7. Item 2, `:795`: now "rejected by `auditex assess` (exit 2)".
8. Item 2, `:711` and `:748`: now describe assessment-case construction, which still calls `annotate_enum_names` in `rule_assessment.py`.
9. Sweep: reworded "prompt evidence", "never enter prompts", "prompt enum annotation", `:78` and `:229` (model views and prompts) and "zero model calls" at `:515`. Redaction was checked against `rule_assessment.py:368`, which passes `redact=True`.
