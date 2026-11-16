## RESULT CHK-M10-T03
status: done
summary:
check: pass
checked: f3c0203633df22d21c637acf26242c9d305e3752
Verify passed (exit 0). 82 negative cases (9 CLI, 73 in code) all failed as they must, plus 10 controls that accepted good input. My first input for the completeness check (H3d) changed nothing, so I re-ran it with a valid input.
Mutation check on a scratch copy: 13 of 16 mutants were caught by the tests. The other 3 are listed under risks.
changes: none (evidence in `.plan/work/CHK-M10-T03/evidence.md`)
verification:
- `make lint && .venv/bin/python -m pytest -q tests/test_local_answer.py tests/test_answer_checks.py tests/test_answer_digest.py && make contract-smoke && grep -qx 'local-answer: ready' .plan/work/M10-T03/result.md`: exit 0, pass
- `PYTHONPATH=src make contract-smoke` (supplement, see risks): exit 0, pass
- `auditex explain <run> --model bogus`: exit 2, fails as it must
- `auditex explain <run> --mod small`: exit 2, fails as it must
- `auditex explain <run> --model=qw`: exit 2, fails as it must
- `auditex run --offline --model qwen ...` (no `--explain`): exit 2, fails as it must, no run folder written
- `auditex run --offline --expl ...`: exit 2, fails as it must
- `auditex run --offline --explain --model bogus ...`: exit 2, fails as it must
- `auditex explain` (no run folder): exit 2, fails as it must
- `auditex explain <nonexistent dir>` and `<empty dir>`: exit 2 each ("Refusing run-dir"), fails as it must
- `python neg.py` (scratch script, 73 negatives, 9 controls): exit 0, all 73 failed as they must

risks:
- My MU12 mutant (runtime-version pin removed) made a test fall through to a real Qwen model download. About 2 GB was fetched into scratch temp before my time limit killed the run. I deleted it, and the user cache was never touched. The remaining mutants ran behind a dead local proxy. The mutant removes the guard, so this is not a product defect.
- Three mutants survived the suite:
  - MU6 (`--model` without `--explain`) and MU16 (report catch list) change nothing in behaviour.
  - MU8 is a real test gap: removing the "already sealed" refusal in `write_answer` lets it overwrite a sealed `local_answer.json`. The guard works (W2 refused it), but no test covers it.
- The shared `.venv` resolves imports to the main checkout, so `make contract-smoke` as written runs main's code, not the branch's. pytest uses the worktree source (`pytest.ini` sets `pythonpath = src`). The `PYTHONPATH=src` re-run exercised the branch and passed. `git status --porcelain` is empty, so the verify changed no tracked path.
questions_for_g: none

### Findings
- Model download SHA-256, same size but wrong bytes: ModelError `model_unverified`, no target, partial file deleted. Failed as it must.
- Hub answers 404: `download_failed`, no target. Failed as it must.
- Download larger than the pinned size: `model_unverified`, partial file deleted. Failed as it must.
- Truncated download (500 of 1000 bytes): `download_failed`, no target. Failed as it must.
- Disk space short: `download_failed`, no network call made. Failed as it must.
- Connection error: `download_failed`. Failed as it must.
- Resume answered 206 with wrong Content-Range, or 416: `download_failed`. Failed as it must.
- Cached model of wrong size or wrong content: `model_unverified`, file deleted, no network used. Failed as it must.
- Wrong or missing llama-cpp-python, unwritable cache (a file in the way, or read-only dir), backend that fails to load: fixed text, no error raised, and the answer counts 102 of 102 items as fixed text. Failed as it must.
- Six hostile model outputs (empty, non-JSON, unknown ids, extra keys, injection text, bare number): all 22 not-met items still present, in order, in the printed text (DEC-120). Failed as it must.
- Completeness check given an answer with a not-met item removed, swapped, relabelled met, text hidden or duplicated: reports a problem each time. Failed as it must.
- Tampered artefact (item dropped, text edited, reordered, verdict relabelled, text hidden, other run id, selection in a fixed-text answer, status `model` without model, wrong model SHA, unknown version, extra property, bad enum, wrong count, truncated JSON, NaN, duplicate key, missing file, missing assessment): `load_answer` raises each time. Failed as it must.
- `write_answer` onto a symlink, onto a sealed file, or with inconsistent counts or numbering: refused each time. Failed as it must.
- Contract validation of a mismatched run id, damaged JSON, bad counts or bad schema: `invalid_local_answer` warning each time. A symlinked file raises. Failed as it must.
- Report section with a tampered answer returns None (never shown); with a symlinked file it raises. Failed as it must.
- MCP tool: a run without an answer or with a tampered one returns "unavailable" and leaks none of the tampered text; a run folder outside the MCP root or a `../` path is refused. Failed as it must.
- `bundle_integrity`: only exactly `local_answer.json` is treated as a post-finalisation output. `.bak`, `2`, `sub/`, `../` and case variants are not, and a stray `.bak` makes verification report a mismatch. Failed as it must.
- Grammar with `minItems` above the available ids raises. The uniqueness guard rejects a repeated id. Failed as it must.
- No negative case was accepted. The earlier H3d miss (my input replaced nothing) is explained in `evidence.md`.
