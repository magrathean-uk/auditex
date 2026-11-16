## RESULT REV-M10-T03
status: done
summary:
verdict: changes-required
reviewed: f3c0203633df22d21c637acf26242c9d305e3752
Incorrect run selection and unrecoverable completed model downloads need repair.
Evidence: .plan/work/REV-M10-T03/evidence.md
changes: .plan/work/REV-M10-T03/progress.md, .plan/work/REV-M10-T03/evidence.md; no product changes
verification: PASS with PYTHONPATH=src: `make lint && .venv/bin/python -m pytest -q tests/test_local_answer.py tests/test_answer_checks.py tests/test_answer_digest.py && make contract-smoke && grep -qx 'local-answer: ready' .plan/work/M10-T03/result.md`; additional MCP registry, manifest guard, architecture and writer suites PASS; gitleaks and diff checks PASS; both defects reproduced
risks: Native inference skipped because the linked environment lacks the runtime; CHK-M10-T03 remains pending; full suite left to the required merge-batch gate
questions_for_g: none

### Findings

- Met: optional runtime is pinned and absent from base dependencies, pyproject.toml:35; MIT licence confirmed from the measured distribution.
- Met: four model choices, revisions, sizes and hashes match M10-T01, src/auditex/local_answer.py:105.
- Met: user-cache placement, progress, hash verification before loading and download-only network access, src/auditex/local_answer.py:544, src/auditex/local_answer.py:603, src/auditex/local_answer.py:644.
- Not met: download recovery can remain permanently stuck after receiving the complete file, src/auditex/local_answer.py:584. Required change 2.
- Met by inspection: form-derived grammar, empty enums, uniqueness guard and four-slot batching, src/auditex/local_answer.py:223, src/auditex/local_answer.py:253, src/auditex/local_answer.py:394.
- Untestable here: native backend execution; the opt-in test skipped, tests/test_local_answer.py:642.
- Not met: `run --explain` does not reliably answer the run just completed, src/auditex/cli.py:808. Required change 1.
- Met: standalone explain, report section and confined read-only MCP tool, src/auditex/cli.py:778, src/auditex/reporting.py:598, src/auditex/mcp_registry.py:177.
- Met: failed selections use counted fixed text; every digest item renders in order; stored answers are rebuilt before display, src/auditex/local_answer.py:725, src/auditex/local_answer.py:889; hostile-output tests, tests/test_local_answer.py:186.
- Met: schema, contract validation and DEC-121 post-finalisation handling, schemas/local_answer.schema.json:1, src/azure_tenant_audit/contracts.py:943, src/azure_tenant_audit/bundle_integrity.py:84.
- Met: security inspection found no secret leakage, tenant mutation or unsafe deserialisation; guarded answer output is tested as 0600, tests/test_local_answer.py:443.
- Met: all 16 changed paths match the authoritative files line, .plan/milestones/M10-local-answer.md:47.
- DoD not met for the claimed local-answer closure: readiness marker exists, but approval is blocked by these findings, .plan/work/M10-T03/result.md:17, .plan/milestones/M10-local-answer.md:19.
- Untestable: separate Tier A executing-check completion; its result is absent, .plan/milestones/M10-local-answer.md:45.

1. src/auditex/cli.py:808 - Destination reconstruction ignores `--resume-from` and takes the first repeated option while the engine takes the last. Reproduced a new run being followed by an answer to an older folder, and a resumed run receiving no answer. Use the engine’s effective completed destination, including resume and repeated-option semantics; add regression coverage.
2. src/auditex/local_answer.py:584 - A complete `.part` file causes `Range: bytes=<size>-`; HTTP 416 then leaves it unchanged indefinitely. Two retries reproduced the same failure despite correct pinned bytes. Verify and promote a complete partial before requesting a range, or reset it safely on 416; add a recovery test.

### Defect classes

Independent reconstruction of CLI state diverges from the engine’s effective destination.
Download recovery fails to handle a complete partial file.
