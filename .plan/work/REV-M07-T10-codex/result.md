## RESULT REV-M07-T10-codex
status: done
summary:
verdict: ship
reviewed: c3e3e85acdfd, manifest check pass
No blocking defect found. Two advisories below.
changes: none
verification: Python SHA-256 and exact file-set checks pass, 366 files; static diffs, function comparisons, assertion review and Python syntax checks pass; git status clean. PowerShell, kit execution, network and tenant access excluded as instructed. Required clean-development doctor failed on an unverifiable lifecycle-lock owner; no repair attempted.
risks: Runtime behaviour and the separately started full offline suite are outside this confirmation.
questions_for_g: none

### Findings
1. Confirmed: session, connection, disconnection, reuse and guard paths match the baseline, with only the Teams loader substitution at kit/20261111-kit-7q/dt-r7q-ro/populate/_common.ps1:3156. Item 4's opener, record, seal, callers, variables and allowances are absent. The sole DtShared name is the baseline's DtSharedSessionCommands at :3089.
2. Confirmed: retained functions match repaired round 7p byte-for-byte, including refusal handling at kit/20261111-kit-7q/dt-r7q-ro/populate/_common.ps1:1211 and exact Teams loading at :3140. Kept documents retain the reviewed changes without shared-sign-in instructions. No removed-helper, signature or journal-field dependency remains; refused already belongs to the schema at kit/20261111-kit-7q/dt-r7q-ro/populate/_schema.ps1:461.
3. Confirmed: exactly four rollback replacements, at kit/20261111-kit-7q/dt-r7q-ro/populate/99-rollback.ps1:64, 726, 731 and 763, correctly close, recheck and describe refused intents. The complete normalised file hash matches 12E9E639CED7… at kit/20261111-kit-7q/dt-r7q-ro/tools/Test-KitConstructs.ps1:275; its writer allowance at :220 is unchanged.
4. Confirmed: 28 retained cases preserve their assertions; the 17 removed cases concern only item 4. See kit/20261111-kit-7q/dt-r7q-ro/tools/mock-harness/Cases-Round7p.ps1:37. Baseline assertion changes serve the authorised licence/docs changes; verdict values, lint rules and allowance entries are unchanged. Construct additions at kit/20261111-kit-7q/dt-r7q-ro/tools/Test-KitConstructs.ps1:112 name exactly two helpers; no wildcard added.
5. Advisory: kit/20261111-kit-7q/dt-r7q-ro/populate/README.md:9 categorically diagnoses replication from HTTP status alone. Smallest fix: change “is directory replication” to “can be directory replication”. Retry guidance fits licence/membership modifications at kit/20261111-kit-7q/dt-r7q-ro/populate/00-identity.ps1:281 and :309; role creates at :321 correctly require intent resolution.
6. No changed-line wrong-tenant, excess-write, rollback-coverage or lockout defect found. Advisory, inherited: workstation paths remain, including kit/20261111-kit-7q/dt-r7q-ro/populate/README.md:54 and kit/20261111-kit-7q/dt-r7q-ro/tools/test_compare.py:759; replace them with configured tool roots in a follow-up. Added identifiers are synthetic test values; no added credentials or live tenant identifiers found.
