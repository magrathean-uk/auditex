## RESULT EXP-m07-phaseE
status: done
summary: PHASE-E-COMMANDS.md is written with ordered steps, expected output, failure handling and a stop gate. The offline rehearsal found that the kit's `compare.py` (7r and the 7s copy) cannot read the product's current assessment file. The file gives a fallback for the tenant chat.
changes: none in the repository; wrote ~/dev/machine/records/auditex/dt-live/phaseE/PHASE-E-COMMANDS.md and .plan/work/EXP-m07-phaseE/progress.md; scratch removed
verification: `auditex run --offline` on the demo fixture, pass; `auditex assess`, pass (102 rows, rc 0); `auditex doctor --json`, pass; kit `compare.py` on that output, fail with exit 2 (schema refusal); same file with schema relabelled, 80 of 102 rows malformed; scratch copy with two constants changed, pass (exit 0, 16 agree and 8 disagree on the demo tenant, which is expected because the demo is not the kit's tenant)
risks: 1) `--collector-preset full` and the live Exchange, Graph and secret path are not rehearsable offline, because offline ignores collector selection and credentials. 2) The Teams policy reader needs a certificate token and the reader app only has a secret, so Teams rows come out `unknown`. 3) The reader app script and the ScubaGear and verify steps are PowerShell with sign-ins, so they are copied from the kit README and not rehearsed.
questions_for_g: none

### Findings
1. Collection command: `auditex run --tenant-name dummy-tenant --run-name bg --tenant-id "$TENANT_ID" --auditor-profile global-reader --plane full --collector-preset full --probe-first --break-glass-accounts "$BG_GROUP_ID" --env "$ENV_FILE" --out "$RUNS"`. The secret goes from the reader app's secret file into a mode-600 env file by `cat`, so it never appears in argv, and `--env` loads it. Bundles go to `dt-live/phaseE/runs` under the records folder on the internal disk. A second run with `--run-name nobg` and no break-glass list follows. The `$ENV_FILE`, `$RUNS` and other variable names are defined in section 1 of the commands file.
2. Rehearsal: `auditex assess <run>` writes `model_assessment.json`, which `compare.py` reads with `run-manifest.json` beside it. Its arguments are `--tenant-config`, `--frozen-dns`, `--variant` and `--json-out`.
   - **Pass and fail:** exit 0 with an `agreement on decided rows: n/m` line and no disagreements is a pass. A listed `disagree` row is a fail, and `--fail-on-disagreement` makes that exit 1. A refusal is a one-line message and exit 2.
   - **Not rehearsable:** `--frozen-dns` and the live tenant check, because they need the live verify file and a live manifest.
3. File: `~/dev/machine/records/auditex/dt-live/phaseE/PHASE_E-COMMANDS.md` is wrong; the correct path is `~/dev/machine/records/auditex/dt-live/phaseE/PHASE-E-COMMANDS.md`. It holds steps E1 to E12, including the ScubaGear cross-check as the kit README states it. Each step is marked rehearsed or not rehearsable.
4. Gap that would make the tenant chat stop:
   - **Schema:** `compare.py` accepts only `2026-10-29` (`SUPPORTED_SCHEMA`, line 186).
   - **Rule class:** it rejects the new rule class `value_rule` (`PRECHECK_CLASSES`, line 197).
   - **Fallback in the file:** a gate command checks for this, and a fallback scores through a scratch copy with those two constants changed. The report must say the score came from that copy. The kit lead owns the real fix, and I did not edit the kit.
5. Other points the tenant chat needs, all in the file:
   - **Sign-in:** the only Auditex-side sign-in is the operator's Graph browser sign-in in the reader app script.
   - **`--env` behaviour:** the loader does not check file mode and does not override variables already set in the shell.
   - **Break-glass id:** `BG_GROUP_ID` comes from the 00-identity output in phase D.
   - **Pre-flight:** it checks that `ExchangeOnlineManagement` is installed.
   - **Superseded file:** it replaces `COMMANDS.md` in that folder, which still names a model step.
