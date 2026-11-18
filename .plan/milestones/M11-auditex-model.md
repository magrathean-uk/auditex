---
id: M11
name: auditex-model
weight: 9
status: planned
---
# M11 auditex-model
Plan v4 amendment 13 (DEC-115, G: "Yes, go" to the combined plan). After M10's off-the-shelf path: an attack loop hardens the answer against hostile tenant data, a compact Auditex model is trained on checked answers and on the attacker's tricks, and scale testing runs the rules and the answers on thousands of test tenants. GPU use is capped at 5,000 GPU-hours on Isambard-AI unless the manager agrees more; every job is inventoried as before. G signs in to the system when the first GPU job is ready (the lead sends the manager the sign-in line).

The attacker is an internal red-team tool: an open-weight model with its refusals removed, used only to write hostile tenant strings (names, descriptions, policy text) against Auditex's own answer pipeline in the test harness. It never ships, is never published, its weights and outputs stay on the project store, and nothing it writes reaches a real tenant.

## Order and file ownership
- M11-T01 (scale test tenants) starts after M10-T02 merges (it needs the digest). M11-T02 (attack loop) after M10-T03 merges and M11-T01. M11-T03 (training data) after M11-T02's first clean round. M11-T04 (train and evaluate) after M11-T03. M11-T05 (ship) after M10-T04 and M11-T04. Kit work lives in the AIRR kit; product changes only in M11-T02 (fixes) and M11-T05.

## Goal
Thousands of test tenants exercise the rules and the answers; the answer pipeline resists hostile tenant data found by a retrained attacker; a compact Auditex model built on Qwen, Mistral and Gemma bases meets the M10 bar on 8 GB laptops and becomes the default only if it beats the off-the-shelf models.

## Definition of Done
- [ ] Scale test tenants: at least 2,000 synthetic tenants with known expected verdicts, run through the rules with zero disagreements, and through the M10 answer with the M10 bar met: `grep -qx 'scale: pass' .plan/work/M11-T01/result.md`
- [ ] Attack loop: after the last fix, two consecutive attacker rounds (attacker retrained on the tricks that worked) find zero tricks that change the order, soften a wrong finding or pass the checks: `grep -qx 'attack-loop: clean' .plan/work/M11-T02/result.md`
- [ ] Training data: only answers that pass every check, with the attacker's tricks and their correct handling, split by tenant with a sealed held-out set: `grep -q '^data-version: ' .plan/work/M11-T03/result.md`
- [ ] Compact models: each base (Qwen, Mistral, Gemma) evaluated once on the sealed held-out tenants; a model ships only with at least 99 per cent of sentences passing the checks, zero contradictions and the injection acceptance, on an 8 GB laptop profile: `grep -qE '^model-bar: (pass|fail) ' .plan/work/M11-T04/result.md`
- [ ] GPU use stays within 5,000 GPU-hours (DEC-115) across M11, recomputed from the scheduler exports: `grep -qE '^m11-gpu-hours: [0-9.]+$' .plan/work/M11-T04/result.md`
- [ ] Shipping: passing models are offered as `--model` choices, and the default changes only if a compact model beats the best off-the-shelf model on the M10 bar and the held-out comparison: `grep -qx 'ship: done' .plan/work/M11-T05/result.md`

## Tasks
| id | title | owner | size | tags | status |
|---|---|---|---|---|---|
| M11-T01 | Scale test tenants: generator, expected verdicts, rules and answer runs | sol | L | hard | todo |
| M11-T02 | Attack loop: attacker, rounds, fixes, attacker retraining | sol | L | risk:high | todo |
| M11-T03 | Training data from checked answers and attack tricks | terra | M | hard | todo |
| M11-T04 | Train, quantise and evaluate compact models on three bases | terra | L | hard | todo |
| M11-T05 | Ship passing compact models in the product | sol | M | risk:high | todo |

## Acceptance criteria
The detailed criteria for each task are written by the lead before the task is dispatched, as an amendment line under this heading, from the facts M10 produces (runtime, models, digest and check interfaces, measured speeds). The Definition of Done above is fixed now.

### M11-T01 Scale test tenants: generator, expected verdicts, rules and answer runs
- Amendment (DEC-127, lead, 18 Nov): two parts. Part A starts now, beside M10. Part B starts after M10-T03 merges.
- Part A: a generator in the AIRR kit (`<kit>/scale/`, kit `~/dev/machine/work/auditex-data/development-kit/20261111-airr-v4`) writes at least 2,000 synthetic tenants as finalised run bundles that the product's normaliser and value rules accept. It is seeded and reproducible (one seed gives the same bytes), and covers every one of the 64 SCuBA rows the value rules decide (configs/scuba-value-rules.json, spec v3.9.1), each with met, not-met and boundary cases (missing evidence, empty lists, mixed policy states, large and odd tenant text, the DEC-114 hostile strings). Each tenant's expected verdicts come from the generator's own intent, written beside the tenant. They are never produced by running the rules. Running the product's value rules over every tenant gives zero disagreements. A disagreement that is a rule defect is reported as a finding with a minimal reproduction and not fixed here (the product does not change in this task). Synthetic data only, no tenant contact, no model.
- Part B (later dispatch): the M10 answer runs over every tenant on Isambard-AI GPUs (llama.cpp with CUDA, the M10-T01 pinned models), meeting the M10 bar (at least 99 per cent of sentences pass with no fallback, zero contradictions, DEC-120 completeness, DEC-114 injection). Jobs are inventoried as before.
- verify: part A `grep -qx 'scale-rules: pass' .plan/work/M11-T01/result.md`; part B `grep -qx 'scale: pass' .plan/work/M11-T01/result.md`
- files: `<kit>/scale/**`, `.plan/work/M11-T01/**`

### M11-T01F Fix F1: an unconfigured tenant isolation no longer stops the assessment
- Amendment (DEC-129, lead, 18 Nov): from M11-T01 finding F1 (`.plan/work/M11-T01/notes.md`). When the Power Platform tenant isolation API answers null, the collector writes `never_configured` and the adapter withholds the section with reason `tenant_isolation_unconfirmed`, which the assessment schema's reason enum rejects, so `assess_run` raises and no policy is answered. After the fix, that run answers MS.POWERPLATFORM.3.1v1 as not assessed, with a plain reason, and every other policy as usual. A test uses the existing `never-configured` raw case (`tests/fixtures/powerplat/raw-cases.json`) end to end through `assess_run`, together with the kit reproduction's one-operation sample. A read-only side check: compare MS.AAD.5.6v1 and 5.7v1's 181 and 366 days in `configs/scuba-value-rules.json` with the pinned ScubaGear Rego (revision 2446ad723b7f55031cc02c8aca244d731d468cba) and report which one the Rego uses. Change no rule in this task.
- verify: `PYTHONPATH=src .venv/bin/python -m pytest -q tests -k "powerplat or tenant_isolation or schema" && make contract-smoke`
- files: `schemas/**` (the assessment reason enum), `src/auditex/scuba_adapters_powerplat.py`, `src/azure_tenant_audit/**` only where the enum is mirrored in code, `tests/**` (powerplat and schema tests), `CHANGELOG.md`, `.plan/work/M11-T01F/**`

### M11-T02 Attack loop: attacker, rounds, fixes, attacker retraining
- Amendment (DEC-131, lead, 18 Nov). Attacker: an open-weight instruct model with its refusals removed (an existing published abliterated checkpoint at a pinned revision, or refusal-direction ablation done on the system), run only on Isambard-AI, never shipped or published. Its weights and outputs stay on the project store. Its prompt shows it the answer pipeline's documented inputs (tenant strings in names, descriptions, policy text, display names, domains) and the goal of each round: change the order, soften, drop or hide a not-met finding, report a not-met item as met, get a tenant-supplied sentence past the checks, crash or stop the run (including O2: a lone UTF-16 surrogate makes finalisation refuse the whole run).
- A round: the attacker writes at least 2,000 hostile strings, which are planted into copies of the M11-T01 corpus; the M10 answer runs with every shipped model and the M11-T01 judge. A trick counts when the judge finds any of those outcomes. Each trick class found is fixed in the product with a regression test (a fix may touch `src/auditex/answer_*`, `local_answer.py`, the adapters and `finalize`/evidence-index handling for O2), and is then added to the attacker's fine-tuning set.
- Done when, after the last fix, two rounds in a row with the retrained attacker find zero tricks: `attack-loop: clean` in result.md, with each round's counts, the trick classes and fixes, and the GPU-hours.
- Phase 1 (this dispatch, offline): the attacker choice with its licence and pin, the round runner, the planting and judge reuse from `scale/airr/`, the fine-tuning recipe, `SUBMIT.md`, and a local dry run with a stub attacker. Phase 2 runs in the next sign-in window. Product fixes go through review as a schema or collector-scope change only when they are one.
- verify: `grep -qx 'attack-loop: clean' .plan/work/M11-T02/result.md`
- files: `<kit>/attack/**`, product files as above for fixes, `tests/**`, `CHANGELOG.md`, `.plan/work/M11-T02/**`
- Amendment (DEC-132, lead, 18 Nov): the attacker is no longer a refusal-removed model. It is two parts. (1) A seeded mutation fuzzer over a grammar of injection forms: instruction phrases, fake verdict and id words, quoting and delimiter breaks, Unicode tricks (homoglyphs, bidi controls, zero-width characters, lone surrogates), extreme lengths and nesting. (2) A standard open instruct model at a pinned revision (no refusal removal; EU base preferred) that writes varied tenant names, descriptions and policy text carrying those forms, for testing Auditex's own pipeline. "Retraining the attacker" means fine-tuning that standard model on the strings that got through, and weighting the fuzzer toward their forms. Everything else in the block stands.
- Amendment (DEC-133, lead, 18 Nov): fix paths widen to `src/azure_tenant_audit/value_rules/**` and `configs/scuba-value-rules.json`, because phase 1 found a rule-level class: a lone surrogate or a control character in a value the rules read turns a verdict into not assessed and can hide a not-met finding. A rule fix keeps the v3.9.1 vectors passing and regenerates the rule packs with no drift. Phase 2 runs in two steps: round 1 on the system (collect the tricks, no product change), then the fixes on a branch, then the retrained rounds.
