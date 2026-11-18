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
