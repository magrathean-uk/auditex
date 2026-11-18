# M11-T02 phase 1: attacker, round runner and offline kit (DEC-132)

prep: ready

## Attacker
- Fuzzer: `kit/attack/forms.py`. It is seeded over a grammar of injection forms: instruction phrases in four
  languages with chat markers, fake verdict and id words (the product's own fixed sentences, summary lines, answer JSON
  forms, policy ids), quote and delimiter breaks, homoglyphs, bidi controls, zero-width characters, lone surrogates,
  control characters, combining marks, lengths up to 120,000 characters and nesting up to depth 1,000. Each form has an
  inclusion weight. One seed and one weights file give the same bytes.
- Model: `mistralai/Ministral-3-8B-Instruct-2512-BF16` at revision `f6fae9795746f63c9be8344932f01275f3c63734`. It is a
  standard instruct model with no refusal removal and an EU base. Licence Apache-2.0, not gated. The snapshot is
  18 files, 35,706,497,300 bytes; the manifest sha256 is `5520b1c8...51bb`. The loaded weights are four shards,
  17,836,123,192 bytes in bf16, with their sha256 values pinned in SUBMIT.md step 2. About 18 GB fits one GH200 for
  sampling and for LoRA. It is already on the project store, fetched and qualified by M01-T04, so phase 2 downloads
  nothing.
- Retraining: `retrain.py` turns the tricked strings into chat cases and fuzzer weights (1 + 4 x the form's share).
  `finetune.py` runs LoRA through the kit trainer's v10 preset, loader and record form: 3 epochs, learning rate 1e-4.
  Each fine-tune continues from the previous adapter.

## Round runner (kit/attack, outside the repository)
- `gen.sbatch`: 2,048 strings (1,024 fuzzer, 1,024 model), then `plant.py`, then a CPU pre-screen (the rules only).
  `plant.py` puts them into 256 copies of the seed-1111 corpus, 8 strings per copy, each with a byte-identical
  control. Slots are only values that already held the generator's hostile or odd text, and every equal value is
  replaced, so references hold and the intent stays true. A round with fewer than 2,000 strings is refused.
- `answer.sbatch` and `answer_round.py`: every shipped model (4 x 8 shards) through `scale/airr/answer_one.py`
  (reused, unchanged).
- `classify.py`: the M11-T01 judge (`scale/airr/judge.py`, reused) compares each copy with its control. Outcomes are
  stop, crash, order, completeness, contradictions, summary, leaks and intent. The class is `<outcome>:<form>`. A
  split pass (one string per copy) names the string, and the loop status prints `attack-loop: clean|open`.
- `inventory.sh`: GPU-hours per round and in total. `SUBMIT.md` has steps 1 to 13 and the estimate.

## GPU-hours (SUBMIT.md)
- About 30 per round (range 20 to 70): answers about 28 (512 tenants x 4 models at M11-T01's per-tenant
  estimates), strings 0.3, retraining 0.3, split 0 to 5.
- The loop needs at least 3 rounds, likely 4 to 6: about 120 to 180 GPU-hours.

## Dry run (no GPU, no network; stub attacker, fake backend): `dryrun: pass`
- 26 checks, including 7 negative cases that fail as they must (evidence.md).
- Round 1: 2,048 strings planted, 256 copies and 256 controls. The controls and every expected.json are
  byte-identical to the corpus.
- Pre-screen: 57 of 256 copies stop, 10 flip a rule verdict, and 0 controls fail.
- Three copies were answered by all 4 models: 8 tricks, `stop:surrogate` x4 (O2) and `intent:surrogate` x4. The
  split pass named each one's string, and the copy without a planted problem had none.
- Retrained weights raised the surrogate strings from 126 to 453 of 2,048 in round 2. Loop status was right in
  4 of 4 cases. Inventory: 2.0000 GPU-hours from the stub sacct.

## Early findings for phase 2 (offline; the real models will confirm them)
- O2 reproduces: a lone surrogate in some tenant values makes finalisation refuse the whole run
  (`UnsafeRunFileError: Refusing evidence index: unsafe input`).
- New candidate class: a lone surrogate or control character in a value the rules read turns met or not met into
  not assessed (MS.EXO.3.1v1, MS.EXO.7.1v1, MS.TEAMS.1.7v2, MS.TEAMS.5.x). That hides a not-met finding at the rule
  level (the value rules or the SCuBA projection, not yet traced), outside the fix paths the milestone lists. The lead decides its owner.

## Review item (phase-1.md)
- Done offline with no remote command and no GPU. The M11-T01 part B kit is reused, not copied. The attacker follows
  DEC-132, the files are under `kit/attack/`, the product is unchanged, and no windows were used.
