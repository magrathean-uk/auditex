## RESULT M11-T03
status: done
summary: Training data is built on Isambard-AI from fixed-product (9a0f301) answers: 13,956 examples (11,240 train, 1,042 validation, 1,674 sealed held-out, 12 per cent of base tenants). Scale is 4 models over 2,048 tenants (8,192 rows). Attack is rounds 1 to 3 (round 1 re-answered on the fixed product), 5,764 rows. Every drop (380) is `judge:leaks`, counted by check; no control dropped. `data-version: 101c02cd2c58ac791793eb55352efa12122a6e308d6a3da83bc71581d2aaa125`, seed 1111, `gpu-hours: train 41.2244`.
changes: (all in the kit, outside the repo; the worktree has no diff)
- `kit/train/`: `build.py`, `answer.sbatch`, `build.sbatch`, `settings.sh`, `stage.sh`, `inventory.sh`, `selftest.py`, `dryrun.sh`, `SUBMIT.md`
- `kit/trainer/answer_examples.py` (reader), README line, `SHA256SUMS` updated; oracle case schema untouched
- `kit/runs/m11t03/`: `data/v2/{summary.md,summary.json,MANIFEST.json}`, `usage/`, `jobs.txt`. Held-out rows stay in `sealed/` on the project store.
- `.plan/work/M11-T03/`: `result.md`, `notes.md`, `progress.md`
verification:
- `grep -q '^data-version: ' .plan/work/M11-T03/result.md` passes (checked from the main checkout; the worktree has no `.plan/work/M11-T03`). `git status --porcelain` empty. `make lint` passes with the main venv's ruff on PATH (the worktree has none). There are no commits because no repo file changed.
- `train/dryrun.sh` (fake backend) passes; `kit-check selftest` passes with the reader listed.
- Negative cases (all fail as they must):
  - `fixed_text_answer`, `fixed_text_item`, `fixed_text_summary`, `failure:injection`, `not_reverified`, `product_completeness`
  - `judge:leaks`, `judge:completeness`, `judge:contradictions`, `judge:order`, `judge:intent`
  - a held-out share below 10 per cent: "the held-out share must be at least 10 per cent of the base tenants"
  - an existing out folder: "v1 exists: a rerun writes a new folder, never over an earlier build"
  - answers from another product commit: "attack round-01: PRODUCT-COMMIT is missing or is not the product commit 29947163336f; an answer from another product is never read"
  - eight reader refusals, e.g. "example split must be train, validation or test"
- Skipped: `trainer/tests/test_trainer.py` (no pytest in the kit venv). `kit-check selftest` ran instead.
risks:
- The leak check drops 380 attack rows. Planted strings that embed a product phrase inside longer text (for example a fake system block containing `Checks to look at first: none.`) trip the judge's containment check, so the dataset is short of those strings.
- I added one rule: a planted string that is a whole line of the control's own answer counts as fixed text, not a leak. Without it, 404 rows dropped instead of 380.
- Every completion names its source model in the header line ("Worded by the local model <choice>"). M11-T04 may want that normalised.
questions_for_g: none. Recommend keeping the strict drop rule. Decision for M11-T04: normalise the model-name header line.
