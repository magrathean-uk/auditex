# M11-T01 part B prep: Isambard job kit for the answer runs

prep: ready

Kit folder: `kit/scale/airr/` (kit = the AIRR v4 development kit). Nothing ran on the system. The first remote
command needs G's sign-in. The repository is unchanged.

## What is there

- `stage.sh` (workstation): `git archive` of the checkout's main commit (copied, not cloned), the generator code,
  the job files and the seed-1111 `SHA256SUMS` and `code-SHA256SUMS` go to `runs/m11t01/stage` over the worker
  route, checked there with `sha256sum -c`.
- `setup.sbatch` (1 GPU): a uv Python 3.12 venv on the project store, the product from the staged archive, and
  `llama-cpp-python` 0.3.36 built with CUDA (sm_90, `module load cuda/12.6`), with a GPU-offload check. `pins.py`
  compares the product's `local_answer.MODELS` with the four M10-T01 result lines. The product's own downloader
  then fetches the four models (pinned revision URL, size and SHA-256), followed by the freeze and versions.
- `corpus.sh` (login node): regenerates s1111 with `gen.py`. It checks the code sums, `cmp`s the regenerated
  `SHA256SUMS` with the staged copy, runs `sha256sum -c` and checks the file count.
- `answer.sbatch` + `answer_one.py`: an array of 4 models x 32 shards = 128 one-GPU tasks. Per tenant: offline
  replay, `assess_run`, `local_answer.explain_run` (what `auditex explain` wraps), `load_answer` re-verification,
  the product's `completeness_problems` and the independent `judge.py`. Each task writes one JSON line per tenant
  and model, and a resubmission resumes.
- `judge.py`: imports no product code. It checks contradictions (verdict lines, frame meanings, data lines against
  the rule facts), DEC-120 completeness and order, the summary counts and highlights, DEC-114 leaks of the
  generator's hostile and odd strings outside quotes, and the rules against the generator's intent.
- `aggregate.py`: per model, the pass rate, fallbacks, contradictions, completeness, injection failures, intent,
  errors and missing tenants, then `scale: pass|fail`. The gate is the models the staged product ships.
- `inventory.sh`: the runbook's `sacct` export, `jobs.json` (stage `auditex`), `gpu-hours: auditex <used>`, an
  `sreport` snapshot and `SHA256SUMS`.
- `SUBMIT.md`: the commands in order, the GPU-hour estimate and the inventory steps.

## Commands (in order; details in kit/scale/airr/SUBMIT.md)

0. G signs in to the system (one line for G); workers check the route with `ssh -F "$AIRR_SSH_CONFIG" -O check "$AIRR_HOST"`.
1. Workstation: `bash "$AIRR_KIT/scale/airr/stage.sh" <auditex checkout>`
2. Login node: `. "$PROJECTDIR/airr-v4/runs/m11t01/stage/kit/scale/airr/settings.sh"; bash "$CODE/airr/corpus.sh"`
3. `id=$(sbatch --parsable --export=ALL --output="$LOGS/%x-%j.out" "$CODE/airr/setup.sbatch"); echo "$id setup" >> "$M/jobs.txt"`
4. Smoke: `LIMIT=2 sbatch --parsable --export=ALL --dependency=afterok:$id --array=0,32,64,96 --time=00:30:00 --output="$LOGS/%x-%A_%a.out" "$CODE/airr/answer.sbatch"` (job id into jobs.txt), then read the seconds per tenant
5. Full: `env -u LIMIT sbatch --parsable --export=ALL --array=0-127 --output="$LOGS/%x-%A_%a.out" "$CODE/airr/answer.sbatch"` (job id into jobs.txt; failed indices are resubmitted the same way)
6. `"$SCALE_PY" "$CODE/airr/aggregate.py" --answers "$ANSWERS" --corpus "$CORPUS" --out "$M/aggregate"`
7. `bash "$CODE/airr/inventory.sh"`
8. rsync `usage/` to `kit/runs/usage/M11-T01/`, and aggregate, answers, logs, setup and jobs.txt to `kit/scale/runs/s1111/part-b/`
9. The lead copies `scale: pass|fail`, the model table and `gpu-hours: auditex <used>` into result.md.

## Expected GPU-hours

About 115 GPU-hours in all (range 60 to 230). Setup takes 0.5 to 2, the smoke about 0.3 and the shard overhead
about 2. The answers are 2,048 tenants x 102 items plus the summary per model: qwen about 34, mistral about 31,
gemma about 23, small about 23. This is extrapolated from M10-T01's Metal figure (170 s per 64 items) at about 4x
on a GH200. The smoke measures the real speed, and the formula is in SUBMIT.md. Wall time is about 4 to 6 hours at
32 GPUs.

## Local dry run (no GPU, no network): `dryrun.sh`, log `.plan/work/M11-T01/dryrun-b.log`

Shell syntax of 7 scripts and Python syntax both passed. stage.sh `--local` staged main 9a0a6f3 (19 files), and
the pins passed. The corpus was regenerated in full (2,048 tenants) and its `SHA256SUMS` matched the
workstation's. The array ran over 4 tenants (SHARDS=512, shard 0 of each model) with the product tests'
FakeBackend. Each tenant gave 102 items, 103 of 103 answers passed, with 0 problems. The aggregate gave
`scale: pass`, and a resubmitted task answered nothing twice.

Negative cases, each failing as it must:
- pins: one changed SHA-256;
- corpus: one changed sum, and a changed `gen.py`;
- the judge self-test (9 planted faults caught): a flipped Verdict line, a flipped highlight, a wrong frame on a
  met check, a changed Reason, a dropped not met item, two swapped items, a wrong count, hostile text outside a
  quote, and an intent mismatch;
- aggregate: the garbage backend (0.00 %, 412 fallbacks, `scale: fail`) and a missing tenant line (`scale: fail`);
- inventory against a stub `sacct`: `gpu-hours: auditex 1.1750`, with `SHA256SUMS` verified.

Kit file sums: `.plan/work/M11-T01/part-b-kit-SHA256SUMS`.
