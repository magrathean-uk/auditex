# M10-T04 result

acceptance: pass
injection: pass

All four models ship (`qwen` default, `mistral`, `gemma`, `small`). Product: the M10-T03 merge plus the shorter item
prompt and CPU-only warning (commit 950f9a7), run from the worktree with the `local-answer` extra, llama-cpp-python
0.3.36, grammar-constrained greedy decoding.

Sets (every model, one model at a time under hostload): the ten kit qa runs sampled to 21 checks each (193 answers),
the same ten runs injected with DEC-114 hostile strings plus four hostile-named not-met rows each (251 answers), and a
64-check lab-4 run (65 answers) on Metal and again CPU-only. 574 answers per model. Judge: `harness/judge.py`, written
independently of `answer_checks`; it reads the printed answer and compares it with the kit run's own facts.

| model | pass, no fallback | fallbacks | contradictions | completeness and order | injection | Metal 64 s | CPU 64 s | peak memory GB (Metal RSS / CPU footprint) | shipped |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| qwen | 574/574 (100%) | 0 | 0 | 0 failures | 0 failures | 144.9 | 456.4 | 6.44 / 5.75 | yes (default) |
| mistral | 574/574 (100%) | 0 | 0 | 0 failures | 0 failures | 142.7 | 695.7 | 6.54 / 5.58 | yes |
| gemma | 574/574 (100%) | 0 | 0 | 0 failures | 0 failures | 95.1 | 317.5 | 6.00 / 3.38 | yes |
| small | 574/574 (100%) | 0 | 0 | 0 failures | 0 failures | 83.6 | 258.1 | 3.58 / 3.36 | yes |

Seconds are whole-process wall time (hash check, load and answer) for 64 checks. Metal and CPU-only runs used
separate llama-cpp-python builds (venvs `m10-t01-metal` and `m10-t01-cpu`).

Memory fit: peak memory at or under 70% of the profile RAM, so 11.2 GB for 16 GB and 5.6 GB for 8 GB. Metal uses max
RSS (the footprint understates GPU-mapped weights); CPU-only uses peak memory footprint (RSS there includes
reclaimable mapped file pages). qwen, mistral and gemma fit the 16 GB profile; small fits the 8 GB profile.

Speed: with Metal every model answers 64 checks in under 3 minutes. CPU-only is 4 to 12 minutes, well over 3, so
`auditex explain` prints a one-line warning first and the guide says so. The one speed attempt (shorter item prompt:
fixed sentences stated once, ids per item, catalogue sentences by their opening words) cut the CPU-only time of a
24-check run on gemma from 147.4 s to 106.2 s with 100% pass and no judge problems, and qwen passes with it on both
builds, so it is kept; the checks, DEC-120 completeness and the order are untouched.

Qwen's Metal sets were run a second time (an earlier judge self-test had overwritten the first answer files), through hostload
from the committed product, and judged again by `harness/judge.py`: the same 574 of 574 with no problem of any kind; the
Metal time and peak memory above are from that second run (the first gave 144.7 s and 6.46 GB). The CPU-only qwen run is
the original. The full answer for the 102-check lab-4 run (103 answers, all passing, 187.9 s on Metal) is
`sample-answer.txt`.

Caveats: measured on a 36 GB M3 Pro with the host heavily shared (load average 6 to 50 on 12 cores), so it is a
faster chip than a base 16 GB laptop and the times are contended; nothing was run on a real 8 GB or 16 GB machine,
memory fit is by the definition above. Mistral's CPU-only run started at load average about 50.
