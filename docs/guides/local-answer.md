# Local Answer Guide

`auditex explain` answers, in plain sentences, what is wrong in a finished audit run (the most severe first) and what is
right. It uses a small language model that runs on the same computer. The rules still decide every verdict and the
order; the model only chooses which prepared sentences and values to show for each check.

## Start

1. Install the optional runtime once, in the Auditex folder. It builds `llama-cpp-python` (llama.cpp) from source, so it
   needs CMake and a C and C++ compiler; on a Mac it is built with Metal.

   ```bash
   python -m pip install -e '.[local-answer]'
   ```

2. Run the audit, then answer it:

   ```bash
   auditex explain <run-dir>
   auditex explain <run-dir> --model small
   auditex run <audit options> --explain
   ```

   `auditex explain` writes the run's rule assessment first when it is missing. `auditex run --explain` answers the
   run folder the engine wrote in that call, and never changes the run's exit status. `--model` chooses the model:

   | `--model` | Model | File | Memory it needs |
   | --- | --- | --- | --- |
   | `qwen` (default) | Qwen3.5-9B, 4-bit | 5.68 GB | a 16 GB laptop |
   | `mistral` | Ministral-3-8B-Instruct, 4-bit | 5.2 GB | a 16 GB laptop |
   | `gemma` | Gemma-4-E4B-it, 4-bit | 5.15 GB | a 16 GB laptop |
   | `small` | Qwen3.5-4B, 4-bit | 2.74 GB | an 8 GB laptop |

   Every model above passed the same acceptance and gives the same kind of answer; `qwen` is the default because it is
   the best passing Qwen. Use `small` on a laptop with 8 GB of memory.

3. The answer is printed and written into the run as `local_answer.json`. Rendered reports (`auditex report render`) show
   it as a `local_answer` section, and the MCP tool `auditex_local_answer` returns it.

Without the runtime, or when a model cannot run, every check shows its fixed text and the answer says what to install or
why the model did not run. The audit is never lost.

## What it downloads

The first use of a model downloads one file from its publisher's hub on the Hugging Face site, at the revision Auditex
pins, into the user cache: `~/Library/Caches/auditex/models` on macOS, `%LOCALAPPDATA%\auditex\models` on Windows, and
`$XDG_CACHE_HOME/auditex/models` (or `~/.cache/auditex/models`) elsewhere. Set `AUDITEX_MODEL_DIR` to keep the files
somewhere else. The command prints the size before it starts and shows progress; an interrupted download resumes.

Auditex checks the file's size and SHA-256 against the pinned values before it is used, and checks the SHA-256 again
before every load. A file that does not match is deleted and not used. After the download the answer runs offline. Keep
free disk space for the file you choose: the sizes are in the table above.

## What it never does

- It never sends anything about your run or your tenant anywhere. The model download is the only network call, and there
  is no telemetry.
- It never changes a verdict, the order or the number of checks. The model's output is only a list of sentence and value
  ids; Auditex checks every id and renders every word. Every check that is not met is always shown, in the rules' order,
  whatever the model selects.
- It never follows instructions inside your tenant's text. Reasons, settings and names from the tenant are shown quoted
  and labelled as data, and a selection that does not pass the checks shows that check's fixed text. The answer states
  how many checks used the fixed text.
- It never writes to a tenant, and it reads only the run's rule assessment and its run id: no message bodies and no file
  content.
- It never runs unless you ask for it (`auditex explain` or `--explain`).

## How fast it is

These are measured times to answer one run of 64 checks, on a Mac with an M3 Pro chip and 36 GB of memory, with
other work running on the same machine. A laptop with less memory or an older chip can be slower.

| Model | With Metal (Mac GPU) | Processor only | Peak memory with Metal | Peak memory, processor only |
| --- | --- | --- | --- | --- |
| `qwen` | 145 s | 456 s | 6.4 GB | 5.8 GB |
| `mistral` | 143 s | 696 s | 6.5 GB | 5.6 GB |
| `gemma` | 95 s | 318 s | 6.0 GB | 3.4 GB |
| `small` | 84 s | 258 s | 3.6 GB | 3.4 GB |

With Metal, a 64-check run is answered in under 3 minutes. A runtime built without GPU support runs the model on the
processor alone and is slower: `auditex explain` then prints one line saying so before it starts. The answer is the
same, only slower; `small` is the quickest there. Peak memory is the most the process held
during these runs: its resident size with Metal, and its memory footprint on the processor alone. A model needs a
laptop whose memory is at least about one and a half times that figure.

`small` is the only model measured against an 8 GB laptop. The other three need 16 GB. All four models passed the same
checks: no check fell back to fixed text, no verdict was contradicted, every check that is not met was shown in the
rules' order, and no instruction hidden in a tenant's text changed an answer.
