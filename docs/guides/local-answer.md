# Local Answer Guide

`auditex explain` answers, in plain sentences, what is wrong in a finished audit run (the most severe first) and what is
right. It uses a small language model that runs on the same computer. The rules still decide every verdict and the
order; the model only chooses which prepared sentences and values to show for each check.

## Start

1. Install the optional runtime once. It builds `llama-cpp-python` (llama.cpp) from source, so it needs CMake and a C
   and C++ compiler; on a Mac it is built with Metal. For a pipx install (see the [install guide](install-guide.md)),
   list every extra you want to keep inside the brackets:

   ```bash
   pipx install --force "auditex[local-answer]"
   ```

   In a source checkout, run this in the Auditex folder instead:

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

## Google Workspace runs

`auditex explain` answers a Google Workspace run the same way. When the run has no rule assessment yet it writes one
against the 138 policies of the CISA SCuBA Google Workspace baselines (ScubaGoggles v1.1.0), the model is told the
tenant is a Google Workspace tenant, and the same checks apply to every selection. An assessment that covers only part
of the catalogue says so in its first line ("Partial: the rules assessed N of the 138 SCuBA Google Workspace checks in
the shipped catalogue; ..."). A Google run has more checks than the 64-check run timed below, so it takes longer.

## What it downloads

The first use of a model downloads one file from the Hugging Face site (`huggingface.co` and its download servers), at
the revision Auditex pins, into the user cache: `~/Library/Caches/auditex/models` on macOS, `%LOCALAPPDATA%\auditex\models` on Windows, and
`$XDG_CACHE_HOME/auditex/models` (or `~/.cache/auditex/models`) elsewhere. Set `AUDITEX_MODEL_DIR` to keep the files
somewhere else. Before it starts, the command prints the size, the repository and revision, and names the model's licence;
it then shows progress, and an interrupted download resumes. `local_answer.json` records the licence with the model
(choice, repository, revision, file, size and SHA-256); an answer saved before the licence was recorded is refused as made
by another Auditex version, so run `auditex explain` again.

Auditex checks the file's size and SHA-256 against the pinned values before it is used, and checks the SHA-256 again
before every load. A file that does not match is deleted and not used. After the download the answer runs offline. Keep
free disk space for the file you choose: the sizes are in the table above.

Auditex does not include or redistribute any model. The file comes from the repository named below, under that
model's own licence, which you accept by downloading and using it. Like any download, the request shows Hugging Face
your IP address; it carries nothing about your run or your tenant.

| `--model` | Downloaded from (Hugging Face repository) | Model by | Licence |
| --- | --- | --- | --- |
| `qwen` | `unsloth/Qwen3.5-9B-GGUF` (a conversion by Unsloth) | Alibaba Cloud (Qwen) | Apache-2.0 |
| `mistral` | `mistralai/Ministral-3-8B-Instruct-2512-GGUF` | Mistral AI | Apache-2.0 |
| `gemma` | `google/gemma-4-E4B-it-qat-q4_0-gguf` | Google | Apache-2.0 |
| `small` | `unsloth/Qwen3.5-4B-GGUF` (a conversion by Unsloth) | Alibaba Cloud (Qwen) | Apache-2.0 |

The licences were read on the model pages on 21 November 2026 at the pinned revisions. Auditex is not affiliated with
or endorsed by these publishers.

## What it never does

- It never sends anything about your run or your tenant anywhere. The model download (from Hugging Face and its
  download servers) is the only network call, and there is no telemetry.
- It never changes a verdict, the order or the number of checks. The model's output is only a list of sentence and value
  ids; Auditex checks every id and renders every word. Every check that is not met is always shown, in the rules' order,
  whatever the model selects.
- Text from your tenant cannot add words to the answer or change a verdict. Reasons, settings and names from the tenant
  are shown to the model quoted and labelled as data, the model can only pick from prepared sentences, and a selection
  that does not pass the checks shows that check's fixed text. The answer states how many checks used the fixed text.
  In the acceptance runs no instruction hidden in tenant text changed an answer; that is a test result, not a promise
  about every possible input.
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
