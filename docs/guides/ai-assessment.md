# AI assessment

`auditex model assess` adds an optional model-assisted assessment to a finished Microsoft 365 run: for each CISA SCuBA
policy it answers "does this tenant meet the policy?" from the run's evidence, using deterministic rules where
they decide and the Auditex model elsewhere. It reads the bundle, writes one private file
(`model_assessment.json`) and never changes findings, scores, reports, exports or customer packs. It is advisory
and off by default; nothing in the audit depends on it.

> **Direction (planned, not yet built).** Deterministic rules are meant to set every verdict (met, not met, not
> assessed, not applicable). The Auditex model's intended role is an optional explainer, off by default: given the
> rule verdict, the cell, the reason code and a redacted evidence view, it would write a plain-language explanation
> and remediation steps, and it would never emit or override a verdict. None of that exists yet: the explainer is
> not implemented, and the shipped model has not been evaluated as an explainer. Until it exists, `auditex model
> assess` works as this guide describes: rules answer the rows they cover and the model answers the rest.

## What decides each answer

Every policy row in `model_assessment.json` is either a **rule row** (`reason: "rule_precheck"`, zero model calls)
or a **model row** (one chat-completions request, retried once). Rules are checked first, in this order:

| Rule class | When it answers | Answer |
| --- | --- | --- |
| `closed_gate` | A field decides the policy does not apply, e.g. SharePoint sharing set to organisation only, or a US Government cloud for a commercial-only Teams policy | not applicable (`policy_not_applicable`) |
| `absent_section` | A section the policy needs was not collected (missing permission, licence, PowerShell-only data, failed read) | not assessed, naming the missing section |
| `absent_field` | The section was collected but a field the policy's Rego reads is missing | not assessed, naming the field |
| `empty_required_list` | The Conditional Access list was collected and is exactly empty, for the ten AAD policies that need at least one policy | not met |
| `value_rule` | A Power BI or AAD 3.4 setting is evaluated from its available evidence | met, not met, or not assessed with a named reason |

Only rows no rule decides reach the model. Gates, fields and lists are in
`configs/scuba-rule-precheck.json`; value-rule cells are in
`configs/scuba-value-rules.json`. The full precedence is in [model development](model-development.md#rule-pre-checks-and-offline-product-scoring).
Value rules are on by default and can be disabled for incident rollback with
`AUDITEX_DISABLE_VALUE_RULES=1`. These rules use the projected model evidence, so
Power BI and authentication-method evidence withheld by the current projection
still yields not assessed. A planned in-memory rule view will remove that coverage limit.
A deterministic **scope post-check** then marks a "met" verdict whose Conditional Access policy is narrowed
by location, platform, device or client-application conditions that ScubaGear's Rego ignores
(`scope_narrowed`); it never changes the verdict.

`--shadow-model-on-precheck` (shadow mode) also sends rule rows to the model and stores its answer under
`model_shadow`. The shadow never changes the rule verdict, the comparison or the totals; use it to watch model
behaviour on a real tenant, not to override rules.

## Obtain the model

One model ships: **`auditex-ministral3-8b-scuba-v10`**, Ministral 3 8B Instruct with a LoRA adapter trained on the
Auditex SCuBA oracle pack v10, merged and quantised to `model-Q5_K_M.gguf` (6,058,747,104 bytes). It was fine-tuned on verdict labels; its planned role is the optional explainer above, and it
has not been evaluated in that role. Its full
provenance (base revision, adapter archive and weights hashes, llama.cpp revision, training pack, scores) is the `product_model` entry of
`auditex model sources`.

The public Hugging Face repository `magrathean-uk/auditex-ministral3-8b-scuba-v10-GGUF` is **pending upload**.
Until it is published the model is not publicly available. Once it is:

```sh
hf download magrathean-uk/auditex-ministral3-8b-scuba-v10-GGUF model-Q5_K_M.gguf SHA256SUMS --local-dir ./auditex-model
cd auditex-model && shasum -a 256 -c SHA256SUMS      # Linux: sha256sum -c SHA256SUMS
```

The expected SHA-256 is `840fb447eb062d7cae8ff1980d30548e1198138e8235e88e1bc0449bacead01a`. Do not serve a file
that fails the check. A copy distributed as two parts (`model-Q5_K_M.gguf.part-00`, 4,294,967,296 bytes, and
`.part-01`, 1,763,779,808 bytes, made with `split -b 4G`) is reassembled and checked with:

```sh
cat model-Q5_K_M.gguf.part-00 model-Q5_K_M.gguf.part-01 > model-Q5_K_M.gguf
shasum -a 256 -c SHA256SUMS
```

The parts are plain byte splits, not llama.cpp `gguf-split` shards: llama.cpp cannot load them until they are
joined. The base model (`mistralai/Ministral-3-8B-Instruct-2512-BF16`) is Apache-2.0 (read on its model card at the
pinned revision on 31 October 2026), and the merged, quantised file is distributed under Apache-2.0 as a modified work:
a mirror keeps the licence text and the base model's notices and says the weights were modified. The training labels are CC0 1.0.

## Serve it

The validated runtime is `llama-server` from llama.cpp at revision `620d2225cc436ab0b001e3200e590e3b286ef9ab`
(build b11669); later builds probably work but were not measured. Build it for your hardware (Metal on Apple
silicon, CUDA, or CPU) and start it on loopback:

```sh
llama-server -m ./auditex-model/model-Q5_K_M.gguf --alias auditex-ministral3-8b-scuba-v10 \
  --host 127.0.0.1 --port 8080 -c 8192 -ngl 99 --seed 42 --parallel 1 --jinja --no-context-shift
```

`-c 8192` is the context the scores were measured at (test prompts are at most about 1,400 tokens; real tenants
send more). `-ngl 99` offloads every layer to the GPU; leave it out on a CPU-only machine. `--parallel 1` keeps
one slot, so requests are answered one at a time, as measured. `--jinja` uses the chat template embedded in the
GGUF, which is identical to training. For `auditex model assess` (the verdict path, live today), do not add a system prompt or template of your
own: Auditex sends the pinned training system prompt. No prompt exists yet for the planned explainer.

**Memory.** Estimated, not measured: the weights take 6.06 GB and the f16 KV cache at 8,192 tokens about 1.1 GB
(34 layers x 8 KV heads x 128 dimensions x 2 bytes, keys and values, calculated), plus llama.cpp compute and
runtime buffers of a few hundred MB (not measured), so plan on roughly 7.5 to 8 GB of free GPU memory, or of unified
memory on Apple silicon, on top of what the operating system and other applications hold. Whether a given laptop
(for example a 16 GB Apple silicon machine) serves it comfortably has not been measured; check free memory before
starting the server and treat laptop suitability as unverified. On one data-centre GPU it generated about 197 tokens/s, about
0.55 s per policy in the verdict benchmark; a laptop is slower (not measured). A VM works the same way; keep the server on
loopback, or put it behind HTTPS and set `AUDITEX_MODEL_API_KEY` if Auditex runs elsewhere (a non-loopback
endpoint prints a warning, because evidence leaves the machine).

Ollama can load the same file if you restate the chat template in a Modelfile by hand, but that path has not
been validated against the scores; prefer `llama-server`.

## Run the assessment

This is the verdict path, live today; the planned explainer has no command yet.

```sh
export AUDITEX_MODEL_ENDPOINT='http://127.0.0.1:8080/v1'
export AUDITEX_MODEL_NAME='auditex-ministral3-8b-scuba-v10'   # the --alias above
auditex model doctor                                   # endpoint reachable and model listed; exit 2 otherwise
auditex model assess <run-dir> --dry-run               # writes the exact prompts, calls nothing
auditex model assess <run-dir>                         # writes <run-dir>/model_assessment.json
auditex model assess <run-dir> --shadow-model-on-precheck
```

Each request sends temperature 0, `max_tokens` 1024, `cache_prompt: false` (so llama-server does not reuse a cached
prompt prefix and greedy answers do not depend on the previous request) and
`chat_template_kwargs: {"enable_thinking": false}`. A server that rejects `response_format`, `chat_template_kwargs`
or `cache_prompt` with an HTTP 400 naming the field is asked again without it, once per session; the assessment
records what was sent (`serving.cache_prompt`, `serving.response_format`, and `thinking_disabled` per row). This
production request differs from the measured benchmark protocol (`max_tokens` 512, no `response_format`, explicit
`seed` 42, `top_k` 1 and neutral penalties); `configs/model-sources.json` lists both (`serving.benchmark_protocol`,
`serving.production_request`). Production parity was checked only on two collection bundles of one real tenant, used for evaluation only (none of its data is in the training, validation or test rows). Personal values are
redacted before they reach the prompt unless `--no-redaction` is given, which needs a loopback endpoint. The file
is written into the run directory outside the bundle seal (mode 0600); a `model_assessment.json` already sealed in
`bundle-hashes.json` is refused, so assess a fresh copy of such a run.

## Read the result

`totals` counts `answered`, `unknown`, `invalid`, `skipped`, `rule_answered` and `scope_narrowed`. The field values
below are the contract's internal ones; the customer term for `unknown` is "not assessed" (mapping in the
[output contract](../reference/output-contract.md)). Per row:

- `claims[requirement_met]`: `status` `confirmed` with `value` true (met) or false (not met), `inferred` true for
  not applicable, or `unknown` (not assessed). `limitations` and `recommendations` say why, e.g.
  `required_evidence_section_not_collected:<section>` and `collect_missing_evidence_section`.
- `rule_precheck` (rule rows): the class, rule id, section and field that decided.
- `reason` for a row without an answer: `model_transport_failed` (the request or its reply was lost twice: a
  connection error, a timeout, a cut-short or empty body, a body that is not a chat completion; `unknown`, retried
  after a 2 s pause), `model_response_invalid` (the model's text failed the answer contract twice; `invalid`) or
  `model_endpoint_unavailable` (an HTTP error status or an oversized reply; `unknown`, not retried).
- `finish_reason` (model rows): the server's `stop` or `length` for the final reply; `length` means the answer hit
  the 1,024-token cap.
- `attempts`, `latency_ms`, `prompt_sha256`, `response_sha256` for provenance.
- `comparison`: the row against Auditex's own deterministic `cisa_scuba` baseline in `reports/report-pack.json`.
  `agree` or `disagree` only when both sides have a pass/fail verdict; otherwise `not_assessed`.
  `baseline_match` says whether the policy versions matched exactly.

Treat a `disagree` as a prompt to read the evidence, not as a finding: the deterministic findings remain the
audit's answer. The schema and field rules are in the [output contract](../reference/output-contract.md).

## Measured accuracy as an answering model

These figures are what the model scored answering verdict rows, which `auditex model assess` does today for rows
no rule covers; the planned design would drop it, and replacing it is not live. They were measured with the four
pre-check rule classes and before the value rules, so they are not a measure of today's output, and they say nothing
about the explainer, which has not been evaluated.

Measured on 30 October 2026 on the frozen test set test-v7: 435 synthetic cases over 12 policies, built from
ScubaGear's Rego unit-test fixtures and labelled by running that Rego (oracle labels, not human review).

| Measure | Result |
| --- | --- |
| Product, as `auditex model assess` answers (173 rule rows, all correct, plus the model) | 419/435 (96.3 %) |
| Model alone on every row | 403/435 (92.6 %) |
| Product on rows with no training twin (no train row with the same Rego-read evidence) | 282/298 (94.6 %) |
| Product, each of the 12 policies weighted equally | 89.1 % |

The twin-free and per-policy figures were recomputed on 4 November 2026 on the 419/435 scoring, with all four rule
classes (earlier figures: 280/298 and 88.6 % on the 417/435 scoring). The same test set also chose between candidate builds, so all figures
are mildly optimistic. One policy, MS.AAD.9.1v1, is 171 of the 435 rows. Synthetic cases say nothing direct about
real tenants, which are noisier and wider; on the one real tenant used for evaluation only, before the `empty_required_list`
class existed, the model answered "met" for two Conditional Access policies in a tenant that had none.

Known weak classes, to read with care:

- Confident "met" on policies whose rule needs several fields at once: 13 false passes on the test set, for
  example MS.EXO.7.1v1 judged on `State` alone (4/9 correct).
- Teams app policies MS.TEAMS.5.1v1 to 5.3v1: the model tends to reuse one verdict across the three on shared
  evidence.
- A missing field inside a collected section: guessed rather than abstained (4/20 correct), unless an
  `absent_field` rule covers it; SharePoint rows without `SharingCapability` are sometimes called not applicable.

Keep model "met" verdicts advisory: they are not safe to show a customer as a pass without the deterministic
baseline behind them.

## Model lifecycle

The base model is re-chosen in January 2027 against the then-current open models (EU-hosted bases preferred when
within the noise band), retrained on the same oracle pipeline and re-measured on the frozen test before it replaces
this one. A replacement for the planned explainer role would also need an explainer evaluation, which does not
exist yet. A replacement gets a new model id, a new catalogue entry and new scores; this entry stays pinned.
