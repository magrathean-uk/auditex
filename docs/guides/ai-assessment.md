# AI assessment

`auditex model assess <run-dir>` writes an optional rule-only CISA SCuBA assessment from a finished
Microsoft 365 run's local evidence. It writes private `model_assessment.json` without changing findings,
scores, reports, exports or customer packs. No model client or endpoint is called.

## What decides each answer

All 102 catalogue policies have value rules across Entra ID, Exchange Online, Power BI, Power Platform,
Defender, SharePoint and Teams. Rule availability does not guarantee a verdict: available evidence, the adapter
and permissions determine whether a policy can be assessed. A catalogue policy without a rule reports not assessed with
`reason: "rule_not_implemented"` and the constant text:

> Not assessed: Auditex has no rule for this policy yet.

On such a row both claims are unknown, with null values and empty evidence IDs. Limitations and recommendations are
empty; attempts and latency are zero; prompt and response hashes are null; thinking flags are false.
IDs outside the catalogue are skipped as `policy_not_in_catalogue`.

For covered policies, a closed applicability gate wins, then missing sections, then the value predicate.
Rules read a private in-memory view captured before the model projection's frozen shape gate, budgets and
redaction. Source, ledger, collector-error, qualifier and scan checks still apply. A rule's met, not met,
not assessed or not applicable result carries its cell, reason code and constant text. Missing evidence
uses `section_not_collected`; collected but unusable evidence uses `evidence_unusable` and the relevant
reason. Optional Power BI or Power Platform collection not enabled retains
`optional_collection_not_enabled`. A rule fault reports `rule_evaluation_failed` (a shared reason with a null cell, not a catalogue cell) with
`report_product_fault`. Teams 2.2v2, 2.3v2 and 4.1v1 record a closed applicability gate as class
`value_rule`, cell `closed_gate`. The scope envelope is still collected for review. Row-level scope marking has been removed;
`totals.scope_narrowed` stays zero. Historical model-row metadata remains readable.
See the [output contract](../reference/output-contract.md) for exact fields and policy coverage.

For SS 2.1, supply `--sensitive-users <file>` during collection (or set
`AUDITEX_SENSITIVE_USERS_FILE`). Assessment verifies the saved private list,
count and HMAC before passing bare lower-case addresses to that rule in memory.
With the other required evidence, SS 2.1 can now decide; an absent or unusable
list retains the existing not-assessed outcome. A copied bundle replays the
same way. Addresses never enter assessment outputs or model prompts.
SS 2.3 uses the separate `--partner-domains <file>` input (or
`AUDITEX_PARTNER_DOMAINS_FILE`); its verified snapshot reaches only that rule's
private in-memory view, independently of SensitiveUsers.
The ScubaGear export configuration path is unchanged.

Collection replaces the transient `TargetedUsersToProtect` list with a bound
`TargetedUsersCoverage` summary before saving evidence or diagnostics. SS 2.1
can establish met from usable membership and the remaining policy conditions.
Invalid, absent or mismatched summaries never fall back to literal targets;
explicit non-compliant flags or actions can still establish not met.
Missing verified private input reports `section_not_collected`.
`config_list_empty` applies only to a direct ScubaGear configuration with no
usable SensitiveUsers entries. A supplied list alone does not establish
compliance. The summary, binding and operator count/HMAC stay out of assessment
outputs, prompts, shareable exports and customer packs. See
[TargetedUsersCoverage v1](../reference/output-contract.md#targeteduserscoverage-v1)
for limits, replay and resume behaviour.

## Run and read the result

```sh
auditex model assess <run-dir>
auditex model assess <run-dir> --policies MS.AAD.3.4v1,MS.POWERBI.1.1v1
auditex model assess <run-dir> --dry-run
```

Assessment needs no endpoint or model name. Dry-run exports local development prompts to
`model_assessment_prompts.jsonl`; it calls nothing. Both files are private (0600), outside the original
bundle seal; sealed outputs cannot be replaced. Treat them as confidential evidence.

Legacy `--endpoint`, `--model`, `--no-redaction`, `--shadow-model-on-precheck`, `AUDITEX_MODEL_*`
configuration and `AUDITEX_DISABLE_VALUE_RULES` are accepted and ignored with one stderr warning per
invocation, without echoing values. They cannot change any answer. Redaction stays enabled.
Assessment help hides the legacy flags.

The envelope keeps historical field names: `endpoint_host` is `none`, `model_name` is `rules-only`, and
there is no `serving` object. `totals.rule_answered` counts rule rows including abstentions;
`totals.unknown` includes all not-assessed rows, including any `rule_not_implemented` row. Confirmed rule
verdicts can agree or disagree with baseline pass/fail statuses; not-assessed rows compare as `not_assessed`.

## Parked model development

`ModelClient`, `ModelConfig`, the model catalogue, doctor, training, benchmarking and offline evaluation
remain available for development. They do not feed product assessment. `auditex model doctor` probes a
development endpoint only when explicitly invoked. A deterministic template explainer ships and is wired into reports; it describes rule results
and never changes a verdict. The catalogued verdict model is parked and has not been evaluated as an explainer.
See [model development](model-development.md).

## Obtain the catalogued model

One model is catalogued: **`auditex-ministral3-8b-scuba-v10`**, Ministral 3 8B Instruct with a LoRA adapter trained on the
Auditex SCuBA oracle pack v10, merged and quantised to `model-Q5_K_M.gguf` (6,058,747,104 bytes). It was fine-tuned on verdict labels; it is parked, and it
has not been evaluated as an explainer (the shipped explainer is a deterministic template). Its full
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

## Serve it for development

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
GGUF, which is identical to training. The parked development client uses the pinned training system prompt. Product assessment makes no requests. The shipped explainer is a deterministic template and uses no prompt.

**Memory.** Estimated, not measured: the weights take 6.06 GB and the f16 KV cache at 8,192 tokens about 1.1 GB
(34 layers x 8 KV heads x 128 dimensions x 2 bytes, keys and values, calculated), plus llama.cpp compute and
runtime buffers of a few hundred MB (not measured), so plan on roughly 7.5 to 8 GB of free GPU memory, or of unified
memory on Apple silicon, on top of what the operating system and other applications hold. Whether a given laptop
(for example a 16 GB Apple silicon machine) serves it comfortably has not been measured; check free memory before
starting the server and treat laptop suitability as unverified. On one data-centre GPU it generated about 197 tokens/s, about
0.55 s per policy in the verdict benchmark; a laptop is slower (not measured). A VM works the same way; keep the server on
loopback, or put it behind HTTPS and set `AUDITEX_MODEL_API_KEY` for direct development-client experiments elsewhere (a non-loopback
endpoint prints a warning, because evidence leaves the machine).

Ollama can load the same file if you restate the chat template in a Modelfile by hand, but that path has not
been validated against the scores; prefer `llama-server`.

## Measured accuracy as an answering model

These are historical verdict-model measurements from before value rules. They do not measure the current
rule-only assessment or the template explainer. The model is parked and never answers a product policy.

Measured on 30 October 2026 on the frozen test set test-v7: 435 synthetic cases over 12 policies, built from
ScubaGear's Rego unit-test fixtures and labelled by running that Rego (oracle labels, not human review).

| Measure | Result |
| --- | --- |
| Historical rules and model together (173 rule rows, all correct) | 419/435 (96.3 %) |
| Model alone on every row | 403/435 (92.6 %) |
| Historical rules and model on rows with no training twin (no train row with the same Rego-read evidence) | 282/298 (94.6 %) |
| Historical rules and model, each of the 12 policies weighted equally | 89.1 % |

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

These historical verdict scores do not measure the current rule-only assessment or the template explainer.

## Model lifecycle

The base model is re-chosen in January 2027 against the then-current open models (EU-hosted bases preferred when
within the noise band), retrained on the same oracle pipeline and re-measured on the frozen test before it replaces
this one. A replacement would not be used as an explainer without its own explainer evaluation, which does not
exist; the shipped explainer is a deterministic template. A replacement gets a new model id, a new catalogue entry and new scores; this entry stays pinned.
