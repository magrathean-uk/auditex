# Auditex model development (retired)

The parked model layer has been removed from Auditex. The `auditex model` command and its `sources`,
`stage`, `evaluate`, `combine`, `prepare`, `assess` and `doctor` subcommands, the model client and prompt
builders, the training, evaluation and benchmark tools, the oracle and lab case builders, the
model-development examples and the `model_train` extra are no longer in the tree. No product answer ever
came from the model: every SCuBA answer comes from the value rules in `configs/scuba-value-rules.json`.

## Running the assessment

`auditex assess <run-dir>` replaces `auditex model assess`. It writes the same private, rule-only
`model_assessment.json` for a finished run (`endpoint_host: "none"`, `model_name: "rules-only"`, no
`serving` object) and accepts `--policies` and the `--projection-*` budget and scan flags. It has no
dry-run, endpoint, model or redaction options; argparse rejects them with exit 2.

```sh
.venv/bin/auditex assess outputs/ci-contract/ci-contract
.venv/bin/auditex assess outputs/ci-contract/ci-contract --policies MS.AAD.3.4v1,MS.POWERBI.1.1v1
```

Historical model-answered assessment files still validate against their recorded schema. The value-rule
classes, cells and reason codes are described in the [output contract](../reference/output-contract.md).
See [AI assessment](ai-assessment.md) for reading the result.

## Oracle-labelled cases

The tools that mined labelled cases from ScubaGear and Prowler for model development have been removed
with the model layer. The provenance of the vendored ScubaGear data that the shipped catalogue and rules
still use is recorded in [provenance](../provenance/provenance.md).
