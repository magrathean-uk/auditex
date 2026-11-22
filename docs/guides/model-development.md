# Auditex model development (retired)

The parked model layer has been removed from Auditex. The old `model` command and its `sources`,
`stage`, `evaluate`, `combine`, `prepare`, `assess` and `doctor` subcommands, the model client and prompt
builders, the training, evaluation and benchmark tools, the oracle and lab case builders, the
model-development examples and the model training extra are no longer in the tree. No product answer ever
came from the model: every SCuBA answer comes from the value rules in `configs/scuba-value-rules.json`.

## Running the assessment

`auditex assess <run-dir>` replaces the old `model assess` subcommand. It writes the same private, rule-only
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

## Where the training ran

The model experiments of 2026 ran on two research supercomputers: Isambard-AI in the UK and JUPITER in the
EU. None of the trained models shipped; the optional plain-language answer uses a ready-made model, and every
verdict still comes from the value rules.

We acknowledge the use of resources provided by the Isambard-AI National AI Research Resource (AIRR)
(McIntosh-Smith, Alam and Woods, 2024, arXiv:2410.11199), operated by the University of Bristol and funded by
the UK Government's Department for Science, Innovation and Technology through UK Research and Innovation and
the Science and Technology Facilities Council [ST/AIRR/I-A-I/1023]. Neither body has reviewed or endorsed
Auditex.
