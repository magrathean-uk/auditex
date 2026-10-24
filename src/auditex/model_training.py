"""Offline curation and a guarded, optional single-base LoRA training recipe.

This module prepares data without importing a model runtime, downloading weights,
or granting approval to proposed labels. Training dependencies are imported only
by an explicitly invoked, qualified-runtime training entry point.
"""
from __future__ import annotations

import argparse
from collections.abc import Mapping
import hashlib
import json
import os
import re
import unicodedata
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = "2026-10-18"
DEFAULT_BASE_MODEL = "Qwen/Qwen3.8-27B"
RUNTIME_PACKAGE_CANDIDATES = {
    "torch": "2.14.1", "transformers": "5.20.1", "trl": "1.16.0",
    "peft": "0.21.2", "accelerate": "1.15.0", "datasets": "5.1.0",
}
_REVISION = re.compile(r"[0-9a-fA-F]{40}")
_MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*")
_SPLITS = {"train", "validation", "test"}
_SHA256 = re.compile(r"[0-9a-f]{64}")
_PROVENANCE_REQUIRED = {"source", "synthetic", "review_status"}
# template groups cases by reasoning template and distinct_prompt_sha256 marks id-only duplicates; both are
# optional curation aids written by scripts/build-oracle-cases.py and read by scripts/split-oracle-cases.py.
# evidence_view and oracle_outcome record how an oracle-labelled case was derived; oracle_provenance() also
# reads them from the evidence_view= and oracle_outcome= pairs that older miner output keeps in source.
# consensus_weight marks an oracle row whose second-engine agreement says nothing (the other engine never changes its verdict across
# the fixture family), so the row weighs as a ScubaGear-only one; adjudication records the ruling of a written adjudication of a
# disagreement that kept the ScubaGear label. Neither changes a label or an export.
_PROVENANCE_OPTIONAL = {"reviewer", "template", "distinct_prompt_sha256", "evidence_view", "oracle_outcome", "consensus_weight", "adjudication"}
_CONSENSUS_WEIGHTS = ("scubagear_only",)
_EVIDENCE_VIEWS = ("rego_ast", "widened")
_ORACLE_OUTCOMES = ("met", "not_met", "fail_closed_missing_input", "not_applicable", "not_collected")
_ORACLE_PROVENANCE_FIELDS = ("evidence_view", "oracle_outcome")
_SOURCE_PAIRS = {field: re.compile(rf"(?:^|;)\s*{field}=([^;\s]+)") for field in _ORACLE_PROVENANCE_FIELDS}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _invalid_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON constant: {value}")


def _parse_json(text: str) -> Any:
    return json.loads(text, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a nonempty string")
    return value.strip()


def _string_set(value: Any, field: str) -> set[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValueError(f"{field} must be an array of nonempty strings")
    if len(set(value)) != len(value):
        raise ValueError(f"{field} contains duplicates")
    return set(value)


def _response_key(value: Any, allowed_evidence_ids: set[str]) -> str:
    """Use the evaluator's exact schema and canonical structured-answer identity."""
    from .model_eval import _response_fingerprint, _validate_response

    response = _validate_response(value)
    if any(not set(claim["evidence_ids"]) <= allowed_evidence_ids for claim in response["claims"]):
        raise ValueError("claim references evidence outside its case allowlist")
    return _response_fingerprint(response)


def validate_case(payload: Any) -> dict[str, Any]:
    """Validate a declared review case; this never creates human approval."""
    required = {"id", "family", "split", "provenance", "messages", "expected"}
    if not isinstance(payload, dict) or set(payload) != required:
        raise ValueError("case requires only id, family, split, provenance, messages and expected")
    _text(payload["id"], "case id")
    _text(payload["family"], "case family")
    if not isinstance(payload["split"], str) or payload["split"] not in _SPLITS:
        raise ValueError("case split must be train, validation or test")
    provenance = payload["provenance"]
    if not isinstance(provenance, dict) or not _PROVENANCE_REQUIRED <= set(provenance) <= _PROVENANCE_REQUIRED | _PROVENANCE_OPTIONAL:
        raise ValueError("provenance requires source, synthetic, review_status and optional reviewer, template, "
                         "distinct_prompt_sha256, evidence_view, oracle_outcome, consensus_weight and adjudication")
    _text(provenance["source"], "provenance source")
    if type(provenance["synthetic"]) is not bool:
        raise ValueError("provenance synthetic must be a boolean")
    if not isinstance(provenance["review_status"], str) or provenance["review_status"] not in {"approved", "unreviewed"}:
        raise ValueError("review_status must be approved or unreviewed")
    for optional in ("reviewer", "template"):
        if optional in provenance:
            _text(provenance[optional], optional)
    if "distinct_prompt_sha256" in provenance and not (
            isinstance(provenance["distinct_prompt_sha256"], str) and _SHA256.fullmatch(provenance["distinct_prompt_sha256"])):
        raise ValueError("distinct_prompt_sha256 must be a lowercase hex SHA-256 digest")
    for field, allowed_values in (("evidence_view", _EVIDENCE_VIEWS), ("oracle_outcome", _ORACLE_OUTCOMES)):
        if field in provenance and not (isinstance(provenance[field], str) and provenance[field] in allowed_values):
            raise ValueError(f"{field} must be one of {', '.join(allowed_values)}")
    if "consensus_weight" in provenance and not (isinstance(provenance["consensus_weight"], str) and provenance["consensus_weight"] in _CONSENSUS_WEIGHTS):
        raise ValueError(f"consensus_weight must be one of {', '.join(_CONSENSUS_WEIGHTS)}")
    if "adjudication" in provenance:
        adjudication = provenance["adjudication"]
        if not isinstance(adjudication, dict) or set(adjudication) != {"source", "ruling"}:
            raise ValueError("adjudication requires only source and ruling")
        _text(adjudication["source"], "adjudication source")
        _text(adjudication["ruling"], "adjudication ruling")
    messages = payload["messages"]
    if not isinstance(messages, list) or len(messages) < 2:
        raise ValueError("messages require a prompt and final assistant response")
    for index, message in enumerate(messages):
        if not isinstance(message, dict) or set(message) != {"role", "content"}:
            raise ValueError("each message requires only role and content")
        if not isinstance(message["role"], str) or message["role"] not in {"system", "user", "assistant"}:
            raise ValueError("unsupported message role")
        if message["role"] == "system" and index != 0:
            raise ValueError("system message is allowed only at the start")
        _text(message["content"], "message content")
    if messages[-1]["role"] != "assistant" or not any(message["role"] == "user" for message in messages[:-1]):
        raise ValueError("case requires a user prompt and a final assistant response")
    expected = payload["expected"]
    if not isinstance(expected, dict) or set(expected) != {"claims", "limitations", "recommendations", "allowed_evidence_ids"}:
        raise ValueError("expected requires claims, limitations, recommendations and allowed_evidence_ids")
    allowed = _string_set(expected["allowed_evidence_ids"], "allowed_evidence_ids")
    response = {key: expected[key] for key in ("claims", "limitations", "recommendations")}
    expected_key = _response_key(response, allowed)
    # Proposed labels remain unreviewed. Approved supervised answers must match
    # their declared rubric rather than quietly teaching a conflicting answer.
    if provenance["review_status"] == "approved":
        _text(provenance.get("reviewer"), "approved case reviewer")
        if _response_key(_parse_json(messages[-1]["content"]), allowed) != expected_key:
            raise ValueError("approved assistant response conflicts with expected labels")
    # Reject non-finite values even for in-memory callers, not just JSONL input.
    try:
        json.dumps(payload, allow_nan=False)
    except (ValueError, TypeError) as exc:
        raise ValueError("case must contain finite JSON values") from exc
    return payload


def oracle_provenance(case: dict[str, Any]) -> dict[str, str | None]:
    """The oracle attributes `evidence_view` and `oracle_outcome` of a case, `None` where a case records neither.

    A first-class provenance field wins. Otherwise the value comes from the first `key=value` pair of that name in
    `provenance.source` (the form older miner output uses). Only validate_case checks the enums, so a pair parsed from
    a legacy source can hold a value such as `evaluated` that the field itself would reject."""
    provenance = case["provenance"]
    source = provenance.get("source")
    result: dict[str, str | None] = {}
    for field in _ORACLE_PROVENANCE_FIELDS:
        value = provenance.get(field)
        if value is None and isinstance(source, str):
            match = _SOURCE_PAIRS[field].search(source)
            value = match.group(1) if match else None
        result[field] = value
    return result


def _normalized_prompt(case: dict[str, Any], *, mask_id: bool = False) -> str:
    """Casefolded, whitespace-normalized prompt; with mask_id the case's own id is hidden where it labels
    the case (the quoted case_id value and the `<id>:` evidence-id prefix), so id-only variants compare equal."""
    case_id = case["id"].strip()
    messages = []
    for item in case["messages"][:-1]:
        content = item["content"]
        if mask_id:
            content = content.replace(f'"{case_id}"', '"<case>"').replace(f"{case_id}:", "<case>:")
        messages.append({"role": item["role"],
                         "content": " ".join(unicodedata.normalize("NFKC", content).casefold().split())})
    return json.dumps(messages, ensure_ascii=False, sort_keys=True)


def distinct_prompt_sha256(case: dict[str, Any]) -> str:
    """SHA-256 of the id-masked normalized prompt, the key that makes id-only duplicates detectable."""
    return hashlib.sha256(_normalized_prompt(case, mask_id=True).encode("utf-8")).hexdigest()


def _answer_key(case: dict[str, Any], *, mask_id: bool = False) -> str:
    """Canonical answer; with mask_id the `<id>:` evidence prefix is hidden, matching _normalized_prompt."""
    case_id = case["id"].strip()
    expected = case["expected"]
    response = {key: expected[key] for key in ("claims", "limitations", "recommendations")}
    allowed = set(expected["allowed_evidence_ids"])
    if mask_id:
        response["claims"] = [{**claim, "evidence_ids": [item.replace(f"{case_id}:", "<case>:") for item in claim["evidence_ids"]]}
                              for claim in expected["claims"]]
        allowed = {item.replace(f"{case_id}:", "<case>:") for item in allowed}
    return _response_key(response, allowed)


def distinct_cases(cases: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    """Keep the first of each id-only duplicate (same masked prompt and answer); report the dropped ids."""
    kept: list[dict[str, Any]] = []
    dropped: list[str] = []
    seen: set[tuple[str, str]] = set()
    for case in cases:
        key = (_normalized_prompt(case, mask_id=True), _answer_key(case, mask_id=True))
        if key in seen:
            dropped.append(case["id"].strip())
            continue
        seen.add(key)
        kept.append(case)
    return kept, dropped


def validate_cases(cases: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    ids: set[str] = set()
    families: dict[str, str] = {}
    prompts: dict[str, str] = {}
    answers: dict[str, Any] = {}
    for raw in cases:
        case = validate_case(raw)
        case_id = case["id"].strip()
        if case_id in ids:
            raise ValueError(f"duplicate case id: {case_id}")
        ids.add(case_id)
        family = unicodedata.normalize("NFKC", case["family"]).strip().casefold()
        split = case["split"]
        if family in families and families[family] != split:
            raise ValueError(f"family leakage across splits: {case['family']}")
        # Both the literal prompt and the id-masked prompt must stay inside one split with one answer, so a
        # copied prompt and an id-only re-skin are both caught.
        for mask_id in (False, True):
            prompt = _normalized_prompt(case, mask_id=mask_id)
            answer = _answer_key(case, mask_id=mask_id)
            if prompt in prompts and prompts[prompt] != split:
                raise ValueError(f"normalized prompt leakage across splits: {case_id}")
            if prompt in answers and answers[prompt] != answer:
                raise ValueError(f"conflicting labels for normalized prompt: {case_id}")
            answers[prompt] = answer
            prompts[prompt] = split
        families[family] = split
        result.append(case)
    return result


def _read_case_sources(paths: str | Path | Iterable[str | Path]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    selected = [paths] if isinstance(paths, (str, Path)) else list(paths)
    cases = []
    sources = []
    for path in selected:
        data = Path(path).read_bytes()
        sources.append({"path": str(Path(path).resolve()), "sha256": hashlib.sha256(data).hexdigest()})
        for number, line in enumerate(data.decode("utf-8-sig").splitlines(), 1):
            if not line.strip():
                continue
            try:
                cases.append(_parse_json(line))
            except (ValueError, TypeError) as exc:
                raise ValueError(f"invalid case JSON at {path}:{number}: {exc}") from exc
    return validate_cases(cases), sources


def load_cases(paths: str | Path | Iterable[str | Path]) -> list[dict[str, Any]]:
    """Read strict JSONL without dropping unreviewed cases or relaxing splits."""
    return _read_case_sources(paths)[0]


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(row, ensure_ascii=False, allow_nan=False) + "\n" for row in rows), encoding="utf-8")
    path.chmod(0o600)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _outside_audit_runs(path: Path) -> None:
    resolved = path.resolve()
    if any((parent / "run-manifest.json").exists() for parent in (resolved, *resolved.parents)):
        raise ValueError("model-development output must be outside finalized audit runs")


def _trl_record(case: dict[str, Any]) -> dict[str, Any]:
    # TRL applies the chat template per example with these kwargs. Thinking must be off so the prompt renders
    # exactly as the thinking-off inference prefix (empty think block, no reasoning-effort preamble) and the
    # completion-only loss starts at the JSON answer.
    return {"prompt": case["messages"][:-1], "completion": [case["messages"][-1]],
            "chat_template_kwargs": {"enable_thinking": False}}


_SFT_OVERRIDE_KEYS = {
    # warmup_steps takes an integer step count or a float ratio in [0, 1); transformers 5 has no warmup_ratio.
    "max_steps", "num_train_epochs", "learning_rate", "lr_scheduler_type", "warmup_steps",
    "weight_decay", "max_grad_norm", "per_device_train_batch_size", "per_device_eval_batch_size",
    "gradient_accumulation_steps", "save_strategy", "save_steps", "save_total_limit", "eval_strategy", "eval_steps",
    "logging_steps", "load_best_model_at_end", "metric_for_best_model", "greater_is_better", "max_length", "seed",
    "ddp_find_unused_parameters", "dataloader_num_workers",
}
_PEFT_OVERRIDE_KEYS = {"r", "lora_alpha", "lora_dropout", "target_modules", "use_rslora", "use_dora"}


def _apply_training_overrides(config: dict[str, Any], overrides: dict[str, Any] | None) -> dict[str, Any]:
    """Merge a reviewed {"sft": {...}, "peft": {...}} document; the recipe's guards cannot be overridden."""
    if overrides is None:
        return config
    if not isinstance(overrides, dict) or not set(overrides) <= {"sft", "peft"}:
        raise ValueError("training overrides must be an object with only sft and/or peft sections")
    for section, allowed in (("sft", _SFT_OVERRIDE_KEYS), ("peft", _PEFT_OVERRIDE_KEYS)):
        values = overrides.get(section, {})
        if not isinstance(values, dict):
            raise ValueError(f"training overrides {section} must be an object")
        unknown = sorted(set(values) - allowed)
        if unknown:
            raise ValueError(f"training overrides {section} keys not allowed: {', '.join(unknown)}")
        config[section].update(values)
    sft = config["sft"]
    if type(sft.get("max_steps")) is not int or type(sft.get("per_device_train_batch_size")) is not int \
            or type(sft.get("gradient_accumulation_steps")) is not int or sft["per_device_train_batch_size"] < 1 \
            or sft["gradient_accumulation_steps"] < 1 or (sft["max_steps"] < 1 and sft["max_steps"] != -1):
        raise ValueError("max_steps must be -1 (epochs) or positive; batch and accumulation must be positive integers")
    if sft.get("load_best_model_at_end") and (sft.get("save_strategy") != sft.get("eval_strategy")):
        raise ValueError("load_best_model_at_end requires matching save and eval strategies")
    return config


_TRAIN_SCRIPT = '''#!/usr/bin/env python3
"""Explicitly invoked local/cluster recipe; never installs or downloads."""
from auditex.model_training import training_main

if __name__ == "__main__":
    raise SystemExit(training_main())
'''

_SLURM_SCRIPT = '''#!/bin/bash
# Submit manually with the confirmed account, e.g. sbatch --account=ACCOUNT this-file.
#SBATCH --job-name=auditex-pilot
#SBATCH --partition=booster
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=288
#SBATCH --gpus-per-node=4
#SBATCH --exclusive
#SBATCH --time=01:30:00
set -euo pipefail
# Slurm 22.05-23.02 stopped passing --cpus-per-task to srun steps; exporting it keeps every rank's threads.
export SRUN_CPUS_PER_TASK="${SLURM_CPUS_PER_TASK:-288}"
: "${JUPITER_ENV_SETUP:?Set an absolute, qualified Arm64 environment setup file}"
: "${AUDITEX_PACK_DIR:?Set the absolute reviewed training-pack directory}"
: "${AUDITEX_TRAIN_OUTPUT:?Set a new durable checkpoint/output directory}"
source "$JUPITER_ENV_SETUP"
: "${PYTHON_BIN:?Environment setup must select an absolute qualified Python}"
: "${HF_HOME:?Use explicit project cache storage}"
: "${XDG_CACHE_HOME:?Use explicit project cache storage}"
: "${TORCH_HOME:?Use explicit project cache storage}"
: "${TRITON_CACHE_DIR:?Use explicit project cache storage}"
: "${TMPDIR:?Use explicit project scratch storage}"
[[ "${SLURM_JOB_NUM_NODES:-}" == 1 ]] || { echo "Requires one allocated node" >&2; exit 1; }
[[ "${SLURM_GPUS_ON_NODE:-}" == 4 ]] || { echo "Requires all four allocated GPUs" >&2; exit 1; }
[[ "$PYTHON_BIN" = /* ]] || { echo "PYTHON_BIN must be absolute" >&2; exit 1; }
# JSC currently exposes one GPU to a one-task launch unless visibility is set.
# This override is confined to the verified full four-GPU allocation above.
export CUDA_VISIBLE_DEVICES=0,1,2,3
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 HF_DATASETS_OFFLINE=1
srun --ntasks=1 --gpus-per-task=4 "$PYTHON_BIN" -m torch.distributed.run --standalone --nnodes=1 --nproc_per_node=4 \\
  "$AUDITEX_PACK_DIR/train_lora.py" --pack-dir "$AUDITEX_PACK_DIR" \\
  --output-dir "$AUDITEX_TRAIN_OUTPUT" "$@"
# After separate runtime qualification, pass --runtime-qualified explicitly.
# Add --resume-from-checkpoint /absolute/checkpoint to resume saved trainer state.
'''


def prepare_training_pack(
    case_paths: str | Path | Iterable[str | Path],
    output_dir: str | Path,
    *,
    base_model: str = DEFAULT_BASE_MODEL,
    revision: str | None = None,
    max_steps: int = 100,
    training_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Prepare one base model's data and recipes, preserving proposed labels."""
    paths = [case_paths] if isinstance(case_paths, (str, Path)) else list(case_paths)
    if not paths:
        raise ValueError("at least one cases JSONL is required")
    if training_overrides is not None:
        json.dumps(training_overrides, allow_nan=False)
    base_model = _text(base_model, "base_model")
    if not _MODEL_ID.fullmatch(base_model):
        raise ValueError("base_model must identify one owner/model repository, not a local path or model list")
    if revision is not None and (not isinstance(revision, str) or not _REVISION.fullmatch(revision)):
        raise ValueError("revision must be an immutable 40-character model commit SHA")
    if type(max_steps) is not int or max_steps < 1:
        raise ValueError("max_steps must be a positive pilot step limit")
    cases, sources = _read_case_sources(paths)
    approved = [case for case in cases if case["provenance"]["review_status"] == "approved"]
    quarantined = [case for case in cases if case["provenance"]["review_status"] != "approved"]
    splits = {split: [case for case in approved if case["split"] == split] for split in sorted(_SPLITS)}
    # Id-only duplicates would give one template double weight; export each distinct example once.
    distinct_train, dropped_train = distinct_cases(splits["train"])
    distinct_validation, dropped_validation = distinct_cases(splits["validation"])
    destination = Path(output_dir)
    _outside_audit_runs(destination)
    if destination.is_symlink() or destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
        raise ValueError("training output directory must be new or empty")
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    _write_jsonl(destination / "train.jsonl", (_trl_record(case) for case in distinct_train))
    _write_jsonl(destination / "validation.jsonl", (_trl_record(case) for case in distinct_validation))
    _write_jsonl(destination / "test.jsonl", splits["test"])
    _write_jsonl(destination / "approved-cases.jsonl", approved)
    _write_jsonl(destination / "quarantine.jsonl", quarantined)
    config = {
        "base_model": base_model,
        "revision": revision.lower() if revision else None,
        "method": "bf16_lora",
        "peft": {"r": 16, "lora_alpha": 32, "lora_dropout": 0.05, "target_modules": "all-linear", "bias": "none", "task_type": "CAUSAL_LM"},
        "sft": {
            "bf16": True, "gradient_checkpointing": True,
            "gradient_checkpointing_kwargs": {"use_reentrant": False},
            "completion_only_loss": True, "max_length": 4096, "max_steps": max_steps,
            "per_device_train_batch_size": 1, "gradient_accumulation_steps": 8,
            "learning_rate": 0.0001, "lr_scheduler_type": "cosine", "warmup_steps": 0.05, "num_train_epochs": 2,
            "save_strategy": "steps", "save_steps": 25, "save_total_limit": 2,
            "eval_strategy": "steps", "eval_steps": 25, "logging_steps": 5,
            "load_best_model_at_end": True, "metric_for_best_model": "eval_loss", "greater_is_better": False,
            "report_to": "none", "seed": 42,
        },
        "local_files_only": True,
        "trust_remote_code": False,
        "runtime_qualification": "pending_arm64_gh200_and_model_architecture",
        "runtime_package_candidates": RUNTIME_PACKAGE_CANDIDATES,
        "text_only": True,
    }
    config = _apply_training_overrides(config, training_overrides)
    _write_json(destination / "training-config.json", config)
    (destination / "train_lora.py").write_text(_TRAIN_SCRIPT, encoding="utf-8")
    (destination / "jupiter-auditex.sbatch").write_text(_SLURM_SCRIPT, encoding="utf-8")
    (destination / "train_lora.py").chmod(0o600)
    (destination / "jupiter-auditex.sbatch").chmod(0o600)
    blocked = []
    if not revision:
        blocked.append("immutable_base_revision_missing")
    for split, rows in splits.items():
        if not rows:
            blocked.append(f"approved_{split}_cases_missing")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "base_model": base_model, "base_revision": config["revision"],
        "one_base_model": True, "weight_merging": False,
        "sources": sources,
        "counts": {**{split: len(rows) for split, rows in splits.items()}, "quarantined": len(quarantined),
                   "exported_train": len(distinct_train), "exported_validation": len(distinct_validation)},
        "deduplicated_ids": {"train": dropped_train, "validation": dropped_validation},
        "training_overrides": training_overrides,
        "families": {split: sorted({case["family"] for case in rows}) for split, rows in splits.items()},
        "job_ready": not blocked,
        "blocked_reasons": blocked,
        "runtime_qualification": config["runtime_qualification"],
        "evaluation_status": "not_run",
        "review_basis": "declared provenance; this preparation does not grant or independently verify approval",
        "token_budget": {"status": "unknown_tokenizer_not_run", "training_tokens": None, "gpu_hours": None},
        "files": {path.name: _digest(path) for path in sorted(destination.iterdir()) if path.is_file()},
    }
    _write_json(destination / "manifest.json", manifest)
    return manifest


def validate_training_pack(pack_dir: str | Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Fail before runtime imports if preparation, approval or hashes are stale."""
    root = Path(pack_dir)
    manifest = _parse_json((root / "manifest.json").read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("training pack manifest must be an object")
    if manifest.get("schema_version") != SCHEMA_VERSION or manifest.get("job_ready") is not True:
        raise ValueError("training pack is not ready: " + ", ".join(manifest.get("blocked_reasons") or ["invalid manifest"]))
    files = manifest.get("files")
    required = {"train.jsonl", "validation.jsonl", "test.jsonl", "approved-cases.jsonl", "quarantine.jsonl", "training-config.json", "train_lora.py", "jupiter-auditex.sbatch"}
    if not isinstance(files, dict) or set(files) != required:
        raise ValueError("training pack file manifest is incomplete")
    for name, digest in files.items():
        if _digest(root / name) != digest:
            raise ValueError(f"training pack hash mismatch: {name}")
    config = _parse_json((root / "training-config.json").read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise ValueError("training config must be an object")
    revision = config.get("revision")
    if not isinstance(revision, str) or not _REVISION.fullmatch(revision):
        raise ValueError("immutable base revision is required before model loading")
    if config.get("base_model") != manifest.get("base_model") or revision != manifest.get("base_revision"):
        raise ValueError("training base model does not match manifest")
    sft = config.get("sft")
    if (not isinstance(sft, dict) or config.get("method") != "bf16_lora" or config.get("local_files_only") is not True
            or config.get("trust_remote_code") is not False or sft.get("report_to") != "none"
            or sft.get("completion_only_loss") is not True or config.get("text_only") is not True):
        raise ValueError("training config must preserve the offline completion-only LoRA recipe")
    cases = load_cases(root / "approved-cases.jsonl")
    if any(case["provenance"]["review_status"] != "approved" for case in cases):
        raise ValueError("unreviewed case in approved training pack")
    for split in ("train", "validation", "test"):
        selected = [case for case in cases if case["split"] == split]
        if not selected or len(selected) != manifest["counts"][split]:
            raise ValueError(f"approved {split} cases missing or count mismatch")
        records = [_parse_json(line) for line in (root / f"{split}.jsonl").read_text(encoding="utf-8").splitlines()]
        expected = selected if split == "test" else [_trl_record(case) for case in distinct_cases(selected)[0]]
        if records != expected:
            raise ValueError(f"{split} export conflicts with approved cases")
    return manifest, config


def _load_text_model(snapshot: str, *, torch: Any, transformers: Any) -> Any:
    """Use the explicit text backbone for Qwen's multimodal configuration."""
    settings = {"local_files_only": True, "trust_remote_code": False}
    model_config = transformers.AutoConfig.from_pretrained(snapshot, **settings)
    if model_config.model_type == "qwen3_5":
        # Qwen3_5TextConfig extracts the checkpoint's nested text_config. The
        # explicit text class excludes vision modules from both loading and LoRA.
        model_config = transformers.Qwen3_5TextConfig.from_pretrained(snapshot, **settings)
        loader = transformers.Qwen3_5ForCausalLM
        settings["key_mapping"] = {r"^model\.language_model\.": "model."}
    else:
        loader = transformers.AutoModelForCausalLM
    model, loading = loader.from_pretrained(
        snapshot, config=model_config, dtype=torch.bfloat16,
        output_loading_info=True, **settings,
    )
    if loading.get("missing_keys") or loading.get("mismatched_keys") or loading.get("error_msgs"):
        raise ValueError("text checkpoint did not load completely; qualify the loader before training")
    unexpected = loading.get("unexpected_keys") or []
    if any(not name.startswith(("model.visual.", "mtp.", "model.mtp.")) for name in unexpected):
        raise ValueError("unexpected checkpoint weights require loader qualification")
    return model


def _measure_training_tokens(cases: list[dict[str, Any]], tokenizer: Any, max_length: int) -> dict[str, Any]:
    counts: dict[str, list[int]] = {"train": [], "validation": []}
    for case in cases:
        if case["split"] not in counts:
            continue
        encoded = tokenizer.apply_chat_template(case["messages"], tokenize=True, add_generation_prompt=False,
                                                enable_thinking=False)
        # Transformers 5 returns a BatchEncoding mapping by default; earlier releases return the id list.
        tokens = encoded["input_ids"] if isinstance(encoded, Mapping) else encoded
        if not isinstance(tokens, (list, tuple)) or not all(isinstance(token, int) for token in tokens):
            raise ValueError("tokenizer must return a flat list of token ids for the length guard")
        length = len(tokens)
        if not 0 < length <= max_length:
            raise ValueError(f"case {case['id']} has {length} tokens; review it before training instead of truncating at {max_length}")
        counts[case["split"]].append(length)
    return {"status": "measured_with_pinned_tokenizer", "tokens_per_pass": {split: sum(values) for split, values in counts.items()},
            "max_case_tokens": max((value for values in counts.values() for value in values), default=0)}


def _record_checkpoint_input(output: Path, step: int, input_record: dict[str, Any]) -> None:
    """Bind each Trainer checkpoint to the inputs that actually produced it."""
    checkpoint = output / f"checkpoint-{step}"
    if not checkpoint.is_dir():
        raise ValueError("saved checkpoint directory is missing")
    _write_json(checkpoint / "auditex-training-input.json", input_record)


def _validate_resume_input(output: Path, checkpoint: Path, input_record: dict[str, Any]) -> None:
    for directory in (output, checkpoint):
        record = directory / "auditex-training-input.json"
        if not record.is_file():
            raise ValueError("resume requires input identity in both the output and selected checkpoint")
        if _parse_json(record.read_text(encoding="utf-8")) != input_record:
            raise ValueError("resume checkpoint belongs to another base model or data pack")


def training_main(argv: list[str] | None = None) -> int:
    """Optional training entry point. Preparation and tests never invoke it."""
    parser = argparse.ArgumentParser(description="Train one reviewed Auditex LoRA adapter using staged local weights")
    parser.add_argument("--pack-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--resume-from-checkpoint")
    parser.add_argument("--runtime-qualified", action="store_true")
    args = parser.parse_args(argv)
    manifest, config = validate_training_pack(args.pack_dir)
    if not args.runtime_qualified:
        raise ValueError("qualify the model architecture and Arm64/GH200 stack, then pass --runtime-qualified")
    for name in ("HF_HOME", "XDG_CACHE_HOME", "TORCH_HOME", "TRITON_CACHE_DIR", "TMPDIR"):
        if not os.environ.get(name) or not Path(os.environ[name]).is_absolute():
            raise ValueError(f"set {name} to absolute project cache/scratch storage before training")
    root = Path(args.pack_dir)
    output = Path(args.output_dir)
    _outside_audit_runs(output)
    if output.resolve().is_relative_to(root.resolve()) or root.resolve().is_relative_to(output.resolve()):
        raise ValueError("training output must be separate from the immutable data pack")
    input_record = {"base_model": manifest["base_model"], "base_revision": manifest["base_revision"],
                    "pack_manifest_sha256": _digest(root / "manifest.json")}
    if args.resume_from_checkpoint:
        checkpoint = Path(args.resume_from_checkpoint)
        if not checkpoint.is_dir() or checkpoint.resolve() == output.resolve() or not checkpoint.resolve().is_relative_to(output.resolve()):
            raise ValueError("resume checkpoint must be inside the selected training output")
        _validate_resume_input(output, checkpoint, input_record)
    # Only the leader tests an initial destination for emptiness. A slower
    # worker must not mistake this launch's leader-created files for old work.
    elif int(os.environ.get("RANK", "0")) == 0 and output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("use a new output directory or an explicit resume checkpoint")
    os.environ.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", HF_DATASETS_OFFLINE="1", HF_HUB_DISABLE_TELEMETRY="1")
    # These are optional dependencies. There is intentionally no installation,
    # login, provider API or download fallback in this path.
    import torch
    import transformers
    from datasets import load_dataset
    from huggingface_hub import snapshot_download
    from importlib.metadata import version
    from peft import LoraConfig
    from transformers import AutoTokenizer, TrainerCallback
    from trl import SFTConfig, SFTTrainer

    if not torch.cuda.is_available() or not torch.cuda.is_bf16_supported():
        raise ValueError("the qualified recipe requires a BF16-capable CUDA device")
    snapshot = snapshot_download(repo_id=config["base_model"], revision=config["revision"], local_files_only=True)
    if Path(snapshot).name != config["revision"]:
        raise ValueError("staged model snapshot does not resolve to the pinned revision")
    tokenizer = AutoTokenizer.from_pretrained(snapshot, local_files_only=True, trust_remote_code=False)
    token_budget = _measure_training_tokens(load_cases(root / "approved-cases.jsonl"), tokenizer, config["sft"]["max_length"])
    model = _load_text_model(snapshot, torch=torch, transformers=transformers)
    model.config.use_cache = False
    dataset = load_dataset("json", data_files={split: str(root / f"{split}.jsonl") for split in ("train", "validation")})

    class _CheckpointInputCallback(TrainerCallback):
        def on_save(self, args: Any, state: Any, control: Any, **kwargs: Any) -> None:
            if state.is_world_process_zero:
                _record_checkpoint_input(Path(args.output_dir), state.global_step, input_record)

    trainer = SFTTrainer(
        model=model, processing_class=tokenizer,
        args=SFTConfig(output_dir=str(output), **config["sft"]),
        peft_config=LoraConfig(**config["peft"]),
        train_dataset=dataset["train"], eval_dataset=dataset["validation"],
        callbacks=[_CheckpointInputCallback()],
    )
    if trainer.is_world_process_zero():
        output.mkdir(parents=True, exist_ok=True)
        _write_json(output / "auditex-training-input.json", input_record)
    result = trainer.train(resume_from_checkpoint=args.resume_from_checkpoint)
    trainer.save_model(str(output / "adapter"))
    trainer.save_state()
    if trainer.is_world_process_zero():
        tokenizer.save_pretrained(output / "adapter")
        trainable, total = trainer.model.get_nb_trainable_parameters()
        adapter_keys = [name for name, _ in trainer.model.named_parameters() if "lora_A" in name]
        _write_json(output / "auditex-training-run.json", {
            "base_model": manifest["base_model"], "base_revision": manifest["base_revision"],
            "pack_manifest_sha256": _digest(root / "manifest.json"), "metrics": result.metrics,
            "runtime_package_versions": {name: version(name) for name in RUNTIME_PACKAGE_CANDIDATES},
            "token_budget": token_budget,
            "slurm_job_id": os.environ.get("SLURM_JOB_ID"), "world_size": int(os.environ.get("WORLD_SIZE", "1")),
            "trainable_parameters": trainable, "total_parameters": total,
            "adapter_key_prefix_sample": adapter_keys[:1],
            "adapter_note": "LoRA keys follow the text-only Qwen3_5ForCausalLM module names (model.layers.*); "
                            "loading into Qwen3_5ForConditionalGeneration or a serving runtime needs the "
                            "model.language_model.* prefix mapped back and must be verified before deployment.",
            "log_history": trainer.state.log_history,
            "evaluation_status": "independent_held_out_evaluation_required", "test_cases_used_for_training": False,
        })
    return 0
