#!/usr/bin/env python3
"""Choose a LoRA checkpoint by greedy generated answers on held-out cases (gate G3).

Eval loss measures next-token fit to the teacher-forced answer; it does not say whether the checkpoint's own
generated JSON passes the reviewed rubric. This script loads the text-only base once, attaches each
checkpoint's adapter in turn, renders every case prompt exactly as training did (thinking off), generates
greedily, parses the raw text as strict JSON (no fence stripping, no repair), and scores the answers with the
recorded-answer evaluator. The selected checkpoint is the one with the highest strict pass rate, never the
lowest eval loss. Offline only: no installation, download, network or tenant call. Torch, transformers and
peft are imported lazily, so --help and the pure scoring and selection code run without them.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import gc
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from auditex.model_eval import evaluate_responses  # noqa: E402
from auditex.model_training import (  # noqa: E402
    _MODEL_ID, _REVISION, _load_text_model, _outside_audit_runs, _parse_json, _trl_record, load_cases,
)

SCHEMA_VERSION = "2026-10-20"
HELD_OUT_SPLITS = ("validation", "test")
DEVICES = ("cuda", "mps", "cpu")
DTYPES = ("bfloat16", "float16", "float32")
ADAPTER_WEIGHT_FILES = ("adapter_model.safetensors", "adapter_model.bin")
_STEP = re.compile(r"checkpoint-(\d+)")
SELECTION_RULE = {
    "metric": "strict_pass_rate",
    "never_by": "eval_loss",
    "description": (
        "Highest strict pass rate (every claim status, typed value, evidence set and limitation/recommendation ID "
        "matches the reviewed rubric on greedy, thinking-off, strictly parsed JSON). Ties: lowest overconfidence "
        "(claims expected unknown answered confirmed), then lowest over-abstention (claims expected confirmed or "
        "inferred answered unknown), then the earliest training step, then name. A tie on the first three keys is "
        "reported in tied_with rather than hidden."
    ),
    "order": ["strict_pass_count desc", "overconfidence asc", "over_abstention asc", "step asc", "name asc"],
}
CAVEATS = [
    "Structured checks only: claim IDs, statuses, typed values, evidence IDs and gap/recommendation IDs are compared mechanically; prose entailment is not verified.",
    "Greedy decoding with thinking off, one sample per case: differences between checkpoints smaller than the sampling noise of this case count are not meaningful.",
    "Selecting on a split uses it up for model selection; report the chosen checkpoint once on an untouched test split.",
    "Batched generation can change bf16 numerics slightly; batch size and padding are held constant across checkpoints and recorded.",
]


def _log(message: str) -> None:
    print(f"[score-adapter-checkpoints {datetime.now().strftime('%H:%M:%S')}] {message}", file=sys.stderr, flush=True)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _file_sha(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _write_private(path: Path, text: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)


def _write_json(path: Path, payload: Any) -> None:
    _write_private(path, json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False) + "\n")


def _append_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    """Append and fsync so a crash at a later checkpoint keeps every finished checkpoint's answers."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        handle.write("".join(json.dumps(row, ensure_ascii=False, allow_nan=False) + "\n" for row in rows))
        handle.flush()
        os.fsync(handle.fileno())


# --- prompt rendering and strict parsing ------------------------------------------------------------------------

def render_prompt(tokenizer: Any, case: dict[str, Any]) -> str:
    """The training-time prompt prefix: the prompt messages and chat_template_kwargs come from the very record
    the trainer reads (`_trl_record`), with the generation prompt TRL appends for prompt/completion data. The
    final assistant target never enters it."""
    record = _trl_record(case)
    return tokenizer.apply_chat_template(
        record["prompt"], tokenize=False, add_generation_prompt=True, **record["chat_template_kwargs"],
    )


def parse_strict(text: str) -> tuple[Any, str | None]:
    """The whole generation must be exactly one JSON value: fences, prose before or after, trailing text,
    duplicate keys and non-finite constants are all rejected, and nothing is repaired."""
    try:
        return _parse_json(text), None
    except (ValueError, RecursionError) as exc:
        return None, str(exc)


def response_row(case_id: str, model_id: str, generation: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """The evaluator row and the full generation trace. A generation that is not strict JSON is recorded as its
    raw text, which the evaluator reports as a response_schema_error, so it can never pass."""
    parsed, error = parse_strict(generation["text"])
    row = {"case_id": case_id, "model_id": model_id, "response": generation["text"] if error else parsed}
    trace = {"case_id": case_id, "model_id": model_id, "raw_text": generation["text"], "strict_json": error is None,
             "parse_error": error, "prompt_tokens": generation.get("prompt_tokens"),
             "new_tokens": generation.get("new_tokens"), "finish_reason": generation.get("finish_reason")}
    return row, trace


def pad_left(sequences: list[list[int]], pad_id: int) -> tuple[list[list[int]], list[list[int]]]:
    """Left-pad token sequences to one width with an attention mask, so generation continues from each prompt's end."""
    width = max(len(sequence) for sequence in sequences)
    ids = [[pad_id] * (width - len(sequence)) + list(sequence) for sequence in sequences]
    mask = [[0] * (width - len(sequence)) + [1] * len(sequence) for sequence in sequences]
    return ids, mask


def cut_at_stop(tokens: list[int], stop_ids: set[int]) -> tuple[list[int], str]:
    """Keep the tokens before the first stop token ('eos'); with none, the generation ran to the limit ('length')."""
    for position, token in enumerate(tokens):
        if token in stop_ids:
            return tokens[:position], "eos"
    return tokens, "length"


# --- checkpoint discovery ----------------------------------------------------------------------------------------

def _checkpoint_step(name: str) -> int | None:
    match = _STEP.fullmatch(name)
    return int(match.group(1)) if match else None


def inspect_checkpoint(path: Path, base_model: str, revision: str) -> dict[str, Any]:
    """Validate one adapter directory and bind it to the base when the trainer recorded its identity."""
    path = path.expanduser().resolve()
    config = path / "adapter_config.json"
    weights = next((path / name for name in ADAPTER_WEIGHT_FILES if (path / name).is_file()), None)
    if not path.is_dir() or not config.is_file() or weights is None:
        raise ValueError(f"{path} is not an adapter checkpoint (needs adapter_config.json and adapter_model.safetensors)")
    identity_path = path / "auditex-training-input.json"
    identity = None
    if identity_path.is_file():
        identity = _parse_json(identity_path.read_text(encoding="utf-8"))
        if not isinstance(identity, dict) or identity.get("base_model") != base_model \
                or str(identity.get("base_revision", "")).lower() != revision:
            raise ValueError(f"{path.name} was trained from another base model or revision than {base_model}@{revision}")
    else:
        _log(f"warning: {path.name} has no auditex-training-input.json; its base model cannot be confirmed")
    adapter_config = _parse_json(config.read_text(encoding="utf-8"))
    adapter_base = adapter_config.get("base_model_name_or_path") if isinstance(adapter_config, dict) else None
    if isinstance(adapter_base, str) and adapter_base and revision not in adapter_base \
            and base_model.replace("/", "--") not in adapter_base and base_model not in adapter_base:
        _log(f"warning: {path.name} adapter_config names base '{adapter_base}', not {base_model}@{revision}")
    return {
        "name": path.name, "path": str(path), "step": _checkpoint_step(path.name),
        "adapter_base_model_name_or_path": adapter_base,
        "training_input": identity,
        "adapter_config_sha256": _file_sha(config), "adapter_weights_file": weights.name,
        "adapter_weights_sha256": _file_sha(weights),
    }


def discover_checkpoints(root: str | None, explicit: list[str], base_model: str, revision: str) -> list[dict[str, Any]]:
    paths: list[Path] = []
    if root:
        directory = Path(root).expanduser().resolve()
        if not directory.is_dir():
            raise ValueError(f"checkpoints root {directory} is not a directory")
        found = sorted((child for child in directory.iterdir() if child.is_dir() and _checkpoint_step(child.name) is not None),
                       key=lambda child: _checkpoint_step(child.name))
        if not found:
            raise ValueError(f"no checkpoint-<step> directories under {directory}")
        paths.extend(found)
    paths.extend(Path(item) for item in explicit)
    if not paths:
        raise ValueError("provide --checkpoints-root and/or at least one --checkpoint")
    checkpoints, seen_paths, seen_names = [], set(), set()
    for path in paths:
        meta = inspect_checkpoint(path, base_model, revision)
        if meta["path"] in seen_paths:
            continue
        if meta["name"] in seen_names:
            raise ValueError(f"two checkpoints are named {meta['name']}; scores are keyed by name, so rename or symlink one")
        seen_paths.add(meta["path"])
        seen_names.add(meta["name"])
        meta["model_id"] = f"{base_model}@{revision}+{meta['name']}"
        checkpoints.append(meta)
    return checkpoints


# --- cases -------------------------------------------------------------------------------------------------------

def select_cases(case_paths: list[str], splits: list[str] | None, limit: int | None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Held-out, approved cases only. Train cases are what the checkpoints saw; unreviewed cases would only be
    quarantined by the evaluator, so neither is generated for."""
    wanted = set(splits) if splits else set(HELD_OUT_SPLITS)
    loaded = load_cases([Path(item) for item in case_paths])
    in_split = [case for case in loaded if case["split"] in wanted]
    approved = [case for case in in_split if case["provenance"]["review_status"] == "approved"]
    if not approved:
        raise ValueError(f"no approved cases in splits {sorted(wanted)} (loaded {len(loaded)}, "
                         f"{len(in_split)} in those splits); pass --splits to choose other splits")
    chosen = approved[:limit] if limit else approved
    summary = {
        "sources": [{"path": str(Path(item).resolve()), "sha256": _file_sha(Path(item))} for item in case_paths],
        "loaded": len(loaded), "in_splits": len(in_split), "skipped_unreviewed": len(in_split) - len(approved),
        "scored": len(chosen), "limit": limit, "splits_requested": sorted(wanted),
        "splits_scored": dict(sorted(Counter(case["split"] for case in chosen).items())),
    }
    return chosen, summary


# --- scoring and selection ---------------------------------------------------------------------------------------

def checkpoint_metrics(evaluation: dict[str, Any], cases: list[dict[str, Any]], model_id: str) -> dict[str, Any]:
    """Derive the selection metrics for one model from the evaluator output; labels come from the cases."""
    score = next(item for item in evaluation["model_scores"] if item["model_id"] == model_id)
    rows = [row for row in evaluation["results"] if row["model_id"] == model_id]
    over_abstention = overconfidence = 0
    issue_counts: Counter[str] = Counter()
    for row in rows:
        for issue in row["issues"]:
            issue_counts[issue["code"]] += 1
            if issue["code"] != "status_mismatch":
                continue
            if issue["expected"] in ("confirmed", "inferred") and issue["observed"] == "unknown":
                over_abstention += 1
            elif issue["expected"] == "unknown" and issue["observed"] == "confirmed":
                overconfidence += 1
    answered = sum(claim["status"] != "unknown" for case in cases for claim in case["expected"]["claims"])
    unknown = sum(claim["status"] == "unknown" for case in cases for claim in case["expected"]["claims"])
    scored = score["approved_case_count"]
    passes = score["mechanical_pass_count"]
    return {
        "strict_pass_count": passes, "scored_cases": scored,
        "strict_pass_rate": passes / scored if scored else None,
        "schema_error_count": sum(row["scored"] and row["schema_valid"] is False for row in rows),
        "over_abstention": over_abstention, "overconfidence": overconfidence,
        "expected_answered_claims": answered, "expected_unknown_claims": unknown,
        "over_abstention_rate": over_abstention / answered if answered else None,
        "overconfidence_rate": overconfidence / unknown if unknown else None,
        "missing_responses": score["missing_case_count"],
        "issue_counts": dict(sorted(issue_counts.items())),
    }


def _rank_key(entry: dict[str, Any]) -> tuple[Any, ...]:
    step = entry["step"]
    return (-entry["strict_pass_count"], entry["overconfidence"], entry["over_abstention"],
            step if step is not None else float("inf"), entry["name"])


def select_checkpoint(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Apply SELECTION_RULE. `entries` carry name, step and the checkpoint_metrics fields; eval loss is not an input."""
    if not entries:
        raise ValueError("no checkpoints to select from")
    ranked = sorted(entries, key=_rank_key)
    best = ranked[0]
    first_three = lambda item: (item["strict_pass_count"], item["overconfidence"], item["over_abstention"])  # noqa: E731
    tied = [item["name"] for item in ranked[1:] if first_three(item) == first_three(best)]
    return {"selected": best["name"], "ranking": [item["name"] for item in ranked],
            "tied_with": tied}


def evaluate_and_select(output_dir: Path, scored_cases: list[dict[str, Any]], run: dict[str, Any]) -> dict[str, Any]:
    """Run the recorded-answer evaluator over responses.jsonl, write evaluation.json and selection.json."""
    evaluation = evaluate_responses(output_dir / "scored-cases.jsonl", output_dir / "responses.jsonl")
    _write_json(output_dir / "evaluation.json", evaluation)
    entries = []
    for meta in run["checkpoints"]:
        entries.append({**meta, **checkpoint_metrics(evaluation, scored_cases, meta["model_id"])})
    choice = select_checkpoint(entries)
    by_name = {entry["name"]: entry for entry in entries}
    warnings = []
    if run["generation"]["limit"]:
        warnings.append("smoke run: --limit restricted the cases, so this is not a selection result")
    if entries and by_name[choice["selected"]]["strict_pass_count"] == 0:
        warnings.append("the selected checkpoint passes no case; check the parse and schema errors before trusting any ranking")
    if choice["tied_with"]:
        warnings.append(f"{choice['selected']} is tied with {', '.join(choice['tied_with'])} on pass count, overconfidence and "
                        "over-abstention; the earliest step broke the tie")
    selection = {
        "schema_version": SCHEMA_VERSION, "kind": "checkpoint_selection_by_generation", "gate": "G3",
        "created": _now(),
        "base_model": run["base_model"], "base_revision": run["base_revision"],
        "selection_rule": SELECTION_RULE,
        "selected": choice["selected"],
        "selected_model_id": by_name[choice["selected"]]["model_id"],
        "selected_path": by_name[choice["selected"]]["path"],
        "ranking": choice["ranking"], "tied_with": choice["tied_with"], "warnings": warnings,
        "smoke": bool(run["generation"]["limit"]),
        "checkpoints": [by_name[name] for name in choice["ranking"]],
        "cases": run["cases"], "generation": run["generation"], "runtime": run["runtime"],
        "files": {"responses": "responses.jsonl", "generations": "generations.jsonl", "evaluation": "evaluation.json",
                  "scored_cases": "scored-cases.jsonl"},
        "caveats": CAVEATS,
    }
    _write_json(output_dir / "selection.json", selection)
    return selection


def generate_all(output_dir: Path, scored_cases: list[dict[str, Any]], checkpoints: list[dict[str, Any]], backend: Any) -> None:
    """One adapter at a time: attach, generate for every case, record, and always detach and free memory."""
    prompts = [backend.render_prompt(case) for case in scored_cases]
    for index, meta in enumerate(checkpoints, start=1):
        _log(f"checkpoint {index}/{len(checkpoints)}: {meta['name']} ({len(prompts)} cases)")
        loaded_at = time.perf_counter()
        backend.load_adapter(Path(meta["path"]))
        meta["adapter_load_seconds"] = round(time.perf_counter() - loaded_at, 3)
        try:
            started = time.perf_counter()
            generations = backend.generate(prompts, lambda done, total, name=meta["name"], t0=started: _log(
                f"{name}: {done}/{total} cases, {time.perf_counter() - t0:.1f}s"))
            elapsed = time.perf_counter() - started
        finally:
            backend.unload_adapter()
        if len(generations) != len(scored_cases):
            raise ValueError("generator returned a different number of answers than prompts")
        rows, traces = zip(*(response_row(case["id"], meta["model_id"], generation)
                             for case, generation in zip(scored_cases, generations)))
        _append_jsonl(output_dir / "responses.jsonl", list(rows))
        _append_jsonl(output_dir / "generations.jsonl", list(traces))
        meta.update({
            "generation_seconds": round(elapsed, 3), "seconds_per_case": round(elapsed / len(scored_cases), 4),
            "strict_json_failures": sum(not trace["strict_json"] for trace in traces),
            "truncated_generations": sum(trace["finish_reason"] == "length" for trace in traces),
        })
        _log(f"{meta['name']}: done in {elapsed:.1f}s ({meta['seconds_per_case']}s per case), "
             f"{meta['strict_json_failures']} not strict JSON, {meta['truncated_generations']} hit the token limit")


def run(args: argparse.Namespace, backend_factory: Callable[[argparse.Namespace], Any] | None = None) -> dict[str, Any]:
    if not _MODEL_ID.fullmatch(args.base_model):
        raise ValueError("--base-model must identify one owner/model repository, not a local path")
    if not _REVISION.fullmatch(args.revision):
        raise ValueError("--revision must be an immutable 40-character model commit SHA")
    args.revision = args.revision.lower()
    for name in ("max_new_tokens", "batch_size", "limit"):
        value = getattr(args, name)
        if value is not None and value < 1:
            raise ValueError(f"--{name.replace('_', '-')} must be a positive integer")
    output_dir = Path(args.output_dir).expanduser().resolve()
    _outside_audit_runs(output_dir)
    if output_dir.exists() or output_dir.is_symlink():
        raise ValueError(f"output directory {output_dir} already exists; use a new one")
    # Everything cheap is validated before the model loads, so a typo costs seconds, not a 27B load.
    scored_cases, case_summary = select_cases(args.cases, args.splits, args.limit)
    checkpoints = discover_checkpoints(args.checkpoints_root, args.checkpoint or [], args.base_model, args.revision)
    _log(f"{len(scored_cases)} cases {case_summary['splits_scored']}; checkpoints: " + ", ".join(c["name"] for c in checkpoints))
    output_dir.mkdir(parents=True, mode=0o700)
    _write_private(output_dir / "scored-cases.jsonl",
                   "".join(json.dumps(case, ensure_ascii=False, allow_nan=False) + "\n" for case in scored_cases))
    backend = (backend_factory or TransformersBackend)(args)
    generate_all(output_dir, scored_cases, checkpoints, backend)
    run_record = {
        "base_model": args.base_model, "base_revision": args.revision, "checkpoints": checkpoints, "cases": case_summary,
        "generation": {"do_sample": False, "enable_thinking": False, "max_new_tokens": args.max_new_tokens,
                       "batch_size": args.batch_size, "limit": args.limit, "device": args.device, "dtype": args.dtype,
                       "answer_parsing": "strict JSON, no repair; a failure is kept as raw text and fails the evaluator"},
        "runtime": backend.describe(),
    }
    selection = evaluate_and_select(output_dir, scored_cases, run_record)
    _log(f"selected {selection['selected']} (ranking: {', '.join(selection['ranking'])}); wrote {output_dir / 'selection.json'}")
    return selection


# --- the real generator ------------------------------------------------------------------------------------------

class TransformersBackend:
    """Text-only base loaded once with model_training's loader; one PEFT adapter attached at a time."""

    def __init__(self, args: argparse.Namespace) -> None:
        os.environ.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", HF_DATASETS_OFFLINE="1", HF_HUB_DISABLE_TELEMETRY="1")
        if not os.environ.get("HF_HOME") or not Path(os.environ["HF_HOME"]).is_absolute():
            raise ValueError("set HF_HOME to the absolute project cache holding the staged base snapshot")
        # Optional dependencies, imported only on this path; nothing is installed or downloaded.
        import torch
        import transformers
        from huggingface_hub import snapshot_download
        from importlib.metadata import version
        import peft

        self._torch, self._peft_module = torch, peft
        if args.device == "cuda" and not torch.cuda.is_available():
            raise ValueError("--device cuda requested but CUDA is not available")
        if args.device == "mps" and not torch.backends.mps.is_available():
            raise ValueError("--device mps requested but MPS is not available")
        self._device, self._max_new_tokens, self._batch_size = args.device, args.max_new_tokens, args.batch_size
        snapshot = snapshot_download(repo_id=args.base_model, revision=args.revision, local_files_only=True)
        if Path(snapshot).name != args.revision:
            raise ValueError("staged model snapshot does not resolve to the pinned revision")
        self._tokenizer = transformers.AutoTokenizer.from_pretrained(snapshot, local_files_only=True, trust_remote_code=False)
        started = time.perf_counter()
        model = _load_text_model(snapshot, torch=torch, transformers=transformers)
        self._base = model.to(device=args.device, dtype=getattr(torch, args.dtype)).eval()
        self._base.config.use_cache = True
        self._load_seconds = round(time.perf_counter() - started, 1)
        self._stop_ids = self._stop_token_ids(model)
        self._pad_id = self._tokenizer.pad_token_id if self._tokenizer.pad_token_id is not None else min(self._stop_ids)
        self._peft = None
        self._versions = {name: version(name) for name in ("torch", "transformers", "peft")}
        self._snapshot = snapshot
        self._device_name = torch.cuda.get_device_name(0) if args.device == "cuda" else args.device
        _log(f"loaded {args.base_model}@{args.revision} on {args.device} ({args.dtype}) in {self._load_seconds}s; stop ids {sorted(self._stop_ids)}")

    def _stop_token_ids(self, model: Any) -> set[int]:
        """Stop at the chat turn end as well as the configured eos: the staged snapshot may declare only
        <|endoftext|>, which would let a finished answer run on past <|im_end|> and break strict parsing."""
        stop: set[int] = set()
        for value in (self._tokenizer.eos_token_id, getattr(model.config, "eos_token_id", None),
                      getattr(getattr(model, "generation_config", None), "eos_token_id", None)):
            stop.update(value if isinstance(value, (list, tuple)) else [value] if isinstance(value, int) else [])
        turn_end = self._tokenizer.convert_tokens_to_ids("<|im_end|>")
        if isinstance(turn_end, int) and turn_end != self._tokenizer.unk_token_id:
            stop.add(turn_end)
        if not stop:
            raise ValueError("no eos token id found for the base model")
        return stop

    def describe(self) -> dict[str, Any]:
        return {"backend": "transformers+peft", "packages": self._versions, "device": self._device,
                "device_name": self._device_name, "snapshot": self._snapshot, "stop_token_ids": sorted(self._stop_ids),
                "base_load_seconds": self._load_seconds}

    def render_prompt(self, case: dict[str, Any]) -> str:
        return render_prompt(self._tokenizer, case)

    def load_adapter(self, path: Path) -> None:
        self._peft = self._peft_module.PeftModel.from_pretrained(self._base, str(path), is_trainable=False).eval()

    def unload_adapter(self) -> None:
        """Remove the LoRA layers (no merge) and prove the base is clean, so one checkpoint cannot leak into the next."""
        if self._peft is not None:
            self._base = self._peft.unload()
            self._peft = None
        if hasattr(self._base, "peft_config"):
            del self._base.peft_config
        if any("lora_" in name for name, _ in self._base.named_parameters()):
            raise ValueError("adapter layers remain on the base model after unload; refusing to score the next checkpoint")
        gc.collect()
        if self._device == "cuda":
            self._torch.cuda.empty_cache()
        elif self._device == "mps":
            self._torch.mps.empty_cache()

    def generate(self, prompts: list[str], progress: Callable[[int, int], None]) -> list[dict[str, Any]]:
        """Greedy generation in length-sorted left-padded batches; results come back in prompt order."""
        torch, tokenizer = self._torch, self._tokenizer
        # Rendered text is tokenised without added special tokens, as apply_chat_template does when TRL trains.
        encoded = [tokenizer(prompt, add_special_tokens=False)["input_ids"] for prompt in prompts]
        order = sorted(range(len(prompts)), key=lambda i: (len(encoded[i]), i))
        results: list[dict[str, Any] | None] = [None] * len(prompts)
        done = 0
        for start in range(0, len(order), self._batch_size):
            chunk = order[start:start + self._batch_size]
            ids, mask = pad_left([encoded[i] for i in chunk], self._pad_id)
            width = len(ids[0])
            with torch.inference_mode():
                output = self._peft.generate(
                    input_ids=torch.tensor(ids, dtype=torch.long, device=self._device),
                    attention_mask=torch.tensor(mask, dtype=torch.long, device=self._device),
                    max_new_tokens=self._max_new_tokens, do_sample=False, temperature=None, top_p=None, top_k=None,
                    eos_token_id=sorted(self._stop_ids), pad_token_id=self._pad_id,
                )
            for row, i in enumerate(chunk):
                kept, finish = cut_at_stop(output[row, width:].tolist(), self._stop_ids)
                results[i] = {"text": tokenizer.decode(kept, skip_special_tokens=True), "new_tokens": len(kept),
                              "prompt_tokens": len(encoded[i]), "finish_reason": finish}
            done += len(chunk)
            progress(done, len(prompts))
        return results  # type: ignore[return-value]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Select a LoRA checkpoint by strictly parsed generated answers on held-out cases (gate G3), never by eval loss.",
    )
    parser.add_argument("--base-model", required=True, help="owner/model repository the adapters were trained on.")
    parser.add_argument("--revision", required=True, help="Immutable 40-character base-model commit SHA staged under HF_HOME.")
    parser.add_argument("--checkpoints-root", help="Directory containing checkpoint-<step>/ adapter directories.")
    parser.add_argument("--checkpoint", action="append", help="One adapter directory; repeatable, combinable with --checkpoints-root.")
    parser.add_argument("--cases", action="append", required=True, help="Held-out cases JSONL; repeat to combine files.")
    parser.add_argument("--splits", action="append", choices=("train", "validation", "test"),
                        help="Split to score; repeatable. Default: validation and test (never train). "
                             "Select on validation and keep test for one final report.")
    parser.add_argument("--output-dir", required=True, help="New directory for responses, evaluation and selection.")
    parser.add_argument("--device", choices=DEVICES, default="cuda", help="Default: cuda.")
    parser.add_argument("--dtype", choices=DTYPES, default="bfloat16", help="Default: bfloat16 (the training dtype).")
    parser.add_argument("--max-new-tokens", type=int, default=512, help="Generation limit per case (default 512).")
    parser.add_argument("--batch-size", type=int, default=8,
                        help="Prompts per generate call (default 8); held constant across checkpoints. Use 1 for exactly batch-independent numerics.")
    parser.add_argument("--limit", type=int, help="Score only the first N cases; marks the result as a smoke, not a selection.")
    return parser


def main(argv: list[str] | None = None, backend_factory: Callable[[argparse.Namespace], Any] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        selection = run(args, backend_factory)
    except (OSError, ValueError, TypeError) as exc:
        print(f"Checkpoint scoring failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"output_dir": str(Path(args.output_dir).expanduser().resolve()), "selected": selection["selected"],
                      "ranking": selection["ranking"], "warnings": selection["warnings"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
