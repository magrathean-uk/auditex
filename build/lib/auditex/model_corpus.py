"""Stage public conversation data for review without running any model or tools.

This produces unreviewed candidates, never approved training examples. Evaluation
sources remain separate; opaque YAML fixtures cannot establish semantic isolation.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

SCHEMA_VERSION = "2026-10-18"
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_FILES = 4096
_REVISION = re.compile(r"^[0-9a-fA-F]{40}$")
_STRIPPED_FIELDS = {"thinking", "reasoning", "analysis", "reasoning_content", "reasoning_details"}
_OUTPUT_NAMES = ("staged-corpus.jsonl", "conflicts.jsonl", "rejected.jsonl",
                 "evaluation-sources.json", "manifest.json")


def _pairs(pairs: list[tuple[str, Any]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _loads(value: str | bytes) -> Any:
    return json.loads(value, object_pairs_hook=_pairs, parse_constant=_invalid_constant)


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a nonempty string")
    return value


def _file_info(path: Path) -> dict:
    if not path.is_file():
        raise ValueError(f"input is not a regular file: {path}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            size += len(chunk)
            if size > MAX_FILE_BYTES:
                raise ValueError(f"input exceeds {MAX_FILE_BYTES} bytes: {path}")
            digest.update(chunk)
    return {"path": str(path), "bytes": size, "sha256": digest.hexdigest()}


def _manifest(path: Path) -> tuple[dict, list[dict], list[dict]]:
    info = _file_info(path)
    if info["bytes"] > MAX_LINE_BYTES:
        raise ValueError("source manifest exceeds size limit")
    with path.open("rb") as handle:
        raw = handle.read(MAX_LINE_BYTES + 1)
    if len(raw) > MAX_LINE_BYTES:
        raise ValueError("source manifest exceeds size limit")
    if len(raw) != info["bytes"] or hashlib.sha256(raw).hexdigest() != info["sha256"]:
        raise ValueError("source manifest changed during validation")
    payload = _loads(raw)
    if not isinstance(payload, dict) or set(payload) != {"sources"}:
        raise ValueError("source manifest must contain only sources")
    sources = payload["sources"]
    if not isinstance(sources, list) or not sources:
        raise ValueError("sources must be a nonempty array")
    files: dict[tuple[str, str, str], dict] = {}
    source_ids: set[str] = set()
    for source in sources:
        if not isinstance(source, dict) or set(source) != {"id", "revision", "training_files", "evaluation_files"}:
            raise ValueError("each source requires id, revision, training_files and evaluation_files")
        source_id = _text(source["id"], "source id")
        if source_id in source_ids:
            raise ValueError("source IDs must be unique")
        source_ids.add(source_id)
        revision = source["revision"]
        if not isinstance(revision, str) or not _REVISION.fullmatch(revision):
            raise ValueError("source revision must be a 40-character hexadecimal commit")
        if not source["training_files"] and not source["evaluation_files"]:
            raise ValueError("each source must identify at least one input file")
        for role in ("training", "evaluation"):
            names = source[f"{role}_files"]
            if not isinstance(names, list):
                raise ValueError(f"{role}_files must be an array")
            for name in names:
                candidate = Path(_text(name, "input path"))
                candidate = (path.parent / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
                extension = candidate.suffix.lower()
                if role == "training" and extension != ".jsonl":
                    raise ValueError("training files must be JSONL")
                if role == "evaluation" and extension not in {".jsonl", ".yaml", ".yml"}:
                    raise ValueError("evaluation files must be JSONL or YAML")
                key = (role, source_id, str(candidate))
                if key in files:
                    raise ValueError("duplicate input path within one source and role")
                if len(files) >= MAX_FILES:
                    raise ValueError("too many input files")
                files[key] = {**_file_info(candidate), "upstream_source_id": source_id,
                              "revision": revision.lower(), "role": role}
    training = [f for f in files.values() if f["role"] == "training"]
    evaluation = [f for f in files.values() if f["role"] == "evaluation"]
    if sum(f["bytes"] for f in files.values()) > MAX_TOTAL_BYTES:
        raise ValueError("total input size exceeds staging limit")
    eval_paths = {f["path"] for f in evaluation}
    eval_hashes = {f["sha256"] for f in evaluation}
    if any(f["path"] in eval_paths or f["sha256"] in eval_hashes for f in training):
        raise ValueError("the same input path or file hash appears in training and evaluation")
    return info, training, evaluation


def _rows(info: dict) -> Iterator[tuple[int, Any, str | None]]:
    """Stream bounded lines, then detect changes since the manifest preflight."""
    digest = hashlib.sha256()
    size = 0
    with Path(info["path"]).open("rb") as handle:
        line_number = 0
        while True:
            line = handle.readline(MAX_LINE_BYTES + 1)
            if not line:
                break
            line_number += 1
            digest.update(line)
            size += len(line)
            if size > MAX_FILE_BYTES:
                raise ValueError("input grew beyond the file size limit")
            if len(line) > MAX_LINE_BYTES:
                while not line.endswith(b"\n"):
                    line = handle.readline(65536)
                    if not line:
                        break
                    size += len(line)
                    digest.update(line)
                    if size > MAX_FILE_BYTES:
                        raise ValueError("input grew beyond the file size limit")
                yield line_number, None, "line exceeds size limit"
                continue
            if not line.strip():
                continue
            try:
                yield line_number, _loads(line.decode("utf-8")), None
            except (ValueError, UnicodeError, RecursionError) as exc:
                yield line_number, None, f"invalid JSONL: {exc}"
    if size != info["bytes"] or digest.hexdigest() != info["sha256"]:
        raise ValueError(f"input changed during staging: {info['path']}")


def _tools(value: Any) -> list[dict]:
    if not isinstance(value, list):
        raise ValueError("tools must be an array")
    names: set[str] = set()
    for tool in value:
        if not isinstance(tool, dict) or set(tool) != {"type", "function"} or tool["type"] != "function":
            raise ValueError("only function tool definitions are supported")
        function = tool["function"]
        if not isinstance(function, dict) or not {"name"} <= function.keys() or set(function) - {"name", "description", "parameters", "strict"}:
            raise ValueError("unsupported function tool definition")
        name = _text(function["name"], "function name")
        if name in names:
            raise ValueError("duplicate function tool name")
        names.add(name)
        if "description" in function and not isinstance(function["description"], str):
            raise ValueError("function description must be a string")
        if "parameters" in function and not isinstance(function["parameters"], dict):
            raise ValueError("function parameters must be an object")
        if "strict" in function and not isinstance(function["strict"], bool):
            raise ValueError("function strict must be boolean")
    return value


def _conversation(row: Any) -> tuple[dict, Counter]:
    if not isinstance(row, dict) or set(row) - {"messages", "tools"} - _STRIPPED_FIELDS:
        raise ValueError("unsupported conversation fields")
    messages = row.get("messages")
    if not isinstance(messages, list) or len(messages) < 2:
        raise ValueError("messages must contain a prompt and assistant target")
    stripped = Counter({key: 1 for key in _STRIPPED_FIELDS if key in row})
    result: dict = {"messages": []}
    definitions: set[str] | None = None
    if "tools" in row:
        result["tools"] = _tools(row["tools"])
        definitions = {t["function"]["name"] for t in result["tools"]}
    pending: list[dict] = []
    seen_call_ids: set[str] = set()
    for index, message in enumerate(messages):
        if not isinstance(message, dict) or set(message) - {"role", "content", "name", "tool_calls", "tool_call_id"} - _STRIPPED_FIELDS:
            raise ValueError("unsupported message fields")
        role = message.get("role")
        if role not in {"system", "user", "assistant", "tool"}:
            raise ValueError("unsupported message role")
        if pending and role != "tool":
            raise ValueError("assistant tool calls lack matching tool results")
        for key in _STRIPPED_FIELDS:
            if key in message:
                stripped[key] += 1
        content = message.get("content")
        if content is not None and not isinstance(content, str):
            raise ValueError("message content must be a string or null")
        normalized = {"role": role, "content": content}
        for key in ("name", "tool_call_id"):
            if key in message:
                normalized[key] = _text(message[key], key)
        if "tool_call_id" in message and role != "tool":
            raise ValueError("tool_call_id is only supported on tool messages")
        if "tool_calls" in message:
            calls = message["tool_calls"]
            if role != "assistant" or not isinstance(calls, list) or not calls:
                raise ValueError("tool_calls requires a nonempty assistant call array")
            normalized["tool_calls"] = []
            for call in calls:
                if not isinstance(call, dict) or set(call) - {"id", "type", "function"} or call.get("type") != "function":
                    raise ValueError("unsupported tool call")
                function = call.get("function")
                if not isinstance(function, dict) or set(function) != {"name", "arguments"}:
                    raise ValueError("tool call requires function name and arguments")
                name = _text(function["name"], "tool call function name")
                if definitions is not None and name not in definitions:
                    raise ValueError("tool call has no corresponding function definition")
                arguments = function["arguments"]
                if not isinstance(arguments, str):
                    raise ValueError("tool call arguments must be a JSON object string")
                parsed_arguments = _loads(arguments)
                if not isinstance(parsed_arguments, dict):
                    raise ValueError("tool call arguments must encode an object")
                normalized_call = {"type": "function", "function": {"name": name, "arguments": _canonical(parsed_arguments)}}
                if "id" in call:
                    call_id = _text(call["id"], "tool call ID")
                    if call_id in seen_call_ids:
                        raise ValueError("duplicate tool call ID")
                    seen_call_ids.add(call_id)
                    normalized_call["id"] = call_id
                normalized["tool_calls"].append(normalized_call)
                if index != len(messages) - 1:
                    pending.append(normalized_call)
        if role == "tool":
            match = next((call for call in pending if
                          ("tool_call_id" in normalized and call.get("id") == normalized["tool_call_id"]) or
                          ("tool_call_id" not in normalized and "id" not in call and
                           call["function"]["name"] == normalized.get("name"))), None)
            if match is None:
                raise ValueError("tool result has no matching preceding assistant call")
            if "name" in normalized and normalized["name"] != match["function"]["name"]:
                raise ValueError("tool result name conflicts with preceding call")
            pending.remove(match)
        result["messages"].append(normalized)
    target = result["messages"][-1]
    if target["role"] != "assistant" or not any(m["role"] == "user" for m in result["messages"][:-1]):
        raise ValueError("conversation requires a user prompt and final assistant target")
    if not target.get("tool_calls") and not (isinstance(target["content"], str) and target["content"].strip()):
        raise ValueError("final assistant target is empty")
    return result, stripped


def _prompt_hash(conversation: dict) -> str:
    return _hash({**conversation, "messages": conversation["messages"][:-1]})


def _ref(info: dict, line: int) -> dict:
    return {key: info[key] for key in ("upstream_source_id", "revision", "path", "sha256")} | {"line": line}


def stage_public_corpus(source_manifest_path: str | Path, output_dir: str | Path) -> dict:
    """Validate and stage public JSONL candidates, retaining source hashes/lines.

    No input content is executed. Invalid manifests or unreadable/changed inputs
    fail before output creation. Existing output files are never overwritten.
    """
    source_path = Path(source_manifest_path).resolve()
    output = Path(output_dir).resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise FileExistsError("output directory must be absent or empty")
    manifest_info, training, evaluation = _manifest(source_path)
    evaluation_prompts: set[str] = set()
    eval_inventory: list[dict] = []
    counts: Counter = Counter()
    stripped_fields: Counter = Counter()
    for info in evaluation:
        entry = dict(info)
        if Path(info["path"]).suffix.lower() == ".jsonl":
            prompts: set[str] = set()
            for line, row, error in _rows(info):
                try:
                    if error:
                        raise ValueError(error)
                    conversation, _ = _conversation(row)
                except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
                    raise ValueError(f"unsupported evaluation row {info['path']}:{line}: {exc}") from exc
                prompts.add(_prompt_hash(conversation))
                counts["evaluation_jsonl_rows"] += 1
            evaluation_prompts.update(prompts)
            entry.update({"overlap_check": "exact_normalized_prompt", "prompt_sha256": sorted(prompts)})
        else:
            entry["overlap_check"] = "not_established_opaque_yaml"
            counts["opaque_evaluation_files"] += 1
        eval_inventory.append(entry)
    candidates: dict[str, dict] = {}
    rejected: list[dict] = []
    for info in training:
        for line, row, error in _rows(info):
            counts["training_rows"] += 1
            ref = _ref(info, line)
            try:
                if error:
                    raise ValueError(error)
                conversation, removed = _conversation(row)
                stripped_fields.update(removed)
                counts["rows_with_stripped_fields"] += bool(removed)
                digest = _hash(conversation)
                prompt = _prompt_hash(conversation)
            except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
                rejected.append({"reason": str(exc), "provenance": [ref], "review_status": "unreviewed"})
                counts["unsupported_rows"] += 1
                continue
            if prompt in evaluation_prompts:
                rejected.append({"reason": "evaluation_prompt_overlap", "conversation_sha256": digest,
                                 "prompt_sha256": prompt, "provenance": [ref], "review_status": "unreviewed"})
                counts["evaluation_overlap_rows"] += 1
                continue
            if digest in candidates:
                candidates[digest]["provenance"].append(ref)
                counts["duplicate_rows"] += 1
            else:
                candidates[digest] = {**conversation, "conversation_sha256": digest, "prompt_sha256": prompt,
                                      "provenance": [ref], "review_status": "unreviewed"}
    by_prompt: dict[str, list[dict]] = {}
    for candidate in candidates.values():
        by_prompt.setdefault(candidate["prompt_sha256"], []).append(candidate)
    staged: list[dict] = []
    conflicts: list[dict] = []
    for prompt, variants in by_prompt.items():
        if len(variants) > 1:
            conflicts.append({"reason": "same_prompt_different_completion", "prompt_sha256": prompt,
                              "review_status": "unreviewed", "variants": variants})
            counts["conflicting_conversations"] += len(variants)
            counts["conflicting_rows"] += sum(len(v["provenance"]) for v in variants)
        else:
            staged.extend(variants)
    counts.update({"staged_conversations": len(staged), "conflicting_prompts": len(conflicts),
                   "rejected_rows": len(rejected), "training_files": len(training),
                   "evaluation_files": len(evaluation)})
    for key in ("duplicate_rows", "unsupported_rows", "evaluation_overlap_rows", "rows_with_stripped_fields",
                "conflicting_conversations", "conflicting_rows", "evaluation_jsonl_rows", "opaque_evaluation_files"):
        counts.setdefault(key, 0)
    def jsonl(rows: list) -> bytes:
        return "".join(_canonical(row) + "\n" for row in rows).encode("utf-8")

    outputs = {"staged-corpus.jsonl": jsonl(staged), "conflicts.jsonl": jsonl(conflicts),
               "rejected.jsonl": jsonl(rejected),
               "evaluation-sources.json": (json.dumps(eval_inventory, indent=2, ensure_ascii=False) + "\n").encode("utf-8")}
    manifest = {"schema_version": SCHEMA_VERSION, "review_status": "unreviewed", "approved_training_records": 0,
                "source_manifest": manifest_info, "training_sources": training,
                "counts": dict(counts), "stripped_fields": dict(stripped_fields),
                "limitations": ["Exact normalized prompt checks do not establish semantic separation.",
                                "YAML evaluation fixtures are opaque and cannot establish prompt non-overlap.",
                                "Upstream provenance and synthetic-data claims have not been independently reviewed."],
                "artifacts": {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                              for name, data in outputs.items()}}
    outputs["manifest.json"] = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    # Every validation above completes before any output path is created.
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise FileExistsError("output directory must be empty")
    created: list[Path] = []
    try:
        for name in _OUTPUT_NAMES:
            destination = output / name
            with destination.open("xb") as handle:
                created.append(destination)
                handle.write(outputs[name])
    except BaseException:
        for destination in created:
            destination.unlink(missing_ok=True)
        raise
    return manifest
