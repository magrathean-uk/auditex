"""Pinned reference inventory; listing it never fetches or executes sources."""
from __future__ import annotations

import json
import math
import re
from datetime import date
from typing import Any
from urllib.parse import urlsplit

from azure_tenant_audit.resources import resolve_resource_path

_SHA256 = re.compile(r"[0-9a-f]{64}")
_REVISION = re.compile(r"[0-9a-f]{40}")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_HOSTNAME = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
PRODUCT_ROLE = "product_model"
# What an operator needs to obtain, verify and serve the shipped model, and to read its scores honestly.
PRODUCT_KEYS = frozenset({
    "id", "role", "repository", "url", "revision", "format", "artifact", "bytes", "sha256", "quantisation", "parts",
    "base", "adapter", "conversion", "training", "serving", "evaluated_at", "evaluation", "scores", "known_weaknesses",
    "licence", "availability",
})
# Nested objects whose every listed field must be a non-empty string (hash and revision fields are checked again below).
_TEXT_FIELDS = {
    "base": ("repository", "url", "revision", "backbone"),
    "adapter": ("method", "checkpoint", "selection", "archive", "sha256", "weights_file", "weights_sha256"),
    "conversion": ("tool", "llama_cpp_revision", "steps", "tokeniser", "chat_template"),
    "training": ("pack_id", "pack", "pack_manifest_sha256", "labels", "dataset_card", "run", "records"),
    "serving": ("runtime", "server_flags", "client", "guide", "protocol_difference"),
    "parts": ("split", "reassemble", "checksums"),
}
# The request the recorded benchmark sent (manifest ``protocol``), and the one ``auditex model assess`` sends.
BENCHMARK_REQUEST_KEYS = frozenset({
    "cache_prompt", "chat_template_kwargs", "frequency_penalty", "max_tokens", "min_p", "n", "presence_penalty",
    "repeat_penalty", "seed", "stream", "temperature", "top_k", "top_p",
})
PRODUCTION_REQUEST_KEYS = frozenset({"temperature", "max_tokens", "cache_prompt", "chat_template_kwargs", "response_format"})


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _count(value: Any) -> bool:
    return type(value) is int and value > 0


def _number(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(value)


def _unit(value: Any) -> bool:
    return _number(value) and 0 <= value <= 1


def _https_url(value: Any) -> bool:
    """An https URL with a host name: the only kind the catalogue may point at."""
    if not _text(value):
        return False
    parts = urlsplit(value)
    try:
        port = parts.port
    except ValueError:
        return False
    host = parts.hostname or ""
    return (parts.scheme == "https" and bool(_HOSTNAME.fullmatch(host)) and "." in host
            and (port is None or 0 < port < 65536))


def _calendar_date(value: Any) -> bool:
    if not isinstance(value, str) or not _DATE.fullmatch(value):
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


# Every request field has a type and a range; a null or a stray type is not a protocol.
_REQUEST_CHECKS = {
    "temperature": lambda v: _number(v) and v >= 0,
    "max_tokens": _count,
    "cache_prompt": lambda v: type(v) is bool,
    "chat_template_kwargs": lambda v: isinstance(v, dict) and set(v) == {"enable_thinking"} and type(v["enable_thinking"]) is bool,
    "response_format": lambda v: isinstance(v, dict) and set(v) == {"type"} and v["type"] in {"json_object", "text"},
    "frequency_penalty": _number,
    "presence_penalty": _number,
    "repeat_penalty": lambda v: _number(v) and v > 0,
    "min_p": _unit,
    "top_p": _unit,
    "top_k": lambda v: type(v) is int and v >= 0,
    "n": lambda v: type(v) is int and v == 1,
    "seed": lambda v: type(v) is int,
    "stream": lambda v: v is False,
}


def _request_issues(name: str, request: Any, keys: frozenset[str]) -> list[str]:
    if not isinstance(request, dict) or set(request) != keys:
        return [name]
    return [name] if any(not _REQUEST_CHECKS[key](request[key]) for key in keys) else []


def _score_issue(score: Any) -> str | None:
    if not isinstance(score, dict):
        return "score entry"
    label = f"score {score.get('id')}"
    if not _text(score.get("id")) or not _text(score.get("definition")):
        return label
    # A count score is correct/total; a weighted score is a rate in [0, 1]; never both.
    correct, total, rate = score.get("correct"), score.get("total"), score.get("rate")
    counted = type(correct) is int and type(total) is int and 0 <= correct <= total and total > 0 and "rate" not in score
    weighted = (type(rate) is float and 0 <= rate <= 1 and "correct" not in score and "total" not in score)
    return None if counted != weighted else label


def _product_issues(source: dict[str, Any]) -> list[str]:
    issues = [f"missing {key}" for key in sorted(PRODUCT_KEYS - set(source))]
    if issues:
        return issues
    for key in ("id", "repository", "url", "format", "artifact", "quantisation", "evaluation", "licence", "availability"):
        if not _text(source[key]):
            issues.append(key)
    if not _https_url(source["url"]):
        issues.append("url")
    if not _calendar_date(source["evaluated_at"]):
        issues.append("evaluated_at")
    if not isinstance(source["sha256"], str) or not _SHA256.fullmatch(source["sha256"]):
        issues.append("sha256")
    if not _count(source["bytes"]):
        issues.append("bytes")
    # Null until the public repository is published; then a pinned 40-hex commit.
    if source["revision"] is not None and not (isinstance(source["revision"], str) and _REVISION.fullmatch(source["revision"])):
        issues.append("revision")
    for key, fields in _TEXT_FIELDS.items():
        if not isinstance(source[key], dict) or not all(_text(source[key].get(name)) for name in fields):
            issues.append(key)
    base, adapter, conversion, training = (source[key] if isinstance(source[key], dict) else {}
                                           for key in ("base", "adapter", "conversion", "training"))
    if "base" not in issues and (not _REVISION.fullmatch(base["revision"]) or not _https_url(base["url"])):
        issues.append("base")
    # ``sha256`` pins the adapter archive and ``weights_sha256`` the weights file inside it; one hash cannot be both.
    if "adapter" not in issues and (not _SHA256.fullmatch(adapter["sha256"]) or not _SHA256.fullmatch(adapter["weights_sha256"])):
        issues.append("adapter")
    elif "adapter" not in issues and adapter["sha256"] == adapter["weights_sha256"]:
        issues.append("adapter sha256 (archive) and weights_sha256 (weights file) must differ")
    if "conversion" not in issues and not _REVISION.fullmatch(conversion["llama_cpp_revision"]):
        issues.append("conversion")
    rows = training.get("rows")
    if ("training" not in issues and (not _SHA256.fullmatch(training["pack_manifest_sha256"]) or not isinstance(rows, dict)
                                      or set(rows) != {"train", "validation", "test"} or not all(map(_count, rows.values())))):
        issues.append("training")
    serving = source["serving"] if isinstance(source["serving"], dict) else {}
    if "request" in serving:
        issues.append("serving request is ambiguous; use benchmark_protocol and production_request")
    protocol = serving.get("benchmark_protocol")
    if (not isinstance(protocol, dict) or set(protocol) != {"manifest", "request", "response_format"}
            or not _text(protocol["manifest"]) or not _text(protocol["response_format"])):
        issues.append("benchmark_protocol")
    else:
        issues.extend(_request_issues("benchmark_protocol", protocol["request"], BENCHMARK_REQUEST_KEYS))
    issues.extend(_request_issues("production_request", serving.get("production_request"), PRODUCTION_REQUEST_KEYS))
    parts = source["parts"]
    files = parts.get("files") if isinstance(parts, dict) else None
    # The parts must reassemble into exactly the artefact: each named once and pinned, positive sizes summing to its size.
    if (not isinstance(files, list) or not files
            or any(not isinstance(part, dict) or not _text(part.get("name")) or not _count(part.get("bytes"))
                   or not isinstance(part.get("sha256"), str) or not _SHA256.fullmatch(part["sha256"]) for part in files)
            or len({part["name"] for part in files}) != len(files)
            or not _count(source["bytes"]) or sum(part["bytes"] for part in files) != source["bytes"]):
        issues.append("parts")
    scores = source["scores"]
    if not isinstance(scores, list) or not scores:
        issues.append("scores")
    else:
        issues.extend(issue for issue in map(_score_issue, scores) if issue)
        ids = [score.get("id") for score in scores if isinstance(score, dict) and _text(score.get("id"))]
        if len(set(ids)) != len(ids):
            issues.append("score ids must be unique")
    weaknesses = source["known_weaknesses"]
    if not isinstance(weaknesses, list) or not weaknesses or not all(map(_text, weaknesses)):
        issues.append("known_weaknesses")
    return issues


def validate_model_sources(payload: Any) -> None:
    if (not isinstance(payload, dict) or not isinstance(payload.get("sources"), list)
            or not all(isinstance(source, dict) for source in payload["sources"])):
        raise ValueError("Invalid model source catalogue.")
    ids = [source.get("id") for source in payload["sources"]]
    if not all(map(_text, ids)) or len(set(ids)) != len(ids):
        raise ValueError("Model source ids must be present and unique.")
    for source in payload["sources"]:
        if "sha256" in source and not (isinstance(source["sha256"], str) and _SHA256.fullmatch(source["sha256"])):
            raise ValueError(f"Invalid sha256 for model source {source['id']}.")
        if source.get("role") != PRODUCT_ROLE and not (
                isinstance(source.get("revision"), str) and _REVISION.fullmatch(source["revision"])):
            raise ValueError(f"Model source {source['id']} must pin a 40-character revision.")
    products = [source for source in payload["sources"] if source.get("role") == PRODUCT_ROLE]
    if len(products) != 1:
        raise ValueError("The model source catalogue must name exactly one product model.")
    issues = _product_issues(products[0])
    if issues:
        raise ValueError(f"Invalid product model entry: {', '.join(issues)}.")


def list_model_sources() -> dict[str, Any]:
    path = resolve_resource_path("configs/model-sources.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    validate_model_sources(payload)
    return payload
