"""The shipped-model catalogue entry is validated field by field: a null, a stray type or a vague URL or date is rejected."""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from auditex.model_sources import validate_model_sources

ROOT = Path(__file__).resolve().parents[1]


def catalogue():
    return json.loads((ROOT / "configs/model-sources.json").read_text(encoding="utf-8"))


def product(payload):
    return next(source for source in payload["sources"] if source.get("role") == "product_model")


def test_real_catalogue_validates():
    validate_model_sources(catalogue())


@pytest.mark.parametrize("path,value", [
    (("serving", "production_request", "response_format"), None),
    (("serving", "production_request", "response_format"), {"type": "yaml"}),
    (("serving", "production_request", "response_format"), {"type": "json_object", "schema": {}}),
    (("serving", "production_request", "temperature"), None),
    (("serving", "production_request", "max_tokens"), 0),
    (("serving", "production_request", "cache_prompt"), "false"),
    (("serving", "production_request", "chat_template_kwargs"), {"enable_thinking": None}),
    (("serving", "benchmark_protocol", "request", "seed"), None),
    (("serving", "benchmark_protocol", "request", "stream"), None),
    (("serving", "benchmark_protocol", "request", "n"), None),
    (("serving", "benchmark_protocol", "request", "n"), 2),
    (("serving", "benchmark_protocol", "request", "top_p"), None),
    (("serving", "benchmark_protocol", "request", "top_p"), 1.5),
    (("serving", "benchmark_protocol", "request", "min_p"), -0.1),
    (("serving", "benchmark_protocol", "request", "top_k"), None),
    (("serving", "benchmark_protocol", "request", "repeat_penalty"), 0),
    (("serving", "benchmark_protocol", "request", "frequency_penalty"), None),
    (("serving", "benchmark_protocol", "request", "presence_penalty"), "0"),
    (("url",), "https://"),
    (("url",), "http://huggingface.co/x/y"),
    (("url",), "https://nohost"),
    (("base", "url"), "not a URL"),
    (("evaluated_at",), "2026-99-99"),
    (("evaluated_at",), "2026-02-30"),
    (("evaluated_at",), "30-10-2026"),
    (("serving", "benchmark_protocol", "request", "n"), True),
    (("serving", "benchmark_protocol", "request", "n"), 1.0),
    (("serving", "benchmark_protocol", "request", "seed"), True),
    (("serving", "production_request", "temperature"), float("inf")),
    (("serving", "benchmark_protocol", "request", "presence_penalty"), float("nan")),
    (("url",), "https://not a URL.example/x"),
    (("url",), "https://example.com:bad/x"),
    (("url",), "https://example.com:70000/x"),
    (("base", "url"), "https://-bad-.example/x"),
    # The adapter pins the archive (sha256) and the weights file inside it (weights_sha256) separately.
    (("adapter", "weights_sha256"), None),
    (("adapter", "weights_sha256"), ""),
    (("adapter", "weights_sha256"), "b477f2b6"),
    (("adapter", "weights_sha256"), "B477F2B60FE72B29207BAC835811590706FC418AA2CBD6AA643465DD174BE682"),
    (("adapter", "weights_file"), None),
    (("adapter", "weights_file"), "  "),
    (("adapter", "sha256"), "40db5b31"),
])
def test_null_stray_or_vague_values_are_rejected(path, value):
    payload = catalogue()
    target = product(payload)
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValueError):
        validate_model_sources(payload)


def test_accepted_values_still_pass():
    payload = catalogue()
    entry = product(payload)
    entry["serving"]["production_request"]["response_format"] = {"type": "text"}
    entry["evaluated_at"] = "2026-02-28"
    validate_model_sources(payload)


def test_adapter_weights_hash_is_required_and_must_differ_from_the_archive_hash():
    payload = catalogue()
    adapter = product(payload)["adapter"]
    assert adapter["archive"].endswith(".tar") and adapter["weights_file"] == "adapter_model.safetensors"
    assert adapter["sha256"] == "40db5b31a3bff37d4d6d57294174ab2b0c4235ebe1687934079e96efd29f1886"
    assert adapter["weights_sha256"] == "b477f2b60fe72b29207bac835811590706fc418aa2cbd6aa643465dd174be682"
    del adapter["weights_sha256"]
    with pytest.raises(ValueError, match="adapter"):
        validate_model_sources(payload)
    del adapter["weights_file"]
    with pytest.raises(ValueError, match="adapter"):
        validate_model_sources(payload)


def test_equal_archive_and_weights_hashes_are_refused_naming_both_fields():
    payload = catalogue()
    adapter = product(payload)["adapter"]
    adapter["sha256"] = adapter["weights_sha256"]
    with pytest.raises(ValueError, match=r"sha256 \(archive\) and weights_sha256 \(weights file\) must differ"):
        validate_model_sources(payload)
