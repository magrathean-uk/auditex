"""Parked offline model client and the legacy entry points of the rule-only assessment.

The rule-only writer lives in :mod:`auditex.rule_assessment`; ``assess_run`` and ``assess_scubagear_export`` here keep
their legacy signatures, warn about ignored model options, write dry-run prompts locally and delegate every other call.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from http.client import HTTPException
import ipaddress
import json
import logging
import math
import os
from pathlib import Path
import re
import sys
from time import monotonic, sleep
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from azure_tenant_audit.guarded_io import guarded_operation
from azure_tenant_audit.private_io import write_private_text
from azure_tenant_audit.strict_json import reject_json_constant as _invalid_constant, strict_pairs as _pairs

from . import rule_assessment
from .model_eval import validate_model_response
from .model_prompt import SYSTEM_PROMPT, SYSTEM_PROMPT_SHA256
from .rule_assessment import (  # noqa: F401  (re-exported for legacy callers until the model layer is removed)
    PROMPT_CONVENTION, RULE_NOT_IMPLEMENTED_TEXT, SCHEMA_VERSION, PolicyUnavailable, _baseline_statuses, _comparison,
    _identity_view, _totals, _uncovered_record, build_case, canonical, policy_catalogue,
    precheck_case,
)
from .scuba_projection import (
    DEFAULT_MAX_CHARS, DEFAULT_MAX_ITEMS, DEFAULT_SCAN_MAX_BYTES, DEFAULT_SCAN_MAX_CHUNKS, DEFAULT_SCAN_MAX_ROWS,
    project_run,
)

_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
# Pause before re-sending a request whose reply was lost in transit (P5: a relay dropped replies under load).
_TRANSPORT_BACKOFF_SECONDS = 2.0
# finish_reason is server text: keep it only when it is a plain token such as stop or length.
_FINISH_REASON = re.compile(r"[a-z][a-z0-9_]{0,31}")
LOG = logging.getLogger(__name__)


def messages_for(case: dict[str, Any]) -> list[dict[str, str]]:
    if sha256(SYSTEM_PROMPT.encode()).hexdigest() != SYSTEM_PROMPT_SHA256:
        raise ValueError("Training system prompt hash mismatch")
    return [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": canonical(case)}]


@dataclass(frozen=True)
class ModelConfig:
    endpoint: str = "http://127.0.0.1:8080/v1"
    model_name: str = ""
    api_key: str = field(default="", repr=False)
    timeout: float = 120.0

    def __post_init__(self) -> None:
        try:
            url = urlsplit(self.endpoint)
            _ = url.port  # Validate malformed/out-of-range ports without retaining URL errors.
        except ValueError:
            raise ValueError("Invalid model endpoint URL") from None
        if (url.scheme not in {"http", "https"} or not url.hostname or url.username is not None
                or url.password is not None or url.query or url.fragment
                or any(ord(ch) <= 32 or ord(ch) == 127 for ch in self.endpoint)):
            raise ValueError("Model endpoint must be an HTTP(S) URL without credentials, query or fragment")
        if not math.isfinite(self.timeout) or self.timeout <= 0:
            raise ValueError("Model timeout must be a positive finite number of seconds")
        if any(ch in self.api_key for ch in "\r\n"):
            raise ValueError("Invalid model API key header")
        if (self.api_key and url.scheme == "http" and not _is_loopback(str(url.hostname))
                and os.environ.get("AUDITEX_MODEL_ALLOW_INSECURE") != "1"):
            raise ValueError("Model API key over non-loopback HTTP requires HTTPS or AUDITEX_MODEL_ALLOW_INSECURE=1")

    @classmethod
    def from_environment(cls, *, endpoint: str | None = None, model: str | None = None) -> ModelConfig:
        return cls(endpoint=endpoint if endpoint is not None else os.environ.get("AUDITEX_MODEL_ENDPOINT", cls.endpoint),
                   model_name=model if model is not None else os.environ.get("AUDITEX_MODEL_NAME", ""),
                   api_key=os.environ.get("AUDITEX_MODEL_API_KEY", ""),
                   timeout=float(os.environ.get("AUDITEX_MODEL_TIMEOUT", "120")))

    @property
    def endpoint_host(self) -> str:
        return str(urlsplit(self.endpoint).hostname)

    def public_configuration(self) -> dict[str, Any]:
        return {"endpoint": self.endpoint.rstrip("/"), "endpoint_host": self.endpoint_host,
                "model_name": self.model_name, "timeout_seconds": self.timeout}


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.lower().rstrip(".") == "localhost"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ModelEndpointError(ValueError):
    """Sanitised endpoint failure, without response bodies or credentials."""


class ModelTransportError(ModelEndpointError):
    """The request or its reply was lost in transit (connection, timeout, truncated read); worth one retry."""


class ModelClient:
    def __init__(self, config: ModelConfig):
        self.config = config
        self._json_format = True
        self._thinking_disabled = True
        self._cache_prompt_off = True
        # No proxy environment or redirects may silently move evidence elsewhere.
        self._opener = build_opener(ProxyHandler({}), _NoRedirect())
        if not _is_loopback(config.endpoint_host):
            print(f"Warning: model endpoint {config.endpoint_host} is not loopback; evidence will leave the machine.", file=sys.stderr)

    def serving(self) -> dict[str, str]:
        """The request settings this session sends after negotiation, for the assessment envelope."""
        return {"cache_prompt": "disabled" if self._cache_prompt_off else "server_default",
                "response_format": "json_object" if self._json_format else "not_sent"}

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> bytes:
        headers = {"Accept": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        data = None
        if payload is not None:
            data = canonical(payload).encode("utf-8", "surrogatepass")  # a lone surrogate in evidence must not abort the run
            headers["Content-Type"] = "application/json"
        request = Request(self.config.endpoint.rstrip("/") + path, data=data, headers=headers, method=method)
        try:
            with self._opener.open(request, timeout=self.config.timeout) as response:
                body = response.read(_MAX_RESPONSE_BYTES + 1)
                if len(body) > _MAX_RESPONSE_BYTES:
                    raise ModelEndpointError("Model endpoint response exceeds 4 MiB")
                return body
        except HTTPError:
            raise
        except (OSError, URLError, HTTPException):
            raise ModelTransportError("Model endpoint unreachable, timed out or reply cut short") from None
        except ValueError as exc:
            if isinstance(exc, ModelEndpointError):
                raise
            raise ModelEndpointError("Model endpoint unavailable or timed out") from None

    def doctor(self) -> dict[str, Any]:
        result = {**self.config.public_configuration(), "endpoint_reachable": False,
                  "model_name_configured": bool(self.config.model_name.strip()), "model_present": False, "ok": False}
        try:
            payload = json.loads(self._request("GET", "/models"))
            rows = payload.get("data") if isinstance(payload, dict) else None
            if not isinstance(rows, list):
                raise ValueError("Invalid models response")
            result["endpoint_reachable"] = True
            result["model_present"] = any(isinstance(row, dict) and row.get("id") == self.config.model_name for row in rows)
        except (OSError, HTTPException, ValueError, UnicodeError) as exc:
            if isinstance(exc, HTTPError):
                exc.close()
            result["error"] = "Model endpoint unavailable or invalid models response"
        result["ok"] = result["endpoint_reachable"] and result["model_name_configured"] and result["model_present"]
        return result

    def assess(self, case: dict[str, Any]) -> dict[str, Any]:
        if not self.config.model_name.strip():
            raise ValueError("AUDITEX_MODEL_NAME or --model is required")
        messages = messages_for(case)
        record = {"policy_id": case["policy_id"], "claims": [], "limitations": [], "recommendations": [],
                  "validation_status": "invalid", "latency_ms": 0, "attempts": 0,
                  "prompt_sha256": sha256(canonical(messages).encode("utf-8", "surrogatepass")).hexdigest(), "response_sha256": None,
                  "thinking_disabled": self._thinking_disabled, "thinking_stripped": False,
                  "reason": None, "finish_reason": None}
        started = monotonic()
        for attempt in range(2):
            if attempt and record["reason"] == "model_transport_failed":
                sleep(_TRANSPORT_BACKOFF_SECONDS)
            payload = {"model": self.config.model_name, "messages": messages, "temperature": 0, "max_tokens": 1024}
            if self._json_format:
                payload["response_format"] = {"type": "json_object"}
            if self._thinking_disabled:
                payload["chat_template_kwargs"] = {"enable_thinking": False}
            # llama-server reuses a cached prompt prefix by default; the validated protocol turns that off so greedy
            # decoding does not depend on the previous request.
            if self._cache_prompt_off:
                payload["cache_prompt"] = False
            try:
                while True:
                    record["attempts"] += 1
                    record["response_sha256"] = None
                    record["finish_reason"] = None
                    record["thinking_disabled"] = "chat_template_kwargs" in payload
                    try:
                        raw = self._request("POST", "/chat/completions", payload)
                        break
                    except HTTPError as exc:
                        try:
                            body = exc.read(_MAX_RESPONSE_BYTES).decode("utf-8", errors="replace")
                        except (OSError, HTTPException):
                            raise ModelEndpointError("Model endpoint unavailable or timed out") from None
                        finally:
                            exc.close()
                        if exc.code == 400 and "response_format" in payload and "response_format" in body:
                            self._json_format = False
                            payload.pop("response_format")
                            continue
                        if exc.code == 400 and "chat_template_kwargs" in payload and "chat_template_kwargs" in body:
                            self._thinking_disabled = False
                            payload.pop("chat_template_kwargs")
                            continue
                        if exc.code == 400 and "cache_prompt" in payload and "cache_prompt" in body:
                            self._cache_prompt_off = False
                            payload.pop("cache_prompt")
                            continue
                        raise ModelEndpointError(f"Model endpoint returned HTTP {exc.code}") from None
            except ModelTransportError:
                record.update(validation_status="unknown", reason="model_transport_failed")
                continue
            except ModelEndpointError:
                record.update(validation_status="unknown", reason="model_endpoint_unavailable")
                break
            # An empty, non-JSON or non-chat-completion body, or one without assistant text, is a reply lost in
            # transit, not a model answer: it is retried like one and never hashed.
            try:
                envelope = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_invalid_constant)
                choice = envelope["choices"][0]
                finish = choice.get("finish_reason")
                record["finish_reason"] = finish if isinstance(finish, str) and _FINISH_REASON.fullmatch(finish) else None
                content = choice["message"]["content"]
                if not isinstance(content, str) or not content.strip():
                    raise ValueError("Missing assistant text")
            except (ValueError, KeyError, IndexError, TypeError, AttributeError, OverflowError, RecursionError):
                record.update(validation_status="unknown", reason="model_transport_failed")
                continue
            content, stripped = re.subn(r"\A\s*<think>.*?</think>\s*", "", content, count=1, flags=re.DOTALL)
            record["thinking_stripped"] = record["thinking_stripped"] or bool(stripped)
            # surrogatepass equals UTF-8 for any real text and hashes a lone surrogate (reachable only through a JSON
            # escape such as \ud800) by its exact code point, so the hash never raises and never collides.
            record["response_sha256"] = sha256(content.encode("utf-8", "surrogatepass")).hexdigest()
            try:
                # Text that is not valid Unicode is no answer: UnicodeEncodeError makes it model_response_invalid.
                content.encode()
                answer = validate_model_response(content, case)
            except (ValueError, KeyError, IndexError, TypeError, OverflowError, RecursionError):
                record.update(validation_status="invalid", reason="model_response_invalid")
                continue
            record.update(answer, validation_status="valid", reason=None)
            break
        if record["validation_status"] != "valid":
            record.update(claims=[{"id": item["id"], "status": "unknown", "value": None, "evidence_ids": []}
                                  for item in case["requested_claims"]], limitations=[record["reason"]], recommendations=[])
        record["latency_ms"] = round((monotonic() - started) * 1000, 3)
        return record


def legacy_model_options_set() -> bool:
    return "AUDITEX_DISABLE_VALUE_RULES" in os.environ or any(
        name.startswith("AUDITEX_MODEL_") for name in os.environ)


def warn_ignored_model_options() -> None:
    print("Warning: legacy model options are ignored for assessment; the model layer is parked and redaction stays enabled.",
          file=sys.stderr)


def _dry_run_prompts(projection: Any, selected: list[str], catalogue: dict[str, Any],
                     generated_at: str) -> list[dict[str, Any]]:
    prompts: list[dict[str, Any]] = []
    for policy_id in selected:
        try:
            case = build_case(policy_id, projection, generated_at, catalogue=catalogue)
        except PolicyUnavailable:
            prompts.append({"policy_id": policy_id, "skipped": True, "reason": "policy_not_in_catalogue"})
            continue
        messages = messages_for(case)
        prompts.append({"policy_id": policy_id, "messages": messages,
                        "prompt_sha256": sha256(canonical(messages).encode("utf-8", "surrogatepass")).hexdigest(),
                        "prompt_convention": PROMPT_CONVENTION, "system_prompt_sha256": SYSTEM_PROMPT_SHA256})
    return prompts


def _prompt_counts(prompts: list[dict[str, Any]]) -> dict[str, int]:
    return {"prompts": sum("messages" in row for row in prompts),
            "skipped": sum(row.get("skipped", False) for row in prompts)}


@guarded_operation
def assess_run(run_dir: str | Path, config: ModelConfig | None = None, *, policies: list[str] | None = None,
               dry_run: bool = False, shadow_model_on_precheck: bool = False, legacy_options: bool = False,
               no_redaction: bool = False, projection_max_items: int = DEFAULT_MAX_ITEMS,
               projection_max_chars: int = DEFAULT_MAX_CHARS, projection_scan_max_rows: int = DEFAULT_SCAN_MAX_ROWS,
               projection_scan_max_bytes: int = DEFAULT_SCAN_MAX_BYTES,
               projection_scan_max_chunks: int = DEFAULT_SCAN_MAX_CHUNKS) -> dict[str, Any]:
    if config is not None or no_redaction or shadow_model_on_precheck or legacy_options or legacy_model_options_set():
        warn_ignored_model_options()
    if not dry_run:
        return rule_assessment.assess_run(
            run_dir, policies=policies, projection_max_items=projection_max_items,
            projection_max_chars=projection_max_chars, projection_scan_max_rows=projection_scan_max_rows,
            projection_scan_max_bytes=projection_scan_max_bytes, projection_scan_max_chunks=projection_scan_max_chunks)
    filename = "model_assessment_prompts.jsonl"
    root, _manifest, catalogue, selected = rule_assessment._admit_run(run_dir, policies, filename)
    target = root / filename
    generated_at = datetime.now(timezone.utc).isoformat()
    projection = project_run(root, redact=True, max_items=projection_max_items,
                             max_chars=projection_max_chars, scan_max_rows=projection_scan_max_rows,
                             scan_max_bytes=projection_scan_max_bytes, scan_max_chunks=projection_scan_max_chunks)
    prompts = _dry_run_prompts(projection, selected, catalogue, generated_at)
    write_private_text(target, "".join(canonical(row) + "\n" for row in prompts))
    return {"path": str(target), "dry_run": True, **_prompt_counts(prompts)}


@guarded_operation
def assess_scubagear_export(export_path: str | Path, output_dir: str | Path, config: ModelConfig | None = None, *,
                            results_path: str | Path | None = None, policies: list[str] | None = None,
                            dry_run: bool = False, no_redaction: bool = False, legacy_options: bool = False,
                            projection_max_items: int = DEFAULT_MAX_ITEMS,
                            projection_max_chars: int = DEFAULT_MAX_CHARS,
                            verdict_map: dict[str, str] | None = None) -> dict[str, Any]:
    """Assess a local ScubaGear export without a run bundle or tenant contact."""
    from .scubagear_export import VERDICT_MAP, _valid_map
    if verdict_map is None:
        verdict_map = VERDICT_MAP
    _valid_map(verdict_map)
    if config is not None or no_redaction or legacy_options or legacy_model_options_set():
        warn_ignored_model_options()
    if not dry_run:
        return rule_assessment.assess_scubagear_export(
            export_path, output_dir, results_path=results_path, policies=policies,
            projection_max_items=projection_max_items, projection_max_chars=projection_max_chars,
            verdict_map=verdict_map)
    view = rule_assessment._export_view(export_path, output_dir, results_path=results_path, policies=policies,
                                        projection_max_items=projection_max_items,
                                        projection_max_chars=projection_max_chars, verdict_map=verdict_map)
    target_dir = view["target_dir"]
    prompts = _dry_run_prompts(view["projection"], view["selected"], view["catalogue"], view["generated_at"])
    sidecar = rule_assessment._export_sidecar(view, None, verdict_map)
    filename = "model_assessment_prompts.jsonl"
    content = "".join(canonical(row) + "\n" for row in prompts)
    result: dict[str, Any] = {"path": str(target_dir / filename), "dry_run": True, **_prompt_counts(prompts),
                              "sidecar_path": str(target_dir / "scubagear_adapter_report.json")}
    sidecar_text = json.dumps(sidecar, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    rule_assessment._prepare_output_directory(target_dir)
    created: list[Path] = []
    try:
        for name, data in ((filename, content), ("scubagear_adapter_report.json", sidecar_text)):
            path = target_dir / name
            created.append(path)
            write_private_text(path, data)
    except OSError:
        from azure_tenant_audit.guarded_io import remove_guarded_output
        for path in created:
            remove_guarded_output(path)
        raise
    return result
