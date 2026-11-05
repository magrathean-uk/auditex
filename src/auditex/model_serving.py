"""Optional rule-only SCuBA assessment and parked offline model client."""
from __future__ import annotations

from dataclasses import dataclass, field
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
from http.client import HTTPException
import ipaddress
import json
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

from azure_tenant_audit.external_sharing import ENUM_NAME_KEYS, annotate_enum_names
from azure_tenant_audit.model_evidence import NOT_COLLECTED
from azure_tenant_audit.private_io import write_private_text
from azure_tenant_audit.resources import open_text_resource

from .model_eval import _invalid_constant, _pairs, validate_model_response
from .model_prompt import SYSTEM_PROMPT, SYSTEM_PROMPT_SHA256
from .model_precheck import precheck_case
from .scope_postcheck import collect_scope_evidence
from .scuba_projection import (
    DEFAULT_MAX_CHARS, DEFAULT_MAX_ITEMS, DEFAULT_SCAN_MAX_BYTES, DEFAULT_SCAN_MAX_CHUNKS, DEFAULT_SCAN_MAX_ROWS,
    policy_section, project_run, rule_policy_section,
)

SCHEMA_VERSION = "2026-11-05"
PROMPT_CONVENTION = "named-enums-v1"
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
# Pause before re-sending a request whose reply was lost in transit (P5: a relay dropped replies under load).
_TRANSPORT_BACKOFF_SECONDS = 2.0
# finish_reason is server text: keep it only when it is a plain token such as stop or length.
_FINISH_REASON = re.compile(r"[a-z][a-z0-9_]{0,31}")


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def policy_catalogue() -> dict[str, Any]:
    return json.loads(open_text_resource("configs/scuba-policy-sections.json"))


class PolicyUnavailable(ValueError):
    """A policy absent from the catalogue cannot be assessed."""


def _identity_view(value: Any) -> Any:
    # conv3 IDs predate enum annotation. Strip only the seven derived names,
    # and only in SPO_tenant, retaining every original numeric value.
    if isinstance(value, list):
        return [_identity_view(item) for item in value]
    if isinstance(value, dict):
        names = {f"{key}_name" for key in ENUM_NAME_KEYS if key in value}
        return {key: _identity_view(item) for key, item in value.items() if key not in names}
    return value


def build_case(policy_id: str, projection: dict[str, Any], as_of: str, *,
               catalogue: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build exactly the training user object; serialise with :func:`canonical`.

    ``as_of`` belongs to the assessment envelope, not the training user shape.
    Case IDs are serving-generated and are not reproducible for pack rows,
    whose IDs also depend on generator inputs unavailable in a serving run.
    No timestamp or additional user-message field is introduced.
    """
    data = catalogue if catalogue is not None else policy_catalogue()
    if policy_id not in data["policies"]:
        raise PolicyUnavailable("policy_not_in_catalogue")
    entry = data["policies"][policy_id]
    item = entry["policy_item"]
    observed = {section: policy_section(projection, policy_id, section) for section in entry["sections"]}
    identity = {section: _identity_view(value) if section == "SPO_tenant" else value
                for section, value in observed.items()}
    view_hash = sha256(f"conv3:{canonical(identity)}".encode("utf-8", "surrogatepass")).hexdigest()[:10]
    product = policy_id.split(".")[1].lower()
    case_id = f"scuba-{product}-{policy_id.lower().replace('.', '-')}-{view_hash}"
    evidence = [{"id": "e0", "observed": dict(item), "section": "policy"}]
    evidence.extend({"id": f"e{index}", "observed": annotate_enum_names(section, value), "section": section}
                    for index, (section, value) in enumerate(observed.items(), start=1))
    # Round-trip sorts every nested key just as the training samples do.
    return json.loads(canonical({
        "case_id": case_id, "evidence": evidence, "limitation_ids": data["limitation_ids"],
        "policy_id": policy_id, "recommendation_ids": data["recommendation_ids"],
        "requested_claims": [
            {"id": "requirement_met", "question": f"Does this tenant meet {policy_id}?"},
            {"id": "policy_criticality", "question": "What criticality does the baseline assign to this policy?"},
        ],
    }))


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


def _comparison(policy_id: str, record: dict[str, Any], baseline: dict[str, str]) -> dict[str, Any]:
    rule_status = baseline.get(policy_id)
    match = "exact" if policy_id in baseline else "none"
    if match == "none":
        unversioned = re.sub(r"v\d+$", "", policy_id)
        candidates = [status for pid, status in baseline.items() if re.sub(r"v\d+$", "", pid) == unversioned]
        if len(candidates) == 1:
            rule_status, match = candidates[0], "version_mismatch"
    requirement = next((claim for claim in record["claims"] if claim["id"] == "requirement_met"), {})
    model_status = None
    if record["validation_status"] == "valid" and requirement.get("status") == "confirmed":
        model_status = "pass" if requirement.get("value") is True else "fail"
    agreement = "not_assessed"
    if rule_status in {"pass", "fail"} and model_status is not None:
        agreement = "agree" if rule_status == model_status else "disagree"
    return {"baseline_status": rule_status, "baseline_match": match, "model_status": model_status, "result": agreement}


def _baseline_statuses(pack_path: Path) -> dict[str, str]:
    """Ignore malformed optional report-pack comparison data."""
    try:
        node = json.loads(pack_path.read_text(encoding="utf-8"))
        for key in ("baseline_alignment", "frameworks", "cisa_scuba", "controls"):
            node = node.get(key) if isinstance(node, dict) else None
        if not isinstance(node, list):
            return {}
        return {row["control_id"]: row["status"] for row in node if isinstance(row, dict)
                and isinstance(row.get("control_id"), str)
                and row.get("status") in ("pass", "fail", "accepted_risk", "not_assessed")}
    except (OSError, ValueError, RecursionError):
        return {}


RULE_NOT_IMPLEMENTED_TEXT = "Not assessed: Auditex has no rule for this policy yet."


def legacy_model_options_set() -> bool:
    return "AUDITEX_DISABLE_VALUE_RULES" in os.environ or any(
        name.startswith("AUDITEX_MODEL_") for name in os.environ)


def warn_ignored_model_options() -> None:
    print("Warning: legacy model options are ignored for assessment; the model layer is parked and redaction stays enabled.",
          file=sys.stderr)


def _uncovered_record(case: dict[str, Any]) -> dict[str, Any]:
    return {"policy_id": case["policy_id"],
            "claims": [{"id": item["id"], "status": "unknown", "value": None, "evidence_ids": []}
                       for item in case["requested_claims"]],
            "limitations": [], "recommendations": [], "validation_status": "unknown",
            "reason": "rule_not_implemented", "reason_text": RULE_NOT_IMPLEMENTED_TEXT,
            "latency_ms": 0, "attempts": 0, "prompt_sha256": None, "response_sha256": None,
            "thinking_disabled": False, "thinking_stripped": False}


def _assess_policies(projection: dict[str, Any], selected: list[str],
                     catalogue: dict[str, Any], generated_at: str, *, dry_run: bool,
                     baseline: dict[str, str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    records, prompts = [], []
    for policy_id in selected:
        try:
            case = build_case(policy_id, projection, generated_at, catalogue=catalogue)
        except PolicyUnavailable:
            record = {"policy_id": policy_id, "claims": [], "limitations": [], "recommendations": [],
                      "validation_status": "skipped", "reason": "policy_not_in_catalogue", "latency_ms": 0,
                      "attempts": 0, "prompt_sha256": None, "response_sha256": None,
                      "thinking_disabled": False, "thinking_stripped": False}
            if dry_run:
                prompts.append({"policy_id": policy_id, "skipped": True, "reason": "policy_not_in_catalogue"})
        else:
            if dry_run:
                messages = messages_for(case)
                prompts.append({"policy_id": policy_id, "messages": messages,
                                "prompt_sha256": sha256(canonical(messages).encode("utf-8", "surrogatepass")).hexdigest(),
                                "prompt_convention": PROMPT_CONVENTION, "system_prompt_sha256": SYSTEM_PROMPT_SHA256})
                continue
            from azure_tenant_audit.value_rules.catalogue import row_for
            row = row_for(policy_id)
            rule_projection = None
            if hasattr(projection, "rule_sections"):
                if row:
                    rule_projection = {section: deepcopy(projection.rule_sections.get(section, NOT_COLLECTED))
                                       for section in row["sections"] if section != "scuba_config"}
                    # stage 4: optional evidence informs the rule without becoming required or cited.
                    rule_projection.update({section: deepcopy(projection.rule_sections[section])
                                            for section in row.get("optional_sections", [])
                                            if section in projection.rule_sections})
                    if "scuba_config" in row["sections"]:
                        rule_projection["scuba_config"] = deepcopy(rule_policy_section(projection, policy_id, "scuba_config"))
            record = (precheck_case(case, absent_fields=True, empty_lists=True, value_rules=True,
                                    rule_projection=rule_projection) if row else None)
            if record is None:
                record = _uncovered_record(case)
        record["comparison"] = _comparison(policy_id, record, baseline)
        records.append(record)
    return records, prompts


def _totals(records: list[dict[str, Any]]) -> dict[str, int]:
    # Keep the historical total in current output; row-level scope metadata is no longer produced.
    totals = {"answered": 0, "unknown": 0, "invalid": 0, "skipped": 0, "rule_answered": 0,
              "scope_narrowed": 0}
    for record in records:
        totals["rule_answered"] += record["reason"] == "rule_precheck"
        state = record["validation_status"]
        if state in {"invalid", "skipped"}:
            totals[state] += 1
        elif state == "unknown" or any(c["id"] == "requirement_met" and c["status"] == "unknown" for c in record["claims"]):
            totals["unknown"] += 1
        else:
            totals["answered"] += 1
    return totals


def assess_run(run_dir: str | Path, config: ModelConfig | None = None, *, policies: list[str] | None = None,
               dry_run: bool = False, shadow_model_on_precheck: bool = False, legacy_options: bool = False,
               no_redaction: bool = False, projection_max_items: int = DEFAULT_MAX_ITEMS,
               projection_max_chars: int = DEFAULT_MAX_CHARS, projection_scan_max_rows: int = DEFAULT_SCAN_MAX_ROWS,
               projection_scan_max_bytes: int = DEFAULT_SCAN_MAX_BYTES,
               projection_scan_max_chunks: int = DEFAULT_SCAN_MAX_CHUNKS) -> dict[str, Any]:
    if config is not None or no_redaction or shadow_model_on_precheck or legacy_options or legacy_model_options_set():
        warn_ignored_model_options()
    root = Path(run_dir).expanduser().resolve()
    manifest = json.loads((root / "run-manifest.json").read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("run_id"), str) or not manifest["run_id"]:
        raise ValueError("Run manifest requires a run_id")
    catalogue = policy_catalogue()
    selected = list(catalogue["policies"]) if policies is None else policies
    if not selected or len(set(selected)) != len(selected) or any(
        not re.fullmatch(r"MS\.[A-Z]+\.\d+\.\d+v\d+", pid) for pid in selected
    ):
        raise ValueError("Policies must be unique SCuBA policy IDs")
    filename = "model_assessment_prompts.jsonl" if dry_run else "model_assessment.json"
    target = root / filename
    # Never replace a file already sealed into the original bundle.
    from azure_tenant_audit.bundle_integrity import listed_artifact_paths
    if filename in (listed_artifact_paths(root) or ()):
        raise ValueError("Model output is already sealed in this bundle; use a fresh run copy")
    if target.is_symlink():
        raise ValueError("Model output must not be a symbolic link")
    generated_at = datetime.now(timezone.utc).isoformat()
    projection = project_run(root, redact=True, max_items=projection_max_items,
                             max_chars=projection_max_chars, scan_max_rows=projection_scan_max_rows,
                             scan_max_bytes=projection_scan_max_bytes, scan_max_chunks=projection_scan_max_chunks)
    baseline = {} if dry_run else _baseline_statuses(root / "reports" / "report-pack.json")
    # Read-only and verdict-independent: which enabled Conditional Access policies carry a scope condition the
    # pinned Rego ignores. The envelope carries this caveat; nothing here reaches a prompt.
    scope = None if dry_run else collect_scope_evidence(
        root, projection, redact=True, max_items=projection_max_items,
        scan_max_rows=projection_scan_max_rows, scan_max_bytes=projection_scan_max_bytes,
        scan_max_chunks=projection_scan_max_chunks)
    records, prompts = _assess_policies(projection, selected, catalogue, generated_at,
                                        dry_run=dry_run, baseline=baseline)
    if dry_run:
        write_private_text(target, "".join(canonical(row) + "\n" for row in prompts))
        return {"path": str(target), "dry_run": True, "prompts": sum("messages" in row for row in prompts),
                "skipped": sum(row.get("skipped", False) for row in prompts)}
    totals = _totals(records)
    result = {"schema_version": SCHEMA_VERSION, "generated_at": generated_at, "run_id": manifest["run_id"],
              "endpoint_host": "none", "model_name": "rules-only",
              "prompt_convention": PROMPT_CONVENTION, "system_prompt_sha256": SYSTEM_PROMPT_SHA256,
              "totals": totals, "policies": records,
              "projection": projection.report, "scope_post_check": scope.summary,
              "limitations": [] if any(v != NOT_COLLECTED for v in projection.values()) else ["projection_not_implemented"]}
    from azure_tenant_audit.model_assessment import validate_assessment
    validate_assessment(result)
    write_private_text(target, json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + "\n")
    return result


def assess_scubagear_export(export_path: str | Path, output_dir: str | Path, config: ModelConfig | None = None, *,
                            results_path: str | Path | None = None, policies: list[str] | None = None,
                            dry_run: bool = False, no_redaction: bool = False, legacy_options: bool = False,
                            projection_max_items: int = DEFAULT_MAX_ITEMS,
                            projection_max_chars: int = DEFAULT_MAX_CHARS,
                            verdict_map: dict[str, str] | None = None) -> dict[str, Any]:
    """Assess a local ScubaGear export without a run bundle or tenant contact."""
    from .scubagear_export import (
        VERDICT_MAP, _valid_map, build_baseline, build_sidecar, load_export, load_results,
        project_export, resolve_output_directory, scope_from_export, scubaresults_layout_ok,
    )
    if verdict_map is None:
        verdict_map = VERDICT_MAP
    _valid_map(verdict_map)
    if config is not None or no_redaction or legacy_options or legacy_model_options_set():
        warn_ignored_model_options()
    target_dir = resolve_output_directory(output_dir)
    catalogue = policy_catalogue()
    selected = list(catalogue["policies"]) if policies is None else policies
    if not selected or len(set(selected)) != len(selected) or any(
        not re.fullmatch(r"MS\.[A-Z]+\.\d+\.\d+v\d+", pid) for pid in selected
    ):
        raise ValueError("Policies must be unique SCuBA policy IDs")
    loaded = load_export(export_path)
    projection, extras = project_export(loaded, catalogue["policies"], redact=True,
                                        max_items=projection_max_items, max_chars=projection_max_chars)
    verdict_error = False
    if results_path is not None:
        try:
            verdict_rows, verdict_kind = load_results(results_path)
        except (OSError, ValueError):
            verdict_rows, verdict_kind, verdict_error = None, "none", True
        verdict_source = "results_file"
    elif loaded.kind == "scubaresults":
        verdict_rows, verdict_kind = loaded.results, "scubaresults"
        verdict_source = "embedded"
    else:
        verdict_rows, verdict_kind, verdict_source = None, "none", "none"
    layout_error = verdict_kind == "scubaresults" and not scubaresults_layout_ok(verdict_rows)
    if ("Results" in loaded.repaired_keys and results_path is None) or layout_error:
        verdict_rows, verdict_kind = None, "none"
    baseline, reasons, unmappable = build_baseline(
        verdict_rows, loaded.raw, kind=verdict_kind, repaired_keys=loaded.repaired_keys,
        verdict_map=verdict_map, catalogue_ids=set(catalogue["policies"]))
    if "Results" in loaded.repaired_keys and results_path is None:
        verdict_state = "unreadable_repaired"
    elif verdict_error:
        verdict_state = "unreadable_file"
    elif verdict_source == "none":
        verdict_state = "absent"
    elif layout_error:
        verdict_state = "unreadable_layout"
    elif not baseline:
        verdict_state = "empty"
    else:
        verdict_state = "readable"
    generated_at = datetime.now(timezone.utc).isoformat()
    scope = None if dry_run else scope_from_export(projection, extras["raw_ca"],
                                                   redact=True, max_items=projection_max_items)
    records, prompts = _assess_policies(projection, selected, catalogue, generated_at,
                                        dry_run=dry_run, baseline=baseline)
    sidecar = build_sidecar(loaded, projection, extras, catalogue["policies"], selected, baseline,
                            reasons, unmappable, verdict_source, verdict_state, verdict_map, generated_at, scope)
    filename = "model_assessment_prompts.jsonl" if dry_run else "model_assessment.json"
    if dry_run:
        content = "".join(canonical(row) + "\n" for row in prompts)
        result: dict[str, Any] = {"path": str(target_dir / filename), "dry_run": True,
                                  "prompts": sum("messages" in row for row in prompts),
                                  "skipped": sum(row.get("skipped", False) for row in prompts),
                                  "sidecar_path": str(target_dir / "scubagear_adapter_report.json")}
    else:
        run_suffix = loaded.report_uuid or loaded.sha256[:16]
        result = {"schema_version": SCHEMA_VERSION, "generated_at": generated_at,
                  "run_id": "scubagear-" + run_suffix, "endpoint_host": "none",
                  "model_name": "rules-only", "prompt_convention": PROMPT_CONVENTION,
                  "system_prompt_sha256": SYSTEM_PROMPT_SHA256, "totals": _totals(records),
                  "policies": records, "projection": projection.report,
                  "scope_post_check": scope.summary,
                  "limitations": [] if any(v != NOT_COLLECTED for v in projection.values()) else ["projection_not_implemented"]}
        from azure_tenant_audit.model_assessment import validate_assessment
        validate_assessment(result)
        content = json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    sidecar_text = json.dumps(sidecar, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    resolve_output_directory(target_dir)
    target_dir.mkdir(mode=0o700, exist_ok=True)
    os.chmod(target_dir, 0o700)
    created: list[Path] = []
    try:
        for name, data in ((filename, content), ("scubagear_adapter_report.json", sidecar_text)):
            path = target_dir / name
            created.append(path)
            write_private_text(path, data)
    except OSError:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return result
