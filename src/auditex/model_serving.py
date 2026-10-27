"""Optional SCuBA model assessment; never feeds or changes deterministic findings."""
from __future__ import annotations

from dataclasses import dataclass, field
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
from time import monotonic
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
from .scuba_projection import project_run

SCHEMA_VERSION = "2026-10-27.1"
PROMPT_CONVENTION = "named-enums-v1"
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024


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
    observed = {section: projection.get(section, dict(NOT_COLLECTED)) for section in entry["sections"]}
    identity = {section: _identity_view(value) if section == "SPO_tenant" else value
                for section, value in observed.items()}
    view_hash = sha256(f"conv3:{canonical(identity)}".encode()).hexdigest()[:10]
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
    """Sanitised transport failure, without response bodies or credentials."""


class ModelClient:
    def __init__(self, config: ModelConfig):
        self.config = config
        self._json_format = True
        self._thinking_disabled = True
        # No proxy environment or redirects may silently move evidence elsewhere.
        self._opener = build_opener(ProxyHandler({}), _NoRedirect())
        if not _is_loopback(config.endpoint_host):
            print(f"Warning: model endpoint {config.endpoint_host} is not loopback; evidence will leave the machine.", file=sys.stderr)

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> bytes:
        headers = {"Accept": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        data = None
        if payload is not None:
            data = canonical(payload).encode()
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
        except (OSError, URLError, HTTPException, ValueError) as exc:
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
                  "prompt_sha256": sha256(canonical(messages).encode()).hexdigest(), "response_sha256": None,
                  "thinking_disabled": self._thinking_disabled, "thinking_stripped": False,
                  "reason": None}
        started = monotonic()
        for _ in range(2):
            payload = {"model": self.config.model_name, "messages": messages, "temperature": 0, "max_tokens": 1024}
            if self._json_format:
                payload["response_format"] = {"type": "json_object"}
            if self._thinking_disabled:
                payload["chat_template_kwargs"] = {"enable_thinking": False}
            try:
                while True:
                    record["attempts"] += 1
                    record["response_sha256"] = None
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
                        raise ModelEndpointError(f"Model endpoint returned HTTP {exc.code}") from None
            except ModelEndpointError:
                record.update(validation_status="unknown", reason="model_endpoint_unavailable")
                break
            try:
                envelope = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_invalid_constant)
                content = envelope["choices"][0]["message"]["content"]
                if not isinstance(content, str):
                    raise ValueError("Missing assistant text")
                content, stripped = re.subn(r"\A\s*<think>.*?</think>\s*", "", content, count=1, flags=re.DOTALL)
                record["thinking_stripped"] = record["thinking_stripped"] or bool(stripped)
                record["response_sha256"] = sha256(content.encode()).hexdigest()
                answer = validate_model_response(content, case)
            except (ValueError, KeyError, IndexError, TypeError, OverflowError, RecursionError):
                record["reason"] = "model_response_invalid"
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


def assess_run(run_dir: str | Path, config: ModelConfig, *, policies: list[str] | None = None,
               dry_run: bool = False) -> dict[str, Any]:
    root = Path(run_dir).expanduser().resolve()
    manifest = json.loads((root / "run-manifest.json").read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("run_id"), str) or not manifest["run_id"]:
        raise ValueError("Run manifest requires a run_id")
    if not dry_run and not config.model_name.strip():
        raise ValueError("AUDITEX_MODEL_NAME or --model is required")
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
    projection = project_run(root)
    baseline = {} if dry_run else _baseline_statuses(root / "reports" / "report-pack.json")
    client = ModelClient(config) if not dry_run else None
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
                                "prompt_sha256": sha256(canonical(messages).encode()).hexdigest(),
                                "prompt_convention": PROMPT_CONVENTION, "system_prompt_sha256": SYSTEM_PROMPT_SHA256})
                continue
            record = client.assess(case)
        record["comparison"] = _comparison(policy_id, record, baseline)
        records.append(record)
    if dry_run:
        write_private_text(target, "".join(canonical(row) + "\n" for row in prompts))
        return {"path": str(target), "dry_run": True, "prompts": sum("messages" in row for row in prompts),
                "skipped": sum(row.get("skipped", False) for row in prompts)}
    totals = {"answered": 0, "unknown": 0, "invalid": 0, "skipped": 0}
    for record in records:
        state = record["validation_status"]
        if state in {"invalid", "skipped"}:
            totals[state] += 1
        elif state == "unknown" or any(c["id"] == "requirement_met" and c["status"] == "unknown" for c in record["claims"]):
            totals["unknown"] += 1
        else:
            totals["answered"] += 1
    result = {"schema_version": SCHEMA_VERSION, "generated_at": generated_at, "run_id": manifest["run_id"],
              "endpoint_host": config.endpoint_host, "model_name": config.model_name,
              "prompt_convention": PROMPT_CONVENTION, "system_prompt_sha256": SYSTEM_PROMPT_SHA256,
              "totals": totals, "policies": records}
    from azure_tenant_audit.model_assessment import validate_assessment
    validate_assessment(result)
    write_private_text(target, json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + "\n")
    return result
