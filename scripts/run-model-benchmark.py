#!/usr/bin/env python3
"""Run approved cases sequentially against an owned, offline llama-server.

Requires a local GGUF and a recent native llama.cpp with Jinja, /props,
/apply-template and /tokenize support. No installation or download is performed.
The case's final assistant answer and expected rubric are evaluation-only.
Outputs are private, include unmodified HTTP/model text, and must be new.
Invalid, incomplete and failed answers remain failures in the existing evaluator.
Thinking is explicit: --disable-thinking is the adapter's serving protocol,
--enable-thinking is a control arm (reasoning recorded per case, never scored),
and neither flag leaves the template default.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from auditex.model_eval import _validate_response, evaluate_responses  # noqa: E402
from auditex.model_training import _parse_json, validate_cases  # noqa: E402


MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_HTTP_BYTES = 8 * 1024 * 1024
REQUIRED_FLAGS = (
    "--model", "--alias", "--host", "--port", "--ctx-size", "--parallel",
    "--threads", "--threads-batch", "--n-gpu-layers", "--seed", "--jinja",
    "--no-context-shift", "--offline",
)
# Required only when thinking is on: the think block must come back in
# message.reasoning_content so that only the final answer is JSON-constrained.
THINKING_ON_FLAGS = ("--reasoning-format",)
REASONING_FORMAT = "deepseek"
REASONING_TOKEN_SOURCES = (
    "usage.completion_tokens_details.reasoning_tokens when the server exposes it; otherwise /tokenize of "
    "message.reasoning_content (excludes the think delimiters, so an estimate, not an exact generated-token count). "
    "The /tokenize call is best effort and runs only after the answer is judged: a failure leaves reasoning_tokens "
    "null and never changes the case status or answer; a fatal transport failure there stops the remaining cases."
)
MAX_TOKENS_SCOPE = "whole completion including any reasoning; there is no separate reasoning budget"


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_sha(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _private_open(path: Path):
    # Set permissions at creation, including subprocess logs and interrupted runs.
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8")


def _write_json(path: Path, value) -> None:
    with _private_open(path) as handle:
        handle.write(_json(value) + "\n")


def load_reviewed_cases(paths: list[Path]) -> tuple[list[dict], list[dict]]:
    cases, sources = [], []
    total = 0
    for path in paths:
        if path.stat().st_size > MAX_INPUT_BYTES:
            raise ValueError("cases inputs exceed 64 MiB")
        data = path.read_bytes()
        total += len(data)
        if total > MAX_INPUT_BYTES:
            raise ValueError("cases inputs exceed 64 MiB in total")
        sources.append({"path": str(path.resolve()), "sha256": _sha(data)})
        cases.extend(_parse_json(line) for line in data.decode("utf-8-sig").splitlines() if line.strip())
    cases = validate_cases(cases)  # Validate leakage across all files together.
    if not cases:
        raise ValueError("at least one reviewed case is required")
    if any(case["provenance"]["review_status"] != "approved" for case in cases):
        raise ValueError("all benchmark cases must already be approved by a reviewer; no autoapproval")
    return cases, sources


def _lists_value(help_text: str, flag: str, value: str) -> bool:
    start = help_text.find(flag)
    window = help_text[start:start + 800] if start >= 0 else ""
    return re.search(rf"(?<![\w-]){re.escape(value)}(?![\w-])", window) is not None


def inspect_runtime(executable: str, reasoning_format: str | None = None) -> dict:
    # These runtime overrides can enable downloads, RPC or change protocol settings.
    # Refuse them rather than editing the caller's environment or cache routing.
    if any(key.startswith("LLAMA_ARG_") for key in os.environ):
        raise ValueError("LLAMA_ARG_* overrides are present; use a session without runtime overrides")
    resolved = shutil.which(executable)
    if not resolved:
        raise ValueError(f"missing native llama-server executable: {executable}")
    path = Path(resolved).resolve()
    outputs = {}
    for flag in ("--version", "--help"):
        result = subprocess.run(
            [str(path), flag], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=15, check=False,
        )
        if result.returncode:
            raise ValueError(f"llama-server {flag} failed with exit {result.returncode}")
        outputs[flag] = result.stdout.decode("utf-8", errors="replace")
    required = REQUIRED_FLAGS + (THINKING_ON_FLAGS if reasoning_format else ())
    missing = [flag for flag in required if flag not in outputs["--help"]]
    if missing:
        raise ValueError("llama-server lacks required flags: " + ", ".join(missing))
    if reasoning_format and not _lists_value(outputs["--help"], THINKING_ON_FLAGS[0], reasoning_format):
        raise ValueError(f"llama-server {THINKING_ON_FLAGS[0]} does not list the {reasoning_format!r} value")
    return {"executable": str(path), "executable_sha256": _file_sha(path),
            "version": outputs["--version"], "help_sha256": _sha(outputs["--help"].encode()),
            "reasoning_format": reasoning_format}  # null: flag not passed, server default applies


class CaseFailure(Exception):
    def __init__(self, code: str, detail: str, *, fatal: bool = False):
        super().__init__(detail)
        self.code = code
        self.fatal = fatal


def request_json(port: int, method: str, endpoint: str, payload, timeout: float, trace: list) -> dict:
    """One literal-loopback HTTP request: no proxies, redirects or POST retries."""
    started = time.monotonic()
    record = {"method": method, "endpoint": endpoint, "request": payload, "request_sent": False}
    trace.append(record)
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    expired = threading.Event()
    timer = None
    try:
        if timeout <= 0:
            raise TimeoutError("case wall-clock deadline reached")
        connection.connect()
        sock = connection.sock

        def expire():
            expired.set()
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        # Socket idle timeouts alone do not bound a slowly streaming response.
        timer = threading.Timer(max(0, timeout - (time.monotonic() - started)), expire)
        timer.daemon = True
        timer.start()
        body = None if payload is None else _json(payload).encode("utf-8")
        record["request_sent"] = True
        connection.request(method, endpoint, body=body, headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        record["http_status"] = response.status
        chunks, size = [], 0
        try:
            while size <= MAX_HTTP_BYTES:
                chunk = response.read1(min(65536, MAX_HTTP_BYTES + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
        finally:
            raw = b"".join(chunks)
            try:
                record["response_text"] = raw.decode("utf-8")
            except UnicodeError:
                record["response_text"] = raw.decode("utf-8", errors="replace")
                record["response_bytes_base64"] = base64.b64encode(raw).decode("ascii")
            record["response_sha256"] = _sha(raw)
        if expired.is_set():
            raise TimeoutError("HTTP wall-clock deadline reached")
        if size > MAX_HTTP_BYTES:
            record["response_capture_truncated"] = True
            raise CaseFailure("http_response_too_large", "HTTP response exceeds 8 MiB", fatal=True)
        if response.length not in (None, 0):
            raise CaseFailure("transport_error", "incomplete HTTP body", fatal=True)
        if response.status != 200:
            raise CaseFailure("http_error", f"{endpoint} returned HTTP {response.status}")
        try:
            parsed = _parse_json(raw.decode("utf-8"))
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise CaseFailure("invalid_http_json", str(exc)) from exc
        if not isinstance(parsed, dict):
            raise CaseFailure("invalid_http_json", "HTTP JSON response must be an object")
        return parsed
    except (OSError, http.client.HTTPException) as exc:
        code = "timeout" if expired.is_set() or isinstance(exc, TimeoutError) else "transport_error"
        raise CaseFailure(code, str(exc), fatal=True) from exc
    finally:
        if timer is not None:
            timer.cancel()
        connection.close()
        record["elapsed_seconds"] = time.monotonic() - started


class OwnedServer:
    def __init__(self, args, runtime: dict, output_dir: Path):
        self.args, self.runtime, self.output_dir = args, runtime, output_dir
        self.process = None
        self.log = None
        self.alias = "auditex-local-" + uuid.uuid4().hex
        self.info = {"alias": self.alias, "startup_http": []}

    def start(self) -> None:
        # Reserve a currently unused ephemeral port. The unique alias below also
        # detects another listener winning the close/bind race before any prompt.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.port = reservation.getsockname()[1]
        args = self.args
        command = [
            self.runtime["executable"], "--model", str(args.model.resolve()),
            "--alias", self.alias, "--host", "127.0.0.1", "--port", str(self.port),
            "--ctx-size", str(args.ctx_size), "--parallel", "1",
            "--threads", str(args.threads), "--threads-batch", str(args.threads),
            "--n-gpu-layers", str(args.gpu_layers), "--seed", str(args.seed),
            "--jinja", "--no-context-shift", "--offline",
        ]
        if self.runtime.get("reasoning_format"):
            command += [THINKING_ON_FLAGS[0], self.runtime["reasoning_format"]]
        self.info.update({"command": command, "host": "127.0.0.1", "port": self.port})
        self.log = _private_open(self.output_dir / "server.log")
        self.process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=self.log, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        self.info["pid"] = self.process.pid
        deadline = time.monotonic() + args.startup_timeout
        while time.monotonic() < deadline:
            self.check_alive()
            try:
                health = request_json(self.port, "GET", "/health", None,
                                      min(2, deadline - time.monotonic()), [])
            except CaseFailure:
                time.sleep(min(0.1, max(0, deadline - time.monotonic())))
                continue  # Only readiness GETs are polled; never a POST.
            if health.get("status") == "ok":
                break
        else:
            raise CaseFailure("startup_timeout", "llama-server did not become ready", fatal=True)
        self.check_alive()
        models = request_json(self.port, "GET", "/v1/models", None,
                              deadline - time.monotonic(), self.info["startup_http"])
        model_rows = models.get("data")
        if not isinstance(model_rows, list) or not any(isinstance(row, dict) and row.get("id") == self.alias for row in model_rows):
            raise CaseFailure("server_identity_mismatch", "listener does not advertise the owned process alias", fatal=True)
        self.props = request_json(self.port, "GET", "/props", None,
                                 deadline - time.monotonic(), self.info["startup_http"])
        self.check_alive()
        settings = self.props.get("default_generation_settings", {})
        self.context_size = settings.get("n_ctx") if isinstance(settings, dict) else None
        template = self.props.get("chat_template")
        if type(self.context_size) is not int or not 0 < self.context_size <= args.ctx_size:
            raise CaseFailure("runtime_contract_error", "/props must report a positive per-slot n_ctx", fatal=True)
        if not isinstance(template, str) or not template:
            raise CaseFailure("runtime_contract_error", "/props must report the effective chat_template", fatal=True)
        self.info.update({"props": self.props, "effective_context_size": self.context_size,
                          "chat_template_sha256": _sha(template.encode("utf-8"))})

    def check_alive(self) -> None:
        if self.process is None or self.process.poll() is not None:
            raise CaseFailure("server_exited", "owned llama-server is not running; see server.log", fatal=True)

    def post(self, endpoint: str, payload: dict, timeout: float, trace: list) -> dict:
        self.check_alive()
        return request_json(self.port, "POST", endpoint, payload, timeout, trace)

    def stop(self) -> None:
        # No pkill, process-name matching, service management or process-group kill.
        try:
            if self.process is not None:
                self.info["stop_action"] = "already_exited"
                if self.process.poll() is None:
                    self.info["stop_action"] = "terminate"
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        self.info["stop_action"] = "kill_after_timeout"
                        self.process.kill()
                        self.process.wait(timeout=5)
                self.info["returncode"] = self.process.returncode
        finally:
            if self.log is not None:
                self.log.close()


def thinking_mode(args) -> str:
    if args.enable_thinking:
        return "enabled"
    return "disabled" if args.disable_thinking else "template_default"


def server_reasoning_format(args) -> str | None:
    return REASONING_FORMAT if args.enable_thinking else None


def protocol_settings(args) -> dict:
    settings = {
        "temperature": 0, "seed": args.seed, "top_k": 1, "top_p": 1, "min_p": 0,
        "repeat_penalty": 1, "presence_penalty": 0, "frequency_penalty": 0,
        "max_tokens": args.max_tokens, "n": 1, "stream": False, "cache_prompt": False,
    }
    if args.response_format == "json-object":
        settings["response_format"] = {"type": "json_object"}
    if args.disable_thinking:
        settings["chat_template_kwargs"] = {"enable_thinking": False}
    elif args.enable_thinking:
        settings["chat_template_kwargs"] = {"enable_thinking": True}
    return settings


def reasoning_metrics(reasoning, usage) -> dict:
    """Size of the reasoning channel from data already in hand; no request, never touches the answer."""
    if reasoning is not None and not isinstance(reasoning, str):
        return {"reasoning_present": False, "reasoning_chars": 0, "reasoning_tokens": None,
                "reasoning_tokens_source": "not_a_string"}
    chars = len(reasoning) if reasoning else 0
    metrics = {"reasoning_present": chars > 0, "reasoning_chars": chars}
    if not chars:
        return {**metrics, "reasoning_tokens": 0, "reasoning_tokens_source": "none"}
    details = usage.get("completion_tokens_details") if isinstance(usage, dict) else None
    exposed = details.get("reasoning_tokens") if isinstance(details, dict) else None
    if type(exposed) is int and exposed >= 0:
        return {**metrics, "reasoning_tokens": exposed,
                "reasoning_tokens_source": "usage.completion_tokens_details.reasoning_tokens"}
    # Pending: replaced by count_reasoning_tokens only if its /tokenize request succeeds.
    return {**metrics, "reasoning_tokens": None, "reasoning_tokens_source": "unavailable"}


def count_reasoning_tokens(row: dict, tokenize) -> None:
    """Best effort, after the answer is judged. Only reasoning_* and abort fields may change:
    never the case status, the answer or the recorded response text."""
    try:
        counted = tokenize(row["reasoning_content"])
    except CaseFailure as exc:
        row["reasoning_tokens_error"] = f"{exc.code}: {exc}"
        if exc.fatal:  # Same rule as any transport failure: the server state is uncertain.
            row.update({"abort_remaining": True, "abort_code": exc.code, "abort_detail": str(exc)})
    except KeyboardInterrupt:
        row["reasoning_tokens_error"] = "interrupted while counting reasoning tokens"
        row.update({"abort_remaining": True, "abort_code": "interrupted", "abort_detail": row["reasoning_tokens_error"]})
    else:
        row.update({"reasoning_tokens": counted, "reasoning_tokens_source": "tokenize_reasoning_content_estimate"})


def run_case(case: dict, server: OwnedServer, settings: dict, timeout: float) -> tuple[dict, dict, list]:
    started = time.monotonic()
    messages = case["messages"][:-1]
    request = {**settings, "model": server.alias, "messages": messages}
    row = {"case_id": case["id"], "prompt_sha256": _sha(_json(messages).encode("utf-8")),
           "request_sha256": _sha(_json(request).encode("utf-8")), "started_at": _now(),
           "status": "not_attempted", "usage": None, "timings": None}
    trace, answer, reasoning_to_count = [], None, None
    thinking_on = (settings.get("chat_template_kwargs") or {}).get("enable_thinking") is True

    def post(endpoint, body):
        return server.post(endpoint, body, timeout - (time.monotonic() - started), trace)

    try:
        rendered = post("/apply-template", {**request, "add_generation_prompt": True})
        prompt = rendered.get("prompt")
        if not isinstance(prompt, str) or not prompt:
            raise CaseFailure("template_error", "/apply-template did not return a prompt")
        row["rendered_prompt_sha256"] = _sha(prompt.encode("utf-8"))
        tokenized = post("/tokenize", {"content": prompt, "add_special": True, "parse_special": True})
        tokens = tokenized.get("tokens")
        if not isinstance(tokens, list) or any(type(token) is not int for token in tokens):
            raise CaseFailure("tokenization_error", "/tokenize did not return integer tokens")
        row["prompt_tokens_preflight"] = len(tokens)
        if len(tokens) + settings["max_tokens"] > server.context_size:
            raise CaseFailure("context_limit", "prompt plus reserved completion exceeds per-slot context; no truncation")
        completion = post("/v1/chat/completions", request)
        row["usage"], row["timings"] = completion.get("usage"), completion.get("timings")
        choices = completion.get("choices")
        if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
            raise CaseFailure("completion_schema_error", "expected exactly one completion choice")
        choice = choices[0]
        row["finish_reason"] = choice.get("finish_reason")
        message = choice.get("message")
        if not isinstance(message, dict) or not isinstance(message.get("content"), str):
            raise CaseFailure("completion_schema_error", "completion message content must be a string")
        row["response_text"] = message["content"]
        reasoning = message.get("reasoning_content")
        # Only the thinking-on control arm enforces the type; the other arms record and score it as before.
        if thinking_on and reasoning is not None and not isinstance(reasoning, str):
            raise CaseFailure("completion_schema_error", "completion reasoning_content must be a string when present")
        row["reasoning_content"] = reasoning
        # Recorded before the finish check so a completion that spent its budget reasoning stays visible.
        row.update(reasoning_metrics(reasoning, row["usage"]))
        if row["reasoning_tokens_source"] == "unavailable":
            reasoning_to_count = reasoning
        if row["finish_reason"] != "stop" or completion.get("truncated") is True:
            raise CaseFailure("incomplete_completion", "completion did not finish normally; retained without repair")
        usage = row["usage"]
        if isinstance(usage, dict) and "prompt_tokens" in usage and usage["prompt_tokens"] != len(tokens):
            raise CaseFailure("prompt_token_mismatch", "completion prompt count differs from preflight; inspect template/truncation")
        try:
            answer = _parse_json(message["content"])
            _json(answer)  # Reject exponent overflow (e.g. 1e400) as well as NaN.
        except (ValueError, TypeError, OverflowError, RecursionError) as exc:
            answer = None
            raise CaseFailure("invalid_response_json", str(exc)) from exc
        try:
            _validate_response(answer)
        except (ValueError, TypeError, OverflowError, RecursionError) as exc:
            raise CaseFailure("response_schema_error", str(exc)) from exc
        row["status"] = "completed"
    except CaseFailure as exc:
        row.update({"status": exc.code, "error": str(exc), "abort_remaining": exc.fatal})
    except KeyboardInterrupt:
        row.update({"status": "interrupted", "error": "interrupted during case", "abort_remaining": True})
    if reasoning_to_count is not None and not row.get("abort_remaining"):
        def tokenize_reasoning(content):
            counted = post("/tokenize", {"content": content, "add_special": False, "parse_special": False}).get("tokens")
            if not isinstance(counted, list) or any(type(token) is not int for token in counted):
                raise CaseFailure("tokenization_error", "/tokenize did not return integer tokens for reasoning_content")
            return len(counted)

        count_reasoning_tokens(row, tokenize_reasoning)
    row["elapsed_seconds"] = time.monotonic() - started
    return row, answer, trace


@contextmanager
def _termination_cleanup():
    def interrupt(signum, frame):
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGTERM, interrupt)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


def run_benchmark(args) -> dict:
    output = args.output_dir.absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("output directory must be new")
    if any((parent / "run-manifest.json").exists() for parent in (output.resolve(), *output.resolve().parents)):
        raise ValueError("benchmark output must be outside finalized audit runs")
    cases, sources = load_reviewed_cases(args.cases)
    model = args.model.resolve(strict=True)
    with model.open("rb") as handle:
        if handle.read(4) != b"GGUF":
            raise ValueError("model must be an existing local GGUF file")
    model_hash = _file_sha(model)
    if args.model_sha256 is not None and model_hash != args.model_sha256.lower():
        raise ValueError("model SHA256 does not match the supplied pin")
    runtime = inspect_runtime(args.server, server_reasoning_format(args))
    settings = protocol_settings(args)
    output.mkdir(mode=0o700, parents=True)
    (output / "traces").mkdir(mode=0o700)
    with _private_open(output / "cases.jsonl") as handle:
        handle.writelines(_json(case) + "\n" for case in cases)
    manifest = {
        "schema_version": "2026-10-20", "mode": "local_gguf_benchmark", "status": "running", "started_at": _now(),
        "model": {"model_id": args.model_id, "path": str(model), "sha256": model_hash, "bytes": model.stat().st_size},
        "runtime": runtime, "protocol": settings, "response_format": args.response_format,
        "thinking": {"mode": thinking_mode(args), "chat_template_kwargs": settings.get("chat_template_kwargs"),
                     "reasoning_format": runtime["reasoning_format"], "max_tokens_scope": MAX_TOKENS_SCOPE,
                     "reasoning_tokens": REASONING_TOKEN_SOURCES},
        "case_inputs": sources, "case_order": [case["id"] for case in cases],
        "runner_sha256": _file_sha(Path(__file__)), "python": sys.version,
        "platform": platform.platform(), "machine": platform.machine(),
        "timeouts_seconds": {"startup": args.startup_timeout, "per_case": args.case_timeout, "terminate": 10, "kill": 5},
        "prompt_fingerprint": "sha256(UTF-8 canonical JSON messages[:-1]); sorted keys, compact separators, ensure_ascii=False",
        "label_handling": "expected and final assistant answer stay in cases.jsonl and evaluator only",
        "protocol_notes": [
            "Only the GGUF's embedded Jinja template is used; no Modelfile system prompt is injected.",
            "JSON-object constraint and enable_thinking override, when requested, are explicit protocol settings.",
            "max_tokens bounds the whole completion including any reasoning_content; a completion that spends it "
            "on reasoning ends with finish_reason=length and fails.",
            "Reasoning is recorded per case (reasoning_present, reasoning_chars, reasoning_tokens) and never sent "
            "to the evaluator; only message.content is the answer.",
            "The reasoning /tokenize call runs after the answer is judged and cannot change the case status or answer.",
            "Temperature 0, fixed seed, one slot, sequential calls; cross-build/hardware bit identity is not guaranteed.",
            "No JSON extraction, fence stripping, repair, context truncation, retry or fallback.",
            "Failed/incomplete requests use response:null; details and raw text are retained separately.",
            "Transport failure aborts remaining cases because the server may still be generating.",
            "Approval is supplied provenance; this runner does not grant or independently verify review.",
        ],
    }
    if args.enable_thinking:
        manifest["protocol_notes"].append(
            f"Thinking on is a control arm only: llama-server runs with --reasoning-format {REASONING_FORMAT} so the "
            "think block arrives in reasoning_content; the adapter's serving protocol is thinking off.")
    _write_json(output / "run-start.json", manifest)
    server = OwnedServer(args, runtime, output)
    records, blocked = [], None
    with _termination_cleanup():
        try:
            try:
                server.start()
            except (CaseFailure, OSError, ValueError) as exc:
                blocked = {"code": getattr(exc, "code", "startup_error"), "detail": str(exc)}
            except KeyboardInterrupt:
                blocked = {"code": "interrupted", "detail": "interrupted during startup"}
            if blocked:
                manifest["startup_failure"] = blocked
            with _private_open(output / "responses.jsonl") as answers, _private_open(output / "records.jsonl") as journal:
                for index, case in enumerate(cases):
                    if blocked:
                        row, answer, trace = ({"case_id": case["id"], "status": "not_attempted", "blocked_by": blocked,
                                              "prompt_sha256": _sha(_json(case["messages"][:-1]).encode("utf-8"))}, None, [])
                    else:
                        row, answer, trace = run_case(case, server, settings, args.case_timeout)
                        if row.get("abort_remaining"):
                            blocked = {"code": row.get("abort_code", row["status"]),
                                       "detail": row.get("abort_detail", row.get("error"))}
                    row["trace_file"] = f"traces/{index + 1:06d}.json"
                    _write_json(output / row["trace_file"], trace)
                    answers.write(_json({"case_id": case["id"], "model_id": args.model_id, "response": answer}) + "\n")
                    answers.flush()
                    journal.write(_json(row) + "\n")
                    journal.flush()
                    records.append(row)
        finally:
            server.stop()
    evaluation = evaluate_responses(output / "cases.jsonl", output / "responses.jsonl")
    _write_json(output / "evaluation.json", evaluation)
    manifest.update({
        "finished_at": _now(), "process": server.info, "case_count": len(cases),
        "case_status_counts": dict(Counter(row["status"] for row in records)),
        "status": "completed" if all(row["status"] == "completed" for row in records) else "case_failures",
        "model_scores": evaluation["model_scores"],
    })
    manifest["files"] = {str(path.relative_to(output)): _file_sha(path)
                         for path in sorted(output.rglob("*")) if path.is_file()}
    _write_json(output / "manifest.json", manifest)
    return manifest


def _positive_int(value: str) -> int:
    result = int(value)
    if result < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return result


def _timeout(value: str) -> float:
    result = float(value)
    if not math.isfinite(result) or not 0 < result <= 3600:
        raise argparse.ArgumentTypeError("timeout must be finite and in (0, 3600] seconds")
    return result


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--server", default="llama-server", help="existing native executable, never an endpoint")
    result.add_argument("--check-runtime", action="store_true", help="version/help only; no model loading or output files")
    result.add_argument("--model", type=Path, help="existing single-file GGUF")
    result.add_argument("--model-id", help="label used by the recorded-response evaluator")
    result.add_argument("--model-sha256", help="optional expected GGUF SHA256; measured hash is always recorded")
    result.add_argument("--cases", type=Path, action="append", help="reviewed JSONL; repeat for multiple files")
    result.add_argument("--output-dir", type=Path, help="new private output directory")
    result.add_argument("--ctx-size", type=_positive_int, default=8192)
    result.add_argument("--max-tokens", type=_positive_int, default=2048,
                        help="completion limit; also bounds any reasoning tokens (no separate reasoning budget)")
    result.add_argument("--threads", type=_positive_int, default=6)
    result.add_argument("--gpu-layers", type=int, default=99, help="99 for native GPU offload, 0 for CPU")
    result.add_argument("--seed", type=int, default=42)
    result.add_argument("--response-format", choices=("none", "json-object"), default="json-object",
                        help="recorded generic JSON-object constraint (default); no case-derived schema")
    thinking = result.add_mutually_exclusive_group()
    thinking.add_argument("--disable-thinking", action="store_true",
                          help="explicit enable_thinking=false Jinja protocol setting (the adapter's serving protocol)")
    thinking.add_argument("--enable-thinking", action="store_true",
                          help=f"explicit enable_thinking=true plus --reasoning-format {REASONING_FORMAT}; "
                               "control arm only, reasoning is recorded and never scored")
    result.add_argument("--startup-timeout", type=_timeout, default=180)
    result.add_argument("--case-timeout", type=_timeout, default=300, help="wall-clock budget including template/tokenization")
    return result


def main(argv=None) -> int:
    cli = parser()
    args = cli.parse_args(argv)
    try:
        if args.check_runtime:
            print(_json({"runtime": inspect_runtime(args.server, server_reasoning_format(args)),
                         "inference_executed": False}))
            return 0
        for name in ("model", "model_id", "cases", "output_dir"):
            if not getattr(args, name):
                cli.error("--" + name.replace("_", "-") + " is required")
        if not args.model_id.strip() or not 0 <= args.seed < 2**32 - 1 or args.gpu_layers < 0:
            cli.error("nonempty model-id, fixed uint32 seed (excluding random sentinel), and nonnegative gpu-layers required")
        if args.max_tokens >= args.ctx_size:
            cli.error("max-tokens must be smaller than ctx-size")
        manifest = run_benchmark(args)
        print(_json({"output_dir": str(args.output_dir.absolute()), "status": manifest["status"],
                     "case_status_counts": manifest["case_status_counts"], "model_scores": manifest["model_scores"]}))
        return 0 if manifest["status"] == "completed" else 1
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        print(_json({"error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
