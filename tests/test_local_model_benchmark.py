"""Synthetic protocol/lifecycle tests. No model inference or benchmark results."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import sys
import time

import pytest


# A deliberately small HTTP test double, not a model or inference runtime.
# It reads only its synthetic GGUF-named fixture and incoming localhost requests.
FAKE_SERVER = r'''
import argparse, json, socket, sys, time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
flags = "--model --alias --host --port --ctx-size --parallel --threads --threads-batch --n-gpu-layers --seed --jinja --no-context-shift --offline"
if "--version" in sys.argv:
    print("FAKE LLAMA SERVER FOR TESTS ONLY; NO INFERENCE")
    raise SystemExit(0)
reasoning_help = REASONING_HELP_PLACEHOLDER
if "--help" in sys.argv:
    print(flags)
    print(reasoning_help)
    raise SystemExit(0)
parser = argparse.ArgumentParser()
for flag in flags.split():
    parser.add_argument(flag, **({"action": "store_true"} if flag in ("--jinja", "--no-context-shift", "--offline") else {}))
parser.add_argument("--reasoning-format")
args = parser.parse_args()
config = json.loads(Path(args.model).read_bytes()[4:])
if config.get("exit"):
    raise SystemExit(7)
answer = {"claims": [{"id": "count", "status": "confirmed", "value": 2, "evidence_ids": ["directory"]}],
          "limitations": [], "recommendations": []}
class Handler(BaseHTTPRequestHandler):
    def reply(self, value, status=200, headers=None):
        data = json.dumps(value).encode() if not isinstance(value, bytes) else value
        self.send_response(status)
        self.send_header("Content-Length", str(len(data)))
        for key, val in (headers or {}).items(): self.send_header(key, val)
        self.end_headers()
        self.wfile.write(data)
    def do_GET(self):
        if self.path == "/health":
            self.reply({"status": "loading" if config.get("loading") else "ok"})
        elif self.path == "/v1/models":
            self.reply({"data": [{"id": "unowned-service" if config.get("wrong_alias") else args.alias}]})
        elif self.path == "/props":
            self.reply({"default_generation_settings": {"n_ctx": int(args.ctx_size)},
                        "chat_template": "synthetic-test-template-not-a-model-template"})
        else: self.reply({"error": "unexpected endpoint"}, 404)
    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path == "/apply-template":
            self.reply({"prompt": json.dumps(request["messages"])})
        elif self.path == "/tokenize":
            if request["content"].startswith("TOKENIZE_DROP"):
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            if request["content"].startswith("TOKENIZE_STALL"):
                time.sleep(3)
            if request["content"].startswith("TOKENIZE_FAIL"):
                self.reply({"error": "synthetic tokenizer failure"}, 500)
                return
            count = int(args.ctx_size) if "OVERLONG" in request["content"] else 3
            if not request["content"].startswith("["):  # reasoning text, not a rendered prompt
                count = len(request["content"].split())
            self.reply({"tokens": list(range(count))})
        elif self.path == "/v1/chat/completions":
            text = request["messages"][-1]["content"]
            if "DISCONNECT" in text:
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            if "SLOW" in text:
                self.send_response(200)
                self.send_header("Content-Length", "10000")
                self.end_headers()
                for _ in range(10000):
                    self.wfile.write(b" ")
                    self.wfile.flush()
                    time.sleep(.01)
                return
            if "HTTP_CONTEXT" in text:
                self.reply({"error": {"message": "context limit exceeded"}}, 400)
                return
            if "REDIRECT" in text:
                self.reply({"redirect": True}, 307, {"Location": config["redirect"]})
                return
            if "BAD_HTTP_JSON" in text:
                self.reply(b'not JSON')
                return
            if "BAD_UTF8" in text:
                self.reply(b'\xff')
                return
            content = json.dumps(answer)
            if "BAD_JSON" in text: content = '{"claims":'
            if "FENCED" in text: content = '```json\n' + content + '\n```'
            if "DUPLICATE" in text: content = '{"claims":[],"claims":[],"limitations":[],"recommendations":[]}'
            if "NONFINITE" in text: content = '{"claims":[],"limitations":[],"recommendations":[],"extra":1e400}'
            if "BAD_SCHEMA" in text: content = '{}'
            if "WRONG_VALUE" in text: content = content.replace('"value": 2', '"value": 999')
            finish = "length" if "TRUNCATED" in text else "stop"
            message = {"role": "assistant", "content": content}
            usage = {"prompt_tokens": 4 if "TOKEN_MISMATCH" in text else 3, "completion_tokens": 30, "total_tokens": 33}
            if "REASONING" in text:
                message["reasoning_content"] = "think alpha beta gamma"
            for scenario in ("FAIL", "DROP", "STALL"):
                if f"REASONING_TOKENIZE_{scenario}" in text:
                    message["reasoning_content"] = f"TOKENIZE_{scenario} think"
            if "REASONING_TRUNCATED" in text:
                message["content"], finish = "", "length"
            if "REASONING_USAGE" in text:
                usage["completion_tokens_details"] = {"reasoning_tokens": 17}
            if "REASONING_BAD_TYPE" in text:
                message["reasoning_content"] = 5
            self.reply({"choices": [{"finish_reason": finish, "message": message}], "usage": usage,
                        "timings": {"prompt_ms": 1.25, "predicted_ms": 2.5}})
        else: self.reply({"error": "unexpected endpoint"}, 404)
HTTPServer((args.host, int(args.port)), Handler).serve_forever()
'''


REASONING_HELP = {
    "full": "--reasoning-format FORMAT  one of:\n - none: leaves thoughts unparsed\n"
            " - deepseek: puts thoughts in message.reasoning_content\n - deepseek-legacy: keeps <think> tags",
    "no_flag": "",
    "no_value": "--reasoning-format FORMAT  one of:\n - none: leaves thoughts unparsed\n - deepseek-legacy: keeps <think> tags",
}


def _fake_server(reasoning_help="full"):
    return FAKE_SERVER.replace("REASONING_HELP_PLACEHOLDER", repr(REASONING_HELP[reasoning_help]))


@pytest.fixture
def runner():
    path = Path(__file__).resolve().parents[1] / "scripts/run-model-benchmark.py"
    spec = importlib.util.spec_from_file_location("local_model_benchmark", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _case(case_id="case-a", *, scenario="NORMAL", split="test", approved=True):
    response = {"claims": [{"id": "count", "status": "confirmed", "value": 2, "evidence_ids": ["directory"]}],
                "limitations": [], "recommendations": []}
    return {
        "id": case_id, "family": "family-" + case_id, "split": split,
        "provenance": {"source": "synthetic protocol unit test, not a benchmark", "synthetic": True,
                       "review_status": "approved" if approved else "unreviewed",
                       **({"reviewer": "synthetic test reviewer"} if approved else {})},
        "messages": [{"role": "system", "content": "Return structured JSON."},
                     {"role": "user", "content": f"{scenario} {case_id} [{split}]: directory has count 2."},
                     {"role": "assistant", "content": json.dumps(response)}],
        "expected": {**response, "allowed_evidence_ids": ["directory", "EVALUATION_ONLY_MARKER"]},
    }


def _write_cases(path, cases):
    path.write_text("".join(json.dumps(case) + "\n" for case in cases), encoding="utf-8")
    return path


def _setup(tmp_path, runner, cases=None, config=None, extra=(), reasoning_help="full"):
    executable = tmp_path / "fake-llama-server"
    executable.write_text("#!" + sys.executable + "\n" + _fake_server(reasoning_help), encoding="utf-8")
    executable.chmod(0o700)
    model = tmp_path / "synthetic.gguf"
    model.write_bytes(b"GGUF" + json.dumps(config or {}).encode())
    cases_path = _write_cases(tmp_path / "input.jsonl", cases or [_case()])
    args = runner.parser().parse_args([
        "--server", str(executable), "--model", str(model), "--model-id", "SYNTHETIC_TEST_DOUBLE",
        "--cases", str(cases_path), "--output-dir", str(tmp_path / "output"),
        "--startup-timeout", "3", "--case-timeout", "2", "--ctx-size", "64", "--max-tokens", "32",
        *extra,
    ])
    return args


def _rows(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def _assert_stopped(manifest):
    process = manifest["process"]
    assert process["returncode"] is not None
    with pytest.raises(ProcessLookupError):
        os.kill(process["pid"], 0)  # Existence check only; never send a signal here.
    with socket.socket() as probe:
        probe.settimeout(.2)
        assert probe.connect_ex(("127.0.0.1", process["port"])) != 0


def test_owned_server_local_protocol_private_outputs_and_existing_evaluator(tmp_path, runner):
    cases = [_case("training", split="train"), _case("heldout")]
    args = _setup(tmp_path, runner, [cases[0]], extra=["--response-format", "json-object", "--disable-thinking"])
    second = _write_cases(tmp_path / "second.jsonl", [cases[1]])
    args.cases.append(second)
    original = {path: path.read_bytes() for path in args.cases}
    # An unrelated listener survives the entire owned-subprocess lifecycle.
    with socket.socket() as unrelated:
        unrelated.bind(("127.0.0.1", 0))
        unrelated.listen()
        unrelated_port = unrelated.getsockname()[1]
        manifest = runner.run_benchmark(args)
        assert manifest["process"]["port"] != unrelated_port
        assert unrelated.fileno() >= 0
        with socket.create_connection(("127.0.0.1", unrelated_port), timeout=.2):
            pass
    assert manifest["status"] == "completed"
    assert manifest["case_order"] == [case["id"] for case in cases]
    assert manifest["model"]["sha256"] == hashlib.sha256(args.model.read_bytes()).hexdigest()
    assert "FAKE LLAMA SERVER" in manifest["runtime"]["version"]
    assert manifest["protocol"]["temperature"] == 0
    assert manifest["protocol"]["seed"] == 42
    assert manifest["protocol"]["response_format"] == {"type": "json_object"}
    assert manifest["protocol"]["chat_template_kwargs"] == {"enable_thinking": False}
    assert manifest["model_scores"][0]["mechanical_pass_count"] == 2
    splits = {row["split"]: row for row in manifest["model_scores"][0]["split_scores"]}
    assert splits["train"]["mechanical_pass_count"] == splits["test"]["mechanical_pass_count"] == 1
    for case, record, answer in zip(cases, _rows(args.output_dir / "records.jsonl"), _rows(args.output_dir / "responses.jsonl")):
        assert set(answer) == {"case_id", "model_id", "response"}
        assert record["usage"]["completion_tokens"] == 30
        assert record["timings"]["predicted_ms"] == 2.5
        canonical = json.dumps(case["messages"][:-1], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        assert record["prompt_sha256"] == hashlib.sha256(canonical.encode()).hexdigest()
        trace = json.loads((args.output_dir / record["trace_file"]).read_text())
        assert [entry["endpoint"] for entry in trace] == ["/apply-template", "/tokenize", "/v1/chat/completions"]
        for entry in trace:
            body = entry["request"]
            assert "EVALUATION_ONLY_MARKER" not in json.dumps(body)
            assert "expected" not in body and "provenance" not in body
            if "messages" in body:
                assert body["messages"] == case["messages"][:-1]
        assert trace[-1]["request"]["model"] == manifest["process"]["alias"]
    for path in [args.output_dir, *args.output_dir.rglob("*")]:
        assert path.stat().st_mode & 0o777 == (0o700 if path.is_dir() else 0o600)
    assert {path: path.read_bytes() for path in args.cases} == original
    assert _rows(args.output_dir / "cases.jsonl") == cases
    _assert_stopped(manifest)


def test_invalid_truncated_context_and_wrong_answers_are_not_repaired_or_gold(tmp_path, runner):
    scenarios = {
        "NORMAL": "completed", "BAD_JSON": "invalid_response_json", "FENCED": "invalid_response_json",
        "DUPLICATE": "invalid_response_json", "NONFINITE": "invalid_response_json", "BAD_SCHEMA": "response_schema_error",
        "TRUNCATED": "incomplete_completion", "OVERLONG": "context_limit", "HTTP_CONTEXT": "http_error",
        "BAD_HTTP_JSON": "invalid_http_json", "BAD_UTF8": "invalid_http_json",
        "TOKEN_MISMATCH": "prompt_token_mismatch", "WRONG_VALUE": "completed",
    }
    cases = [_case(name, scenario=name) for name in scenarios]
    args = _setup(tmp_path, runner, cases)
    manifest = runner.run_benchmark(args)
    records = {row["case_id"]: row for row in _rows(args.output_dir / "records.jsonl")}
    assert {key: row["status"] for key, row in records.items()} == scenarios
    responses = {row["case_id"]: row["response"] for row in _rows(args.output_dir / "responses.jsonl")}
    assert responses["TRUNCATED"] is None  # Even complete valid JSON with finish_reason=length fails.
    assert responses["BAD_SCHEMA"] == {}
    assert responses["NONFINITE"] is None
    assert responses["WRONG_VALUE"]["claims"][0]["value"] == 999
    assert records["BAD_JSON"]["response_text"] == '{"claims":'
    assert records["FENCED"]["response_text"].startswith("```json")
    assert manifest["status"] == "case_failures"
    score = manifest["model_scores"][0]
    assert score["response_count"] == len(cases)
    assert score["mechanical_pass_count"] == 1
    assert score["mechanical_fail_count"] == len(cases) - 1
    assert score["missing_case_count"] == 0
    overlong = json.loads((args.output_dir / records["OVERLONG"]["trace_file"]).read_text())
    assert len(overlong) == 2  # No generation request when context is insufficient.
    bad_http = json.loads((args.output_dir / records["BAD_HTTP_JSON"]["trace_file"]).read_text())
    assert bad_http[-1]["response_text"] == "not JSON"
    bad_utf8 = json.loads((args.output_dir / records["BAD_UTF8"]["trace_file"]).read_text())
    assert bad_utf8[-1]["response_bytes_base64"] == "/w=="
    _assert_stopped(manifest)


@pytest.mark.parametrize("scenario", ["SLOW", "DISCONNECT"])
def test_transport_failure_has_no_post_retry_aborts_remaining_and_stops_only_child(tmp_path, runner, scenario):
    args = _setup(tmp_path, runner, [_case(scenario, scenario=scenario), _case("remaining")],
                  extra=["--case-timeout", ".25"])
    started = time.monotonic()
    manifest = runner.run_benchmark(args)
    assert time.monotonic() - started < 3
    rows = _rows(args.output_dir / "records.jsonl")
    assert rows[0]["status"] == ("timeout" if scenario == "SLOW" else "transport_error")
    assert rows[1]["status"] == "not_attempted"
    trace = json.loads((args.output_dir / rows[0]["trace_file"]).read_text())
    assert len([entry for entry in trace if entry["endpoint"] == "/v1/chat/completions"]) == 1
    assert _rows(args.output_dir / "responses.jsonl")[0]["response"] is None
    assert manifest["model_scores"][0]["mechanical_fail_count"] == 2
    _assert_stopped(manifest)


@pytest.mark.parametrize("config,code", [({"exit": True}, "server_exited"),
                                       ({"wrong_alias": True}, "server_identity_mismatch"),
                                       ({"loading": True}, "startup_timeout")])
def test_startup_failure_preserves_all_case_failures_without_sending_prompts(tmp_path, runner, config, code):
    args = _setup(tmp_path, runner, config=config, extra=["--startup-timeout", ".5"])
    manifest = runner.run_benchmark(args)
    assert manifest["startup_failure"]["code"] == code
    row = _rows(args.output_dir / "records.jsonl")[0]
    assert row["status"] == "not_attempted"
    assert json.loads((args.output_dir / row["trace_file"]).read_text()) == []
    assert manifest["model_scores"][0]["mechanical_fail_count"] == 1
    _assert_stopped(manifest)


def test_interruption_is_recorded_and_owned_process_is_reaped(tmp_path, runner, monkeypatch):
    args = _setup(tmp_path, runner, [_case(), _case("later")])
    original = runner.request_json
    original_handler = signal.getsignal(signal.SIGTERM)

    def interrupt(port, method, endpoint, payload, timeout, trace):
        if endpoint == "/v1/chat/completions":
            assert signal.getsignal(signal.SIGTERM) != original_handler
            signal.raise_signal(signal.SIGTERM)
        return original(port, method, endpoint, payload, timeout, trace)

    monkeypatch.setattr(runner, "request_json", interrupt)
    manifest = runner.run_benchmark(args)
    assert [row["status"] for row in _rows(args.output_dir / "records.jsonl")] == ["interrupted", "not_attempted"]
    assert signal.getsignal(signal.SIGTERM) == original_handler
    _assert_stopped(manifest)


def test_local_transport_ignores_proxy_environment_and_never_follows_redirects(tmp_path, runner, monkeypatch):
    with socket.socket() as trap:
        trap.bind(("127.0.0.1", 0))
        trap.listen()
        url = f"http://127.0.0.1:{trap.getsockname()[1]}/should-not-be-called"
        monkeypatch.setenv("HTTP_PROXY", url)
        monkeypatch.setenv("http_proxy", url)
        args = _setup(tmp_path, runner, [_case(scenario="REDIRECT")], config={"redirect": url})
        manifest = runner.run_benchmark(args)
        row = _rows(args.output_dir / "records.jsonl")[0]
        assert row["status"] == "http_error"
        trace = json.loads((args.output_dir / row["trace_file"]).read_text())
        assert trace[-1]["http_status"] == 307
        trap.settimeout(.1)
        with pytest.raises(TimeoutError):
            trap.accept()
    _assert_stopped(manifest)


@pytest.mark.parametrize("problem", ["unreviewed", "family_leakage", "duplicate_id", "existing_output", "hash_mismatch"])
def test_preflight_rejects_bad_inputs_before_any_runtime_command(tmp_path, runner, monkeypatch, problem):
    first, second = _case(), _case("second", split="train")
    if problem == "unreviewed":
        second = _case("second", approved=False)
    elif problem == "family_leakage":
        second["family"] = first["family"]
    elif problem == "duplicate_id":
        second["id"] = first["id"]
    args = _setup(tmp_path, runner, [first])
    args.cases.append(_write_cases(tmp_path / "second.jsonl", [second]))
    if problem == "existing_output":
        args.output_dir.mkdir()
        (args.output_dir / "existing-work").write_text("preserve")
    elif problem == "hash_mismatch":
        args.model_sha256 = "0" * 64

    def forbidden(*_):
        pytest.fail("runtime must not be invoked before input validation")

    monkeypatch.setattr(runner, "inspect_runtime", forbidden)
    with pytest.raises(ValueError):
        runner.run_benchmark(args)
    if problem == "existing_output":
        assert (args.output_dir / "existing-work").read_text() == "preserve"
    else:
        assert not args.output_dir.exists()


def test_fingerprint_and_inference_requests_ignore_changed_labels(runner):
    first, second = _case(), deepcopy(_case())
    second["expected"]["claims"][0]["value"] = "LABEL_ONLY_SECRET"
    second["messages"][-1]["content"] = json.dumps({key: second["expected"][key] for key in ("claims", "limitations", "recommendations")})

    class SyntheticServer:
        alias, context_size = "SYNTHETIC_TEST", 64

        def post(self, endpoint, payload, timeout, trace):
            trace.append({"endpoint": endpoint, "request": payload})
            if endpoint == "/apply-template":
                return {"prompt": json.dumps(payload["messages"])}
            if endpoint == "/tokenize":
                return {"tokens": [1, 2, 3]}
            return {"choices": [{"finish_reason": "stop", "message": {"content": first["messages"][-1]["content"]}}]}

    settings = runner.protocol_settings(runner.parser().parse_args(["--max-tokens", "32"]))
    one, _, first_trace = runner.run_case(first, SyntheticServer(), settings, 2)
    two, _, second_trace = runner.run_case(second, SyntheticServer(), settings, 2)
    assert one["prompt_sha256"] == two["prompt_sha256"]
    assert one["request_sha256"] == two["request_sha256"]
    assert first_trace == second_trace
    assert "LABEL_ONLY_SECRET" not in json.dumps(second_trace)


def test_missing_runtime_and_runtime_overrides_do_not_install_or_fallback(runner, monkeypatch, capsys):
    assert runner.main(["--check-runtime", "--server", "/nonexistent/native/llama-server"]) == 2
    assert "missing native llama-server executable" in capsys.readouterr().err
    monkeypatch.setenv("LLAMA_ARG_MODEL_URL", "https://invalid.example/model.gguf")
    with pytest.raises(ValueError, match="LLAMA_ARG"):
        runner.inspect_runtime("llama-server")


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "3601"])
def test_unbounded_timeouts_are_not_accepted(runner, value):
    with pytest.raises(SystemExit):
        runner.parser().parse_args(["--case-timeout", value])


REASONING_ARM = {
    "on": (["--enable-thinking"], {"enable_thinking": True}, "enabled", "deepseek"),
    "off": (["--disable-thinking"], {"enable_thinking": False}, "disabled", None),
    "default": ([], None, "template_default", None),
}


@pytest.mark.parametrize("arm", list(REASONING_ARM))
def test_thinking_protocol_block_runtime_block_and_server_command(tmp_path, runner, arm):
    flags, kwargs, mode, reasoning_format = REASONING_ARM[arm]
    args = _setup(tmp_path, runner, extra=flags)
    settings = runner.protocol_settings(args)
    assert settings.get("chat_template_kwargs") == kwargs
    assert ("chat_template_kwargs" in settings) == (kwargs is not None)
    manifest = runner.run_benchmark(args)
    assert manifest["status"] == "completed"
    assert manifest["schema_version"] == "2026-10-20"
    assert manifest["protocol"].get("chat_template_kwargs") == kwargs
    assert manifest["thinking"]["mode"] == mode
    assert manifest["thinking"]["chat_template_kwargs"] == kwargs
    assert manifest["thinking"]["reasoning_format"] == manifest["runtime"]["reasoning_format"] == reasoning_format
    # max_tokens is the whole-completion limit, and the manifest says so.
    assert manifest["protocol"]["max_tokens"] == 32
    assert "whole completion including any reasoning" in manifest["thinking"]["max_tokens_scope"]
    assert any("whole completion including any reasoning_content" in note for note in manifest["protocol_notes"])
    assert any("control arm only" in note for note in manifest["protocol_notes"]) == (arm == "on")
    process = manifest["process"]
    # Off and default launch exactly the legacy server command; only thinking on appends the reasoning flag.
    legacy = [manifest["runtime"]["executable"], "--model", str(args.model.resolve()), "--alias", process["alias"],
              "--host", "127.0.0.1", "--port", str(process["port"]), "--ctx-size", "64", "--parallel", "1",
              "--threads", "6", "--threads-batch", "6", "--n-gpu-layers", "99", "--seed", "42",
              "--jinja", "--no-context-shift", "--offline"]
    assert process["command"] == legacy + (["--reasoning-format", "deepseek"] if arm == "on" else [])
    record = _rows(args.output_dir / "records.jsonl")[0]
    trace = json.loads((args.output_dir / record["trace_file"]).read_text())
    assert trace[-1]["request"].get("chat_template_kwargs") == kwargs
    assert trace[-1]["request"]["max_tokens"] == 32
    legacy_keys = {"model", "messages", "temperature", "seed", "top_k", "top_p", "min_p", "repeat_penalty",
                   "presence_penalty", "frequency_penalty", "max_tokens", "n", "stream", "cache_prompt",
                   "response_format"}
    assert set(trace[-1]["request"]) == legacy_keys | ({"chat_template_kwargs"} if kwargs is not None else set())
    assert [entry["endpoint"] for entry in trace] == ["/apply-template", "/tokenize", "/v1/chat/completions"]
    # No reasoning came back: recorded as absent rather than missing.
    assert (record["reasoning_present"], record["reasoning_chars"], record["reasoning_tokens"]) == (False, 0, 0)
    assert record["reasoning_content"] is None
    _assert_stopped(manifest)


def test_enable_and_disable_thinking_are_mutually_exclusive(runner, capsys):
    with pytest.raises(SystemExit) as raised:
        runner.parser().parse_args(["--enable-thinking", "--disable-thinking"])
    assert raised.value.code == 2
    assert "not allowed with argument" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        runner.main(["--check-runtime", "--disable-thinking", "--enable-thinking"])


def _setup_in(tmp_path, runner, name, **kwargs):
    (tmp_path / name).mkdir()
    return _setup(tmp_path / name, runner, **kwargs)


def test_reasoning_flag_is_required_only_when_thinking_is_on(tmp_path, runner, capsys):
    assert "--reasoning-format" not in runner.REQUIRED_FLAGS
    full = _setup_in(tmp_path, runner, "full", reasoning_help="full")
    assert runner.inspect_runtime(full.server)["reasoning_format"] is None
    assert runner.inspect_runtime(full.server, "deepseek")["reasoning_format"] == "deepseek"
    assert runner.main(["--check-runtime", "--server", full.server, "--enable-thinking"]) == 0
    assert '"reasoning_format":"deepseek"' in capsys.readouterr().out

    bare = _setup_in(tmp_path, runner, "bare", reasoning_help="no_flag", extra=["--enable-thinking"])
    assert runner.inspect_runtime(bare.server)["reasoning_format"] is None  # thinking off: not required
    assert runner.main(["--check-runtime", "--server", bare.server]) == 0
    capsys.readouterr()
    with pytest.raises(ValueError, match="lacks required flags: --reasoning-format"):
        runner.inspect_runtime(bare.server, "deepseek")
    assert runner.main(["--check-runtime", "--server", bare.server, "--enable-thinking"]) == 2
    assert "--reasoning-format" in capsys.readouterr().err
    with pytest.raises(ValueError, match="lacks required flags: --reasoning-format"):
        runner.run_benchmark(bare)  # refused after input checks, before any server start
    assert not bare.output_dir.exists()

    novalue = _setup_in(tmp_path, runner, "novalue", reasoning_help="no_value")
    assert runner.inspect_runtime(novalue.server)["reasoning_format"] is None
    with pytest.raises(ValueError, match="does not list the 'deepseek' value"):
        runner.inspect_runtime(novalue.server, "deepseek")  # deepseek-legacy is not deepseek


def test_reasoning_fields_are_recorded_per_case_and_never_scored_or_repaired(tmp_path, runner):
    scenarios = {
        "NORMAL": ("completed", False, 0, "none"),
        "REASONING": ("completed", True, 4, "tokenize_reasoning_content_estimate"),
        "REASONING_USAGE": ("completed", True, 17, "usage.completion_tokens_details.reasoning_tokens"),
        "REASONING_TRUNCATED": ("incomplete_completion", True, 4, "tokenize_reasoning_content_estimate"),
        "REASONING_TOKENIZE_FAIL": ("completed", True, None, "unavailable"),
        "REASONING_BAD_TYPE": ("completion_schema_error", None, None, None),
    }
    cases = [_case(name, scenario=name) for name in scenarios]
    args = _setup(tmp_path, runner, cases, extra=["--enable-thinking"])
    manifest = runner.run_benchmark(args)
    records = {row["case_id"]: row for row in _rows(args.output_dir / "records.jsonl")}
    for name, (status, present, tokens, source) in scenarios.items():
        row = records[name]
        assert row["status"] == status
        if present is None:  # Malformed reasoning_content type: failed before any metrics.
            assert "reasoning_present" not in row
            continue
        assert row["reasoning_present"] is present
        assert row["reasoning_tokens"] == tokens
        assert row["reasoning_tokens_source"] == source
        assert row["reasoning_chars"] == len(row["reasoning_content"] or "")
    assert records["REASONING"]["reasoning_content"] == "think alpha beta gamma"
    assert records["REASONING"]["reasoning_chars"] == len("think alpha beta gamma")
    assert "reasoning_tokens_error" in records["REASONING_TOKENIZE_FAIL"]
    assert not any(row.get("abort_remaining") for row in records.values())
    # A completion that ran out of budget while reasoning stays visible, and the answer is not repaired.
    assert records["REASONING_TRUNCATED"]["response_text"] == ""
    assert records["REASONING_TRUNCATED"]["finish_reason"] == "length"
    trace = json.loads((args.output_dir / records["REASONING"]["trace_file"]).read_text())
    assert [entry["endpoint"] for entry in trace] == ["/apply-template", "/tokenize", "/v1/chat/completions", "/tokenize"]
    assert trace[-1]["request"] == {"content": "think alpha beta gamma", "add_special": False, "parse_special": False}
    # Exposed server counts need no extra /tokenize request.
    usage_trace = json.loads((args.output_dir / records["REASONING_USAGE"]["trace_file"]).read_text())
    assert [entry["endpoint"] for entry in usage_trace][-1] == "/v1/chat/completions"
    # Reasoning stays out of the evaluator inputs; only message.content is the answer.
    for name in ("responses.jsonl", "evaluation.json"):
        assert "think alpha" not in (args.output_dir / name).read_text()
    responses = {row["case_id"]: row["response"] for row in _rows(args.output_dir / "responses.jsonl")}
    assert responses["REASONING"]["claims"][0]["id"] == "count"
    assert responses["REASONING_TRUNCATED"] is None
    assert manifest["model_scores"][0]["mechanical_pass_count"] == 4
    _assert_stopped(manifest)


@pytest.mark.parametrize("arm", [[], ["--enable-thinking"]], ids=["default", "thinking-on"])
@pytest.mark.parametrize("failure", ["DROP", "STALL"])
def test_reasoning_token_count_failure_never_changes_status_or_answer(tmp_path, runner, failure, arm):
    # The default arm matters too: llama.cpp's --reasoning-format auto returns reasoning_content there.
    cases = [_case("counted", scenario=f"REASONING_TOKENIZE_{failure}"), _case("later")]
    args = _setup(tmp_path, runner, cases, extra=[*arm, "--case-timeout", ".5"])
    started = time.monotonic()
    manifest = runner.run_benchmark(args)
    assert time.monotonic() - started < 4
    rows = _rows(args.output_dir / "records.jsonl")
    code = "transport_error" if failure == "DROP" else "timeout"
    # The valid completion keeps its status and its answer; only the token count is lost.
    assert rows[0]["status"] == "completed"
    assert "error" not in rows[0]
    assert rows[0]["response_text"].startswith('{"claims"')
    assert rows[0]["reasoning_present"] is True
    assert rows[0]["reasoning_tokens"] is None
    assert rows[0]["reasoning_tokens_source"] == "unavailable"
    assert rows[0]["reasoning_tokens_error"].startswith(code)
    answer = _rows(args.output_dir / "responses.jsonl")[0]["response"]
    assert answer["claims"][0]["id"] == "count"
    assert manifest["model_scores"][0]["mechanical_pass_count"] == 1
    # The fatal transport failure stops the remaining cases, and says why.
    assert rows[0]["abort_remaining"] is True
    assert rows[1]["status"] == "not_attempted"
    assert rows[1]["blocked_by"]["code"] == code
    assert manifest["case_status_counts"] == {"completed": 1, "not_attempted": 1}
    trace = json.loads((args.output_dir / rows[0]["trace_file"]).read_text())
    assert [entry["endpoint"] for entry in trace] == ["/apply-template", "/tokenize", "/v1/chat/completions", "/tokenize"]
    _assert_stopped(manifest)


@pytest.mark.parametrize("arm,status", [([], "completed"), (["--disable-thinking"], "completed"),
                                        (["--enable-thinking"], "completion_schema_error")],
                         ids=["default", "thinking-off", "thinking-on"])
def test_non_string_reasoning_content_is_enforced_only_when_thinking_is_on(tmp_path, runner, arm, status):
    args = _setup(tmp_path, runner, [_case("bad", scenario="REASONING_BAD_TYPE")], extra=arm)
    runner.run_benchmark(args)
    row = _rows(args.output_dir / "records.jsonl")[0]
    assert row["status"] == status
    if status == "completed":  # As at git HEAD: recorded raw and scored on content alone.
        assert row["reasoning_content"] == 5
        assert (row["reasoning_present"], row["reasoning_chars"], row["reasoning_tokens"]) == (False, 0, None)
        assert row["reasoning_tokens_source"] == "not_a_string"
        assert _rows(args.output_dir / "responses.jsonl")[0]["response"]["claims"][0]["id"] == "count"
    else:
        assert "reasoning_content" not in row
