from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from hashlib import sha256
from http.client import IncompleteRead
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import socket
import threading
import time
from urllib.error import HTTPError

import jsonschema
import pytest

from auditex.cli import main
from auditex.model_eval import validate_model_response
from auditex.model_prompt import SYSTEM_PROMPT, SYSTEM_PROMPT_SHA256
from auditex.model_serving import (
    ModelClient, ModelConfig, PolicyUnavailable, assess_run, build_case,
    canonical, messages_for, policy_catalogue,
)
from auditex.scuba_projection import project_run
from azure_tenant_audit.bundle_integrity import verify_bundle_hashes
from azure_tenant_audit.cli import run_offline
from azure_tenant_audit.contracts import build_validation_report, contract_schema_manifest
from azure_tenant_audit.model_assessment import validate_assessment
from azure_tenant_audit.model_evidence import NOT_COLLECTED
from azure_tenant_audit.resources import shipped_resource_manifest

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = [json.loads(line) for line in (ROOT / "tests/fixtures/model-serving-cases.jsonl").read_text().splitlines()]
POLICY = "MS.AAD.7.3v1"


@pytest.fixture(autouse=True)
def isolate_model_environment(monkeypatch):
    for name in ("ENDPOINT", "NAME", "API_KEY", "TIMEOUT", "ALLOW_INSECURE"):
        monkeypatch.delenv(f"AUDITEX_MODEL_{name}", raising=False)


def fake_projection(root, values):
    projection = project_run(root)
    for key, value in values.items():
        if key in projection:
            previous = projection.report["sections"].get(key, {})
            projection[key] = value
            projection.report["sections"][key] = {
                "status": "projected" if value != NOT_COLLECTED else "not_collected",
                "reason": None if value != NOT_COLLECTED else "incomplete_shape",
                "source": ["raw/synthetic.json"],
            }
            # scuba_config is synthesised, never read: a faked value keeps the real synthesis record (and the
            # per-policy views the readers see) so the entry stays consistent with what the validator requires.
            if key == "scuba_config" and value != NOT_COLLECTED and "synthesis" in previous:
                projection.report["sections"][key]["synthesis"] = previous["synthesis"]
            # A faked section is what every reader sees: drop the per-policy views the real projection kept for it.
            for views in getattr(projection, "views", {}).values():
                views.pop(key, None)
    return projection


def sample_case():
    return json.loads(SAMPLES[0]["messages"][1]["content"])


def sample_answer():
    return json.loads(SAMPLES[0]["messages"][2]["content"])


def missing_answer():
    return {"claims": [
        {"id": "requirement_met", "status": "unknown", "value": None, "evidence_ids": ["e0", "e1"]},
        {"id": "policy_criticality", "status": "confirmed", "value": "Shall", "evidence_ids": ["e0"]},
    ], "limitations": ["required_evidence_section_not_collected"], "recommendations": ["collect_missing_evidence_section"]}


def envelope(answer):
    return canonical({"choices": [{"message": {"content": canonical(answer)}}]}).encode()


@pytest.mark.parametrize("row", SAMPLES, ids=["aad", "sharepoint"])
def test_prompt_is_byte_equal_to_training_sample(row):
    text = row["messages"][1]["content"]
    case = json.loads(text)
    projection = {item["section"]: item["observed"] for item in case["evidence"][1:]}
    saved = deepcopy(projection)
    actual = build_case(case["policy_id"], projection, "2026-10-27")
    actual["case_id"] = case["case_id"]
    assert canonical(actual).encode() == text.encode()
    assert messages_for(actual) == row["messages"][:2]
    assert projection == saved
    assert row["messages"][0]["content"] == SYSTEM_PROMPT
    assert sha256(SYSTEM_PROMPT.encode()).hexdigest() == SYSTEM_PROMPT_SHA256


def test_projection_missing_sections_and_explicit_null_are_distinct(tmp_path):
    assert all(value == NOT_COLLECTED for value in project_run(tmp_path).values())
    case = build_case(POLICY, {}, "2026-10-27")
    assert case["evidence"][1]["observed"] == NOT_COLLECTED
    assert build_case(POLICY, {"privileged_users": None}, "2026-10-27")["evidence"][1]["observed"] is None
    assert set(case) == {"case_id", "evidence", "limitation_ids", "policy_id", "recommendation_ids", "requested_claims"}


def test_named_enums_are_added_without_changing_numbers():
    case = build_case("MS.SHAREPOINT.1.1v1", {"SPO_tenant": [{"SharingCapability": 0}]}, "2026-10-27")
    observed = case["evidence"][1]["observed"][0]
    assert observed == {"SharingCapability": 0, "SharingCapability_name": "disabled (Only people in your organization)"}


def test_catalogue_preserves_all_trained_policy_items():
    data = policy_catalogue()
    assert len(data["policies"]) == 102
    assert all(isinstance(p["policy_item"]["baseline_text"], str) for p in data["policies"].values())
    assert sum("applicability" in p["policy_item"] for p in data["policies"].values()) == 8
    assert data["policies"]["MS.POWERPLATFORM.2.3v1"]["policy_item"]["baseline_text"] == ""
    for pid, entry in data["policies"].items():
        assert build_case(pid, {}, "2026-10-27")["evidence"][0]["observed"] == entry["policy_item"]
    assert data["limitation_ids"] == sample_case()["limitation_ids"]
    assert data["recommendation_ids"] == sample_case()["recommendation_ids"]
    with pytest.raises(PolicyUnavailable, match="policy_not_in_catalogue"):
        build_case("unknown", {}, "2026-10-27")


@pytest.mark.parametrize("mutation", ["extra_claim", "missing_claim", "evidence", "limitation", "recommendation", "unknown_value",
                                      "missing_value", "bool_number", "no_policy_ref", "criticality", "duplicate", "nan"])
def test_serving_validator_reuses_structure_and_checks_request_contract(mutation):
    answer = sample_answer()
    if mutation == "extra_claim":
        answer["claims"].append({"id": "extra", "status": "unknown", "evidence_ids": [], "value": None})
    elif mutation == "missing_claim":
        answer["claims"].pop()
    elif mutation == "evidence":
        answer["claims"][0]["evidence_ids"].append("e999")
    elif mutation == "limitation":
        answer["limitations"] = ["invented"]
    elif mutation == "recommendation":
        answer["recommendations"] = ["invented"]
    elif mutation == "unknown_value":
        answer["claims"][0]["status"] = "unknown"
    elif mutation == "missing_value":
        del answer["claims"][0]["value"]
    elif mutation == "bool_number":
        answer["claims"][0]["value"] = 1
    elif mutation == "no_policy_ref":
        answer["claims"][0]["evidence_ids"] = ["e1"]
    elif mutation == "criticality":
        answer["claims"][1]["value"] = "invented"
    text = canonical(answer)
    if mutation == "duplicate":
        text = text.replace('"limitations":[]', '"limitations":[],"limitations":[]')
    if mutation == "nan":
        text = text.replace('"value":true', '"value":NaN')
    with pytest.raises(ValueError):
        validate_model_response(text, sample_case())


def test_valid_answers_pass_but_p1_cannot_confirm_missing_evidence():
    assert validate_model_response(canonical(sample_answer()), sample_case()) == sample_answer()
    missing = build_case(POLICY, {}, "2026-10-27")
    assert validate_model_response(canonical(missing_answer()), missing) == missing_answer()
    with pytest.raises(ValueError, match="collected evidence"):
        validate_model_response(canonical(sample_answer()), missing)


@contextmanager
def stub_server(actions):
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            calls.append({"method": "GET", "path": self.path, "headers": dict(self.headers)})
            self.reply(200, canonical({"data": [{"id": "test-model"}]}).encode())

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            calls.append({"method": "POST", "path": self.path, "headers": dict(self.headers), "body": body})
            status, response, delay = actions.pop(0)
            if delay:
                time.sleep(delay)
            self.reply(status, response)

        def reply(self, status, body):
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    except PermissionError:
        pytest.skip("Execution sandbox forbids binding a loopback http.server")
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/v1", calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize("scenario", ["success", "invalid_json_retry", "schema_retry", "format_fallback", "timeout"])
def test_client_with_local_http_server(scenario):
    actions = [(200, envelope(sample_answer()), 0)]
    if scenario == "invalid_json_retry":
        actions.insert(0, (200, b"not JSON", 0))
    if scenario == "schema_retry":
        actions.insert(0, (200, envelope({"claims": [], "limitations": [], "recommendations": []}), 0))
    if scenario == "format_fallback":
        actions.insert(0, (400, b'{"error":"unsupported response_format"}', 0))
    if scenario == "timeout":
        actions = [(200, envelope(sample_answer()), 0.1)]
    with stub_server(actions) as (endpoint, calls):
        client = ModelClient(ModelConfig(endpoint, "test-model", "private-key", 0.02 if scenario == "timeout" else 2))
        record = client.assess(sample_case())
        assert record["attempts"] == (2 if scenario in {"invalid_json_retry", "schema_retry", "format_fallback"} else 1)
        assert record["validation_status"] == ("unknown" if scenario == "timeout" else "valid")
        assert calls[0]["path"] == "/v1/chat/completions"
        request = calls[0]["body"]
        assert request["temperature"] == 0 and request["max_tokens"] == 1024
        assert request["response_format"] == {"type": "json_object"}
        assert request["chat_template_kwargs"] == {"enable_thinking": False}
        assert "private-key" not in canonical(request)
        assert calls[0]["headers"]["Authorization"] == "Bearer private-key"
        if scenario == "format_fallback":
            assert "response_format" not in calls[1]["body"]


class FakeOpener:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return io.BytesIO(response)


def client_with_responses(responses):
    client = ModelClient(ModelConfig(model_name="test-model"))
    client._opener = FakeOpener(responses)
    return client


def test_request_retry_and_hashes_without_network():
    client = client_with_responses([b"broken", envelope(sample_answer())])
    record = client.assess(sample_case())
    assert record["validation_status"] == "valid" and record["attempts"] == 2
    assert record["response_sha256"] == sha256(canonical(sample_answer()).encode()).hexdigest()
    assert record["prompt_sha256"] == sha256(canonical(messages_for(sample_case())).encode()).hexdigest()
    assert record["latency_ms"] >= 0


def test_exhausted_validation_never_retains_invalid_answer():
    bad = sample_answer()
    bad["recommendations"] = ["invented"]
    record = client_with_responses([envelope(bad), b"broken"]).assess(sample_case())
    assert record["validation_status"] == "invalid" and record["attempts"] == 2
    assert record["limitations"] == ["model_response_invalid"]
    assert all(c["status"] == "unknown" and c["value"] is None for c in record["claims"])
    assert "invented" not in canonical(record)


def test_http_error_body_timeout_is_sanitised():
    class UnreadableBody(io.BytesIO):
        def read(self, *args):
            raise socket.timeout("private diagnostic")
    error = HTTPError("http://localhost/v1", 400, "private diagnostic", {}, UnreadableBody())
    record = client_with_responses([error]).assess(sample_case())
    assert record["validation_status"] == "unknown"
    assert record["limitations"] == ["model_endpoint_unavailable"]
    assert "private" not in canonical(record)


def test_response_format_fallback_persists_without_using_validation_retry():
    error = HTTPError("http://localhost/v1", 400, "bad request", {}, io.BytesIO(b"unsupported response_format"))
    client = client_with_responses([error, b"broken", envelope(sample_answer()), envelope(sample_answer())])
    first = client.assess(sample_case())
    second = client.assess(sample_case())
    assert first["validation_status"] == second["validation_status"] == "valid"
    assert first["attempts"] == 3 and second["attempts"] == 1
    bodies = [json.loads(req.data) for req, _timeout in client._opener.requests]
    assert "response_format" in bodies[0]
    assert all("response_format" not in body for body in bodies[1:])


@pytest.mark.parametrize("failure", [socket.timeout(), IncompleteRead(b"short", 100),
                                     HTTPError("http://localhost/v1", 400, "private", {}, io.BytesIO(b"unrelated invalid request")),
                                     HTTPError("http://localhost/v1", 401, "private", {}, io.BytesIO(b"private response")),
                                     HTTPError("http://localhost/v1", 302, "redirect", {"Location": "https://elsewhere.invalid"}, io.BytesIO())])
def test_transport_errors_abstain_without_retries_or_leaking_body(failure):
    record = client_with_responses([failure]).assess(sample_case())
    assert record["validation_status"] == "unknown" and record["attempts"] == 1
    assert record["limitations"] == ["model_endpoint_unavailable"]
    assert "private" not in canonical(record)


def test_nonloopback_warns_once_and_secrets_are_not_in_configuration(capsys):
    config = ModelConfig("https://model.example.invalid/v1", "test-model", "private-key")
    client = ModelClient(config)
    client._opener = FakeOpener([envelope(sample_answer()), envelope(sample_answer())])
    client.assess(sample_case())
    client.assess(sample_case())
    err = capsys.readouterr().err
    assert err.count("evidence will leave the machine") == 1
    assert "private-key" not in repr(config) + canonical(config.public_configuration()) + err


@pytest.mark.parametrize("endpoint", ["file:///tmp/data", "http://user:secret@localhost/v1", "http://localhost/v1?key=secret",
                                     "http://localhost/v1#secret", "http://localhost:invalid/v1", "http://localhost/\n"])
def test_unsafe_endpoint_configuration_is_refused_without_echoing_secrets(endpoint):
    with pytest.raises(ValueError) as exc:
        ModelConfig(endpoint=endpoint)
    assert "secret" not in str(exc.value)


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf")])
def test_invalid_timeout_is_refused(timeout):
    with pytest.raises(ValueError, match="timeout"):
        ModelConfig(timeout=timeout)


def test_environment_and_cli_overrides(monkeypatch):
    monkeypatch.setenv("AUDITEX_MODEL_ENDPOINT", "http://localhost:9000/v1")
    monkeypatch.setenv("AUDITEX_MODEL_NAME", "environment-model")
    monkeypatch.setenv("AUDITEX_MODEL_API_KEY", "private-key")
    monkeypatch.setenv("AUDITEX_MODEL_TIMEOUT", "3.5")
    config = ModelConfig.from_environment(endpoint="http://127.0.0.1:8080/v1", model="override")
    assert config.model_name == "override" and config.endpoint == "http://127.0.0.1:8080/v1"
    assert config.timeout == 3.5 and config.api_key == "private-key"


def test_doctor_checks_models_with_real_local_server(capsys):
    with stub_server([]) as (endpoint, calls):
        assert main(["model", "doctor", "--endpoint", endpoint, "--model", "test-model"]) == 0
        assert json.loads(capsys.readouterr().out)["model_present"] is True
        assert main(["model", "doctor", "--endpoint", endpoint, "--model", "missing"]) == 2
        assert calls[0]["method"] == "GET" and calls[0]["path"] == "/v1/models"


@pytest.mark.parametrize("model,reachable,expected", [("test-model", True, 0), ("", True, 2), ("missing", True, 2), ("test-model", False, 2)])
def test_doctor_cli_checks_config_without_exposing_key(monkeypatch, capsys, model, reachable, expected):
    monkeypatch.setenv("AUDITEX_MODEL_API_KEY", "private-key")
    def request(self, method, path, payload=None):
        assert method == "GET" and path == "/models" and payload is None
        if not reachable:
            raise OSError("private-key")
        return b'{"data":[{"id":"test-model"}]}'
    monkeypatch.setattr(ModelClient, "_request", request)
    assert main(["model", "doctor", "--model", model]) == expected
    output = capsys.readouterr()
    assert "private-key" not in output.out + output.err
    assert json.loads(output.out)["ok"] == (expected == 0)


@pytest.fixture
def demo_bundle(tmp_path):
    from auditex.demo import DEMO_AS_OF, DEMO_SAMPLE
    assert run_offline(ROOT / DEMO_SAMPLE, tmp_path, "p1", "demo", plane="full", as_of=DEMO_AS_OF) == 0
    return tmp_path / "p1-demo"


def snapshot(root):
    return {p.relative_to(root).as_posix(): sha256(p.read_bytes()).hexdigest() for p in root.rglob("*") if p.is_file()}


def test_dry_run_cli_on_demo_bundle_is_offline_private_and_preserves_seal(demo_bundle, monkeypatch, capsys):
    def no_network(*args, **kwargs):
        pytest.fail("Dry-run must not call an endpoint")
    monkeypatch.setattr(ModelClient, "_request", no_network)
    before = snapshot(demo_bundle)
    assert main(["model", "assess", str(demo_bundle), "--dry-run"]) == 0
    rows = [json.loads(line) for line in (demo_bundle / "model_assessment_prompts.jsonl").read_text().splitlines()]
    assert len(rows) == 102
    assert sum("messages" in row for row in rows) == 102
    assert sum(row.get("skipped", False) for row in rows) == 0
    projection = project_run(demo_bundle)
    for row in rows:
        case = json.loads(row["messages"][1]["content"])
        assert case == build_case(row["policy_id"], projection, "unused")
    assert (demo_bundle / "model_assessment_prompts.jsonl").stat().st_mode & 0o777 == 0o600
    after = snapshot(demo_bundle)
    assert all(after[path] == digest for path, digest in before.items())
    assert verify_bundle_hashes(demo_bundle)["status"] == "verified"
    assert not (demo_bundle / "model_assessment.json").exists()


def test_assessment_writes_valid_optional_artifact_and_unknown_totals(demo_bundle, monkeypatch):
    def reply(self, method, path, payload):
        case = json.loads(payload["messages"][1]["content"])
        answer = missing_answer()
        answer["claims"][1]["value"] = case["evidence"][0]["observed"]["criticality"]
        return envelope(answer)
    monkeypatch.setattr(ModelClient, "_request", reply)
    before = snapshot(demo_bundle)
    result = assess_run(demo_bundle, ModelConfig(model_name="test-model"))
    assert result["totals"] == {"answered": 0, "unknown": 102, "invalid": 0, "skipped": 0, "rule_answered": 99,
                                "scope_narrowed": 0}
    assert result["limitations"] == []
    assert {name for name, detail in result["projection"]["sections"].items()
            if detail["status"] == "projected"} == {"service_plans", "tenant_id", "privileged_users", "scuba_config"}
    # The three rules that read only the projected privileged users reach the model; the rest are rule answers.
    model_rows = {row["policy_id"] for row in result["policies"] if row["reason"] != "rule_precheck"}
    assert model_rows == {"MS.AAD.7.1v1", "MS.AAD.7.2v1", "MS.AAD.7.3v1"}
    assert all(row["attempts"] == (0 if row["policy_id"] not in model_rows else 1) for row in result["policies"])
    assert result["endpoint_host"] == "127.0.0.1" and result["run_id"] == "demo"
    assert all(row["comparison"]["result"] == "not_assessed" for row in result["policies"])
    validate_assessment(result)
    schema = json.loads((ROOT / "schemas/model_assessment.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(result, schema)
    assert json.loads((demo_bundle / "model_assessment.json").read_text()) == result
    assert (demo_bundle / "model_assessment.json").stat().st_mode & 0o777 == 0o600
    assert all(snapshot(demo_bundle)[path] == digest for path, digest in before.items())
    assert build_validation_report(run_dir=demo_bundle, read_only=True)["valid"] is True
    assert verify_bundle_hashes(demo_bundle)["status"] == "verified"
    result["totals"]["unknown"] = 999
    (demo_bundle / "model_assessment.json").write_text(canonical(result))
    report = build_validation_report(run_dir=demo_bundle, read_only=True)
    assert "invalid_model_assessment" in {issue["code"] for issue in report["issues"]}


@pytest.mark.parametrize("rule_status,value,expected", [("pass", True, "agree"), ("pass", False, "disagree"),
                                                       ("fail", False, "agree"), ("accepted_risk", False, "not_assessed")])
def test_assessment_baseline_comparison(tmp_path, monkeypatch, rule_status, value, expected):
    (tmp_path / "run-manifest.json").write_text('{"run_id":"run"}')
    (tmp_path / "reports").mkdir()
    (tmp_path / "reports/report-pack.json").write_text(canonical({"baseline_alignment": {"frameworks": {
        "cisa_scuba": {"controls": [{"control_id": POLICY, "status": rule_status}]}}}}))
    monkeypatch.setattr("auditex.model_serving.project_run", lambda root, **kwargs: fake_projection(root, {"privileged_users": {}}))
    answer = sample_answer()
    answer["claims"][0]["value"] = value
    answer["recommendations"] = [] if value else ["review_policy_against_baseline_text"]
    monkeypatch.setattr(ModelClient, "_request", lambda *args: envelope(answer))
    result = assess_run(tmp_path, ModelConfig(model_name="test-model"), policies=[POLICY])
    assert result["policies"][0]["comparison"]["result"] == expected
    assert result["totals"]["answered"] == 1


def test_invalid_policy_or_missing_model_fails_before_output(tmp_path, capsys):
    (tmp_path / "run-manifest.json").write_text('{"run_id":"run"}')
    assert main(["model", "assess", str(tmp_path)]) == 2
    assert "required" in capsys.readouterr().err
    assert main(["model", "assess", str(tmp_path), "--dry-run", "--policies", "unknown"]) == 2
    assert not (tmp_path / "model_assessment.json").exists()
    assert not (tmp_path / "model_assessment_prompts.jsonl").exists()


def test_sealed_or_symlink_output_is_refused(tmp_path):
    (tmp_path / "run-manifest.json").write_text('{"run_id":"run"}')
    (tmp_path / "bundle-hashes.json").write_text('{"artifacts":[{"path":"model_assessment.json"}]}')
    with pytest.raises(ValueError, match="sealed"):
        assess_run(tmp_path, ModelConfig(model_name="test-model"))
    target = tmp_path / "model_assessment_prompts.jsonl"
    outside = tmp_path / "outside"
    outside.write_text("untouched")
    target.symlink_to(outside)
    with pytest.raises(ValueError, match="symbolic"):
        assess_run(tmp_path, ModelConfig(), dry_run=True)
    assert outside.read_text() == "untouched"


def test_assessment_resources_are_shipped_and_schema_is_registered():
    resources = shipped_resource_manifest()["resources"]
    assert "configs/scuba-policy-sections.json" in resources
    assert "configs/scuba-rule-precheck.json" in resources
    assert "configs/scuba-scope-blind.json" in resources
    assert "schemas/model_assessment-2026-10-27.1.schema.json" in resources
    assert "schemas/model_assessment-2026-10-28.schema.json" in resources
    assert "schemas/model_assessment.schema.json" in resources
    assert "model_assessment.schema.json" in contract_schema_manifest()["schemas"]


@pytest.mark.parametrize("mutation", ["evidence", "criticality", "policy", "comparison", "nonfinite", "boolean_number"])
def test_optional_artifact_validation_rejects_tampering(tmp_path, monkeypatch, mutation):
    (tmp_path / "run-manifest.json").write_text('{"run_id":"run"}')
    monkeypatch.setattr("auditex.model_serving.project_run", lambda root, **kwargs: fake_projection(root, {"privileged_users": {}}))
    monkeypatch.setattr(ModelClient, "_request", lambda *args: envelope(sample_answer()))
    result = assess_run(tmp_path, ModelConfig(model_name="test-model"), policies=[POLICY])
    row = result["policies"][0]
    if mutation == "evidence":
        row["claims"][0]["evidence_ids"].append("e999")
    elif mutation == "criticality":
        row["claims"][1]["value"] = "May"
    elif mutation == "policy":
        row["policy_id"] = "MS.FAKE.99.99v1"
    elif mutation == "comparison":
        row["comparison"] = {"baseline_status": "pass", "model_status": "fail", "result": "agree"}
    elif mutation == "nonfinite":
        row["latency_ms"] = float("inf")
    elif mutation == "boolean_number":
        row["attempts"] = True
    with pytest.raises(ValueError):
        validate_assessment(result)


def test_assessment_schema_checker_handles_large_json_integer(tmp_path, monkeypatch):
    (tmp_path / "run-manifest.json").write_text('{"run_id":"run"}')
    monkeypatch.setattr(ModelClient, "_request", lambda *args: envelope(missing_answer()))
    # This checks numeric range handling, independently of zero-latency rule provenance.
    monkeypatch.setattr("auditex.model_serving.project_run",
                        lambda root, **kwargs: fake_projection(root, {"privileged_users": {}}))
    result = assess_run(tmp_path, ModelConfig(model_name="test-model"), policies=[POLICY])
    result["policies"][0]["latency_ms"] = 10 ** 400
    validate_assessment(result)  # Finite integers must not overflow a float conversion.


def test_optional_assessment_with_malformed_manifest_reports_issue(demo_bundle, monkeypatch):
    monkeypatch.setattr(ModelClient, "_request", lambda *args: envelope(missing_answer()))
    assess_run(demo_bundle, ModelConfig(model_name="test-model"), policies=["MS.AAD.1.1v1"])
    (demo_bundle / "run-manifest.json").write_text("[]")
    report = build_validation_report(run_dir=demo_bundle, read_only=True)
    assert "invalid_model_assessment" in {issue["code"] for issue in report["issues"]}


def test_v7_prompt_fixture_has_byte_parity_across_all_products():
    path = ROOT / 'tests/fixtures/model-serving-v7.json'
    fixture = json.loads(path.read_text())
    assert path.stat().st_size < 300_000
    assert len(fixture['samples']) >= 50
    assert fixture['system_prompt'] == SYSTEM_PROMPT
    products = set()
    for row in fixture['samples']:
        trained = json.loads(row['content'])
        products.add(trained['policy_id'].split('.')[1])
        projection = {item['section']: item['observed'] for item in trained['evidence'][1:]
                      if item['observed'] != NOT_COLLECTED}
        actual = build_case(trained['policy_id'], projection, '2026-10-27')
        actual['case_id'] = trained['case_id']
        assert messages_for(actual)[1]['content'].encode() == row['content'].encode(), row['source_line']
        validate_model_response(row['answer'], actual)
    assert products == {'AAD', 'EXO', 'SECURITYSUITE', 'SHAREPOINT', 'TEAMS', 'POWERPLATFORM', 'POWERBI'}


def test_generator_and_serving_share_not_collected_marker():
    import runpy
    generator = runpy.run_path(str(ROOT / 'scripts/build-oracle-cases.py'))
    assert generator['NOT_COLLECTED'] is NOT_COLLECTED


@pytest.mark.parametrize('status,value', [('confirmed', True), ('confirmed', False), ('inferred', True), ('inferred', False)])
def test_partial_missing_dependency_prevents_known_verdict(status, value):
    case = build_case('MS.AAD.1.1v1', {}, '2026-10-27')
    assert len(case['evidence']) > 2
    case['evidence'][1]['observed'] = {}
    answer = sample_answer()
    answer['claims'][0].update(status=status, value=value, evidence_ids=[e['id'] for e in case['evidence']])
    answer['claims'][1]['value'] = case['evidence'][0]['observed']['criticality']
    answer['recommendations'] = [] if value else ['review_policy_against_baseline_text']
    with pytest.raises(ValueError, match='collected evidence'):
        validate_model_response(canonical(answer), case)
    answer['claims'][0].update(status='inferred', value=True)
    answer.update(limitations=['policy_not_applicable'], recommendations=[])
    assert validate_model_response(canonical(answer), case) == answer


@pytest.mark.parametrize('status,value,limitations,recommendations', [
    ('confirmed', True, [], ['review_policy_against_baseline_text']),
    ('confirmed', True, ['policy_not_applicable'], []),
    ('confirmed', False, [], []),
    ('confirmed', False, ['policy_not_applicable'], ['review_policy_against_baseline_text']),
    ('inferred', False, ['policy_not_applicable'], []),
    ('inferred', True, ['policy_not_applicable'], ['review_policy_against_baseline_text']),
    ('unknown', None, [], ['collect_missing_evidence_section']),
    ('unknown', None, ['required_evidence_section_not_collected'], []),
    ('unknown', None, ['required_evidence_section_not_collected', 'policy_not_applicable'], ['collect_missing_evidence_section']),
])
def test_contradictory_verdict_codes_are_rejected(status, value, limitations, recommendations):
    answer = sample_answer()
    answer['claims'][0].update(status=status, value=value)
    answer.update(limitations=limitations, recommendations=recommendations)
    with pytest.raises(ValueError, match='contradict'):
        validate_model_response(canonical(answer), sample_case())


def test_thinking_fallback_persists_and_combines_with_format_negotiation():
    def error(field):
        return HTTPError('http://localhost/v1', 400, 'bad request', {}, io.BytesIO(f'unsupported {field}'.encode()))
    client = client_with_responses([error('chat_template_kwargs'), error('response_format'), b'broken',
                                    envelope(sample_answer()), envelope(sample_answer())])
    first = client.assess(sample_case())
    second = client.assess(sample_case())
    assert first['validation_status'] == second['validation_status'] == 'valid'
    assert first['attempts'] == 4 and second['attempts'] == 1
    assert first['thinking_disabled'] is second['thinking_disabled'] is False
    bodies = [json.loads(req.data) for req, _ in client._opener.requests]
    assert bodies[0]['chat_template_kwargs'] == {'enable_thinking': False}
    assert all('chat_template_kwargs' not in body for body in bodies[1:])
    assert all('response_format' not in body for body in bodies[2:])


def test_thinking_block_is_stripped_before_validation_and_hashing():
    content = canonical(sample_answer())
    raw = canonical({'choices': [{'message': {'content': ' \n<think>private\nreasoning</think>\n' + content}}]}).encode()
    result = client_with_responses([raw]).assess(sample_case())
    assert result['validation_status'] == 'valid'
    assert result['thinking_disabled'] is True and result['thinking_stripped'] is True
    assert result['response_sha256'] == sha256(content.encode()).hexdigest()
    assert 'private' not in canonical(result)


@pytest.mark.parametrize('final', [b'broken', socket.timeout(),
    canonical({'choices': [{'message': {'content': None}}]}).encode()])
def test_response_hash_never_retains_an_earlier_attempt_or_envelope(final):
    bad = sample_answer()
    bad['recommendations'] = ['invented']
    result = client_with_responses([envelope(bad), final]).assess(sample_case())
    assert result['response_sha256'] is None


def test_invalid_assistant_text_hashes_final_text():
    text = 'not a JSON answer'
    result = client_with_responses([envelope(sample_answer()),]).assess(sample_case())
    assert result['validation_status'] == 'valid'
    raw = canonical({'choices': [{'message': {'content': text}}]}).encode()
    result = client_with_responses([raw, raw]).assess(sample_case())
    assert result['response_sha256'] == sha256(text.encode()).hexdigest()


@pytest.mark.parametrize('endpoint', ['http://model.example.invalid/v1', 'http://192.0.2.1/v1'])
def test_nonloopback_http_api_key_requires_explicit_override(endpoint, monkeypatch):
    with pytest.raises(ValueError, match='AUDITEX_MODEL_ALLOW_INSECURE=1'):
        ModelConfig(endpoint=endpoint, api_key='private-key')
    monkeypatch.setenv('AUDITEX_MODEL_ALLOW_INSECURE', 'true')
    with pytest.raises(ValueError):
        ModelConfig(endpoint=endpoint, api_key='private-key')
    monkeypatch.setenv('AUDITEX_MODEL_ALLOW_INSECURE', '1')
    assert ModelConfig(endpoint=endpoint, api_key='private-key').endpoint == endpoint


@pytest.mark.parametrize('host', ['127.0.0.1', '[::1]', 'localhost', 'localhost.'])
def test_loopback_http_api_key_is_allowed(host):
    assert ModelConfig(endpoint=f'http://{host}/v1', api_key='private-key').api_key


@pytest.mark.parametrize('pack', [None, [], {}, {'baseline_alignment': None}, {'baseline_alignment': []},
    {'baseline_alignment': {'frameworks': None}},
    {'baseline_alignment': {'frameworks': {'cisa_scuba': {'controls': None}}}},
    {'baseline_alignment': {'frameworks': {'cisa_scuba': {'controls': [None, [], {}, {'control_id': POLICY},
        {'control_id': POLICY, 'status': None}, {'control_id': POLICY, 'status': {}}]}}}}, 'broken JSON'])
def test_malformed_report_pack_does_not_break_assessment(tmp_path, monkeypatch, pack):
    (tmp_path / 'run-manifest.json').write_text('{"run_id":"run"}')
    (tmp_path / 'reports').mkdir()
    (tmp_path / 'reports/report-pack.json').write_text(pack if isinstance(pack, str) else canonical(pack))
    monkeypatch.setattr(ModelClient, '_request', lambda *a: envelope(missing_answer()))
    result = assess_run(tmp_path, ModelConfig(model_name='test-model'), policies=[POLICY])
    assert result['policies'][0]['comparison']['baseline_match'] == 'none'


def test_dry_run_does_not_read_report_pack_and_renders_messages_once(tmp_path, monkeypatch):
    (tmp_path / 'run-manifest.json').write_text('{"run_id":"run"}')
    original = Path.read_text
    def read(path, *args, **kwargs):
        assert path.name != 'report-pack.json'
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'read_text', read)
    calls = []
    def messages(case):
        calls.append(case)
        return messages_for(case)
    monkeypatch.setattr('auditex.model_serving.messages_for', messages)
    assess_run(tmp_path, ModelConfig(), dry_run=True, policies=[POLICY])
    assert len(calls) == 1


@pytest.mark.parametrize('policy_id,baseline_id,match', [
    ('MS.AAD.3.2v2', 'MS.AAD.3.2v1', 'version_mismatch'),
    ('MS.EXO.2.2v3', 'MS.EXO.2.2v2', 'version_mismatch'),
    (POLICY, POLICY, 'exact'), (POLICY, 'MS.AAD.1.1v1', 'none')])
def test_baseline_version_matching(tmp_path, monkeypatch, policy_id, baseline_id, match):
    (tmp_path / 'run-manifest.json').write_text('{"run_id":"run"}')
    (tmp_path / 'reports').mkdir()
    controls = [{'control_id': baseline_id, 'status': 'pass'}]
    (tmp_path / 'reports/report-pack.json').write_text(canonical({'baseline_alignment': {'frameworks': {
        'cisa_scuba': {'controls': controls}}}}))
    monkeypatch.setattr(ModelClient, '_request', lambda *a: envelope(missing_answer()))
    result = assess_run(tmp_path, ModelConfig(model_name='test-model'), policies=[policy_id])
    assert result['policies'][0]['comparison']['baseline_match'] == match


def test_absent_catalogue_policy_is_defensively_skipped(tmp_path, monkeypatch):
    (tmp_path / 'run-manifest.json').write_text('{"run_id":"run"}')
    monkeypatch.setattr(ModelClient, '_request', lambda *a: pytest.fail('Skipped policies must not call a server'))
    result = assess_run(tmp_path, ModelConfig(model_name='test-model'), policies=['MS.UNKNOWN.1.1v1'])
    assert result['totals']['skipped'] == 1
    assert result['policies'][0]['reason'] == 'policy_not_in_catalogue'
    dry = assess_run(tmp_path, ModelConfig(), dry_run=True, policies=['MS.UNKNOWN.1.1v1'])
    assert dry['skipped'] == 1


@pytest.mark.parametrize('mutation', ['future_version', 'bad_version', 'invalid_json'])
def test_malformed_optional_assessment_warns_without_changing_gate(demo_bundle, monkeypatch, mutation):
    from auditex.gate import gate_findings
    before = gate_findings(run_dir=str(demo_bundle), fail_on='critical')
    monkeypatch.setattr(ModelClient, '_request', lambda *a: envelope(missing_answer()))
    result = assess_run(demo_bundle, ModelConfig(model_name='test-model'), policies=[POLICY])
    result['schema_version'] = '2099-01-01' if mutation == 'future_version' else None
    (demo_bundle / 'model_assessment.json').write_text('{' if mutation == 'invalid_json' else canonical(result))
    after = gate_findings(run_dir=str(demo_bundle), fail_on='critical')
    assert after['status'] == before['status'] != 'blocked'
    assert after['pass'] == before['pass']
    report = build_validation_report(run_dir=demo_bundle, read_only=True)
    assert report['valid'] is True
    assert any(i['code'] == 'invalid_model_assessment' and i['severity'] == 'warning' for i in report['issues'])


def test_known_older_optional_assessment_uses_its_recorded_schema(tmp_path, monkeypatch):
    (tmp_path / 'run-manifest.json').write_text('{"run_id":"run"}')
    monkeypatch.setattr(ModelClient, '_request', lambda *a: envelope(missing_answer()))
    # Legacy schema dispatch is checked using an actual model row.
    monkeypatch.setattr('auditex.model_serving.project_run',
                        lambda root, **kwargs: fake_projection(root, {'privileged_users': {}}))
    result = assess_run(tmp_path, ModelConfig(model_name='test-model'), policies=[POLICY])
    result['schema_version'] = '2026-10-27'
    del result['limitations'], result['projection'], result['totals']['rule_answered']
    del result['scope_post_check'], result['totals']['scope_narrowed']
    row = result['policies'][0]
    del row['thinking_disabled'], row['thinking_stripped'], row['comparison']['baseline_match']
    validate_assessment(result)
    row['thinking_disabled'] = True
    with pytest.raises(ValueError, match='Unexpected'):
        validate_assessment(result)
