"""Rules-only assessment contracts, compatibility and network isolation."""
import http.client
import json
import socket
import urllib.request
from pathlib import Path

import jsonschema
import pytest

from auditex import rule_assessment
from auditex.cli import main
from auditex.rule_assessment import assess_run, assess_scubagear_export
from azure_tenant_audit.cli import run_offline
from azure_tenant_audit.scuba_assessment import validate_assessment

ROOT = Path(__file__).resolve().parents[1]
# Every catalogue policy has a value rule today; tests withdraw this one rule to reach the uncovered path.
SYNTHETIC = 'MS.SECURITYSUITE.1.1v1'
TEXT = 'Not assessed: Auditex has no rule for this policy yet.'


@pytest.fixture
def uncovered_policy(monkeypatch):
    from azure_tenant_audit.value_rules import catalogue as rule_catalogue
    original = rule_catalogue.row_for
    monkeypatch.setattr(rule_catalogue, 'row_for',
                        lambda policy_id: None if policy_id == SYNTHETIC else original(policy_id))
    return SYNTHETIC


def uncovered(root):
    (root / 'run-manifest.json').write_text('{"run_id":"synthetic"}')
    return assess_run(root, policies=[SYNTHETIC])


def rules_only(root):
    (root / 'run-manifest.json').write_text('{"run_id":"synthetic"}')
    return assess_run(root, policies=['MS.POWERBI.1.1v1'])


def historical_row(case, answer):
    """A model-answered row as the retired client recorded it (valid answer, one attempt)."""
    from auditex.rule_assessment import _comparison
    row = {'policy_id': case['policy_id'], 'claims': answer['claims'], 'limitations': answer['limitations'],
           'recommendations': answer['recommendations'], 'validation_status': 'valid', 'reason': None,
           'attempts': 1, 'latency_ms': 0.17, 'prompt_sha256': '0' * 64, 'response_sha256': '1' * 64,
           'finish_reason': 'stop', 'thinking_disabled': True, 'thinking_stripped': False}
    row['comparison'] = _comparison(row['policy_id'], row, {})
    return row


def model_row():
    from test_model_serving import sample_answer, sample_case
    return historical_row(sample_case(), sample_answer())


def test_uncovered_contract_and_legacy_rejection(tmp_path, uncovered_policy):
    result = uncovered(tmp_path)
    row = result['policies'][0]
    assert row['reason'] == 'rule_not_implemented' and row['reason_text'] == TEXT
    assert all(c == {'id': c['id'], 'status': 'unknown', 'value': None, 'evidence_ids': []}
               for c in row['claims'])
    assert row['attempts'] == row['latency_ms'] == 0
    assert row['prompt_sha256'] is row['response_sha256'] is None
    assert not row['thinking_disabled'] and not row['thinking_stripped']
    assert row['limitations'] == row['recommendations'] == []
    assert result['totals']['unknown'] == 1 and result['totals']['rule_answered'] == 0
    validate_assessment(result)
    jsonschema.validate(result, json.loads((ROOT / 'schemas/model_assessment.schema.json').read_text()))
    result['schema_version'] = '2026-10-29'
    with pytest.raises(ValueError):
        validate_assessment(result)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(result, json.loads((ROOT / 'schemas/model_assessment-2026-10-29.schema.json').read_text()))


@pytest.mark.parametrize('mutation', [
    'status', 'attempts', 'latency_ms', 'prompt_sha256', 'response_sha256', 'thinking_disabled',
    'thinking_stripped', 'reason_text', 'missing_text', 'limitations', 'recommendations', 'claims',
    'evidence_ids', 'finish_reason', 'rule_precheck', 'model_shadow', 'post_check',
    'endpoint_host', 'model_name', 'serving', 'model_row',
])
def test_uncovered_and_mixed_file_mutations_are_rejected(tmp_path, uncovered_policy, mutation):
    result = uncovered(tmp_path)
    row = result['policies'][0]
    if mutation == 'status':
        row['validation_status'] = 'valid'
    elif mutation == 'missing_text':
        del row['reason_text']
    elif mutation == 'claims':
        row['claims'][0].update(status='confirmed', value=True, evidence_ids=['e0'])
    elif mutation == 'evidence_ids':
        row['claims'][0]['evidence_ids'] = ['e0']
    elif mutation in {'endpoint_host', 'model_name'}:
        result[mutation] = 'localhost' if mutation == 'endpoint_host' else 'historical-model'
    elif mutation == 'serving':
        result['serving'] = {'cache_prompt': 'disabled', 'response_format': 'json_object'}
    elif mutation == 'model_row':
        from auditex.rule_assessment import _totals
        result['policies'].append(model_row())
        result['totals'] = _totals(result['policies'])
    else:
        values = {'attempts': 1, 'latency_ms': 1, 'prompt_sha256': '0'*64, 'response_sha256': '0'*64,
                  'thinking_disabled': True, 'thinking_stripped': True, 'reason_text': 'Other',
                  'limitations': ['model_transport_failed'], 'recommendations': ['collect_missing_evidence_section'],
                  'finish_reason': None, 'rule_precheck': {}, 'model_shadow': {}, 'post_check': {}}
        row[mutation] = values[mutation]
    with pytest.raises(ValueError):
        validate_assessment(result)


def test_rules_only_file_without_uncovered_rows_validates(tmp_path):
    result = rules_only(tmp_path)
    assert result['policies'][0]['reason'] == 'rule_precheck'
    assert (result['endpoint_host'], result['model_name']) == ('none', 'rules-only') and 'serving' not in result
    validate_assessment(result)


@pytest.mark.parametrize('mutation', [
    'endpoint_host', 'model_name', 'serving', 'model_row', 'model_shadow',
    'model_envelope_with_rules_only_name', 'model_envelope_with_no_endpoint',
])
def test_rules_only_envelope_binds_without_uncovered_rows(tmp_path, mutation):
    """The rules-only envelope alone (no rule_not_implemented row) forbids every model trace."""
    from auditex.rule_assessment import _totals
    result = rules_only(tmp_path)
    assert not any(row['reason'] == 'rule_not_implemented' for row in result['policies'])
    if mutation == 'endpoint_host':
        result['endpoint_host'] = 'localhost'
    elif mutation == 'model_name':
        result['model_name'] = 'historical-model'
    elif mutation == 'serving':
        result['serving'] = {'cache_prompt': 'disabled', 'response_format': 'json_object'}
    elif mutation == 'model_row':
        result['policies'].append(model_row())
        result['totals'] = _totals(result['policies'])
    elif mutation == 'model_shadow':
        result['policies'][0]['model_shadow'] = {key: value for key, value in model_row().items()
                                                 if key != 'comparison'}
    else:
        # A model-answered file that names only one half of the rules-only envelope.
        result['policies'] = [model_row()]
        result['totals'] = _totals(result['policies'])
        if mutation == 'model_envelope_with_rules_only_name':
            result['endpoint_host'] = 'localhost'
        else:
            result['model_name'] = 'historical-model'
    with pytest.raises(ValueError, match='Inconsistent rules-only assessment'):
        validate_assessment(result)


def test_current_model_file_with_a_real_endpoint_still_validates(tmp_path):
    """A 2026-11-05 file recorded before the model was parked keeps validating."""
    from auditex.rule_assessment import _totals
    result = rules_only(tmp_path)
    result.update(policies=[model_row()], endpoint_host='localhost', model_name='historical-model',
                  serving={'cache_prompt': 'disabled', 'response_format': 'json_object'})
    result['totals'] = _totals(result['policies'])
    validate_assessment(result)


@pytest.mark.parametrize('policy', ['MS.POWERBI.1.1v1', 'MS.UNKNOWN.1.1v1'])
def test_uncovered_text_is_forbidden_on_other_rows(tmp_path, policy):
    (tmp_path / 'run-manifest.json').write_text('{"run_id":"synthetic"}')
    result = assess_run(tmp_path, policies=[policy])
    result['policies'][0]['reason_text'] = TEXT
    with pytest.raises(ValueError, match='Unexpected uncovered-policy text'):
        validate_assessment(result)


@pytest.mark.parametrize('flags', [
    ['--endpoint', 'private-url'], ['--model', 'private-name'], ['--dry-run'], ['--no-redaction'],
    ['--shadow-model-on-precheck'],
], ids=['endpoint', 'model', 'dry-run', 'no-redaction', 'shadow'])
def test_assess_rejects_retired_model_options_and_writes_nothing(tmp_path, capsys, flags):
    (tmp_path / 'run-manifest.json').write_text('{"run_id":"synthetic"}')
    before = sorted(tmp_path.iterdir())
    with pytest.raises(SystemExit) as exit_info:
        main(['assess', str(tmp_path), *flags])
    assert exit_info.value.code == 2
    assert sorted(tmp_path.iterdir()) == before
    assert 'private' not in capsys.readouterr().err


def test_legacy_environment_keeps_rules(tmp_path, monkeypatch, capsys):
    (tmp_path / 'run-manifest.json').write_text('{"run_id":"synthetic"}')
    baseline = assess_run(tmp_path)
    capsys.readouterr()
    for key in ('ENDPOINT', 'NAME', 'API_KEY', 'TIMEOUT', 'ALLOW_INSECURE'):
        monkeypatch.setenv('AUDITEX_MODEL_' + key, 'private-invalid-value')
    monkeypatch.setenv('AUDITEX_DISABLE_VALUE_RULES', '1')
    assert main(['assess', str(tmp_path)]) == 0
    assert 'private' not in capsys.readouterr().err
    result = json.loads((tmp_path / 'model_assessment.json').read_text())
    assert result['policies'] == baseline['policies']
    assert result['projection']['redaction']['enabled']
    assert all('model_shadow' not in row for row in result['policies'])


@pytest.mark.parametrize('withdrawn', [False, True], ids=['all-rules', 'one-rule-withdrawn'])
def test_no_model_or_network_is_reachable_on_demo_and_mocktenant_exports(tmp_path, monkeypatch, request, withdrawn):
    from auditex.demo import DEMO_AS_OF, DEMO_SAMPLE
    expected = set()
    if withdrawn:
        expected = {request.getfixturevalue('uncovered_policy')}
    def forbidden(*args, **kwargs):
        pytest.fail('Rules-only assessment reached a model client or network')
    monkeypatch.setattr(urllib.request, 'urlopen', forbidden)
    monkeypatch.setattr(urllib.request.OpenerDirector, 'open', forbidden)
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    monkeypatch.setattr(http.client.HTTPConnection, 'connect', forbidden)
    assert run_offline(ROOT / DEMO_SAMPLE, tmp_path, 'synthetic', 'demo', plane='full', as_of=DEMO_AS_OF) == 0
    results = [assess_run(tmp_path / 'synthetic-demo')]
    fixtures = ROOT / 'tests/fixtures/scubagear-export'
    for index, name in enumerate(('mocktenant-provider-export.json', 'mocktenant-realformat-export.json')):
        source = fixtures / name
        for with_results in (False, True):
            results.append(assess_scubagear_export(source, tmp_path / f'export-{index}-{with_results}',
                results_path=fixtures / 'mocktenant-scubaresults.json' if with_results else None))
    for result in results:
        assert result['endpoint_host'] == 'none' and result['model_name'] == 'rules-only' and 'serving' not in result
        assert {row['policy_id'] for row in result['policies'] if row['reason'] == 'rule_not_implemented'} == expected
        assert result['totals']['rule_answered'] == 102 - len(expected)
        assert all(row['attempts'] == 0 and 'model_shadow' not in row for row in result['policies'])
        validate_assessment(result)


@pytest.mark.parametrize('recorded', [('localhost', 'historical-model'), ('none', 'rules-only')],
                         ids=['model-envelope', 'rules-only-envelope'])
@pytest.mark.parametrize('version', ['2026-10-27', '2026-10-27.1', '2026-10-28', '2026-10-29'])
def test_historical_model_records_keep_their_recorded_schema(tmp_path, version, recorded):
    # Legacy files are unchanged: the rules-only envelope check applies to 2026-11-05 only.
    from test_model_serving import sample_answer, sample_case

    from auditex.rule_assessment import _totals
    (tmp_path / 'run-manifest.json').write_text('{"run_id":"historical-synthetic"}')
    case = sample_case()
    result = assess_run(tmp_path, policies=[case['policy_id']])
    row = historical_row(case, sample_answer())
    result.update(schema_version=version, policies=[row], totals=_totals([row]),
                  endpoint_host=recorded[0], model_name=recorded[1])
    result['projection']['redaction']['strategy'] = 'run-salted-sha256-v1'  # what writers of these versions wrote
    filename = 'model_assessment-' + version + '.schema.json'
    schema = json.loads((ROOT / 'schemas' / filename).read_text())
    def resolved(node):
        return schema['$defs'][node['$ref'].split('/')[-1]] if '$ref' in node else node
    def trim(value, definition):
        definition = resolved(definition)
        if isinstance(value, dict) and 'properties' in definition:
            for key in list(value):
                if key not in definition['properties']:
                    del value[key]
                else:
                    trim(value[key], definition['properties'][key])
        elif isinstance(value, list) and 'items' in definition:
            for item in value:
                trim(item, definition['items'])
    trim(result, schema)
    validate_assessment(result)
    jsonschema.validate(result, schema)


def _demo_run(tmp_path):
    from auditex.demo import DEMO_AS_OF, DEMO_SAMPLE
    assert run_offline(ROOT / DEMO_SAMPLE, tmp_path, 'synthetic', 'demo', plane='full', as_of=DEMO_AS_OF) == 0
    return tmp_path / 'synthetic-demo'


def test_assess_command_writes_the_rule_assessment_rows(tmp_path, capsys):
    run = _demo_run(tmp_path)
    assert main(['assess', str(run)]) == 0
    written = json.loads((run / 'model_assessment.json').read_text())
    assert json.loads(capsys.readouterr().out)['policies'] == written['policies']
    direct = assess_run(run)
    assert written['policies'] == direct['policies'] and written['totals'] == direct['totals']
    validate_assessment(written)


def test_assess_command_passes_policies_and_projection_flags(tmp_path, monkeypatch):
    seen = []
    def fake(run_dir, **kwargs):
        seen.append((run_dir, kwargs))
        return {'policies': []}
    monkeypatch.setattr(rule_assessment, 'assess_run', fake)
    (tmp_path / 'run-manifest.json').write_text('{"run_id":"synthetic"}')
    assert main(['assess', str(tmp_path), '--policies', 'MS.AAD.1.1v1, MS.EXO.4.1v1',
                 '--projection-max-items', '7', '--projection-max-chars', '800',
                 '--projection-scan-max-rows', '11', '--projection-scan-max-bytes', '1234',
                 '--projection-scan-max-chunks', '5']) == 0
    assert main(['assess', str(tmp_path)]) == 0
    assert seen == [
        (str(tmp_path), {'policies': ['MS.AAD.1.1v1', 'MS.EXO.4.1v1'], 'projection_max_items': 7,
                         'projection_max_chars': 800, 'projection_scan_max_rows': 11,
                         'projection_scan_max_bytes': 1234, 'projection_scan_max_chunks': 5}),
        (str(tmp_path), {'policies': None, 'projection_max_items': 40, 'projection_max_chars': 12000,
                         'projection_scan_max_rows': 250000, 'projection_scan_max_bytes': 268435456,
                         'projection_scan_max_chunks': 10000}),
    ]


def test_assess_failure_is_reported_on_stderr_with_exit_2(tmp_path, capsys):
    (tmp_path / 'run-manifest.json').write_text('{"run_id":"synthetic"}')
    assert main(['assess', str(tmp_path), '--policies', 'MS.NOT.A.POLICY']) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith('Assessment failed: ') and captured.out == ''
    assert not (tmp_path / 'model_assessment.json').exists()
    assert main(['assess', str(tmp_path / 'missing-run')]) == 2
    assert capsys.readouterr().out == ''


def test_assess_and_assessment_dispatch_separately(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(rule_assessment, 'assess_run',
                        lambda *a, **k: pytest.fail('auditex assessment reached the rule assessment'))
    assert main(['assessment', 'sources']) == 0
    assert 'scubagear' in capsys.readouterr().out
    with pytest.raises(SystemExit) as exit_info:
        main(['assess', 'sources', 'extra'])
    assert exit_info.value.code == 2


@pytest.mark.parametrize('argv', [['model'], ['model', 'assess', '{run}'], ['model', 'sources']])
def test_model_command_is_unknown(tmp_path, argv, capsys):
    (tmp_path / 'run-manifest.json').write_text('{"run_id":"synthetic"}')
    with pytest.raises(SystemExit) as exit_info:
        main([arg.format(run=tmp_path) for arg in argv])
    assert exit_info.value.code == 2
    assert 'invalid arguments' in capsys.readouterr().err
    assert not (tmp_path / 'model_assessment.json').exists()
