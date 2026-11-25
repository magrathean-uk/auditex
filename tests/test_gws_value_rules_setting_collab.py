"""Collaboration setting rows: synthetic inputs and literal verdicts."""
import copy
import json
from pathlib import Path

import pytest

from azure_tenant_audit.value_rules import gws
from azure_tenant_audit.value_rules.gws.catalogue import catalogue

VECTORS = [json.loads(line) for line in (Path(__file__).parent / 'fixtures/gws-value-rules/setting-collab.jsonl')
           .read_text().splitlines()]
GOOD = [v for v in VECTORS if v['verdict'] == 'met']


def answer(v, sections):
    result = gws.assess(v['policy'], sections)
    return result['verdict'], result['cell']


@pytest.mark.parametrize('vector', GOOD, ids=lambda v: v['policy'])
def test_each_row_rejects_missing_incomplete_and_unusable_inputs(vector):
    sections = copy.deepcopy(vector['sections'])
    missing = copy.deepcopy(sections)
    del missing['gws_policies']
    assert answer(vector, missing) == ('not_assessed', 'section_not_collected')
    partial = copy.deepcopy(sections)
    partial['gws_policies']['complete'] = False
    assert answer(vector, partial) == ('not_assessed', 'policy_read_incomplete')
    for invalid in (None, '', [], {}, 1):
        malformed = copy.deepcopy(sections)
        field = next(iter(malformed['gws_policies']['policies'][-1]['value']))
        malformed['gws_policies']['policies'][-1]['value'][field] = invalid
        assert answer(vector, malformed) == ('not_assessed', 'setting_value_unusable')
    for unit in ('', None, 'ou:', 'bad'):
        malformed = copy.deepcopy(sections)
        malformed['gws_policies']['policies'][-1]['unit'] = unit
        assert answer(vector, malformed)[0] == 'not_assessed'


@pytest.mark.parametrize('vector', GOOD, ids=lambda v: v['policy'])
def test_each_gated_row_checks_service_state(vector):
    row = catalogue()['policies'][vector['policy']]
    if row['params']['service'] is None:
        return
    for state in (None, '', 'UNKNOWN', [], 1):
        sections = copy.deepcopy(vector['sections'])
        sections['gws_policies']['policies'][0]['value']['serviceState'] = state
        assert answer(vector, sections)[0] == 'not_assessed'
    sections = copy.deepcopy(vector['sections'])
    sections['gws_policies']['policies'][0]['value']['serviceState'] = 'DISABLED'
    assert answer(vector, sections) == ('not_applicable', 'service_off_everywhere')


def test_drive_default_is_a_violation():
    vector = next(v for v in GOOD if v['policy'] == 'GWS.DRIVEDOCS.1.8v1')
    sections = copy.deepcopy(vector['sections'])
    sections['gws_policies']['policies'].pop()
    assert answer(vector, sections) == ('not_met', 'unit_violates')


def test_sites_only_checks_explicit_states():
    vector = next(v for v in GOOD if v['policy'] == 'GWS.SITES.1.1v1')
    sections = copy.deepcopy(vector['sections'])
    sections['gws_policies']['policies'].clear()
    assert answer(vector, sections)[0] == 'not_assessed'


@pytest.mark.parametrize('policy', [
    'GWS.DRIVEDOCS.1.9v1', 'GWS.DRIVEDOCS.2.1v1', 'GWS.DRIVEDOCS.2.2v1', 'GWS.CALENDAR.4.1v1',
    'GWS.CHAT.2.1v1', 'GWS.CHAT.3.1v1', 'GWS.MEET.1.1v1', 'GWS.MEET.2.1v1', 'GWS.MEET.3.1v1',
    'GWS.MEET.4.1v1', 'GWS.MEET.5.1v1', 'GWS.MEET.5.2v1', 'GWS.CLASSROOM.1.1v1', 'GWS.CLASSROOM.1.2v1',
    'GWS.CLASSROOM.2.1v1', 'GWS.CLASSROOM.3.1v1', 'GWS.CLASSROOM.4.1v1', 'GWS.CLASSROOM.5.1v1',
])
def test_absent_setting_without_default_is_not_assessed(policy):
    vector = next(v for v in GOOD if v['policy'] == policy)
    sections = copy.deepcopy(vector['sections'])
    sections['gws_policies']['policies'].pop()
    assert answer(vector, sections) == ('not_assessed', 'setting_absent')


@pytest.mark.parametrize('vector', GOOD, ids=lambda v: v['policy'])
def test_each_row_rejects_an_unknown_enum_and_checks_group_values(vector):
    row = catalogue()['policies'][vector['policy']]
    params = row['params']
    if 'known' in params:
        sections = copy.deepcopy(vector['sections'])
        sections['gws_policies']['policies'][-1]['value'][params['field']] = 'NOT_A_VALID_VALUE'
        assert answer(vector, sections) == ('not_assessed', 'setting_value_unusable')
        assert params.get('case', 'exact') == 'exact'
    bad = next(v for v in VECTORS if v['policy'] == vector['policy'] and v['verdict'] == 'not_met')
    sections = copy.deepcopy(vector['sections'])
    group = copy.deepcopy(bad['sections']['gws_policies']['policies'][-1])
    group['unit'] = 'ou:root/group:g1'
    group['unit_kind'] = 'group'
    sections['gws_policies']['policies'].append(group)
    assert answer(vector, sections) == ('not_met', 'unit_violates')
