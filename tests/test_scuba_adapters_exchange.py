"""Synthetic Exchange adapter checks; no tenant access or network calls."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

from auditex import scuba_adapters_exchange as exchange
from auditex import scuba_projection as projection
from azure_tenant_audit.model_evidence import NOT_COLLECTED

MODULE = 'auditex.scuba_adapters_exchange'
OPERATIONS = {'remote_domains': 'remoteDomains', 'transport_rule': 'transportRules',
              'sharing_policy': 'sharingPolicy'}
ROWS = {
    'remote_domains': [{'DomainName': 'Contoso.COM', 'AutoForwardEnabled': False}],
    'transport_rule': [{'State': 'Enabled', 'Mode': 'Enforce',
                        'FromScope': 'NotInOrganization', 'PrependSubject': '[External]'}],
    'sharing_policy': [{'Name': 'Default', 'Domains': ['contoso.com:CalendarSharingFreeBusySimple']}],
}
FIELDS = {'remote_domains': ('DomainName', 'AutoForwardEnabled'),
          'transport_rule': ('State', 'Mode', 'FromScope', 'PrependSubject'),
          'sharing_policy': ('Name', 'Domains')}
VECTORS = json.loads((Path(__file__).parent / 'fixtures/collect-exchange/adapter-vectors-v39.json').read_text())
# Explicit expectations, rather than deriving rejection from the implementation.
WITHHELD = {
    'MS.EXO.1.1v2': {'bad_unlabelled', 'clear_with_junk_elements',
                    'field_absent_AutoForwardEnabled', 'field_int_AutoForwardEnabled',
                    'field_null_AutoForwardEnabled', 'field_string_AutoForwardEnabled',
                    'section_empty_list', 'section_only_junk'},
    'MS.EXO.6.1v1': {'bad_unlabelled', 'clear_with_junk_elements', 'domains_absent',
                    'domains_null', 'domains_null_element', 'domains_number_element',
                    'domains_object', 'domains_string'},
    'MS.EXO.6.2v1': {'bad_unlabelled', 'clear_with_junk_elements', 'domains_absent',
                    'domains_null', 'domains_null_element', 'domains_number_element',
                    'domains_object', 'domains_string'},
    'MS.EXO.7.1v1': {'none_Mode_null', 'unusable_FromScope_absent',
                    'qualifying_with_junk_elements', 'qualifying_prepend_list'},
}


def write(root, relative, data):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def make_bundle(root, rows=None, *, metadata=None):
    rows = ROWS if rows is None else rows
    write(root, 'run-manifest.json', {'run_id': 't', 'platform': 'm365',
                                     'tenant_id': '11111111-1111-4111-8111-111111111111'})
    write(root, 'raw/exchange_policy.json', {
        OPERATIONS[section]: {'value': value, 'status': 'ok', **(metadata or {})}
        for section, value in rows.items()
    })
    return projection.Bundle(root, 250_000, 256 * 1024 * 1024, 10_000)


def normalise(section, rows):
    result = [{key: deepcopy(row[key]) for key in FIELDS[section]} for row in rows]
    if section == 'remote_domains':
        for row in result:
            row['DomainName'] = row['DomainName'].lower()
    return result


def register_isolated(monkeypatch, *sections):
    # Exercise the permitted hook for non-reserved keys without editing its guard.
    name = 'synthetic_exchange_adapters'
    monkeypatch.setitem(sys.modules, name, SimpleNamespace(
        ADAPTERS={section: exchange.ADAPTERS[section] for section in sections}))
    monkeypatch.setattr(projection, 'AREA_ADAPTER_MODULES', (name,))


def test_registration_projects_all_three_sections(tmp_path):
    make_bundle(tmp_path)
    assert MODULE in projection.AREA_ADAPTER_MODULES
    p = projection.project_run(tmp_path)
    for section, rows in ROWS.items():
        assert p.rule_sections[section] == normalise(section, rows)


def test_without_registration_sections_are_missing(tmp_path, monkeypatch):
    make_bundle(tmp_path)
    monkeypatch.setattr(projection, 'AREA_ADAPTER_MODULES', ())
    p = projection.project_run(tmp_path)
    for section in ROWS:
        assert p.rule_sections[section] == NOT_COLLECTED
        assert p.report['sections'][section]['reason'] == 'missing_artifact'


def test_bad_module_import_propagates(tmp_path, monkeypatch):
    make_bundle(tmp_path)
    monkeypatch.setattr(projection, 'AREA_ADAPTER_MODULES', ('auditex.no_such_exchange_adapter',))
    with pytest.raises(ImportError):
        projection.project_run(tmp_path)


@pytest.mark.parametrize('vector', VECTORS, ids=lambda v: v['vector_id'])
def test_fixture_round_trip(tmp_path, monkeypatch, vector):
    bundle = make_bundle(tmp_path, vector['sections'])
    for section, rows in vector['sections'].items():
        bundle.reset()
        original = deepcopy(rows)
        if vector['family'] in WITHHELD[vector['policy']]:
            with pytest.raises(projection.Unavailable):
                exchange.ADAPTERS[section](bundle)
        else:
            assert exchange.ADAPTERS[section](bundle) == normalise(section, rows)
        assert rows == original
        register_isolated(monkeypatch, section)
        p = projection.project_run(tmp_path)
        expected = (NOT_COLLECTED if vector['family'] in WITHHELD[vector['policy']]
                    else normalise(section, rows))
        assert p.rule_sections[section] == expected


@pytest.mark.parametrize('section,patch', [
    ('transport_rule', {'State': 1}), ('transport_rule', {'Mode': 2}),
    ('sharing_policy', {'Domains': '*:ContactsSharing'}),
    ('sharing_policy', {'Domains': [{'Domain': '*'}]}),
    ('sharing_policy', {'Domains': None}),
])
def test_wrong_types_withhold(tmp_path, section, patch):
    row = {**ROWS[section][0], **patch}
    with pytest.raises(projection.Unavailable) as exc:
        exchange.ADAPTERS[section](make_bundle(tmp_path, {section: [row]}))
    assert exc.value.detail['kind'] == 'invalid_type'


@pytest.mark.parametrize('field', FIELDS['transport_rule'])
def test_missing_transport_field_is_not_null(tmp_path, field):
    row = dict(ROWS['transport_rule'][0])
    del row[field]
    with pytest.raises(projection.Unavailable) as exc:
        exchange.transport_rule(make_bundle(tmp_path, {'transport_rule': [row]}))
    assert exc.value.detail == {'field': field, 'kind': 'missing_field'}


def test_nullable_fields_remain_null(tmp_path):
    row = {**ROWS['transport_rule'][0], 'FromScope': None, 'PrependSubject': None}
    assert exchange.transport_rule(make_bundle(tmp_path, {'transport_rule': [row]})) == [row]


@pytest.mark.parametrize('section', ROWS)
@pytest.mark.parametrize('marker', [
    {'error': 'synthetic error', 'error_class': 'access_denied'},
    {'collection_truncated': True}, {'@odata.nextLink': 'synthetic-next-page'},
])
@pytest.mark.parametrize('location', ['row', 'envelope'])
def test_health_markers_withhold(tmp_path, section, marker, location):
    rows = [{**ROWS[section][0], **marker}] if location == 'row' else ROWS[section]
    bundle = make_bundle(tmp_path, {section: rows}, metadata=marker if location == 'envelope' else None)
    with pytest.raises(projection.Unavailable):
        exchange.ADAPTERS[section](bundle)


@pytest.mark.parametrize('section', ROWS)
def test_missing_operation(tmp_path, section):
    with pytest.raises(projection.Unavailable) as exc:
        exchange.ADAPTERS[section](make_bundle(tmp_path, {}))
    assert exc.value.reason == 'missing_artifact'


@pytest.mark.parametrize('section', ROWS)
def test_empty_collections(tmp_path, section):
    bundle = make_bundle(tmp_path, {section: []})
    if section == 'remote_domains':
        with pytest.raises(projection.Unavailable) as exc:
            exchange.remote_domains(bundle)
        assert exc.value.detail == {'field': '$', 'kind': 'empty_remote_domains'}
    else:
        assert exchange.ADAPTERS[section](bundle) == []
        assert bundle.complete


def test_c2_lower_cases_without_merging_domains(tmp_path):
    rows = [{'DomainName': name, 'AutoForwardEnabled': False}
            for name in ('Contoso.COM', 'contoso.com', '*')]
    assert exchange.remote_domains(make_bundle(tmp_path, {'remote_domains': rows})) == [
        {'DomainName': 'contoso.com', 'AutoForwardEnabled': False},
        {'DomainName': 'contoso.com', 'AutoForwardEnabled': False},
        {'DomainName': '*', 'AutoForwardEnabled': False},
    ]


def test_transport_ignored_fields_record_names_only(tmp_path, monkeypatch):
    row = {**ROWS['transport_rule'][0], 'Name': 'private-name', 'Priority': 10,
           'RedirectMessageTo': ['private@example.invalid'], 'BlindCopyTo': [], 'CopyTo': [],
           'ApplyHtmlDisclaimerText': 'private-disclaimer', 'UnexpectedField': 'private-extra'}
    make_bundle(tmp_path, {'transport_rule': [row]})
    register_isolated(monkeypatch, 'transport_rule')
    p = projection.project_run(tmp_path)
    ignored = p.report['sections']['transport_rule']['ignored_fields']
    assert {'Name', 'Priority', 'RedirectMessageTo', 'ApplyHtmlDisclaimerText', 'UnexpectedField'} <= set(ignored)
    assert 'private-' not in json.dumps(p.report)
    assert p.rule_sections['transport_rule'] == ROWS['transport_rule']


@pytest.mark.parametrize('section', ['remote_domains', 'transport_rule', 'sharing_policy'])
def test_rule_view_survives_model_shape_gate(tmp_path, monkeypatch, section):
    # Product may add digests later; this pins the current model/rule separation.
    make_bundle(tmp_path)
    register_isolated(monkeypatch, section)
    p = projection.project_run(tmp_path)
    assert p[section] == NOT_COLLECTED
    assert p.rule_sections[section] == normalise(section, ROWS[section])
    report = p.report['sections'][section]
    assert report['reason'] == 'incomplete_shape'
    assert report['detail'] == {'field': '$', 'kind': 'unseen_shape'}


def test_sharing_policy_partner_domain_stays_in_rule_view(tmp_path):
    canary = 'private-partner-canary.example.invalid'
    rows = [{'Name': 'Default', 'Domains': [f'{canary}:CalendarSharingFreeBusySimple']}]
    make_bundle(tmp_path, {'sharing_policy': rows})
    p = projection.project_run(tmp_path)
    assert p.rule_sections['sharing_policy'] == rows
    assert canary in p.rule_sections['sharing_policy'][0]['Domains'][0]
    assert canary not in json.dumps(dict(p))
    assert canary not in json.dumps(p.report)
    assert canary not in json.dumps(p.views)


def test_incomplete_empty_collection_withholds_on_run_path(tmp_path, monkeypatch):
    make_bundle(tmp_path, {'transport_rule': []})
    write(tmp_path, 'raw/exchange_policy.json', {'transportRules': {'value': []}})
    register_isolated(monkeypatch, 'transport_rule')
    p = projection.project_run(tmp_path)
    assert p.rule_sections['transport_rule'] == NOT_COLLECTED


def test_registration_does_not_change_other_sections(tmp_path, monkeypatch):
    make_bundle(tmp_path)
    monkeypatch.setattr(projection, 'AREA_ADAPTER_MODULES', ())
    before = projection.project_run(tmp_path)
    register_isolated(monkeypatch, 'remote_domains', 'transport_rule')
    after = projection.project_run(tmp_path)
    for section in before:
        if section not in ROWS:
            assert after[section] == before[section]
            assert after.rule_sections[section] == before.rule_sections[section]
            assert after.report['sections'][section] == before.report['sections'][section]
