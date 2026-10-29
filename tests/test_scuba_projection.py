"""Projection contract tests use synthetic evidence only; no tenant or web calls."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import socket

import jsonschema
import pytest

from auditex.cli import main
from auditex.model_precheck import precheck_case
from auditex.model_serving import ModelClient, ModelConfig, assess_run, canonical
from auditex.scuba_projection import project_run
from azure_tenant_audit.model_assessment import validate_assessment
from azure_tenant_audit.model_evidence import NOT_COLLECTED

ROOT = Path(__file__).resolve().parents[1]
TENANT = '11111111-1111-4111-8111-111111111111'
PERSON = 'Synthetic Person'
EMAIL = 'sensitive.local@example.invalid'
CA = {'Conditions': {'Applications': {'ExcludeApplications': [], 'IncludeApplications': ['All'], 'IncludeUserActions': ['urn:user:registersecurityinfo']}, 'AuthenticationFlows': {'TransferMethods': None}, 'ClientAppTypes': ['other', 'exchangeActiveSync'], 'SignInRiskLevels': ['high'], 'UserRiskLevels': ['high'], 'Users': {'ExcludeGroups': [], 'ExcludeGuestsOrExternalUsers': None, 'ExcludeRoles': [], 'ExcludeUsers': ['sensitive.local@example.invalid'], 'IncludeRoles': ['Role1', 'Role2'], 'IncludeUsers': ['All']}}, 'DisplayName': 'Require MFA', 'GrantControls': {'AuthenticationStrength': {'AllowedCombinations': ['windowsHelloForBusiness', 'fido2', 'x509CertificateMultiFactor']}, 'BuiltInControls': ['block'], 'Operator': None}, 'State': 'enabled'}
SPO = {
    'SharingCapability': 2, 'ODBSharingCapability': 3, 'DefaultLinkPermission': 1,
    'DefaultSharingLinkType': 1, 'FileAnonymousLinkType': 1, 'FolderAnonymousLinkType': 1,
    'SharingDomainRestrictionMode': 1, 'RequireAnonymousLinksExpireInDays': -1,
    'EmailAttestationRequired': True, 'EmailAttestationReAuthDays': 30,
}
AUTH = {'Id': 'authorizationPolicy', 'AllowInvitesFrom': 'adminsAndGuestInviters',
        'GuestUserRoleId': TENANT, 'DefaultUserRolePermissions': {'AllowedToCreateApps': False},
        'PermissionGrantPolicyIdsAssignedToDefaultUserRole': ['ManagePermissionGrantsForSelf.test']}
ROLES = [{'Assignments': [{'EndDateTime': '/Date(1691006065170)/', 'PrincipalId': 'ae71e61c-f465-4db6-8d26-5f3e52bdd800', 'StartDateTime': '/Date(1660328610000)/'}], 'DisplayName': 'Global Administrator', 'RoleTemplateId': 'Role1', 'Rules': [{'Id': 'Expiration_Admin_Assignment', 'IsExpirationRequired': True, 'MaximumDuration': 'P30D', 'NotificationRecipients': ['test@example.com'], 'NotificationType': 'Email', 'RuleSource': 'Global Administrator', 'RuleSourceType': 'Directory Role', 'Setting': {'IsApprovalRequired': True}}, {'Id': 'Notification_Admin_Admin_Eligibility', 'NotificationRecipients': ['test@example.com'], 'NotificationType': 'Email', 'RuleSource': 'Global Administrator', 'RuleSourceType': 'Directory Role'}]}, {'Assignments': [{'EndDateTime': '/Date(1691006065170)/', 'PrincipalId': 'e54ac846-1f5a-4afe-aa69-273b42c3b0c1'}], 'DisplayName': 'Privileged Role Administrator', 'RoleTemplateId': 'Role2', 'Rules': [{'Id': 'Expiration_Admin_Assignment', 'IsExpirationRequired': True, 'MaximumDuration': 'P30D', 'NotificationRecipients': ['test@example.com'], 'RuleSource': 'Global Administrator', 'RuleSourceType': 'Directory Role', 'Setting': {'IsApprovalRequired': True}}]}]
ROLE = ROLES[0]
PS = {
    'accepted_domains': ('exchange_policy', 'acceptedDomains', {'Name': 'Example', 'DomainName': 'example.invalid'}),
    'dkim_config': ('exchange_policy', 'dkimSigningConfig', {'Domain': 'example.invalid', 'Enabled': True}),
    'transport_config': ('exchange_policy', 'transportConfig', {'Name': 'Transport', 'SmtpClientAuthenticationDisabled': True}),
    'org_config': ('exchange_policy', 'organizationAuditConfig', {'Identity': 'Tenant', 'Name': 'Example', 'AuditDisabled': False}),
    'meeting_policies': ('teams_policy', 'meetingPolicies', {
        'Identity': 'Global', 'AllowAnonymousUsersToStartMeeting': False, 'AllowCloudRecording': False,
        'AllowExternalParticipantGiveRequestControl': False, 'AllowPSTNUsersToBypassLobby': False,
        'AutoAdmittedUsers': 'EveryoneInCompany'}),
}
EXPECTED = {
    'SPO_tenant': [SPO], 'conditional_access_policies': [CA], 'authorization_policies': [AUTH],
    'service_plans': [{'ServicePlanId': TENANT, 'ServicePlanName': 'AAD_PREMIUM_P2'}],
    'privileged_users': {'User1': {'DisplayName': PERSON, 'OnPremisesImmutableId': None, 'roles': ['Global Administrator']}},
    'privileged_roles': ROLES, 'tenant_id': TENANT,
    **{k: [v[2]] for k, v in PS.items()},
    **{k: ([{'domain': 'example.invalid', 'compliant': True, 'message': 'SPF record found.'}] if k == 'spf_records' else [{'domain': 'example.invalid', 'rdata': ['v=TEST;']}])
       for k in ('dmarc_records', 'spf_records', 'dkim_records')},
}


def write(root, path, payload):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload) + '\n')


def graph(value):
    if isinstance(value, dict):
        return {k[0].lower() + k[1:]: graph(v) for k, v in value.items()}
    if isinstance(value, list):
        return [graph(v) for v in value]
    return value


def operation(root, collector, name, rows, **metadata):
    path = root / f'raw/{collector}.json'
    payload = json.loads(path.read_text()) if path.exists() else {}
    payload[name] = {'value': rows, 'status': 'ok', **metadata}
    write(root, f'raw/{collector}.json', payload)


@pytest.fixture
def complete_bundle(tmp_path):
    write(tmp_path, 'run-manifest.json', {'run_id': 'synthetic-run', 'platform': 'm365',
                                        'tenant_id': TENANT, 'graph_endpoint': 'https://graph.microsoft.com/v1.0'})
    operation(tmp_path, 'identity', 'organization', [{'id': TENANT}])
    operation(tmp_path, 'identity', 'users', [{'id': TENANT, 'displayName': PERSON, 'onPremisesImmutableId': None}])
    write(tmp_path, 'normalized/effective_admin_set.json', {'records': [
        {'kind': 'effective_admin_set_summary', 'state': 'complete', 'unresolved_principal_count': 0, 'admin_count': 1},
        {'kind': 'effective_admin', 'state': 'complete', 'is_user': True, 'principal_id': TENANT,
         'role_names': ['Global Administrator']}]})
    write(tmp_path, 'normalized/sharepoint_tenant_settings.json', {'records': [{
        'read_state': 'collected', 'sharing_capability': 'externalUserAndGuestSharing',
        'onedrive_sharing_capability': 'existingExternalUserSharingOnly'}]})
    operation(tmp_path, 'sharepoint_access', 'sharePointSettings', [SPO])
    operation(tmp_path, 'conditional_access', 'conditionalAccessPolicies', [graph(CA)])
    auth = graph(AUTH)
    assigned = auth.pop('permissionGrantPolicyIdsAssignedToDefaultUserRole')
    auth['defaultUserRolePermissions']['permissionGrantPoliciesAssigned'] = assigned
    operation(tmp_path, 'consent_policy', 'authorizationPolicy', [auth])
    operation(tmp_path, 'licensing', 'subscribedSkus', [{'servicePlans': [graph(EXPECTED['service_plans'][0])]}])
    write(tmp_path, 'normalized/privileged_roles.json', {'records': ROLES})
    for collector, name, row in PS.values():
        operation(tmp_path, collector, name, [row])
    for name in ('dmarc_records', 'spf_records', 'dkim_records'):
        operation(tmp_path, 'dns_posture', name, EXPECTED[name])
    return tmp_path


def assert_structure(actual, expected):
    assert type(actual) is type(expected)
    if isinstance(expected, dict):
        assert set(actual) == set(expected)
        for key in expected:
            assert_structure(actual[key], expected[key])
    elif isinstance(expected, list):
        assert len(actual) == len(expected)
        for a, b in zip(actual, expected):
            assert_structure(a, b)


@pytest.mark.parametrize('section', EXPECTED)
def test_adapter_exact_keys_types_values_and_provenance(complete_bundle, section):
    projected = project_run(complete_bundle, redact=False)
    assert projected[section] == EXPECTED[section]
    assert_structure(projected[section], EXPECTED[section])
    detail = projected.report['sections'][section]
    assert detail['status'] == 'projected' and detail['reason'] is None
    assert detail['source'] and all((complete_bundle / p).is_file() for p in detail['source'])
    assert '_name' not in canonical(projected['SPO_tenant'])


# Removing even one required field invalidates the entire section, not one row.
GAPS = [
    ('SPO_tenant', 'raw/sharepoint_access.json', ('sharePointSettings', 'value', 0, 'EmailAttestationRequired')),
    ('conditional_access_policies', 'raw/conditional_access.json', ('conditionalAccessPolicies', 'value', 0, 'conditions', 'users', 'excludeRoles')),
    ('authorization_policies', 'raw/consent_policy.json', ('authorizationPolicy', 'value', 0, 'defaultUserRolePermissions', 'allowedToCreateApps')),
    ('service_plans', 'raw/licensing.json', ('subscribedSkus', 'value', 0, 'servicePlans', 0, 'servicePlanId')),
    ('privileged_users', 'raw/identity.json', ('users', 'value', 0, 'onPremisesImmutableId')),
    ('privileged_roles', 'normalized/privileged_roles.json', ('records', 0, 'Rules')),
    *[(section, f'raw/{collector}.json', (name, 'value', 0, next(iter(row)))) for section, (collector, name, row) in PS.items()],
    *[(section, 'raw/dns_posture.json', (section, 'value', 0, 'compliant' if section == 'spf_records' else 'rdata')) for section in ('dmarc_records', 'spf_records', 'dkim_records')],
]


@pytest.mark.parametrize('section,path,keys', GAPS)
def test_incomplete_adapter_never_emits_partial_section(complete_bundle, section, path, keys):
    data = json.loads((complete_bundle / path).read_text())
    value = data
    for key in keys[:-1]:
        value = value[key]
    del value[keys[-1]]
    write(complete_bundle, path, data)
    p = project_run(complete_bundle)
    assert p[section] == NOT_COLLECTED
    assert p.report['sections'][section]['reason'] == 'incomplete_shape'


@pytest.mark.parametrize('field,value', [('SharingCapability', True), ('DefaultLinkPermission', '1'),
                                        ('DefaultLinkPermission', 0), ('DefaultSharingLinkType', 3),
                                        ('SharingDomainRestrictionMode', 2), ('EmailAttestationRequired', 1),
                                        ('RequireAnonymousLinksExpireInDays', -2)])
def test_spo_rejects_invalid_enum_or_scalar_types(complete_bundle, field, value):
    row = {**SPO, field: value}
    operation(complete_bundle, 'sharepoint_access', 'sharePointSettings', [row])
    assert project_run(complete_bundle)['SPO_tenant'] == NOT_COLLECTED


def test_config_and_sharing_policy_are_disabled_without_faithful_pack_evidence(complete_bundle):
    p = project_run(complete_bundle)
    for section in ('scuba_config', 'sharing_policy'):
        assert p[section] == NOT_COLLECTED
        assert p.report['sections'][section]['reason'] == 'incomplete_shape'


@pytest.mark.parametrize('case', ['conflict', 'non_uuid', 'recorded_conflict'])
def test_tenant_identity_fails_closed(complete_bundle, case):
    if case == 'recorded_conflict':
        write(complete_bundle, 'run-manifest.json', {'run_id': 'test', 'tenant_identity': {'status': 'conflict'}})
    else:
        operation(complete_bundle, 'identity', 'organization', [{'id': '22222222-2222-4222-8222-222222222222' if case == 'conflict' else 'example.invalid'}])
    assert project_run(complete_bundle)['tenant_id'] == NOT_COLLECTED


@pytest.mark.parametrize('metadata', [{'collection_truncated': True}, {'bounded_sample': True},
                                      {'sample_truncated': True}, {'error': 'Forbidden'}, {'item_count': 9}])
def test_incomplete_endpoint_metadata_is_never_projected(complete_bundle, metadata):
    operation(complete_bundle, 'conditional_access', 'conditionalAccessPolicies', [graph(CA)], **metadata)
    assert project_run(complete_bundle)['conditional_access_policies'] == NOT_COLLECTED


@pytest.mark.parametrize('damage', [None, 'missing', 'invalid', 'count', 'escape', 'symlink'])
def test_chunked_export_is_authoritative_and_complete(complete_bundle, damage):
    path = 'raw/conditional_access/conditionalAccessPolicies/part-00001.jsonl'
    target = complete_bundle / path
    target.parent.mkdir(parents=True)
    target.write_text(canonical(graph(CA)) + '\n')
    if damage == 'missing':
        target.unlink()
    elif damage == 'invalid':
        target.write_text('{')
    elif damage == 'escape':
        path = '../outside.jsonl'
    elif damage == 'symlink':
        target.unlink()
        target.symlink_to(complete_bundle / 'raw/identity.json')
    operation(complete_bundle, 'conditional_access', 'conditionalAccessPolicies', [{'displayName': 'incorrect inline sample'}],
              chunk_files=[path], chunk_count=1, item_count=2 if damage == 'count' else 1)
    p = project_run(complete_bundle, redact=False)
    assert p['conditional_access_policies'] == (NOT_COLLECTED if damage else [CA])
    if not damage:
        assert path in p.report['sections']['conditional_access_policies']['source']


@pytest.mark.parametrize('bounds', [{'max_items': 1}, {'max_chars': 40}])
def test_section_size_bound_marks_whole_section_and_report(complete_bundle, bounds):
    if 'max_items' in bounds:
        operation(complete_bundle, 'conditional_access', 'conditionalAccessPolicies', [graph(CA), graph(CA)])
    p = project_run(complete_bundle, **bounds)
    assert p['conditional_access_policies'] == NOT_COLLECTED
    assert p.report['sections']['conditional_access_policies']['reason'] == 'oversize'


@pytest.mark.parametrize('bounds', [{'max_items': 0}, {'max_chars': -1}, {'max_items': True}])
def test_invalid_size_bounds_are_refused(complete_bundle, bounds):
    with pytest.raises(ValueError, match='positive integers'):
        project_run(complete_bundle, **bounds)


def test_projection_is_read_only_and_has_no_network(complete_bundle, monkeypatch):
    def tree():
        return {str(p.relative_to(complete_bundle)): (p.stat().st_mode, sha256(p.read_bytes()).hexdigest())
                for p in complete_bundle.rglob('*') if p.is_file()}
    before = tree()
    monkeypatch.setattr(socket, 'socket', lambda *a, **kw: pytest.fail('Projection opened a network socket'))
    p = project_run(complete_bundle)
    assert sum(v['status'] == 'projected' for v in p.report['sections'].values()) == 15
    assert tree() == before


def test_default_redaction_is_stable_per_run_and_changes_between_runs(complete_bundle):
    a = project_run(complete_bundle)
    assert a == project_run(complete_bundle)
    assert PERSON not in canonical(a) and 'sensitive.local' not in canonical(a)
    assert '***@example.invalid' in canonical(a)
    assert 'Global Administrator' in canonical(a) and 'Require MFA' in canonical(a)
    original = a['privileged_users']['User1']['DisplayName']
    manifest = json.loads((complete_bundle / 'run-manifest.json').read_text())
    manifest['run_id'] = 'another-run'
    write(complete_bundle, 'run-manifest.json', manifest)
    assert project_run(complete_bundle)['privileged_users']['User1']['DisplayName'] != original


@pytest.mark.parametrize('no_redaction', [False, True])
def test_endpoint_prompts_respect_redaction_and_all_dependencies(complete_bundle, monkeypatch, no_redaction):
    calls = []
    def reply(self, method, path, payload):
        case = json.loads(payload['messages'][1]['content'])
        calls.append(payload)
        assert all(e['observed'] != NOT_COLLECTED for e in case['evidence'][1:])
        answer = {'claims': [
            {'id': 'requirement_met', 'status': 'confirmed', 'value': True,
             'evidence_ids': [e['id'] for e in case['evidence']]},
            {'id': 'policy_criticality', 'status': 'confirmed',
             'value': case['evidence'][0]['observed']['criticality'], 'evidence_ids': ['e0']}],
            'limitations': [], 'recommendations': []}
        return canonical({'choices': [{'message': {'content': canonical(answer)}}]}).encode()
    monkeypatch.setattr(ModelClient, '_request', reply)
    args = ['model', 'assess', str(complete_bundle), '--model', 'stub']
    if no_redaction:
        args.append('--no-redaction')
    assert main(args) == 0
    prompts = canonical(calls)
    assert (PERSON in prompts) is no_redaction
    projected = project_run(complete_bundle, redact=not no_redaction)
    assert (PERSON in canonical(projected)) is no_redaction
    assert 'sensitive.local' not in prompts
    assert ('sensitive.local' in canonical(projected)) is no_redaction
    result = json.loads((complete_bundle / 'model_assessment.json').read_text())
    assert result['projection']['redaction']['enabled'] is not no_redaction
    assert 'salt' not in result['projection']['redaction']
    assert len(calls) + result['totals']['rule_answered'] == 102
    validate_assessment(result)


@pytest.mark.parametrize('host', ['model.example.invalid', '127.0.0.1.example.invalid', '192.168.1.2'])
def test_no_redaction_refused_off_loopback_before_reads_or_calls(tmp_path, host, monkeypatch):
    monkeypatch.setattr(ModelClient, '_request', lambda *a: pytest.fail('Refusal must precede transport'))
    with pytest.raises(ValueError, match='loopback'):
        assess_run(tmp_path, ModelConfig(endpoint=f'https://{host}/v1', model_name='test'), no_redaction=True)
    assert list(tmp_path.iterdir()) == []


def test_other_platform_and_absent_bundle_are_all_markers(tmp_path, monkeypatch):
    write(tmp_path, 'run-manifest.json', {'run_id': 'google', 'platform': 'google_workspace'})
    p = project_run(tmp_path)
    assert all(v == NOT_COLLECTED for v in p.values())
    assert {v['reason'] for v in p.report['sections'].values()} == {'not_applicable_to_platform'}
    monkeypatch.setattr(ModelClient, '_request', lambda *a: pytest.fail('Absent sections called model'))
    result = assess_run(tmp_path, ModelConfig(model_name='stub'))
    assert result['totals']['rule_answered'] == result['totals']['unknown'] == 102
    assert result['limitations'] == ['projection_not_implemented']


def test_previous_schema_is_byte_identical_to_pinned_predecessor():
    old = (ROOT / 'schemas/model_assessment-2026-10-28.schema.json').read_bytes()
    assert sha256(old).hexdigest() == '00cf684c8c08f89f8e7ba714155bd3ac3a7f2aa345592fa0d5d4e1f1cd8b157a'


@pytest.mark.parametrize('mutation', ['status_reason', 'missing_section', 'bounds', 'source', 'limitations', 'redaction'])
def test_projection_envelope_validation_rejects_tampering(complete_bundle, monkeypatch, mutation):
    # Select a missing-section rule so no transport is needed.
    result = assess_run(complete_bundle, ModelConfig(model_name='stub'), policies=['MS.POWERBI.1.1v1'])
    if mutation == 'status_reason':
        result['projection']['sections']['SPO_tenant']['reason'] = 'missing_artifact'
    elif mutation == 'missing_section':
        del result['projection']['sections']['SPO_tenant']
    elif mutation == 'bounds':
        result['projection']['bounds']['max_items'] = 0
    elif mutation == 'source':
        result['projection']['sections']['SPO_tenant']['source'] = ['raw/../.secrets/no.json']
    elif mutation == 'limitations':
        result['limitations'] = ['projection_partial']
    else:
        result['projection']['redaction']['enabled'] = False
        result['endpoint_host'] = 'remote.invalid'
    with pytest.raises(ValueError):
        validate_assessment(result)
    schema = json.loads((ROOT / 'schemas/model_assessment.schema.json').read_text())
    if mutation in {'missing_section', 'bounds', 'limitations'}:
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(result, schema)
    else:
        # These cross-field and safe-path invariants supplement JSON Schema.
        jsonschema.validate(result, schema)



PACK_SHAPES = json.loads((ROOT / 'tests/fixtures/scuba-projection-shapes-v7.json').read_text())


@pytest.mark.parametrize('section', sorted(PACK_SHAPES['sections']))
def test_forward_golden_complete_section_matches_one_real_pack_shape(complete_bundle, section):
    from auditex.scuba_projection import _shape, _seen_shape
    p = project_run(complete_bundle, redact=False)
    if p[section] == NOT_COLLECTED:
        assert section not in EXPECTED
        return
    assert _shape(p[section]) in PACK_SHAPES['sections'][section]
    _seen_shape(section, p[section])


def test_runtime_shapes_and_enum_domains_match_complete_pack_goldens():
    from auditex.scuba_projection import PACK_SHAPE_DIGESTS, PACK_ENUM_DOMAINS
    for section, hashes in PACK_SHAPE_DIGESTS.items():
        assert hashes == sorted(sha256(canonical(v).encode()).hexdigest()
                                for v in PACK_SHAPES['sections'][section])
        assert PACK_ENUM_DOMAINS[section] == PACK_SHAPES['enum_domains'][section]


def test_synthetic_demo_assess_split_and_prompt_privacy(tmp_path, monkeypatch):
    from auditex.demo import DEMO_AS_OF, DEMO_SAMPLE
    from azure_tenant_audit.cli import run_offline
    assert run_offline(ROOT / DEMO_SAMPLE, tmp_path, 'p2', 'demo', plane='full', as_of=DEMO_AS_OF) == 0
    root = tmp_path / 'p2-demo'
    findings = json.loads((root / 'findings/findings.json').read_text())
    assert {r['rule_id']: r['severity'] for r in findings if r['rule_id'] in {
        'sharepoint.default_link_type_broad', 'sharepoint.external_sharing_broad'}} == {
        'sharepoint.default_link_type_broad': 'high', 'sharepoint.external_sharing_broad': 'high'}
    calls = []
    def reply(self, method, path, payload):
        case = json.loads(payload['messages'][1]['content'])
        assert precheck_case(case) is None
        assert all(e['observed'] != NOT_COLLECTED for e in case['evidence'][1:])
        calls.append(payload)
        answer = {'claims': [
            {'id': 'requirement_met', 'status': 'unknown', 'value': None, 'evidence_ids': ['e0']},
            {'id': 'policy_criticality', 'status': 'confirmed',
             'value': case['evidence'][0]['observed']['criticality'], 'evidence_ids': ['e0']}],
            'limitations': ['required_evidence_section_not_collected'],
            'recommendations': ['collect_missing_evidence_section']}
        return canonical({'choices': [{'message': {'content': canonical(answer)}}]}).encode()
    monkeypatch.setattr(ModelClient, '_request', reply)
    result = assess_run(root, ModelConfig(model_name='local-stub'))
    assert sum(s['status'] == 'projected' for s in result['projection']['sections'].values()) == 2
    assert result['totals'] == {'answered': 0, 'unknown': 102, 'invalid': 0, 'skipped': 0, 'rule_answered': 102}
    assert len(calls) == 0
    assert sum(r['attempts'] for r in result['policies']) == 0
    demo = json.loads((ROOT / DEMO_SAMPLE).read_text())
    prompts = canonical(calls)
    for user in demo['identity']['users']['value']:
        assert user['displayName'] not in prompts
        # A local part such as 'accounts' also occurs in immutable policy prose.
        # Check address tokens; the dedicated privacy fixture uses a unique local part.
        assert user['userPrincipalName'].split('@')[0] + '@' not in prompts
    for row in result['policies']:
        if row['reason'] == 'rule_precheck':
            assert row['attempts'] == 0 and row['prompt_sha256'] is None
    validate_assessment(result)


@pytest.mark.parametrize('section,collector,name', [
    ('conditional_access_policies', 'conditional_access', 'conditionalAccessPolicies'),
    ('service_plans', 'licensing', 'subscribedSkus'),
    ('accepted_domains', 'exchange_policy', 'acceptedDomains'),
])
def test_explicit_complete_empty_collection_is_known_empty(complete_bundle, section, collector, name):
    operation(complete_bundle, collector, name, [], item_count=0)
    p = project_run(complete_bundle)
    assert p[section] == (NOT_COLLECTED if section == 'accepted_domains' else [])
    assert p.report['sections'][section]['status'] == ('not_collected' if section == 'accepted_domains' else 'projected')
    # Removing the artefact is a collection gap, never another empty result.
    (complete_bundle / f'raw/{collector}.json').unlink()
    assert project_run(complete_bundle)[section] == NOT_COLLECTED


def test_export_only_operation_summary_and_normalised_provider_records(complete_bundle):
    (complete_bundle / 'raw/conditional_access.json').unlink()
    write(complete_bundle, 'raw/conditional_access/conditionalAccessPolicies/summary.json', {'value': [graph(CA)], 'item_count': 1})
    assert project_run(complete_bundle, redact=False)['conditional_access_policies'] == [CA]
    (complete_bundle / 'raw/teams_policy.json').unlink()
    write(complete_bundle, 'normalized/teams_policy_objects.json', {'records': [
        {**PS['meeting_policies'][2], 'source_name': 'meetingPolicies', 'key': 'policy:global', 'kind': 'teams_policy'}]})
    p = project_run(complete_bundle)
    assert p['meeting_policies'] == EXPECTED['meeting_policies']
    assert 'normalized/teams_policy_objects.json' in p.report['sections']['meeting_policies']['source']


@pytest.mark.parametrize('payload', ['{"subscribedSkus":{},"subscribedSkus":{"value":[]}}',
                                     '{"subscribedSkus":{"value":[NaN]}}', '{'])
def test_malformed_raw_json_fails_closed(complete_bundle, payload):
    (complete_bundle / 'raw/licensing.json').write_text(payload)
    assert project_run(complete_bundle)['service_plans'] == NOT_COLLECTED


def test_effective_admin_set_requires_all_counted_users_and_redacts_immutable_ids(complete_bundle):
    operation(complete_bundle, 'identity', 'users', [{'id': TENANT, 'displayName': PERSON, 'onPremisesImmutableId': 'private-immutable'}])
    p = project_run(complete_bundle)
    assert 'private-immutable' not in canonical(p)
    assert p.report['redaction']['immutable_ids'] == 1
    data = json.loads((complete_bundle / 'normalized/effective_admin_set.json').read_text())
    data['records'][0]['admin_count'] = 2
    write(complete_bundle, 'normalized/effective_admin_set.json', data)
    assert project_run(complete_bundle)['privileged_users'] == NOT_COLLECTED


def test_2026_10_28_assessments_continue_to_validate(complete_bundle):
    payload = assess_run(complete_bundle, ModelConfig(model_name='unused'), policies=['MS.POWERBI.1.1v1'])
    payload['schema_version'] = '2026-10-28'
    del payload['projection']
    validate_assessment(payload)
    jsonschema.validate(payload, json.loads((ROOT / 'schemas/model_assessment-2026-10-28.schema.json').read_text()))


@pytest.mark.parametrize('marker', [{'error': 'Forbidden'}, {'read_state': 'blocked'},
                                    {'collection_status': 'not_collected'}])
def test_failed_record_with_stale_fields_is_unavailable(complete_bundle, marker):
    operation(complete_bundle, 'exchange_policy', 'acceptedDomains', [{**PS['accepted_domains'][2], **marker}])
    assert project_run(complete_bundle)['accepted_domains'] == NOT_COLLECTED


@pytest.mark.parametrize('section,collector,name,metadata', [
    ('conditional_access_policies', 'conditional_access', 'conditionalAccessPolicies', {'collection_status': 'not_collected'}),
    ('service_plans', 'licensing', 'subscribedSkus', {'error': 'Forbidden'}),
])
def test_failed_endpoint_and_sku_records_never_become_authoritative(complete_bundle, section, collector, name, metadata):
    rows = [graph(CA)] if collector == 'conditional_access' else [{'servicePlans': []}]
    rows[0].update(metadata)
    operation(complete_bundle, collector, name, rows)
    p = project_run(complete_bundle)
    assert p[section] == NOT_COLLECTED
    assert p.report['sections'][section]['reason'] == 'incomplete_shape'


@pytest.mark.parametrize('payload', [{'chunk_files': []}, {'value': []}, {'chunk_files': [], 'item_count': 0}])
def test_empty_collection_requires_explicit_completeness(complete_bundle, payload):
    write(complete_bundle, 'raw/licensing.json', {'subscribedSkus': payload})
    assert project_run(complete_bundle)['service_plans'] == NOT_COLLECTED


@pytest.mark.parametrize('path,rows', [
    ('coverage.json', [{'collector': 'licensing', 'name': 'subscribedSkus', 'status': 'failed', 'error': 'Forbidden'}]),
    ('normalized/coverage_ledger.json', {'records': [{'collector': 'licensing', 'coverage_status': 'partial_success'}]}),
    ('normalized/collection_gaps.json', {'records': [{'source': 'licensing.subscribedSkus', 'reason': 'read_failed'}]}),
])
def test_coverage_failures_override_usable_payload(complete_bundle, path, rows):
    write(complete_bundle, path, rows)
    assert project_run(complete_bundle)['service_plans'] == NOT_COLLECTED


@pytest.mark.parametrize('condition', ['locations', 'devices', 'platforms'])
def test_ca_unsupported_scope_withholds_entire_section_and_names_condition(complete_bundle, condition):
    row = graph(CA)
    row['conditions'][condition] = {'include': ['restricted']}
    operation(complete_bundle, 'conditional_access', 'conditionalAccessPolicies', [graph(CA), row])
    p = project_run(complete_bundle)
    assert p['conditional_access_policies'] == NOT_COLLECTED
    assert p.report['sections']['conditional_access_policies']['unsupported_conditions'] == ['conditions.' + condition]
    assert p.report['sections']['conditional_access_policies']['reason'] == 'incomplete_shape'
    result = assess_run(complete_bundle, ModelConfig(model_name='stub'), policies=['MS.POWERBI.1.1v1'], dry_run=False)
    validate_assessment(result)


@pytest.mark.parametrize('section,path,keys', [
    ('conditional_access_policies', 'raw/conditional_access.json', ('conditionalAccessPolicies', 'value', 0, 'conditions', 'applications')),
    ('privileged_roles', 'normalized/privileged_roles.json', ('records', 0, 'Assignments', 0)),
    ('meeting_policies', 'raw/teams_policy.json', ('meetingPolicies', 'value', 0)),
])
def test_unexpected_nested_person_field_cannot_reach_prompt(complete_bundle, monkeypatch, section, path, keys):
    from auditex.model_serving import build_case, policy_catalogue
    data = json.loads((complete_bundle / path).read_text())
    row = data
    for key in keys:
        row = row[key]
    row['UnexpectedPersonName'] = 'Injected Private Person'
    write(complete_bundle, path, data)
    p = project_run(complete_bundle)
    assert p[section] == NOT_COLLECTED
    assert p.report['sections'][section]['reason'] == 'incomplete_shape'
    assert 'Injected Private Person' not in canonical([
        build_case(pid, p, 'test') for pid in policy_catalogue()['policies']])


@pytest.mark.parametrize('field,value', [('state', 'tenant-wide'), ('state', 1), ('state', True)])
def test_invalid_ca_state_is_never_projected(complete_bundle, field, value):
    row = graph(CA)
    row[field] = value
    operation(complete_bundle, 'conditional_access', 'conditionalAccessPolicies', [row])
    assert project_run(complete_bundle)['conditional_access_policies'] == NOT_COLLECTED


@pytest.mark.parametrize('key,value', [('StartDateTime', '2026-10-29'), ('EndDateTime', 'yesterday'), ('EndDateTime', 123)])
def test_role_dates_require_pack_date_convention(complete_bundle, key, value):
    roles = json.loads(json.dumps(ROLES))
    roles[0]['Assignments'][0][key] = value
    write(complete_bundle, 'normalized/privileged_roles.json', {'records': roles})
    assert project_run(complete_bundle)['privileged_roles'] == NOT_COLLECTED


def test_unseen_minimal_role_and_spf_union_are_withheld(complete_bundle):
    roles = json.loads(json.dumps(ROLES))
    roles[0]['Rules'] = [{k: v for k, v in roles[0]['Rules'][0].items()
                         if k in {'Id', 'IsExpirationRequired', 'MaximumDuration', 'RuleSource', 'RuleSourceType'}}]
    write(complete_bundle, 'normalized/privileged_roles.json', {'records': roles})
    operation(complete_bundle, 'dns_posture', 'spf_records', [{'domain': 'test.invalid', 'doamin': 'test.invalid', 'rdata': ['v=spf1 -all']}])
    p = project_run(complete_bundle)
    assert p['privileged_roles'] == p['spf_records'] == NOT_COLLECTED


def test_prompt_enum_annotation_is_included_in_character_bound(complete_bundle):
    from azure_tenant_audit.external_sharing import annotate_enum_names
    raw = len(canonical([SPO]))
    assert len(canonical(annotate_enum_names('SPO_tenant', [SPO]))) > raw
    p = project_run(complete_bundle, max_chars=raw)
    assert p['SPO_tenant'] == NOT_COLLECTED
    assert p.report['sections']['SPO_tenant']['reason'] == 'oversize'


def test_strict_chunk_json_rejects_duplicate_keys(complete_bundle):
    path = 'raw/licensing/subscribedSkus/part-00001.jsonl'
    target = complete_bundle / path
    target.parent.mkdir(parents=True)
    target.write_text('{"error":"Forbidden","error":null,"servicePlans":[]}\n')
    operation(complete_bundle, 'licensing', 'subscribedSkus', [], chunk_files=[path], item_count=1)
    assert project_run(complete_bundle)['service_plans'] == NOT_COLLECTED


def test_chunk_iteration_stops_at_item_and_line_bounds(complete_bundle, monkeypatch):
    import auditex.scuba_projection as projection
    from contextlib import contextmanager
    import io
    class Guarded(io.BytesIO):
        def fileno(self):
            return 0
        def readline(self, size=-1):
            assert size > 0
            self.calls += 1
            assert self.calls <= 2, 'Read beyond item bound'
            return super().readline(size)
    data = Guarded((canonical({'servicePlans': []}) + '\n').encode() * 100000)
    data.calls = 0
    original = projection._open_chunk
    @contextmanager
    def opened(root, relative):
        if relative.endswith('.jsonl'):
            yield data
        else:
            with original(root, relative) as handle:
                yield handle
    monkeypatch.setattr(projection, '_open_chunk', opened)
    operation(complete_bundle, 'licensing', 'subscribedSkus', [],
              chunk_files=['raw/licensing/subscribedSkus/part-00001.jsonl'], item_count=100000)
    p = project_run(complete_bundle, max_items=1)
    assert p.report['sections']['service_plans']['reason'] == 'oversize'
    assert data.calls == 2 and data.tell() < 100
    data.calls = 0
    data.seek(0)
    data.write(b'x' * 10000)
    data.seek(0)
    p = project_run(complete_bundle, max_chars=100)
    assert p.report['sections']['service_plans']['reason'] == 'oversize'
    assert data.calls == 1 and data.tell() == 401


def test_redaction_salt_is_absent_and_rejected_by_both_validators(complete_bundle):
    result = assess_run(complete_bundle, ModelConfig(model_name='stub'), policies=['MS.POWERBI.1.1v1'])
    assert 'salt' not in result['projection']['redaction']
    result['projection']['redaction']['salt'] = 'a' * 64
    with pytest.raises(ValueError):
        validate_assessment(result)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(result, json.loads((ROOT / 'schemas/model_assessment.schema.json').read_text()))


def test_demo_original_sharepoint_settings_and_generated_twin():
    import runpy
    module = runpy.run_path(str(ROOT / 'scripts/make-remediated-demo.py'))
    before = json.loads((ROOT / 'examples/demo_tenant/demo_tenant.json').read_text())
    after = ROOT / 'examples/demo_tenant/demo_tenant_remediated.json'
    assert after.read_text() == module['dumps_fixture'](module['remediate'](before)[0])
    for collector in ('sharepoint_access', 'onedrive_posture'):
        settings = before[collector]['sharePointSettings']
        assert settings['defaultSharingLinkType'] == 'anonymous'
        assert settings['defaultLinkPermission'] == 'edit'
        assert 'requireAnonymousLinksExpireInDays' not in settings
        assert 'fileAnonymousLinkType' not in settings and 'folderAnonymousLinkType' not in settings


FROZEN_PACK = Path('/Volumes/4TB/dev/auditex-data/development-kit/20261026-oracle-pack-v7/training-pack-oracle-v7')
PACK_ENUM_FIELDS = frozenset({
    'State', 'Operator', 'BuiltInControls', 'ClientAppTypes', 'SignInRiskLevels', 'UserRiskLevels',
    'AgentIdRiskLevels', 'TransferMethods', 'MembershipKind', 'GuestOrExternalUserTypes', 'AllowInvitesFrom',
    'AutoAdmittedUsers', 'NotificationType', 'RuleSourceType', 'SharingCapability', 'ODBSharingCapability',
    'DefaultLinkPermission', 'DefaultSharingLinkType', 'FileAnonymousLinkType', 'FolderAnonymousLinkType',
    'SharingDomainRestrictionMode', 'M365Environment', 'IncludeUserActions', 'AllowedCombinations',
})


def _frozen_pack_goldens(pack):
    """Reconstruct complete shape witnesses directly from the two read-only JSONL files.

    Array entries are canonical JSON strings of complete item shapes, sorted and
    deduplicated. This preserves nested shape combinations without binding lengths.
    No evidence values are retained except the explicitly named enum domains.
    """
    from azure_tenant_audit.external_sharing import ENUM_NAME_KEYS
    from auditex.model_serving import policy_catalogue
    sections = {s: {} for row in policy_catalogue()['policies'].values() for s in row['sections']}
    domains = {s: {} for s in sections}
    witnesses = {s: {} for s in sections}
    def strip_names(value):
        if isinstance(value, dict):
            return {k: strip_names(v) for k, v in value.items() if k not in {f'{n}_name' for n in ENUM_NAME_KEYS}}
        if isinstance(value, list):
            return [strip_names(v) for v in value]
        return value
    def shape(value):
        if isinstance(value, dict):
            if value and all(k.startswith('User') and k[4:].isdigit() for k in value):
                return {'users': sorted({canonical(shape(v)) for v in value.values()})}
            return {'object': {k: shape(v) for k, v in value.items()}}
        if isinstance(value, list):
            return {'array': sorted({canonical(shape(v)) for v in value})}
        return type(value).__name__
    def enums(value, section, path=''):
        if isinstance(value, dict):
            for key, child in value.items():
                if key in PACK_ENUM_FIELDS:
                    domains[section].setdefault(path + '.' + key, set()).update(
                        canonical(v) for v in (child if isinstance(child, list) else [child]))
                enums(child, section, path + '.' + key)
        elif isinstance(value, list):
            for child in value:
                enums(child, section, path + '[]')
    source_files = {}
    for filename in ('train.jsonl', 'test.jsonl'):
        path = pack / filename
        digest = sha256()
        count = 0
        with path.open('rb') as handle:
            for count, line in enumerate(handle, 1):
                digest.update(line)
                row = json.loads(line)
                for message in row.get('messages', row.get('prompt', [])):
                    if message['role'] != 'user':
                        continue
                    for evidence in json.loads(message['content']).get('evidence', [])[1:]:
                        section = evidence.get('section')
                        if section not in sections or evidence['observed'] == NOT_COLLECTED:
                            continue
                        value = strip_names(evidence['observed'])
                        structural = shape(value)
                        encoded = canonical(structural)
                        sections[section][encoded] = structural
                        witnesses[section].setdefault(sha256(encoded.encode()).hexdigest(), {
                            'file': filename, 'line': count, 'evidence_id': evidence['id']})
                        enums(value, section)
        source_files[filename] = {'sha256': digest.hexdigest(), 'rows': count}
    return {
        'canonicalisation': 'whole-section-v1; list cardinality ignored; empty/populated lists distinct; UserN collections preserve all item shapes; derived SharePoint enum names removed',
        'source_files': source_files,
        'sections': {s: [variants[k] for k in sorted(variants)] for s, variants in sorted(sections.items())},
        'enum_domains': {s: {p: sorted(values) for p, values in sorted(paths.items())} for s, paths in sorted(domains.items())},
        'witnesses': witnesses,
    }


def test_complete_shape_goldens_reproduce_both_frozen_packs():
    if not all((FROZEN_PACK / name).is_file() for name in ('train.jsonl', 'test.jsonl')):
        pytest.skip('Read-only frozen v7 train/test packs are not mounted')
    assert _frozen_pack_goldens(FROZEN_PACK) == PACK_SHAPES


@pytest.mark.parametrize('path,metadata', [
    ('coverage.json', [{'collector': 'teams_policy', 'name': 'meetingPolicies', 'status': 'failed'}]),
    ('normalized/coverage_ledger.json', {'records': [{'collector': 'teams_policy', 'coverage_status': 'failed_runtime', 'actual_status': 'failed'}]}),
])
def test_normalised_powershell_fallback_cannot_bypass_failed_coverage(complete_bundle, path, metadata):
    (complete_bundle / 'raw/teams_policy.json').unlink()
    write(complete_bundle, 'normalized/teams_policy_objects.json', {'records': [
        {**PS['meeting_policies'][2], 'source_name': 'meetingPolicies'}]})
    write(complete_bundle, path, metadata)
    assert project_run(complete_bundle)['meeting_policies'] == NOT_COLLECTED


@pytest.mark.parametrize('collector,name', [('identity', 'roleAssignments'), ('identity', 'groupMembers'),
                                           ('identity_governance', 'roleEligibilitySchedules')])
@pytest.mark.parametrize('path', ['coverage.json', 'normalized/collection_gaps.json', 'raw'])
def test_stale_complete_admin_summary_cannot_bypass_failed_dependencies(complete_bundle, collector, name, path):
    row = {'collector': collector, 'name': name, 'list': name, 'status': 'failed', 'error': 'Forbidden'}
    if path == 'raw':
        operation(complete_bundle, collector, name, [], error='Forbidden')
    else:
        write(complete_bundle, path, [row] if path == 'coverage.json' else {'records': [row]})
    assert project_run(complete_bundle)['privileged_users'] == NOT_COLLECTED


@pytest.mark.parametrize('path,key', [('applications', 'includeUserActions'), ('authenticationStrength', 'allowedCombinations')])
def test_ca_enum_fields_reject_unseen_values_and_person_names(complete_bundle, path, key):
    row = graph(CA)
    parent = row['conditions'] if path == 'applications' else row['grantControls']
    parent[path][key] = ['Injected Private Person']
    operation(complete_bundle, 'conditional_access', 'conditionalAccessPolicies', [row])
    p = project_run(complete_bundle)
    assert p['conditional_access_policies'] == NOT_COLLECTED
    assert 'Injected Private Person' not in canonical(p)


def test_authorisation_permissions_reject_unexpected_nested_fields(complete_bundle):
    path = 'raw/consent_policy.json'
    data = json.loads((complete_bundle / path).read_text())
    data['authorizationPolicy']['value'][0]['defaultUserRolePermissions']['unexpectedPerson'] = PERSON
    write(complete_bundle, path, data)
    assert project_run(complete_bundle)['authorization_policies'] == NOT_COLLECTED


@pytest.mark.parametrize('metadata', [{'complete': False}, {'status': 'failed'}, {'collection_status': 'not_collected'}])
def test_empty_collection_success_cannot_override_failure_metadata(complete_bundle, metadata):
    operation(complete_bundle, 'licensing', 'subscribedSkus', [], **metadata)
    assert project_run(complete_bundle)['service_plans'] == NOT_COLLECTED


def test_malformed_manifest_cannot_hide_coverage_failures(complete_bundle):
    (complete_bundle / 'run-manifest.json').write_text('{"coverage_gaps":')
    assert all(v == NOT_COLLECTED for v in project_run(complete_bundle).values())


@pytest.mark.parametrize('metadata', [{'error': 'Forbidden'}, {'collection_status': 'not_collected'}, {'status': 'failed'}])
@pytest.mark.parametrize('offline', [False, True])
def test_failed_collector_envelope_overrides_populated_endpoint(complete_bundle, metadata, offline):
    payload = json.loads((complete_bundle / 'raw/licensing.json').read_text())
    payload.update(metadata)
    if offline:
        (complete_bundle / 'raw/licensing.json').unlink()
        write(complete_bundle, 'raw/sample_input.json', {'licensing': payload})
    else:
        write(complete_bundle, 'raw/licensing.json', payload)
    assert project_run(complete_bundle)['service_plans'] == NOT_COLLECTED


def test_chunk_whitespace_and_manifest_count_are_bounded(complete_bundle, monkeypatch):
    import auditex.scuba_projection as projection
    import io
    from contextlib import contextmanager
    data = io.BytesIO(b'\n' * 100000 + b'{"servicePlans":[]}\n')
    original = projection._open_chunk
    class Guarded:
        def fileno(self):
            return 0
        def readline(self, size=-1):
            assert 0 < size <= 401
            assert data.tell() <= 400
            return data.readline(size)
    @contextmanager
    def opened(root, relative):
        if relative.endswith('.jsonl'):
            yield Guarded()
        else:
            with original(root, relative) as handle:
                yield handle
    monkeypatch.setattr(projection, '_open_chunk', opened)
    operation(complete_bundle, 'licensing', 'subscribedSkus', [],
              chunk_files=['raw/licensing/subscribedSkus/a.jsonl'], item_count=1)
    p = project_run(complete_bundle, max_chars=100)
    assert p.report['sections']['service_plans']['reason'] == 'oversize'
    assert data.tell() == 401
    data.seek(0)
    operation(complete_bundle, 'licensing', 'subscribedSkus', [],
              chunk_files=['raw/licensing/subscribedSkus/a.jsonl', 'raw/licensing/subscribedSkus/b.jsonl'])
    assert project_run(complete_bundle, max_items=1).report['sections']['service_plans']['reason'] == 'oversize'
    assert data.tell() == 0


def test_manifest_collection_gap_overrides_successful_endpoint(complete_bundle):
    path = 'run-manifest.json'
    manifest = json.loads((complete_bundle / path).read_text())
    manifest['coverage_gaps'] = [{'collector': 'licensing', 'list': 'subscribedSkus', 'reason': 'pagination_failed'}]
    write(complete_bundle, path, manifest)
    assert project_run(complete_bundle)['service_plans'] == NOT_COLLECTED


def test_ca_union_of_individually_seen_fields_is_not_a_seen_whole_shape(complete_bundle):
    unseen = {
        'displayName': 'Require MFA', 'state': 'enabled',
        'conditions': {
            'applications': {'includeApplications': ['All'], 'excludeApplications': [], 'includeUserActions': []},
            'authenticationFlows': {'transferMethods': None}, 'clientAppTypes': ['all'],
            'clientApplications': None, 'signInRiskLevels': [], 'userRiskLevels': [], 'agentIdRiskLevels': None,
            'users': {'includeUsers': ['All'], 'excludeUsers': [EMAIL], 'includeRoles': [],
                      'excludeRoles': [], 'excludeGroups': [], 'excludeGuestsOrExternalUsers': None}},
        'grantControls': {'builtInControls': ['mfa'], 'operator': 'OR', 'authenticationStrength': None},
    }
    operation(complete_bundle, 'conditional_access', 'conditionalAccessPolicies', [unseen])
    p = project_run(complete_bundle)
    assert p['conditional_access_policies'] == NOT_COLLECTED
    detail = p.report['sections']['conditional_access_policies']
    assert detail['reason'] == 'incomplete_shape' and 'unsupported_conditions' not in detail


@pytest.mark.parametrize('section,path,keys,value', [
    ('conditional_access_policies', 'raw/conditional_access.json', ('conditionalAccessPolicies', 'value', 0, 'grantControls', 'operator'), 'NOR'),
    ('conditional_access_policies', 'raw/conditional_access.json', ('conditionalAccessPolicies', 'value', 0, 'grantControls', 'builtInControls'), ['unknownControl']),
    ('authorization_policies', 'raw/consent_policy.json', ('authorizationPolicy', 'value', 0, 'allowInvitesFrom'), 'unknownAudience'),
    ('privileged_roles', 'normalized/privileged_roles.json', ('records', 0, 'Rules', 0, 'RuleSourceType'), 'unknownRoleType'),
    ('meeting_policies', 'raw/teams_policy.json', ('meetingPolicies', 'value', 0, 'AutoAdmittedUsers'), 'unknownLobbyPolicy'),
])
def test_projected_enum_domains_reject_unseen_values(complete_bundle, section, path, keys, value):
    data = json.loads((complete_bundle / path).read_text())
    row = data
    for key in keys[:-1]:
        row = row[key]
    row[keys[-1]] = value
    write(complete_bundle, path, data)
    p = project_run(complete_bundle)
    assert p[section] == NOT_COLLECTED
    assert p.report['sections'][section]['reason'] == 'incomplete_shape'


@pytest.mark.parametrize('extra', [{'unexpectedPerson': 'Injected Private Person'}, {'provisioningStatus': 'unseenStatus'}, {'appliesTo': 'unseenScope'}])
def test_service_plan_nested_fields_are_explicitly_validated(complete_bundle, extra):
    plan = {**graph(EXPECTED['service_plans'][0]), **extra}
    operation(complete_bundle, 'licensing', 'subscribedSkus', [{'servicePlans': [plan]}])
    p = project_run(complete_bundle)
    assert p['service_plans'] == NOT_COLLECTED
    assert p.report['sections']['service_plans']['reason'] == 'incomplete_shape'
    assert 'Injected Private Person' not in canonical(p)
