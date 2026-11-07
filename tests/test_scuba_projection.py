"""Projection contract tests use synthetic evidence only; no tenant or web calls."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import socket

import jsonschema
import pytest

from auditex.cli import main
from auditex.model_precheck import precheck_case
from auditex.model_serving import ModelClient, ModelConfig, assess_run, build_case, canonical
from auditex.scuba_projection import project_run
from azure_tenant_audit.collectors.identity import IdentityCollector
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
GLOBAL_ADMIN_ROLE = {'role': 'Global Administrator', 'route': 'direct_active', 'scope': '/'}
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


@pytest.fixture(autouse=True)
def _no_area_adapter_modules(monkeypatch):
    # This file pins the built-in adapters (shape gate, digests, demo totals); each area adapter module has its own tests.
    monkeypatch.setattr('auditex.scuba_projection.AREA_ADAPTER_MODULES', ())


@pytest.fixture
def complete_bundle(tmp_path):
    write(tmp_path, 'run-manifest.json', {'run_id': 'synthetic-run', 'platform': 'm365',
                                        'tenant_id': TENANT, 'graph_endpoint': 'https://graph.microsoft.com/v1.0'})
    operation(tmp_path, 'identity', 'organization', [{'id': TENANT}])
    operation(tmp_path, 'identity', 'users', [{'id': TENANT, 'displayName': PERSON, 'onPremisesImmutableId': None}])
    write(tmp_path, 'normalized/effective_admin_set.json', {'records': [
        {'kind': 'effective_admin_set_summary', 'state': 'complete', 'unresolved_principal_count': 0, 'admin_count': 1},
        {'kind': 'effective_admin', 'state': 'complete', 'is_user': True, 'principal_id': TENANT,
         'role_names': ['Global Administrator'], 'roles': [GLOBAL_ADMIN_ROLE]}]})
    write(tmp_path, 'normalized/sharepoint_tenant_settings.json', {'records': [{
        'read_state': 'collected', 'sharing_capability': 'externalUserAndGuestSharing',
        'onedrive_sharing_capability': 'existingExternalUserSharingOnly'}]})
    operation(tmp_path, 'sharepoint_access', 'sharePointSettings', [SPO])
    operation(tmp_path, 'conditional_access', 'conditionalAccessPolicies', [graph(CA)])
    auth = graph(AUTH)
    assigned = auth.pop('permissionGrantPolicyIdsAssignedToDefaultUserRole')
    auth['defaultUserRolePermissions']['permissionGrantPoliciesAssigned'] = assigned
    operation(tmp_path, 'consent_policy', 'authorizationPolicy', [auth])
    operation(tmp_path, 'licensing', 'subscribedSkus', [{'skuPartNumber': 'SPE_E5', 'servicePlans': [{**graph(EXPECTED['service_plans'][0]), 'provisioningStatus': 'Success'}]}])
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


def test_sharing_policy_is_disabled_without_faithful_pack_evidence(complete_bundle):
    p = project_run(complete_bundle)
    assert p['sharing_policy'] == NOT_COLLECTED
    assert p.report['sections']['sharing_policy']['reason'] == 'missing_artifact'


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
    assert sum(v['status'] == 'projected' for v in p.report['sections'].values()) == 16
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
def test_assessment_never_calls_model_and_keeps_redaction(complete_bundle, monkeypatch, no_redaction):
    monkeypatch.setattr(ModelClient, '__init__', lambda *args: pytest.fail('No assessment model client'))
    args = ['model', 'assess', str(complete_bundle), '--model', 'stub']
    if no_redaction:
        args.append('--no-redaction')
    assert main(args) == 0
    result = json.loads((complete_bundle / 'model_assessment.json').read_text())
    assert result['projection']['redaction']['enabled']
    assert 'salt' not in result['projection']['redaction']
    assert all(row['attempts'] == 0 for row in result['policies'])
    assert PERSON not in canonical(result) and 'sensitive.local' not in canonical(result)
    validate_assessment(result)


@pytest.mark.parametrize('host', ['model.example.invalid', '127.0.0.1.example.invalid', '192.168.1.2'])
def test_no_redaction_ignored_for_any_model_host(tmp_path, host, monkeypatch):
    write(tmp_path, 'run-manifest.json', {'run_id': 'run'})
    monkeypatch.setattr(ModelClient, '__init__', lambda *args: pytest.fail('No assessment model client'))
    result = assess_run(tmp_path, ModelConfig(endpoint=f'https://{host}/v1', model_name='test'), no_redaction=True)
    assert result['projection']['redaction']['enabled'] and result['endpoint_host'] == 'none'
    validate_assessment(result)


def test_other_platform_and_absent_bundle_are_all_markers(tmp_path, monkeypatch):
    write(tmp_path, 'run-manifest.json', {'run_id': 'google', 'platform': 'google_workspace'})
    p = project_run(tmp_path)
    assert all(v == NOT_COLLECTED for v in p.values())
    assert {v['reason'] for v in p.report['sections'].values()} == {'not_applicable_to_platform'}
    monkeypatch.setattr(ModelClient, '_request', lambda *a: pytest.fail('Absent sections called model'))
    result = assess_run(tmp_path, ModelConfig(model_name='stub'))
    assert result['totals']['rule_answered'] == 102 and result['totals']['unknown'] == 102
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
    monkeypatch.delenv("AUDITEX_DISABLE_VALUE_RULES", raising=False)
    assert run_offline(ROOT / DEMO_SAMPLE, tmp_path, 'p2', 'demo', plane='full', as_of=DEMO_AS_OF) == 0
    root = tmp_path / 'p2-demo'
    findings = json.loads((root / 'findings/findings.json').read_text())
    assert {r['rule_id']: r['severity'] for r in findings if r['rule_id'] in {
        'sharepoint.default_link_type_broad', 'sharepoint.external_sharing_broad'}} == {
        'sharepoint.default_link_type_broad': 'high', 'sharepoint.external_sharing_broad': 'high'}
    monkeypatch.setattr(ModelClient, '__init__', lambda *args: pytest.fail('Rules-only assessment built a model client'))
    returned = assess_run(root)
    written_text = (root / 'model_assessment.json').read_text(encoding='utf-8')
    result = json.loads(written_text)
    assert result == returned
    sections = result['projection']['sections']
    assert sections['SPO_tenant']['detail'] == {'field': 'FileAnonymousLinkType', 'kind': 'missing_field'}
    assert sections['authorization_policies']['detail'] == {
        'field': 'AllowInvitesFrom', 'kind': 'unseen_enum_value', 'value': 'everyone'}
    assert sum(s['status'] == 'projected' for s in result['projection']['sections'].values()) == 5
    assert sections['privileged_users']['status'] == 'projected' and sections['scuba_config']['status'] == 'projected'
    # The sample's accepted domains carry fields the training shape does not know: ignored and named, never withholding.
    assert sections['accepted_domains']['status'] == 'projected'
    assert sections['accepted_domains']['ignored_fields'] == ['Default', 'DomainType', 'Identity']
    # Every catalogue policy has a value rule: all 102 rows are rule answers, none reaches a model. This file turns
    # the area adapters off (autouse fixture), so more rows abstain than in test_model_serving's demo (24 answered).
    assert result['totals'] == {'answered': 13, 'unknown': 89, 'invalid': 0, 'skipped': 0, 'rule_answered': 102,
                                'scope_narrowed': 0}
    assert (result['endpoint_host'], result['model_name']) == ('none', 'rules-only') and 'serving' not in result
    assert result['projection']['redaction']['enabled']
    for row in result['policies']:
        assert row['reason'] == 'rule_precheck' and 'model_shadow' not in row
        assert row['attempts'] == 0 and row['prompt_sha256'] is None and row['response_sha256'] is None
    # Privacy: neither the written assessment nor the locally written development prompts carry a demo user's
    # display name or e-mail address.
    assert assess_run(root, dry_run=True)['prompts'] == 102
    prompts_text = (root / 'model_assessment_prompts.jsonl').read_text(encoding='utf-8')
    demo = json.loads((ROOT / DEMO_SAMPLE).read_text())
    users = demo['identity']['users']['value']
    assert users
    for text in (written_text, prompts_text):
        for user in users:
            assert user['displayName'] not in text
            # A local part such as 'accounts' also occurs in immutable policy prose.
            # Check address tokens; the dedicated privacy fixture uses a unique local part.
            assert user['userPrincipalName'].split('@')[0] + '@' not in text
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


@pytest.mark.parametrize('version', ['2026-10-28', '2026-10-29'])
def test_legacy_assessments_continue_to_validate(complete_bundle, monkeypatch, version):
    # Construct the historical precheck fixture explicitly; the legacy switch no longer selects a route.
    from auditex.model_precheck import precheck_case
    monkeypatch.setattr('auditex.model_serving.precheck_case', lambda case, **kw: precheck_case(
        case, **{**kw, 'value_rules': False}))
    payload = assess_run(complete_bundle, ModelConfig(model_name='unused'), policies=['MS.POWERBI.1.1v1'])
    assert payload['policies'][0]['rule_precheck']['class'] != 'value_rule'
    payload['schema_version'] = version
    if version == '2026-10-28':
        del payload['projection'], payload['scope_post_check'], payload['totals']['scope_narrowed']
        payload.pop('serving', None)
    validate_assessment(payload)
    jsonschema.validate(payload, json.loads((ROOT / f'schemas/model_assessment-{version}.schema.json').read_text()))


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
    assert p.report['sections'][section]['reason'] == ('incomplete_shape' if 'error' not in metadata else 'collector_error')


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


SCHEDULE = {'id': TENANT, 'principalId': TENANT, 'roleDefinitionId': 'Role1', 'status': 'Provisioned',
            'scheduleInfo': {'startDateTime': '2026-10-01T00:00:00Z'}}


@pytest.mark.parametrize('section', ['privileged_users', 'privileged_roles'])
def test_graph_record_status_is_data_not_collection_health(complete_bundle, section):
    # A role schedule's own status is Graph data; no pack row carries it and no rule reads it.
    operation(complete_bundle, 'identity_governance', 'roleAssignmentSchedules', [SCHEDULE])
    operation(complete_bundle, 'identity', 'users', [
        {'id': TENANT, 'displayName': PERSON, 'onPremisesImmutableId': None, 'status': 'Provisioned',
         'nested': {'status': 'Provisioned'}}])
    p = project_run(complete_bundle, redact=False)
    assert p[section] == EXPECTED[section]
    assert p.report['sections'][section]['status'] == 'projected'


@pytest.mark.parametrize('section,collector,name,metadata', [
    ('privileged_users', 'identity_governance', 'roleAssignmentSchedules', {'status': 'failed'}),
    ('privileged_roles', 'identity_governance', 'roleAssignmentSchedules', {'status': 'partial_success'}),
    ('privileged_users', 'identity', 'users', {'status': 'failed'}),
    ('service_plans', 'licensing', 'subscribedSkus', {'status': 'failed'}),
])
def test_envelope_failure_status_still_withholds(complete_bundle, section, collector, name, metadata):
    rows = {'identity_governance': [SCHEDULE], 'licensing': [{'servicePlans': []}],
            'identity': [{'id': TENANT, 'displayName': PERSON, 'onPremisesImmutableId': None}]}[collector]
    operation(complete_bundle, collector, name, rows, **metadata)
    p = project_run(complete_bundle)
    assert p[section] == NOT_COLLECTED
    assert p.report['sections'][section]['detail'] == {'field': 'status', 'kind': 'unseen_enum_value'}


def test_normalised_envelope_failure_status_still_withholds(complete_bundle):
    write(complete_bundle, 'normalized/privileged_roles.json', {'records': ROLES, 'status': 'failed'})
    p = project_run(complete_bundle)
    assert p['privileged_roles'] == NOT_COLLECTED
    assert p.report['sections']['privileged_roles']['detail'] == {'field': 'status', 'kind': 'unseen_enum_value'}


def test_record_status_does_not_hide_an_envelope_error(complete_bundle):
    operation(complete_bundle, 'identity_governance', 'roleAssignmentSchedules', [SCHEDULE], error='Forbidden')
    p = project_run(complete_bundle)
    assert p['privileged_users'] == NOT_COLLECTED and p['privileged_roles'] == NOT_COLLECTED
    assert p.report['sections']['privileged_users']['reason'] == 'collector_error'
    assert p.report['sections']['privileged_users']['detail'] == {
        'error_class': 'unclassified', 'operation': 'identity_governance.roleAssignmentSchedules'}


POLICY_A, POLICY_B = '0a1b2c3d-1111-4222-8333-444455556666', '0a1b2c3d-1111-4222-8333-777788889999'
MANAGED_SESSION = {'signInFrequency': {'isEnabled': True, 'type': 'hours', 'value': 4, 'frequencyInterval': 'timeBased'},
                   'persistentBrowser': None}


def ca_section(root, rows):
    operation(root, 'conditional_access', 'conditionalAccessPolicies', rows)
    p = project_run(root, redact=False)
    return p['conditional_access_policies'], p.report['sections']['conditional_access_policies']


def ca_row(set_at=(), *, state='enabled', pid=None):
    row = graph({**CA, 'State': state})
    if pid:
        row['id'] = pid
    for path, value in set_at:
        target = row
        for key in path[:-1]:
            target = target.setdefault(key, {})
        target[path[-1]] = value
    return row


BLANK = [None, {}, [], '', {'applicationEnforcedRestrictions': None, 'signInFrequency': {'isEnabled': None}}]
RESTRICTIONS = [('sessionControls',), ('conditions', 'platforms'), ('conditions', 'locations'), ('conditions', 'devices'),
                ('conditions', 'users', 'includeGroups'), ('conditions', 'applications', 'applicationFilter'),
                ('conditions', 'users', 'includeGuestsOrExternalUsers')]


@pytest.mark.parametrize('path', RESTRICTIONS, ids='.'.join)
@pytest.mark.parametrize('value', BLANK, ids=lambda v: json.dumps(v)[:20])
def test_ca_null_or_empty_restriction_is_read_as_absent(complete_bundle, path, value):
    section, report = ca_section(complete_bundle, [ca_row([(path, value)])])
    assert section == [CA] and report['status'] == 'projected' and 'unsupported_conditions' not in report
    assert '.'.join(path) in report['ignored_fields']


@pytest.mark.parametrize('path', RESTRICTIONS, ids='.'.join)
@pytest.mark.parametrize('value', [{'include': ['restricted']}, ['x'], 'x', {'signInFrequency': {'isEnabled': False}}], ids=str)
def test_ca_populated_restriction_on_an_enabled_policy_still_withholds(complete_bundle, path, value):
    section, report = ca_section(complete_bundle, [ca_row(), ca_row([(path, value)], pid=POLICY_A)])
    assert section == NOT_COLLECTED and report['reason'] == 'incomplete_shape'
    assert report['unsupported_conditions'] == ['.'.join(path)] and 'dropped_conditions' not in report


@pytest.mark.parametrize('state', ['disabled', 'enabledForReportingButNotEnforced'])
def test_ca_policy_that_is_not_enabled_keeps_its_state_and_drops_unsupported_keys(complete_bundle, state):
    # AADConfig.rego: every Conditional Access base check requires State == "enabled", so no rule counts this policy.
    managed = ca_row([(('sessionControls',), MANAGED_SESSION), (('conditions', 'locations'), {'includeLocations': ['All']}),
                      (('conditions', 'newCondition'), {'mode': 'x'})], state=state, pid=POLICY_A)
    anonymous = ca_row([(('conditions', 'platforms'), {'includePlatforms': ['iOS']})], state=state)
    section, report = ca_section(complete_bundle, [managed, anonymous])
    assert section == [{**CA, 'State': state}, {**CA, 'State': state}] and report['status'] == 'projected'
    assert report['dropped_conditions'] == sorted([
        'policy1:conditions.platforms', f'{POLICY_A}:conditions.locations', f'{POLICY_A}:conditions.unrecognisedField',
        f'{POLICY_A}:sessionControls'])
    assert 'unsupported_conditions' not in report


def test_ca_microsoft_managed_policy_beside_a_kit_policy_gives_a_collected_section(complete_bundle):
    managed = ca_row([(('sessionControls',), MANAGED_SESSION)], state='disabled', pid=POLICY_B)
    managed['displayName'] = 'Microsoft-managed: Multifactor authentication for admins accessing Microsoft Admin Portals'
    section, report = ca_section(complete_bundle, [ca_row(pid=POLICY_A), managed])
    assert section == [CA, {**CA, 'State': 'disabled', 'DisplayName': managed['displayName']}]
    assert report['status'] == 'projected' and report['dropped_conditions'] == [f'{POLICY_B}:sessionControls']
    result = assess_run(complete_bundle, ModelConfig(model_name='stub'), policies=['MS.POWERBI.1.1v1'])
    validate_assessment(result)
    jsonschema.validate(result, json.loads((ROOT / 'schemas/model_assessment.schema.json').read_text()))
    assert result['projection']['sections']['conditional_access_policies']['dropped_conditions'] == [
        f'{POLICY_B}:sessionControls']


def test_ca_enabled_policy_still_withholds_beside_a_dropped_one(complete_bundle):
    disabled = ca_row([(('sessionControls',), MANAGED_SESSION)], state='disabled', pid=POLICY_A)
    enabled = ca_row([(('conditions', 'platforms'), {'includePlatforms': ['iOS']})], pid=POLICY_B)
    section, report = ca_section(complete_bundle, [disabled, enabled])
    assert section == NOT_COLLECTED and report['unsupported_conditions'] == ['conditions.platforms']
    assert 'dropped_conditions' not in report


def test_ca_invalid_state_of_a_policy_that_carries_a_restriction_still_withholds(complete_bundle):
    section, report = ca_section(complete_bundle, [ca_row([(('sessionControls',), MANAGED_SESSION)], state='unknown')])
    assert section == NOT_COLLECTED and report['detail'] == {'field': 'State', 'kind': 'unseen_enum_value'}


def test_ca_null_list_field_is_read_as_empty_and_recorded(complete_bundle):
    # Count(null) is 0, ContainsValue(null, _) is false and ConvertToSet(null) is set() in utils/KeyFunctions.rego; every
    # other read of these fields is an `in`, which is false for null as for []. Graph documents no nullability either way.
    row = ca_row([(('conditions', 'users', 'excludeRoles'), None), (('conditions', 'applications', 'excludeApplications'), None)])
    section, report = ca_section(complete_bundle, [row])
    assert section == [CA] and report['null_lists_read_as_empty'] == [
        'Conditions.Applications.ExcludeApplications', 'Conditions.Users.ExcludeRoles']
    # The projected value still has to be a shape the pack holds: a null that reads as an unseen empty list withholds.
    section, report = ca_section(complete_bundle, [ca_row([(('conditions', 'users', 'includeUsers'), None)])])
    assert section == NOT_COLLECTED and report['detail'] == {'field': '$', 'kind': 'unseen_shape'}
    assert 'null_lists_read_as_empty' not in report
    # Null on a scalar or an object-valued required field is no list: it is not read as empty.
    section, report = ca_section(complete_bundle, [ca_row([(('displayName',), None)])])
    assert section == NOT_COLLECTED and report['detail'] == {'field': 'DisplayName', 'kind': 'invalid_type'}


def test_ca_section_withheld_oversize_after_redaction_carries_no_record_keys(complete_bundle):
    # Redaction grows a short email (a@b.cc -> ***@b.cc) by two characters but shrinks the fixture's longer ExcludeUsers
    # address, so each policy name holds ten of them for a net growth; a section sitting exactly on the bound passes the
    # first size check and fails the second, and the record keys of a projected section must not outlive that flip.
    dropped = ca_row([(('sessionControls',), MANAGED_SESSION)], state='disabled', pid=POLICY_A)
    dropped['displayName'] = ' '.join(['a@b.cc'] * 10)
    kept = ca_row([(('conditions', 'users', 'excludeRoles'), None)], pid=POLICY_B)
    kept['displayName'] = ' '.join(['a@b.cc'] * 10)
    operation(complete_bundle, 'conditional_access', 'conditionalAccessPolicies', [dropped, kept])
    bound = len(json.dumps(project_run(complete_bundle, redact=False)['conditional_access_policies'],
                           sort_keys=True, separators=(',', ':'), ensure_ascii=False))
    projected = project_run(complete_bundle, redact=False, max_chars=bound)
    assert projected.report['sections']['conditional_access_policies']['status'] == 'projected'
    assert 'dropped_conditions' in projected.report['sections']['conditional_access_policies']
    assert 'null_lists_read_as_empty' in projected.report['sections']['conditional_access_policies']
    p = project_run(complete_bundle, max_chars=bound)
    report = p.report['sections']['conditional_access_policies']
    assert p['conditional_access_policies'] == NOT_COLLECTED
    assert report['status'] == 'not_collected' and report['reason'] == 'oversize'
    assert 'dropped_conditions' not in report and 'null_lists_read_as_empty' not in report
    result = assess_run(complete_bundle, ModelConfig(model_name='stub'), policies=['MS.POWERBI.1.1v1'],
                        projection_max_chars=bound)
    validate_assessment(result)
    jsonschema.validate(result, json.loads((ROOT / 'schemas/model_assessment.schema.json').read_text()))


@pytest.mark.parametrize('name,value', [('dropped_conditions', [f'{POLICY_A}:sessionControls']),
                                        ('null_lists_read_as_empty', ['Conditions.Users.ExcludeRoles'])])
def test_ca_record_keys_validate(complete_bundle, name, value):
    result = assess_run(complete_bundle, ModelConfig(model_name='stub'), policies=['MS.POWERBI.1.1v1'])
    sections = result['projection']['sections']
    sections['conditional_access_policies'][name] = value
    validate_assessment(result)
    sections['conditional_access_policies'][name] = value[:] * 2
    with pytest.raises(ValueError):
        validate_assessment(result)
    sections['conditional_access_policies'][name] = value
    sections['service_plans'][name] = value
    with pytest.raises(ValueError):
        validate_assessment(result)
    del sections['service_plans'][name]
    sections['conditional_access_policies'][name] = [PERSON]
    with pytest.raises(ValueError):
        validate_assessment(result)


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
    ('privileged_roles', 'normalized/privileged_roles.json', ('records', 0)),
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
    report = p.report['sections'][section]
    if section == 'conditional_access_policies':
        # A populated unknown field inside the conditions can narrow the policy: it still withholds.
        assert p[section] == NOT_COLLECTED and report['reason'] == 'incomplete_shape'
        assert report['unsupported_conditions'] == ['conditions.applications.unrecognisedField']
    elif section == 'privileged_roles':
        # A populated unknown field on a role or assignment can scope it: it withholds and is named, never its value.
        prefix = 'Assignments.' if len(keys) > 2 else ''
        assert p[section] == NOT_COLLECTED and report['reason'] == 'incomplete_shape'
        assert report['detail'] == {'field': prefix + 'UnexpectedPersonName', 'kind': 'unexpected_field'}
    else:
        # Elsewhere an extra field is ignored: the section projects without it and the report names it, never its value.
        assert p[section] != NOT_COLLECTED and report['status'] == 'projected'
        assert report['ignored_fields'] == ['UnexpectedPersonName']
    assert 'Injected Private Person' not in canonical([
        build_case(pid, p, 'test') for pid in policy_catalogue()['policies']])
    assert 'Injected Private Person' not in canonical(p.report)


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


def test_chunk_iteration_stops_at_scan_row_and_byte_bounds(complete_bundle, monkeypatch):
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
            # Every open starts the file afresh: scuba_config reads the SKUs too (its cloud signal) before service_plans.
            data.seek(0)
            data.calls = 0
            yield data
        else:
            with original(root, relative) as handle:
                yield handle
    monkeypatch.setattr(projection, '_open_chunk', opened)
    operation(complete_bundle, 'licensing', 'subscribedSkus', [],
              chunk_files=['raw/licensing/subscribedSkus/part-00001.jsonl'], item_count=100000)
    p = project_run(complete_bundle, scan_max_rows=1)
    section = p.report['sections']['service_plans']
    assert section['reason'] == 'oversize' and section['detail'] == {'field': 'scan_max_rows', 'kind': 'scan_bound'}
    assert section['scan']['rows'] == 1
    assert data.calls == 2 and data.tell() < 100
    data.calls = 0
    data.seek(0)
    data.write(b'x' * 10000)
    data.seek(0)
    p = project_run(complete_bundle, scan_max_bytes=400)
    section = p.report['sections']['service_plans']
    assert section['reason'] == 'oversize' and section['detail'] == {'field': 'scan_max_bytes', 'kind': 'scan_bound'}
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


def _frozen_pack_goldens(pack):
    """Reconstruct complete shape witnesses directly from the two read-only JSONL files.

    The derivation is scripts/derive-scuba-projection-shapes.py, the one used for any later pack too.
    """
    import importlib.util
    path = ROOT / 'scripts/derive-scuba-projection-shapes.py'
    spec = importlib.util.spec_from_file_location('derive_scuba_projection_shapes', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.derive(pack)


def test_complete_shape_goldens_reproduce_both_frozen_packs():
    pack = os.environ.get('AUDITEX_TEST_PROJECTION_PACK')
    if not pack:
        pytest.skip('AUDITEX_TEST_PROJECTION_PACK unset; opt in to frozen v7 shape tests')
    pack = Path(pack)
    if not all((pack / name).is_file() for name in ('train.jsonl', 'test.jsonl')):
        pytest.skip('Frozen v7 train/test pack files not present at AUDITEX_TEST_PROJECTION_PACK')
    assert _frozen_pack_goldens(pack) == PACK_SHAPES


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
    diagnostic = p.report['sections']['conditional_access_policies']['detail']
    assert diagnostic == {
        'field': ('Conditions.Applications.IncludeUserActions' if path == 'applications'
                  else 'GrantControls.AuthenticationStrength.AllowedCombinations'),
        'kind': 'unseen_enum_value'}


def test_authorisation_permissions_reject_unexpected_nested_fields(complete_bundle):
    path = 'raw/consent_policy.json'
    data = json.loads((complete_bundle / path).read_text())
    data['authorizationPolicy']['value'][0]['defaultUserRolePermissions'].update(
        allowedToCreateSecurityGroups=True, allowedToReadOtherUsers=False, unexpectedPerson=PERSON)
    write(complete_bundle, path, data)
    p = project_run(complete_bundle)
    # An extra permission is ignored and named; a key that is not an identifier is masked, its value never echoed.
    assert p['authorization_policies'] == [AUTH]
    assert p.report['sections']['authorization_policies']['ignored_fields'] == ['DefaultUserRolePermissions.unexpectedPerson']
    assert PERSON not in canonical(p.report) and PERSON not in canonical(p)


def test_authorisation_known_irrelevant_permissions_are_dropped(complete_bundle):
    path = 'raw/consent_policy.json'
    data = json.loads((complete_bundle / path).read_text())
    data['authorizationPolicy']['value'][0]['defaultUserRolePermissions'].update(
        allowedToCreateSecurityGroups=True, allowedToReadOtherUsers=False)
    write(complete_bundle, path, data)
    p = project_run(complete_bundle)
    assert p['authorization_policies'] == [AUTH]
    assert 'detail' not in p.report['sections']['authorization_policies']


@pytest.mark.parametrize('redact', [True, False])
@pytest.mark.parametrize('value', [PERSON, EMAIL, 'Alice', 'Free text with confidential details'])
def test_enum_diagnostic_never_echoes_person_or_free_text(complete_bundle, value, redact):
    path = 'raw/consent_policy.json'
    data = json.loads((complete_bundle / path).read_text())
    data['authorizationPolicy']['value'][0]['allowInvitesFrom'] = value
    write(complete_bundle, path, data)
    p = project_run(complete_bundle, redact=redact)
    assert p.report['sections']['authorization_policies']['detail'] == {
        'field': 'AllowInvitesFrom', 'kind': 'unseen_enum_value'}
    assert value not in canonical(p.report)


@pytest.mark.parametrize('mutation,expected', [
    ('missing', {'field': 'DefaultUserRolePermissions.AllowedToCreateApps', 'kind': 'missing_field'}),
    ('type', {'field': 'DefaultUserRolePermissions.AllowedToCreateApps', 'kind': 'invalid_type'}),
    ('key', None),
])
def test_nested_diagnostic_paths_do_not_echo_person_data(complete_bundle, mutation, expected):
    path = 'raw/consent_policy.json'
    data = json.loads((complete_bundle / path).read_text())
    permissions = data['authorizationPolicy']['value'][0]['defaultUserRolePermissions']
    if mutation == 'missing':
        del permissions['allowedToCreateApps']
    elif mutation == 'type':
        permissions['allowedToCreateApps'] = PERSON
    else:
        permissions[PERSON] = EMAIL
    write(complete_bundle, path, data)
    p = project_run(complete_bundle)
    assert p.report['sections']['authorization_policies'].get('detail') == expected
    if mutation == 'key':
        # A key that is not an identifier is ignored under a masked name.
        assert p.report['sections']['authorization_policies']['ignored_fields'] == [
            'DefaultUserRolePermissions.unrecognisedField']
    assert PERSON not in canonical(p.report) and EMAIL not in canonical(p.report)


def test_numeric_enum_diagnostic_and_optional_detail_validate(complete_bundle):
    operation(complete_bundle, 'sharepoint_access', 'sharePointSettings', [{**SPO, 'FileAnonymousLinkType': 99}])
    result = assess_run(complete_bundle, ModelConfig(model_name='stub'), policies=['MS.POWERBI.1.1v1'])
    assert result['projection']['sections']['SPO_tenant']['detail'] == {
        'field': 'FileAnonymousLinkType', 'kind': 'unseen_enum_value', 'value': 99}
    schema = json.loads((ROOT / 'schemas/model_assessment.schema.json').read_text())
    validate_assessment(result)
    jsonschema.validate(result, schema)
    for section in result['projection']['sections'].values():
        section.pop('detail', None)
    validate_assessment(result)
    jsonschema.validate(result, schema)


@pytest.mark.parametrize('diagnostic', [
    {}, {'field': 'AllowInvitesFrom', 'kind': 'unknown'},
    {'field': PERSON, 'kind': 'invalid_type'},
    {'field': 'AllowInvitesFrom', 'kind': 'unseen_enum_value', 'value': PERSON},
    {'field': 'AllowInvitesFrom', 'kind': 'unseen_enum_value', 'value': True},
    {'field': 'AllowInvitesFrom', 'kind': 'unseen_enum_value', 'value': {'displayName': PERSON}},
    {'field': 'AllowInvitesFrom', 'kind': 'missing_field', 'extra': PERSON},
])
def test_projection_diagnostic_both_validators_reject_malformed_detail(complete_bundle, diagnostic):
    result = assess_run(complete_bundle, ModelConfig(model_name='stub'), policies=['MS.POWERBI.1.1v1'])
    result['projection']['sections']['scuba_config']['detail'] = diagnostic
    with pytest.raises(ValueError):
        validate_assessment(result)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(result, json.loads((ROOT / 'schemas/model_assessment.schema.json').read_text()))


@pytest.mark.parametrize('section,diagnostic', [
    ('SPO_tenant', {'field': 'FileAnonymousLinkType', 'kind': 'missing_field'}),
    ('scuba_config', {'field': 'AllowInvitesFrom', 'kind': 'missing_field', 'value': 'everyone'}),
    ('scuba_config', {'field': 'DisplayName', 'kind': 'unseen_enum_value', 'value': 'everyone'}),
])
def test_projection_diagnostic_validation_rejects_inconsistent_detail(complete_bundle, section, diagnostic):
    result = assess_run(complete_bundle, ModelConfig(model_name='stub'), policies=['MS.POWERBI.1.1v1'])
    result['projection']['sections'][section]['detail'] = diagnostic
    with pytest.raises(ValueError):
        validate_assessment(result)


@pytest.mark.parametrize('metadata', [{'complete': False}, {'status': 'failed'}, {'collection_status': 'not_collected'}])
def test_empty_collection_success_cannot_override_failure_metadata(complete_bundle, metadata):
    operation(complete_bundle, 'licensing', 'subscribedSkus', [], **metadata)
    assert project_run(complete_bundle)['service_plans'] == NOT_COLLECTED


def test_malformed_manifest_cannot_hide_coverage_failures(complete_bundle):
    from azure_tenant_audit.run_files import UnsafeRunFileError
    (complete_bundle / 'run-manifest.json').write_text('{"coverage_gaps":')
    with pytest.raises(UnsafeRunFileError):
        project_run(complete_bundle)


@pytest.mark.parametrize('raw', [
    '{"run_id":"synthetic-run","platform":"m365","extra":1e999}',          # float overflow to inf
    '{"run_id":"synthetic-run","platform":"m365","extra":-1e999}',
    '{"run_id":"synthetic-run","platform":"m365","extra":"\\ud800"}',        # lone surrogate
    '{"run_id":"synthetic-run","platform":"m365","\\udc00":1}',              # lone surrogate in a key
    '{"run_id":"synthetic-run","platform":"m365","extra":[[[1e999]]]}',    # nested
])
def test_unserialisable_manifest_withholds_instead_of_raising(complete_bundle, raw):
    (complete_bundle / 'run-manifest.json').write_text(raw)
    projection = project_run(complete_bundle)
    assert all(v == NOT_COLLECTED for v in projection.values())
    assert projection.report['sections']['tenant_id']['reason'] == 'incomplete_shape'
    assert projection.report['redaction']['enabled'] is True


def test_unserialisable_manifest_withholds_without_redaction(complete_bundle):
    (complete_bundle / 'run-manifest.json').write_text('{"extra":1e999}')
    assert all(v == NOT_COLLECTED for v in project_run(complete_bundle, redact=False).values())


def test_manifest_nested_beyond_the_parser_depth_is_refused(complete_bundle):
    from azure_tenant_audit.run_files import UnsafeRunFileError
    (complete_bundle / 'run-manifest.json').write_text('[' * 100000 + ']' * 100000)
    with pytest.raises(UnsafeRunFileError):
        project_run(complete_bundle)


def test_manifest_with_a_huge_integer_is_refused(complete_bundle):
    from azure_tenant_audit.run_files import UnsafeRunFileError
    # Pin: already withheld at parse (int max str digits); not part of the salt fix.
    (complete_bundle / 'run-manifest.json').write_text('{"run_id":"x","platform":"m365","n":' + '9' * 5000 + '}')
    with pytest.raises(UnsafeRunFileError):
        project_run(complete_bundle)


def test_manifest_gaps_deeper_than_the_walkers_are_withheld_not_raised(complete_bundle):
    (complete_bundle / 'run-manifest.json').write_text('{"platform":"m365","coverage_gaps":' + '[' * 1500 + '"a"' + ']' * 1500 + '}')
    projection = project_run(complete_bundle)
    assert all(v == NOT_COLLECTED for v in projection.values())
    assert projection.report['sections']['tenant_id']['reason'] == 'incomplete_shape'


def test_deep_raw_envelope_is_withheld_not_raised(complete_bundle):
    operation(complete_bundle, 'identity', 'other', json.loads('[' * 1500 + ']' * 1500))
    assert project_run(complete_bundle).report['sections']['privileged_users']['reason'] == 'incomplete_shape'


def test_deep_normalised_file_is_withheld_not_raised(complete_bundle):
    write(complete_bundle, 'normalized/privileged_roles.json', {'records': [json.loads('{"a":' * 1500 + '1' + '}' * 1500)]})
    assert project_run(complete_bundle).report['sections']['privileged_roles']['reason'] == 'incomplete_shape'


def test_deep_coverage_row_is_withheld_not_raised(complete_bundle):
    write(complete_bundle, 'coverage.json', [{'collector': 'identity', 'name': 'users', 'status': 'ok', 'x': json.loads('[' * 1500 + ']' * 1500)}])
    projection = project_run(complete_bundle)
    assert projection.report['sections']['privileged_users']['reason'] == 'incomplete_shape'


def test_chunk_row_nested_too_deep_is_withheld_not_raised(complete_bundle):
    raw = json.loads((complete_bundle / 'raw/identity.json').read_text())
    raw['users'] = {'status': 'ok', 'chunk_files': ['chunks/identity/users-0.jsonl']}
    write(complete_bundle, 'raw/identity.json', raw)
    (complete_bundle / 'chunks/identity').mkdir(parents=True, exist_ok=True)
    (complete_bundle / 'chunks/identity/users-0.jsonl').write_text('{"id":"a","x":' + '[' * 1500 + ']' * 1500 + '}\n')
    report = project_run(complete_bundle).report['sections']['privileged_users']
    assert report['reason'] == 'incomplete_shape' and report['detail']['field'] == 'chunk_files'


def test_nested_but_legal_depth_still_projects_identically(complete_bundle):
    deep = json.loads('[' * 14 + ']' * 14)
    baseline = dict(project_run(complete_bundle))
    operation(complete_bundle, 'identity', 'other', deep)
    write(complete_bundle, 'coverage.json', [{'collector': 'identity', 'name': 'users', 'status': 'ok', 'x': deep}])
    nested = dict(project_run(complete_bundle))
    assert nested == baseline and nested['privileged_users'] != NOT_COLLECTED


def test_depth_bound_is_exactly_64_containers(complete_bundle):
    from auditex.scuba_projection import _MAX_DEPTH, _shallow
    assert _MAX_DEPTH == 64
    for nest in (lambda n: json.loads('[' * n + ']' * n), lambda n: json.loads('{"a":' * (n - 1) + '{}' + '}' * (n - 1))):
        assert _shallow(nest(64)) and not _shallow(nest(65))
    # raw/identity.json wraps the operation value in 2 containers: 62 inner levels is 64 in the file, 63 is 65.
    operation(complete_bundle, 'identity', 'other', json.loads('[' * 62 + ']' * 62))
    assert project_run(complete_bundle)['privileged_users'] != NOT_COLLECTED
    operation(complete_bundle, 'identity', 'other', json.loads('[' * 63 + ']' * 63))
    assert project_run(complete_bundle).report['sections']['privileged_users']['reason'] == 'incomplete_shape'


def test_manifest_depth_bound_is_exactly_64_containers(complete_bundle):
    manifest = json.loads((complete_bundle / 'run-manifest.json').read_text())
    # The manifest root is level 1, so 63 nested levels under an unrelated key reach 64 and 64 levels reach 65.
    write(complete_bundle, 'run-manifest.json', {**manifest, 'extra': json.loads('[' * 63 + ']' * 63)})
    assert project_run(complete_bundle)['tenant_id'] != NOT_COLLECTED
    write(complete_bundle, 'run-manifest.json', {**manifest, 'extra': json.loads('[' * 64 + ']' * 64)})
    projection = project_run(complete_bundle)
    assert projection['tenant_id'] == NOT_COLLECTED
    assert projection.report['sections']['tenant_id']['reason'] == 'incomplete_shape'


def test_chunk_row_depth_bound_is_exactly_64_containers(complete_bundle):
    path = 'raw/licensing/subscribedSkus/part-00001.jsonl'
    target = complete_bundle / path
    target.parent.mkdir(parents=True)
    row = {'skuPartNumber': 'SPE_E5', 'servicePlans': [{**graph(EXPECTED['service_plans'][0]), 'provisioningStatus': 'Success'}]}
    operation(complete_bundle, 'licensing', 'subscribedSkus', [], chunk_files=[path], item_count=1)
    # The row object is level 1, so 63 nested levels under an unrelated key reach 64 and 64 levels reach 65.
    target.write_text(json.dumps({**row, 'x': json.loads('[' * 63 + ']' * 63)}) + '\n')
    assert project_run(complete_bundle)['service_plans'] != NOT_COLLECTED
    target.write_text(json.dumps({**row, 'x': json.loads('[' * 64 + ']' * 64)}) + '\n')
    projection = project_run(complete_bundle)
    assert projection['service_plans'] == NOT_COLLECTED
    assert projection.report['sections']['service_plans']['detail']['field'] == 'chunk_files'


def test_normal_manifest_salt_and_output_are_unchanged(complete_bundle, monkeypatch):
    # Hermetic: the frozen output hash covers the built-in adapters only; area adapter modules have their own tests.
    monkeypatch.setattr('auditex.scuba_projection.AREA_ADAPTER_MODULES', ())
    projection = project_run(complete_bundle)
    manifest = json.loads((complete_bundle / 'run-manifest.json').read_text())
    salt = sha256(json.dumps(manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
    assert salt == 'fed5fb19ba49484bd4e1106e433bfbb4192030f0ff496f2474fb051a39fca1b6'
    pseudonym = 'User ' + sha256((salt + '\0' + PERSON).encode()).hexdigest()[:16]
    assert pseudonym in json.dumps(projection['privileged_users'])
    # sharing_policy is no longer withheld unconditionally: without a sharingPolicy operation it is missing_artifact.
    assert sha256(canonical([dict(projection), projection.report, projection.views]).encode()).hexdigest() == '3050ddbe748d9ae332422c070b1ed1d5cfd5b8a4640913e5087060e40dcf56af'


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


def test_chunk_whitespace_and_chunk_count_are_scan_bounded(complete_bundle, monkeypatch):
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
            data.seek(0)  # Every open starts afresh: scuba_config reads the SKUs before service_plans.
            yield Guarded()
        else:
            with original(root, relative) as handle:
                yield handle
    monkeypatch.setattr(projection, '_open_chunk', opened)
    operation(complete_bundle, 'licensing', 'subscribedSkus', [],
              chunk_files=['raw/licensing/subscribedSkus/a.jsonl'], item_count=1)
    p = project_run(complete_bundle, scan_max_bytes=400)
    section = p.report['sections']['service_plans']
    assert section['reason'] == 'oversize' and section['detail'] == {'field': 'scan_max_bytes', 'kind': 'scan_bound'}
    assert data.tell() == 401
    data.seek(0)
    operation(complete_bundle, 'licensing', 'subscribedSkus', [],
              chunk_files=['raw/licensing/subscribedSkus/a.jsonl', 'raw/licensing/subscribedSkus/b.jsonl'])
    section = project_run(complete_bundle, scan_max_chunks=1).report['sections']['service_plans']
    assert section['reason'] == 'oversize' and section['detail'] == {'field': 'scan_max_chunks', 'kind': 'scan_bound'}
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


@pytest.mark.parametrize('extra', [{'provisioningStatus': 'unseenStatus'}, {'appliesTo': 'unseenScope'}])
def test_service_plan_nested_fields_are_explicitly_validated(complete_bundle, extra):
    plan = {**graph(EXPECTED['service_plans'][0]), 'provisioningStatus': 'Success', **extra}
    operation(complete_bundle, 'licensing', 'subscribedSkus', [{'servicePlans': [plan]}])
    p = project_run(complete_bundle)
    assert p['service_plans'] == NOT_COLLECTED
    assert p.report['sections']['service_plans']['reason'] == 'incomplete_shape'
    field = next(iter(extra))
    assert p.report['sections']['service_plans']['detail'] == {'field': 'servicePlans.' + field, 'kind': 'unseen_enum_value'}


@pytest.mark.parametrize('extra,ignored', [
    ({'servicePlanType': 'Standard'}, ['servicePlans.servicePlanType']),
    ({'unexpectedPerson': 'Injected Private Person'}, ['servicePlans.unexpectedPerson']),
    ({PERSON: 'Injected Private Person', 'servicePlanType': 'Standard'}, ['servicePlans.servicePlanType', 'servicePlans.unrecognisedField']),
])
def test_service_plan_extra_fields_are_ignored_and_reported(complete_bundle, extra, ignored):
    # Field presence depends on the token (a delegated token returns servicePlanType, the Azure CLI one does not): an extra
    # field is not a tenant property, so it never withholds. Its name is recorded; its value never leaves the source.
    plan = {**graph(EXPECTED['service_plans'][0]), 'provisioningStatus': 'Success', **extra}
    operation(complete_bundle, 'licensing', 'subscribedSkus', [{'servicePlans': [plan]}])
    p = project_run(complete_bundle)
    assert p['service_plans'] == EXPECTED['service_plans']
    section = p.report['sections']['service_plans']
    assert section['status'] == 'projected' and section['ignored_fields'] == ignored
    assert 'Injected Private Person' not in canonical(p) and 'Injected Private Person' not in canonical(p.report)
    result = assess_run(complete_bundle, ModelConfig(model_name='stub'), policies=['MS.POWERBI.1.1v1'])
    assert result['projection']['sections']['service_plans']['ignored_fields'] == ignored
    validate_assessment(result)


def test_missing_role_rule_field_diagnostic(complete_bundle):
    roles = json.loads(json.dumps(ROLES))
    del roles[0]['Rules'][0]['RuleSourceType']
    write(complete_bundle, 'normalized/privileged_roles.json', {'records': roles})
    assert project_run(complete_bundle).report['sections']['privileged_roles']['detail'] == {
        'field': 'Rules.RuleSourceType', 'kind': 'missing_field'}


# --- Projection budget applies to the projected section; the source read has scan bounds ---------------------

def many_users(root, count=500, admins=3, chunked=False):
    """A large synthetic user list with a few administrators; returns the administrators' ids in sorted order."""
    ids = [f'00000000-0000-4000-8000-{n:012d}' for n in range(count)]
    users = [{'id': i, 'displayName': f'Synthetic Person {n}', 'userPrincipalName': f'person{n}@example.invalid',
              'jobTitle': 'Synthetic analyst', 'department': 'Operations', 'userType': 'Member', 'accountEnabled': True,
              'onPremisesImmutableId': None} for n, i in enumerate(ids)]
    if chunked:
        paths = []
        for part, start in enumerate(range(0, count, count // 2), 1):
            path = f'raw/identity/users/part-{part:05d}.jsonl'
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(''.join(canonical(u) + '\n' for u in users[start:start + count // 2]))
            paths.append(path)
        operation(root, 'identity', 'users', users[:5], chunk_files=paths, chunk_count=len(paths), item_count=count,
                  sample_truncated=True)
    else:
        operation(root, 'identity', 'users', users)
    admin_ids = ids[7::count // admins][:admins]
    write(root, 'normalized/effective_admin_set.json', {'records': [
        {'kind': 'effective_admin_set_summary', 'state': 'complete', 'unresolved_principal_count': 0, 'admin_count': admins},
        *[{'kind': 'effective_admin', 'state': 'complete', 'is_user': True, 'principal_id': i,
           'role_names': ['Global Administrator'], 'roles': [GLOBAL_ADMIN_ROLE]} for i in admin_ids]]})
    return admin_ids


@pytest.mark.parametrize('chunked', [False, True])
def test_privileged_users_projects_from_a_large_user_list_within_the_default_budget(complete_bundle, monkeypatch, chunked):
    from auditex.scuba_projection import Bundle, DEFAULT_MAX_CHARS, DEFAULT_MAX_ITEMS
    admin_ids = many_users(complete_bundle, chunked=chunked)
    original = Bundle.operation
    def guarded(self, collector, name):
        assert (collector, name) != ('identity', 'users'), 'the user list must be streamed, not materialised'
        return original(self, collector, name)
    monkeypatch.setattr(Bundle, 'operation', guarded)
    p = project_run(complete_bundle, redact=False)
    section = p.report['sections']['privileged_users']
    assert section['status'] == 'projected' and section['reason'] is None
    assert list(p['privileged_users']) == ['User1', 'User2', 'User3']
    assert [u['DisplayName'] for u in p['privileged_users'].values()] == [
        f'Synthetic Person {int(i[-12:])}' for i in admin_ids]
    # The source is far over the budget; the projected section is well inside it.
    assert section['scan']['rows'] == 500 > DEFAULT_MAX_ITEMS
    assert section['scan']['bytes'] > DEFAULT_MAX_CHARS
    assert section['scan']['chunks'] == (2 if chunked else 0)
    assert len(canonical(p['privileged_users'])) < DEFAULT_MAX_CHARS
    assert p.report['bounds'] == {'max_items': 40, 'max_chars': 12000, 'scan_max_rows': 250000,
                                  'scan_max_bytes': 268435456, 'scan_max_chunks': 10000}
    assert 'ignored_failures' not in section


@pytest.mark.parametrize('count,page_size,admin_positions', [
    (99, None, (1,)), (100, None, (1, 100)), (101, None, (1, 100, 101)),
    (5000, None, (1, 100, 101, 4999)),
    (50_001, 100, (1, 100, 101, 50_001)),
    (25_001, 50, (1, 100, 101, 25_001)),
])
def test_paged_identity_users_keep_late_admins_on_the_model_path(complete_bundle, monkeypatch, count, page_size, admin_positions):
    """The hybrid collector's first-100 sample includes guests and cannot supply late admins."""
    users = [
        {'id': f'00000000-0000-4000-8000-{position:012d}',
         'displayName': f'Mocktenant user {position}',
         'userType': 'Guest' if position % 7 == 0 else 'Member',
         'onPremisesImmutableId': f'mocktenant-immutable-{position}'}
        for position in range(1, count + 1)
    ]
    ids = [users[position - 1]['id'] for position in admin_positions]

    class PagedClient:
        def iter_pages(self, endpoint, params=None):
            if endpoint == '/users' and params['$select'] != 'id,signInActivity':
                selected = set(params['$select'].split(','))
                request_size = int(params['$top'])
                assert request_size == (100 if page_size in (50, 100) else 500)
                for start in range(0, count, request_size):
                    yield {'value': [{key: value for key, value in row.items() if key in selected}
                                     for row in users[start:start + request_size]],
                           **({'@odata.nextLink': 'https://graph.microsoft.com/v1.0/users?next=mocktenant'}
                              if start + request_size < count else {})}
            elif endpoint == '/roleManagement/directory/roleAssignments':
                yield {'value': [{'id': f'assignment-{i}', 'principalId': principal,
                                  'roleDefinitionId': 'role-global', 'directoryScopeId': '/'}
                                 for i, principal in enumerate(ids)]}
            else:
                yield {'value': []}

        def iter_items(self, endpoint, params=None, result_limit=None):
            for page in self.iter_pages(endpoint, params):
                yield from page['value']

        def get_json(self, endpoint, params=None, full_url=False):
            assert endpoint == '/organization'
            return {'value': [{'id': TENANT}]}

    def chunk_writer(collector, name, page_number, rows, metadata):
        path = f'raw/{collector}/{name}/part-{page_number:05d}.jsonl'
        target = complete_bundle / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(''.join(canonical(row) + '\n' for row in rows))
        return path

    result = IdentityCollector().run({'client': PagedClient(), 'top': None, 'page_size': page_size,
                                      'chunk_writer': chunk_writer, 'run_dir': complete_bundle})
    assert result.status == 'ok'
    assert result.payload['users']['item_count'] == count
    request_size = 100 if page_size in (50, 100) else 500
    assert result.payload['users']['chunk_count'] == (count + request_size - 1) // request_size
    write(complete_bundle, 'raw/identity.json', result.payload)
    operation(complete_bundle, 'domains_hybrid', 'syncSampleUsers', users[:100])
    write(complete_bundle, 'normalized/effective_admin_set.json', {'records': [
        {'kind': 'effective_admin_set_summary', 'state': 'complete', 'unresolved_principal_count': 0,
         'admin_count': len(ids)},
        *[{'kind': 'effective_admin', 'state': 'complete', 'is_user': True, 'principal_id': principal,
           'role_names': ['Global Administrator'], 'roles': [GLOBAL_ADMIN_ROLE]}
          for principal in ids],
    ]})

    projection = project_run(complete_bundle, redact=False)
    section = projection.report['sections']['privileged_users']
    assert section['status'] == 'projected' and section['reason'] is None
    assert section['scan']['rows'] == count
    assert sum(row['userType'] == 'Guest' for row in users) == count // 7
    assert {item['OnPremisesImmutableId'] for item in projection['privileged_users'].values()} == {
        f'mocktenant-immutable-{position}' for position in admin_positions}
    for policy_id in ('MS.AAD.7.1v1', 'MS.AAD.7.2v1', 'MS.AAD.7.3v1'):
        assert precheck_case(build_case(policy_id, projection, '2026-11-04'),
                             absent_fields=True, empty_lists=True) is None

    if count == 5000:
        monkeypatch.setattr('azure_tenant_audit.collectors.identity.USER_MAX_ROWS', 500)
        capped = IdentityCollector().run({'client': PagedClient(), 'top': None,
                                          'chunk_writer': chunk_writer, 'run_dir': complete_bundle})
        assert capped.status == 'partial'
        assert capped.payload['users']['item_count'] == 500
        assert capped.payload['users']['collection_truncated'] is True
        assert capped.payload['users']['truncation_reason'] == 'pagination_not_followed'
        write(complete_bundle, 'raw/identity.json', capped.payload)
        write(complete_bundle, 'coverage.json', {'records': capped.coverage})
        limited = project_run(complete_bundle)
        assert limited.report['sections']['privileged_users']['status'] == 'not_collected'
        assert limited.report['sections']['privileged_users']['reason'] == 'collector_error'
        for policy_id in ('MS.AAD.7.1v1', 'MS.AAD.7.2v1', 'MS.AAD.7.3v1'):
            response = precheck_case(build_case(policy_id, limited, '2026-11-04'),
                                     absent_fields=True, empty_lists=True)
            assert response['claims'][0]['status'] == 'unknown'
            assert 'required_evidence_section_not_collected' in response['limitations']

        write(complete_bundle, 'raw/identity.json', result.payload)
        write(complete_bundle, 'coverage.json', {'records': result.coverage})
        bounded = assess_run(complete_bundle, ModelConfig(model_name='stub'),
                             policies=['MS.AAD.7.1v1', 'MS.AAD.7.2v1', 'MS.AAD.7.3v1'],
                             projection_scan_max_rows=100)
        withheld = bounded['projection']['sections']['privileged_users']
        assert withheld['status'] == 'not_collected' and withheld['reason'] == 'oversize'
        assert withheld['detail'] == {'field': 'scan_max_rows', 'kind': 'scan_bound'}
        for row in bounded['policies']:
            assert row['comparison']['result'] == 'not_assessed'
            assert row['reason'] == 'rule_precheck' and row['attempts'] == 0
            assert row['claims'][0]['status'] == 'unknown' and row['claims'][0]['value'] is None
            assert 'required_evidence_section_not_collected' in row['limitations']


@pytest.mark.parametrize('chunked,bound,value', [
    (False, 'scan_max_rows', 100), (False, 'scan_max_bytes', 5000),
    (True, 'scan_max_rows', 100), (True, 'scan_max_bytes', 5000), (True, 'scan_max_chunks', 1)])
def test_scan_bound_withholds_as_oversize_and_names_the_bound(complete_bundle, chunked, bound, value):
    many_users(complete_bundle, chunked=chunked)
    p = project_run(complete_bundle, **{bound: value})
    section = p.report['sections']['privileged_users']
    assert p['privileged_users'] == NOT_COLLECTED
    assert section['status'] == 'not_collected' and section['reason'] == 'oversize'
    assert section['detail'] == {'field': bound, 'kind': 'scan_bound'}
    if bound == 'scan_max_rows':
        assert section['scan']['rows'] == value
    # Sections that never read the user list are unaffected.
    assert p.report['sections']['service_plans']['status'] == 'projected'


def test_a_user_row_without_an_id_or_a_duplicate_administrator_row_withholds(complete_bundle):
    admin_ids = many_users(complete_bundle)
    users = json.loads((complete_bundle / 'raw/identity.json').read_text())
    rows = users['users']['value']
    users['users']['value'] = rows + [dict(rows[int(admin_ids[0][-12:])])]
    write(complete_bundle, 'raw/identity.json', users)
    assert project_run(complete_bundle)['privileged_users'] == NOT_COLLECTED
    users['users']['value'] = rows + [{k: v for k, v in rows[0].items() if k != 'id'}]
    write(complete_bundle, 'raw/identity.json', users)
    assert project_run(complete_bundle)['privileged_users'] == NOT_COLLECTED


@pytest.mark.parametrize('bounds', [{'max_items': 2}, {'max_chars': 150}])
def test_projected_object_bound_still_withholds_an_oversize_section(complete_bundle, bounds):
    many_users(complete_bundle)
    p = project_run(complete_bundle, redact=False, **bounds)
    section = p.report['sections']['privileged_users']
    assert p['privileged_users'] == NOT_COLLECTED
    assert section['reason'] == 'oversize' and 'detail' not in section
    assert section['scan']['rows'] == 500
    assert p.report['sections']['tenant_id']['status'] == 'projected'


def test_service_plans_stream_a_source_far_larger_than_the_budget(complete_bundle):
    plans = [{'servicePlanId': f'00000000-0000-4000-8000-0000000000{n:02d}', 'servicePlanName': f'PLAN_{n}',
              'provisioningStatus': 'Success', 'appliesTo': 'User'} for n in range(5)]
    skus = [{'id': f'sku-{n}', 'skuPartNumber': f'SKU_{n}', 'consumedUnits': n, 'capabilityStatus': 'Enabled',
             'prepaidUnits': {'enabled': 100, 'suspended': 0, 'warning': 0}, 'servicePlans': plans} for n in range(100)]
    assert len(canonical(skus)) > 12000 and len(skus) > 40
    operation(complete_bundle, 'licensing', 'subscribedSkus', skus)
    p = project_run(complete_bundle)
    assert [r['ServicePlanName'] for r in p['service_plans']] == [f'PLAN_{n}' for n in range(5)]
    assert p.report['sections']['service_plans']['scan']['rows'] == 100


@pytest.mark.parametrize('bounds', [{'scan_max_rows': 0}, {'scan_max_bytes': -1}, {'scan_max_chunks': True}])
def test_invalid_scan_bounds_are_refused(complete_bundle, bounds):
    with pytest.raises(ValueError, match='positive integers'):
        project_run(complete_bundle, **bounds)


def test_oversized_manifest_reports_the_scan_bound_not_a_shape_failure(complete_bundle):
    p = project_run(complete_bundle, scan_max_bytes=50)
    assert all(v == NOT_COLLECTED for v in p.values())
    assert {s['detail']['kind'] for s in p.report['sections'].values()} == {'scan_bound'}


def test_scan_fields_and_detail_validate_in_both_validators(complete_bundle):
    many_users(complete_bundle)
    result = assess_run(complete_bundle, ModelConfig(model_name='stub'), policies=['MS.POWERBI.1.1v1'],
                        projection_scan_max_rows=100)
    section = result['projection']['sections']['privileged_users']
    assert section['detail'] == {'field': 'scan_max_rows', 'kind': 'scan_bound'} and section['scan']['rows'] == 100
    assert result['projection']['bounds']['scan_max_rows'] == 100
    schema = json.loads((ROOT / 'schemas/model_assessment.schema.json').read_text())
    validate_assessment(result)
    jsonschema.validate(result, schema)
    for mutation in ('reason', 'field', 'kind'):
        broken = json.loads(json.dumps(result))
        target = broken['projection']['sections']['privileged_users']
        if mutation == 'reason':
            target['reason'] = 'incomplete_shape'
        elif mutation == 'field':
            target['detail']['field'] = 'users'
        else:
            target['detail']['kind'] = 'unseen_shape'
        with pytest.raises(ValueError):
            validate_assessment(broken)
        jsonschema.validate(broken, schema)
    for key, value in (('scan', {'rows': -1, 'bytes': 0, 'chunks': 0}), ('ignored_failures', ['not a name'])):
        broken = json.loads(json.dumps(result))
        broken['projection']['sections']['privileged_users'][key] = value
        with pytest.raises(ValueError):
            validate_assessment(broken)
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(broken, schema)
    # An assessment written before the scan bounds existed carries neither bounds nor scan counts.
    old = json.loads(json.dumps(result))
    for key in ('scan_max_rows', 'scan_max_bytes', 'scan_max_chunks'):
        del old['projection']['bounds'][key]
    for section in old['projection']['sections'].values():
        section.pop('scan', None)
    old['projection']['sections']['privileged_users'].pop('detail')
    old['projection']['sections']['privileged_users']['reason'] = 'oversize'
    validate_assessment(old)
    jsonschema.validate(old, schema)


def test_scan_flags_reach_the_projection_and_defaults_match(complete_bundle, monkeypatch, capsys):
    import auditex.model_serving as serving
    from auditex.scuba_projection import DEFAULT_SCAN_MAX_BYTES, DEFAULT_SCAN_MAX_CHUNKS, DEFAULT_SCAN_MAX_ROWS
    seen = []
    def spy(*args, **kwargs):
        seen.append(kwargs)
        return project_run(*args, **kwargs)
    monkeypatch.setattr(serving, 'project_run', spy)
    assert main(['model', 'assess', str(complete_bundle), '--dry-run']) == 0
    assert (seen[-1]['scan_max_rows'], seen[-1]['scan_max_bytes'], seen[-1]['scan_max_chunks']) == (
        DEFAULT_SCAN_MAX_ROWS, DEFAULT_SCAN_MAX_BYTES, DEFAULT_SCAN_MAX_CHUNKS)
    assert (seen[-1]['max_items'], seen[-1]['max_chars']) == (40, 12000)
    (complete_bundle / 'model_assessment_prompts.jsonl').unlink()
    assert main(['model', 'assess', str(complete_bundle), '--dry-run', '--projection-scan-max-rows', '7',
                 '--projection-scan-max-bytes', '9000000', '--projection-scan-max-chunks', '3']) == 0
    assert (seen[-1]['scan_max_rows'], seen[-1]['scan_max_bytes'], seen[-1]['scan_max_chunks']) == (7, 9000000, 3)
    with pytest.raises(SystemExit):
        main(['model', 'assess', '--help'])
    help_text = capsys.readouterr().out
    for flag in ('--projection-scan-max-rows', '--projection-scan-max-bytes', '--projection-scan-max-chunks'):
        assert flag in help_text


# --- Collection health is judged per operation ----------------------------------------------------------------

SIGNIN_REFUSED = {'error': 'Forbidden', 'error_class': 'license_required'}
SIGNIN_COVERAGE = {'collector': 'identity', 'type': 'graph', 'name': 'userSignInActivity', 'status': 'failed',
                   'error_class': 'license_required', 'error': 'Forbidden'}


def diagnostic(item, collector='identity', error_class='license_required'):
    return {'collector': collector, 'item': item, 'status': 'failed', 'error_class': error_class, 'error': 'refused'}


def ledger_row(collector='identity', status='partial_success', reason='collector_returned_partial', diagnostics=()):
    return {'collector': collector, 'coverage_status': status, 'coverage_reason': reason,
            'actual_status': 'partial' if status == 'partial_success' else 'ok', 'diagnostics': list(diagnostics)}


def refuse_signin(root, *, coverage=False, ledger=False, gap=False, manifest=False):
    operation(root, 'identity', 'userSignInActivity', [], **SIGNIN_REFUSED)
    if coverage or manifest:
        write(root, 'coverage.json', [SIGNIN_COVERAGE])
    if ledger or manifest:
        write(root, 'normalized/coverage_ledger.json', {'records': [
            ledger_row(diagnostics=[diagnostic('userSignInActivity')]),
            ledger_row('identity_governance', 'complete_exact_scope', 'runtime_success_with_expected_scope')]})
    if gap:
        write(root, 'normalized/collection_gaps.json', {'records': [{
            'collector': 'identity', 'id': 'identity.userSignInActivity', 'kind': 'collection_gap',
            'list': 'userSignInActivity', 'reason': 'read_failed', 'source': 'identity.userSignInActivity'}]})
    if manifest:
        data = json.loads((root / 'run-manifest.json').read_text())
        data['coverage_gaps'] = [{'surface': 'identity', 'status': 'partial', 'severity': 'medium',
                                  'collectors': ['identity', 'auth_methods'], 'error_classes': ['license_required']}]
        write(root, 'run-manifest.json', data)


@pytest.mark.parametrize('evidence', [
    {}, {'coverage': True}, {'ledger': True}, {'gap': True}, {'manifest': True},
    {'coverage': True, 'ledger': True, 'gap': True, 'manifest': True}])
def test_unrelated_operation_error_does_not_withhold_privileged_users(complete_bundle, evidence):
    refuse_signin(complete_bundle, **evidence)
    p = project_run(complete_bundle, redact=False)
    section = p.report['sections']['privileged_users']
    assert p['privileged_users'] == EXPECTED['privileged_users'] and section['status'] == 'projected'
    assert section['ignored_failures'] == ['identity.userSignInActivity']
    if evidence:
        assert p['tenant_id'] == TENANT
        assert p.report['sections']['tenant_id']['ignored_failures'] == ['identity.userSignInActivity']


@pytest.mark.parametrize('collector,name', [
    ('identity', 'users'), ('identity', 'groups'), ('identity', 'servicePrincipals'), ('identity', 'roleDefinitions'),
    ('identity', 'roleAssignments'), ('identity', 'roleAssignableGroupMembers'),
    ('identity_governance', 'roleAssignmentSchedules'), ('identity_governance', 'roleEligibilitySchedules')])
def test_error_on_an_operation_the_section_reads_withholds(complete_bundle, collector, name):
    refuse_signin(complete_bundle)
    # A licence refusal of a PIM schedule read is the no-P2 case (test below); any other refusal withholds.
    refusal = SIGNIN_REFUSED if collector == 'identity' else {'error': 'Forbidden', 'error_class': 'insufficient_permissions'}
    operation(complete_bundle, collector, name, [] if name != 'users' else [
        {'id': TENANT, 'displayName': PERSON, 'onPremisesImmutableId': None}], **refusal)
    p = project_run(complete_bundle)
    assert p['privileged_users'] == NOT_COLLECTED
    assert p.report['sections']['privileged_users']['reason'] == 'collector_error'
    assert p.report['sections']['privileged_users']['detail'] == {
        'error_class': refusal['error_class'], 'operation': f'{collector}.{name}'}
    assert 'ignored_failures' not in p.report['sections']['privileged_users'] or \
        f'{collector}.{name}' not in p.report['sections']['privileged_users']['ignored_failures']


def test_collector_envelope_failure_withholds_even_when_the_read_operation_is_healthy(complete_bundle):
    refuse_signin(complete_bundle)
    payload = json.loads((complete_bundle / 'raw/identity.json').read_text())
    payload['error'] = 'Forbidden'
    write(complete_bundle, 'raw/identity.json', payload)
    assert project_run(complete_bundle)['privileged_users'] == NOT_COLLECTED


@pytest.mark.parametrize('rows', [
    [ledger_row(diagnostics=[diagnostic('users', error_class='collection_limit')])],
    [ledger_row(diagnostics=[diagnostic('userSignInActivity'), diagnostic('roleAssignments')])],
    [ledger_row(diagnostics=[diagnostic('userSignInActivity'), diagnostic('notAnOperation')])],
    [ledger_row(diagnostics=[diagnostic('privilegedGroupFanout', error_class='incomplete_evidence')])],
    [ledger_row(diagnostics=[diagnostic('userSignInActivity'), {'item': None}])],
    [ledger_row(diagnostics=[])],
    [ledger_row(status='failed_runtime', reason='collector_failed_runtime', diagnostics=[diagnostic('userSignInActivity')])],
    [ledger_row('identity_governance', diagnostics=[diagnostic('roleEligibilitySchedules')])],
])
def test_coverage_ledger_failure_of_a_read_operation_withholds(complete_bundle, rows):
    refuse_signin(complete_bundle)
    write(complete_bundle, 'normalized/coverage_ledger.json', {'records': rows})
    assert project_run(complete_bundle)['privileged_users'] == NOT_COLLECTED


@pytest.mark.parametrize('path,rows', [
    ('coverage.json', [{'collector': 'identity', 'name': 'users', 'status': 'failed', 'error': 'Forbidden'}]),
    ('coverage.json', [{'collector': 'identity', 'name': 'roleAssignableGroupMembersFanout', 'type': 'derived',
                        'status': 'partial'}]),
    ('coverage.json', [{'collector': 'identity', 'status': 'failed', 'error': 'Forbidden'}]),
    ('coverage.json', [{'collector': 'identity', 'name': 'unknownOperation', 'status': 'failed', 'error': 'Forbidden'}]),
    ('normalized/collection_gaps.json', {'records': [{'collector': 'identity', 'list': 'users', 'source': 'identity.users',
                                                      'reason': 'operator_limit'}]}),
    ('normalized/collection_gaps.json', {'records': [{'collector': 'identity', 'reason': 'read_failed'}]}),
])
def test_coverage_and_gap_rows_for_a_read_operation_or_the_whole_collector_withhold(complete_bundle, path, rows):
    refuse_signin(complete_bundle, coverage=True)
    write(complete_bundle, path, rows)
    assert project_run(complete_bundle)['privileged_users'] == NOT_COLLECTED


def test_unrelated_failure_is_ignored_for_a_single_read_and_a_read_failure_is_not(complete_bundle):
    operation(complete_bundle, 'licensing', 'licensedUsers', [], **SIGNIN_REFUSED)
    write(complete_bundle, 'normalized/coverage_ledger.json', {'records': [
        ledger_row('licensing', diagnostics=[diagnostic('licensedUsers', 'licensing')])]})
    p = project_run(complete_bundle, redact=False)
    assert p['service_plans'] == EXPECTED['service_plans']
    assert p.report['sections']['service_plans']['ignored_failures'] == ['licensing.licensedUsers']
    write(complete_bundle, 'normalized/coverage_ledger.json', {'records': [
        ledger_row('licensing', diagnostics=[diagnostic('subscribedSkus', 'licensing')])]})
    assert project_run(complete_bundle)['service_plans'] == NOT_COLLECTED


def test_manifest_truncated_list_is_judged_by_its_operation(complete_bundle):
    refuse_signin(complete_bundle, coverage=True, ledger=True)
    manifest = json.loads((complete_bundle / 'run-manifest.json').read_text())
    for name, withheld in (('userSignInActivity', False), ('users', True)):
        manifest['coverage_gaps'] = [{'surface': 'identity', 'status': 'partial', 'collectors': ['identity'],
                                      'truncated_lists': [{'collector': 'identity', 'list': name,
                                                           'rows_collected': 7, 'reason': 'operator_limit'}]}]
        write(complete_bundle, 'run-manifest.json', manifest)
        assert (project_run(complete_bundle)['privileged_users'] == NOT_COLLECTED) is withheld


def test_manifest_surface_summary_without_coverage_rows_still_withholds(complete_bundle):
    manifest = json.loads((complete_bundle / 'run-manifest.json').read_text())
    manifest['coverage_gaps'] = [{'surface': 'identity', 'status': 'partial', 'collectors': ['identity'],
                                  'error_classes': ['license_required']}]
    write(complete_bundle, 'run-manifest.json', manifest)
    p = project_run(complete_bundle)
    assert p['privileged_users'] == p['tenant_id'] == NOT_COLLECTED
    assert p.report['sections']['tenant_id']['detail'] == {'field': 'coverage_gaps', 'kind': 'unseen_shape'}


def test_sign_in_activity_refusal_in_a_real_offline_run_does_not_withhold_privileged_users(tmp_path):
    from auditex.demo import DEMO_AS_OF, DEMO_SAMPLE
    from azure_tenant_audit.cli import run_offline
    sample = json.loads((ROOT / DEMO_SAMPLE).read_text())
    sample['identity']['userSignInActivity'] = SIGNIN_REFUSED
    write(tmp_path, 'sample.json', sample)
    # The run is partial (exit status 1) and its coverage ledger, coverage rows and manifest all say so.
    assert run_offline(tmp_path / 'sample.json', tmp_path, 'p2', 'signin', plane='full', as_of=DEMO_AS_OF) == 1
    root = tmp_path / 'p2-signin'
    ledger = json.loads((root / 'normalized/coverage_ledger.json').read_text())['records']
    identity = next(r for r in ledger if r['collector'] == 'identity')
    assert identity['coverage_status'] == 'partial_success'
    assert [d['item'] for d in identity['diagnostics']] == ['userSignInActivity']
    assert json.loads((root / 'run-manifest.json').read_text())['coverage_gaps']
    p = project_run(root)
    for section in ('privileged_users', 'tenant_id'):
        assert p.report['sections'][section]['status'] == 'projected'
        assert p.report['sections'][section]['ignored_failures'] == ['identity.userSignInActivity']
    assert p.report['sections']['privileged_users']['scan']['rows'] == len(sample['identity']['users']['value'])


# ---- privileged_roles from the identity_governance policy reads ---------------------------------------------------------


def _demo_run(tmp_path, name, edit=None, *, expect=0):
    from auditex.demo import DEMO_AS_OF, DEMO_SAMPLE
    from azure_tenant_audit.cli import run_offline
    sample = json.loads((ROOT / DEMO_SAMPLE).read_text())
    if edit:
        edit(sample['identity_governance'])
    write(tmp_path, f'{name}.json', sample)
    assert run_offline(tmp_path / f'{name}.json', tmp_path, 'pim', name, plane='full', as_of=DEMO_AS_OF) == expect
    return tmp_path / f'pim-{name}'


def _admit_shape(monkeypatch, rows):
    """Add the whole shape of ``rows`` to the frozen set, as a pack that holds it would."""
    from auditex import scuba_projection
    digest = sha256(scuba_projection._json(scuba_projection._shape(rows)).encode()).hexdigest()
    monkeypatch.setitem(scuba_projection.PACK_SHAPE_DIGESTS, 'privileged_roles',
                        [*scuba_projection.PACK_SHAPE_DIGESTS['privileged_roles'], digest])


def test_the_demo_policy_reads_write_an_artefact_that_only_the_frozen_shape_gate_withholds(tmp_path, monkeypatch):
    root = _demo_run(tmp_path, 'demo')
    artefact = json.loads((root / 'normalized/privileged_roles.json').read_text())
    assert artefact['complete'] is True and artefact['collection_status'] == 'collected'
    rows = [{k: v for k, v in row.items() if k != 'key'} for row in artefact['records']]
    assert {r['DisplayName'] for r in rows} == {'Global Administrator', 'Exchange Administrator', 'Helpdesk Administrator',
                                                 'Privileged Role Administrator'}
    # Every field, enum and health check of the adapter holds. The whole-shape gate does not: no frozen v7 row holds an
    # expiration rule without NotificationRecipients and Setting, and Graph returns neither on such a rule. A pack that
    # holds this shape (the day one is frozen) changes PACK_SHAPE_DIGESTS and this expectation together.
    withheld = project_run(root)
    assert withheld['privileged_roles'] == NOT_COLLECTED
    assert withheld.report['sections']['privileged_roles']['reason'] == 'incomplete_shape'
    assert withheld.report['sections']['privileged_roles']['detail'] == {'field': '$', 'kind': 'unseen_shape'}
    assert withheld.report['sections']['privileged_users']['status'] == 'projected'
    _admit_shape(monkeypatch, rows)
    p = project_run(root, redact=False)
    assert p.report['sections']['privileged_roles']['status'] == 'projected'
    assert p['privileged_roles'] == rows and all('key' not in row for row in p['privileged_roles'])
    ga = next(r for r in p['privileged_roles'] if r['DisplayName'] == 'Global Administrator')
    assert len(ga['Assignments']) == 6 and all(a['EndDateTime'] is None for a in ga['Assignments'])
    notified = next(r for r in ga['Rules'] if r['Id'] == 'Notification_Admin_EndUser_Assignment')
    assert notified['NotificationRecipients'] == ['it@halcyonfreight.example']
    # E-mail recipients are masked by default (``redact=False``, as above, sends them unmasked); the local part is then not in the prompt.
    masked = project_run(root)
    assert 'it@halcyonfreight.example' not in canonical(masked['privileged_roles'])
    assert '***@halcyonfreight.example' in canonical(masked['privileged_roles'])


POLICY_REFUSALS = [
    pytest.param('roleManagementPolicyAssignments', 'resource_not_found', 'partial_success', 'endpoint_unavailable', id='assignments-404'),
    pytest.param('roleManagementPolicyAssignments', 'insufficient_permissions', 'blocked_permission', 'read_failed', id='assignments-403'),
    pytest.param('roleManagementPolicyRules', 'insufficient_permissions', 'blocked_permission', 'read_failed', id='rules-403'),
]


@pytest.mark.parametrize('operation,error_class,ledger_status,reason', POLICY_REFUSALS)
def test_a_refused_or_missing_policy_read_is_a_gap_and_never_an_empty_privileged_roles(tmp_path, operation, error_class, ledger_status, reason):
    def refuse(governance):
        governance[operation] = {'error': 'refused', 'error_class': error_class}
        if operation == 'roleManagementPolicyAssignments':
            governance.pop('roleManagementPolicyRules')

    root = _demo_run(tmp_path, 'refused', refuse, expect=1)
    ledger = {r['collector']: r for r in json.loads((root / 'normalized/coverage_ledger.json').read_text())['records']}
    assert ledger['identity_governance']['coverage_status'] == ledger_status
    gaps = {r['source']: r for r in json.loads((root / 'normalized/collection_gaps.json').read_text())['records']}
    gap = gaps[f'identity_governance.{operation}']
    assert (gap['reason'], gap['status'], gap['error_classes']) == (reason, 'failed', [error_class])
    assert not (root / 'normalized/privileged_roles.json').exists()
    p = project_run(root)
    assert p['privileged_roles'] == NOT_COLLECTED
    assert p.report['sections']['privileged_roles']['reason'] == 'missing_artifact'
    # The failed policy read is not one privileged_users reads: it is listed and does not withhold that section.
    assert p.report['sections']['privileged_users']['status'] == 'projected'
    assert f'identity_governance.{operation}' in p.report['sections']['privileged_users']['ignored_failures']


def test_policy_reads_of_a_tenant_with_a_cut_fan_out_never_become_the_artefact(tmp_path):
    def cut(governance):
        governance['roleManagementPolicyRules'].update(
            collection_truncated=True, truncation_reason='fanout_limit',
            fanout={**governance['roleManagementPolicyRules']['fanout'], 'fanout_complete': False, 'collection_truncated': True})

    root = _demo_run(tmp_path, 'cut', cut, expect=1)
    assert not (root / 'normalized/privileged_roles.json').exists()
    assert project_run(root)['privileged_roles'] == NOT_COLLECTED


def test_a_withheld_privileged_roles_artefact_names_its_reason_and_does_not_withhold_privileged_users(tmp_path):
    exchange = '29232cdf-9323-42fd-ade2-1d097af3e4de'

    def drop_a_policy(governance):
        rows = governance['roleManagementPolicyAssignments']['value']
        governance['roleManagementPolicyAssignments']['value'] = [row for row in rows if row['roleDefinitionId'] != exchange]

    root = _demo_run(tmp_path, 'withheld', drop_a_policy)
    assert not (root / 'normalized/privileged_roles.json').exists()
    gaps = {r['source']: r for r in json.loads((root / 'normalized/collection_gaps.json').read_text())['records']}
    gap = gaps['identity_governance.privileged_roles']
    assert (gap['reason'], gap['reasons'], gap['rows_collected']) == ('artefact_withheld', [f'role_without_policy:{exchange}'], 0)
    ledger = {r['collector']: r for r in json.loads((root / 'normalized/coverage_ledger.json').read_text())['records']}
    assert ledger['identity_governance']['coverage_status'].startswith('complete'), 'the collector read in full: not partial'
    p = project_run(root)
    assert p['privileged_roles'] == NOT_COLLECTED
    assert p.report['sections']['privileged_roles']['reason'] == 'missing_artifact'
    assert p.report['sections']['privileged_roles']['ignored_failures'] == ['identity_governance.privileged_roles']
    # The gap is about the artefact, not about a read privileged_users makes: it is listed there and does not withhold it.
    assert p.report['sections']['privileged_users']['status'] == 'projected'
    assert 'identity_governance.privileged_roles' in p.report['sections']['privileged_users']['ignored_failures']


# scuba_config: ScubaGear's operator configuration, synthesised per policy family (scuba_projection._scuba_config).
EMPTY_CAP = {'Applications': [], 'Groups': [], 'GuestUserTypes': [], 'Users': []}
EMPTY_ROLE = {'Groups': [], 'Users': []}
AAD_DEFAULT = {'Aad': None, 'CapExclusions': EMPTY_CAP, 'RoleExclusions': EMPTY_ROLE}
CONFIG_READERS = sorted(p for p, e in json.loads((ROOT / 'configs/scuba-policy-sections.json').read_text())['policies'].items()
                        if 'scuba_config' in e['sections'])
BREAK_GLASS_ID = '0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d'
BREAK_GLASS_GROUP = '5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d'
BREAK_GLASS_UPN = 'breakglass1@example.invalid'


def config_bundle(root, *, accounts=(), footprint=None, skus=None):
    manifest = json.loads((root / 'run-manifest.json').read_text())
    manifest['rule_parameters'] = {'schema_version': '2026-10-22', 'break_glass_accounts': list(accounts)}
    write(root, 'run-manifest.json', manifest)
    if footprint is not None:
        operation(root, 'dns_posture', 'publicFootprint', footprint)
    if skus is not None:
        operation(root, 'licensing', 'subscribedSkus', [{'skuPartNumber': sku, 'servicePlans': []} for sku in skus])
    return root


def footprint(scope='NA', sub=None, instance='microsoftonline.com', domain='example.invalid'):
    return {'domain': domain, 'discovery_status': 'ok', 'tenant_region_scope': scope,
            'tenant_region_sub_scope': sub, 'cloud_instance_name': instance}


def case_config(projection, policy_id):
    from auditex.model_serving import build_case
    case = build_case(policy_id, projection, '2026-10-30T00:00:00Z')
    return next(e['observed'] for e in case['evidence'] if e['section'] == 'scuba_config')


def test_scuba_config_default_shape_per_family(complete_bundle):
    from auditex.scuba_projection import PACK_SHAPE_DIGESTS, _seen_shape
    p = project_run(config_bundle(complete_bundle))
    assert len(CONFIG_READERS) == 19 and len(PACK_SHAPE_DIGESTS['scuba_config']) == 99
    assert p['scuba_config'] == AAD_DEFAULT
    expected = {pid: dict(AAD_DEFAULT) for pid in CONFIG_READERS if pid.startswith('MS.AAD.')}
    expected['MS.AAD.9.1v1'] = {**AAD_DEFAULT, 'M365Environment': 'commercial'}
    expected['MS.EXO.1.1v2'] = None
    expected.update({pid: {'M365Environment': 'commercial'} for pid in CONFIG_READERS if pid.startswith('MS.TEAMS.')})
    expected.update({pid: NOT_COLLECTED for pid in CONFIG_READERS if pid.startswith('MS.SECURITYSUITE.')})
    assert {pid: case_config(p, pid) for pid in CONFIG_READERS} == expected
    for pid, view in expected.items():
        if view != NOT_COLLECTED:
            _seen_shape('scuba_config', view)
    entry = p.report['sections']['scuba_config']
    assert entry['status'] == 'projected' and entry['reason'] is None and entry['source'][0] == 'run-manifest.json'
    synthesis = entry['synthesis']
    assert synthesis['source'] == 'synthesised:default-config' and synthesis['basis'] == 'scubagear_default_config'
    assert synthesis['m365_environment'] == {'value': 'commercial', 'basis': 'assumed_default'}
    assert synthesis['break_glass'] == {'source': 'none'}
    assert {k for k, v in synthesis['policies'].items() if v != 'projected'} == {
        'MS.SECURITYSUITE.2.1v1', 'MS.SECURITYSUITE.2.3v1', 'MS.SECURITYSUITE.3.2v1'}
    assert set(synthesis['policies'].values()) == {'projected', 'operator_input_required'}
    from auditex.scuba_projection import rule_policy_section
    for pid in ('MS.AAD.9.1v1', 'MS.TEAMS.2.2v2', 'MS.TEAMS.2.3v2', 'MS.TEAMS.4.1v1'):
        assert rule_policy_section(p, pid, 'scuba_config')['M365Environment'] == 'commercial'


def test_scuba_config_environment_evidence_that_cannot_be_read_fails_closed(complete_bundle):
    # Two DoD answers under a one-row scan bound: the discovery exists but cannot be read, so no cloud is assumed.
    root = config_bundle(complete_bundle, footprint=[footprint('USGov', 'DOD', 'microsoftonline.us'),
                                                      footprint('USGov', 'DOD', 'microsoftonline.us', domain='b.invalid')])
    full = project_run(root)
    assert full.report['sections']['scuba_config']['synthesis']['m365_environment'] == {'value': 'dod', 'basis': 'openid_discovery'}
    bounded = project_run(root, scan_max_rows=1)
    synthesis = bounded.report['sections']['scuba_config']['synthesis']
    assert synthesis['m365_environment'] == {'value': None, 'basis': 'unreadable'}
    for pid in ('MS.AAD.9.1v1', 'MS.TEAMS.2.2v2', 'MS.TEAMS.2.3v2', 'MS.TEAMS.4.1v1'):
        assert case_config(bounded, pid) == NOT_COLLECTED and synthesis['policies'][pid] == 'environment_ambiguous'
    assert case_config(bounded, 'MS.AAD.1.1v1') == AAD_DEFAULT


@pytest.mark.parametrize('bounds', [{'max_items': 1}, {'max_chars': 50}])
def test_scuba_config_withheld_section_feeds_no_policy_view(complete_bundle, bounds):
    from auditex.scuba_projection import policy_section
    p = project_run(config_bundle(complete_bundle), **bounds)
    entry = p.report['sections']['scuba_config']
    assert entry['status'] == 'not_collected' and 'synthesis' not in entry
    assert p['scuba_config'] == NOT_COLLECTED and all('scuba_config' not in v for v in p.views.values())
    for pid in ('MS.AAD.1.1v1', 'MS.EXO.1.1v2', 'MS.TEAMS.2.2v2'):
        assert policy_section(p, pid, 'scuba_config') == NOT_COLLECTED and case_config(p, pid) == NOT_COLLECTED


def test_scuba_config_unread_sections_keep_their_own_value(complete_bundle):
    from auditex.scuba_projection import policy_section
    p = project_run(config_bundle(complete_bundle))
    assert policy_section(p, 'MS.EXO.1.1v2', 'scuba_config') is None
    assert policy_section(p, 'MS.EXO.1.1v2', 'tenant_id') == p['tenant_id']
    assert policy_section({'scuba_config': AAD_DEFAULT}, 'MS.AAD.1.1v1', 'scuba_config') == AAD_DEFAULT


def test_rule_capture_precedes_model_budget_and_preserves_distinct_role_dates(complete_bundle):
    from auditex.scuba_projection import rule_policy_section
    operation(complete_bundle, 'teams_policy', 'meetingPolicies', [PS['meeting_policies'][2]] * 41)
    roles_path = complete_bundle / 'normalized/privileged_roles.json'
    roles = json.loads(roles_path.read_text())
    roles['records'][0]['Assignments'][0]['EndDateTime'] = None
    roles['records'][0]['Assignments'][0]['StartDateTime'] = None
    roles['records'][1]['Assignments'][0].pop('EndDateTime', None)
    roles['records'][1]['Assignments'][0].pop('StartDateTime', None)
    write(complete_bundle, 'normalized/privileged_roles.json', roles)
    p = project_run(complete_bundle)
    assert len(p.rule_sections['meeting_policies']) == 41
    assert p['meeting_policies'] == NOT_COLLECTED
    assert p.rule_sections['privileged_users']['User1']['DisplayName'] == PERSON
    assert p['privileged_users']['User1']['DisplayName'] != PERSON
    assignments = [role['Assignments'][0] for role in p.rule_sections['privileged_roles']]
    assert assignments[0]['EndDateTime'] is None and assignments[0]['StartDateTime'] is None
    assert 'EndDateTime' not in assignments[1] and 'StartDateTime' not in assignments[1]
    assert rule_policy_section(p, 'MS.SECURITYSUITE.2.1v1', 'scuba_config') == NOT_COLLECTED


def test_rule_capture_honours_run_scan_and_collector_withholding(complete_bundle):
    operation(complete_bundle, 'teams_policy', 'meetingPolicies', [PS['meeting_policies'][2]] * 2)
    p = project_run(complete_bundle, scan_max_rows=1)
    assert p.rule_sections['meeting_policies'] == NOT_COLLECTED
    operation(complete_bundle, 'teams_policy', 'meetingPolicies',
              {'error': 'synthetic secret', 'error_class': 'permission_denied'})
    p = project_run(complete_bundle)
    assert p.rule_sections['meeting_policies'] == NOT_COLLECTED


@pytest.mark.parametrize('section', ['spf_records', 'dkim_records', 'dmarc_records'])
def test_dns_resolver_log_is_private_on_run_path(complete_bundle, section, caplog, capsys):
    canary = 'dns-log-canary@example.invalid'
    before = project_run(complete_bundle)
    rows = deepcopy(EXPECTED[section])
    rows[0]['log'] = [{'query_result': 'Domain name exists but no answers returned.', 'detail': canary}]
    operation(complete_bundle, 'dns_posture', section, rows)
    projection = project_run(complete_bundle)
    assert projection.rule_sections[section] == rows
    assert projection[section] == before[section]
    assert canary not in json.dumps(projection) + json.dumps(projection.report)
    with caplog.at_level('DEBUG'):
        assess_run(complete_bundle, ModelConfig(model_name='stub'), dry_run=True)
    written = (complete_bundle / 'model_assessment_prompts.jsonl').read_text()
    assert canary not in written + caplog.text + str(capsys.readouterr())
    bounded = project_run(complete_bundle, scan_max_rows=1, scan_max_bytes=1)
    assert bounded.rule_sections[section] == NOT_COLLECTED


@pytest.mark.parametrize('operator', ['AND', 'OR', None])
def test_ca_operator_survives_run_rule_capture(complete_bundle, operator):
    ca = deepcopy(CA)
    ca['GrantControls']['Operator'] = operator
    operation(complete_bundle, 'conditional_access', 'conditionalAccessPolicies', [graph(ca)])
    projection = project_run(complete_bundle)
    assert projection.rule_sections['conditional_access_policies'][0]['GrantControls']['Operator'] == operator


def test_defender_run_path_does_not_invent_uncollected_provider_evidence(complete_bundle):
    projection = project_run(complete_bundle)
    for section in ('defender_license', 'defender_dlp_license', 'atp_policy_rules',
                    'securitysuite_unsuccessful_commands'):
        assert projection.rule_sections[section] == NOT_COLLECTED


def test_serving_rules_use_private_view_while_model_case_keeps_marker():
    from azure_tenant_audit.value_rules.catalogue import row_for
    policy = 'MS.POWERBI.1.1v1'
    setting = row_for(policy)['params']['setting_name']
    private = {'powerbi_license_found': True, 'powerbi_access_denied_reason': '',
               'powerbi_tenant_settings': [{'settingName': setting, 'enabled': True}] * 41}
    case = build_case(policy, {}, '2026-11-05')
    assert all(e['observed'] == NOT_COLLECTED for e in case['evidence'][1:])
    record = precheck_case(case, value_rules=True, rule_projection=private)
    assert record['rule_precheck']['class'] == 'value_rule'
    assert record['rule_precheck']['cell'] == 'setting_entry_duplicated'
    assert 'powerbi_tenant_settings' in record['rule_precheck']['section']


def test_run_rule_view_canaries_never_enter_prompts_or_assessment(complete_bundle, caplog, capsys):
    canary_email = 'rule-view-run-canary@example.invalid'
    canary_name = 'Rule View Run Canary DisplayName'
    path = complete_bundle / 'normalized/privileged_roles.json'
    roles = json.loads(path.read_text())
    role = roles['records'][0]
    role['DisplayName'] = canary_name
    role['Rules'][0]['NotificationRecipients'] = [canary_email]
    roles['records'] = [role] * 41
    write(complete_bundle, 'normalized/privileged_roles.json', roles)
    projection = project_run(complete_bundle)
    assert canary_email in repr(projection.rule_sections['privileged_roles'])
    assert canary_name in repr(projection.rule_sections['privileged_roles'])
    assert projection['privileged_roles'] == NOT_COLLECTED
    with caplog.at_level('DEBUG'):
        assess_run(complete_bundle, ModelConfig(model_name='stub'), dry_run=True)
        assess_run(complete_bundle, ModelConfig(model_name='stub'),
                   policies=['MS.POWERBI.1.1v1'])
    written = (complete_bundle / 'model_assessment_prompts.jsonl').read_text() + (
        complete_bundle / 'model_assessment.json').read_text()
    assert canary_email not in written + caplog.text + str(capsys.readouterr())
    assert canary_name not in written + caplog.text


def test_run_rule_reads_unredacted_canary_without_persisting_it(complete_bundle, monkeypatch, caplog, capsys):
    import auditex.model_serving as serving
    from azure_tenant_audit import value_rules
    canary_email = 'rule-input-canary@example.invalid'
    canary_name = 'Rule Input Canary DisplayName'
    original_project = serving.project_run
    original_assess = value_rules.assess
    seen = []

    def with_private_evidence(root, **options):
        projection = original_project(root, **options)
        projection.rule_sections.update({
            'powerbi_access_denied_reason': '', 'powerbi_license_found': True,
            'powerbi_tenant_settings': [{'settingName': 'PublishToWeb', 'enabled': canary_name,
                                         'Owner': canary_email}],
        })
        return projection

    def reading_rule(policy_id, sections):
        seen.append((sections['powerbi_tenant_settings'][0]['enabled'],
                     sections['powerbi_tenant_settings'][0]['Owner']))
        return original_assess(policy_id, sections)

    monkeypatch.setattr(serving, 'project_run', with_private_evidence)
    monkeypatch.setattr(value_rules, 'assess', reading_rule)
    with caplog.at_level('DEBUG'):
        result = assess_run(complete_bundle, ModelConfig(model_name='stub'), policies=['MS.POWERBI.1.1v1'])
    assert seen == [(canary_name, canary_email)]
    assert result['policies'][0]['rule_precheck']['cell'] == 'enabled_not_boolean'
    written = (complete_bundle / 'model_assessment.json').read_text()
    assert canary_email not in written + caplog.text + str(capsys.readouterr())
    assert canary_name not in written + caplog.text


def test_unaffected_run_prompt_hashes_match_pre_rule_view_fixture(complete_bundle):
    from auditex.model_serving import messages_for, policy_catalogue
    projection = project_run(complete_bundle)
    hashes = {}
    for policy_id in policy_catalogue()['policies']:
        messages = messages_for(build_case(policy_id, projection, '2026-11-05'))
        hashes[policy_id] = sha256(canonical(messages).encode()).hexdigest()
    assert len(hashes) == 102
    assert sha256(canonical(hashes).encode()).hexdigest() == (
        'a57bba64c13c01be52bb609e00d22d2fb4d18e359d8822445d1704a22a0b2047')


@pytest.mark.parametrize('kwargs,environment,basis', [
    ({}, 'commercial', 'assumed_default'),
    ({'footprint': [footprint()]}, 'commercial', 'openid_discovery'),
    ({'footprint': [footprint(sub='GCC')]}, 'gcc', 'openid_discovery'),
    ({'footprint': [footprint('USGov', 'DODCON', 'microsoftonline.us')]}, 'gcchigh', 'openid_discovery'),
    ({'footprint': [footprint('USGov', 'DOD', 'microsoftonline.us')]}, 'dod', 'openid_discovery'),
    ({'skus': ['ENTERPRISEPACK_USGOV_DOD']}, 'dod', 'licence_sku'),
    ({'skus': ['ENTERPRISEPACK_GOV', 'SPE_E5']}, 'gcc', 'licence_sku'),
    ({'skus': ['SPE_E5']}, 'commercial', 'assumed_default'),
    ({'footprint': [footprint(), footprint(sub='GCC', domain='b.invalid')]}, None, 'ambiguous'),
    ({'footprint': [footprint('USGov', 'Unknown', 'microsoftonline.us')]}, None, 'ambiguous'),
    ({'skus': ['ENTERPRISEPACK_USGOV_GCCHIGH', 'ENTERPRISEPACK_GOV']}, None, 'ambiguous'),
    ({'footprint': [footprint(scope=None, instance=None)]}, None, 'ambiguous'),   # an ok answer without cloud fields
    ({'footprint': [footprint('AS', None, 'partner.microsoftonline.cn')]}, None, 'ambiguous'),   # 21Vianet: no ScubaGear value
    ({'footprint': [footprint('USGov', 'DOD', 'microsoftonline.us')], 'skus': ['SPE_E5']}, 'dod', 'openid_discovery'),
    ({'footprint': [{}]}, None, 'unreadable'),   # not a row the collector writes
    ({'footprint': [footprint(scope=['USGov'], instance=None)]}, None, 'unreadable'),   # a field of the wrong type
    ({'footprint': [footprint('USGov', 'DOD', 'partner.microsoftonline.cn')]}, None, 'ambiguous'),   # sovereign instance wins
    ({'footprint': [footprint('USGov', 'DOD', 'microsoftonline.com')]}, None, 'ambiguous'),   # scope and instance disagree
    ({'footprint': [footprint('NA', None, 'microsoftonline.us')]}, None, 'ambiguous'),
    ({'footprint': [footprint('USGov', 'DOD', None)]}, 'dod', 'openid_discovery'),   # scope alone, instance not stated
    ({'footprint': [footprint(None, 'DOD', 'microsoftonline.us')]}, 'dod', 'openid_discovery'),   # instance alone
    ({'footprint': [{**footprint('USGov', 'DOD', 'microsoftonline.us'), 'discovery_status': None}]}, None, 'unreadable'),
    ({'footprint': [{**footprint('USGov', 'DOD', 'microsoftonline.us'), 'discovery_status': 'bogus'}]}, None, 'unreadable'),
    ({'skus': [['ENTERPRISEPACK_USGOV_DOD']]}, None, 'unreadable'),   # a SKU of the wrong type
    ({'skus': [None]}, None, 'unreadable'),   # a licence row without a SKU
    ({'skus': ['']}, None, 'unreadable'),
])
def test_scuba_config_m365_environment_derivation(complete_bundle, kwargs, environment, basis):
    p = project_run(config_bundle(complete_bundle, **kwargs))
    synthesis = p.report['sections']['scuba_config']['synthesis']
    assert synthesis['m365_environment'] == {'value': environment, 'basis': basis}
    gated = ['MS.AAD.9.1v1', 'MS.TEAMS.2.2v2', 'MS.TEAMS.2.3v2', 'MS.TEAMS.4.1v1']
    if environment is None:
        assert all(case_config(p, pid) == NOT_COLLECTED for pid in gated)
        assert {synthesis['policies'][pid] for pid in gated} == {'environment_ambiguous'}
        assert case_config(p, 'MS.AAD.1.1v1') == AAD_DEFAULT
    else:
        assert case_config(p, 'MS.TEAMS.2.2v2') == {'M365Environment': environment}
        assert case_config(p, 'MS.AAD.9.1v1')['M365Environment'] == environment
        assert case_config(p, 'MS.AAD.1.1v1') == AAD_DEFAULT


def test_scuba_config_gov_cloud_closes_teams_gate_by_rule(complete_bundle):
    from auditex.model_serving import build_case
    p = project_run(config_bundle(complete_bundle, footprint=[footprint('USGov', 'DODCON', 'microsoftonline.us')]))
    record = precheck_case(build_case('MS.TEAMS.4.1v1', p, '2026-10-30T00:00:00Z'))
    assert record['rule_precheck']['class'] == 'closed_gate' and record['rule_precheck']['value'] == 'gcchigh'


def identity_rows(root):
    operation(root, 'identity', 'users', [
        {'id': TENANT, 'displayName': PERSON, 'onPremisesImmutableId': None},
        {'id': BREAK_GLASS_ID, 'displayName': 'Emergency One', 'userPrincipalName': BREAK_GLASS_UPN,
         'onPremisesImmutableId': None}])
    operation(root, 'identity', 'groups', [{'id': BREAK_GLASS_GROUP, 'displayName': 'Emergency Group'}])
    return root


def test_scuba_config_break_glass_maps_to_exclusions_by_object_id(complete_bundle):
    from auditex.model_serving import build_case, messages_for
    p = project_run(config_bundle(identity_rows(complete_bundle), accounts=[BREAK_GLASS_UPN]))
    from auditex.scuba_projection import SCUBA_CONFIG_EXCLUSION_KEYS
    assert SCUBA_CONFIG_EXCLUSION_KEYS == {'MS.AAD.3.2v2': 'MS.AAD.3.2v1'}
    for pid in ('MS.AAD.1.1v1', 'MS.AAD.3.8v1'):
        assert case_config(p, pid) == {**AAD_DEFAULT, 'Aad': {pid: {
            'CapExclusions': {**EMPTY_CAP, 'Users': [BREAK_GLASS_ID]}, 'RoleExclusions': EMPTY_ROLE}}}
    # MS.AAD.3.2v2's Rego reads the entry under MS.AAD.3.2v1 (CISA finding F2). The exclusion is written there, where the
    # oracle honours it, and training never held that shape, so the policy is withheld rather than shown an entry the
    # oracle would ignore or a shape the model has never seen.
    assert case_config(p, 'MS.AAD.3.2v2') == NOT_COLLECTED
    assert p.report['sections']['scuba_config']['synthesis']['policies']['MS.AAD.3.2v2'] == 'unseen_shape'
    assert case_config(p, 'MS.AAD.7.4v1') == {**AAD_DEFAULT, 'Aad': {'MS.AAD.7.4v1': {
        'CapExclusions': EMPTY_CAP, 'RoleExclusions': {**EMPTY_ROLE, 'Users': [BREAK_GLASS_ID]}}}}
    # Rego without an exclusion for the account keeps the default: MFA-method and AI-agent policies.
    assert case_config(p, 'MS.AAD.3.3v2') == AAD_DEFAULT
    assert 'Aad' in case_config(p, 'MS.AAD.9.1v1') and case_config(p, 'MS.AAD.9.1v1')['Aad'] is None
    synthesis = p.report['sections']['scuba_config']['synthesis']
    assert synthesis['break_glass'] == {'source': 'operator', 'entries': 1, 'unresolved': 0, 'unverified': 0,
                                        'state': 'resolved', 'users': 1, 'groups': 0}
    # The operator's entry is a user principal name: only the object ID reaches a prompt or the report.
    prompts = canonical([messages_for(build_case(pid, p, '2026-10-30T00:00:00Z')) for pid in CONFIG_READERS])
    assert BREAK_GLASS_UPN not in prompts and 'breakglass1' not in canonical(p.report)
    assert BREAK_GLASS_ID in prompts


def test_scuba_config_break_glass_users_and_groups_fail_closed_where_unseen(complete_bundle):
    p = project_run(config_bundle(identity_rows(complete_bundle), accounts=[BREAK_GLASS_ID, 'Emergency Group']))
    view = case_config(p, 'MS.AAD.2.1v1')['Aad']['MS.AAD.2.1v1']['CapExclusions']
    assert view['Users'] == [BREAK_GLASS_ID] and view['Groups'] == [BREAK_GLASS_GROUP]
    # Training never held MS.AAD.3.8v1 with both lists, nor MS.AAD.7.4v1 role exclusions of both kinds.
    policies = p.report['sections']['scuba_config']['synthesis']['policies']
    for pid in ('MS.AAD.3.8v1', 'MS.AAD.7.4v1'):
        assert case_config(p, pid) == NOT_COLLECTED and policies[pid] == 'unseen_shape'


@pytest.mark.parametrize('accounts,state', [(['nobody@example.invalid'], 'unresolved'), (None, None)])
def test_scuba_config_unresolved_or_unrecorded_list_withholds_exclusion_policies(complete_bundle, accounts, state):
    if accounts is None:
        p = project_run(identity_rows(complete_bundle))  # A manifest from before rule_parameters were recorded.
        assert p.report['sections']['scuba_config']['synthesis']['break_glass'] == {'source': 'unrecorded'}
    else:
        p = project_run(config_bundle(identity_rows(complete_bundle), accounts=accounts))
        assert p.report['sections']['scuba_config']['synthesis']['break_glass']['state'] == state
    policies = p.report['sections']['scuba_config']['synthesis']['policies']
    for pid in ('MS.AAD.1.1v1', 'MS.AAD.3.2v2', 'MS.AAD.7.4v1'):
        assert case_config(p, pid) == NOT_COLLECTED and policies[pid] == 'break_glass_unresolved'
    assert case_config(p, 'MS.AAD.3.3v2') == AAD_DEFAULT and case_config(p, 'MS.EXO.1.1v2') is None
    assert 'nobody' not in canonical(p.report)


def test_scuba_config_synthesis_validates_and_tampering_is_rejected(complete_bundle):
    schema = json.loads((ROOT / 'schemas/model_assessment.schema.json').read_text())
    config_bundle(complete_bundle)
    result = assess_run(complete_bundle, ModelConfig(model_name='stub'), policies=['MS.POWERBI.1.1v1'])
    validate_assessment(result)
    jsonschema.validate(result, schema)
    entry = result['projection']['sections']['scuba_config']
    for mutate in (lambda e: e['synthesis']['policies'].pop('MS.AAD.1.1v1'),
                   lambda e: e['synthesis']['policies'].update({'MS.AAD.1.1v1': 'guessed'}),
                   lambda e: e.pop('synthesis')):
        tampered = json.loads(json.dumps(result))
        mutate(tampered['projection']['sections']['scuba_config'])
        with pytest.raises(ValueError):
            validate_assessment(tampered)
    moved = json.loads(json.dumps(result))
    moved['projection']['sections']['SPO_tenant']['synthesis'] = entry['synthesis']
    with pytest.raises(ValueError):
        validate_assessment(moved)


@pytest.mark.parametrize('selected,reason', [(['identity'], 'dns_posture_not_run'),
                                             (['identity', 'dns_posture'], 'dns_records_not_saved')])
def test_dns_sections_say_why_they_are_missing(complete_bundle, selected, reason):
    payload = json.loads((complete_bundle / 'raw/dns_posture.json').read_text())
    for name in ('dmarc_records', 'spf_records', 'dkim_records'):
        payload.pop(name)
    payload['domainPosture'] = {'value': [], 'status': 'ok'}
    write(complete_bundle, 'raw/dns_posture.json', payload)
    manifest = json.loads((complete_bundle / 'run-manifest.json').read_text())
    write(complete_bundle, 'run-manifest.json', {**manifest, 'selected_collectors': selected})
    result = assess_run(complete_bundle, ModelConfig(model_name='stub'), policies=['MS.EXO.4.1v1'])
    for name in ('dmarc_records', 'spf_records', 'dkim_records'):
        assert result['projection']['sections'][name]['status'] == 'not_collected'
        assert result['projection']['sections'][name]['reason'] == reason
    validate_assessment(result)
    jsonschema.validate(result, json.loads((ROOT / 'schemas/model_assessment.schema.json').read_text()))


# --- Extra Graph fields never withhold; a failed read names its cause -----------------------------------------

def test_authorization_extra_permissions_are_ignored_and_reported(complete_bundle):
    # Graph added these to defaultUserRolePermissions; the training shape knows none of them and none is projected.
    path = 'raw/consent_policy.json'
    data = json.loads((complete_bundle / path).read_text())
    data['authorizationPolicy']['value'][0]['defaultUserRolePermissions'].update(
        allowedToCreateTenants=True, allowedToReadBitlockerKeysForOwnedDevice=True)
    write(complete_bundle, path, data)
    p = project_run(complete_bundle)
    assert p['authorization_policies'] == [AUTH]
    assert p.report['sections']['authorization_policies']['ignored_fields'] == [
        'DefaultUserRolePermissions.allowedToCreateTenants', 'DefaultUserRolePermissions.allowedToReadBitlockerKeysForOwnedDevice']
    validate_assessment(assess_run(complete_bundle, ModelConfig(model_name='stub'), policies=['MS.POWERBI.1.1v1']))


@pytest.mark.parametrize('mutation,expected', [
    ('enum', {'field': 'AllowInvitesFrom', 'kind': 'unseen_enum_value'}),
    ('type', {'field': 'DefaultUserRolePermissions.AllowedToCreateApps', 'kind': 'invalid_type'}),
    ('missing', {'field': 'DefaultUserRolePermissions.AllowedToCreateApps', 'kind': 'missing_field'}),
])
def test_extra_fields_do_not_excuse_enum_type_or_missing_fields(complete_bundle, mutation, expected):
    path = 'raw/consent_policy.json'
    data = json.loads((complete_bundle / path).read_text())
    row = data['authorizationPolicy']['value'][0]
    row['defaultUserRolePermissions']['allowedToCreateTenants'] = True
    if mutation == 'enum':
        row['allowInvitesFrom'] = 'unseenValue'
    elif mutation == 'type':
        row['defaultUserRolePermissions']['allowedToCreateApps'] = 'yes'
    else:
        del row['defaultUserRolePermissions']['allowedToCreateApps']
    write(complete_bundle, path, data)
    section = project_run(complete_bundle).report['sections']['authorization_policies']
    assert section['status'] == 'not_collected' and section['reason'] == 'incomplete_shape' and section['detail'] == expected


def test_ca_extra_fields_ignored_unless_populated_inside_conditions_or_controls(complete_bundle):
    row = graph(CA)
    row.update(templateId='template-1', deletedDateTime=None)
    row['conditions']['insiderRiskLevels'] = None
    row['grantControls']['newControls'] = []
    operation(complete_bundle, 'conditional_access', 'conditionalAccessPolicies', [row])
    p = project_run(complete_bundle, redact=False)
    assert p['conditional_access_policies'] == EXPECTED['conditional_access_policies']
    assert p.report['sections']['conditional_access_policies']['ignored_fields'] == [
        'conditions.insiderRiskLevels', 'deletedDateTime', 'grantControls.newControls', 'templateId']
    # A populated unknown condition can narrow who the policy covers: it withholds, as a known restriction does.
    row['conditions']['insiderRiskLevels'] = 'elevated'
    operation(complete_bundle, 'conditional_access', 'conditionalAccessPolicies', [row])
    section = project_run(complete_bundle).report['sections']['conditional_access_policies']
    assert section['status'] == 'not_collected'
    assert section['unsupported_conditions'] == ['conditions.unrecognisedField']


def test_collector_error_names_the_error_class_and_operation_never_the_message(complete_bundle):
    message = f'Forbidden for {PERSON} ({EMAIL})'
    operation(complete_bundle, 'licensing', 'subscribedSkus', [], error=message, error_class='permission_stop')
    result = assess_run(complete_bundle, ModelConfig(model_name='stub'), policies=['MS.POWERBI.1.1v1'])
    section = result['projection']['sections']['service_plans']
    assert section['status'] == 'not_collected' and section['reason'] == 'collector_error'
    assert section['detail'] == {'error_class': 'permission_stop', 'operation': 'licensing.subscribedSkus'}
    assert PERSON not in canonical(result) and EMAIL not in canonical(result)
    validate_assessment(result)
    jsonschema.validate(result, json.loads((ROOT / 'schemas/model_assessment.schema.json').read_text()))


@pytest.mark.parametrize('error_class', [None, 'Not A Class', PERSON])
def test_collector_error_class_outside_the_vocabulary_is_not_echoed(complete_bundle, error_class):
    operation(complete_bundle, 'licensing', 'subscribedSkus', [], error='Forbidden', error_class=error_class)
    section = project_run(complete_bundle).report['sections']['service_plans']
    assert section['reason'] == 'collector_error'
    assert section['detail'] == {'error_class': 'unclassified', 'operation': 'licensing.subscribedSkus'}


def pim_refused(root, error_class='license_required'):
    refuse_signin(root)
    for name in ('roleAssignmentSchedules', 'roleEligibilitySchedules'):
        operation(root, 'identity_governance', name, [], error='refused', error_class=error_class, item_count=0)
    write(root, 'coverage.json', [SIGNIN_COVERAGE] + [
        {'collector': 'identity_governance', 'type': 'graph', 'name': name, 'status': 'failed',
         'error_class': error_class, 'error': 'refused'} for name in ('roleAssignmentSchedules', 'roleEligibilitySchedules')])
    write(root, 'normalized/coverage_ledger.json', {'records': [
        ledger_row(diagnostics=[diagnostic('userSignInActivity')]),
        ledger_row('identity_governance', 'blocked_permission', 'permission_or_auth_blocker', diagnostics=[
            diagnostic('roleAssignmentSchedules', 'identity_governance', error_class),
            diagnostic('roleEligibilitySchedules', 'identity_governance', error_class)])]})
    (root / 'normalized/privileged_roles.json').unlink()


def test_no_p2_privileged_users_project_from_directory_roles(complete_bundle):
    # Without Entra ID P2 the PIM schedules are refused for want of a licence: the admin set is the directory role
    # assignments (the normaliser marks the schedule sources not_applicable) and the training shape has no PIM field.
    pim_refused(complete_bundle)
    result = assess_run(complete_bundle, ModelConfig(model_name='stub'), policies=['MS.POWERBI.1.1v1'])
    p = project_run(complete_bundle, redact=False)
    users = p.report['sections']['privileged_users']
    assert p['privileged_users'] == EXPECTED['privileged_users'] and users['status'] == 'projected'
    assert users['ignored_failures'] == [
        'identity.userSignInActivity', 'identity_governance.roleAssignmentSchedules', 'identity_governance.roleEligibilitySchedules']
    # Every frozen privileged_roles shape carries PIM rules: there is no no-P2 shape to project, so it is withheld and
    # the report says why.
    roles = p.report['sections']['privileged_roles']
    assert p['privileged_roles'] == NOT_COLLECTED and roles['reason'] == 'collector_error'
    assert roles['detail'] == {'error_class': 'license_required', 'operation': 'identity_governance.roleAssignmentSchedules'}
    validate_assessment(result)
    jsonschema.validate(result, json.loads((ROOT / 'schemas/model_assessment.schema.json').read_text()))


@pytest.mark.parametrize('error_class', ['permission_stop', 'insufficient_permissions'])
def test_pim_refused_for_another_reason_withholds_privileged_users(complete_bundle, error_class):
    # A refused permission can hide eligible assignments in a licensed tenant: only a licence refusal is the no-P2 case.
    pim_refused(complete_bundle, error_class)
    users = project_run(complete_bundle).report['sections']['privileged_users']
    assert users['reason'] == 'collector_error'
    assert users['detail'] == {'error_class': error_class, 'operation': 'identity_governance.roleAssignmentSchedules'}


def test_licence_refusal_with_rows_is_not_the_no_p2_case(complete_bundle):
    pim_refused(complete_bundle)
    operation(complete_bundle, 'identity_governance', 'roleAssignmentSchedules', [SCHEDULE],
              error='refused', error_class='license_required')
    assert project_run(complete_bundle).report['sections']['privileged_users']['reason'] == 'collector_error'


def test_ledger_collector_error_reports_the_failed_read_not_the_first_diagnostic(complete_bundle):
    write(complete_bundle, 'normalized/coverage_ledger.json', {'records': [
        ledger_row('identity_governance', 'blocked_permission', 'permission_or_auth_blocker', diagnostics=[
            diagnostic('accessReviews', 'identity_governance', 'insufficient_permissions'),
            diagnostic('roleEligibilitySchedules', 'identity_governance', 'permission_stop')])]})
    operation(complete_bundle, 'identity_governance', 'accessReviews', [], error='refused', error_class='insufficient_permissions')
    operation(complete_bundle, 'identity_governance', 'roleEligibilitySchedules', [])
    users = project_run(complete_bundle).report['sections']['privileged_users']
    assert users['detail'] == {'error_class': 'permission_stop', 'operation': 'identity_governance.roleEligibilitySchedules'}


def test_failed_group_fanout_does_not_withhold_tenant_id(complete_bundle):
    # The fan-out is a derived coverage row the identity payload has no operation for; tenant_id does not read it.
    write(complete_bundle, 'normalized/coverage_ledger.json', {'records': [
        ledger_row(diagnostics=[diagnostic('userSignInActivity'), diagnostic('privilegedGroupFanout', error_class='incomplete_evidence')])]})
    refuse_signin(complete_bundle)
    p = project_run(complete_bundle)
    assert p['tenant_id'] == TENANT
    assert p.report['sections']['tenant_id']['ignored_failures'] == ['identity.privilegedGroupFanout', 'identity.userSignInActivity']
    # privileged_users reads the fan-out, so the same row withholds it.
    users = p.report['sections']['privileged_users']
    assert users['reason'] == 'collector_error' and users['detail']['operation'] == 'identity.privilegedGroupFanout'


@pytest.mark.parametrize('sample,expected', [
    ([{'id': TENANT, 'onPremisesImmutableId': None}], 'projected'),
    ([{'id': 'someone-else', 'onPremisesImmutableId': None}], 'not_collected'),
    (None, 'not_collected'),
])
def test_immutable_id_comes_from_the_sync_sample_when_the_user_read_lacks_it(complete_bundle, sample, expected):
    operation(complete_bundle, 'identity', 'users', [{'id': TENANT, 'displayName': PERSON}])
    if sample is not None:
        operation(complete_bundle, 'domains_hybrid', 'syncSampleUsers', sample)
    p = project_run(complete_bundle, redact=False)
    users = p.report['sections']['privileged_users']
    assert users['status'] == expected
    if expected == 'projected':
        assert p['privileged_users'] == EXPECTED['privileged_users']
        assert 'chunks/domains_hybrid' not in canonical(users['source']) and 'raw/domains_hybrid.json' in users['source']
    else:
        assert users['detail'] == {'field': 'OnPremisesImmutableId', 'kind': 'missing_field'}


@pytest.mark.parametrize('ignored', [['b', 'a'], ['a', 'a'], ['has space'], [PERSON]])
def test_ignored_fields_validation(complete_bundle, ignored):
    result = assess_run(complete_bundle, ModelConfig(model_name='stub'), policies=['MS.POWERBI.1.1v1'])
    result['projection']['sections']['service_plans']['ignored_fields'] = ['a', 'b.c']
    validate_assessment(result)
    result['projection']['sections']['service_plans']['ignored_fields'] = ignored
    with pytest.raises(ValueError):
        validate_assessment(result)


@pytest.mark.parametrize('section,reason,diagnostic', [
    ('service_plans', 'collector_error', {'field': 'error', 'kind': 'unseen_shape'}),
    ('service_plans', 'collector_error', {'error_class': 'license_required', 'message': 'Forbidden'}),
    ('service_plans', 'collector_error', None),
    ('service_plans', 'incomplete_shape', {'error_class': 'license_required'}),
    ('service_plans', 'collector_error', {'error_class': PERSON}),
])
def test_collector_error_detail_validation(complete_bundle, section, reason, diagnostic):
    operation(complete_bundle, 'licensing', 'subscribedSkus', [], error='Forbidden', error_class='license_required')
    result = assess_run(complete_bundle, ModelConfig(model_name='stub'), policies=['MS.POWERBI.1.1v1'])
    validate_assessment(result)
    entry = result['projection']['sections'][section]
    entry.update(status='not_collected', reason=reason)
    entry.pop('detail', None)
    if diagnostic is not None:
        entry['detail'] = diagnostic
    with pytest.raises(ValueError):
        validate_assessment(result)


# --- Qualifiers that can scope a kept field withhold; every ignored source field is recorded -----------------------

def roles_with(mutate):
    roles = json.loads(json.dumps(ROLES))
    mutate(roles[0])
    return roles


TARGET = {'@odata.type': '#microsoft.graph.unifiedRoleManagementPolicyRuleTarget', 'caller': 'Admin', 'level': 'Assignment',
          'operations': ['All'], 'inheritableSettings': [], 'enforcedSettings': [], 'targetObjects': None}


@pytest.mark.parametrize('where,key,value,withheld', [
    # A populated scope or applicability qualifier the frozen shape cannot carry withholds, naming the field.
    ('Assignments', 'DirectoryScopeId', '/administrativeUnits/11111111-2222-4333-8444-555555555555', True),
    ('Assignments', 'AppScopeId', '/apps/x', True),
    ('Assignments', 'MemberType', 'Group', True),
    ('Assignments', 'Status', 'Revoked', True),
    ('Assignments', 'RoleDefinitionId', 'AnotherRole', True),
    ('Rules', 'Target', {**TARGET, 'level': 'Eligibility'}, True),
    ('Rules', 'Target', {**TARGET, 'targetObjects': ['restricted']}, True),
    ('Rules', 'Target', {**TARGET, 'operations': ['selfActivate']}, True),
    ('Rules', 'Target', {**TARGET, 'unknownQualifier': 'x'}, True),
    ('Rules', 'NotificationLevel', 'Critical', True),
    ('Rules.Setting', 'ApprovalStages', [{'primaryApprovers': ['x']}], True),
    ('$', 'IsEnabled', False, True),
    # Empty, tenant-wide or restating what is kept: ignored and reported.
    ('Assignments', 'DirectoryScopeId', '/', False),
    ('Assignments', 'DirectoryScopeId', None, False),
    ('Assignments', 'AppScopeId', '', False),
    ('Assignments', 'RoleDefinitionId', 'role1', False),
    ('Rules', 'Target', TARGET, False),
    ('Rules', 'Target', {'Caller': 'Admin', 'Level': 'Assignment', 'Operations': ['All']}, False),
    ('Rules', 'Target', {}, False),
    ('Rules.Setting', 'ApprovalStages', [], False),
    ('$', 'IsBuiltIn', True, False),
])
def test_privileged_role_qualifiers_withhold_when_populated(complete_bundle, where, key, value, withheld):
    def mutate(role):
        target = {'$': role, 'Assignments': role['Assignments'][0], 'Rules': role['Rules'][0],
                  'Rules.Setting': role['Rules'][0]['Setting']}[where]
        target[key] = value
    write(complete_bundle, 'normalized/privileged_roles.json', {'records': roles_with(mutate)})
    p = project_run(complete_bundle, redact=False)
    section = p.report['sections']['privileged_roles']
    field = key if where == '$' else f'{where}.{key}'
    if withheld:
        assert p['privileged_roles'] == NOT_COLLECTED and section['reason'] == 'incomplete_shape'
        assert section['detail'] == {'field': field, 'kind': 'unexpected_field'}
        assert 'restricted' not in canonical(p.report) and '/administrativeUnits' not in canonical(p.report)
    else:
        assert p['privileged_roles'] == ROLES and section['ignored_fields'] == [field]
    validate_assessment(assess_run(complete_bundle, ModelConfig(model_name='stub'), policies=['MS.POWERBI.1.1v1']))


@pytest.mark.parametrize('rule_id,recipient,withheld', [
    ('Notification_Admin_Admin_Eligibility', 'Admin', False),
    ('Notification_Admin_Admin_Eligibility', 'Requestor', True),
    ('Expiration_Admin_Assignment', 'Admin', True),
])
def test_notification_recipient_type_must_restate_the_rule_id(complete_bundle, rule_id, recipient, withheld):
    def mutate(role):
        next(rule for rule in role['Rules'] if rule['Id'] == rule_id)['RecipientType'] = recipient
    write(complete_bundle, 'normalized/privileged_roles.json', {'records': roles_with(mutate)})
    p = project_run(complete_bundle)
    section = p.report['sections']['privileged_roles']
    assert (p['privileged_roles'] == NOT_COLLECTED) is withheld
    if withheld:
        assert section['detail'] == {'field': 'Rules.RecipientType', 'kind': 'unexpected_field'}
    else:
        assert section['ignored_fields'] == ['Rules.RecipientType']


@pytest.mark.parametrize('roles,detail', [
    ([{'role': 'Global Administrator', 'scope': '/administrativeUnits/11111111-2222-4333-8444-555555555555'}],
     {'field': 'roles.scope', 'kind': 'unseen_enum_value'}),
    ([{'role': 'Global Administrator'}], {'field': 'roles.scope', 'kind': 'missing_field'}),
    ([], {'field': 'roles.role', 'kind': 'missing_field'}),
    (None, {'field': 'roles', 'kind': 'missing_field'}),
    # A scoped assignment of a role also held tenant-wide changes nothing.
    ([{'role': 'Global Administrator', 'scope': '/administrativeUnits/x'}, GLOBAL_ADMIN_ROLE], None),
])
def test_privileged_users_withhold_a_role_held_only_at_a_scope(complete_bundle, roles, detail):
    data = json.loads((complete_bundle / 'normalized/effective_admin_set.json').read_text())
    admin = data['records'][1]
    if roles is None:
        del admin['roles']
    else:
        admin['roles'] = roles
    write(complete_bundle, 'normalized/effective_admin_set.json', data)
    p = project_run(complete_bundle, redact=False)
    section = p.report['sections']['privileged_users']
    if detail is None:
        assert p['privileged_users'] == EXPECTED['privileged_users']
    else:
        assert p['privileged_users'] == NOT_COLLECTED and section['detail'] == detail
        assert 'administrativeUnits' not in canonical(p.report)
    validate_assessment(assess_run(complete_bundle, ModelConfig(model_name='stub'), policies=['MS.POWERBI.1.1v1']))


def test_service_plans_keep_only_provisioned_plans_as_scubagear_does(complete_bundle):
    plan = graph(EXPECTED['service_plans'][0])
    others = [{'servicePlanId': f'{n}1111111-1111-4111-8111-111111111111', 'servicePlanName': name, 'provisioningStatus': status}
              for n, (name, status) in enumerate([('EXCHANGE_S_STANDARD', 'Disabled'), ('INTUNE_A', 'PendingActivation')])]
    operation(complete_bundle, 'licensing', 'subscribedSkus', [{'servicePlans': [{**plan, 'provisioningStatus': 'Success'}, *others]}])
    assert project_run(complete_bundle)['service_plans'] == EXPECTED['service_plans']
    # The same plan disabled in one SKU and provisioned in another is the tenant's.
    operation(complete_bundle, 'licensing', 'subscribedSkus', [
        {'servicePlans': [{**plan, 'provisioningStatus': 'Disabled'}]}, {'servicePlans': [{**plan, 'provisioningStatus': 'Success'}]}])
    assert project_run(complete_bundle)['service_plans'] == EXPECTED['service_plans']
    # No provisioned plan at all: an empty list, as ScubaGear exports it, not a withheld section.
    operation(complete_bundle, 'licensing', 'subscribedSkus', [{'servicePlans': others}], item_count=1)
    p = project_run(complete_bundle)
    assert p['service_plans'] == [] and p.report['sections']['service_plans']['status'] == 'projected'


@pytest.mark.parametrize('section,path,locate,ignored', [
    ('SPO_tenant', 'raw/sharepoint_access.json', ('sharePointSettings', 'value', 0), ['newSetting']),
    ('authorization_policies', 'raw/consent_policy.json', ('authorizationPolicy', 'value', 0), ['newSetting']),
    ('service_plans', 'raw/licensing.json', ('subscribedSkus', 'value', 0), ['newSetting', 'skuPartNumber']),
    ('privileged_users', 'raw/identity.json', ('users', 'value', 0), ['newSetting']),
    ('conditional_access_policies', 'raw/conditional_access.json', ('conditionalAccessPolicies', 'value', 0), ['newSetting']),
])
def test_every_adapter_reports_a_new_source_field(complete_bundle, section, path, locate, ignored):
    data = json.loads((complete_bundle / path).read_text())
    row = data
    for key in locate:
        row = row[key]
    row.update({'newSetting': 'Injected Private Person', '@odata.type': '#microsoft.graph.thing'})
    write(complete_bundle, path, data)
    p = project_run(complete_bundle, redact=False)
    assert p[section] == EXPECTED[section] and p.report['sections'][section]['ignored_fields'] == ignored
    assert 'Injected Private Person' not in canonical(p) and 'Injected Private Person' not in canonical(p.report)
    validate_assessment(assess_run(complete_bundle, ModelConfig(model_name='stub'), policies=['MS.POWERBI.1.1v1']))


def test_ca_records_policy_metadata_and_skips_nested_annotations(complete_bundle):
    row = graph(CA)
    row.update(id='policy-id', createdDateTime='2026-01-01T00:00:00Z', templateId=None)
    row['grantControls']['authenticationStrength@odata.context'] = 'https://graph.microsoft.com/v1.0/$metadata#x'
    row['conditions']['applications']['@odata.type'] = '#microsoft.graph.conditionalAccessApplications'
    operation(complete_bundle, 'conditional_access', 'conditionalAccessPolicies', [row])
    p = project_run(complete_bundle, redact=False)
    assert p['conditional_access_policies'] == [CA]
    assert p.report['sections']['conditional_access_policies']['ignored_fields'] == ['createdDateTime', 'id', 'templateId']


@pytest.mark.parametrize('error_class,reported', [
    ('alice_smith', 'unclassified'), ('graph_http_429', 'graph_http_429'), ('graph_http_None', 'unclassified'),
    ('license_required', 'license_required'), ('section_absent', 'section_absent'),
])
def test_collector_error_class_is_checked_against_the_collector_vocabulary(complete_bundle, error_class, reported):
    operation(complete_bundle, 'licensing', 'subscribedSkus', [], error='Forbidden', error_class=error_class)
    result = assess_run(complete_bundle, ModelConfig(model_name='stub'), policies=['MS.POWERBI.1.1v1'])
    assert result['projection']['sections']['service_plans']['detail']['error_class'] == reported
    validate_assessment(result)
    result['projection']['sections']['service_plans']['detail']['error_class'] = 'alice_smith'
    with pytest.raises(ValueError, match='error class'):
        validate_assessment(result)


@pytest.mark.parametrize('environment', ['gcchigh', 'dod', 'unknown', None])
@pytest.mark.parametrize('error_class,reported', [
    ('unsupported_environment', 'unsupported_environment'), ('alice_smith', 'unclassified'),
])
def test_teams_unsupported_environment_error_projects_and_validates(
        complete_bundle, monkeypatch, environment, error_class, reported):
    from azure_tenant_audit.adapters import teams_admin_rest

    def no_request(*args, **kwargs):
        pytest.fail('Unsupported Teams environments must not make a request')

    monkeypatch.setattr(teams_admin_rest.requests, 'get', no_request)
    marker = teams_admin_rest.TeamsAdminRestAdapter().get('meetingPolicies', None, environment)
    assert marker == {'error': 'unsupported_environment', 'error_class': 'unsupported_environment'}
    marker['error_class'] = error_class
    operation(complete_bundle, 'teams_policy', 'meetingPolicies', [], status='error', **marker)
    projection = project_run(complete_bundle)
    assert projection['meeting_policies'] == NOT_COLLECTED
    result = assess_run(complete_bundle, ModelConfig(model_name='stub'), policies=['MS.TEAMS.1.1v1'])
    section = result['projection']['sections']['meeting_policies']
    assert section['status'] == 'not_collected' and section['reason'] == 'collector_error'
    assert section['detail'] == {'error_class': reported, 'operation': 'teams_policy.meetingPolicies'}
    validate_assessment(result)
    jsonschema.validate(result, json.loads((ROOT / 'schemas/model_assessment.schema.json').read_text()))
    section['detail']['error_class'] = 'alice_smith'
    with pytest.raises(ValueError, match='error class'):
        validate_assessment(result)


def test_collector_error_vocabulary_covers_every_class_the_engine_writes():
    # Every error class literal under src/azure_tenant_audit: classifier returns, ``error_class`` dict values and keyword
    # arguments, and names ending in error_class. A new one must be added to COLLECTOR_ERROR_CLASSES or it reads unclassified.
    import ast
    from azure_tenant_audit.model_assessment import COLLECTOR_ERROR_CLASSES

    def literals(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return {node.value}
        if isinstance(node, ast.IfExp):
            return literals(node.body) | literals(node.orelse)
        if isinstance(node, ast.BoolOp):
            return set().union(*(literals(v) for v in node.values))
        return set()

    found: dict[str, str] = {}
    for path in sorted((ROOT / 'src/azure_tenant_audit').rglob('*.py')):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            values = set()
            if isinstance(node, ast.FunctionDef) and 'classif' in node.name and 'error' in node.name:
                values = set().union(*(literals(r.value.elts[0]) for r in ast.walk(node)
                                       if isinstance(r, ast.Return) and isinstance(r.value, ast.Tuple)))
            elif isinstance(node, ast.Dict):
                values = set().union(*(literals(v) for k, v in zip(node.keys, node.values)
                                       if isinstance(k, ast.Constant) and k.value == 'error_class'))
            elif isinstance(node, ast.keyword) and node.arg and node.arg.endswith('error_class'):
                values = literals(node.value)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                    if isinstance(target, ast.Name) and target.id.lower().endswith('error_class') and node.value is not None:
                        values |= literals(node.value)
            for value in values:
                found.setdefault(value, f'{path.name}:{node.lineno}')
    assert len(found) > 40
    assert {k: v for k, v in found.items() if k not in COLLECTOR_ERROR_CLASSES} == {}


def test_service_plan_without_provisioning_status_withholds_the_section(complete_bundle):
    """A raw plan that does not say whether it is provisioned cannot assert a licence: the section is withheld, not defaulted."""
    operation(complete_bundle, 'licensing', 'subscribedSkus',
              [{'skuPartNumber': 'SPE_E5', 'servicePlans': [graph(EXPECTED['service_plans'][0])]}])
    p = project_run(complete_bundle)
    assert p['service_plans'] == NOT_COLLECTED
    section = p.report['sections']['service_plans']
    assert section['reason'] == 'incomplete_shape' and section['detail'] == {'field': 'servicePlans.provisioningStatus', 'kind': 'missing_field'}


def test_text_validators_reject_lone_surrogates():
    """Evidence text with a lone surrogate (a JSON \\ud800 escape) is not valid interchange text: the typed field checks
    refuse it, so the section is withheld as an invalid type instead of reaching a hash or a request body."""
    from auditex.scuba_projection import _nullable_text, _strings, _text
    assert _text("Global Administrator") and _nullable_text(None) and _strings(["a", "b"])
    assert not _text("x\ud800y") and not _nullable_text("\udfff") and not _strings(["ok", "\ud800"])


def _gate_admits_users(users):
    from auditex import scuba_projection as sp
    return sha256(sp._json(sp._shape(users)).encode()).hexdigest() in sp.PACK_SHAPE_DIGESTS['privileged_users']


_ROLES = ['Global Administrator']
_USER_MIXED = {
    'User1': {'DisplayName': PERSON, 'roles': _ROLES},
    'User2': {'DisplayName': 'Second Person', 'OnPremisesImmutableId': None, 'roles': _ROLES}}


def test_the_gate_admits_a_users_value_with_one_entry_missing_the_immutable_id_key():
    # Shape digests record the distinct entry shapes, so a mix of key-less and null entries is a seen shape.
    # Premise pin: delete with the 44e39708 digest.
    assert _gate_admits_users(_USER_MIXED)


@pytest.mark.parametrize('redact', [True, False])
def test_a_gate_admitted_users_entry_missing_the_immutable_id_key_withholds_instead_of_crashing(
        complete_bundle, monkeypatch, redact):
    from auditex import scuba_projection as sp
    monkeypatch.setattr(sp, '_users', lambda bundle: {k: dict(v) for k, v in _USER_MIXED.items()})
    p = project_run(complete_bundle, redact=redact)
    section = p.report['sections']['privileged_users']
    assert p['privileged_users'] == NOT_COLLECTED
    assert section['status'] == 'not_collected' and section['reason'] == 'incomplete_shape'
    assert section['detail'] == {'field': 'User1.OnPremisesImmutableId', 'kind': 'missing_field'}
    assert PERSON not in canonical(p) and 'Second Person' not in canonical(p)
    # Sections that do not depend on the user list are unaffected.
    assert p.report['sections']['service_plans']['status'] == 'projected'


@pytest.mark.parametrize('users', [
    {'User1': {'DisplayName': PERSON, 'OnPremisesImmutableId': None, 'roles': _ROLES}},
    {'User1': {'DisplayName': PERSON, 'OnPremisesImmutableId': 'immutable', 'roles': _ROLES}},
    {'User1': {'DisplayName': PERSON, 'OnPremisesImmutableId': None, 'roles': _ROLES},
     'User2': {'DisplayName': 'Second Person', 'OnPremisesImmutableId': 'immutable', 'roles': _ROLES}}])
def test_neighbouring_valid_users_shapes_still_project_and_redact(complete_bundle, monkeypatch, users):
    from auditex import scuba_projection as sp
    monkeypatch.setattr(sp, '_users', lambda bundle: {k: dict(v) for k, v in users.items()})
    p = project_run(complete_bundle)
    assert p.report['sections']['privileged_users']['status'] == 'projected'
    assert p.report['redaction']['user_display_names'] == len(users)
    assert p.report['redaction']['immutable_ids'] == sum(u['OnPremisesImmutableId'] is not None for u in users.values())
    assert all(u['DisplayName'].startswith('User ') and u['DisplayName'] != PERSON for u in p['privileged_users'].values())
    assert all(u['OnPremisesImmutableId'] is None or u['OnPremisesImmutableId'].startswith('Id ')
               for u in p['privileged_users'].values()) and 'immutable' not in canonical(p)
