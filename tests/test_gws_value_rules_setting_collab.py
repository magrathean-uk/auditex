"""Collaboration setting rows: a literal pin of every row, synthetic inputs and literal verdicts.

ROWS is a second, hand-written copy of design section 14 for the 36 collaboration rows. Each line is checked against the
cited ScubaGoggles v1.1.0 predicate (Drive.rego, Calendar.rego, Chat.rego, Meet.rego, Groups.rego, Sites.rego,
Classroom.rego, Assuredcontrols.rego) and is never read back from the config under test.
"""
import copy
import json
from pathlib import Path

import pytest

from azure_tenant_audit.value_rules import gws
from azure_tenant_audit.value_rules.gws.catalogue import catalogue

VECTORS = [json.loads(line) for line in (Path(__file__).parent / 'fixtures/gws-value-rules/setting-collab.jsonl')
           .read_text().splitlines()]
GOOD = [v for v in VECTORS if v['verdict'] == 'met']

ALL, EXPLICIT = 'all_units', 'explicit_only'
DRIVE, CAL, CHAT, MEET, GROUPS, CLASS = 'drive_and_docs', 'calendar', 'chat', 'meet', 'groups_for_business', 'classroom'
# policy -> (section, field, op, pinned value, service, scope, vocabulary or None). `op` marks the violation:
# `ne X` violates on anything but X, `eq X` on X itself, `not_in [..]` on anything outside the list.
ROWS = {
    'DRIVEDOCS.1.1': ('drive_and_docs_external_sharing', 'externalSharingMode', 'not_in',
                      ['ALLOWLISTED_DOMAINS', 'DISALLOWED'], DRIVE, ALL, ['ALLOWED', 'ALLOWLISTED_DOMAINS', 'DISALLOWED']),
    'DRIVEDOCS.1.6': ('drive_and_docs_external_sharing', 'accessCheckerSuggestions', 'ne', 'RECIPIENTS_ONLY', DRIVE, ALL,
                      ['RECIPIENTS_ONLY', 'RECIPIENTS_OR_AUDIENCE', 'RECIPIENTS_OR_AUDIENCE_OR_PUBLIC']),
    'DRIVEDOCS.1.8': ('drive_and_docs_general_access_default', 'defaultFileAccess', 'ne', 'PRIVATE_TO_OWNER', DRIVE, ALL,
                      ['PRIVATE_TO_OWNER', 'PRIMARY_AUDIENCE_WITH_LINK', 'PRIMARY_AUDIENCE_WITH_LINK_OR_SEARCH',
                       'LINK_SHARING_PRIVATE']),
    'DRIVEDOCS.1.9': ('drive_and_docs_external_file_warning', 'highlightingEnabled', 'ne', True, DRIVE, ALL, None),
    'DRIVEDOCS.2.1': ('drive_and_docs_shared_drive_creation', 'allowManagersToOverrideSettings', 'ne', False, DRIVE, ALL,
                      None),
    'DRIVEDOCS.2.2': ('drive_and_docs_shared_drive_creation', 'allowNonMemberAccess', 'ne', True, DRIVE, ALL, None),
    'DRIVEDOCS.4.1': ('drive_and_docs_drive_sdk', 'enableDriveSdkApiAccess', 'ne', False, DRIVE, ALL, None),
    'CALENDAR.1.1': ('calendar_primary_calendar_max_allowed_external_sharing', 'maxAllowedExternalSharing', 'ne',
                     'EXTERNAL_FREE_BUSY_ONLY', CAL, ALL,
                     ['EXTERNAL_FREE_BUSY_ONLY', 'EXTERNAL_ALL_INFO_READ_ONLY', 'EXTERNAL_ALL_INFO_READ_WRITE',
                      'EXTERNAL_ALL_INFO_READ_WRITE_MANAGE']),
    'CALENDAR.1.2': ('calendar_secondary_calendar_max_allowed_external_sharing', 'maxAllowedExternalSharing', 'ne',
                     'EXTERNAL_FREE_BUSY_ONLY', CAL, ALL,
                     ['EXTERNAL_FREE_BUSY_ONLY', 'EXTERNAL_ALL_INFO_READ_ONLY', 'EXTERNAL_ALL_INFO_READ_WRITE',
                      'EXTERNAL_ALL_INFO_READ_WRITE_MANAGE']),
    'CALENDAR.2.1': ('calendar_external_invitations', 'warnOnInvite', 'ne', True, CAL, ALL, None),
    'CALENDAR.3.1': ('calendar_interoperability', 'enableInteroperability', 'ne', False, CAL, ALL, None),
    'CALENDAR.4.1': ('calendar_appointment_schedules', 'enablePayments', 'ne', False, CAL, ALL, None),
    'CHAT.1.1': ('chat_chat_history', 'historyOnByDefault', 'eq', False, CHAT, ALL, None),
    'CHAT.1.2': ('chat_chat_history', 'allowUserModification', 'ne', False, CHAT, ALL, None),
    'CHAT.2.1': ('chat_chat_file_sharing', 'externalFileSharing', 'ne', 'NO_FILES', CHAT, ALL,
                 ['NO_FILES', 'ALL_FILES', 'IMAGES_ONLY', 'FILE_SHARING_OPTION_UNSPECIFIED']),
    'CHAT.3.1': ('chat_space_history', 'historyState', 'ne', 'HISTORY_ALWAYS_ON', CHAT, ALL,
                 ['HISTORY_ALWAYS_ON', 'HISTORY_ALWAYS_OFF', 'DEFAULT_HISTORY_OFF', 'DEFAULT_HISTORY_ON',
                  'HISTORY_STATE_UNSPECIFIED']),
    'MEET.1.1': ('meet_meet_joining', 'allowedAudience', 'not_in', ['TRUSTED', 'RESTRICTED'], MEET, ALL,
                 ['TRUSTED', 'RESTRICTED', 'OPEN', 'ALLOWED_AUDIENCE_UNSPECIFIED']),
    'MEET.2.1': ('meet_safety_access', 'meetingsAllowedToJoin', 'not_in',
                 ['SAME_ORGANIZATION_ONLY', 'ANY_WORKSPACE_ORGANIZATION'], MEET, ALL,
                 ['SAME_ORGANIZATION_ONLY', 'ANY_WORKSPACE_ORGANIZATION', 'ALL']),
    'MEET.3.1': ('meet_safety_host_management', 'enableHostManagement', 'ne', True, MEET, ALL, None),
    'MEET.4.1': ('meet_safety_external_participants', 'enableExternalLabel', 'ne', True, MEET, ALL, None),
    'MEET.5.1': ('meet_automatic_recording', 'enabled', 'eq', True, MEET, ALL, None),
    'MEET.5.2': ('meet_automatic_transcription', 'enabled', 'eq', True, MEET, ALL, None),
    'GROUPS.1.1': ('groups_for_business_groups_sharing', 'collaborationCapability', 'ne', 'DOMAIN_USERS_ONLY', GROUPS, ALL,
                   ['DOMAIN_USERS_ONLY', 'ANYONE_CAN_ACCESS']),
    'GROUPS.1.2': ('groups_for_business_groups_sharing', 'ownersCanAllowExternalMembers', 'ne', False, GROUPS, ALL, None),
    'GROUPS.1.3': ('groups_for_business_groups_sharing', 'ownersCanAllowIncomingMailFromPublic', 'ne', False, GROUPS, ALL,
                   None),
    'GROUPS.2.1': ('groups_for_business_groups_sharing', 'createGroupsAccessLevel', 'ne', 'ADMIN_ONLY', GROUPS, ALL,
                   ['ADMIN_ONLY', 'USERS_IN_DOMAIN', 'ANYONE_CAN_CREATE']),
    'GROUPS.3.1': ('groups_for_business_groups_sharing', 'viewTopicsDefaultAccessLevel', 'ne', 'GROUP_MEMBERS', GROUPS, ALL,
                   ['OWNERS', 'MANAGERS', 'GROUP_MEMBERS', 'DOMAIN_USERS', 'ANYONE_CAN_VIEW_TOPICS']),
    'SITES.1.1': ('sites_service_status', 'serviceState', 'eq', 'ENABLED', None, EXPLICIT, ['DISABLED', 'ENABLED']),
    'CLASSROOM.1.1': ('classroom_class_membership', 'whoCanJoinClasses', 'not_in',
                      ['ANYONE_IN_DOMAIN', 'ANYONE_IN_ALLOWLISTED_DOMAINS'], CLASS, ALL,
                      ['ANYONE_IN_DOMAIN', 'ANYONE_IN_ALLOWLISTED_DOMAINS', 'ANY_GOOGLE_WORKSPACE_USER', 'ANYONE']),
    'CLASSROOM.1.2': ('classroom_class_membership', 'whichClassesCanUsersJoin', 'not_in',
                      ['CLASSES_IN_DOMAIN', 'CLASSES_IN_ALLOWLISTED_DOMAINS'], CLASS, ALL,
                      ['CLASSES_IN_DOMAIN', 'CLASSES_IN_ALLOWLISTED_DOMAINS', 'ANY_GOOGLE_WORKSPACE_CLASS']),
    'CLASSROOM.2.1': ('classroom_api_data_access', 'enableApiAccess', 'ne', False, CLASS, ALL, None),
    'CLASSROOM.3.1': ('classroom_roster_import', 'rosterImportOption', 'ne', 'OFF', CLASS, ALL, ['OFF', 'ON_CLEVER']),
    'CLASSROOM.4.1': ('classroom_student_unenrollment', 'whoCanUnenrollStudents', 'ne', 'TEACHERS_ONLY', CLASS, ALL,
                      ['TEACHERS_ONLY', 'STUDENTS_AND_TEACHERS']),
    'CLASSROOM.5.1': ('classroom_teacher_permissions', 'whoCanCreateClasses', 'ne', 'VERIFIED_TEACHERS_ONLY', CLASS, ALL,
                      ['VERIFIED_TEACHERS_ONLY', 'ALL_PENDING_AND_VERIFIED_TEACHERS', 'ANYONE_IN_DOMAIN']),
    'ASSUREDCONTROLS.1.1': ('access_approval_axa_user_scoping', 'requiresCustomerApproval', 'ne', True, None, ALL, None),
    'ASSUREDCONTROLS.1.2': ('access_management_user_scoping', 'accessManagementRegime', 'not_in',
                            ['CJIS_IRS_1075_GOOGLE_STAFF', 'US_GOOGLE_STAFF'], None, ALL,
                            ['CJIS_IRS_1075_GOOGLE_STAFF', 'US_GOOGLE_STAFF', 'PREFERENCE_UNSPECIFIED',
                             'EU_GOOGLE_STAFF']),
}
IDS = {f'GWS.{key}v1': value for key, value in ROWS.items()}
FOLDED = {'GWS.SITES.1.1v1'}
EXPLICIT_ONLY = {'GWS.COMMONCONTROLS.16.1v1', 'GWS.COMMONCONTROLS.16.2v1', 'GWS.SITES.1.1v1'}
TENANT = {'as_of': '2026-11-25T12:00:00Z', 'top_unit': 'ou:root', 'org_units': {'ou:root': None, 'ou:a': 'ou:root'},
          'complete': True}


def _p(unit, section, value, kind='org_unit'):
    return {'unit': unit, 'unit_kind': kind, 'section': section, 'sort_order': 1, 'value': value}


def _sections(policies):
    return {'gws_tenant': copy.deepcopy(TENANT), 'gws_policies': {'complete': True, 'policies': policies}}


def _on(pid, state='ENABLED', unit='ou:root'):
    return _p(unit, f'{IDS[pid][4]}_service_status', {'serviceState': state})


def _with(pid, value, unit='ou:root', gate='ENABLED'):
    """Root service status (when the row is gated) plus one record of the row's field holding ``value``."""
    section, field = IDS[pid][0], IDS[pid][1]
    records = [_on(pid, gate)] if IDS[pid][4] else []
    return _sections(records + [_p(unit, section, {field: value})])


def _violating(pid):
    return next(v for v in VECTORS if v['policy'] == pid and v['verdict'] == 'not_met')['sections']['gws_policies'][
        'policies'][-1]['value'][IDS[pid][1]]


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
    if IDS[vector['policy']][4] is None:
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
    if IDS[vector['policy']][6] is not None:
        sections = copy.deepcopy(vector['sections'])
        sections['gws_policies']['policies'][-1]['value'][IDS[vector['policy']][1]] = 'NOT_A_VALID_VALUE'
        assert answer(vector, sections) == ('not_assessed', 'setting_value_unusable')
    bad = next(v for v in VECTORS if v['policy'] == vector['policy'] and v['verdict'] == 'not_met')
    sections = copy.deepcopy(vector['sections'])
    group = copy.deepcopy(bad['sections']['gws_policies']['policies'][-1])
    group['unit'] = 'ou:root/group:g1'
    group['unit_kind'] = 'group'
    sections['gws_policies']['policies'].append(group)
    assert answer(vector, sections) == ('not_met', 'unit_violates')


# --- the literal pin of every row --------------------------------------------------------------------------------------

def test_the_36_rows_use_the_setting_kind_and_the_pinned_parameters():
    assert len(ROWS) == 36
    policies = catalogue()['policies']
    for pid, (section, field, op, value, service, scope, known) in IDS.items():
        row = policies[pid]
        assert row['kind'] == 'setting' and row['rule_id'] == f'{pid}.setting', pid
        assert row['sections'] == ['gws_tenant', 'gws_policies'], pid
        params = dict(row['params'])
        assert ('source' in params) == (known is not None), pid
        assert params.pop('source', 'SG:scubagoggles/').startswith('SG:scubagoggles/'), pid
        assert params.pop('known', None) == known, pid
        assert params.pop('case', 'exact') == ('fold' if pid in FOLDED else 'exact'), pid
        assert params == {'section': section, 'field': field, 'op': op, 'value': value, 'service': service,
                          'scope': scope}, pid


def test_the_setting_rows_are_exactly_the_core_and_collaboration_rows():
    rows = {pid for pid, row in catalogue()['policies'].items() if row['kind'] == 'setting'}
    core = {pid for pid in rows if pid.startswith(('GWS.GMAIL.', 'GWS.COMMONCONTROLS.'))}
    assert len(core) == 38
    assert rows == core | set(IDS)
    assert len(rows) == 74


def test_explicit_only_rows_are_exactly_cc_16_1_cc_16_2_and_sites():
    explicit = {pid for pid, row in catalogue()['policies'].items()
                if row['kind'] == 'setting' and row['params']['scope'] == 'explicit_only'}
    assert explicit == EXPLICIT_ONLY


def test_the_gated_collaboration_rows_are_exactly_these_services():
    gates = {pid: row['params']['service'] for pid, row in catalogue()['policies'].items()
             if pid in IDS and row['params']['service'] is not None}
    assert gates == {
        **{f'GWS.DRIVEDOCS.{n}v1': 'drive_and_docs' for n in ('1.1', '1.6', '1.8', '1.9', '2.1', '2.2', '4.1')},
        **{f'GWS.CALENDAR.{n}v1': 'calendar' for n in ('1.1', '1.2', '2.1', '3.1', '4.1')},
        **{f'GWS.CHAT.{n}v1': 'chat' for n in ('1.1', '1.2', '2.1', '3.1')},
        **{f'GWS.MEET.{n}v1': 'meet' for n in ('1.1', '2.1', '3.1', '4.1', '5.1', '5.2')},
        **{f'GWS.GROUPS.{n}v1': 'groups_for_business' for n in ('1.1', '1.2', '1.3', '2.1', '3.1')},
        **{f'GWS.CLASSROOM.{n}v1': 'classroom' for n in ('1.1', '1.2', '2.1', '3.1', '4.1', '5.1')},
    }


# --- behaviour that pins the parameters from the outside ---------------------------------------------------------------

NOT_IN = [(pid, value) for pid, row in IDS.items() if row[2] == 'not_in' for value in row[3]]


@pytest.mark.parametrize(('pid', 'value'), NOT_IN)
def test_every_compliant_value_of_a_not_in_row_answers_met(pid, value):
    assert _answer(pid, _with(pid, value)) == ('met', 'no_unit_violates')


GATED = [pid for pid, row in IDS.items() if row[4] is not None]


@pytest.mark.parametrize('pid', GATED)
def test_a_service_that_is_off_answers_not_applicable_even_for_a_violating_value(pid):
    assert _answer(pid, _with(pid, _violating(pid), gate='DISABLED')) == ('not_applicable', 'service_off_everywhere')
    assert _answer(pid, _with(pid, _violating(pid))) == ('not_met', 'unit_violates')


@pytest.mark.parametrize('pid', [pid for pid, row in IDS.items() if row[4] is None])
def test_an_ungated_row_answers_without_any_service_status(pid):
    assert _answer(pid, _with(pid, _violating(pid))) == ('not_met', 'unit_violates')


NOT_MET_DEFAULT = ['DRIVEDOCS.1.1', 'DRIVEDOCS.1.6', 'DRIVEDOCS.1.8', 'DRIVEDOCS.4.1', 'CALENDAR.1.2', 'CHAT.1.1', 'CHAT.1.2',
                   'GROUPS.1.3', 'GROUPS.2.1', 'GROUPS.3.1', 'ASSUREDCONTROLS.1.1', 'ASSUREDCONTROLS.1.2']
MET_DEFAULT = ['CALENDAR.1.1', 'CALENDAR.2.1', 'CALENDAR.3.1', 'GROUPS.1.1', 'GROUPS.1.2']


@pytest.mark.parametrize(('key', 'expected'), [(k, ('not_met', 'unit_violates')) for k in NOT_MET_DEFAULT]
                         + [(k, ('met', 'no_unit_violates')) for k in MET_DEFAULT])
def test_a_complete_read_without_the_setting_applies_the_pinned_default(key, expected):
    pid = f'GWS.{key}v1'
    sections = _sections([_on(pid)] if IDS[pid][4] else [])
    assert _answer(pid, sections) == expected


def test_the_defaulted_and_undefaulted_rows_together_cover_every_row_but_sites():
    undefaulted = {'DRIVEDOCS.1.9', 'DRIVEDOCS.2.1', 'DRIVEDOCS.2.2', 'CALENDAR.4.1', 'CHAT.2.1', 'CHAT.3.1', 'MEET.1.1',
                   'MEET.2.1', 'MEET.3.1', 'MEET.4.1', 'MEET.5.1', 'MEET.5.2', 'CLASSROOM.1.1', 'CLASSROOM.1.2',
                   'CLASSROOM.2.1', 'CLASSROOM.3.1', 'CLASSROOM.4.1', 'CLASSROOM.5.1'}
    assert set(NOT_MET_DEFAULT) | set(MET_DEFAULT) | undefaulted | {'SITES.1.1'} == set(ROWS)
    assert not (set(NOT_MET_DEFAULT) | set(MET_DEFAULT)) & (undefaulted | {'SITES.1.1'})


SITES = 'GWS.SITES.1.1v1'


def _sites(*records):
    return _sections([_p(unit, 'sites_service_status', {'serviceState': state}) for unit, state in records])


def test_sites_reads_explicit_sub_unit_states_without_a_root_record():
    assert _answer(SITES, _sites(('ou:a', 'DISABLED'))) == ('met', 'no_unit_violates')
    assert _answer(SITES, _sites(('ou:a', 'ENABLED'))) == ('not_met', 'unit_violates')
    assert _answer(SITES, _sites()) == ('not_assessed', 'setting_absent')


def test_sites_folds_the_explicit_state_like_the_pinned_helper():
    assert _answer(SITES, _sites(('ou:root', 'DISABLED'), ('ou:a', 'enabled'))) == ('not_met', 'unit_violates')
    assert _answer(SITES, _sites(('ou:a', 'disabled'))) == ('met', 'no_unit_violates')
    assert _answer(SITES, _sites(('ou:root', 'DISABLED'), ('ou:a', 'maybe'))) == (
        'not_assessed', 'setting_value_unusable')


def _answer(pid, sections):
    record = gws.assess(pid, sections)
    return record['verdict'], record['cell']
