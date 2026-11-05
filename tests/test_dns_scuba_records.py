"""Raw DNS compatibility tests against pinned SG-P (2446ad72), entirely offline."""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re

import pytest

from auditex.scuba_projection import project_run
from azure_tenant_audit import dns_lookup as dns
from azure_tenant_audit.collectors import dns_posture as collector
from azure_tenant_audit.collection_gaps import REASON_FANOUT_LIMIT, TRUNCATION_ERROR_CLASS
from azure_tenant_audit.graph import GraphError
from azure_tenant_audit.model_evidence import NOT_COLLECTED

OPERATIONS = ('spf_records', 'dkim_records', 'dmarc_records')
VECTORS = json.loads((Path(__file__).parent / 'fixtures/collect-exchange/dns-vectors-v39.json').read_text())


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Network access forbidden in DNS record tests')
    monkeypatch.setattr('requests.sessions.Session.request', forbidden)
    monkeypatch.setattr('socket.socket.connect', forbidden)
    monkeypatch.setattr('socket.getaddrinfo', forbidden)


class Resolver:
    def __init__(self, answers=None):
        self.answers = answers or {}
        self.calls = []

    def query(self, name, record_type):
        self.calls.append((name, record_type))
        value = self.answers.get(name, [])
        if isinstance(value, Exception):
            raise value
        return list(value)


class DetailedResolver(Resolver):
    def query_detailed(self, name, record_type):
        self.calls.append((name, record_type))
        return self.answers.get(name, dns.DnsAnswer([], 'empty'))


class Graph:
    def __init__(self, domains):
        self.domains = domains

    def get_all(self, endpoint, params):
        assert endpoint == '/domains'
        if isinstance(self.domains, Exception):
            raise self.domains
        return self.domains


def run(resolver, domains=('example.invalid',), **context):
    entries = [{'id': d, 'isVerified': True} for d in domains]
    return collector.DnsPostureCollector().run({
        'client': Graph(entries), 'dns_resolver': resolver, 'public_lookups': False, **context,
    })


def write(root, path, payload):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload) + '\n')


def bundle(root, payload, coverage=()):
    write(root, 'raw/dns_posture.json', payload)
    write(root, 'coverage.json', {'records': coverage})
    write(root, 'run-manifest.json', {
        'run_id': 't', 'platform': 'm365',
        'tenant_id': '11111111-1111-4111-8111-111111111111',
        'selected_collectors': ['dns_posture'],
    })
    projection = project_run(root, redact=False)
    return projection, projection.report


@pytest.mark.parametrize('answers,compliant,message', [
    (['v=spf1 -all'], True, 'SPF record found.'),
    (['v=spf1 ~all'], True, 'SPF record found.'),
    (['v=spf1 redirect=example.invalid'], True, 'SPF record found.'),
    (['v=spf1 +all'], False, 'SPF record found, but it does not fail unapproved senders or redirect to one that does.'),
    (['v=spf1 ?all'], False, 'SPF record found, but it does not fail unapproved senders or redirect to one that does.'),
    (['v=spf1 -ALL'], False, 'SPF record found, but it does not fail unapproved senders or redirect to one that does.'),
    (['V=SPF1 -all'], False, 'Domain name exists but no SPF records returned.'),
    (['v=spf1'], False, 'Domain name exists but no SPF records returned.'),
    (['unrelated'], False, 'Domain name exists but no SPF records returned.'),
    (['unrelated', 'v=spf1 +all', 'v=spf1 -all'], True, 'SPF record found.'),
    ([], False, 'Domain name exists but no answers returned.'),
])
def test_spf(answers, compliant, message):
    # SG-P:520-560: exact messages, prefix and substring case sensitivity.
    result = dns.scuba_spf_record('example.invalid', Resolver({'example.invalid': answers}))
    assert result == {'domain': 'example.invalid', 'compliant': compliant, 'message': message,
                      'rdata': answers, 'log': [{
                          'query_name': 'example.invalid', 'query_method': 'DoH',
                          'query_result': f'Query returned {len(answers)} txt records', 'query_answers': answers,
                      }]}


def test_spf_nxdomain():
    # SG-P:547-560: NXDOMAIN differs from NOERROR-empty; resolver failures raise.
    resolver = DetailedResolver({'example.invalid': dns.DnsAnswer([], 'nxdomain')})
    result = dns.scuba_spf_record('example.invalid', resolver)
    assert result['message'] == 'Domain does not exist.'
    assert result['compliant'] is False
    assert result['rdata'] == []
    assert result['log'] == [{'query_name': 'example.invalid', 'query_method': 'DoH',
                              'query_result': 'Query returned NXDomain', 'query_answers': []}]


@pytest.mark.parametrize('hit', [0, 1, 2, 3, None])
def test_dkim_selectors(hit):
    # SG-P:601-629: dashed selectors, first answer wins, last empty response retained.
    names = [f'{s}._domainkey.a.b.com' for s in
             ('selector1', 'selector2', 'selector1-a-b-com', 'selector2-a-b-com')]
    answers = ['selector1.target.invalid']  # SG-P DoH keeps CNAME data too (433-450).
    resolver = Resolver({names[hit]: answers} if hit is not None else {})
    result = dns.scuba_dkim_record('a.b.com', resolver)
    expected = names[:hit + 1] if hit is not None else names
    assert resolver.calls == [(name, 'TXT') for name in expected]
    assert result['rdata'] == (answers if hit is not None else [])
    assert result['log'] == [{'query_name': n, 'query_method': 'DoH',
                              'query_result': f'Query returned {int(hit is not None and n == names[hit])} txt records',
                              'query_answers': answers if hit is not None and n == names[hit] else []}
                             for n in expected]


@pytest.mark.parametrize('domain,expected', [('A.MAIL.ONMICROSOFT.COM', True),
                                            ('a.onmicrosoft.com', False), ('notmail.onmicrosoft.com', False)])
def test_coexistence(domain, expected):
    # SG-P:594-599,661-665: skip coexistence domains; Graph lacks this EXO property.
    assert dns.is_coexistence_domain(domain) is expected
    if expected:
        resolver = Resolver()
        assert dns.scuba_dkim_record(domain, resolver) is None
        assert dns.scuba_dmarc_record(domain, resolver) is None
        assert resolver.calls == []


@pytest.mark.parametrize('answers,expected', [
    (['v=DMARC1; p=reject'], ['v=DMARC1; p=reject']),
    (['unrelated', 'v=dmarc1; p=none'], ['v=dmarc1; p=none']),
    (['v=DMARC1; p=none', 'v=DMARC1; p=reject'], []),
    (['unrelated'], []), ([], []),
])
def test_dmarc_author(answers, expected):
    # SG-P:668-696: exactly one case-insensitive version prefix wins; otherwise walk.
    resolver = Resolver({'_dmarc.example.invalid': answers})
    result = dns.scuba_dmarc_record('example.invalid', resolver)
    assert result['rdata'] == expected
    names = ['_dmarc.example.invalid'] + ([] if expected else ['_dmarc.invalid'])
    assert resolver.calls == [(n, 'TXT') for n in names]
    assert [entry['query_name'] for entry in result['log']] == names


@pytest.mark.parametrize('parent,top,expected,names', [
    ('v=DMARC1; p=reject', None, 'v=DMARC1; p=reject', ['mail.example.invalid', 'example.invalid', 'invalid']),
    ('v=DMARC1; PSD=N; p=reject', 'v=DMARC1; p=none', 'v=DMARC1; PSD=N; p=reject', ['mail.example.invalid', 'example.invalid']),
    ('v=DMARC1; p=reject', 'v=DMARC1; PSD=Y', 'v=DMARC1; p=reject', ['mail.example.invalid', 'example.invalid', 'invalid']),
    (None, 'v=DMARC1; psd=y', 'v=DMARC1; psd=y', ['mail.example.invalid', 'example.invalid', 'invalid']),
    ('v=DMARC1; psd=yellow', 'v=DMARC1; p=none', 'v=DMARC1; p=none', ['mail.example.invalid', 'example.invalid', 'invalid']),
    ('v=DMARC1; psd=no', 'v=DMARC1; p=none', 'v=DMARC1; p=none', ['mail.example.invalid', 'example.invalid', 'invalid']),
])
def test_dmarc_walk(parent, top, expected, names):
    # SG-P:707-764: continue up the tree, word-boundary PSD stops, organisational preference.
    resolver = Resolver({f'_dmarc.{n}': [v] for n, v in
                         [('example.invalid', parent), ('invalid', top)] if v is not None})
    result = dns.scuba_dmarc_record('mail.example.invalid', resolver)
    assert result['rdata'] == [expected]
    assert resolver.calls == [(f'_dmarc.{n}', 'TXT') for n in names]
    assert [r['query_name'] for r in result['log']] == [f'_dmarc.{n}' for n in names]


def test_dmarc_psd_without_adjacent_organisational_policy():
    # SG-P:739-753: a more distant policy must not displace the PSD policy.
    resolver = Resolver({'_dmarc.b.example.invalid': ['v=DMARC1; p=reject'],
                         '_dmarc.invalid': ['v=DMARC1; psd=y']})
    assert dns.scuba_dmarc_record('a.b.example.invalid', resolver)['rdata'] == ['v=DMARC1; psd=y']
    assert resolver.calls == [(f'_dmarc.{n}', 'TXT') for n in
                              ['a.b.example.invalid', 'b.example.invalid', 'example.invalid', 'invalid']]


def test_dmarc_walk_bound():
    # SG-P:707-723: author plus seven queries, trim directly to seven labels.
    resolver = Resolver()
    row = dns.scuba_dmarc_record('a.b.c.d.e.f.g.h.invalid', resolver)
    expected = ['a.b.c.d.e.f.g.h.invalid', 'c.d.e.f.g.h.invalid', 'd.e.f.g.h.invalid',
                'e.f.g.h.invalid', 'f.g.h.invalid', 'g.h.invalid', 'h.invalid', 'invalid']
    assert resolver.calls == [(f'_dmarc.{n}', 'TXT') for n in expected]
    assert row['rdata'] == []
    assert len(row['log']) == 8


@pytest.mark.parametrize('answers', [[], ['v=spf1 -all']])
def test_ask_legacy_resolver(answers):
    result = dns._ask(Resolver({'example.invalid': answers}), 'example.invalid')
    assert result == dns.DnsAnswer(answers, 'answers' if answers else 'empty')


class Session:
    def __init__(self, payload, stage=None):
        self.payload = payload
        self.stage = stage

    def get(self, *args, **kwargs):
        if self.stage == 'transport':
            raise RuntimeError('offline transport failure')
        return self

    def raise_for_status(self):
        if self.stage == 'http':
            raise RuntimeError('HTTP 503')

    def json(self):
        if self.stage == 'json':
            raise ValueError('invalid json')
        return self.payload


@pytest.mark.parametrize('payload,outcome,records', [
    ({'Status': 0, 'Answer': [{'data': '"v=spf1 " "-all"'}, {'data': 'target.invalid'}, {}, 5]}, 'answers', ['v=spf1 -all', 'target.invalid']),
    ({'Status': 0}, 'empty', []), ({'Status': 3}, 'nxdomain', []),
    ({'Status': 0, 'Answer': [{'data': 5}]}, 'empty', []),
    ({'Status': 3, 'Answer': [{'data': '"x"'}]}, 'answers', ['x']),
    ({'Status': 2, 'Answer': [{'data': '"x"'}]}, 'answers', ['x']),
])
def test_doh_query_detailed_agrees(payload, outcome, records):
    client = dns.DohClient(session=Session(payload))
    assert client.query('example.invalid', 'TXT') == records
    assert client.query_detailed('example.invalid', 'TXT') == dns.DnsAnswer(records, outcome)


@pytest.mark.parametrize('payload,stage', [
    (None, 'transport'), (None, 'http'), (None, 'json'), ([], None), ({}, None),
    ({'Status': True}, None), ({'Status': 'bogus'}, None),
    ({'Status': 0, 'TC': True}, None), ({'Status': 3, 'TC': True}, None),
    *[({'Status': n}, None) for n in (1, 2, 4, 5, 99)],
])
def test_doh_query_errors_agree(payload, stage):
    client = dns.DohClient(session=Session(payload, stage))
    with pytest.raises(dns.DohError) as legacy:
        client.query('example.invalid', 'TXT')
    with pytest.raises(dns.DohError) as detailed:
        client.query_detailed('example.invalid', 'TXT')
    assert str(legacy.value) == str(detailed.value)


def test_doh_carries_answer_types_without_changing_query_strings():
    client = dns.DohClient(session=Session({'Status': 0, 'Answer': [
        {'type': 5, 'data': 'target.invalid'}, {'type': 16, 'data': 5},
        {'type': 16, 'data': '"v=DKIM1; p=key"'}, {}, {'data': 'untyped'},
    ]}))
    records = ['target.invalid', 'v=DKIM1; p=key', 'untyped']
    assert client.query('example.invalid', 'TXT') == records
    assert client.query_detailed('example.invalid', 'TXT') == dns.DnsAnswer(
        records, 'answers', (5, 16, None))


@pytest.mark.parametrize('with_txt', [False, True])
def test_dkim_ignores_typed_cname_and_keeps_txt(with_txt):
    first = 'selector1._domainkey.example.invalid'
    second = 'selector2._domainkey.example.invalid'

    class DkimSession(Session):
        def get(self, *args, **kwargs):
            name = kwargs['params']['name']
            entries = [{'type': 5, 'data': 'target.invalid'}] if name == first else []
            if name == second or with_txt:
                entries.append({'type': 16, 'data': '"v=DKIM1; p=key"'})
            self.payload = {'Status': 0, 'Answer': entries}
            return self

    resolver = dns.CachingResolver(dns.DohClient(session=DkimSession(None)))
    result = dns.scuba_dkim_record('example.invalid', resolver)
    assert result['rdata'] == ['v=DKIM1; p=key']
    assert [entry['query_name'] for entry in result['log']] == ([first] if with_txt else [first, second])
    assert result['log'][0]['query_answers'] == (['v=DKIM1; p=key'] if with_txt else [])
    # Posture and the query API still see the original CNAME data in the shared cache.
    assert resolver.query(first, 'TXT') == ['target.invalid'] + (['v=DKIM1; p=key'] if with_txt else [])


def test_cache_shares_both_interfaces_and_does_not_cache_errors():
    resolver = DetailedResolver({'x': dns.DnsAnswer([], 'nxdomain')})
    cached = dns.CachingResolver(resolver)
    assert cached.query('x', 'TXT') == []
    assert cached.query_detailed('x', 'TXT').outcome == 'nxdomain'
    assert cached.query_detailed('x', 'CNAME').outcome == 'nxdomain'
    assert resolver.calls == [('x', 'TXT'), ('x', 'CNAME')]
    legacy = Resolver({'x': dns.DohError('failed')})
    cached = dns.CachingResolver(legacy)
    for _ in range(2):
        with pytest.raises(dns.DohError):
            cached.query('x', 'TXT')
    legacy.answers['x'] = ['recovered']
    assert cached.query_detailed('x', 'TXT').records == ['recovered']
    assert len(legacy.calls) == 3


def test_cache_does_not_share_mutable_record_lists():
    source = ['original']
    resolver = DetailedResolver({'x': dns.DnsAnswer(source, 'answers', (16,))})
    cached = dns.CachingResolver(resolver)
    cached.query('x', 'TXT').append('query caller mutation')
    detailed = cached.query_detailed('x', 'TXT')
    assert detailed == dns.DnsAnswer(['original'], 'answers', (16,))
    detailed.records.clear()
    source.append('upstream mutation')
    assert cached.query('x', 'TXT') == ['original']
    assert resolver.calls == [('x', 'TXT')]


def happy_resolver():
    return Resolver({'example.invalid': ['v=spf1 -all'], '_dmarc.example.invalid': ['v=DMARC1; p=reject'],
                     'selector1._domainkey.example.invalid': ['v=DKIM1; p=key']})


def test_collector_raw_records_and_projection(tmp_path):
    resolver = happy_resolver()
    result = run(resolver)
    assert result.status == 'ok'
    assert list(result.payload) == ['domains', 'domainPosture', *OPERATIONS]
    assert [c['name'] for c in result.coverage] == ['domains', 'posture:example.invalid', *OPERATIONS]
    for operation, kind in zip(OPERATIONS, ('spf', 'dkim', 'dmarc')):
        envelope = result.payload[operation]
        assert envelope['status'] == 'ok'
        assert len(envelope['value']) == 1
        row = next(c for c in result.coverage if c['name'] == operation)
        assert row == {'collector': 'dns_posture', 'type': 'dns', 'name': operation,
                       'endpoint': f'doh://records/{kind}', 'status': 'ok', 'item_count': 1,
                       'duration_ms': row['duration_ms'], 'error_class': None, 'error': None}
    counts = Counter(resolver.calls)
    assert counts[('example.invalid', 'TXT')] == 1
    assert counts[('_dmarc.example.invalid', 'TXT')] == 1
    assert counts[('selector1._domainkey.example.invalid', 'TXT')] == 1
    projection, report = bundle(tmp_path, result.payload, result.coverage)
    for operation in OPERATIONS:
        expected = [{k: v for k, v in r.items() if k != 'log'} for r in result.payload[operation]['value']]
        assert projection.rule_sections[operation] == expected
        assert projection[operation] == expected
        assert 'log' in report['sections'][operation]['ignored_fields']


def test_collector_noerror_empty_spf_reaches_the_rule_view(tmp_path):
    resolver = DetailedResolver({'example.invalid': dns.DnsAnswer([], 'empty')})
    result = run(resolver)
    assert result.status == 'ok'
    row = result.payload['spf_records']['value'][0]
    assert row['domain'] == 'example.invalid'
    assert row['rdata'] == []
    assert row['compliant'] is False
    assert row['message'] == 'Domain name exists but no answers returned.'
    projection, report = bundle(tmp_path, result.payload, result.coverage)
    # Rules read the in-memory rule view, captured after the adapter and before the shape gate:
    # the empty-rdata row reaches MS.EXO.2.2 and 3.1 (product, 5 Nov 2026).
    assert projection.rule_sections['spf_records'] == [{k: v for k, v in row.items() if k != 'log'}]
    # Only the model view is withheld by the digest gate; this part may flip or become irrelevant
    # when the model fallback is removed.
    assert projection['spf_records'] == NOT_COLLECTED
    section = report['sections']['spf_records']
    assert section['status'] == 'not_collected'
    assert section['reason'] == 'incomplete_shape'
    assert section['detail'] == {'field': '$', 'kind': 'unseen_shape'}


@pytest.mark.parametrize('operation,bad_name,answer', [
    ('spf_records', 'a.invalid', 'v=spf1 -all'),
    ('dkim_records', 'selector1-a-invalid._domainkey.a.invalid', 'v=DKIM1; p=key'),
    ('dmarc_records', '_dmarc.invalid', 'v=DMARC1; p=reject; psd=n'),
])
@pytest.mark.parametrize('failures', [1, 2])
def test_record_retry_is_bounded_and_operations_are_isolated(operation, bad_name, answer, failures):
    class Flaky(Resolver):
        def query(self, name, record_type):
            records = super().query(name, record_type)
            if name == bad_name and self.calls.count((name, record_type)) <= failures:
                raise dns.DohError('transient resolver failure')
            return records

    resolver = Flaky({bad_name: [answer]})
    coverage = []
    # Isolate the record path so posture cannot supply an implicit earlier retry.
    payload = collector.DnsPostureCollector()._scuba_records(
        [{'id': 'a.invalid'}], dns.CachingResolver(resolver), coverage, 'ok', None, None)
    assert resolver.calls.count((bad_name, 'TXT')) == 2
    envelope = payload[operation]
    if failures == 1:
        assert envelope['status'] == 'ok'
        assert envelope['value'][0]['rdata'] == [answer]
    else:
        assert envelope == {'value': [], 'status': 'failed', 'error_class': 'dns_resolver_error',
                            'error': 'transient resolver failure'}
    for other in set(OPERATIONS) - {operation}:
        assert payload[other]['status'] == 'ok'
        assert len(payload[other]['value']) == 1
    assert next(c for c in coverage if c['name'] == operation)['status'] == envelope['status']


@pytest.mark.parametrize('failed_operation,bad_name', [
    ('spf_records', 'b.invalid'), ('dkim_records', 'selector1-b-invalid._domainkey.b.invalid'),
    ('dmarc_records', '_dmarc.b.invalid'),
])
def test_collector_failure_isolated(tmp_path, failed_operation, bad_name):
    resolver = Resolver({bad_name: dns.DohError('offline resolver failure')})
    result = run(resolver, domains=('a.invalid', 'b.invalid', 'c.invalid'))
    assert result.status == 'partial'
    envelope = result.payload[failed_operation]
    assert envelope['status'] == 'failed'
    assert envelope['error_class'] == 'dns_resolver_error'
    assert envelope['error'] == 'offline resolver failure'
    assert [r['domain'] for r in envelope['value']] == ['a.invalid']
    assert next(c for c in result.coverage if c['name'] == failed_operation)['status'] == 'failed'
    for operation in set(OPERATIONS) - {failed_operation}:
        assert result.payload[operation]['status'] == 'ok'
        assert len(result.payload[operation]['value']) == 3
    projection, report = bundle(tmp_path, result.payload, result.coverage)
    assert projection.rule_sections[failed_operation] == NOT_COLLECTED
    assert report['sections'][failed_operation]['reason'] == 'collector_error'


def test_collector_graph_failure():
    result = run(Resolver(), client=Graph(GraphError('forbidden', status=403, request='/domains')))
    assert result.status == 'partial'
    for operation in OPERATIONS:
        assert result.payload[operation] == {'value': [], 'status': 'failed',
                                            'error_class': 'insufficient_permissions', 'error': 'forbidden'}
        assert next(c for c in result.coverage if c['name'] == operation)['status'] == 'failed'


def test_collector_coexistence_unverified_and_blank():
    result = run(Resolver(), client=Graph([{'id': 'tenant.mail.onmicrosoft.com', 'isVerified': True},
                                         {'id': 'pending.invalid', 'isVerified': False},
                                         {'id': '', 'isVerified': True}]))
    assert len(result.payload['spf_records']['value']) == 1
    assert result.payload['dkim_records']['value'] == []
    assert result.payload['dmarc_records']['value'] == []


def test_collector_fanout_limit(monkeypatch, tmp_path):
    monkeypatch.setattr(collector, 'MAX_RECORD_DOMAINS', 1)
    result = run(Resolver(), domains=('a.invalid', 'b.invalid'))
    assert result.status == 'partial'
    for operation in OPERATIONS:
        envelope = result.payload[operation]
        assert envelope['collection_truncated'] is True
        assert envelope['truncation_reason'] == REASON_FANOUT_LIMIT
        assert envelope['result_limit'] == envelope['rows_collected'] == 1
        coverage = next(c for c in result.coverage if c['name'] == operation)
        assert coverage['status'] == 'partial'
        assert coverage['error_class'] == TRUNCATION_ERROR_CLASS
    projection, _ = bundle(tmp_path, result.payload, result.coverage)
    assert all(projection.rule_sections[op] == NOT_COLLECTED for op in OPERATIONS)


def test_old_payload_explains_missing_raw_records(tmp_path):
    _, report = bundle(tmp_path, {'domains': {'value': []}, 'domainPosture': {'value': []}})
    assert all(report['sections'][op]['reason'] == 'dns_records_not_saved' for op in OPERATIONS)


@pytest.mark.parametrize('vector', VECTORS, ids=lambda v: v['vector_id'])
def test_fixture_projection_round_trip(tmp_path, vector):
    payload = {name: {'status': 'ok', 'value': rows} for name, rows in vector['sections'].items()}
    projection, report = bundle(tmp_path, payload)
    for name, rows in vector['sections'].items():
        projected = projection.rule_sections[name]
        if projected == NOT_COLLECTED:
            assert report['sections'][name]['status'] != 'projected'
        else:
            assert projected == [{k: v for k, v in row.items() if k in
                                  {'domain', 'doamin', 'rdata', 'compliant', 'message'}} for row in rows]


@pytest.mark.parametrize('vector', [v for v in VECTORS if 'dmarc_records' in v['sections']], ids=lambda v: v['vector_id'])
def test_fixture_dmarc_collector_round_trip(vector):
    rows = vector['sections']['dmarc_records']
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('domain'), str):
            continue
        records = row.get('rdata')
        if not isinstance(records, list) or not all(isinstance(r, str) for r in records):
            continue
        valid = [r for r in records if re.match('^v=DMARC1', r, re.I)]
        if len(valid) > 1:
            continue
        assert records == valid  # Selected witnesses contain whole DMARC strings or empty rdata.
        domain = row['domain']
        result = run(Resolver({f'_dmarc.{domain}': valid}), domains=(domain,))
        assert result.payload['dmarc_records']['value'][0]['rdata'] == records


def test_dmarc_ambiguous_parent_keeps_previous_policy():
    # SG-P:724-765: ambiguous parent is ignored, retaining the last usable policy.
    policy = 'v=DMARC1; p=reject'
    resolver = Resolver({'_dmarc.b.example.invalid': [policy],
                         '_dmarc.example.invalid': ['v=DMARC1; p=none', 'v=DMARC1; p=reject']})
    assert dns.scuba_dmarc_record('a.b.example.invalid', resolver)['rdata'] == [policy]
    assert resolver.calls == [(f'_dmarc.{n}', 'TXT') for n in
                              ['a.b.example.invalid', 'b.example.invalid', 'example.invalid', 'invalid']]


@pytest.mark.parametrize('operation,bad_name,unqueried', [
    ('spf_records', 'b.invalid', 'c.invalid'),
    ('dkim_records', 'selector1._domainkey.b.invalid', 'selector1._domainkey.c.invalid'),
    ('dmarc_records', '_dmarc.b.invalid', '_dmarc.c.invalid'),
])
def test_raw_operation_stops_after_first_error(operation, bad_name, unqueried):
    resolver = Resolver({bad_name: dns.DohError('failed')})
    coverage = []
    payload = collector.DnsPostureCollector()._scuba_records(
        [{'id': d} for d in ('a.invalid', 'b.invalid', 'c.invalid')], resolver, coverage, 'ok', None, None)
    assert payload[operation]['status'] == 'failed'
    assert (unqueried, 'TXT') not in resolver.calls
    assert all(payload[other]['status'] == 'ok' for other in OPERATIONS if other != operation)


def test_existing_posture_and_https_order_preserved():
    class Fetcher:
        def __init__(self):
            self.calls = []

        def get_text(self, url):
            self.calls.append(url)
            if url.startswith('https://mta-sts.'):
                return 200, 'version: STSv1\nmode: enforce\nmx: *.example.invalid\nmax_age: 86400\n', None
            return 200, '{}', None

    resolver = happy_resolver()
    resolver.answers['_mta-sts.example.invalid'] = ['v=STSv1; id=1']
    fetcher = Fetcher()
    result = run(resolver, public_lookups=True, https_fetcher=fetcher)
    assert list(result.payload) == ['domains', 'domainPosture', 'publicFootprint', *OPERATIONS]
    assert [r['name'] for r in result.coverage] == [
        'domains', 'posture:example.invalid', 'public_footprint:example.invalid', *OPERATIONS]
    assert fetcher.calls == ['https://mta-sts.example.invalid/.well-known/mta-sts.txt',
                             'https://login.microsoftonline.com/example.invalid/v2.0/.well-known/openid-configuration']
    assert result.payload['domainPosture']['value'][0]['mta_sts']['policy']['mode'] == 'enforce'
    assert result.status == 'ok'


def test_record_domain_limit_is_200_and_fixture_is_bounded():
    assert collector.MAX_RECORD_DOMAINS == 200
    assert all(n <= 8 for n in Counter(v['policy'] for v in VECTORS).values())
    assert len({v['policy'] for v in VECTORS}) == 6
    for vector in VECTORS:
        assert set(vector) == {'policy', 'vector_id', 'family', 'sections'}
        assert set(vector['sections']) <= set(OPERATIONS)
        assert 'collection_status' not in json.dumps(vector)


def test_worktree_source_is_loaded():
    assert Path(dns.__file__).resolve() == Path(__file__).resolve().parents[1] / 'src/azure_tenant_audit/dns_lookup.py'


def test_dmarc_single_label_stops_after_author():
    # SG-P:707: there is no parent when only one non-empty label remains.
    resolver = Resolver()
    assert dns.scuba_dmarc_record('invalid', resolver)['rdata'] == []
    assert resolver.calls == [('_dmarc.invalid', 'TXT')]


def test_collector_all_resolver_errors_withhold_all_operations(tmp_path):
    class Broken(Resolver):
        def query(self, name, record_type):
            raise dns.DohError('offline failure')
    result = run(Broken())
    projection, report = bundle(tmp_path, result.payload, result.coverage)
    for operation in OPERATIONS:
        assert result.payload[operation]['value'] == []
        assert result.payload[operation]['status'] == 'failed'
        assert projection.rule_sections[operation] == NOT_COLLECTED
        assert report['sections'][operation]['reason'] == 'collector_error'


def test_peak_queries_with_existing_posture():
    domain = 'a.b.c.d.e.f.g.h.invalid'
    resolver = Resolver()
    result = run(resolver, domains=(domain,))
    assert result.status == 'ok'
    assert len(result.payload['spf_records']['value'][0]['log']) == 1
    assert len(result.payload['dkim_records']['value'][0]['log']) == 4
    assert len(result.payload['dmarc_records']['value'][0]['log']) == 8
    # 13 record questions + 6 preserved fallback selectors + 3 other posture TXT names.
    assert len(resolver.calls) == 22
    assert max(Counter(resolver.calls).values()) == 1
