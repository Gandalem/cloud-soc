"""Generic sites use real contracts/engines; ES transport remains isolated here."""
from copy import deepcopy
from datetime import timedelta
import json
import sqlite3
from unittest.mock import Mock, patch

import pytest

from cloud_soc.detection.engine import detect_rule, event_fingerprint
from cloud_soc.detection.profiles import catalog, select, CORE_RULE_IDS
from cloud_soc.pipeline.alerts import build_security_alert, make_alert_id
from cloud_soc.portal.log_contract import parse_filters, project_hit
from cloud_soc.portal.log_query import LogReader, LogQueryError
from cloud_soc.portal.operations import Operations
from cloud_soc.portal.runtime_rules import inventory
from cloud_soc.portal.site_context import context
from cloud_soc.processing.contract import normalize, NORMALIZED
from cloud_soc.processing.worker import run_once
from cloud_soc.web.scope import NORMALIZER_VERSION, LEGACY_VERSION
from ruleset_fixtures import BASE, positive, assign
from test_site_agents import web_hit

RULE_ID = 'WEB-SITE-404-001'


def rule():
    return select(rule_ids=[RULE_ID], retain_auth=False)[0]


def test_new_version_preserves_scope_http_and_immutable_legacy():
    hit = web_hit()
    legacy = normalize(hit, BASE.isoformat())
    key, record, event = normalize(hit, BASE.isoformat(), web_version=NORMALIZER_VERSION)
    assert record['version'] == event['cloud_soc']['normalizer_version'] == NORMALIZER_VERSION
    assert event['cloud_soc']['detail']['adapter'] == 'web_access_site_v2'
    assert event['service'] == hit['_source']['service'] and event['http'] == hit['_source']['http']
    assert key != legacy[0] and legacy[1]['version'] == LEGACY_VERSION and 'service' not in legacy[2]
    assert normalize(hit, BASE.isoformat()) == legacy
    assert normalize(hit, '2026-10-20T00:00:00Z', web_version=NORMALIZER_VERSION)[0] == key
    assert 'message' not in event and 'url' not in event and 'body' not in event['http']['request']


@pytest.mark.parametrize('host', [None, '', [], ' host ', 'h' * 129])
def test_site_normalization_requires_valid_collector_host(host):
    hit = web_hit()
    hit['_source']['host']['id'] = host
    _, record, event = normalize(hit, BASE.isoformat(), web_version=NORMALIZER_VERSION)
    assert event is None and record['status'] == 'invalid' and record['reason'] == 'web_collector_host_invalid'


@pytest.mark.parametrize('path', ['organization.id', 'host.id', 'service.id', 'source.ip'])
def test_sites_hosts_tenants_and_peers_never_combine_or_share_cooldown(path):
    rows = positive(RULE_ID)
    other = deepcopy(rows)
    value = '192.0.2.2' if path == 'source.ip' else 'other-scope'
    for row in other:
        assign(row, path, value)
    assert not detect_rule(rows[:10] + other[10:], rule())
    runtime = {}
    first = detect_rule(rows, rule(), runtime=runtime)
    second = detect_rule(other, rule(), runtime=runtime)
    assert len(first) == len(second) == 1
    assert make_alert_id(first[0]) != make_alert_id(second[0])
    restored = json.loads(json.dumps(runtime))
    assert not detect_rule([rows[-1], other[-1]], rule(), runtime=restored)
    document = build_security_alert(first[0])
    assert document['service']['id'] == rows[0]['service']['id']
    assert document['cloud_soc']['provenance']['scope'] == first[0]['group']


def test_new_and_legacy_web_profiles_do_not_double_alert():
    rows = positive(RULE_ID)
    old = next(r for r in catalog(include_applications=False) if r['id'] == 'WEB-404-001')
    assert not detect_rule(rows, old)
    assert not detect_rule(positive('WEB-404-001'), rule())


def test_core_selection_inventory_and_acceptance_do_not_require_mall_files():
    from cloud_soc.detection.profiles import load_rules
    def without_apps(path, **options):
        if path.name == 'security_mall.yml':
            raise FileNotFoundError('optional app absent')
        return load_rules(path, **options)
    with patch('cloud_soc.detection.profiles.load_rules', side_effect=without_apps):
        assert [r['id'] for r in select(rule_ids=[RULE_ID])] == ['AUTH-001', RULE_ID]
        assert {r['id'] for r in catalog(include_applications=False)} == set(CORE_RULE_IDS)
        assert all(r['scope'] == 'general' for r in inventory({'detector': {'state': 'not_started'}}))
        with pytest.raises(FileNotFoundError):
            select(rule_ids=['WEB-AUTH-01'])


def test_site_filter_is_exact_with_tenant_guard_and_cursor_preserves_scope():
    filters = parse_filters([('site', 'site-A')], now=BASE)
    reader = LogReader(Mock(), secret='synthetic', principal='fixture', organizations=('team-A',))
    body = reader.body(filters, 'fixture-pit', None)
    clauses = body['query']['bool']['filter']
    assert {'term': {'soc_query_site': 'site-A'}} in clauses
    assert {'terms': {'organization.id': ['team-A']}} in clauses
    assert 'service.id' in body['runtime_mappings']['soc_query_site']['script']['source']
    from dataclasses import asdict
    state = {'v': 1, 'principal': 'fixture', 'pit': 'fixture-pit', 'filters': asdict(filters),
             'after': [1, 1], 'expires': int(reader.clock()) + 60}
    _, decoded = reader.decode(reader.encode(state))
    assert decoded.site == 'site-A'
    assert project_hit(web_hit())['site_id'] == 'dvwa'
    for value in ('bad.site', '*', ' site ', 'a' * 65):
        with pytest.raises(ValueError):
            parse_filters([('site', value)], now=BASE)


def transport():
    client = Mock()
    client.options.return_value = client
    client.bulk.side_effect = lambda **kw: {'items': [{'create': {'status': 201}} for _ in kw['operations'][::2]]}
    return client


def test_resident_normalizer_pins_site_floor_and_retains_old_state(tmp_path):
    hit = web_hit()
    start = '2026-10-14T00:00:00Z'
    now = BASE.replace(day=14) + timedelta(minutes=10)
    client = transport()
    state = tmp_path / 'site.sqlite'
    options = dict(now=now, scanner=lambda *_: [hit], web_site_v2_start=start)
    run_once(client, state, start, **options)
    docs = client.bulk.call_args.kwargs['operations'][1::2]
    assert docs[0]['cloud_soc']['normalizer_version'] == NORMALIZER_VERSION
    run_once(client, state, start, **options)
    with pytest.raises(ValueError, match='cannot change'):
        run_once(client, state, start, now=now, scanner=lambda *_: [])
    with sqlite3.connect(state) as db:
        assert db.execute("select start from adapter_config where name='web_access_site_v2'").fetchone()[0] == start
    legacy = tmp_path / 'old.sqlite'
    run_once(client, legacy, start, now=now, scanner=lambda *_: [])
    with pytest.raises(ValueError, match='new explicit state'):
        run_once(client, legacy, start, **options)


@pytest.fixture
def site_reader():
    rows = positive(RULE_ID)
    detection = detect_rule(rows, rule())[0]
    alert = build_security_alert(detection)
    # Context's actual ES hash/raw guard is separately exercised below.
    reader = Operations(transport(), organizations=('lab',))
    reader.get = Mock(return_value=alert)
    anchor = {'state': 'exact_reference', 'integrity': 'normalized_hash_verified', 'normalized_event': {
        'organization': 'lab', 'host_id': 'fixture-host', 'site_id': 'dvwa', 'source_ip': '192.0.2.1'}}
    reader.evidence = Mock(return_value=anchor)
    reader.client.indices.resolve_index.return_value = {'indices': [{'name': NORMALIZED}]}
    hits = [{'_index': NORMALIZED, '_id': row['_cloud_soc_meta']['document_id'], '_source': row} for row in rows]
    reader.client.search.return_value = {'hits': {'total': {'relation': 'eq', 'value': len(hits)}, 'hits': hits}}
    return reader, alert, hits


def test_context_requeries_latest_data_and_never_promotes_it_to_detection_evidence(site_reader):
    reader, _, hits = site_reader
    now = BASE + timedelta(minutes=1)
    result = json.loads(context(reader, [('id', 'alert')], now=now))
    assert result['count'] == 20 and result['detection_evidence'] is False
    assert result['request_correlation'] == 'not_available'
    assert 'message' not in json.dumps(result) and 'url' not in json.dumps(result)
    request = reader.client.search.call_args.kwargs
    assert {'term': {'service.id': 'dvwa'}} in request['query']['bool']['filter']
    extra = deepcopy(hits[-1]); extra['_id'] = 'new-context'; extra['_source']['http']['response']['status_code'] = 200
    hits.append(extra)
    reader.client.search.return_value['hits']['total']['value'] = 21
    updated = json.loads(context(reader, [('id', 'alert')], now=now))
    assert updated['count'] == 21 and len(updated['events']) == 21
    assert reader.client.search.call_count == 2


@pytest.mark.parametrize('failure', ['site', 'tenant', 'host', 'peer', 'future', 'partial', 'anchor', 'scope', 'count', 'alias'])
def test_context_rejects_cross_scope_partial_and_unverified_results(site_reader, failure):
    reader, alert, hits = site_reader
    if failure in ('site', 'tenant', 'host', 'peer'):
        path = {'site': 'service.id', 'tenant': 'organization.id', 'host': 'host.id', 'peer': 'source.ip'}[failure]
        assign(hits[0]['_source'], path, 'other')
    elif failure == 'future':
        hits[0]['_source']['@timestamp'] = (BASE + timedelta(days=1)).isoformat()
    elif failure == 'partial':
        reader.client.search.return_value['timed_out'] = True
    elif failure == 'anchor':
        reader.evidence.return_value['integrity'] = 'unverified_legacy'
    elif failure == 'scope':
        alert['cloud_soc']['provenance']['scope']['service.id'] = 'other'
    elif failure == 'count':
        reader.client.search.return_value['hits']['total']['relation'] = 'gte'
    elif failure == 'alias':
        reader.client.indices.resolve_index.return_value['aliases'] = [{'name': NORMALIZED}]
    with pytest.raises(LogQueryError) as error:
        context(reader, [('id', 'alert')], now=BASE + timedelta(minutes=1))
    assert error.value.status == 503


@pytest.mark.parametrize('peer', ['192.0.2.1', '2001:0DB8::1'])
def test_raw_site_tampering_fails_even_with_verified_normalized_hash(peer):
    hit = web_hit()
    hit['_source']['source']['ip'] = peer
    key, _, event = normalize(hit, BASE.isoformat(), web_version=NORMALIZER_VERSION)
    reference = {'normalized': {'index': NORMALIZED, 'id': key},
                 'raw': {'index': hit['_index'], 'id': hit['_id']}}
    hashed = deepcopy(event)
    hashed['_cloud_soc_meta'] = {'index': NORMALIZED, 'document_id': key}
    reference['event_hash'] = event_fingerprint(hashed)
    reader = Operations(transport(), organizations=('lab',))
    def get(index, *_):
        return event if index == NORMALIZED else hit['_source']
    reader.get = Mock(side_effect=get)
    assert reader.evidence(reference, organization='lab')['state'] == 'exact_reference'
    hit['_source']['service']['id'] = 'other-site'
    assert reader.evidence(reference, organization='lab')['state'] == 'provenance_mismatch'
    hit['_source']['service']['id'] = 'dvwa'
    hit['_source']['@timestamp'] = '2026-10-14T01:00:00Z'
    assert reader.evidence(reference, organization='lab')['state'] == 'provenance_mismatch'


def test_site_context_route_permits_own_tenant_and_hides_foreign_alerts(tmp_path):
    from test_integration_security import make_session_portal, login
    app, monitor, _, _ = make_session_portal(tmp_path)
    monitor.indices.resolve_index.side_effect = lambda **kw: {'indices': [{'name': kw['name']}]}
    monitor.get.return_value = {'_source': {'organization': {'id': 'synthetic'}}}
    http, _ = login(app, 'investigate')
    own = http.get('/api/alerts/site-context?id=own-alert')
    assert own.status_code == 200 and own.json['state'] == 'unsupported'
    monitor.get.return_value = {'_source': {'organization': {'id': 'foreign'}}}
    assert http.get('/api/alerts/site-context?id=foreign-alert').status_code == 404
    assert http.get('/api/alerts/site-context?id=own-alert&organization=foreign').status_code == 400
    assert app.test_client().get('/api/alerts/site-context?id=own-alert').status_code == 401
