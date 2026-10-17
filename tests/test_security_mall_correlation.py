"""7-A local-only engine/store and real normalizer/detector contracts."""
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
import json
import sqlite3

import pytest

from cloud_soc.correlation.security_mall import Scope
from cloud_soc.correlation.store import CorrelationStore
from cloud_soc.detection.engine import detect_events, event_evidence
from cloud_soc.pipeline.alerts import build_security_alert, make_alert_id
from cloud_soc.portal.log_access import LogPrincipal
from cloud_soc.portal.log_contract import field
from cloud_soc.processing.contract import normalize
from cloud_soc.parsers.security_mall_edge import envelope, parse_access, parse_native
from security_mall_fixtures import BASE, mall
from test_security_mall_detection import rules, sequence
from test_security_mall_edge import MANIFEST, RULE, native

RID = 'atI3YyuokZgOiD33Gh3LxwAAAAI'
NORM = 'soc-normalized-mall-correlation-test'
RAW = 'soc-host-raw-mall-correlation-test'
EDGE = 'soc-host-raw-mall-edge-correlation-test'
ALERT = 'soc-mall-alerts-lab-correlation-test'
SCOPE = Scope('mall-org', 'shop-lab', 'mall-host', 'security-mall', (NORM,), (RAW,), (EDGE,), (ALERT,))
VIEWER = LogPrincipal('analyst', 'investigator', ('mall-org',), ())


def stamp(seconds):
    return (BASE + timedelta(seconds=seconds)).isoformat().replace('+00:00', 'Z')


def app(number=1, seconds=1, rid=RID, action='order_view', **kwargs):
    event = mall(number, seconds=seconds, action=action, **kwargs)
    event['http'] = {'request': {'id': rid}} if rid else {}
    event['cloud_soc']['provenance']['raw'] = {'index': RAW, 'id': 'app-' + str(number)}
    event.pop('_cloud_soc_meta')
    return {'_index': NORM, '_id': 'norm-app-' + str(number), '_source': event}


def edge(stream, seconds=1, rid=RID, status=403, suffix=''):
    # Existing 6-C parsers and normalizer, with only synthetic native/TSV input.
    if stream == 'web':
        text = f'soc-mall-access-v1\t{stamp(seconds)}\t127.0.0.1\tGET\t/order/complete/:id\t{status}\t25\t{rid}\n'
        body = parse_access(text)
    else:
        body = parse_native(native(RULE, request_id=rid), MANIFEST)
        body['timestamp'] = stamp(seconds)
    source = envelope(body, SCOPE.organization, SCOPE.host)
    source['event']['ingested'] = stamp(seconds + 50)
    identifier, record, event = normalize({'_index': EDGE, '_id': stream + str(seconds) + suffix, '_source': source}, stamp(100))
    assert record['status'] == 'normalized'
    return {'_index': NORM, '_id': identifier, '_source': event}


def detected(hits):
    events = []
    for hit in hits:
        event = deepcopy(hit['_source'])
        event['_cloud_soc_meta'] = {'index': hit['_index'], 'document_id': hit['_id']}
        events.append(event)
    return [{'_index': ALERT, '_id': make_alert_id(d), '_source': build_security_alert(d)}
            for d in detect_events(events, rules())]


@pytest.fixture
def store(tmp_path):
    return CorrelationStore(tmp_path / 'evidence.sqlite', SCOPE)


def test_three_real_formats_and_evidence_contract(store):
    hits = [edge('web'), edge('waf'), app()]
    before = deepcopy(hits)
    store.ingest(hits, detected([hits[-1]]))
    result = store.snapshot(VIEWER)
    assert len(result['requests']) == 1
    bundle = result['requests'][0]
    assert bundle['state'] == 'complete' and not bundle['missing']
    assert bundle['present'] == {'web': True, 'waf': True, 'app': True}
    assert len(bundle['event_ids']) == 3 and bundle['request_id'] == RID
    assert all(o['raw'] == field(h['_source'], 'cloud_soc.provenance.raw')
               for e in bundle['events'] for o in e['observations'] for h in hits if h['_id'] == o['normalized']['id'])
    assert bundle['related_alerts'] == [result['alert_links'][0]['alert']]
    assert result['alert_links'][0]['state'] == 'complete'
    assert hits == before


@pytest.mark.parametrize('streams', [('web',), ('web', 'waf'), ('app',), ('waf',)])
def test_incomplete_combinations(store, streams):
    store.ingest([app() if s == 'app' else edge(s) for s in streams])
    result = store.snapshot(VIEWER)['requests'][0]
    assert result['state'] == 'incomplete'
    assert set(result['missing']) == set(('web', 'waf', 'app')) - set(streams)
    assert len(result['events']) == len(streams)


@pytest.mark.parametrize('path,value', [('organization.id', 'other-org'), ('host.id', 'other-host'),
                                     ('service.name', 'other-service')])
def test_scope_rejects_mixed_batch_atomically(store, path, value):
    bad = app(2)
    current = bad['_source']
    a, b = path.split('.');current[a][b] = value
    with pytest.raises(ValueError, match='event_scope_mismatch'):
        store.ingest([app(), bad])
    assert store.snapshot(VIEWER)['requests'] == []


def test_site_is_server_binding_not_event_claim(store, tmp_path):
    hit = app();hit['_source']['site'] = {'id': 'spoofed-site'}
    store.ingest([hit])
    assert store.snapshot(VIEWER)['requests'][0]['scope']['site'] == 'shop-lab'
    with pytest.raises(ValueError, match='store_binding_mismatch'):
        CorrelationStore(store.path, replace(SCOPE, site='different-site'))
    other = CorrelationStore(tmp_path / 'other.sqlite', replace(SCOPE, site='other-site',
                 app_indices=('soc-host-raw-mall-other-site',)))
    with pytest.raises(ValueError, match='reference_scope_mismatch'):
        other.ingest([hit])


def test_reused_id_far_apart_is_two_instances_even_with_same_edge_event_id(store):
    store.ingest([edge('web', 1), edge('waf', 1), app(1, 1),
                  edge('web', 301), edge('waf', 301), app(2, 301)])
    bundles = store.snapshot(VIEWER)['requests']
    assert len(bundles) == 2 and all(b['state'] == 'complete' for b in bundles)
    assert len({b['id'] for b in bundles}) == 2


def test_same_id_multiple_access_nearby_is_ambiguous_no_false_join(store):
    store.ingest([edge('web', 1), edge('web', 2), edge('waf', 1), app()])
    result = store.snapshot(VIEWER)['requests']
    assert len(result) == 4
    assert all(b['state'] == 'ambiguous' and len(b['events']) == 1 for b in result)


def test_span_is_bounded_not_transitive(store):
    store.ingest([edge('web', 1), edge('waf', 30), app(1, 59)])
    assert len(store.snapshot(VIEWER)['requests']) == 2


def test_late_arrival_out_of_order_updates_links_without_dangling_bundle(store):
    a = app();alert = detected([a])
    store.ingest([], alert)
    assert store.snapshot(VIEWER)['alert_links'][0]['state'] == 'incomplete'
    store.ingest([a]);old = store.snapshot(VIEWER)
    store.ingest([edge('waf', 0), edge('web', 0)])
    updated = store.snapshot(VIEWER)
    assert len(updated['requests']) == 1 and updated['requests'][0]['state'] == 'complete'
    assert updated['revision'] != old['revision']
    assert updated['alert_links'][0]['request_bundle_ids'] == [updated['requests'][0]['id']]
    assert updated['alert_links'][0]['state'] == 'complete'


def test_replay_reopen_and_input_order_are_idempotent(store, tmp_path):
    hits = [app(), edge('web'), edge('waf')];alerts = detected([hits[0]])
    store.ingest(hits, alerts);before = store.snapshot(VIEWER)
    store.ingest(list(reversed(hits)), alerts)
    assert store.snapshot(VIEWER) == before
    assert CorrelationStore(store.path, SCOPE).snapshot(VIEWER) == before
    other = CorrelationStore(tmp_path / 'reverse.sqlite', SCOPE)
    for hit in reversed(hits):other.ingest([hit])
    other.ingest([], alerts)
    rebuilt = other.snapshot(VIEWER)
    assert {key: value for key, value in rebuilt.items() if key != 'revision_order'} == {
        key: value for key, value in before.items() if key != 'revision_order'}
    assert rebuilt['revision_order']['publisher_id'] != before['revision_order']['publisher_id']


def test_duplicate_delivery_distinct_references_retains_alias_provenance(store):
    first = app();second = deepcopy(first);second['_id'] = 'norm-replayed'
    second['_source']['cloud_soc']['provenance']['raw']['id'] = 'raw-replayed'
    store.ingest([first, second])
    bundle = store.snapshot(VIEWER)['requests'][0]
    assert len(bundle['events']) == 1 and len(bundle['events'][0]['observations']) == 2


def test_multiple_audits_same_request_retained(store):
    store.ingest([app(1), app(2), edge('web'), edge('waf')])
    bundle = store.snapshot(VIEWER)['requests'][0]
    assert len(bundle['events']) == 4 and len(bundle['event_ids']) == 4


def test_legacy_no_request_id_is_supported_unlinked(store):
    store.ingest([app(1, rid=None), app(2, rid=None)])
    assert len(store.snapshot(VIEWER)['requests']) == 2
    assert all(b['state'] == 'unlinked' for b in store.snapshot(VIEWER)['requests'])


def test_auth_alert_keeps_six_requests_rule_severity_and_calculated_risk(store):
    hits = []
    for number, event in enumerate(sequence()):
        event.pop('_cloud_soc_meta')
        event['http'] = {'request': {'id': chr(65 + number) * 26 + 'A'}}
        event['cloud_soc']['provenance']['raw'] = {'index': RAW, 'id': 'auth-' + str(number)}
        hits.append({'_index': NORM, '_id': 'auth-norm-' + str(number), '_source': event})
    alerts = detected(hits)
    assert len(alerts) == 1
    store.ingest(hits, alerts)
    result = store.snapshot(VIEWER);link = result['alert_links'][0]
    assert link['rule_id'] == 'WEB-AUTH-01' and len(link['request_bundle_ids']) == 6
    assert len(result['requests']) == 6
    assert (link['rule_severity'], link['risk_score'], link['risk_level']) == ('medium', 60, 'high')
    store.ingest(hits, alerts)
    assert store.snapshot(VIEWER) == result


@pytest.mark.parametrize('change', ['hash', 'raw', 'normalized', 'organization', 'missing_hash'])
def test_alert_exact_evidence_and_scope_required(store, change):
    event = app();alert = detected([event])[0]
    evidence = alert['_source']['cloud_soc']['provenance']['evidence'][0]
    if change == 'organization':
        alert['_source']['organization']['id'] = 'other-org'
        with pytest.raises(ValueError, match='alert_scope_mismatch'):store.ingest([event], [alert])
        return
    if change == 'hash':evidence['event_hash'] = '0' * 64
    if change in ('raw', 'normalized'):evidence[change]['id'] = 'not-the-evidence'
    if change == 'missing_hash':evidence.pop('event_hash')
    store.ingest([event], [alert]);link = store.snapshot(VIEWER)['alert_links'][0]
    assert link['state'] == 'incomplete' and not link['request_bundle_ids']


def test_waf_detection_only_403_app_denial_and_general_403(store, tmp_path):
    store.ingest([app(), edge('web'), edge('waf')])
    assessment = store.snapshot(VIEWER)['requests'][0]['assessment']
    assert assessment == {'application_denial_observed': True, 'http_403_observed': True,
                          'http_403_cause': 'consistent_with_application_denial', 'waf_block_observed': False,
                          'origin_authenticated': False, 'compromise_confirmed': False}
    other = CorrelationStore(tmp_path / 'general.sqlite', SCOPE);other.ingest([edge('web')])
    assert other.snapshot(VIEWER)['requests'][0]['assessment']['http_403_cause'] == 'undetermined'
    assert other.snapshot(VIEWER)['requests'][0]['assessment']['waf_block_observed'] is None
    assert detected([edge('web')]) == []


def test_cross_organization_read_is_non_disclosing_and_no_client_index(store):
    store.ingest([app()]);bundle = store.snapshot(VIEWER)['requests'][0]
    other = LogPrincipal('other', 'investigator', ('other-org',), ())
    assert store.snapshot(other) == {'requests': [], 'alert_links': []}
    for identifier in (bundle['id'], 'nonexistent'):
        with pytest.raises(LookupError, match='^correlation_not_found$'):store.request(identifier, other)
    assert len(store.evidence(bundle['id'], VIEWER)) == 1
    # References expose no protected raw contents; existing source policy remains separate.
    assert not VIEWER.can_read_source(SCOPE.organization)


def test_privacy_allowlist_and_fixed_errors(store):
    event = app();event['_source'].update(message='PRIVATE_CANARY', password='PRIVATE_CANARY',
                 cookie='PRIVATE_CANARY', user={'name': 'PRIVATE_CANARY'})
    alert = detected([event])[0]
    alert['_source']['message'] = 'PRIVATE_CANARY'
    store.ingest([event], [alert])
    result = store.snapshot(VIEWER)
    assert 'PRIVATE_CANARY' not in json.dumps(result)
    assert b'PRIVATE_CANARY' not in store.path.read_bytes()
    bad = app(2);bad['_source']['http']['request']['id'] = 'PRIVATE_CANARY\n'
    with pytest.raises(ValueError, match='^request_id_invalid$') as error:store.ingest([bad])
    assert 'PRIVATE_CANARY' not in str(error.value)


@pytest.mark.parametrize('kind', ['event', 'normalized', 'raw', 'alert'])
def test_immutable_identity_conflicts_fail_closed(store, kind):
    first = app();alerts = detected([first]);store.ingest([first], alerts)
    before = store.snapshot(VIEWER);other = deepcopy(first)
    if kind == 'event':other['_source']['cloud_soc']['security_mall']['account_key_id'] = 'changed'
    if kind == 'normalized':other['_source']['cloud_soc']['normalized_at'] = stamp(333)
    if kind == 'raw':other['_id'] = 'new-normalized';other['_source']['event']['id'] = '8903d1e6-0366-4c07-8c95-9d1f64991a09'
    if kind == 'alert':
        changed = deepcopy(alerts);changed[0]['_source']['cloud_soc']['risk_score'] = 21
        with pytest.raises(ValueError, match='alert_identity_conflict'):store.ingest([], changed)
    else:
        with pytest.raises(ValueError, match='identity_conflict'):store.ingest([other])
    assert store.snapshot(VIEWER) == before


@pytest.mark.parametrize('part', ['raw', 'normalized', 'alert'])
def test_exact_index_allowlist_rejects_unknown_or_synthetic_scope(store, part):
    event = app();alerts = detected([event])
    if part == 'raw':event['_source']['cloud_soc']['provenance']['raw']['index'] = 'soc-host-raw-mall-synthetic-other'
    if part == 'normalized':event['_index'] = 'soc-normalized-production'
    if part == 'alert':alerts[0]['_index'] = 'soc-mall-alerts-lab-synthetic-other'
    with pytest.raises(ValueError, match='reference_scope_mismatch'):store.ingest([event], alerts)


def test_capacity_limit_is_transactional(tmp_path):
    store = CorrelationStore(tmp_path / 'small.sqlite', replace(SCOPE, max_events=1))
    store.ingest([app()]);before = store.snapshot(VIEWER)
    with pytest.raises(ValueError, match='correlation_capacity_limit'):store.ingest([app(2)])
    assert store.snapshot(VIEWER) == before


def test_evidence_hash_is_the_existing_detector_contract(store):
    hit = app();event = dict(hit['_source'], _cloud_soc_meta={'index': NORM, 'document_id': hit['_id']})
    expected = event_evidence(event);store.ingest([hit])
    observation = store.snapshot(VIEWER)['requests'][0]['events'][0]['observations'][0]
    assert all(observation[key] == expected[key] for key in expected)
    assert observation['ingested_at'] != store.snapshot(VIEWER)['requests'][0]['events'][0]['occurred_at']


def test_fractional_time_order_and_span_do_not_use_lexical_iso_sort(store):
    store.ingest([app(1, 30.3), edge('waf', .5), edge('web', 0)])
    bundles = store.snapshot(VIEWER)['requests']
    assert len(bundles) == 2
    pair = next(b for b in bundles if len(b['events']) == 2)
    assert [e['stream'] for e in pair['events']] == ['web', 'waf']


def test_different_request_ids_do_not_join_on_time_or_ip(store):
    store.ingest([app(), edge('web', rid='B' * 27), edge('waf', rid='C' * 27)])
    assert len(store.snapshot(VIEWER)['requests']) == 3


@pytest.mark.parametrize('change,code', [('engine_mode', 'edge_mode_invalid'), ('blocked', 'edge_mode_invalid'),
                                      ('event_id', 'edge_identity_mismatch'), ('unknown', 'edge_fields_invalid')])
def test_waf_unsupported_or_tampered_metadata_not_inferred_as_block(store, change, code):
    hit = edge('waf');body = hit['_source']['cloud_soc']['security_mall_edge']
    if change == 'engine_mode':body['engine_mode'] = 'On'
    if change == 'blocked':body['blocked'] = True
    if change == 'event_id':hit['_source']['event']['id'] = '0' * 64
    if change == 'unknown':body['message'] = 'PRIVATE_CANARY'
    with pytest.raises(ValueError, match='^' + code + '$') as error:store.ingest([hit])
    assert 'PRIVATE_CANARY' not in str(error.value)
    assert store.snapshot(VIEWER)['requests'] == []


@pytest.mark.parametrize('change,code', [('time', 'event_time_invalid'), ('version', 'event_adapter_unsupported'),
                                      ('parse', 'event_not_recognized')])
def test_invalid_normalization_contract_is_rejected(store, change, code):
    hit = app()
    if change == 'time':hit['_source']['@timestamp'] = '2026-10-17T10:00:00'
    if change == 'version':hit['_source']['cloud_soc']['normalizer_version'] = 'unknown'
    if change == 'parse':hit['_source']['cloud_soc']['parse_status'] = 'unsupported'
    with pytest.raises(ValueError, match='^' + code + '$'):store.ingest([hit])


def test_persisted_evidence_limit_rolls_back_only_new_batch(tmp_path):
    store = CorrelationStore(tmp_path / 'fanout.sqlite', replace(SCOPE, max_events=3))
    first = app();alert = detected([first])[0]
    alert['_source']['cloud_soc']['provenance']['evidence'] *= 3
    store.ingest([first], [alert]);before = store.snapshot(VIEWER)
    second = deepcopy(alert);second['_id'] = 'additional-alert'
    second['_source']['cloud_soc']['provenance']['evidence'] = second['_source']['cloud_soc']['provenance']['evidence'][:1]
    with pytest.raises(ValueError, match='correlation_evidence_limit'):store.ingest([], [second])
    assert store.snapshot(VIEWER) == before


@pytest.mark.parametrize('names', [('soc-normalized-*',), ('soc-normalized-a,soc-normalized-b',)])
def test_server_scope_forbids_wildcards_and_client_style_index_selection(names):
    with pytest.raises(ValueError, match='invalid_index'):replace(SCOPE, normalized_indices=names)


def test_foreign_database_path_is_read_only_rejected_without_schema_change(tmp_path):
    path = tmp_path / 'unrelated.sqlite'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE unrelated(id INTEGER)')
        db.execute('INSERT INTO unrelated VALUES(7)')
    path.chmod(0o600)  # Exercise schema rejection after satisfying the private-file gate.
    before = path.read_bytes()
    with pytest.raises(ValueError, match='foreign_store_database'):CorrelationStore(path, SCOPE)
    assert path.read_bytes() == before
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT * FROM unrelated').fetchall() == [(7,)]


def test_corrupt_projection_file_is_rejected_without_modification(tmp_path):
    path = tmp_path / 'corrupt.sqlite';path.write_bytes(b'not a database');path.chmod(0o600)
    with pytest.raises(ValueError, match='store_database_invalid'):CorrelationStore(path, SCOPE)
    assert path.read_bytes() == b'not a database'
