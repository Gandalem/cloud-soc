"""Exercise the real query builder/projection with deterministic paged transport replies."""
from copy import deepcopy
import json

import pytest

from cloud_soc.portal.dashboard_insights import InsightReader
from cloud_soc.portal.insight_state import InsightError
from cloud_soc.portal.log_contract import parse_filters
from cloud_soc.portal.log_query import LogReader
from test_log_query import client as transport, FIXTURE

NAMES = ['soc-cloud-aws-quality-one', 'soc-cloud-aws-quality-two']
PAIRS = [('start', '2026-10-01T00:00:00Z'), ('end', '2026-10-02T00:00:00Z')]


def hits(count=503):
    rows = []
    for i in range(count):
        source = deepcopy(FIXTURE['_source'])
        source.update(organization={'id': 'org-a'}, labels={'log_source': 'aws_cloudtrail'},
                      cloud={'provider': 'aws', 'account': {'id': '123456789012'}},
                      event={'action': 'CreateUser', 'ingested': '2026-10-01T00:00:00Z'},
                      aws={'cloudtrail': {'schema': 1, 'management_only': True}})
        rows.append({'_index': NAMES[i % 2], '_id': str(i // 2), '_source': source,
                     'sort': [1790812800000, i]})
    return rows


def page(rows, pit='pit-next', **extra):
    return {'pit_id': pit, '_shards': {'failed': 0}, 'timed_out': False,
            'hits': {'hits': deepcopy(rows)}, **extra}


def scanner(pages, **options):
    client = transport()
    client.indices.resolve_index.return_value = {'indices': [{'name': n} for n in NAMES], 'aliases': [], 'data_streams': []}
    client.open_point_in_time.return_value = {'id': 'pit-initial', '_shards': {'failed': 0}}
    client.search.side_effect = pages
    reader = LogReader(client, secret='synthetic-query-secret', principal='reader', organizations=('org-a',))
    return InsightReader(reader, **options), client


def test_all_503_exact_references_search_after_and_rotated_pit():
    expected = hits()
    reader, client = scanner([page(expected[:250], 'pit-one'), page(expected[250:500], 'pit-two'), page(expected[500:], 'pit-three')])
    rows, state = reader.scan(parse_filters(PAIRS), 'cloud', {'provider': 'aws', 'account': '123456789012'})
    assert state == 'ok'
    assert [(r['reference']['index'], r['reference']['id']) for r in rows] == [(h['_index'], h['_id']) for h in expected]
    bodies = [c.kwargs['body'] for c in client.search.call_args_list]
    assert len(bodies) == 3
    assert [b['pit']['id'] for b in bodies] == ['pit-initial', 'pit-one', 'pit-two']
    assert bodies[1]['search_after'] == expected[249]['sort']
    assert bodies[2]['search_after'] == expected[499]['sort']
    assert 'search_after' not in bodies[0]
    for body in bodies:
        assert body['size'] == 250
        assert {'terms': {'organization.id': ['org-a']}} in body['query']['bool']['filter']
        assert {'term': {'insight_provider': 'aws'}} in body['query']['bool']['filter']
        assert {'term': {'insight_account': '123456789012'}} in body['query']['bool']['filter']
        assert body['sort'] == [{'event.ingested': {'order': 'desc', 'unmapped_type': 'date', 'numeric_type': 'date'}}, {'_shard_doc': 'asc'}]
    assert all(c.kwargs['allow_partial_search_results'] is False for c in client.search.call_args_list)
    client.open_point_in_time.assert_called_once_with(index=','.join(NAMES), keep_alive='30s', allow_partial_search_results=False)
    client.close_point_in_time.assert_called_once_with(id='pit-three')


@pytest.mark.parametrize('fault', ['duplicate', 'reversed_sort', 'foreign_organization', 'outside_index', 'wrong_account', 'invalid_sort'])
def test_bad_second_page_never_returns_a_partial_success(fault):
    original = hits(251)
    bad = deepcopy(original[250])
    expected_code = 'invalid_page'
    if fault == 'duplicate':
        bad['_index'], bad['_id'] = original[0]['_index'], original[0]['_id']
    elif fault == 'reversed_sort':
        bad['sort'] = original[249]['sort']
    elif fault == 'invalid_sort':
        bad['sort'] = ['invalid', 250]
    else:
        expected_code = 'scope_mismatch'
        if fault == 'foreign_organization':
            bad['_source']['organization']['id'] = 'org-b'
        elif fault == 'outside_index':
            bad['_index'] = 'soc-host-raw-outside'
        else:
            bad['_source']['cloud']['account']['id'] = '999999999999'
    reader, client = scanner([page(original[:250], 'pit-one'), page([bad], 'pit-two')])
    with pytest.raises(InsightError) as failure:
        reader.scan(parse_filters(PAIRS), 'cloud', {'account': '123456789012'})
    assert failure.value.code == expected_code
    client.close_point_in_time.assert_called_once_with(id='pit-two')
    assert not reader.cache


@pytest.mark.parametrize('fault', ['timeout', 'shard', 'terminated', 'connection'])
def test_second_page_remote_failure_is_not_cached_and_retry_requeries(fault):
    rows = hits(251)
    bad = {'timeout': page([], 'pit-failed', timed_out=True),
           'shard': page([], 'pit-failed', _shards={'failed': 1}),
           'terminated': page([], 'pit-failed', terminated_early=True),
           'connection': ConnectionError('synthetic-transport-failure')}[fault]
    reader, client = scanner([page(rows[:250], 'pit-one'), bad])
    with pytest.raises(ConnectionError if fault == 'connection' else InsightError) as failure:
        reader.dataset(PAIRS, 'cloud')
    if fault != 'connection':
        assert failure.value.code == 'incomplete_query' and failure.value.status == 503
    assert not reader.cache
    client.close_point_in_time.assert_called_once_with(id='pit-one' if fault == 'connection' else 'pit-failed')
    client.search.side_effect = [page(rows[:1], 'pit-recovered')]
    recovered, state, *_ = reader.dataset(PAIRS, 'cloud')
    assert state == 'ok' and len(recovered) == 1
    assert client.open_point_in_time.call_count == 2
    assert client.close_point_in_time.call_args.kwargs == {'id': 'pit-recovered'}


def test_capacity_failure_is_explicit_and_closes_snapshot():
    rows = hits(251)
    reader, client = scanner([page(rows[:250], 'pit-one'), page(rows[250:], 'pit-two')], max_events=250)
    with pytest.raises(InsightError) as failure:
        reader.dataset(PAIRS, 'cloud')
    assert failure.value.code == 'query_event_capacity' and failure.value.status == 413
    assert not reader.cache
    client.close_point_in_time.assert_called_once_with(id='pit-two')


def test_full_count_is_independent_of_fifty_row_display_and_cache_pagination():
    rows = hits()
    reader, client = scanner([page(rows[:250]), page(rows[250:500]), page(rows[500:])])
    first = reader.cloud(PAIRS)
    second = reader.cloud(PAIRS + [('offset', '50')])
    assert first['recognized'] == 503 and len(first['rows']) == 50 and first['next_offset'] == 50
    assert second['recognized'] == 503 and len(second['rows']) == 50 and second['next_offset'] == 100
    assert {json.dumps(r['reference'], sort_keys=True) for r in first['rows']}.isdisjoint(
        json.dumps(r['reference'], sort_keys=True) for r in second['rows'])
    assert client.open_point_in_time.call_count == 1
