"""Read-only bounded history pages; fixed index scope and validated seek cursors."""
import base64
from datetime import datetime, timedelta, timezone
import json
import re
from cloud_soc.detection.telemetry import RUNS, EXCLUSIONS
from cloud_soc.portal.agent_status import parse_time, iso
from cloud_soc.portal.log_query import LogQueryError, bounded_json
from cloud_soc.portal.privacy import display

FIELDS = ['@timestamp', 'record_id', 'run_id', 'rule', 'state', 'range_start', 'range_end',
          'counts', 'assessment', 'error', 'reason', 'missing_fields', 'normalized', 'raw', 'event_time', 'event_hash']


def latest_runs(client, sources):
    """Resolve final phases even when the paired records straddle a seek page."""
    groups, legacy = {}, []
    for source in sources:
        run, rule = source.get('run_id'), source.get('rule', {}).get('id')
        if (not isinstance(run, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', run)
                or not isinstance(rule, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', rule)):
            legacy.append(project(source)); continue
        groups.setdefault((run, rule), []).append(source)
    ids = [run + ':' + rule + ':' + phase for run, rule in groups
           for phase in ('committed', 'failed', 'evaluated', 'waiting')]
    if ids:
        response = client.mget(index=RUNS, ids=ids, source_includes=FIELDS)
        docs = response.get('docs')
        if not isinstance(docs, list) or len(docs) != len(ids):
            raise RuntimeError('incomplete_run_phases')
        for expected, doc in zip(ids, docs):
            if doc.get('_id') != expected or doc.get('_index') != RUNS or doc.get('error'):
                raise RuntimeError('incomplete_run_phases')
            if not doc.get('found'):
                continue
            source = doc.get('_source', {})
            key = (source.get('run_id'), source.get('rule', {}).get('id'))
            if key not in groups or source.get('record_id') != expected or source.get('state') != expected.rsplit(':', 1)[1]:
                raise RuntimeError('run_phase_mismatch')
            groups[key].append(source)
    rank = {'committed': 4, 'failed': 3, 'evaluated': 2, 'waiting': 1}
    rows = []
    for phases in groups.values():
        best = max(phases, key=lambda s: rank.get(s.get('state'), 0))
        row = project(best)
        row['phases'] = list(dict.fromkeys(p.get('state') for p in phases if p.get('state') in rank))
        rows.append(row)
    return rows + legacy


def project(source):
    result = {key: display(source.get(key)) for key in ('@timestamp', 'record_id', 'run_id', 'state',
              'range_start', 'range_end', 'error', 'reason', 'event_time', 'event_hash') if key in source}
    for key, fields in (('rule', ('id', 'version')), ('raw', ('index', 'id')), ('normalized', ('index', 'id'))):
        value = source.get(key)
        if isinstance(value, dict):
            result[key] = {field: display(value.get(field)) for field in fields}
    counts = source.get('counts')
    if isinstance(counts, dict):
        result['counts'] = {k: v for k, v in counts.items() if k in ('input_events', 'source_events', 'matched', 'not_matched', 'unknown',
            'excluded', 'late', 'policy_excluded', 'alerts_created', 'alerts_existing', 'evaluated_events', 'detection_matches') and type(v) is int and v >= 0}
    if isinstance(source.get('missing_fields'), list):
        result['missing_fields'] = [display(value) for value in source['missing_fields'][:50] if isinstance(value, str)]
    value = source.get('assessment')
    if (isinstance(value, dict) and value.get('state') in ('unverified', 'not_evaluable', 'evaluated')
            and value.get('reason') in ('run_not_committed', 'incomplete_or_excluded_input',
                                     'no_source_observations', 'bounded_observed_input')):
        result['assessment'] = {'state': value['state'], 'reason': value['reason']}
    return result


def history(operations, pairs):
    pairs = list(pairs)
    args = dict(pairs)
    try:
        if len(args) != len(pairs) or set(args) - {'kind', 'rule', 'start', 'end', 'after', 'limit', 'view'}:
            raise ValueError()
        kind = args.get('kind', 'runs')
        view = args.get('view', 'records')
        if view not in ('records', 'summary') or view == 'summary' and kind != 'runs':
            raise ValueError()
        index = {'runs': RUNS, 'exclusions': EXCLUSIONS}[kind]
        limit_text = args.get('limit', '25')
        if not re.fullmatch(r'[0-9]{1,3}', limit_text):
            raise ValueError()
        limit = int(limit_text)
        if not 1 <= limit <= 100:
            raise ValueError()
        end = parse_time(args.get('end')) if 'end' in args else datetime.now(timezone.utc)
        start = parse_time(args.get('start')) if 'start' in args else end - timedelta(days=1)
        if not start or not end or not start < end or end - start > timedelta(days=30):
            raise ValueError()
        rule = args.get('rule')
        if rule is not None and not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', rule):
            raise ValueError()
        after = None
        if 'after' in args:
            token = args['after']
            if len(token) > 512 or not re.fullmatch(r'[A-Za-z0-9_-]+', token):
                raise ValueError()
            after = json.loads(base64.urlsafe_b64decode(token + '=' * (-len(token) % 4)))
            if not isinstance(after, list) or len(after) != 2 or not isinstance(after[0], int) or not isinstance(after[1], str) or not re.fullmatch(r'[A-Za-z0-9:_-]{1,160}', after[1]):
                raise ValueError()
    except (ValueError, KeyError, TypeError):
        raise LogQueryError('invalid_history_query', 400, '실행 이력 조회 조건을 확인하세요.') from None
    try:
        from cloud_soc.portal.operations import exact_indices
        if not exact_indices(operations.client, [index]):
            return bounded_json({'state': 'no_index', 'rows': [], 'next': None, 'start': iso(start), 'end': iso(end)})
        filters = [{'range': {'@timestamp': {'gte': iso(start), 'lt': iso(end)}}}]
        if rule: filters.append({'term': {'rule.id': rule}})
        result = operations.client.search(index=index, size=limit + 1, search_after=after,
            query={'bool': {'filter': filters}}, sort=[{'@timestamp': 'desc'}, {'record_id': 'asc'}],
            allow_partial_search_results=False, timeout='5s', track_total_hits=False,
            source=FIELDS)
        if result.get('timed_out') or result.get('_shards', {}).get('failed', 0):
            raise RuntimeError('partial_history')
        hits = result['hits']['hits']
        selected = hits[:limit]
        rows = latest_runs(operations.client, [hit['_source'] for hit in selected]) if view == 'summary' else [project(hit['_source']) for hit in selected]
        cursor = None
        if len(hits) > limit:
            seek = selected[-1].get('sort')
            if not seek or seek == after:
                raise RuntimeError('invalid_history_cursor')
            cursor = base64.urlsafe_b64encode(json.dumps(seek).encode()).decode().rstrip('=')
        return bounded_json({'state': 'ok', 'rows': rows, 'next': cursor, 'start': iso(start), 'end': iso(end)})
    except Exception:
        raise LogQueryError('history_unavailable', 503, '실행·제외 이력을 조회하지 못했습니다.') from None
