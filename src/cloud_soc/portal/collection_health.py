"""Authenticated source-discovery reports, deliberately separate from log counts."""
from datetime import datetime, timedelta, timezone
import json
import math
import re

from cloud_soc.portal.agent_status import iso, parse_time, encode_cursor
from cloud_soc.portal.privacy import display

STATUSES = {'selected', 'unreadable', 'enumeration_error', 'disabled', 'unsupported_direct_channel',
            'unsafe_name', 'unsafe_path', 'missing', 'reparse_point', 'symlink',
            'binary_archive_or_secret', 'unsupported_encoding', 'unsupported_encoding_or_binary',
            'binary', 'empty_pending', 'policy_excluded'}

METRICS = ('queue_bytes', 'queue_events', 'queue_pct', 'queue_max_bytes', 'pipeline_active',
           'output_total', 'output_acked', 'output_failed', 'output_dropped',
           'output_dead_letter', 'output_failure_store', 'read_errors', 'write_errors')
PROBLEMS = ('output_failed', 'output_dropped', 'output_dead_letter', 'output_failure_store',
            'read_errors', 'write_errors')


def collector_metrics(value, generated, now):
    """Allowlisted interval samples; missing counters are never claimed as zero."""
    unavailable = {'state': 'unavailable', 'queue_state': 'unknown', 'transport_state': 'unknown'}
    if value is None:
        return unavailable
    invalid = {**unavailable, 'state': 'invalid'}
    if not isinstance(value, dict) or type(value.get('schema')) is not int or value['schema'] != 1:
        return invalid
    if value.get('state') == 'unavailable':
        return unavailable
    sampled = parse_time(value.get('sampled_at'))
    interval = value.get('interval_seconds')
    if (value.get('state') != 'observed' or value.get('counter_scope') != 'logged_interval_delta'
            or not sampled or type(interval) is not int or not 1 <= interval <= 86400
            or type(value.get('scan_partial')) is not bool):
        return invalid
    numbers = {}
    for name in METRICS:
        number = value.get(name)
        if number is not None:
            if name == 'queue_pct':
                valid = type(number) in (int, float) and 0 <= number <= 1 and math.isfinite(number)
            else:
                valid = type(number) is int and 0 <= number <= 9007199254740991
            if not valid:
                return invalid
        numbers[name] = number
    future = (sampled - now).total_seconds() > 60 or (sampled - generated).total_seconds() > 60
    age = max(0, round((now - sampled).total_seconds()))
    state = 'clock_warning' if future else 'stale' if age > 300 else 'recent'
    problem = parse_time(value.get('last_problem_at'))
    if value.get('last_problem_at') is not None and (not problem or (problem - sampled).total_seconds() > 60):
        return invalid
    recent_problem = problem and now - timedelta(minutes=30) <= problem <= now + timedelta(seconds=60)
    active = state == 'recent'
    queue = numbers['queue_pct']
    return {**numbers, 'state': state, 'sampled_at': iso(sampled), 'age_seconds': age,
            'interval_seconds': interval, 'counter_scope': 'logged_interval_delta',
            'scan_partial': value['scan_partial'], 'last_problem_at': iso(problem) if problem else None,
            'queue_state': 'unknown' if not active or queue is None else 'high' if queue >= .8 else 'measured',
            'transport_state': ('error_observed' if recent_problem or any((numbers[k] or 0) > 0 for k in PROBLEMS)
                                else 'observed') if active else 'unknown'}


def project(source, key, now):
    report = source.get('cloud_soc', {}).get('discovery', {})
    if report.get('schema') != 1:
        raise ValueError('Unsupported health schema')
    values = {}
    for name in ('selected', 'excluded', 'errors', 'total', 'policy_version'):
        value = report.get(name)
        if type(value) is not int or not 0 <= value <= 1000000000:
            raise ValueError('Invalid health counters')
        values[name] = value
    if values['selected'] + values['excluded'] + values['errors'] != values['total']:
        raise ValueError('Inconsistent health counters')
    entries = report.get('sources')
    if not isinstance(entries, list) or len(entries) > 200 or len(entries) > values['total']:
        raise ValueError('Invalid health sources')
    sources = []
    for entry in entries:
        if (not isinstance(entry, dict) or not isinstance(entry.get('id'), str)
                or not re.fullmatch('[a-f0-9]{64}', entry['id']) or entry.get('status') not in STATUSES):
            raise ValueError('Invalid health source')
        sources.append({'id': entry['id'], 'status': entry['status']})
    generated = parse_time(report.get('generated_at'))
    received = parse_time(source.get('event', {}).get('ingested'))
    if not generated or not received:
        raise ValueError('Missing health times')
    delay = (received - generated).total_seconds()
    age = (now - received).total_seconds()
    metrics = collector_metrics(report.get('collector_metrics'), generated, now)
    network_metrics = collector_metrics(report.get('network_collector_metrics'), generated, now)
    return {**values, 'sources': sources, 'omitted_sources': values['total'] - len(sources),
            'agent_id': display(key.get('agent_id')), 'organization': display(key.get('organization')),
            'host': display(source.get('host', {}).get('name')), 'generated_at': iso(generated),
            'received_at': iso(received), 'delay_seconds': round(delay) if delay >= 0 else None,
            'clock_warning': delay < 0 or age < -60,
            'report_state': 'unknown' if age < -60 else 'recent' if age <= 300 else 'stale',
            'queue_state': metrics['queue_state'], 'transport_state': metrics['transport_state'],
            'collector_metrics': metrics, 'network_collector_metrics': network_metrics,
            'network_identity': 'agent_reported_co_located_not_attested', 'source_success': 'not_measured'}


def snapshot(client, after=None, now=None):
    now = now or datetime.now(timezone.utc)
    composite = {'size': 50, 'sources': [
        {'organization': {'terms': {'field': 'organization.id', 'missing_bucket': True}}},
        {'agent_id': {'terms': {'field': 'agent.id'}}},
        {'agent_type': {'terms': {'field': 'agent.type', 'missing_bucket': True}}},
    ]}
    if after:
        composite['after'] = after
    result = client.options(request_timeout=5, max_retries=0).search(
        index='soc-agent-health-*', size=0, timeout='4s', allow_no_indices=True,
        allow_partial_search_results=False, expand_wildcards='open',
        query={'range': {'event.ingested': {'gte': iso(now - timedelta(days=30)), 'lte': iso(now + timedelta(minutes=1))}}},
        aggs={'agents': {'composite': composite, 'aggs': {'latest': {'top_hits': {
            'size': 1, 'sort': [{'event.ingested': 'desc'}],
            '_source': ['host.name', 'cloud_soc.discovery', 'event.ingested']}}}}})
    if result.get('timed_out') or result.get('_shards', {}).get('failed', 0):
        raise ValueError('Incomplete health response')
    if result.get('_shards', {}).get('total') == 0:
        groups = {}
    else:
        groups = result['aggregations']['agents']
    rows = [project(bucket['latest']['hits']['hits'][0]['_source'], bucket['key'], now)
            for bucket in groups.get('buckets', [])]
    cursor = groups.get('after_key') if len(rows) == 50 else None
    payload = {'rows': rows, 'checked_at': iso(now), 'next_cursor': encode_cursor(cursor) if cursor else None,
               'window_days': 30, 'identity': 'agent_reported_not_attested'}
    encoded = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    if len(encoded) > 2 * 1024 * 1024:
        raise ValueError('Health response too large')
    return encoded
