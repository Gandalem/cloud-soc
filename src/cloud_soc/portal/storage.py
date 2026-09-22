"""Read-only capacity/retention planning. This module cannot delete or change ILM."""
from datetime import datetime, timedelta, timezone
import re

from cloud_soc.portal.agent_status import iso, parse_time

INDICES = 'soc-host-raw-*,soc-network-*,soc-agent-health-*,soc-cloud-aws-*,soc-cloud-oci-*'
NAME = re.compile(r'soc-(?:host-raw|network|agent-health|cloud-aws|cloud-oci)-[a-z0-9][a-z0-9_.-]*\Z')


def lifecycle_proposal(days):
    if type(days) is not int or not 1 <= days <= 365:
        raise ValueError('Proposed retention must be 1-365 days')
    return {'policy': {'phases': {'hot': {'actions': {}},
                                'delete': {'min_age': f'{days}d', 'actions': {'delete': {}}}}}}


def survey(client, *, days, now=None):
    if type(days) is not int or not 1 <= days <= 365:
        raise ValueError('Proposed retention must be 1-365 days')
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)
    es = client.options(request_timeout=10, max_retries=0)
    stats = es.indices.stats(index=INDICES, metric='docs,store,indexing', expand_wildcards='open')
    if stats.get('_shards', {}).get('failed', 0):
        raise ValueError('Incomplete storage statistics')
    rows = []
    for name, value in sorted(stats.get('indices', {}).items()):
        if not NAME.fullmatch(name):
            raise ValueError('Unexpected storage index')
        result = es.search(index=name, size=0, timeout='4s', allow_partial_search_results=False,
                           aggs={'last_received': {'max': {'field': 'event.ingested'}},
                                 'missing_received': {'missing': {'field': 'event.ingested'}}})
        if result.get('timed_out') or result.get('_shards', {}).get('failed', 0):
            raise ValueError('Incomplete retention metadata')
        received = result['aggregations']['last_received'].get('value_as_string')
        received = parse_time(received)
        missing = result['aggregations']['missing_received']['doc_count']
        candidate = received is not None and received < cutoff and missing == 0
        primary = value['primaries']
        rows.append({'index': name, 'uuid': value['uuid'], 'documents': primary['docs']['count'],
                     'primary_bytes': primary['store']['size_in_bytes'],
                     'total_bytes': value['total']['store']['size_in_bytes'],
                     'indexed_operations': primary['indexing']['index_total'],
                     'last_received': iso(received) if received else None,
                     'missing_receipt': missing, 'review_candidate': candidate})
    nodes = es.nodes.stats(metric='fs')
    if nodes.get('_nodes', {}).get('failed', 0):
        raise ValueError('Incomplete filesystem statistics')
    disks = []
    for node in nodes['nodes'].values():
        total = node['fs']['total']['total_in_bytes']
        available = node['fs']['total']['available_in_bytes']
        used = round(100 * (1 - available / total), 2) if total else None
        disks.append({'total_bytes': total, 'available_bytes': available, 'used_percent': used,
                      'advisory': 'unknown' if used is None else 'critical' if used >= 85 else 'warning' if used >= 75 else 'normal'})
    return {'schema': 1, 'measured_at': iso(now), 'proposed_days': days, 'approved': False,
            'automatic_deletion': False, 'indices': rows, 'disks': disks,
            'thresholds_proposal': {'warning_percent': 75, 'critical_percent': 85},
            'note': 'Review candidates only. Last receipt is not a legal retention decision; backups and active writers must be reviewed.'}


def growth(previous, current):
    """Net primary growth, not wire traffic; merges/deletion invalidate estimates."""
    start, end = parse_time(previous.get('measured_at')), parse_time(current.get('measured_at'))
    if not start or not end or end <= start:
        raise ValueError('Two ordered measurements are required')
    old = {row['index']: row for row in previous['indices']}
    new = {row['index']: row for row in current['indices']}
    if set(old) - set(new) or any(old[name]['uuid'] != new[name]['uuid'] for name in old):
        return {'status': 'unknown', 'reason': 'indices_removed_or_recreated'}
    delta = sum(row['primary_bytes'] for row in new.values()) - sum(row['primary_bytes'] for row in old.values())
    seconds = (end - start).total_seconds()
    if delta < 0 or seconds < 3600:
        return {'status': 'unknown', 'reason': 'net_shrink_or_sample_under_one_hour'}
    daily = round(delta * 86400 / seconds)
    return {'status': 'estimate', 'sample_seconds': seconds, 'net_primary_bytes_per_day': daily,
            'proposed_primary_bytes': daily * current['proposed_days'],
            'excludes': ['replicas', 'translog', 'snapshots', 'merge_headroom', 'other_services'],
            'note': 'Use multiple representative 24-hour samples; this is not gross ingestion volume.'}
