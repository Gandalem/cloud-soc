"""Fresh, bounded site context. Nearby observations are never detection evidence."""
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

from cloud_soc.portal.agent_status import iso, parse_time
from cloud_soc.portal.log_contract import field, document_reference
from cloud_soc.portal.log_query import LogQueryError, bounded_json
from cloud_soc.portal.security_detail import text
from cloud_soc.processing.contract import NORMALIZED
from cloud_soc.processing.worker import checked
from cloud_soc.web.scope import NORMALIZER_VERSION, NORMALIZED_ADAPTER, valid_site_id
from cloud_soc.web.modsecurity import VERSION as WAF_VERSION, ADAPTER as WAF_ADAPTER

LIMIT = 50
FIELDS = ['@timestamp', 'organization.id', 'host.id', 'service.id', 'source.ip', 'http.request.method',
          'http.response.status_code', 'cloud_soc.normalizer_version', 'cloud_soc.detail.adapter',
          'cloud_soc.provenance.raw']


def context(reader, pairs, *, now=None):
    from cloud_soc.portal.operations import ALERT_FIELDS, exact_indices, identifier, exact_count
    pairs = list(pairs)
    if len(pairs) != 1 or pairs[0][0] != 'id':
        raise LogQueryError('invalid_context_query', 400, '경보 참조를 확인하세요.')
    try:
        alert_id = identifier(pairs[0][1])
    except ValueError:
        raise LogQueryError('invalid_context_query', 400, '경보 참조를 확인하세요.') from None
    now = now or datetime.now(timezone.utc)
    try:
        source = reader.get(reader.alert_index, alert_id, ALERT_FIELDS)
        if source is None:
            raise LogQueryError('alert_missing', 404, '경보가 없거나 조회 범위 밖입니다.')
        scope = field(source, 'cloud_soc.provenance.scope')
        if reader.mall_scope or not isinstance(scope, dict):
            return bounded_json({'state': 'unsupported', 'reason': 'site_scope_not_recorded'})
        if (set(scope) != {'organization.id', 'host.id', 'service.id', 'source.ip'}
                or not valid_site_id(scope['service.id'])
                or any(not isinstance(v, str) or not v or text(v) != v for v in scope.values())
                or any(field(source, path) != value for path, value in scope.items())
                or str(ip_address(scope['source.ip'])) != scope['source.ip']):
            raise ValueError('Invalid alert site scope')
        refs = field(source, 'cloud_soc.provenance.evidence')
        if not isinstance(refs, list) or not refs:
            raise ValueError('Missing scope anchor')
        anchor = reader.evidence(refs[0], organization=scope['organization.id'])
        names = {'organization.id': 'organization', 'host.id': 'host_id', 'service.id': 'site_id', 'source.ip': 'source_ip'}
        if (anchor.get('integrity') != 'normalized_hash_verified' or anchor.get('state') != 'exact_reference'
                or any(anchor.get('normalized_event', {}).get(names[path]) != value for path, value in scope.items())):
            raise ValueError('Unverified scope anchor')
        start, end = (parse_time(field(source, 'cloud_soc.' + name)) for name in ('window_start', 'window_end'))
        if start is None or end is None or not timedelta(0) <= end - start <= timedelta(hours=1) or end > now:
            raise ValueError('Invalid context bounds')
        upper = min(now, end + timedelta(minutes=5))
        if exact_indices(reader.client, [NORMALIZED]) != [NORMALIZED]:
            raise ValueError('Missing concrete normalized scope')
        result = checked(reader.client.search(index=NORMALIZED, size=LIMIT, source=FIELDS,
            sort=[{'@timestamp': 'desc'}], track_total_hits=True, timeout='4s', allow_partial_search_results=False,
            query={'bool': {'filter': [*[{'term': {key: value}} for key, value in scope.items()],
                {'terms': {'cloud_soc.normalizer_version': [NORMALIZER_VERSION, WAF_VERSION]}},
                {'range': {'@timestamp': {'gte': iso(start), 'lte': iso(upper)}}}]}}))
        total = result['hits']['total']
        if total['relation'] != 'eq':
            raise ValueError('Inexact context count')
        count = exact_count(total['value'])
        hits = result['hits']['hits']
        if len(hits) != min(count, LIMIT):
            raise ValueError('Incomplete context response')
        rows, seen = [], set()
        for hit in hits:
            event = hit['_source']
            stamp = parse_time(event.get('@timestamp'))
            doc_id = identifier(hit['_id'])
            if (hit['_index'] != NORMALIZED or doc_id in seen or stamp is None or not start <= stamp <= upper
                    or any(field(event, path) != value for path, value in scope.items())
                    or (field(event, 'cloud_soc.detail.adapter'), field(event, 'cloud_soc.normalizer_version')) not in (
                        (NORMALIZED_ADAPTER, NORMALIZER_VERSION), (WAF_ADAPTER, WAF_VERSION))):
                raise ValueError('Context scope mismatch')
            seen.add(doc_id)
            raw = field(event, 'cloud_soc.provenance.raw')
            raw = document_reference(raw['index'], raw['id'])
            status = field(event, 'http.response.status_code')
            method = field(event, 'http.request.method')
            if type(status) is not int or not 100 <= status <= 599 or method not in ('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'):
                raise ValueError('Invalid HTTP metadata')
            rows.append({'timestamp': iso(stamp), 'method': method, 'status_code': status,
                         'normalized': {'index': NORMALIZED, 'id': doc_id}, 'raw': raw})
        return bounded_json({'state': 'ok', 'checked_at': iso(now), 'scope': scope,
            'start': iso(start), 'end': iso(upper), 'count': count, 'limit': LIMIT,
            'truncated': count > LIMIT, 'events': rows,
            'relation': 'same_site_host_peer_in_time_window', 'request_correlation': 'not_available',
            'detection_evidence': False})
    except LogQueryError:
        raise
    except Exception:
        raise LogQueryError('site_context_unavailable', 503, '사이트 범위와 근거를 확인하지 못했습니다. 다시 조회하세요.') from None
