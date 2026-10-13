"""Tenant-scoped latest notice revisions and verified references, no telemetry writes."""
from datetime import datetime, timedelta, timezone
import re

from cloud_soc.detection.early import NOTICES, STATES, MAPPING
from cloud_soc.portal.operations import exact_indices
from cloud_soc.portal.log_contract import parse_filters, field
from cloud_soc.portal.log_query import LogQueryError
from cloud_soc.portal.security_detail import address
from cloud_soc.processing.worker import checked
from cloud_soc.privacy import redact_metadata


def bad():
    return LogQueryError('notices_unavailable', 503, '초기 통지를 조회하지 못했습니다. 연결·권한·상태 형식을 확인하세요.')


def project(document, organizations=None):
    header, body = document.get('notice'), document.get('body')
    if (not isinstance(header, dict) or not isinstance(body, dict)
            or not isinstance(header.get('id'), str) or not re.fullmatch('[0-9a-f]{64}', header['id'])
            or header.get('state') not in STATES or type(header.get('revision')) is not int or header['revision'] < 1
            or body.get('id') != header['id'] or body.get('state') != header['state']
            or body.get('revision') != header['revision'] or body.get('organization') != field(document, 'organization.id')
            or body.get('rule_id') != 'AUTH-001' or body.get('threshold') != 10 or body.get('window_seconds') != 300
            or type(body.get('observed_count')) is not int or body['observed_count'] != 10
            or address(body.get('source_ip')) != body.get('source_ip') or not body.get('source_ip')
            or not isinstance(body.get('evidence'), list) or len(body['evidence']) != 10
            or organizations is not None and body['organization'] not in organizations):
        raise bad()
    final = body.get('final_alert_id')
    if final is not None and (not isinstance(final, str) or not re.fullmatch('[0-9a-f]{64}', final)):
        raise bad()
    if (header['state'] == 'confirmed') != (final is not None):
        raise bad()
    result = {key: body.get(key) for key in ('id', 'state', 'revision', 'organization', 'rule_id', 'rule_version',
        'title', 'severity', 'source_ip', 'observed_count', 'threshold', 'window_seconds', 'window_start', 'window_end',
        'initial_at', 'updated_at', 'final_at', 'final_alert_id', 'first_received_at', 'normalized_at',
        'search_observed_at', 'normalization_to_initial_seconds', 'final_observed_count', 'reason', 'attack_success')}
    result['evidence_count'] = 10
    result['effective_state'] = result['state']
    try:
        stamp = datetime.fromisoformat(result['updated_at'].replace('Z', '+00:00'))
        if stamp.tzinfo is None:
            raise ValueError()
        if result['state'] in ('initial', 'verifying') and datetime.now(timezone.utc) - stamp > timedelta(minutes=20):
            result['effective_state'] = 'delayed'
    except (TypeError, ValueError, AttributeError):
        raise bad() from None
    return redact_metadata(result)


class NoticeReader:
    def __init__(self, operations):
        self.operations = operations

    def sources(self, *, identifier=None, start=None, end=None):
        client, organizations = self.operations.client, self.operations.organizations
        if not client:
            raise bad()
        if not exact_indices(client, [NOTICES]):
            return None
        mapping = client.indices.get_mapping(index=NOTICES)
        if set(mapping) != {NOTICES} or mapping[NOTICES]['mappings'] != MAPPING:
            raise bad()
        filters = []
        if organizations is not None:
            filters.append({'terms': {'organization.id': list(organizations)}})
        if identifier:
            filters.append({'term': {'notice.id': identifier}})
        if start:
            filters.append({'range': {'notice.initial_at': {'gte': start, 'lt': end}}})
        result = checked(client.search(index=NOTICES, size=1 if identifier else 50, timeout='4s',
            allow_partial_search_results=False, track_total_hits=False,
            query={'bool': {'filter': filters}}, source=False, sort=[{'@timestamp': 'desc'}],
            collapse={'field': 'notice.id', 'inner_hits': {'name': 'current', 'size': 1,
                'sort': [{'notice.revision': 'desc'}], '_source': True}}))
        hits = result['hits']['hits']
        if not isinstance(hits, list) or len(hits) > (1 if identifier else 50):
            raise bad()
        sources = []
        for hit in hits:
            current = hit['inner_hits']['current']['hits']['hits']
            if len(current) != 1:
                raise bad()
            source = current[0]['_source']
            project(source, organizations)
            sources.append(source)
        ids = [source['notice']['id'] for source in sources]
        if len(ids) != len(set(ids)) or identifier and any(key != identifier for key in ids):
            raise bad()
        return sources

    def listing(self, pairs):
        pairs = list(pairs)
        try:
            if any(key not in ('start', 'end') for key, _ in pairs):
                raise ValueError()
            interval = parse_filters(pairs)
        except ValueError:
            raise LogQueryError('invalid_notice_query', 400, '초기 통지 조회 기간을 확인하세요.') from None
        try:
            sources = self.sources(start=interval.start, end=interval.end)
            return {'state': 'not_configured' if sources is None else 'ok',
                'rows': [] if sources is None else [project(source, self.operations.organizations) for source in sources],
                'limit': 50, 'count_basis': 'latest_visible_logical_notices_not_attack_count',
                'start': interval.start, 'end': interval.end, 'checked_at': datetime.now(timezone.utc).isoformat()}
        except LogQueryError:
            raise
        except Exception:
            raise bad() from None

    def detail(self, pairs):
        pairs = list(pairs)
        values = dict(pairs)
        if (len(pairs) != len(values) or set(values) not in ({'id'}, {'id', 'evidence'})
                or not re.fullmatch('[0-9a-f]{64}', values.get('id', ''))
                or 'evidence' in values and not re.fullmatch('[0-9]', values['evidence'])):
            raise LogQueryError('invalid_notice_reference', 400, '통지와 근거 참조를 확인하세요.')
        try:
            sources = self.sources(identifier=values['id'])
            if not sources:
                raise LogQueryError('notice_missing', 404, '통지가 없거나 보존 기간이 지났습니다.')
            source = sources[0]
            result = {'notice': project(source, self.operations.organizations)}
            if 'evidence' in values:
                result['evidence'] = self.operations.evidence(source['body']['evidence'][int(values['evidence'])],
                                                             organization=source['body']['organization'])
            return redact_metadata(result)
        except LogQueryError:
            raise
        except Exception:
            raise bad() from None
