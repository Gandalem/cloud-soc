"""Deterministic request/alert review queue. No detection, IO or incident mutation."""
from datetime import timedelta
import re

from cloud_soc.correlation.security_mall import (VERSION as CORRELATION_VERSION, correlate, require,
    select_event, select_alert, reference)
from cloud_soc.correlation.store import encode
from cloud_soc.detection.engine import event_fingerprint
from cloud_soc.parsers.security_mall import ADAPTER as APP, VERSION as APP_VERSION
from cloud_soc.parsers.security_mall_edge import ADAPTER as EDGE, VERSION as EDGE_VERSION
from cloud_soc.portal.agent_status import iso, parse_time
from cloud_soc.triage.policy import Policy, VERSION


def digest(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'triage_digest_invalid')
    return value


def time_range(start, end, policy):
    first, last = parse_time(start), parse_time(end)
    require(first is not None and last is not None and timedelta(0) < last - first <= timedelta(days=policy.max_range_days),
            'triage_range_invalid')
    return {'start': iso(first), 'end': iso(last)}


def validate_snapshot(snapshot, scope):
    """Rebuild the 7-A view through the real parsers, not a permissive JSON copier.

    Hashes here prove agreement with trusted 7-A evidence metadata, not that the
    caller is authenticated or that original ES/raw contents have been re-read.
    """
    require(isinstance(snapshot, dict) and set(snapshot) == {'schema_version', 'version', 'scope',
            'revision', 'revision_order', 'requests', 'alert_links'}, 'triage_snapshot_contract')
    require(snapshot['schema_version'] == 1 and snapshot['version'] == CORRELATION_VERSION and
            snapshot['scope'] == scope.identity, 'triage_scope_mismatch')
    order = snapshot['revision_order']
    require(isinstance(order, dict) and set(order) == {'publisher_id', 'sequence', 'binding_id'}, 'triage_order_missing')
    require(isinstance(order['publisher_id'], str) and re.fullmatch('[0-9a-f]{32}', order['publisher_id']) and
            type(order['sequence']) is int and order['sequence'] >= 0, 'triage_order_invalid')
    from dataclasses import asdict
    require(order['binding_id'] == event_fingerprint({'version': CORRELATION_VERSION, 'scope': asdict(scope)}),
            'triage_binding_mismatch')
    digest(snapshot['revision'])
    require(isinstance(snapshot['requests'], list) and isinstance(snapshot['alert_links'], list) and
            len(snapshot['requests']) <= scope.max_events and len(snapshot['alert_links']) <= scope.max_events,
            'triage_capacity_limit')
    events, seen, seen_observations = [], set(), set()
    for bundle in snapshot['requests']:
        require(isinstance(bundle, dict) and isinstance(bundle.get('events'), list), 'triage_bundle_invalid')
        for event in bundle['events']:
            require(isinstance(event, dict) and set(event) == {'key', 'event_id', 'stream', 'request_id',
                    'occurred_at', 'source_ip', 'metadata', 'observations'}, 'triage_event_invalid')
            observations = event['observations']
            require(isinstance(observations, list) and 0 < len(observations) <= scope.max_events, 'triage_evidence_invalid')
            for observation in observations:
                require(isinstance(observation, dict) and set(observation) == {'normalized', 'raw', 'event_hash',
                        'complete', 'ingested_at'} and observation['complete'] is True, 'triage_evidence_invalid')
                reference(observation['normalized'], scope.normalized_indices)
                reference(observation['raw'], scope.app_indices if event['stream'] == 'app' else scope.edge_indices)
                digest(observation['event_hash'])
                received = parse_time(observation['ingested_at'])
                require(received is not None and iso(received) == observation['ingested_at'], 'triage_time_invalid')
                key = encode(observation['normalized'])
                require(key not in seen_observations, 'triage_duplicate_observation')
                seen_observations.add(key)
            require(event['key'] not in seen, 'triage_duplicate_event')
            seen.add(event['key'])
            require(isinstance(event['metadata'], dict), 'triage_metadata_invalid')
            app = event['stream'] == 'app'
            metadata = event['metadata']
            first = observations[0]
            source = {'@timestamp': event['occurred_at'], 'organization': {'id': scope.organization},
                      'host': {'id': scope.host}, 'service': {'name': scope.service}, 'source': {'ip': event['source_ip']},
                      'event': {'id': event['event_id'], 'kind': 'event', 'ingested': first['ingested_at']},
                      'http': {'request': {'id': event['request_id']}}, 'cloud_soc': {'parse_status': 'recognized',
                      'normalizer_version': APP_VERSION if app else EDGE_VERSION,
                      'detail': {'adapter': APP if app else EDGE}, 'provenance': {'schema_version': 1, 'raw': first['raw']}}}
            if app:
                source['event'].update(action=metadata.get('action'), outcome=metadata.get('outcome'))
                source['cloud_soc']['security_mall'] = {key: value for key, value in metadata.items()
                                                       if key not in ('action', 'outcome')}
                source['cloud_soc']['security_mall']['schema_version'] = 1
            else:
                require(event['stream'] in ('web', 'waf'), 'triage_stream_invalid')
                source['event']['action'] = 'http_access' if event['stream'] == 'web' else 'waf_rule_match'
                source['cloud_soc']['security_mall_edge'] = dict(metadata, schema_version=1,
                    stream='access' if event['stream'] == 'web' else 'waf', timestamp=event['occurred_at'],
                    request_id=event['request_id'], source_ip=event['source_ip'], service_name=scope.service)
            selected, _ = select_event({'_index': first['normalized']['index'], '_id': first['normalized']['id'], '_source': source}, scope)
            require(selected == {key: value for key, value in event.items() if key != 'observations'}, 'triage_event_mismatch')
            events.append(dict(selected, observations=observations))
    require(len(events) <= scope.max_events and len(seen_observations) <= scope.max_events, 'triage_capacity_limit')
    alerts, seen_alerts = [], set()
    for link in snapshot['alert_links']:
        require(isinstance(link, dict) and isinstance(link.get('alert'), dict), 'triage_alert_invalid')
        ref = link['alert'];key = encode(ref)
        require(key not in seen_alerts, 'triage_duplicate_alert')
        seen_alerts.add(key)
        source = {'@timestamp': link.get('occurred_at'), 'organization': {'id': scope.organization},
                  'rule': {'id': link.get('rule_id')}, 'cloud_soc': {'severity': link.get('rule_severity'),
                  'risk_score': link.get('risk_score'), 'risk_level': link.get('risk_level'),
                  'provenance': {'evidence': link.get('evidence')}}}
        alerts.append(select_alert({'_index': ref.get('index'), '_id': ref.get('id'), '_source': source}, scope))
    require(sum(len(alert['evidence']) for alert in alerts) <= scope.max_events, 'triage_capacity_limit')
    rebuilt = correlate(scope, events, alerts)
    require(rebuilt == {key: value for key, value in snapshot.items() if key != 'revision_order'}, 'triage_revision_invalid')
    return rebuilt


def event_list(bundles):
    return list({event['key']: event for bundle in bundles for event in bundle['events']}.values())


def independent(bundles):
    """Observed HTTP requests, not a count of three log streams or attacker certainty."""
    return {event['key'] for bundle in bundles if bundle['state'] not in ('ambiguous', 'unlinked')
            for event in bundle['events'] if event['stream'] == 'web'}


def actor(bundles):
    values = {(event['metadata'].get('account_id'), event['metadata'].get('account_key_id'), event['source_ip'])
              for event in event_list(bundles) if event['stream'] == 'app' and
              event['metadata'].get('authorization_reason') == 'not_owner'}
    if len(values) != 1:
        return None
    value = next(iter(values))
    return event_fingerprint(value) if value[0] is not None else None


def references(bundles, link):
    values = {}
    for event in event_list(bundles):
        for observation in event['observations']:
            selected = {key: observation[key] for key in ('normalized', 'raw', 'event_hash')}
            values[encode(selected)] = dict(selected, event_id=event['event_id'],
                                           ingested_at=observation['ingested_at'], verification='correlated_metadata')
    if link:
        unresolved = {encode(item['reference']) for item in link['unresolved']}
        for ref in link['evidence']:
            key = encode(ref)
            values.setdefault(key, dict(ref, event_id=None, ingested_at=None))
            values[key]['verification'] = 'unresolved' if key in unresolved else 'matched_normalized_hash'
    return [values[key] for key in sorted(values)]


def describe(scope, bundles, link, context, policy, frame):
    events = event_list(bundles)
    base = link['risk_score'] if link else 0
    factors = [{'code': 'existing_detection_risk' if link else 'no_detection_alert', 'points': base}]
    independent_count = len(independent(bundles))
    repeat_keys, repeat_alerts = set(), []
    who = actor(bundles)
    if link and link['rule_id'] == 'WEB-ACCESS-01' and who is not None and link['state'] == 'complete':
        for candidate, neighbors in context:
            age = parse_time(link['occurred_at']) - parse_time(candidate['occurred_at'])
            if (candidate['rule_id'] == 'WEB-ACCESS-01' and candidate['state'] == 'complete' and
                    timedelta(0) <= age <= timedelta(seconds=policy.repetition_window_seconds) and actor(neighbors) == who):
                keys = independent(neighbors)
                if keys:
                    repeat_keys.update(keys);repeat_alerts.append(candidate['alert'])
    bonus = min(policy.max_repetition_bonus, (len(repeat_keys) - 1) * policy.repeated_request_points
                ) if len(repeat_keys) >= policy.repeated_request_threshold else 0
    if bonus:
        factors.append({'code': 'repeated_independent_application_denials', 'points': bonus,
                        'request_count': len(repeat_keys), 'alert_references': sorted(repeat_alerts, key=encode)})
    if link and link['rule_id'] == 'WEB-AUTH-01':
        factors.append({'code': 'authentication_sequence_already_in_base_risk', 'points': 0})
    factors.append({'code': 'additional_streams_change_confidence_not_risk', 'points': 0})
    uncertainties = {'request_id_not_origin_authentication', 'application_id_may_be_spoofed',
                     'observed_ip_may_be_proxy', 'correlation_not_compromise_confirmation',
                     'raw_contents_not_reverified_by_triage'}
    for bundle in bundles:
        uncertainties.update(bundle['uncertainties'])
    if link and link['unresolved']:
        uncertainties.add('evidence_missing_or_integrity_unverified')
    if any(bundle['missing'] for bundle in bundles) or not bundles:
        uncertainties.add('missing_streams')
    if any(bundle['state'] == 'ambiguous' for bundle in bundles):
        uncertainties.add('ambiguous_request_id')
    for event in events:
        for obs in event['observations']:
            delay = (parse_time(obs['ingested_at']) - parse_time(event['occurred_at'])).total_seconds()
            if delay > policy.late_evidence_seconds:
                uncertainties.add('delayed_evidence')
            if delay < 0:
                uncertainties.add('receipt_precedes_event_clock_uncertainty')
    integrity = link is None or link['state'] == 'complete'
    complete = bool(bundles) and all(bundle['state'] == 'complete' for bundle in bundles) and integrity
    confidence = 'corroborated_metadata' if complete else 'limited' if integrity and bundles else 'unverified'
    expected_refs = {encode(ref) for ref in link['evidence']} if link else set()
    unresolved_refs = {encode(item['reference']) for item in link['unresolved']} if link else set()
    completeness = {'state': 'complete' if complete else 'missing' if not bundles else
                     'ambiguous' if any(b['state'] == 'ambiguous' for b in bundles) else 'partial',
                    'bundle_count': len(bundles), 'missing_streams':
                    sorted({kind for b in bundles for kind in b['missing']}) if bundles else ['app', 'waf', 'web'],
                    'verified_alert_references': len(expected_refs - unresolved_refs),
                    'unresolved_alert_references': len(unresolved_refs)}
    behavior = {'login_failures': 0, 'login_successes': 0, 'application_denials': 0,
                'application_denial_reasons': [],
                'http_403_causes': sorted({bundle['assessment']['http_403_cause'] for bundle in bundles
                                           if bundle['assessment']['http_403_observed']}),
                'http_403_responses': 0, 'waf_rule_matches': 0, 'waf_diagnostic_matches': 0,
                'waf_detection_only_observed': False, 'waf_block_observed': None,
                'origin_authenticated': False, 'compromise_confirmed': False}
    for event in events:
        meta = event['metadata']
        if event['stream'] == 'app':
            if meta['action'] == 'login':
                behavior['login_failures' if meta['outcome'] == 'failure' else 'login_successes'] += 1
            elif meta['outcome'] == 'failure' and meta.get('authorization_reason') in ('not_owner', 'admin_required', 'unauthenticated'):
                behavior['application_denials'] += 1
                behavior['application_denial_reasons'].append(meta['authorization_reason'])
        elif event['stream'] == 'web':
            behavior['http_403_responses'] += int(meta['status_code'] == 403)
        else:
            behavior['waf_detection_only_observed'] = True;behavior['waf_block_observed'] = False
            behavior['waf_rule_matches'] += sum(not rule['diagnostic'] for rule in meta['rules'])
            behavior['waf_diagnostic_matches'] += sum(rule['diagnostic'] for rule in meta['rules'])
    behavior['application_denial_reasons'] = sorted(set(behavior['application_denial_reasons']))
    score = min(100, base + bonus)
    stable = ['alert', link['alert']] if link else ['observation', sorted(event['key'] for event in events)]
    return {'id': event_fingerprint([VERSION, scope.identity, stable]), 'scope': scope.identity,
            'triage_score': score, 'triage_priority': policy.priority(score),
            'base_risk_score': base if link else None, 'review_kind': 'alert' if link else 'unalerted_observation',
            'original_severity': link['rule_severity'] if link else None,
            'original_risk_level': link['risk_level'] if link else None,
            'rule_ids': [link['rule_id']] if link else [],
            'evidence_confidence': confidence, 'evidence_completeness': completeness,
            'contributing_factors': factors, 'uncertainty_factors': sorted(uncertainties),
            'linked_alert_ids': [link['alert']] if link else [],
            'linked_request_ids': sorted({b['request_id'] for b in bundles if b['request_id'] is not None}),
            'linked_request_bundle_ids': sorted(b['id'] for b in bundles),
            'independent_request_count': independent_count, 'repeated_independent_request_count': len(repeat_keys),
            'independent_request_count_basis': 'verified_web_observations_lower_bound',
            'evidence_references': references(bundles, link), 'behavior': behavior,
            'occurred_at': link['occurred_at'] if link else iso(min(parse_time(event['occurred_at']) for event in events)),
            'range': frame, 'explanation':
            f'{link["rule_id"] if link else "미경보 관측"}: '
            f'{"기존 위험도 " + str(base) + "점" if link else "기존 탐지 위험도 없음"}에 '
            f'독립 요청 반복 가산 {bonus}점을 적용해 조사 우선순위 {score}점으로 계산했습니다. '
            f'관측 독립 요청 {independent_count}건, 연결 묶음 {len(bundles)}개, '
            f'미검증 경보 참조 {completeness["unresolved_alert_references"]}건입니다. '
            '증거 신뢰도는 공격 성공 확률이 아닙니다. DetectionOnly는 차단이 아니며 앱 권한 거부·403만으로 '
            'WAF 차단이나 침해를 확정하지 않습니다. 로그인 성공·요청 ID·관측 IP는 계정 탈취나 출처 인증의 증거가 아닙니다. '
            '지연 증거가 추가되면 신뢰도·연결·반복 가산을 다시 계산합니다.'}


def evaluate(snapshot, scope, start, end, policy=None):
    policy = policy or Policy()
    frame = time_range(start, end, policy)
    data = validate_snapshot(snapshot, scope)
    first, last = parse_time(frame['start']), parse_time(frame['end'])
    bundles = {b['id']: b for b in data['requests']}
    context = [(link, [bundles[key] for key in link['request_bundle_ids']]) for link in data['alert_links']]
    items, covered = [], {key for link in data['alert_links'] for key in link['request_bundle_ids']}
    for link, linked in context:
        if first <= parse_time(link['occurred_at']) < last:
            items.append(describe(scope, linked, link, context, policy, frame))
    for key, bundle in bundles.items():
        if key not in covered and any(first <= parse_time(event['occurred_at']) < last for event in bundle['events']):
            items.append(describe(scope, [bundle], None, context, policy, frame))
    items.sort(key=lambda item: (-item['triage_score'], parse_time(item['occurred_at']), item['id']))
    for item in items:
        item['correlation_revision'] = snapshot['revision']
    return {'schema_version': 1, 'version': VERSION, 'scope': scope.identity, 'range': frame,
            'correlation_revision': snapshot['revision'], 'revision_order': dict(snapshot['revision_order']),
            'policy_id': policy.identity, 'items': items}
