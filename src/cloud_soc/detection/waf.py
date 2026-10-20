"""WEB-WAF-01 metadata adapter for the existing threshold/sliding-window engine.

No payload matching, risk formula, network IO or separate detection engine.
The current edge contract supports DetectionOnly only, not proven WAF blocking.
"""
from copy import deepcopy

from cloud_soc.detection.engine import (
    _detect_threshold, build_group_key, event_evidence, event_fingerprint,
    event_matches_rule, get_field_value, parse_event_timestamp,
)
from cloud_soc.parsers.security_mall_edge import EdgeError, identifier, validate

# Verified in CRS v3.3.5 REQUEST-942-APPLICATION-ATTACK-SQLI.conf.
# Deliberately limited initial coverage; exclude 942011/942012 control rules.
SQLI_IDS = frozenset({'942100', '942140', '942160', '942170', '942190', '942220', '942230', '942240'})
GROUP = ['organization.id', 'service.name', 'host.id', 'source.ip']


def validate_waf_rule(rule):
    spec = rule.get('waf_sqli')
    if ((rule.get('id') != 'WEB-WAF-01' and rule.get('metadata_profile') != 'security_mall_edge_v1') or rule.get('type') != 'threshold'
            or rule.get('group_by') != GROUP or rule.get('threshold') != {'count': 1}
            or rule.get('cooldown') != {'seconds': 0}
            or not 1 <= rule['time_window']['seconds'] <= 300
            or not isinstance(spec, dict) or set(spec) != {'crs_version', 'rule_ids', 'repeat_requests'}
            or spec['crs_version'] != '3.3.5' or not isinstance(spec['rule_ids'], list)
            or not spec['rule_ids'] or any(not isinstance(v, str) or v not in SQLI_IDS for v in spec['rule_ids'])
            or len(set(spec['rule_ids'])) != len(spec['rule_ids'])
            or type(spec['repeat_requests']) is not int or not 2 <= spec['repeat_requests'] <= 100):
        raise ValueError('Invalid WEB-WAF-01 metadata policy')


def matches_waf(event, rule):
    """Validate the existing normalized contract before consulting SQLi IDs."""
    if (not event_matches_rule(event, rule)
            or get_field_value(event, 'cloud_soc.detail.adapter') != 'security_mall_edge_v1'
            or get_field_value(event, 'event.action') != 'waf_rule_match'
            or build_group_key(event, GROUP) is None):
        return False
    body = get_field_value(event, 'cloud_soc.security_mall_edge')
    try:
        validate(body)  # Strict allowlist; rejects raw strings, malformed IDs and blocked=True.
        if (body['stream'] != 'waf' or body['request_id'] != get_field_value(event, 'http.request.id')
                or body['service_name'] != get_field_value(event, 'service.name')
                or body['source_ip'] != get_field_value(event, 'source.ip')
                or body != get_field_value(event, 'cloud_soc.detail.fields')
                or parse_event_timestamp({'@timestamp': body['timestamp']}) != parse_event_timestamp(event)
                or get_field_value(event, 'event.id') != identifier(
                    body, get_field_value(event, 'organization.id'), get_field_value(event, 'host.id'))):
            return False
    except (EdgeError, ValueError, TypeError):
        return False
    return any(item['diagnostic'] is False and item['id'] in rule['waf_sqli']['rule_ids'] for item in body['rules'])


def request_identity(event):
    # Host+service is the single configured site boundary of edge contract v1.
    return event_fingerprint({p: get_field_value(event, p) for p in [*GROUP, 'http.request.id']})


def detect_waf(events, rule, runtime=None):
    validate_waf_rule(rule)
    selected = [e for e in events if matches_waf(e, rule)]
    if any(not event_evidence(e)['complete'] for e in selected):
        raise ValueError('WEB-WAF-01 requires complete evidence')
    prior = [e for state in (runtime or {}).values() for e in state.get('window', [])]
    # Replayed observations can precede the current finalized frontier. Drop
    # only the already retained request within its bounded window, not new IDs.
    prior_requests = {}
    for event in prior:
        prior_requests.setdefault(request_identity(event), []).append(parse_event_timestamp(event))
    selected = [e for e in selected if not any(
        abs((parse_event_timestamp(e) - stamp).total_seconds()) <= rule['time_window']['seconds']
        for stamp in prior_requests.get(request_identity(e), []))]
    by_hash = {event_fingerprint(e): e for e in [*prior, *selected]}
    detections = _detect_threshold(selected, rule, runtime=runtime, _observation=request_identity)
    for detection in detections:
        rows = [by_hash[ref['event_hash']] for ref in detection['evidence']]
        count = len(rows)
        repeated = count >= rule['waf_sqli']['repeat_requests']
        matched = [item for e in rows for item in get_field_value(e, 'cloud_soc.security_mall_edge.rules')
                   if not item['diagnostic'] and item['id'] in rule['waf_sqli']['rule_ids']]
        detection['assessment'] = {
            'type': 'attack_indicator', 'reason': 'scoped_crs_sqli_metadata',
            'pattern': 'repeated_suspected_requests' if repeated else
                       'single_suspected_request' if count == 1 else 'multiple_suspected_requests',
            'request_count': count, 'repeat_threshold': rule['waf_sqli']['repeat_requests'],
            'request_ids': sorted({get_field_value(e, 'http.request.id') for e in rows}),
            'event_ids': [get_field_value(e, 'event.id') for e in rows],
            'matched_rule_ids': sorted({item['id'] for item in matched}),
            'declared_actions': sorted({item['action'] for item in matched}),
            'engine_mode': 'DetectionOnly', 'blocked': False, 'attack_success': 'not_established',
            'limitations': ['metadata_not_payload_analysis', 'request_id_not_authenticated',
                            'observed_peer_not_verified_client', 'host_scopes_single_configured_site'],
        }
        # One immutable alert per newly observed request. Replays/normalization
        # revisions cannot create another alert for the same triggering request.
        detection['identity_anchor'] = event_fingerprint({
            'request': request_identity(rows[-1]), 'timestamp': detection['window_end']})
        detection['alert'] = deepcopy(detection['alert'])
        label = '반복 기준 충족' if repeated else '단일 요청' if count == 1 else '반복 기준 미만'
        detection['alert']['message'] += f' 관측 독립 요청 {count}건 ({label}).'
    return detections
