"""Opt-in metadata cardinality, with explicit identities and incomplete-input reporting."""
from collections import Counter, deque
from copy import deepcopy
from datetime import timedelta
import json
from ipaddress import ip_address

from cloud_soc.detection.engine import (build_group_key, event_evidence, event_fingerprint,
    get_field_value, parse_event_timestamp, rule_revision, ssh_collection_mirror)
from cloud_soc.detection.behavior import conditions_status, scalar
from cloud_soc.web.scope import valid_site_id

FIELDS = {'organization.id', 'source.ip', 'destination.ip', 'destination.port', 'host.id', 'service.id', 'http.request.id', 'user.name',
          'user.id', 'cloud.account.id', 'event.action', 'network.transport',
          'cloud_soc.detail.fields.logon_type', 'cloud_soc.detail.fields.flow_id',
          'cloud_soc.detail.fields.event_id', 'cloud_soc.detail.fields.identity_arn'}
NUMBERS = {'destination.port': (1, 65535), 'cloud_soc.detail.fields.logon_type': (0, 255)}


def valid_value(field, value):
    if field == 'service.id':
        return valid_site_id(value)
    if field in NUMBERS:
        low, high = NUMBERS[field]
        return type(value) is int and low <= value <= high
    if field in ('source.ip', 'destination.ip'):
        try:
            return isinstance(value, str) and str(ip_address(value)) == value
        except ValueError:
            return False
    return scalar(value)


def validate_pattern(rule):
    distinct = rule.get('distinct', {})
    required, dedup = rule.get('required_fields'), rule.get('dedup_fields')
    cooldown = rule.get('cooldown', {'seconds': 0})
    if (not isinstance(distinct, dict) or set(distinct) != {'field', 'count'}
            or not isinstance(distinct['field'], str) or distinct['field'] not in FIELDS
            or type(distinct['count']) is not int
            or type(rule['threshold']['count']) is not int or not 1 <= rule['threshold']['count'] <= 10000
            or not 1 <= distinct['count'] <= rule['threshold']['count']
            or type(rule['time_window']['seconds']) is not int or not 1 <= rule['time_window']['seconds'] <= 3600
            or not isinstance(cooldown, dict) or set(cooldown) != {'seconds'}
            or type(cooldown['seconds']) is not int or not 0 <= cooldown['seconds'] <= 3600
            or any(not isinstance(f, str) or f not in FIELDS for f in rule['group_by'])
            or not isinstance(required, list) or not required or any(not isinstance(f, str) or f not in FIELDS for f in required)
            or not isinstance(dedup, list) or any(not isinstance(f, str) or f not in FIELDS for f in dedup)
            or not isinstance(rule.get('limitations'), list) or not rule['limitations']):
        raise ValueError('Invalid metadata cardinality specification')
    if not {'organization.id', *rule['group_by'], distinct['field'], *dedup} <= set(required):
        raise ValueError('Required fields must include group, diversity and duplicate identities')


def evaluate_pattern(event, rule):
    outcome, missing = conditions_status(event, rule['conditions'])
    if outcome != 'matched':
        return outcome, missing
    missing = [field for field in rule['required_fields'] if not valid_value(field, get_field_value(event, field))]
    if missing:
        return 'unknown', missing
    if rule['id'] == 'WEB-SITE-WAF-001':
        from cloud_soc.web.modsecurity import validate
        try:
            values = validate(event)
            if values != get_field_value(event, 'cloud_soc.detail.fields'):
                raise ValueError()
        except ValueError:
            return 'unknown', ['waf']
    return 'matched', []


def observation(event, rule):
    fields = rule['dedup_fields']
    return event_fingerprint({field: get_field_value(event, field) for field in fields}) if fields else event_fingerprint({
        'organization': get_field_value(event, 'organization.id'), 'raw': get_field_value(event, 'cloud_soc.provenance.raw')})


def detect_pattern(events, rule, runtime=None):
    runtime = runtime if runtime is not None else {}
    groups, result = {}, []
    fields = list(dict.fromkeys(['organization.id', *rule['group_by']]))
    for event in events:
        if evaluate_pattern(event, rule)[0] != 'matched':
            continue
        if not event_evidence(event)['complete']:
            raise ValueError('Metadata patterns require complete evidence')
        key = build_group_key(event, fields)
        groups.setdefault(key, []).append(event)
    for key, rows in groups.items():
        state = runtime.setdefault(json.dumps(key), {'window': [], 'last_alert': None})
        pool = deque(deepcopy(state['window']))
        identities = {observation(e, rule) for e in pool}
        values = Counter(get_field_value(e, rule['distinct']['field']) for e in pool)
        last = parse_event_timestamp({'@timestamp': state['last_alert']}) if state['last_alert'] else None
        for event in sorted(rows, key=lambda e: (parse_event_timestamp(e), observation(e, rule), event_fingerprint(e))):
            stamp = parse_event_timestamp(event)
            if pool and stamp < parse_event_timestamp(pool[-1]):
                raise ValueError('Metadata runtime requires finalized event order')
            lower = stamp - timedelta(seconds=rule['time_window']['seconds'])
            while pool and parse_event_timestamp(pool[0]) < lower:
                expired = pool.popleft()
                identities.remove(observation(expired, rule))
                value = get_field_value(expired, rule['distinct']['field'])
                values[value] -= 1
                if not values[value]:
                    del values[value]
            identifier = observation(event, rule)
            mirror = False
            if get_field_value(event, 'cloud_soc.observation.origin') in ('journald', 'rfc3339'):
                for prior in reversed(pool):
                    if (stamp - parse_event_timestamp(prior)).total_seconds() > .005:
                        break
                    if ssh_collection_mirror(prior, event):
                        mirror = True
                        break
            if identifier in identities or mirror:
                continue
            pool.append(deepcopy(event))
            identities.add(identifier)
            values[get_field_value(event, rule['distinct']['field'])] += 1
            if last and (stamp - last).total_seconds() < rule.get('cooldown', {}).get('seconds', 0):
                continue
            distinct = values.keys()
            if len(pool) < rule['threshold']['count'] or len(distinct) < rule['distinct']['count']:
                continue
            evidence = [event_evidence(e) for e in pool]
            result.append({'rule_id': rule['id'], 'rule_name': rule['name'], 'severity': rule['severity'],
                'group': dict(zip(fields, key)), 'organization_id': get_field_value(event, 'organization.id'),
                'rule_version': rule_revision(rule), 'rule_snapshot': deepcopy(rule), 'engine_version': 'metadata-cardinality-v1',
                'event_count': len(pool), 'threshold': rule['threshold']['count'], 'time_window_seconds': rule['time_window']['seconds'],
                'window_start': parse_event_timestamp(pool[0]).isoformat(), 'window_end': stamp.isoformat(),
                'alert': deepcopy(rule['alert']), 'mitre': deepcopy(rule.get('mitre', {})),
                'evidence': evidence, 'evidence_status': 'complete',
                'assessment': {'type': 'attack_indicator', 'reason': 'metadata_count_and_distinct_values',
                    'observed_count': len(pool), 'distinct_count': len(distinct),
                    'distinct_values': sorted(distinct), 'limitations': deepcopy(rule['limitations']),
                    'attack_success': 'not_established'}})
            if rule['id'] == 'WEB-SITE-WAF-001':
                result[-1]['assessment'].update(reason='site_scoped_crs_sqli_metadata', waf={
                    'engine_modes': sorted({get_field_value(e, 'waf.engine_mode') for e in pool}),
                    'interruption_states': sorted({get_field_value(e, 'waf.interruption') for e in pool}),
                    'matched_rule_ids': sorted({value for e in pool for value in get_field_value(e, 'cloud_soc.detail.fields.sqli_rule_ids')}),
                    'blocking_result': 'not_established', 'application_outcome': 'not_established'})
            last = stamp
        state.update(window=list(pool), last_alert=last.isoformat() if last else None)
    return result
