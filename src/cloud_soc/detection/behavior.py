"""Opt-in metadata correlations; no payload parsing, baseline or attack-success claims."""
from copy import deepcopy
from collections import Counter, deque
from datetime import timedelta
import json
import re

from cloud_soc.detection.engine import (
    build_group_key, condition_matches, event_evidence, event_fingerprint,
    get_field_value, parse_event_timestamp, rule_revision,
)
from cloud_soc.privacy import REDACTED

KINDS = ('ordered', 'diversity')
FIELD = re.compile(r'[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)+')


def scalar(value):
    return isinstance(value, str) and bool(value.strip()) and value != REDACTED


def conditions_status(event, conditions):
    missing = []
    for condition in conditions:
        value = get_field_value(event, condition['field'])
        if value is None and condition['operator'] != 'exists':
            missing.append(condition['field'])
        elif not condition_matches(event, condition):
            return 'not_matched', []
    return ('unknown', missing) if missing else ('matched', [])


def evaluate_behavior(event, rule):
    outcome, missing = conditions_status(event, rule['conditions'])
    if outcome != 'matched':
        return outcome, missing
    if rule['type'] == 'diversity':
        provider, action = (get_field_value(event, f) for f in ('event.provider', 'event.action'))
        if not isinstance(provider, str) or action not in rule['api_pairs'].get(provider, []):
            return 'not_matched', []
        required = [rule['distinct']['field'], 'cloud_soc.detail.fields.event_id']
    else:
        matches = [conditions_status(event, stage['conditions']) for stage in rule['stages']]
        if not any(status == 'matched' for status, _ in matches):
            missing = sorted({field for status, fields in matches if status == 'unknown' for field in fields})
            return ('unknown', missing) if missing else ('not_matched', [])
        required = []
        for stage, (status, _) in zip(rule['stages'], matches):
            if status == 'matched':
                required += stage.get('required_fields', []) + stage.get('link_fields', [])
    required += list(dict.fromkeys(['organization.id', *rule['group_by']]))
    missing = [field for field in required if not scalar(get_field_value(event, field))]
    if missing:
        return 'unknown', sorted(set(missing))
    for exception in rule.get('exclusions', []):
        stamp = parse_event_timestamp(event)
        period = exception['time_range']
        if (conditions_status(event, exception['conditions'])[0] == 'matched'
                and parse_event_timestamp({'@timestamp': period['start']}) <= stamp
                < parse_event_timestamp({'@timestamp': period['end']})):
            return 'excluded', []
    return 'matched', []


def validate_behavior(rule, validate_conditions):
    def positive(value):
        return type(value) is int and 1 <= value <= 86400

    if (not positive(rule['time_window'].get('seconds'))
            or not positive(rule['threshold'].get('count'))
            or any(not isinstance(f, str) or not FIELD.fullmatch(f) for f in rule['group_by'])
            or type(rule.get('cooldown', {}).get('seconds', 0)) is not int
            or not 0 <= rule.get('cooldown', {}).get('seconds', 0) <= 86400):
        raise ValueError('Invalid behavior bounds or grouping')
    if not isinstance(rule.get('limitations'), list) or not rule['limitations'] or any(
            not isinstance(v, str) or not v for v in rule['limitations']):
        raise ValueError('Behavior rules must declare judgment limitations')
    exceptions = rule.get('exclusions', [])
    if not isinstance(exceptions, list) or len(exceptions) > 100:
        raise ValueError('Invalid exceptions')
    for exception in exceptions:
        if not isinstance(exception, dict):
            raise ValueError('Invalid exception')
        validate_conditions(exception.get('conditions'))
        exact = {c['field'] for c in exception['conditions'] if c['operator'] == 'equals' and scalar(c['value'])}
        if not {'organization.id', *rule['group_by']} <= exact:
            raise ValueError('Exceptions must specify the complete exact scope')
        period = exception.get('time_range')
        if not isinstance(period, dict) or set(period) != {'start', 'end'}:
            raise ValueError('Exceptions require an explicit event-time interval')
        try:
            begin, end = [parse_event_timestamp({'@timestamp': period[k]}) for k in ('start', 'end')]
        except (ValueError, TypeError, OverflowError):
            raise ValueError('Invalid exception interval') from None
        if not 0 < (end - begin).total_seconds() <= 86400:
            raise ValueError('Exception intervals must be bounded to at most one day')
    if rule['type'] == 'diversity':
        distinct, pairs = rule.get('distinct'), rule.get('api_pairs')
        if (not isinstance(distinct, dict) or distinct.get('field') != 'event.action'
                or not positive(distinct.get('count')) or distinct['count'] > rule['threshold']['count']
                or not isinstance(pairs, dict) or not pairs or len(pairs) > 20
                or any(not isinstance(k, str) or not isinstance(v, list) or not v
                       or len(v) > 100 or any(not scalar(a) for a in v) for k, v in pairs.items())):
            raise ValueError('Invalid API diversity specification')
    else:
        stages = rule.get('stages')
        if not isinstance(stages, list) or not 2 <= len(stages) <= 3:
            raise ValueError('Ordered rules require two or three stages')
        for i, stage in enumerate(stages):
            if not isinstance(stage, dict) or not scalar(stage.get('name')):
                raise ValueError('Invalid stage')
            validate_conditions(stage.get('conditions'))
            if not positive(stage.get('count', 1)) or (i > 0 and stage.get('count', 1) != 1):
                raise ValueError('Only the first stage can aggregate')
            if i > 0 and (not positive(stage.get('within_seconds'))
                          or stage['within_seconds'] > rule['time_window']['seconds']):
                raise ValueError('Invalid stage time bound')
            for key in ('link_fields', 'required_fields'):
                fields = stage.get(key, [])
                if not isinstance(fields, list) or any(not isinstance(f, str) or not FIELD.fullmatch(f) for f in fields):
                    raise ValueError('Invalid stage linkage')
            if i == 0 and stage.get('link_fields'):
                raise ValueError('First stage has no preceding stage')
            for key in ('latest_only', 'reset_on_next'):
                if key in stage and type(stage[key]) is not bool:
                    raise ValueError('Invalid stage policy')
        if rule['threshold']['count'] != stages[0].get('count', 1):
            raise ValueError('Threshold must describe the first-stage count')


def observation_id(event):
    if get_field_value(event, 'event.dataset') == 'aws.cloudtrail':
        return event_fingerprint({f: get_field_value(event, f) for f in (
            'organization.id', 'cloud.account.id', 'cloud_soc.detail.fields.event_id')})
    return event_fingerprint({'organization': get_field_value(event, 'organization.id'),
                              'raw': get_field_value(event, 'cloud_soc.provenance.raw')})


def ordered_chain(pool, rule, terminal):
    stages = rule['stages']

    def preceding(position, following):
        stage, next_stage = stages[position], stages[position + 1]
        upper = parse_event_timestamp(following)
        lower = upper - timedelta(seconds=next_stage['within_seconds'])
        candidates = [e for e in pool if lower <= parse_event_timestamp(e) < upper
                      and conditions_status(e, stage['conditions'])[0] == 'matched'
                      and all(scalar(get_field_value(e, f)) and
                              get_field_value(e, f) == get_field_value(following, f)
                              for f in next_stage.get('link_fields', []))]
        if position == 0:
            if stage.get('reset_on_next'):
                resets = [parse_event_timestamp(e) for e in pool if parse_event_timestamp(e) < upper
                          and conditions_status(e, next_stage['conditions'])[0] == 'matched'
                          and all(get_field_value(e, f) == get_field_value(following, f)
                                  for f in next_stage.get('link_fields', []))]
                if resets:
                    candidates = [e for e in candidates if parse_event_timestamp(e) > max(resets)]
            count = stage.get('count', 1)
            return [candidates[-count:]] if len(candidates) >= count else None
        for candidate in reversed(candidates):
            chain = preceding(position - 1, candidate)
            if chain:
                return [*chain, [candidate]]
            if stage.get('latest_only'):
                break
        return None

    chain = preceding(len(stages) - 2, terminal)
    return [*chain, [terminal]] if chain else None


def detect_behavior(events, rule, runtime=None):
    runtime = runtime if runtime is not None else {}
    result = []
    fields = list(dict.fromkeys(['organization.id', *rule['group_by']]))
    groups = {}
    for event in events:
        if evaluate_behavior(event, rule)[0] != 'matched':
            continue
        if not event_evidence(event)['complete']:
            raise ValueError('Behavior detection requires exact evidence')
        key = build_group_key(event, fields)
        groups.setdefault(key, []).append(event)
    for key, group_events in groups.items():
        state = runtime.setdefault(json.dumps(key), {'window': [], 'last_alert': None})
        window = deque((parse_event_timestamp(e), observation_id(e), e) for e in state['window'])
        seen = {identifier for _, identifier, _ in window}
        diversity = Counter(get_field_value(e, rule['distinct']['field']) for _, _, e in window) if rule['type'] == 'diversity' else Counter()
        last_alert = parse_event_timestamp({'@timestamp': state['last_alert']}) if state['last_alert'] else None
        for event in sorted(group_events, key=lambda e: (parse_event_timestamp(e), observation_id(e), event_fingerprint(e))):
            stamp, identifier = parse_event_timestamp(event), observation_id(event)
            if identifier in seen:
                continue
            if window and stamp < window[-1][0]:
                raise ValueError('Behavior runtime requires finalized event-time order')
            lower = stamp - timedelta(seconds=rule['time_window']['seconds'])
            while window and window[0][0] < lower:
                _, old_id, old_event = window.popleft()
                seen.remove(old_id)
                if rule['type'] == 'diversity':
                    action = get_field_value(old_event, rule['distinct']['field'])
                    diversity[action] -= 1
                    if not diversity[action]:
                        del diversity[action]
            window.append((stamp, identifier, deepcopy(event)))
            seen.add(identifier)
            if rule['type'] == 'diversity':
                diversity[get_field_value(event, rule['distinct']['field'])] += 1
            if last_alert and (stamp - last_alert).total_seconds() < rule.get('cooldown', {}).get('seconds', 0):
                continue
            assessment = {'type': rule.get('detection_type', 'attack_indicator'),
                          'limitations': deepcopy(rule['limitations']), 'attack_success': 'not_established'}
            if rule['type'] == 'diversity':
                if len(window) < rule['threshold']['count'] or len(diversity) < rule['distinct']['count']:
                    continue
                evidence_events = [e for _, _, e in window]
                assessment.update(reason='call_count_and_api_diversity', observed_count=len(evidence_events),
                                  distinct_count=len(diversity), distinct_values=sorted(diversity))
            else:
                if conditions_status(event, rule['stages'][-1]['conditions'])[0] != 'matched':
                    continue
                chain = ordered_chain([e for _, _, e in window], rule, event)
                if not chain:
                    continue
                evidence_events = [e for stage_events in chain for e in stage_events]
                assessment.update(reason='ordered_metadata_stages', stages=[
                    {'name': stage['name'], 'count': len(rows), 'evidence_offsets': list(range(
                        sum(len(r) for r in chain[:i]), sum(len(r) for r in chain[:i + 1])))}
                    for i, (stage, rows) in enumerate(zip(rule['stages'], chain))])
            evidence = [event_evidence(e) for e in evidence_events]
            result.append({'rule_id': rule['id'], 'rule_name': rule['name'], 'severity': rule.get('severity', 'high'),
                           'group': dict(zip(fields, key)), 'organization_id': get_field_value(event, 'organization.id'),
                           'rule_version': rule_revision(rule), 'rule_snapshot': deepcopy(rule),
                           'engine_version': 'behavior-v1', 'event_count': len(evidence_events),
                           'threshold': rule['threshold']['count'], 'time_window_seconds': rule['time_window']['seconds'],
                           'window_start': evidence_events[0]['@timestamp'], 'window_end': stamp.isoformat(),
                           'alert': deepcopy(rule.get('alert', {})), 'mitre': deepcopy(rule.get('mitre', {})),
                           'evidence': evidence, 'evidence_status': 'complete', 'assessment': assessment})
            last_alert = stamp
        state.update(window=[e for _, _, e in window], last_alert=last_alert.isoformat() if last_alert else None)
    return result
