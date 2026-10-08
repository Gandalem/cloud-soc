"""Failure-to-success sequence, scoped by organization/host/account/source IP."""
from copy import deepcopy
from datetime import timedelta
import json
from cloud_soc.detection.engine import (build_group_key, event_matches_rule, event_fingerprint,
    parse_event_timestamp, get_field_value, event_evidence, rule_revision)


def detect_sequence(events, rule, runtime):
    result = []
    fields = list(dict.fromkeys(['organization.id', *rule['group_by']]))
    seconds = rule['time_window']['seconds']
    version = rule_revision(rule)
    seen = set()
    for event in sorted(events, key=lambda e: (parse_event_timestamp(e), event_fingerprint(e))):
        if not event_matches_rule(event, rule):
            continue
        key = build_group_key(event, fields)
        if key is None or any(get_field_value(event, f) in (None, '') for f in fields):
            continue
        fingerprint = event_fingerprint(event)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        stamp = parse_event_timestamp(event)
        state = runtime.setdefault(json.dumps(key), {'failures': []})
        failures = [e for e in state['failures'] if parse_event_timestamp(e) >= stamp - timedelta(seconds=seconds)]
        outcome = get_field_value(event, 'event.outcome')
        if outcome == 'failure':
            if fingerprint not in {event_fingerprint(item) for item in failures}:
                failures.append(deepcopy(event))
            state['failures'] = failures
            continue
        # Same-timestamp ordering cannot establish a preceding failure.
        earlier = [e for e in failures if parse_event_timestamp(e) < stamp]
        if outcome == 'success' and len(earlier) >= rule['threshold']['count']:
            evidence = [event_evidence(e) for e in earlier + [event]]
            result.append({'rule_id': rule['id'], 'rule_name': rule['name'], 'severity': rule.get('severity', 'high'),
                'group': dict(zip(fields, key)), 'organization_id': get_field_value(event, 'organization.id'),
                'rule_version': version, 'rule_snapshot': deepcopy(rule), 'engine_version': 'failure-success-v2',
                'event_count': len(earlier) + 1, 'threshold': rule['threshold']['count'],
                'time_window_seconds': seconds, 'window_start': earlier[0]['@timestamp'], 'window_end': stamp.isoformat(),
                'alert': rule.get('alert', {}), 'mitre': rule.get('mitre', {}), 'evidence': evidence,
                'evidence_status': 'complete' if all(e['complete'] for e in evidence) else 'incomplete_legacy'})
        if outcome == 'success':
            state['failures'] = []
    return result
