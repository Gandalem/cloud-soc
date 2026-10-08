"""Offline synthetic evaluation using production projection, normalization and detection.

No cloud API calls, Elasticsearch writes or attacks. Run from repository root.
"""
import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from cloud_soc.aws.cloudtrail import project_event, timestamp
from cloud_soc.detection.engine import detect_events
from cloud_soc.detection.worker import approved_rules
from cloud_soc.pipeline.alerts import build_security_alert, make_alert_id
from cloud_soc.processing.contract import normalize, NORMALIZED


def raw_event(action, provider, request, number, failure=False):
    template = json.loads((ROOT / 'tests/fixtures/cloudtrail_management.json').read_text())['events'][1]
    value = deepcopy(template)
    value.update(eventName=action, eventSource=provider, requestParameters=request,
                 eventID=f'11111111-2222-3333-4444-{number:012d}')
    if failure:
        value['errorCode'] = 'AccessDenied'
    return value


def project(value):
    envelope = {'EventId': value['eventID'], 'EventTime': timestamp(value['eventTime']),
                'EventName': value['eventName'], 'EventSource': value['eventSource'],
                'CloudTrailEvent': json.dumps(value)}
    index, identifier, source = project_event(envelope, account=value['recipientAccountId'],
                                              region=value['awsRegion'], organization='portfolio-fixture')
    source['event']['ingested'] = value['eventTime']
    return {'_index': index, '_id': identifier, '_source': source}


def normalized(hit):
    key, status, row = normalize(hit, '2026-10-05T00:00:00Z')
    if status['status'] != 'normalized':
        raise ValueError('Fixture failed normalization')
    row['_cloud_soc_meta'] = {'index': NORMALIZED, 'document_id': key}
    return row


def ingress(port=22, cidr='0.0.0.0/0', protocol='tcp'):
    ranges, address = ('ipv6Ranges', 'cidrIpv6') if ':' in cidr else ('ipRanges', 'cidrIp')
    return {'ipPermissions': {'items': [{'ipProtocol': protocol, 'fromPort': port, 'toPort': port,
                                         ranges: {'items': [{address: cidr}]}}]}}


def cases():
    # Ground truth is whether the declared rule condition should match, not maliciousness.
    specifications = [
        ('AWS-IAM-001', 'admin policy', True, 'AttachUserPolicy', 'iam.amazonaws.com', {'policyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'}, False),
        ('AWS-IAM-001', 'power user role', True, 'AttachRolePolicy', 'iam.amazonaws.com', {'policyArn': 'arn:aws:iam::aws:policy/PowerUserAccess'}, False),
        ('AWS-IAM-001', 'read only', False, 'AttachUserPolicy', 'iam.amazonaws.com', {'policyArn': 'arn:aws:iam::aws:policy/ReadOnlyAccess'}, False),
        ('AWS-IAM-001', 'denied admin', False, 'AttachUserPolicy', 'iam.amazonaws.com', {'policyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'}, True),
        ('AWS-IAM-001', 'missing policy', False, 'AttachUserPolicy', 'iam.amazonaws.com', {}, False),
        ('AWS-AUDIT-001', 'stop logging', True, 'StopLogging', 'cloudtrail.amazonaws.com', {'name': 'fixture-trail'}, False),
        ('AWS-AUDIT-001', 'delete trail', True, 'DeleteTrail', 'cloudtrail.amazonaws.com', {'name': 'fixture-trail'}, False),
        ('AWS-AUDIT-001', 'start logging', False, 'StartLogging', 'cloudtrail.amazonaws.com', {}, False),
        ('AWS-AUDIT-001', 'denied stop', False, 'StopLogging', 'cloudtrail.amazonaws.com', {}, True),
        ('AWS-AUDIT-001', 'wrong provider', False, 'StopLogging', 'iam.amazonaws.com', {}, False),
        ('AWS-NETWORK-001', 'public ssh', True, 'AuthorizeSecurityGroupIngress', 'ec2.amazonaws.com', ingress(), False),
        ('AWS-NETWORK-001', 'public ipv6 rdp', True, 'AuthorizeSecurityGroupIngress', 'ec2.amazonaws.com', ingress(3389, '::/0'), False),
        ('AWS-NETWORK-001', 'all protocols', True, 'AuthorizeSecurityGroupIngress', 'ec2.amazonaws.com', ingress(protocol='-1'), False),
        ('AWS-NETWORK-001', 'private ssh', False, 'AuthorizeSecurityGroupIngress', 'ec2.amazonaws.com', ingress(cidr='10.0.0.0/8'), False),
        ('AWS-NETWORK-001', 'public web', False, 'AuthorizeSecurityGroupIngress', 'ec2.amazonaws.com', ingress(port=443), False),
        ('AWS-NETWORK-001', 'denied public ssh', False, 'AuthorizeSecurityGroupIngress', 'ec2.amazonaws.com', ingress(), True),
        ('AWS-NETWORK-001', 'missing permissions', False, 'AuthorizeSecurityGroupIngress', 'ec2.amazonaws.com', {}, False),
    ]
    return [{'rule': rule, 'name': name, 'expected': expected,
             'event': raw_event(action, provider, request, n, failure)}
            for n, (rule, name, expected, action, provider, request, failure) in enumerate(specifications, 1)]


def evaluate():
    rules = approved_rules(include_cloud=True, include_sequence=True)
    samples = cases()
    rows, metrics = [], {}
    for case in samples:
        matches = detect_events([normalized(project(case['event']))], rules)
        found = {match['rule_id'] for match in matches}
        actual = case['rule'] in found
        outcome = ('TP' if actual else 'FN') if case['expected'] else ('FP' if actual else 'TN')
        counts = metrics.setdefault(case['rule'], dict(TP=0, FP=0, FN=0, TN=0))
        counts[outcome] += 1
        rows.append({'rule': case['rule'], 'case': case['name'], 'expected': case['expected'],
                     'actual': actual, 'outcome': outcome, 'unexpected_rules': sorted(found - {case['rule']})})
    for counts in metrics.values():
        counts['precision'] = counts['TP'] / (counts['TP'] + counts['FP']) if counts['TP'] + counts['FP'] else None
        counts['recall'] = counts['TP'] / (counts['TP'] + counts['FN']) if counts['TP'] + counts['FN'] else None
    return {'scope': 'synthetic rule-condition conformance; not production attack accuracy',
            'dataset_sha256': hashlib.sha256(json.dumps(samples, sort_keys=True).encode()).hexdigest(),
            'cases': rows, 'metrics': metrics}


def demo():
    selected = [case for case in cases() if case['name'] in ('admin policy', 'stop logging', 'public ssh')]
    rules = approved_rules(include_cloud=True)
    result = []
    for case in selected:
        hit = project(case['event'])
        row = normalized(hit)
        matches = detect_events([row], rules)
        if [m['rule_id'] for m in matches] != [case['rule']]:
            raise ValueError('Demo does not produce expected rule')
        alert = build_security_alert(matches[0])
        result.append({'scenario': case['name'], 'raw': hit, 'normalized': row,
                       'alert_id': make_alert_id(matches[0]), 'alert': alert})
    return result


def benchmark(count, repeats):
    rules = approved_rules(include_cloud=True)
    # Unique raw event IDs prevent replay deduplication from inflating throughput.
    inputs = [raw_event('StopLogging', 'cloudtrail.amazonaws.com', {'name': 'fixture-trail'}, n)
              for n in range(1, count + 1)]
    durations = {key: [] for key in ('projection', 'normalization', 'detection', 'alert_build')}
    detected = 0
    for _ in range(repeats + 1):
        start = time.perf_counter()
        hits = [project(value) for value in inputs]
        projected = time.perf_counter()
        rows = [normalized(hit) for hit in hits]
        normal = time.perf_counter()
        matches = detect_events(rows, rules)
        detected = time.perf_counter()
        alerts = [build_security_alert(match) for match in matches]
        finished = time.perf_counter()
        if len(alerts) != count:
            raise ValueError('Benchmark lost expected detections')
        if _:
            for key, duration in zip(durations, (projected-start, normal-projected, detected-normal, finished-detected)):
                durations[key].append(duration)
    medians = {key: statistics.median(values) for key, values in durations.items()}
    total = statistics.median([sum(values) for values in zip(*durations.values())])
    return {'scope': 'in-process AWS StopLogging positive events; no network/ES/indexing',
            'events': count, 'repeats': repeats, 'warmups': 1, 'python': platform.python_version(),
            'platform': platform.platform(), 'processor': platform.processor(),
            'seconds_samples': durations, 'median_seconds': medians,
            'total_median_seconds': total, 'events_per_second': count / total}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--events', type=int, default=10000)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--output', type=Path, default=Path('docs/portfolio/evaluation.json'))
    args = parser.parse_args()
    if not 1 <= args.events <= 100000 or not 1 <= args.repeats <= 10:
        parser.error('events: 1..100000; repeats: 1..10')
    quality = evaluate()
    result = {'created_at': datetime.now(timezone.utc).isoformat(), 'quality': quality,
              'benchmark': benchmark(args.events, args.repeats), 'demo': demo()}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps({'quality': quality['metrics'], 'benchmark': result['benchmark']}, indent=2))
    if any(row['outcome'] in ('FP', 'FN') or row['unexpected_rules'] for row in quality['cases']):
        raise SystemExit('Synthetic evaluation failed')


if __name__ == '__main__':
    main()
