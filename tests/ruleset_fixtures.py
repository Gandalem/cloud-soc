"""Public synthetic observations, passed through the existing real adapters."""
from copy import deepcopy
from datetime import timedelta
import json
from pathlib import Path

from cloud_soc.detection.incremental import utc
from cloud_soc.oci.audit import project_event
from cloud_soc.processing.contract import normalize, NORMALIZED
from test_attack_detection import attack_one, aws, iam, audit
from test_cloud_detection import event as cloud_event, ingress
from test_metadata_patterns import ssh, windows, flow, console
from test_sequence_detection import ssh as sequence_ssh
from test_web_collection import received, event as web_event, line
from security_mall_fixtures import mall

BASE = utc('2026-10-01T00:00:00Z')


def web(number):
    source = received(web_event(line('/?password=CANARY_WEB_NEVER_TRANSMIT', status=404, seconds=number), offset=number))
    key, record, result = normalize({'_index': 'soc-host-raw-web-v1', '_id': source['event']['id'], '_source': source}, BASE.isoformat())
    assert record['status'] == 'normalized'
    result['_cloud_soc_meta'] = {'index': NORMALIZED, 'document_id': key}
    return result


def oci():
    fixture = json.loads((Path(__file__).parent / 'fixtures/oci_audit.json').read_text(encoding='utf-8'))
    value = deepcopy(fixture['events'][2])
    value['data']['response']['status'] = '200'
    index, key, source = project_event(value, tenancy=fixture['tenancy'], compartment=fixture['compartment'],
                                      region=fixture['region'], organization='fixture')
    source['event']['ingested'] = value['event_time']
    identifier, record, result = normalize({'_index': index, '_id': key, '_source': source}, BASE.isoformat())
    assert record['status'] == 'normalized'
    result['_cloud_soc_meta'] = {'index': NORMALIZED, 'document_id': identifier}
    return result


def positive(identifier):
    if identifier == 'AUTH-001':
        rows = [sequence_ssh(i) for i in range(10)]
    elif identifier == 'AUTH-SEQ-001':
        rows = [sequence_ssh(i) for i in range(5)] + [sequence_ssh(5, outcome='success')]
    elif identifier == 'WEB-ACCESS-01':
        rows = [mall(0, action='order_view')]
    elif identifier == 'WEB-AUTH-01':
        rows = [mall(i) for i in range(5)] + [mall(5, outcome='success')]
    elif identifier == 'AUTH-SPRAY-001':
        rows = [ssh(i) for i in range(10)]
    elif identifier == 'ATTACK-01':
        rows = attack_one()
    elif identifier == 'ATTACK-02':
        rows = [aws(i) for i in range(20)]
    elif identifier == 'ATTACK-03':
        rows = [iam(), audit()]
    elif identifier == 'AWS-IAM-001':
        rows = [iam()]
    elif identifier == 'AWS-AUDIT-001':
        rows = [audit()]
    elif identifier == 'AWS-NETWORK-001':
        rows = [cloud_event('AuthorizeSecurityGroupIngress', 'ec2.amazonaws.com', ingress())]
    elif identifier == 'OCI-IAM-001':
        rows = [oci()]
    else:
        generator, count = {'WIN-AUTH-001': (windows, 10), 'WEB-404-001': (web, 20),
                            'NET-PORT-001': (flow, 15), 'AWS-CONSOLE-001': (console, 5)}[identifier]
        rows = [generator(i) for i in range(count)]
    # One consistent synthetic event/receipt timeline; no source bodies in alerts.
    for i, row in enumerate(rows):
        row['@timestamp'] = (BASE + timedelta(seconds=i)).isoformat()
        row['cloud_soc']['normalized_at'] = (BASE + timedelta(seconds=10)).isoformat()
    return rows


def delete(row, path):
    parts = path.split('.')
    for part in parts[:-1]:
        row = row.get(part, {})
    row.pop(parts[-1], None)


def assign(row, path, value):
    parts = path.split('.')
    for part in parts[:-1]:
        row = row.setdefault(part, {})
    row[parts[-1]] = value


def second_burst(rows, seconds):
    result = deepcopy(rows)
    for row in result:
        row['@timestamp'] = (utc(row['@timestamp']) + timedelta(seconds=seconds)).isoformat()
        row['cloud_soc']['provenance']['raw']['id'] += '-second'
        row['_cloud_soc_meta']['document_id'] += '-second'
        if row.get('service', {}).get('name') == 'security-mall':
            from uuid import NAMESPACE_URL, uuid5
            row['event']['id'] = str(uuid5(NAMESPACE_URL, row['event']['id'] + '/second'))
        for field in ('event_id', 'flow_id'):
            values = row['cloud_soc']['detail']['fields']
            if field in values:
                values[field] += '-second'
    return result
