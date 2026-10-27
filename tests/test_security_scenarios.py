"""Synthetic collector → normalization → detector → Portal integration coverage."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from cloud_soc.detection.engine import detect_rule
from cloud_soc.detection.profiles import catalog, source_observed
from cloud_soc.parsers.security_scenario_export import project
from cloud_soc.parsers.security_scenarios import VERSION, parse
from cloud_soc.portal.log_query import project_list_hit
from cloud_soc.processing.contract import normalize, NORMALIZED

BASE = datetime(2026, 10, 27, tzinfo=timezone.utc)
SAMPLES = {
    'server_file': ('SCENARIO-SERVER-FILE-001', 'modified',
                    {'actor': 'operator', 'object_path': '/etc/ssh/sshd_config', 'critical_asset': True}),
    'server_persistence': ('SCENARIO-SERVER-PERSIST-001', 'created',
                           {'actor': 'operator', 'object_name': 'daily-backup', 'object_type': 'cron'}),
    'server_defense': ('SCENARIO-SERVER-DEFENSE-001', 'stopped',
                       {'actor': 'operator', 'object_name': 'auditd'}),
    'app_role': ('SCENARIO-APP-ROLE-001', 'granted',
                 {'actor': 'operator', 'target_user': 'analyst', 'role_before': 'reader', 'role_after': 'admin'}),
    'app_export': ('SCENARIO-APP-EXPORT-001', 'exported',
                   {'actor': 'analyst', 'resource_type': 'orders', 'record_count': 1000}),
    'app_upload': ('SCENARIO-APP-UPLOAD-001', 'uploaded',
                   {'actor': 'analyst', 'object_name': 'upload.exe', 'risk_reason': 'mime_mismatch'}),
    'network_dns': ('SCENARIO-NET-DNS-001', 'query',
                    {'source_ip': '192.0.2.1', 'dns_name': 'missing.example', 'dns_rcode': 'NXDOMAIN'}),
    'network_firewall': ('SCENARIO-NET-FIREWALL-001', 'denied',
                         {'source_ip': '192.0.2.1', 'destination_ip': '198.51.100.1', 'destination_port': 443}),
    'network_ids': ('SCENARIO-NET-IDS-001', 'alert',
                    {'source_ip': '192.0.2.1', 'destination_ip': '198.51.100.1',
                     'signature_id': '100001', 'signature_name': 'Suspicious request'}),
}


def document(kind, number=0):
    _, action, values = SAMPLES[kind]
    return {'timestamp': (BASE + timedelta(seconds=number)).isoformat(),
            'security_scenario': {'schema': VERSION, 'kind': kind, 'action': action, **deepcopy(values)}}


def raw(kind, number=0, organization='org-a', host='host-a', service='app-a'):
    source = project(document(kind, number), organization=organization, host=host, service=service)
    source['event']['ingested'] = (BASE + timedelta(seconds=60 + number)).isoformat()
    return {'_index': 'soc-host-raw-scenarios-2026.10.27', '_id': f'{kind}-{number}', '_source': source}


def normalized(hit):
    identifier, record, event = normalize(hit, (BASE + timedelta(minutes=5)).isoformat())
    assert record['status'] == 'normalized', record
    event['_cloud_soc_meta'] = {'index': NORMALIZED, 'document_id': identifier}
    return event


@pytest.fixture(scope='module')
def rules():
    return {rule['id']: rule for rule in catalog()}


@pytest.mark.parametrize('kind', SAMPLES)
def test_nine_sources_reach_three_event_detection_with_exact_evidence(kind, rules):
    rule = rules[SAMPLES[kind][0]]
    events = [normalized(raw(kind, number)) for number in range(3)]
    assert all(source_observed(event, rule['id']) for event in events)
    assert detect_rule(events[:2], rule) == []
    assert detect_rule([events[0]] * 3, rule) == []
    detections = detect_rule(events, rule)
    assert len(detections) == 1
    assert detections[0]['event_count'] == 3
    assert detections[0]['evidence_status'] == 'complete'
    assert len({item['raw']['id'] for item in detections[0]['evidence']}) == 3
    assert detections[0]['assessment']['type'] == 'security_observation'
    assert detections[0]['assessment']['attack_success'] == 'not_established'
    runtime = {}
    assert len(detect_rule(events, rule, runtime=runtime)) == 1
    # Incremental workers finalize ordering before invoking this engine. A full
    # older batch replay into the same finalized in-memory state is refused.
    with pytest.raises(ValueError, match='finalized event order'):
        detect_rule(events, rule, runtime=runtime)
    assert detect_rule([events[-1]], rule, runtime=runtime) == []
    late = deepcopy(events[0])
    late['cloud_soc']['provenance']['raw']['id'] = 'new-late-observation'
    with pytest.raises(ValueError, match='finalized event order'):
        detect_rule([late], rule, runtime=runtime)


@pytest.mark.parametrize('kind', SAMPLES)
def test_scope_time_window_and_portal_metadata(kind, rules):
    rule = rules[SAMPLES[kind][0]]
    events = [normalized(raw(kind, number)) for number in range(2)]
    assert detect_rule(events + [normalized(raw(kind, 2, organization='org-b'))], rule) == []
    assert detect_rule(events + [normalized(raw(kind, 2, host='host-b'))], rule) == []
    assert detect_rule(events + [normalized(raw(kind, 902))], rule) == []
    if kind.startswith('app_'):
        assert detect_rule(events + [normalized(raw(kind, 2, service='app-b'))], rule) == []
    row = project_list_hit(raw(kind))
    assert row['source_kind'] == 'security_scenario'
    assert row['parse_status'] == 'recognized'
    assert row['log_type']['code'] == kind


@pytest.mark.parametrize('kind', SAMPLES)
def test_missing_required_metadata_is_rejected_and_payload_is_not_copied(kind):
    doc = document(kind)
    key = next(iter(SAMPLES[kind][2]))
    del doc['security_scenario'][key]
    with pytest.raises(ValueError):
        project(doc, organization='org-a', host='host-a', service='app-a')
    doc = document(kind)
    doc.update(organization={'id': 'untrusted'}, message='PRIVATE_CANARY')
    doc['security_scenario']['password'] = 'PRIVATE_CANARY'
    result = project(doc, organization='org-a', host='host-a', service='app-a')
    assert result['organization']['id'] == 'org-a'
    assert 'PRIVATE_CANARY' not in json.dumps(result)


def test_semantic_thresholds_and_wrong_intake_scope(rules):
    cases = [('server_file', 'critical_asset', False), ('app_export', 'record_count', 999),
             ('network_dns', 'dns_rcode', 'NOERROR')]
    for kind, key, value in cases:
        events = []
        for number in range(3):
            hit = raw(kind, number)
            hit['_source']['security_scenario'][key] = value
            events.append(normalized(hit))
        assert detect_rule(events, rules[SAMPLES[kind][0]]) == []
    hit = raw('network_ids')
    hit['_index'] = 'soc-network-other'
    assert normalize(hit, BASE.isoformat())[2] is None


def test_cli_stream_rejects_invalid_lines_without_losing_next_good_record():
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, '-m', 'cloud_soc.parsers.security_scenario_export',
         '--organization', 'org-a', '--host', 'host-a'],
        input=b'PRIVATE_CANARY\n' + b'x' * 65537 + b'\n' + json.dumps(document('server_file')).encode() + b'\n',
        capture_output=True, cwd=root, env={**os.environ, 'PYTHONPATH': str(root / 'src')}, timeout=15)
    assert result.returncode == 1
    assert len(result.stdout.splitlines()) == 1
    assert json.loads(result.stdout)['security_scenario']['kind'] == 'server_file'
    assert b'PRIVATE_CANARY' not in result.stderr + result.stdout


@pytest.mark.parametrize('bad', [True, -1, 1.5, '1000'])
def test_record_count_requires_nonnegative_integer(bad):
    source = raw('app_export')['_source']
    source['security_scenario']['record_count'] = bad
    with pytest.raises(ValueError):
        parse(source)
