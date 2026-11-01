"""Opt-in intake of operator-supplied protected AWS samples into a disposable ES.

The samples remain in Git-ignored state, never in fixtures or test output.
"""
import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import time

from elasticsearch import Elasticsearch
import pytest
from werkzeug.security import generate_password_hash

from cloud_soc.aws.collector import ElasticsearchSink
from cloud_soc.aws.service_logs import SOURCE, VERSION, detail
from cloud_soc.detection.engine import detect_events
from cloud_soc.detection.rule_loader import load_rules
from cloud_soc.detection.worker import normalized_snapshot
from cloud_soc.elastic.repository import ensure_security_alerts_index, save_security_alert
from cloud_soc.main import build_security_alert, make_alert_id
from cloud_soc.portal.app import create_app
from cloud_soc.portal.operations import Operations
from cloud_soc.portal.status_setup import configure_reader, configure_template, install_receipt_pipeline
from cloud_soc.processing.contract import NORMALIZED, RECORDS, STATUS
from cloud_soc.processing.setup import prepare, ROLE
from cloud_soc.processing.worker import run_once

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(os.environ.get('SOC_AWS_ISOLATED_ES_TEST') != '1', reason='Explicit disposable Docker ES only')
def test_actual_aws_projections_to_es_normalizer_and_authenticated_portal(tmp_path):
    evidence_path = Path(os.environ.get('SOC_AWS_REAL_SAMPLES_FILE', str(ROOT / 'state/aws-real-source-check/real-samples.json')))
    assert evidence_path.resolve().is_relative_to((ROOT / 'state').resolve())
    assert evidence_path.is_file(), 'Protected real samples must be supplied separately'
    evidence = json.loads(evidence_path.read_text())
    assert evidence['schema'] == 'aws-real-samples-v1'
    assert evidence['mode'] == 'manual_readonly_cloudshell_sample'
    assert evidence['account'] == '897722691159' and evidence['organization'] == 'aws-dev-gyumin'
    sources = evidence['sources']
    expected = {'route53_resolver', 'cloudfront', 'rds_error'}
    if os.environ.get('SOC_AWS_EXPECT_GENERAL') == '1': expected.add('rds_general')
    if os.environ.get('SOC_AWS_EXPECT_SECURITYHUB') == '1':
        expected.add('securityhub')
        assert len(evidence['validation_findings']) == 1 and evidence['validation_findings'][0]['archived'] is True
    expect_firewall = os.environ.get('SOC_AWS_EXPECT_FIREWALL') == '1'
    if expect_firewall:
        expected.update(('network_firewall_alert', 'network_firewall_flow'))
        assert evidence['firewall_validation']['route_restoration_manifest_confirmed'] is True
    count = len(expected)
    assert {s['kind'] for s in sources} == expected
    assert len(sources) == count and all(s['status'] == 'verified' for s in sources)
    for source in sources:
        document = source['document']
        assert document['labels'] == {'log_source': SOURCE, 'privacy_policy': VERSION}
        assert 'message' not in document and 'original' not in document['event']
        assert document['cloud']['account']['id'] == evidence['account']
        fields = detail(document)
        assert fields['kind'] == source['kind']
        identity = [SOURCE, evidence['organization'], evidence['account'], document['cloud']['region'],
                    fields['log_group'], fields['log_stream'], fields['event_id'], fields.get('finding_id')]
        identifier = hashlib.sha256(json.dumps(identity, separators=(',', ':')).encode()).hexdigest()
        assert identifier == source['reference']['id'] == document['event']['id']
    cluster = os.environ['SOC_AWS_TEST_CLUSTER']
    assert cluster.startswith('soc-aws-logs-test-')
    password = os.environ['SOC_AWS_TEST_PASSWORD']
    url = 'http://aws-service-es-test:9200'
    with Elasticsearch(url, basic_auth=('elastic', password), max_retries=0, request_timeout=10) as admin:
        for _ in range(90):
            try:
                info = admin.info()
                break
            except Exception:
                time.sleep(1)
        else:
            pytest.fail('Disposable ES readiness timeout')
        assert info['cluster_name'] == cluster and info['version']['number'] == '9.5.2'
        health = admin.cluster.health(wait_for_status='yellow', wait_for_no_initializing_shards=True, timeout='60s')
        assert health['timed_out'] is False, 'Disposable ES shards not ready'
        install_receipt_pipeline(admin, [])
        configure_reader(admin, password)
        template = json.loads((ROOT / 'deploy/aws/index-template.json').read_text())
        template['template']['settings']['number_of_replicas'] = 0
        admin.indices.put_index_template(name='real-aws-dev-check', body=configure_template(template))
        writer_role = json.loads((ROOT / 'deploy/aws/publisher-role.json').read_text())
        writer = admin.security.create_api_key(name='disposable-real-aws-writer', expiration='1h', role_descriptors={'writer': writer_role})
        start = datetime.now(timezone.utc) - timedelta(minutes=1)
        with Elasticsearch(url, api_key=writer['encoded'], max_retries=0) as publisher:
            sink = ElasticsearchSink(publisher)
            for source in sources:
                ref = source['reference']
                document = deepcopy(source['document'])
                document['event']['ingested'] = '2099-01-01T00:00:00Z'
                assert sink.create(ref['index'], ref['id'], document)
                assert not sink.create(ref['index'], ref['id'], document)
        admin.indices.refresh(index='soc-cloud-aws-*')
        assert admin.count(index='soc-cloud-aws-*')['count'] == count
        prepare(admin)
        normalizer = admin.security.create_api_key(name='disposable-real-aws-normalizer', expiration='1h', role_descriptors={'normalizer': ROLE})
        with Elasticsearch(url, api_key=normalizer['encoded'], max_retries=0) as worker:
            source_indices = sorted({s['reference']['index'] for s in sources})
            checkpoint = tmp_path / 'normalizer.sqlite'
            for delay in (40, 45):
                run_once(worker, checkpoint, start.isoformat(), now=datetime.now(timezone.utc) + timedelta(seconds=delay), source_indices=source_indices)
                admin.indices.refresh(index=[NORMALIZED, RECORDS, STATUS])
                assert admin.count(index=NORMALIZED)['count'] == admin.count(index=RECORDS)['count'] == count
        events = normalized_snapshot(admin, 10)
        by_raw_id = {event['cloud_soc']['provenance']['raw']['id']: event for event in events}
        for source in sources:
            event = by_raw_id[source['reference']['id']]
            assert event['cloud_soc']['provenance']['raw'] == source['reference']
            assert event['@timestamp'] == source['document']['@timestamp']
            assert event['cloud_soc']['detail']['fields']['original_sha256'] == source['document']['aws']['service_logs']['original_sha256']
        rules = load_rules(ROOT / 'deploy/aws/service-rules.example.yml', enabled_only=False)
        for rule in rules: rule['enabled'] = True  # local memory only; no active profile change
        detections = detect_events(events, rules)
        assert len(detections) == (1 if expect_firewall else 0)
        if expect_firewall:
            assert detections[0]['rule_id'] == 'AWS-FIREWALL-LAB-001'
            # A native rule observation is not an attack claim; candidates stay disabled on disk.
            assert load_rules(ROOT / 'deploy/aws/service-rules.example.yml', enabled_only=True) == []
            ensure_security_alerts_index(admin)
            for detection in detections:
                identifier, alert = make_alert_id(detection), build_security_alert(detection)
                assert save_security_alert(admin, alert, document_id=identifier, index_prepared=True)['result'] == 'created'
                assert save_security_alert(admin, alert, document_id=identifier, index_prepared=True)['result'] == 'existing'
            admin.indices.refresh(index='security-alerts')
            assert admin.count(index='security-alerts')['count'] == 1
            assert [make_alert_id(d) for d in detect_events(events, rules)] == [make_alert_id(d) for d in detections]
        with Elasticsearch(url, basic_auth=('cloud_soc_agent_monitor', password), max_retries=0) as monitor:
            state = tmp_path / 'portal'
            state.mkdir()
            settings = {'STATE_DIR': state, 'AGENT_SOURCE': ROOT / 'deploy/agents', 'CA_BYTES': b'disposable-test-only',
                        'PUBLIC_URL': 'http://localhost', 'ENDPOINT': 'https://unused.example.test:9200',
                        'ADMIN_USER': 'dev-admin', 'ADMIN_HASH': generate_password_hash(password, method='pbkdf2:sha256:1000')}
            app = create_app(settings, issuer=monitor, monitor=monitor)
            client = app.test_client()
            headers = {'Authorization': 'Basic ' + base64.b64encode(('dev-admin:' + password).encode()).decode()}
            assert client.get('/api/logs').status_code == 401
            page = client.get('/api/logs?collector=aws-cloudwatch&os=cloud', headers=headers)
            assert page.status_code == 200 and len(page.json['rows']) == count
            assert {r['log_type']['code'] for r in page.json['rows']} == {s['kind'] for s in sources}
            assert all(not r['received_at'].startswith('2099') for r in page.json['rows'])
            for source in sources:
                response = client.get('/api/logs/detail', query_string=source['reference'], headers=headers)
                assert response.status_code == 200 and response.json['security']['status'] == 'recognized'
                assert response.json['row']['reference'] == source['reference']
                assert response.json['security']['fields']['original_sha256'] == source['document']['aws']['service_logs']['original_sha256']
            assert client.get('/logs.html', headers=headers).status_code == 200
            for detection in detections:
                observation = json.loads(Operations(monitor).detail([('id', make_alert_id(detection)), ('evidence', '0')]))
                assert observation['evidence']['state'] == 'exact_reference'
    summary = {'schema': 1, 'source_mode': evidence['mode'], 'real_aws_sources': sorted(s['kind'] for s in sources),
               'raw': count, 'normalized': count, 'processing_records': count, 'portal_list_status': 200,
               'portal_details': count, 'portal_html_status': 200, 'unauthenticated_status': 401,
               'duplicate_raw_additions': 0, 'duplicate_normalized_additions': 0, 'candidate_alerts': len(detections),
               'candidate_alert_classification': 'native_firewall_rule_observation_not_attack' if expect_firewall else None,
               'firewall_validation': evidence.get('firewall_validation'),
               'occurrence_and_original_sha256_preserved': True, 'continuous_collector_deployed': False,
               'school_deployment': False, 'browser_rendering_verified': False,
               'intentional_validation_findings': evidence.get('validation_findings', []),
               'evidence_sha256': hashlib.sha256(evidence_path.read_bytes()).hexdigest()}
    Path('/results/real-intake-summary.json').write_text(json.dumps(summary, indent=2))
