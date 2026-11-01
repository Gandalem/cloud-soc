"""Opt-in synthetic pipeline against a fresh isolated Linux ES, never an operator URL."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import time

from elasticsearch import Elasticsearch, AuthorizationException
import pytest

from cloud_soc.aws.collector import ElasticsearchSink
from cloud_soc.detection.engine import detect_events
from cloud_soc.detection.rule_loader import load_rules
from cloud_soc.detection.worker import normalized_snapshot
from cloud_soc.elastic.repository import ensure_security_alerts_index, save_security_alert
from cloud_soc.main import build_security_alert, make_alert_id
from cloud_soc.portal.log_query import LogReader
from cloud_soc.portal.operations import Operations
from cloud_soc.portal.status_setup import configure_reader, configure_template, install_receipt_pipeline
from cloud_soc.processing.contract import NORMALIZED, RECORDS, STATUS
from cloud_soc.processing.setup import prepare, ROLE
from cloud_soc.processing.worker import run_once
from test_aws_service_logs import KINDS, native, projected, CANARY

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(os.environ.get('SOC_AWS_ISOLATED_ES_TEST') != '1', reason='Explicit disposable Docker ES only')
def test_real_es_service_intake_normalizer_portal_alerts_and_replay(tmp_path):
    # Fixed private test alias; no user-configurable production URL is accepted.
    url = 'http://aws-service-es-test:9200'
    cluster = os.environ['SOC_AWS_TEST_CLUSTER']
    assert cluster.startswith('soc-aws-logs-test-')
    password = os.environ['SOC_AWS_TEST_PASSWORD']
    with Elasticsearch(url, basic_auth=('elastic', password), request_timeout=10, max_retries=0) as admin:
        for _ in range(90):
            try:
                info = admin.info()
                break
            except Exception:
                time.sleep(1)
        else:
            pytest.fail('Disposable ES readiness timeout')
        assert info['cluster_name'] == cluster and info['version']['number'] == '9.5.2'
        install_receipt_pipeline(admin, [])
        configure_reader(admin, password)
        template = json.loads((ROOT / 'deploy/aws/index-template.json').read_text())
        template['template']['settings']['number_of_replicas'] = 0
        admin.indices.put_index_template(name='aws-service-test', body=configure_template(template))
        writer_role = json.loads((ROOT / 'deploy/aws/publisher-role.json').read_text())
        writer = admin.security.create_api_key(name='disposable-service-writer', expiration='1h', role_descriptors={'writer': writer_role})
        start = datetime.now(timezone.utc) - timedelta(minutes=1)
        references = []
        with Elasticsearch(url, api_key=writer['encoded'], max_retries=0) as publisher:
            sink = ElasticsearchSink(publisher)
            for kind in KINDS:
                count = 10 if kind == 'route53_resolver' else 5 if kind == 'cloudfront' else 1
                value = native(kind)
                if kind == 'route53_resolver': value['rcode'] = 'NXDOMAIN'
                if kind == 'cloudfront': value['sc-status'] = '503'
                for number in range(count):
                    index, identifier, document = projected(kind, number, value)[0]
                    document['event']['ingested'] = '2099-01-01T00:00:00Z'
                    assert sink.create(index, identifier, document)
                    assert not sink.create(index, identifier, document)
                    references.append({'index': index, 'id': identifier})
            with pytest.raises(AuthorizationException):
                publisher.search(index='soc-cloud-aws-*')
        admin.indices.refresh(index='soc-cloud-aws-*')
        assert admin.count(index='soc-cloud-aws-*')['count'] == 20
        prepare(admin)
        worker_key = admin.security.create_api_key(name='disposable-normalizer', expiration='1h', role_descriptors={'normalizer': ROLE})
        raw_indices = sorted({ref['index'] for ref in references})
        with Elasticsearch(url, api_key=worker_key['encoded'], max_retries=0) as worker:
            checkpoint = tmp_path / 'normalizer.sqlite'
            run_once(worker, checkpoint, start.isoformat(), now=datetime.now(timezone.utc) + timedelta(seconds=40), source_indices=raw_indices)
            admin.indices.refresh(index=[NORMALIZED, RECORDS, STATUS])
            assert admin.count(index=NORMALIZED)['count'] == 20
            run_once(worker, checkpoint, start.isoformat(), now=datetime.now(timezone.utc) + timedelta(seconds=45), source_indices=raw_indices)
            admin.indices.refresh(index=[NORMALIZED, RECORDS])
            assert admin.count(index=NORMALIZED)['count'] == admin.count(index=RECORDS)['count'] == 20
        events = normalized_snapshot(admin, 100)
        assert len(events) == 20 and CANARY not in json.dumps(events)
        rules = load_rules(ROOT / 'deploy/aws/service-rules.example.yml', enabled_only=False)
        assert all(rule['enabled'] is False for rule in rules)
        for rule in rules: rule['enabled'] = True  # isolated in-memory candidates only
        detections = detect_events(events, rules)
        assert len(detections) == 5
        ensure_security_alerts_index(admin)
        for detection in detections:
            identifier, alert = make_alert_id(detection), build_security_alert(detection)
            assert save_security_alert(admin, alert, document_id=identifier, index_prepared=True)['result'] == 'created'
            assert save_security_alert(admin, alert, document_id=identifier, index_prepared=True)['result'] == 'existing'
        admin.indices.refresh(index='security-alerts')
        assert admin.count(index='security-alerts')['count'] == 5
        with Elasticsearch(url, basic_auth=('cloud_soc_agent_monitor', password), max_retries=0) as monitor:
            reader = LogReader(monitor, secret='synthetic', principal='fixture', organizations=['fixture'])
            page = json.loads(reader.page([('collector', 'aws-cloudwatch'), ('os', 'cloud')]))
            assert len(page['rows']) == 20
            assert {row['log_type']['code'] for row in page['rows']} == set(KINDS)
            assert all(not row['received_at'].startswith('2099') for row in page['rows'])
            for reference in references:
                detail = json.loads(reader.detail(list(reference.items())))
                assert detail['security']['status'] == 'recognized' and CANARY not in json.dumps(detail)
            alerts = Operations(monitor)
            for detection in detections:
                detail = json.loads(alerts.detail([('id', make_alert_id(detection)), ('evidence', '0')]))
                assert detail['evidence']['state'] == 'exact_reference'
                assert CANARY not in json.dumps(detail)
