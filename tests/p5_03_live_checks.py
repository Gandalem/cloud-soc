"""Explicit disposable-cluster checks. Never accepts a central-server endpoint."""
from contextlib import closing
from copy import deepcopy
from datetime import timedelta
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

from elasticsearch import AuthorizationException, Elasticsearch
from cloud_soc.processing.setup import prepare as prepare_processing, ROLE as NORMALIZER_ROLE
from cloud_soc.processing.worker import run_once as normalize_once
from cloud_soc.processing.contract import NORMALIZED, RECORDS
from cloud_soc.detection.setup import prepare as prepare_detection, ROLE as DETECTOR_ROLE
from cloud_soc.detection.incremental import run_incremental
from cloud_soc.detection.worker import run_once as snapshot_once
from cloud_soc.portal.status_setup import configure_reader
from cloud_soc.portal.operations import Operations
from test_attack_detection import BASE, APIS
from test_cloudtrail import EVENTS, projected
from test_intake_detection import raw

URL = 'http://p5-test-es:9200'
PHASE = 'disposable_identity_guard'


def guarded_admin():
    expected = os.environ.get('SOC_P5_FIXTURE_CLUSTER', '')
    if (os.environ.get('SOC_P5_DISPOSABLE_FIXTURE') != '1'
            or not expected.startswith('p5-fixture-') or len(expected) != 43):
        raise ValueError('Explicit disposable cluster identity required')
    client = Elasticsearch(URL, basic_auth=('elastic', os.environ['SOC_P5_FIXTURE_PASSWORD']),
                           request_timeout=20, max_retries=0)
    for _ in range(90):
        try:
            info = client.info()
            break
        except Exception:
            time.sleep(1)
    else:
        client.close()
        raise RuntimeError('Disposable ES startup timeout')
    if info['cluster_name'] != expected:
        client.close()
        raise ValueError('Unexpected cluster; no writes allowed')
    return client


def cloud_source(number, action, provider, seconds, *, receipt=5, request=None):
    event = deepcopy(EVENTS[1])
    event.update(eventTime=(BASE + timedelta(seconds=seconds)).isoformat(),
                 eventID=f'11111111-2222-3333-4444-{number:012d}', eventName=action,
                 eventSource=provider, requestParameters=request or {})
    event.pop('errorCode', None)
    index, identifier, source = projected(event)
    source['event']['ingested'] = (BASE + timedelta(seconds=receipt)).isoformat()
    return {'_index': index, '_id': identifier, '_source': source}


def sources():
    rows = []
    for i in range(7):
        seconds = i if i < 5 else 10 if i == 5 else 60
        hit = raw(i, seconds=seconds)
        stamp = BASE + timedelta(seconds=seconds)
        source = hit['_source']
        source['@timestamp'] = stamp.isoformat()
        source['event']['ingested'] = (BASE + timedelta(seconds=5)).isoformat()
        source['host'] = {'id': 'p5-host-fixture', 'name': 'SYNTHETIC-P5'}
        if i == 5:
            source['message'] = stamp.strftime('%b %d %H:%M:%S') + ' host sshd[100]: Accepted password for fixture from 192.0.2.10 port 12345 ssh2'
        elif i == 6:
            source['message'] = stamp.strftime('%b %d %H:%M:%S') + ' host sudo[200]: pam_unix(sudo:session): session opened for user root(uid=0) by fixture(uid=1000)'
        else:
            source['message'] = stamp.strftime('%b %d %H:%M:%S') + ' host sshd[100]: Failed password for fixture from 192.0.2.10 port 12345 ssh2'
        rows.append(hit)
    for i in range(20):
        provider, action = APIS[i % 4]
        rows.append(cloud_source(i, action, provider, i))
    rows.append(cloud_source(100, 'AttachRolePolicy', 'iam.amazonaws.com', 10,
        request={'policyArn': 'arn:aws:iam::aws:policy/AdministratorAccess', 'roleName': 'fixture-target'}))
    rows.append(cloud_source(101, 'StopLogging', 'cloudtrail.amazonaws.com', 60,
                             request={'name': 'fixture-trail'}))
    return rows


def state_body(path):
    with closing(sqlite3.connect(path)) as db:
        return db.execute('SELECT body FROM runtime').fetchone()[0]


def runtime(client, path, seconds):
    return run_incremental(client, state_path=path, start=BASE,
        now=BASE + timedelta(seconds=seconds), lateness_seconds=60,
        source_id='disposable-p5', include_attacks=True, include_cloud=True, include_sequence=True)


def child_resume(path, seconds):
    with guarded_admin(), Elasticsearch(URL, api_key=os.environ['SOC_P5_DETECTOR_KEY'],
                                      request_timeout=20, max_retries=0) as detector:
        result = runtime(detector, Path(path), int(seconds))
        print(json.dumps(result))


def check():
    global PHASE
    test = unittest.TestCase()
    report = {'synthetic': True, 'operational_deployment': False, 'checks': []}
    with guarded_admin() as admin, tempfile.TemporaryDirectory(prefix='p5-runtime-') as directory:
        PHASE = 'prepare_fixture'
        prepare_processing(admin)
        prepare_detection(admin)
        configure_reader(admin, os.environ['SOC_P5_FIXTURE_PASSWORD'])
        rows = sources()
        for index in sorted({h['_index'] for h in rows}):
            admin.indices.create(index=index, settings={'number_of_shards': 1, 'number_of_replicas': 0},
                mappings={'properties': {'event': {'properties': {'ingested': {'type': 'date'}}}}})
        for hit in rows:
            admin.create(index=hit['_index'], id=hit['_id'], document=hit['_source'])
        admin.indices.refresh(index=[h['_index'] for h in rows])
        keys = {}
        for name, role in [('normalizer', NORMALIZER_ROLE), ('detector', DETECTOR_ROLE)]:
            keys[name] = admin.security.create_api_key(name='p5-fixture-' + name, expiration='1h',
                role_descriptors={name: role})['encoded']
        with Elasticsearch(URL, api_key=keys['normalizer'], request_timeout=20, max_retries=0) as normalizer:
            PHASE = 'actual_normalization'
            path = Path(directory) / 'normalizer.sqlite'
            result = normalize_once(normalizer, path, BASE.isoformat(), now=BASE + timedelta(seconds=120))
            test.assertEqual(result['counts'], {'normalized': 29, 'unsupported': 0, 'invalid': 0})
            admin.indices.refresh(index=[NORMALIZED, RECORDS])
            test.assertEqual(admin.count(index=NORMALIZED)['count'], 29)
            normalize_once(normalizer, path, BASE.isoformat(), now=BASE + timedelta(seconds=130))
            admin.indices.refresh(index=NORMALIZED)
            test.assertEqual(admin.count(index=NORMALIZED)['count'], 29)
            for operation in (lambda: normalizer.create(index='security-alerts', id='denied', document={}),
                              lambda: normalizer.index(index=NORMALIZED, id='denied', document={})):
                with test.assertRaises(AuthorizationException):
                    operation()
        report['checks'].append('real_normalization_bulk_mapping_idempotence_and_least_privilege')
        with Elasticsearch(URL, api_key=keys['detector'], request_timeout=20, max_retries=0) as detector:
            PHASE = 'actual_attack_detection'
            state = Path(directory) / 'detector.sqlite'
            result = runtime(detector, state, 340)
            test.assertEqual(result['created'], 6)
            admin.indices.refresh(index='security-alerts')
            expected = {'AUTH-SEQ-001', 'AWS-IAM-001', 'AWS-AUDIT-001', 'ATTACK-01', 'ATTACK-02', 'ATTACK-03'}
            alerts = admin.search(index='security-alerts', size=20)['hits']['hits']
            test.assertEqual({h['_source']['rule']['id'] for h in alerts}, expected)
            test.assertEqual(admin.count(index='security-alerts')['count'], 6)
            report['alert_rule_ids'] = sorted(expected)
            report['checks'].append('three_attack_rules_plus_existing_rules_real_ES')
            env = {**os.environ, 'SOC_P5_DETECTOR_KEY': keys['detector']}
            PHASE = 'restart_and_replay'
            restart = subprocess.run([sys.executable, __file__, '--resume', str(state), '410'],
                                     capture_output=True, text=True, timeout=90, env=env)
            test.assertEqual(restart.returncode, 0, 'Separate-process resume failed; details withheld')
            test.assertEqual(json.loads(restart.stdout)['created'], 0)
            replay = runtime(detector, Path(directory) / 'replay.sqlite', 340)
            test.assertEqual((replay['created'], replay['existing']), (0, 6))
            snapshot = snapshot_once(detector, include_attacks=True, include_cloud=True, include_sequence=True)
            test.assertEqual((snapshot['created'], snapshot['existing']), (0, 6))
            for operation in (lambda: detector.indices.delete(index='security-alerts'),
                              lambda: detector.create(index='soc-host-raw-denied', id='denied', document={})):
                with test.assertRaises(AuthorizationException):
                    operation()
            report['checks'].append('separate_process_SQLite_resume_snapshot_replay_and_create_only')
            baseline = state_body(state)
            PHASE = 'real_authorization_failure'
            no_alert_role = deepcopy(DETECTOR_ROLE)
            for item in no_alert_role['indices']:
                if item['names'] == ['security-alerts']:
                    item['privileges'] = ['view_index_metadata']
            denied_key = admin.security.create_api_key(name='p5-denied-detector', expiration='1h',
                role_descriptors={'denied': no_alert_role})['encoded']
            # A new state re-evaluates the same real documents; even an existing
            # alert needs create_doc. Real ES authorization failure must retain state.
            failure_path = Path(directory) / 'failure.sqlite'
            with Elasticsearch(URL, api_key=denied_key, request_timeout=20, max_retries=0) as denied:
                with test.assertRaises(RuntimeError):
                    runtime(denied, failure_path, 340)
            with closing(sqlite3.connect(failure_path)) as db:
                test.assertIsNone(db.execute('SELECT body FROM runtime').fetchone())
            retried = runtime(detector, failure_path, 340)
            test.assertEqual((retried['created'], retried['existing']), (0, 6))
            test.assertEqual(state_body(state), baseline)
            report['checks'].append('real_authorization_failure_checkpoint_retention_and_retry')
        with Elasticsearch(URL, basic_auth=('cloud_soc_agent_monitor', os.environ['SOC_P5_FIXTURE_PASSWORD']),
                           request_timeout=20, max_retries=0) as monitor:
            PHASE = 'real_evidence_integrity'
            reader = Operations(monitor)
            for hit in alerts:
                detail = json.loads(reader.detail([('id', hit['_id']), ('evidence', '0')]))
                test.assertEqual(detail['evidence']['state'], 'exact_reference')
                test.assertEqual(detail['evidence']['integrity'], 'normalized_hash_verified')
                if hit['_source']['rule']['id'].startswith('ATTACK-'):
                    test.assertEqual(detail['assessment']['attack_success'], 'not_established')
                foreign = Operations(monitor, organizations=['other-org'])
                test.assertIsNone(foreign.get('security-alerts', hit['_id'], None))
            with test.assertRaises(AuthorizationException):
                monitor.create(index='security-alerts', id='denied', document={})
            report['checks'].append('real_evidence_hash_exact_raw_refs_org_scope_and_monitor_read_only')
            chosen = next(h for h in alerts if h['_source']['rule']['id'] == 'ATTACK-03')
            reference = chosen['_source']['cloud_soc']['provenance']['evidence'][0]
            normalized_ref = reference['normalized']
            old = admin.get(index=normalized_ref['index'], id=normalized_ref['id'])['_source']
            changed = deepcopy(old)
            changed['event']['action'] = 'tampered_fixture'
            admin.index(index=normalized_ref['index'], id=normalized_ref['id'], document=changed, refresh=True)
            test.assertEqual(reader.evidence(reference, organization=chosen['_source']['organization']['id'])['state'],
                             'normalized_hash_mismatch')
            admin.index(index=normalized_ref['index'], id=normalized_ref['id'], document=old, refresh=True)
            raw_ref = reference['raw']
            admin.delete(index=raw_ref['index'], id=raw_ref['id'], refresh=True)
            test.assertEqual(reader.evidence(reference, organization=chosen['_source']['organization']['id'])['state'],
                             'raw_missing_or_expired')
            report['checks'].append('fixture_only_tamper_and_missing_evidence_visible')
    report['passed'] = True
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    try:
        if len(sys.argv) == 4 and sys.argv[1] == '--resume':
            child_resume(sys.argv[2], sys.argv[3])
        elif len(sys.argv) == 1:
            check()
        else:
            raise ValueError('Unsupported verification mode')
    except Exception as error:
        print(json.dumps({'passed': False, 'error_type': type(error).__name__, 'phase': PHASE, 'details_withheld': True}))
        raise SystemExit(1) from None
