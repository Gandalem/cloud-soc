"""Only called with the disposable Docker test cluster, never production settings."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import time

from elasticsearch import AuthorizationException, Elasticsearch
from cloud_soc.portal.agent_status import iso
from cloud_soc.portal.collection_health import snapshot
from cloud_soc.portal.status_setup import configure_template
from cloud_soc.portal.storage import survey, lifecycle_proposal

ROOT = Path(__file__).resolve().parents[1]


def check_p2(test, admin, monitor, url):
    template = json.loads((ROOT / 'deploy/agents/health-index-template.json').read_text())
    admin.indices.put_index_template(name='test-health', body=configure_template(template))
    role = json.loads((ROOT / 'deploy/agents/publisher-role.json').read_text())
    key = admin.security.create_api_key(name='test-health-only', expiration='1h', role_descriptors={'host': role})
    now = datetime.now(timezone.utc)
    doc = {'@timestamp': iso(now), 'host': {'name': 'SYNTHETIC'}, 'agent': {'id': 'health-agent', 'type': 'filebeat'},
           'event': {'ingested': '2099-01-01T00:00:00Z'}, 'organization': {'id': 'test'},
           'cloud_soc': {'discovery': {'schema': 1, 'generated_at': iso(now), 'policy_version': 2,
                                     'selected': 3, 'excluded': 1, 'errors': 0, 'total': 4,
                                     'sources': [{'id': 'a' * 64, 'status': 'selected'}]}}}
    with Elasticsearch(url, api_key=key['encoded']) as publisher:
        publisher.index(index='soc-agent-health-test', id='one', op_type='create', pipeline='_none', document=doc)
        with test.assertRaises(AuthorizationException):
            publisher.search(index='soc-agent-health-test')
        with test.assertRaises(AuthorizationException):
            publisher.index(index='security-alerts', document={})
    admin.indices.refresh(index='soc-agent-health-test')
    page = json.loads(snapshot(monitor))
    test.assertEqual(len(page['rows']), 1)
    test.assertEqual(page['rows'][0]['policy_version'], 2)
    test.assertFalse(page['rows'][0]['received_at'].startswith('2099'))
    test.assertEqual(page['rows'][0]['queue_state'], 'unknown')
    with test.assertRaises(AuthorizationException):
        monitor.indices.delete(index='soc-agent-health-test')

    # Expiration and restore are confined to named synthetic indices in this container.
    old = 'soc-host-raw-retention-fixture'
    keep = 'soc-host-raw-retention-keep'
    policy = 'test-retention-only'
    admin.ilm.put_lifecycle(name=policy, body=lifecycle_proposal(30))
    for name, age in ((old, 90), (keep, 0)):
        admin.indices.create(index=name, settings={'index.final_pipeline': '_none', 'index.lifecycle.name': policy,
                             'index.lifecycle.origination_date': int((now - timedelta(days=age)).timestamp() * 1000)})
        admin.index(index=name, id='synthetic', document={'message': 'RESTORE_SYNTHETIC',
                    'event': {'ingested': iso(now - timedelta(days=age))}}, refresh=True)
    report = survey(admin, days=30)
    test.assertTrue(next(row for row in report['indices'] if row['index'] == old)['review_candidate'])
    test.assertFalse(next(row for row in report['indices'] if row['index'] == keep)['review_candidate'])
    admin.snapshot.create_repository(name='test-backup', repository={'type': 'fs', 'settings': {'location': '/tmp/cloud-soc-snapshots'}})
    result = admin.snapshot.create(repository='test-backup', snapshot='synthetic-backup', wait_for_completion=True,
                                  indices=old, include_global_state=False, feature_states=['none'])
    test.assertEqual(result['snapshot']['state'], 'SUCCESS')
    admin.cluster.put_settings(persistent={'indices.lifecycle.poll_interval': '1s'})
    for _ in range(90):
        if not admin.indices.exists(index=old):
            break
        time.sleep(1)
    else:
        test.fail('Isolated ILM did not delete its expired synthetic fixture')
    test.assertTrue(admin.indices.exists(index=keep))
    restored = 'soc-host-raw-retention-restored'
    admin.snapshot.restore(repository='test-backup', snapshot='synthetic-backup', wait_for_completion=True,
                           indices=old, include_global_state=False, include_aliases=False,
                           rename_pattern=old, rename_replacement=restored,
                           ignore_index_settings=['index.lifecycle.name', 'index.lifecycle.origination_date'])
    test.assertEqual(admin.get(index=restored, id='synthetic')['_source']['message'], 'RESTORE_SYNTHETIC')
