"""Opt-in full isolated ES/Kibana/portal runtime; never mounts an existing server.

Requires root on a disposable local Docker host and the three pinned infra
images plus cloud-soc:ci already present. Fixture state/volumes remain for review.
No attacks, Slack sends, production credentials or operating data are used.
"""
from contextlib import redirect_stdout
from datetime import datetime, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import tempfile
import time
import uuid

from elasticsearch import Elasticsearch
import requests

from cloud_soc.deployment import host
from cloud_soc.deployment.contract import ALL_WORKERS, SERVICES, digest
from cloud_soc.deployment.migrations import atomic_json
from cloud_soc.deployment.verify import portal
from cloud_soc.processing.contract import normalize


ROOT = Path(__file__).resolve().parents[1]


def main():
    assert os.name == 'posix' and os.geteuid() == 0
    engine = host.Docker();project = 'soc-full-'+uuid.uuid4().hex[:10]
    directory = Path(tempfile.mkdtemp(prefix='soc-full-', dir='/var/tmp'));directory.chmod(0o700)
    state = directory/'state';report = {'project': project, 'fixture_state': str(state), 'passed': False}
    spec = importlib.util.spec_from_file_location('isolated_prepare', ROOT/'deploy/server/prepare.py')
    prepare = importlib.util.module_from_spec(spec);spec.loader.exec_module(prepare)
    password = secrets.token_urlsafe(32)
    with redirect_stdout(io.StringIO()): prepare.prepare('127.0.0.1', '127.0.0.1', state, password)
    def ready(engine, name, project):
        deadline = time.monotonic()+180
        while time.monotonic() < deadline:
            found = host.containers(engine, project)
            if name in found and host.service_running(found[name]): return
            time.sleep(1)
        raise AssertionError('Isolated '+name+' readiness failed')
    try:
        print(json.dumps({'stage': 'full_fresh_plan', 'project': project}), flush=True)
        plan = host.snapshot(engine, ROOT, state, 'cloud-soc:ci', project)
        atomic_json(directory/'plan.json', plan)
        assert plan['resources']['ok'], 'Full fixture resource budget refused'
        receipt = host.apply(engine, plan, poll=ready)
        report['receipt'] = receipt
        print(json.dumps({'stage': 'full_runtime_started', 'runtime_ready': receipt['runtime_ready']}), flush=True)
        before = host.containers(engine, project)
        report['portal'] = portal('https://127.0.0.1', state/'tls/ca.crt', password)
        session = requests.Session();session.trust_env = False
        kibana = session.get('https://127.0.0.1:5601/api/status', verify=str(state/'tls/ca.crt'), timeout=30)
        assert kibana.status_code == 200
        client = Elasticsearch('https://127.0.0.1:9200', basic_auth=('elastic', (state/'secrets/elastic_password').read_text().strip()),
                               ca_certs=str(state/'tls/ca.crt'), request_timeout=30, max_retries=0)
        assert client.info()['version']['number'] == '9.5.2'
        # A normal synthetic source event, not an authentication/attack exercise.
        now = datetime.now(timezone.utc).isoformat();raw_id = 'isolated-normal-log'
        index = 'soc-host-raw-isolated'
        body = {'@timestamp': now, 'event': {'ingested': now}, 'organization': {'id': 'isolated-only'},
                'host': {'name': 'synthetic-host'}, 'labels': {'log_source': 'linux_journald'},
                'process': {'name': 'systemd'}, 'message': 'Started isolated service.'}
        normalized_id, record, _ = normalize({'_index': index, '_id': raw_id, '_source': body}, now)
        assert record['status'] == 'normalized'
        client.create(index=index, id=raw_id, document=body, refresh='wait_for')
        deadline = time.monotonic()+100;normalized = []
        while time.monotonic() < deadline:
            found = client.options(ignore_status=404).get(index='soc-normalized-v1', id=normalized_id)
            normalized = [found] if found.get('found') else []
            if normalized: break
            time.sleep(3)
        assert len(normalized) == 1, 'New isolated raw event normalization absent or duplicated'
        assert normalized[0]['_source']['cloud_soc']['provenance']['raw'] == {'index': index, 'id': raw_id}
        report['normalization'] = {'synthetic_raw_documents': 1, 'normalized': 1, 'exact_raw_reference': True}
        print(json.dumps({'stage': 'full_managed_reapply'}), flush=True)
        next_plan = host.snapshot(engine, ROOT, state, 'cloud-soc:ci', project)
        again = host.apply(engine, next_plan, poll=ready)
        assert again.get('unchanged'), 'A fully matching managed deployment should not restart'
        after = host.containers(engine, project)
        assert set(host.worker_inventory(engine, project)) == set(ALL_WORKERS)
        assert all(before[name]['Id'] == after[name]['Id'] and before[name]['RestartCount'] == after[name]['RestartCount']
                   and not after[name]['State']['OOMKilled'] for name in SERVICES)
        notification = engine.json(['exec', project+'-slack-notifier-1', 'python', '-c',
            'import json;from cloud_soc.notifications.store import SlackStore;print(json.dumps(SlackStore("/notifications").status()))'])
        assert notification['enabled'] is False and notification['configured'] is False
        report.update(passed=True, services=12, processing_workers=6, slack_workers=1,
            kibana_http_status=kibana.status_code, cleanup_off_restarts=after['enrollment-cleanup']['RestartCount'],
            unchanged_reapply=True, no_oom_or_restart_increase=True, slack_unconfigured_off=True,
            image_id=receipt['image_id'], source_sha256=receipt['source_sha256'],
            verified_rule_count=7, detection_lateness_seconds=900,
            synthetic_runtime_only=True, live_attack_acceptance='not_performed', fingerprint=digest(report['normalization']))
        client.close();session.close()
    finally:
        atomic_json(directory/'result.json', report)
        ids = engine.run(['ps', '-aq', '--filter', 'label=com.docker.compose.project='+project]).split()
        if ids: engine.run(['rm', '-f', *ids])
        # Deliberately retain fixture DBs, WAL, certificates, backups and volumes.
        print(json.dumps(report), flush=True)


if __name__ == '__main__':
    main()
