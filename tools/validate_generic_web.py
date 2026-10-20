"""Two real Nginx sites -> Filebeat -> resident workers, only on disposable ES.

Run prepare before starting tests/fixtures/generic-web.compose.yaml; then run
exercise on that Docker network with the fixture mounted read/write. No reset,
production deployment, Slack channel send or implicit collector installation.
"""
import argparse
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import requests

from elasticsearch import Elasticsearch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from cloud_soc.acceptance import inspect
from cloud_soc.detection.setup import prepare as prepare_detection, ROLE as DETECTOR_ROLE
from cloud_soc.portal.log_query import LogReader
from cloud_soc.portal.operations import Operations
from cloud_soc.portal.site_agents import profile
from cloud_soc.portal.site_context import context
from cloud_soc.processing.contract import NORMALIZED
from cloud_soc.processing.setup import prepare as prepare_processing, ROLE as NORMALIZER_ROLE

ORG, HOST, RULE = 'generic-fixture', 'generic-web-fixture', 'WEB-SITE-404-001'


def private(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as output:
        output.write(value)


def prepare(client, args):
    global ORG
    target = Path(args.fixture)
    if target.exists():
        raise ValueError('Use a new isolated fixture directory')
    target.mkdir(mode=0o700)
    for name in ('logs', 'beat-data'):
        (target / name).mkdir(mode=0o755)
    start = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
    raw = 'soc-host-raw-generic-' + os.urandom(8).hex()
    ORG = 'generic-' + raw.rsplit('-', 1)[-1]
    pipeline = raw + '-receipt'
    client.ingest.put_pipeline(id=pipeline, processors=[
        {'set': {'field': 'event.ingested', 'value': '{{{_ingest.timestamp}}}'}},
        {'set': {'field': 'organization.id', 'value': ORG}}])
    client.indices.create(index=raw, settings={'number_of_replicas': 0, 'index.default_pipeline': pipeline},
        mappings={'dynamic': False, 'properties': {
            '@timestamp': {'type': 'date'}, 'event': {'properties': {'ingested': {'type': 'date'}}},
            **{k: {'properties': {'id': {'type': 'keyword'}, 'name': {'type': 'keyword'}}} for k in ('organization', 'host', 'service')},
            'labels': {'properties': {'log_source': {'type': 'keyword'}}}}})
    prepare_processing(client, update_role=False)
    prepare_detection(client)
    key = client.security.create_api_key(name='generic-web-collector', expiration='1h', role_descriptors={
        'collector': {'cluster': ['monitor'], 'indices': [{'names': [raw], 'privileges': ['create_doc']}]}})
    private(target / 'collector-key-id', key['id'])
    sites = [{'id': f'site-{letter}', 'name': f'Public site {letter.upper()}', 'server_type': 'nginx',
              'log_path': f'/fixture-logs/site-{letter}.log', 'start_at': start} for letter in ('a', 'b')]
    compiled = profile({'os': 'ubuntu', 'system': False, 'network': False, 'sites': sites})
    config = {'filebeat.inputs': compiled['web_inputs'], 'processors': [
        {'add_fields': {'target': 'organization', 'fields': {'id': ORG}}},
        {'add_fields': {'target': 'host', 'fields': {'id': HOST, 'name': HOST, 'os': {'type': 'linux'}}}},
        {'script': {'lang': 'javascript', 'file': '/fixture/privacy.js', 'tag_on_exception': '_privacy_error'}},
        {'drop_event': {'when': {'contains': {'tags': '_privacy_error'}}}}],
        'output.elasticsearch': {'hosts': [args.es_url], 'api_key': key['id'] + ':' + key['api_key'],
            'ssl.certificate_authorities': ['/fixture/ca.crt'], 'ssl.verification_mode': 'full',
            'index': raw, 'allow_older_versions': True},
        'setup.ilm.enabled': False, 'setup.template.enabled': False,
        'logging.level': 'warning', 'queue.mem.flush.timeout': '1s'}
    private(target / 'filebeat.yml', json.dumps(config))
    private(target / 'manifest.json', json.dumps({'start': start, 'raw_index': raw, 'organization': ORG}))
    shutil.copyfile(args.ca_file, target / 'ca.crt')
    for script in ('site-privacy.js', 'privacy.js'):
        shutil.copyfile(ROOT / 'deploy/agents' / script, target / script)
    nginx = ['pid /tmp/nginx.pid;', 'error_log /dev/stderr warn;', 'events {}', 'http {',
             'client_body_temp_path /tmp/client;', 'proxy_temp_path /tmp/proxy;',
             'fastcgi_temp_path /tmp/fastcgi;', 'uwsgi_temp_path /tmp/uwsgi;', 'scgi_temp_path /tmp/scgi;']
    for number, letter in enumerate(('a', 'b')):
        nginx += [f'server {{ listen {8080 + number}; access_log /fixture-logs/site-{letter}.log combined;',
                  'location / { return 404; } location = /health { return 200 "ok"; } }']
    (target / 'nginx.conf').write_text('\n'.join([*nginx, '}']) + '\n', encoding='utf-8')
    (target / 'nginx.conf').chmod(0o644)


def exercise(client, args, report):
    global ORG
    target = Path(args.fixture)
    manifest = json.loads((target / 'manifest.json').read_text())
    ORG = manifest['organization']
    raw, start = manifest['raw_index'], manifest['start']
    keys, processes, handles = [], [], []

    def check(name, passed):
        report['checks'].append({'name': name, 'passed': bool(passed)})
        if not passed:
            raise AssertionError(name)

    def wait_for(predicate, timeout=180):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if any(process.poll() is not None for process in processes):
                raise RuntimeError('Resident worker stopped; inspect private fixture logs')
            value = predicate()
            if value:
                return value
            time.sleep(2)
        raise TimeoutError('Timed out waiting for the generic pipeline')

    def request(site, count, path='/CANARY_GENERIC_NEVER_SEND'):
        for number in range(count):
            with requests.get(f'http://web:{8080 + site}{path}-{number}', timeout=5, allow_redirects=False) as response:
                code = response.status_code
            check(f'http_site_{site}_{len(report["checks"])}', code == 404)

    def alerts():
        return client.search(index='security-alerts', query={'bool': {'filter': [
            {'term': {'organization.id': ORG}}, {'term': {'rule.id': RULE}}]}}, size=10)['hits']['hits']

    def processed(count):
        client.indices.refresh(index=[raw, NORMALIZED, 'security-alerts'])
        return client.count(index=NORMALIZED, query={'term': {'organization.id': ORG}})['count'] >= count

    commands = []
    try:
        for name, role in (('normalizer', NORMALIZER_ROLE), ('detector', DETECTOR_ROLE)):
            role = deepcopy(role)
            if name == 'normalizer':
                role['indices'][0]['names'] = [raw]
            key = client.security.create_api_key(name='generic-web-' + name, expiration='1h', role_descriptors={name: role})
            keys.append(key['id'])
            private(target / (name + '.key'), key['encoded'])
            command = [sys.executable, '-m', 'cloud_soc.processing' if name == 'normalizer' else 'cloud_soc.detection',
                       '--run', '--start', start, '--state', str(target / (name + '.sqlite')),
                       '--es-url', args.es_url, '--ca-file', args.ca_file,
                       '--api-key-file', str(target / (name + '.key')), '--interval', '10']
            command += ['--web-site-v2-start', start, '--window-minutes', '60'] if name == 'normalizer' else [
                '--additional-rules', RULE, '--lateness-seconds', '60']
            commands.append((name, command))
        def launch():
            for name, command in commands:
                log = open(target / (name + '.log'), 'a', encoding='utf-8')
                handles.append(log)
                processes.append(subprocess.Popen(command, stdout=log, stderr=log))
        def stop():
            for process in processes:
                if process.poll() is None:
                    process.terminate()
            for process in processes:
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=5)
            processes.clear()
        launch()
        request(0, 10); request(1, 10)
        wait_for(lambda: processed(20))
        # Wait for detector to pass the latest normalization receipt, not just intake.
        def caught_up():
            reader = Operations(client)
            status = reader.worker_status('detector-additional')
            newest = client.search(index=NORMALIZED, query={'term': {'organization.id': ORG}},
                size=1, sort=[{'cloud_soc.normalized_at': 'desc'}])['hits']['hits'][0]['_source']['cloud_soc']['normalized_at']
            return status.get('checkpoint', '') >= newest
        wait_for(caught_up)
        check('ten_per_site_do_not_combine', len(alerts()) == 0)
        request(0, 10)
        wait_for(lambda: processed(30) and len(alerts()) == 1)
        check('site_a_independent_alert', alerts()[0]['_source']['service']['id'] == 'site-a')
        request(1, 10)
        wait_for(lambda: processed(40) and len(alerts()) == 2)
        check('site_b_independent_alert', {h['_source']['service']['id'] for h in alerts()} == {'site-a', 'site-b'})
        first_ids = {h['_id'] for h in alerts()}
        wait_for(caught_up)
        check('raw_canary_removed_before_ingestion', all('CANARY_GENERIC_NEVER_SEND' not in json.dumps(h['_source'])
            for h in client.search(index=raw, size=100)['hits']['hits']))
        reader = LogReader(client, secret='disposable-generic-fixture', principal='fixture', organizations=(ORG,))
        page = json.loads(reader.page([('site', 'site-a')]))
        check('site_filter_reads_only_site_a', len(page['rows']) == 20 and all(r['site_id'] == 'site-a' for r in page['rows']))
        for hit in alerts():
            result = inspect(client, alert_id=hit['_id'], organization=ORG, rule_id=RULE,
                             since=start, raw_indices=[raw])
            check('stored_pipeline_acceptance_' + hit['_source']['service']['id'], result['pipeline_evidence'] == 'passed')
            scoped = Operations(client, organizations=(ORG,))
            live = json.loads(context(scoped, [('id', hit['_id'])]))
            check('fresh_context_' + hit['_source']['service']['id'], live['count'] == 20 and not live['detection_evidence'])
        # New non-404 traffic changes fresh context, never the saved evidence list.
        with requests.get('http://web:8080/health', timeout=5, allow_redirects=False) as response:
            check('ordinary_health_request', response.status_code == 200)
        wait_for(lambda: processed(41))
        a = next(h for h in alerts() if h['_source']['service']['id'] == 'site-a')
        check('context_updates_without_snapshot', json.loads(context(Operations(client, organizations=(ORG,)), [('id', a['_id'])]))['count'] == 21)
        stop()
        baseline = client.count(index=NORMALIZED, query={'term': {'organization.id': ORG}})['count']
        launch()
        time.sleep(22)
        check('same_state_restart_workers_alive', all(process.poll() is None for process in processes))
        check('same_state_restart_no_duplicate_alert', {h['_id'] for h in alerts()} == first_ids)
        check('same_state_restart_no_duplicate_normalization', client.count(index=NORMALIZED, query={'term': {'organization.id': ORG}})['count'] == baseline)
        stop()
        report.update(raw_index=raw, raw_count=41, normalized_count=baseline, alerts=2,
                      browser='unverified', slack_channel_receipt='unverified', host_installation='unverified')
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate(); process.wait(timeout=15)
        for handle in handles:
            handle.close()
        keys.append((target / 'collector-key-id').read_text().strip())
        client.security.invalidate_api_key(ids=keys)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('prepare', 'exercise'))
    for name in ('fixture', 'es-url', 'ca-file', 'password-file'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    report = {'scope': 'disposable_nginx_filebeat_and_resident_workers', 'checks': [], 'passed': False}
    try:
        with Elasticsearch(args.es_url, basic_auth=('elastic', Path(args.password_file).read_text().strip()),
                           ca_certs=args.ca_file, request_timeout=15, max_retries=0) as client:
            if client.info()['cluster_name'] != 'cloud-soc-integration-20261008':
                raise ValueError('Only the disposable TLS integration cluster is permitted')
            if args.phase == 'prepare':
                prepare(client, args)
                print('generic_web_fixture_prepared; private credentials omitted')
                return 0
            exercise(client, args, report)
            report['passed'] = True
        return 0
    except Exception as error:
        report['error_type'] = type(error).__name__
        print('generic_web_validation_failed; inspect private fixture logs; payloads and credentials omitted')
        return 1
    finally:
        if args.phase == 'exercise':
            private(Path(args.fixture) / 'acceptance.json', json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
