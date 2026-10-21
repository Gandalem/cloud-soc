"""Real ModSecurity/CRS HTTP -> Filebeat -> site-scoped alert, disposable TLS ES only."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import urlencode
import requests

from elasticsearch import Elasticsearch

from validate_generic_web import prepare, private
from cloud_soc.acceptance import inspect
from cloud_soc.detection.setup import ROLE as DETECTOR_ROLE
from cloud_soc.portal.site_agents import profile
from cloud_soc.processing.setup import ROLE as NORMALIZER_ROLE
from cloud_soc.portal.operations import Operations
from cloud_soc.processing.contract import NORMALIZED

RULE = 'WEB-SITE-WAF-001'


def prepare_waf(client, args):
    prepare(client, args)
    target = Path(args.fixture)
    manifest = json.loads((target / 'manifest.json').read_text())
    config = json.loads((target / 'filebeat.yml').read_text())
    compiled = profile({'os': 'ubuntu', 'system': False, 'network': False, 'sites': [{
        'id': 'public-site', 'name': 'Generic public site', 'server_type': 'nginx',
        'log_path': '/fixture-logs/access.log', 'start_at': manifest['start'],
        'modsecurity': {'log_path': '/fixture-logs/waf.json', 'timezone': '+00:00'}}]})
    config['filebeat.inputs'] = [row for row in compiled['web_inputs'] if row['fields']['labels']['log_source'] == 'generic_modsecurity']
    (target / 'filebeat.yml').write_text(json.dumps(config))
    (target / 'logs/waf.json').touch(mode=0o666)
    (target / 'logs/waf.json').chmod(0o666)  # Synthetic private parent; image worker UID may differ.


def exercise(client, args, report):
    target = Path(args.fixture)
    manifest = json.loads((target / 'manifest.json').read_text())
    org, raw, start = (manifest[k] for k in ('organization', 'raw_index', 'start'))
    keys, processes, handles = [], [], []
    def check(name, passed):
        report['checks'].append({'name': name, 'passed': bool(passed)})
        if not passed:
            raise AssertionError(name)
    def wait_for(predicate):
        deadline = time.monotonic() + 210
        while time.monotonic() < deadline:
            if any(p.poll() is not None for p in processes):
                raise RuntimeError('Resident WAF worker stopped')
            if predicate():
                return
            time.sleep(2)
        raise TimeoutError('WAF pipeline timed out')
    try:
        for name, role in (('normalizer', NORMALIZER_ROLE), ('detector', DETECTOR_ROLE)):
            key = client.security.create_api_key(name='generic-waf-' + name, expiration='1h', role_descriptors={name: role})
            keys.append(key['id']); private(target / (name + '.key'), key['encoded'])
            command = [sys.executable, '-m', 'cloud_soc.processing' if name == 'normalizer' else 'cloud_soc.detection',
                '--run', '--start', start, '--state', str(target / (name + '.sqlite')), '--interval', '10',
                '--es-url', args.es_url, '--ca-file', args.ca_file, '--api-key-file', str(target / (name + '.key'))]
            command += ['--window-minutes', '60'] if name == 'normalizer' else ['--additional-rules', RULE, '--lateness-seconds', '60']
            handle = open(target / (name + '.log'), 'a', encoding='utf-8'); handles.append(handle)
            processes.append(subprocess.Popen(command, stdout=handle, stderr=handle))
        # Prove the controlled backend succeeds independently of WAF mode.
        with requests.get('http://web:8080/health', timeout=5, allow_redirects=False) as response:
            check('controlled_backend_200', response.status_code == 200)
        for number in range(3):
            uri = 'http://waf:8080/health?' + urlencode({'id': "1' OR '1'='1", 'marker': 'CANARY_GENERIC_WAF_' + str(number)})
            with requests.get(uri, timeout=10, allow_redirects=False) as response:
                status = response.status_code
            check('real_sqli_http_' + str(number), status == (200 if args.mode == 'DetectionOnly' else 403))
        def alerts():
            client.indices.refresh(index=[raw, NORMALIZED, 'security-alerts'])
            return client.search(index='security-alerts', size=10, query={'bool': {'filter': [
                {'term': {'organization.id': org}}, {'term': {'rule.id': RULE}}]}})['hits']['hits']
        wait_for(lambda: bool(alerts()))
        hits = alerts(); check('one_site_scoped_waf_alert', len(hits) == 1)
        alert = hits[0]
        assessment = alert['_source']['cloud_soc']['provenance']['assessment']['waf']
        check('engine_mode_preserved', assessment['engine_modes'] == [args.mode])
        check('sqli_metadata_present', '942100' in assessment['matched_rule_ids'])
        check('no_invented_application_verdict', assessment['application_outcome'] == 'not_established')
        source = client.search(index=raw, size=100)['hits']['hits']
        check('audit_payload_removed_before_queue', len(source) == 3 and all(
            'CANARY_GENERIC_WAF' not in json.dumps(h['_source']) and 'message' not in h['_source']
            for h in source))
        refs = alert['_source']['cloud_soc']['provenance']['evidence']
        check('three_distinct_requests', len(refs) == 3)
        acceptance = inspect(client, alert_id=alert['_id'], organization=org, rule_id=RULE, since=start, raw_indices=[raw])
        check('raw_normalized_hash_and_resident_worker_acceptance', acceptance['pipeline_evidence'] == 'passed')
        reader = Operations(client, organizations=(org,))
        check('portal_exact_waf_evidence', all(reader.evidence(ref, organization=org).get('integrity') == 'normalized_hash_verified' for ref in refs))
        report.update(mode=args.mode, checked_at=datetime.now(timezone.utc).isoformat(), raw_index=raw,
                      organization=org, alert_id=alert['_id'], raw_count=3, alerts=1,
                      engine_interruption=assessment['interruption_states'],
                      http_observation='backend_200_waf_200' if args.mode == 'DetectionOnly' else 'backend_200_waf_403',
                      slack_channel_receipt='unverified', host_installation='unverified')
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=5)
        for handle in handles:
            handle.close()
        keys.append((target / 'collector-key-id').read_text().strip())
        client.security.invalidate_api_key(ids=keys)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('prepare', 'exercise'))
    parser.add_argument('--mode', choices=('DetectionOnly', 'On'), required=True)
    for name in ('fixture', 'es-url', 'ca-file', 'password-file'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    report = {'scope': 'disposable_real_modsecurity_crs', 'checks': [], 'passed': False}
    try:
        with Elasticsearch(args.es_url, basic_auth=('elastic', Path(args.password_file).read_text().strip()),
                ca_certs=args.ca_file, request_timeout=15, max_retries=0) as client:
            if client.info()['cluster_name'] != 'cloud-soc-integration-20261008':
                raise ValueError('Only the disposable integration cluster is permitted')
            if args.phase == 'prepare':
                prepare_waf(client, args)
                print('generic_waf_fixture_prepared; credentials omitted')
            else:
                exercise(client, args, report)
                report['passed'] = True
        return 0
    except Exception as error:
        report['error_type'] = type(error).__name__
        print('generic_waf_validation_failed; inspect private fixture; no payloads or credentials printed')
        return 1
    finally:
        if args.phase == 'exercise':
            private(Path(args.fixture) / 'acceptance.json', json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
