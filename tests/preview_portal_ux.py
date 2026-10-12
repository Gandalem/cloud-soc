"""Loopback UX fixture: synthetic data, temporary stores, real portal sessions."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import uuid
from unittest.mock import Mock, patch

from flask import jsonify, request
from werkzeug.serving import make_server
from werkzeug.security import generate_password_hash

from cloud_soc.portal.app import create_app
from cloud_soc.portal.collection_health import project as project_health
from cloud_soc.portal.log_query import project_list_hit
from cloud_soc.portal.security_detail import security_detail
from cloud_soc.portal.operations import analysis_coverage
from preview_logs import FIXTURES, ROOT
from preview_p5_attacks import ALERTS, ROWS, READER

URL = 'http://127.0.0.1:8773'


def build(directory, *, session_login=True):
    def now():
        return datetime.now(timezone.utc).isoformat()
    password_hash = generate_password_hash('synthetic-password', method='pbkdf2:sha256:1000')
    users = directory / 'users.json'
    users.write_text(json.dumps({role: {'role': role, 'password_hash': password_hash}
                                for role in ('admin', 'analyst', 'viewer')}), encoding='utf-8')
    users.chmod(0o600)
    keys = {}
    issuer = Mock()
    issuer.info.return_value = {'cluster_name': 'SYNTHETIC-UX'}

    def issue(**kwargs):
        identifier = 'fixture-' + uuid.uuid4().hex
        row = {'id': identifier, 'api_key': 'SYNTHETIC-NOT-A-CREDENTIAL',
               'expiration': int((datetime.now(timezone.utc) + timedelta(days=1)).timestamp() * 1000),
               'invalidated': False, 'metadata': kwargs.get('metadata', {}),
               'role_descriptors': kwargs.get('role_descriptors', {})}
        keys[identifier] = row
        return row

    def revoke(**kwargs):
        ids = kwargs.get('ids', [])
        for identifier in ids:
            keys[identifier]['invalidated'] = True
        return {'invalidated_api_keys': ids, 'previously_invalidated_api_keys': [], 'error_count': 0}

    issuer.security.create_api_key.side_effect = issue
    issuer.security.invalidate_api_key.side_effect = revoke
    issuer.security.get_api_key.side_effect = lambda **kw: {'api_keys': [keys[kw['id']]]}
    monitor = Mock()
    def read_document(**kwargs):
        if kwargs['index'] == 'security-alerts':
            return {'_source': ALERTS[kwargs['id']]}
        return deepcopy(next(hit for hit in FIXTURES if hit['_index'] == kwargs['index'] and hit['_id'] == kwargs['id']))
    monitor.get.side_effect = read_document
    app = create_app({'STATE_DIR': directory, 'AGENT_SOURCE': ROOT / 'deploy/agents',
                      'CA_BYTES': b'SYNTHETIC PUBLIC CA - not a valid certificate',
                      'PUBLIC_URL': URL, 'ENDPOINT': 'https://soc.example.invalid:9200',
                      'ADMIN_USER': 'admin', 'ADMIN_HASH': password_hash,
                      'USERS_FILE': str(users) if session_login else None, 'ENROLLMENT_ENABLED': True}, issuer=issuer, monitor=monitor)
    app.config['TESTING'] = True
    scenario = {'value': 'populated'}
    original_portal = app.view_functions['portal']

    def portal():
        response = original_portal()
        data = response.get_json()
        for package in data['packages']:
            package['enrollment_protocol'] = 1
        if scenario['value'] == 'empty':
            data['packages'] = []
        return jsonify(data)

    def control():
        if request.path == '/__fixture/scenario':
            value = request.args.get('value')
            if value not in ('populated', 'empty', 'error', 'blocked', 'catching_up'):
                return jsonify(error='Unknown fixture scenario'), 400
            scenario['value'] = value
            return jsonify(synthetic=True, scenario=value)
        return None

    app.before_request_funcs[None].insert(0, control)

    def wrap(function):
        def view(*args, **kwargs):
            if scenario['value'] == 'error':
                return jsonify(error='SYNTHETIC-UNAVAILABLE'), 503
            return function(*args, **kwargs)
        return view

    def operations():
        end = request.args.get('end', now())
        start = request.args.get('start', now())
        empty = {'state': 'ok', 'count': 0, 'rows': [], 'statuses': [], 'buckets': []}
        sections = {k: deepcopy(empty) for k in ('intake', 'processing', 'alerts', 'quality')}
        if scenario['value'] != 'empty':
            for name, count in (('intake', 1240), ('processing', 1210), ('alerts', 3), ('quality', 2)):
                # Synthetic shape only; never infer a live trend from these values.
                finish = datetime.fromisoformat(end.replace('Z', '+00:00'))
                weights = [4, 5, 6, 10, 12, 16, 13, 8, 7, 8, 6, 5]
                counts = [count * weight // sum(weights) for weight in weights]
                counts[-1] += count - sum(counts)
                sections[name].update(count=count, buckets=[
                    {'time': (finish - timedelta(minutes=(11 - i) * 5)).isoformat(), 'count': amount}
                    for i, amount in enumerate(counts)])
            sections['alerts']['rows'] = ROWS
            sections['processing']['statuses'] = [{'key': 'normalized', 'doc_count': 1200}, {'key': 'unsupported', 'doc_count': 10}]
        sections['pipeline'] = {'state': 'success', 'last_success': end, 'checkpoint': end,
                                'detector': {'state': 'success', 'last_success': end, 'detection': 'AUTH-001,ATTACK-01,ATTACK-02,ATTACK-03'}}
        if scenario['value'] in ('blocked', 'catching_up'):
            sections['alerts'] = deepcopy(empty)
            sections['pipeline']['detector'].update(detection='AUTH-001', latest_input_count=0)
            sections['pipeline']['state'] = 'failed' if scenario['value'] == 'blocked' else 'running'
            sections['pipeline']['checkpoint'] = (datetime.now(timezone.utc) - timedelta(minutes=44)).isoformat()
            if scenario['value'] == 'catching_up':
                sections['pipeline']['progress'] = {'state': 'catching_up', 'processed': 200000, 'range_complete': False}
        sections['pipeline']['coverage'] = analysis_coverage(sections['pipeline'], sections['pipeline']['detector'])
        return jsonify(start=start, end=end, sections=sections)

    def operations_status():
        return jsonify(operations().get_json()['sections']['pipeline'])

    def alert_detail():
        source = ALERTS.get(request.args.get('id'))
        if source is None:
            return jsonify(error='Synthetic alert not found'), 404
        if 'evidence' in request.args:
            return jsonify(evidence={'state': 'raw_missing_or_expired'})
        with patch.object(READER, 'get', return_value=source):
            return app.response_class(READER.detail(request.args.items()), mimetype='application/json')

    def logs():
        rows = [project_list_hit(hit) for hit in FIXTURES]
        for row in rows:
            row['received_at'] = now()
        for name, field in (('host', 'host_name'), ('collector', 'collector'), ('os', 'os')):
            if request.args.get(name):
                rows = [row for row in rows if row.get(field) == request.args[name]]
        if scenario['value'] == 'empty':
            rows = []
        return jsonify(contract_version=1, rows=rows, filters={
            'start': request.args.get('start', now()), 'end': request.args.get('end', now()),
            'time_basis': request.args.get('time_basis', 'ingested')}, raw_access='restricted', next_cursor=None, total=None)

    def log_detail():
        hit = next((h for h in FIXTURES if h['_id'] == request.args.get('id') and h['_index'] == request.args.get('index')), None)
        if hit is None:
            return jsonify(error='Synthetic log missing'), 404
        return jsonify(contract_version=1, row=project_list_hit(hit), raw_access='restricted', security=security_detail(hit['_source']))

    def status():
        rows = [{'status': 'recent', 'host_name': 'SYNTHETIC-WINDOWS', 'host_ips': ['192.0.2.10'],
                 'os': 'Windows', 'organization': 'school', 'agent_id': 'synthetic-' + kind,
                 'agent_type': kind, 'version': '9.5.2', 'last_received': now(), 'last_event': now(), 'documents': count}
                for kind, count in [('filebeat', 750), ('packetbeat', 490)]]
        return jsonify(checked_at=now(), basis='server_ingestion', agents=[] if scenario['value'] == 'empty' else rows,
                       next_cursor=None, unidentified_documents=0)

    def health():
        source = {'host': {'name': 'SYNTHETIC-WINDOWS'}, 'event': {'ingested': now()},
                  'cloud_soc': {'discovery': {'schema': 1, 'generated_at': now(), 'policy_version': 2,
                     'selected': 28, 'excluded': 4, 'errors': 1, 'total': 33,
                     'sources': [{'id': 'a' * 64, 'status': 'selected'}, {'id': 'b' * 64, 'status': 'unreadable'}]}}}
        metrics = {'schema': 1, 'state': 'observed', 'counter_scope': 'logged_interval_delta', 'sampled_at': now(),
                   'interval_seconds': 30, 'scan_partial': True, 'queue_events': 120, 'queue_bytes': 1048576,
                   'queue_pct': .001, 'queue_max_bytes': 1000000000, 'output_total': 125, 'output_acked': 125}
        source['cloud_soc']['discovery'].update(collector_metrics=metrics, network_collector_metrics=deepcopy(metrics))
        row = project_health(source, {'agent_id': 'synthetic-worker', 'organization': 'school'}, datetime.now(timezone.utc))
        return jsonify(rows=[] if scenario['value'] == 'empty' else [row], next_cursor=None)

    def detection_history():
        row = {'rule': {'id': 'ATTACK-02'}, '@timestamp': now(), 'state': 'committed',
               'counts': {'input_events': 20, 'matched': 20, 'not_matched': 0, 'unknown': 0, 'excluded': 0,
                          'evaluated_events': 20, 'detection_matches': 1, 'alerts_created': 1, 'alerts_existing': 0, 'late': 0, 'policy_excluded': 0}}
        if scenario['value'] in ('blocked', 'catching_up') and request.args.get('kind', 'runs') == 'runs':
            rows = []
            for i in range(12):
                quiet = deepcopy(row)
                quiet.update(run_id='fixture-run-' + str(i), rule={'id': 'AUTH-001'},
                    phases=['committed', 'evaluated'], **{'@timestamp': (datetime.now(timezone.utc) - timedelta(minutes=i)).isoformat()})
                quiet['counts'] = {key: 0 for key in quiet['counts']}
                rows.append(quiet)
            return jsonify(state='ok', rows=rows, next=None)
        if request.args.get('kind') == 'exclusions':
            row = {'rule': {'id': 'ATTACK-02'}, '@timestamp': now(), 'reason': 'missing_group_fields',
                   'missing_fields': ['user.id'], 'normalized': {'index': 'soc-normalized-v1', 'id': 'synthetic-reference'}}
        return jsonify(state='ok', rows=[] if scenario['value'] == 'empty' else [row], next=None)

    def reprocessing():
        rows = [{'id': 'fixture-normalized', 'adapter': 'fixture-parser', 'parse_status': 'partial',
                 'timestamp': now(), 'ingested': now(), 'host': 'SYNTHETIC-LINUX', 'action': 'sudo',
                 'time_basis': 'fixture', 'outcome': 'unknown', 'timezone_corrected': True,
                 'raw': {'index': 'soc-host-raw-fixture', 'id': 'fixture-source'}}]
        if scenario['value'] == 'empty':
            rows = []
        return jsonify(rows=rows, total=len(rows), recognized=0, partial=len(rows), timezone_corrected=len(rows))

    for endpoint, view in {'operations_summary': operations, 'operations_status': operations_status, 'alert_detail': alert_detail,
                           'portal': portal,
                           'agent_status': status, 'collection_health': health, 'logs': logs,
                           'log_detail': log_detail, 'reprocessing_history': reprocessing,
                           'detection_history': detection_history}.items():
        # Validate endpoint names: fixtures must not silently leave a real ES path.
        if endpoint not in app.view_functions:
            raise ValueError('Unknown preview endpoint: ' + endpoint)
        app.view_functions[endpoint] = wrap(view)

    @app.after_request
    def banner(response):
        if response.mimetype == 'text/html':
            response.direct_passthrough = False
            html = response.get_data(as_text=True)
            import re
            html = re.sub(r'(<main\b[^>]*>)', r'\1<p class="inline-note" role="status">합성 화면 검증 · 운영 데이터 아님</p>', html, count=1)
            response.set_data(html)
        return response

    cases = app.extensions['cases']
    identifier = ROWS[0]['id']
    cases.create({'title': 'SSH 인증 공격 조사', 'alert_id': identifier, 'priority': 'high'}, 'admin', str(uuid.uuid4()), lambda _: ROWS[0])
    app.extensions['packages'].create({'name': 'school-windows', 'os': 'windows', 'organization': 'school', 'network': True, 'description': 'Synthetic UX fixture'})
    return app


if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='cloud-soc-ux-fixture-') as directory:
        application = build(Path(directory))
        print('Synthetic only: ' + URL + '/login (admin / synthetic-password)', flush=True)
        make_server('127.0.0.1', 8773, application, threaded=True).serve_forever()
