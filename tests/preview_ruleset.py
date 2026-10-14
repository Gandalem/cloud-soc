"""Explicit loopback preview: real all-rule engines, synthetic ES and temporary DBs."""
from copy import deepcopy
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import sys
import tempfile
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from preview_logs import Preview
from test_ruleset_integration import fixture_for, run_at
from test_early_notices import Fixture
from cloud_soc.detection.profiles import RULE_IDS
from cloud_soc.detection.telemetry import RUNS
from cloud_soc.portal.operations import Operations, alert_row
from cloud_soc.portal.detection_history import project
from cloud_soc.portal.dashboard_widgets import catalog, TEMPLATES, template
from cloud_soc.portal.dashboards import DashboardStore


def build(folder):
    hits = []
    for identifier in RULE_IDS:
        for hit in fixture_for(identifier).hits:
            hit['_id'] += '-' + identifier
            hit['_source']['organization']['id'] = 'isolated-' + identifier.lower()
            hit['_source']['cloud_soc']['provenance']['raw']['id'] += '-' + identifier
            hits.append(hit)
    fixture = Fixture(hits)
    run_at(fixture, folder / 'pipeline.sqlite', 230)
    records = [project(body) for (index, _), body in fixture.docs.items() if index == RUNS and body['state'] == 'committed']
    empty = Fixture([])
    run_at(empty, folder / 'empty.sqlite', 230)
    empty_records = [project(body) for (index, _), body in empty.docs.items() if index == RUNS and body['state'] == 'committed']
    incomplete = deepcopy(hits)
    for hit in incomplete:
        hit['_source']['organization'].pop('id')
    missing = Fixture(incomplete)
    run_at(missing, folder / 'missing.sqlite', 230)
    missing_records = [project(body) for (index, _), body in missing.docs.items() if index == RUNS and body['state'] == 'committed']
    histories = [([records, empty_records, missing_records][i % 3])[i] for i in range(14)]
    store = deepcopy(fixture.docs)
    for hit in hits:
        row = hit['_source']
        store[(hit['_index'], hit['_id'])] = row
        raw = row['cloud_soc']['provenance']['raw']
        store[(raw['index'], raw['id'])] = {'organization': row['organization'], '@timestamp': row['@timestamp']}
    dashboards = DashboardStore(folder / 'dashboards.sqlite')
    value = dashboards.mutate('synthetic', 'admin', {'revision': 0, 'action': 'create', 'name': '전체 룰 격리 검증', 'template': 'security'})
    layout = value['dashboards'][0]['layout']
    for widget in layout['widgets']:
        if widget['type'] == 'alerts':
            widget['config']['limit'] = 50
    value = dashboards.mutate('synthetic', 'admin', {'revision': value['revision'], 'action': 'save', 'id': value['selected_id'], 'layout': layout})
    value = dashboards.mutate('synthetic', 'admin', {'revision': value['revision'], 'action': 'default', 'id': value['selected_id']})
    return fixture, store, histories, dashboards, value


class RulesPreview(Preview):
    def do_GET(self):
        parsed = urlsplit(self.path)
        values = parse_qs(parsed.query)
        alerts = {key: body for (index, key), body in self.store.items() if index == 'security-alerts'}
        rows = [alert_row({'_id': key, '_source': body}) for key, body in alerts.items()]
        now = '2026-10-14T02:00:00Z'
        pipeline = {'state': 'success', 'checkpoint': now, 'last_success': now,
                    'coverage': {'state': 'observed'}, 'detector': {'state': 'success', 'last_success': now,
                    'detection': ','.join(RULE_IDS)}}
        if parsed.path == '/api/auth/me':
            return self.json({'mode': 'basic', 'role': 'admin', 'user': 'SYNTHETIC-ISOLATED'})
        if parsed.path == '/api/dashboards':
            return self.json({**self.dashboards.collection('synthetic', 'admin'), 'catalog': catalog('admin'),
                              'templates': [{'id': key, 'name': value[0],
                                             'layout': template(key, 'admin')} for key, value in TEMPLATES.items()]})
        if parsed.path == '/api/operations/status':
            return self.json(pipeline)
        if parsed.path == '/api/operations':
            empty = {'state': 'ok', 'count': 0, 'rows': [], 'buckets': [], 'statuses': []}
            sections = {key: deepcopy(empty) for key in ('intake', 'processing', 'quality', 'alerts')}
            sections['alerts'].update(count=len(rows), rows=rows)
            sections['pipeline'] = pipeline
            return self.json({'start': values.get('start', [now])[0], 'end': values.get('end', [now])[0], 'sections': sections})
        if parsed.path == '/api/detection/history':
            return self.json({'state': 'ok', 'rows': self.histories, 'next': None})
        if parsed.path == '/api/alerts/detail':
            reader = Operations(self.fixture.client)
            with patch.object(reader, 'get', side_effect=lambda index, key, fields: self.store.get((index, key))):
                body = reader.detail([(key, vals[0]) for key, vals in values.items()])
            return self.reply(200, body if isinstance(body, bytes) else body.encode(), 'application/json')
        if parsed.path == '/api/cases':
            return self.json({'rows': [], 'counts': {'total': 0, 'open': 0, 'investigating': 0, 'unassigned': 0}, 'has_next': False})
        if parsed.path == '/api/alerts/notices':
            return self.json({'state': 'ok', 'rows': [], 'next': None})
        if parsed.path == '/api/logs':
            return self.json({'rows': [], 'data_state': 'no_index', 'next_cursor': None})
        name = parsed.path.lstrip('/')
        path = ROOT / 'prototype' / name
        if name and ('/' not in name or name == 'assets/mark.svg') and path.is_file() and path.suffix in ('.html', '.js', '.css', '.svg'):
            types = {'.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml'}
            body = path.read_bytes()
            if path.suffix == '.html':
                body = body.replace(b'<main id="main"', '<p role="status">전체 14개 룰 합성 격리 시험 · 운영 데이터 아님</p><main id="main"'.encode())
            return self.reply(200, body, types[path.suffix])
        return self.reply(404, b'Not found', 'text/plain')

    def json(self, body):
        return self.reply(200, json.dumps(body).encode(), 'application/json')


if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='cloud-soc-isolated-rules-') as temp:
        fixture, store, histories, dashboards, _ = build(Path(temp))
        RulesPreview.fixture, RulesPreview.store = fixture, store
        RulesPreview.histories, RulesPreview.dashboards = histories, dashboards
        print('Synthetic all-rule preview only: http://127.0.0.1:8796/dashboard.html', flush=True)
        ThreadingHTTPServer(('127.0.0.1', 8796), RulesPreview).serve_forever()
