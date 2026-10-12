"""Loopback synthetic browser fixture using the real P5 engine and evidence API."""
from copy import deepcopy
import json
from http.server import ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from preview_logs import Preview, ROOT
from test_attack_detection import RULES, attack_one, aws, iam, audit
from test_intake_detection import client_for
from cloud_soc.detection.engine import detect_events
from cloud_soc.main import make_alert_id, build_security_alert
from cloud_soc.portal.operations import Operations, alert_row

EVENTS = attack_one() + [aws(i) for i in range(20)] + [iam(), audit()]
DETECTIONS = detect_events(EVENTS, list(RULES.values()))
ALERTS = {make_alert_id(d): build_security_alert(d) for d in DETECTIONS}
ROWS = [alert_row({'_id': identifier, '_source': source}) for identifier, source in ALERTS.items()]
READER = Operations(client_for([]))


class AttackPreview(Preview):
    def do_GET(self):
        parsed = urlsplit(self.path)
        values = parse_qs(parsed.query)
        if parsed.path == '/api/auth/me':
            return self.reply(200, b'{"mode":"basic","role":"admin","user":"SYNTHETIC-PREVIEW"}', 'application/json')
        if parsed.path == '/api/cases':
            return self.reply(200, b'{"rows":[],"counts":{"total":0,"open":0,"investigating":0,"unassigned":0},"has_next":false}', 'application/json')
        if parsed.path == '/api/operations':
            start, end = values['start'][0], values['end'][0]
            section = {'state': 'ok', 'count': 0, 'rows': [], 'statuses': [], 'buckets': []}
            sections = {k: deepcopy(section) for k in ('intake', 'processing', 'alerts', 'quality')}
            sections['alerts'].update(count=3, rows=ROWS)
            sections['pipeline'] = {'state': 'success', 'last_success': end, 'checkpoint': end,
                'detector': {'state': 'success', 'detection': 'AUTH-001,ATTACK-01,ATTACK-02,ATTACK-03'}}
            return self.reply(200, json.dumps({'start': start, 'end': end, 'sections': sections}).encode(), 'application/json')
        if parsed.path == '/api/alerts/detail':
            identifier = values.get('id', [''])[0]
            source = ALERTS.get(identifier)
            if source is None:
                return self.reply(404, b'{}', 'application/json')
            # This fixture makes no assertion about an existing ES raw document.
            if 'evidence' in values:
                return self.reply(200, b'{"evidence":{"state":"raw_missing_or_expired"}}', 'application/json')
            with patch.object(READER, 'get', return_value=source):
                data = READER.detail([('id', identifier)])
            return self.reply(200, data if isinstance(data, bytes) else data.encode(), 'application/json')
        assets = {'/index.html': 'text/html', '/operations.js': 'text/javascript', '/operations.css': 'text/css',
            '/styles.css': 'text/css', '/agents.css': 'text/css', '/auth-client.js': 'text/javascript', '/shell.js': 'text/javascript',
            '/shell.css': 'text/css', '/cases.js': 'text/javascript', '/cases.css': 'text/css', '/assets/mark.svg': 'image/svg+xml'}
        if parsed.path in assets:
            data = (ROOT / 'prototype' / parsed.path.lstrip('/')).read_bytes()
            if parsed.path == '/index.html':
                data = data.replace(b'<main id="main"', '<p role="status">합성 UI 시험 · 운영 데이터 아님</p><main id="main"'.encode())
            return self.reply(200, data, assets[parsed.path])
        if parsed.path == '/favicon.ico':
            return self.reply(204, b'', 'image/x-icon')
        return self.reply(404, b'Not found', 'text/plain')


if __name__ == '__main__':
    print('Synthetic preview only: http://127.0.0.1:8772/index.html', flush=True)
    ThreadingHTTPServer(('127.0.0.1', 8772), AttackPreview).serve_forever()
