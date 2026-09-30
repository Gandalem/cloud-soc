"""Real standalone Filebeat -> loopback 400, using one approved synthetic OS reference."""
import argparse
import http.server
import json
from pathlib import Path
import subprocess
import threading
import time

from p0c18_filebeat_format_checks import ElasticFixture, ROOT


def run(root, filebeat):
    expected = json.loads((root / 'expected.json').read_text(encoding='utf-8-sig'))
    assert expected['channel'] == 'Application' and expected['provider'] == 'CloudSOCTest'
    assert expected['event_code'] == '1000' and expected['marker'].startswith('CLOUD_SOC_P0C18_')
    captured = []

    class Receiver(ElasticFixture):
        def do_POST(self):
            size = int(self.headers.get('Content-Length', 0))
            if not 0 < size <= 1048576:
                self.send_error(400)
                return
            rows = self.rfile.read(size).splitlines()
            items = []
            for n in range(0, len(rows), 2):
                operation = next(iter(json.loads(rows[n])))
                payload = json.loads(rows[n + 1])
                captured.append(payload)
                items.append({operation: {'_index': 'isolated-reference-fixture', '_id': 'fixture', 'status': 400,
                    'error': {'type': 'document_parsing_exception', 'reason': 'Explicit loopback-only rejection test'}}})
            self.reply({'errors': True, 'items': items})

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    process = None
    try:
        # Read exactly the benign OS record, not a JSON reconstruction with a harvest timestamp.
        xml = ('<QueryList><Query Id="0" Path="Application"><Select Path="Application">'
               f'*[System[EventRecordID={expected["record_id"]}]]</Select></Query></QueryList>')
        config = {'filebeat.inputs': [{'type': 'winlog', 'id': 'p0c18-os-reference-fixture',
            'xml_query': xml, 'include_xml': False}],
            'processors': [{'add_fields': {'target': 'agent', 'fields': {'id': expected['agent_id']}}},
                {'script': {'lang': 'javascript', 'file': str(ROOT / 'deploy/agents/privacy.js')}}],
            'output.elasticsearch': {'hosts': [f'http://127.0.0.1:{server.server_port}'],
                'index': 'isolated-reference-fixture', 'compression_level': 0, 'bulk_max_size': 1},
            'setup.ilm.enabled': False, 'setup.template.enabled': False,
            'logging.to_files': True, 'logging.to_stderr': False, 'logging.level': 'info',
            'logging.files': {'path': str(root / 'logs'), 'name': 'filebeat'},
            'logging.event_data.files': {'path': str(root / 'logs'), 'name': 'filebeat-events-data'}}
        config_path = root / 'filebeat.yml'
        config_path.write_text(json.dumps(config), encoding='utf-8')
        process = subprocess.Popen([str(filebeat), '-c', str(config_path), '--path.home', str(filebeat.parent),
            '--path.config', str(root), '--path.data', str(root / 'fixture-data'), '--path.logs', str(root / 'logs')],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and process.poll() is None:
            if any('Cannot index event' in p.read_text(encoding='utf-8') for p in (root / 'logs').glob('*.ndjson')):
                break
            time.sleep(.2)
        else:
            raise AssertionError('Loopback rejection diagnostic missing')
        process.terminate()
        process.wait(timeout=10)
        process = None
        assert len(captured) == 1 and captured[0]['agent']['id'] == expected['agent_id']
        assert captured[0]['winlog']['event_data']['param1'] == expected['marker']
        assert 'SYNTHETIC_PRIVATE_CANARY' not in json.dumps(captured[0])
        with (root / 'received-payload.json').open('x', encoding='utf-8') as output:
            json.dump(captured[0], output)
        print('Standalone Filebeat loopback 400 with actual synthetic OS reference: passed.')
    finally:
        if process is not None:
            process.terminate()
            process.wait(timeout=10)
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--filebeat', required=True, type=Path)
    args = parser.parse_args()
    run(args.root.resolve(), args.filebeat.resolve())
