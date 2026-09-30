"""Explicit loopback-only Filebeat rejection fixture; never an installed service."""
import argparse
from datetime import datetime, timezone
import http.server
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]


class ElasticFixture(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, body):
        raw = json.dumps(body).encode()
        self.send_response(200)
        self.send_header('X-Elastic-Product', 'Elasticsearch')
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        self.reply({'version': {'number': '9.5.2', 'build_flavor': 'default'},
                    'cluster_name': 'isolated-fixture', 'license': {'status': 'active', 'type': 'basic'}})

    def do_POST(self):
        size = int(self.headers.get('Content-Length', 0))
        if not 0 < size <= 1048576:
            self.send_error(400)
            return
        rows = self.rfile.read(size).splitlines()
        items = []
        for n in range(0, len(rows), 2):
            operation = next(iter(json.loads(rows[n])))
            items.append({operation: {'_index': 'synthetic', '_id': 'synthetic', 'status': 400,
                'error': {'type': 'document_parsing_exception', 'reason': 'Limit of total fields [1000] has been exceeded'}}})
        self.reply({'errors': True, 'items': items})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--filebeat', type=Path, required=True)
    args = parser.parse_args()
    assert args.filebeat.is_file()
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), ElasticFixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix='p0c18-format-', dir=ROOT / 'state') as temporary:
            root = Path(temporary)
            logs = root / 'logs'
            logs.mkdir()
            event = {'@timestamp': datetime.now(timezone.utc).isoformat(),
                     'winlog': {'channel': 'Application', 'provider_name': 'Cloud-SOC-Synthetic', 'record_id': 42},
                     'event': {'code': '1000'}, 'message': 'FORMAT_CANARY', 'password': 'FORMAT_CANARY'}
            fixture = root / 'fixture.ndjson'
            fixture.write_text(json.dumps(event) + '\n', encoding='utf-8')
            config = {'filebeat.inputs': [{'type': 'filestream', 'id': 'p0c18-format-fixture',
                'paths': [str(fixture)], 'prospector.scanner.fingerprint.length': 64,
                'parsers': [{'ndjson': {'target': ''}}]}],
                'processors': [{'script': {'lang': 'javascript', 'file': str(ROOT / 'deploy/agents/privacy.js')}}],
                'output.elasticsearch': {'hosts': [f'http://127.0.0.1:{server.server_port}'],
                    'index': 'synthetic', 'compression_level': 0, 'bulk_max_size': 1},
                'setup.ilm.enabled': False, 'setup.template.enabled': False,
                'logging.to_files': True, 'logging.to_stderr': False, 'logging.level': 'info',
                'logging.files': {'path': str(logs), 'name': 'filebeat'},
                'logging.event_data.files': {'path': str(logs), 'name': 'filebeat-events-data'}}
            config_path = root / 'filebeat.yml'
            config_path.write_text(json.dumps(config), encoding='utf-8')
            process = subprocess.Popen([str(args.filebeat.resolve()), '-c', str(config_path),
                '--path.home', str(args.filebeat.resolve().parent), '--path.config', str(root),
                '--path.data', str(root / 'data'), '--path.logs', str(logs)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + 25
            found = False
            while time.monotonic() < deadline and process.poll() is None:
                found = any('Cannot index event' in p.read_text(encoding='utf-8') for p in logs.glob('*.ndjson'))
                if found:
                    break
                time.sleep(.2)
            process.terminate()
            process.wait(timeout=10)
            process = None
            assert found, 'Synthetic rejection diagnostic was not observed.'
            framework = Path(os.environ['WINDIR']) / 'Microsoft.NET/Framework64/v4.0.30319'
            exe = root / 'evidence-format.exe'
            result = subprocess.run([str(framework / 'csc.exe'), '/noconfig', '/nologo', '/target:exe', '/platform:x64', '/main:EvidenceTests',
                *[f'/reference:{framework / name}' for name in ('System.dll', 'System.Core.dll', 'System.Web.Extensions.dll')],
                f'/out:{exe}', str(ROOT / 'deploy/agents/discovery-native.cs'),
                str(ROOT / 'deploy/agents/tests/rejection-evidence-tests.cs')], capture_output=True, timeout=30)
            assert result.returncode == 0, 'Native fixture build failed.'
            result = subprocess.run([str(exe), '--format-root', str(root)], capture_output=True, timeout=15)
            if result.returncode:
                print(result.stdout.decode('utf-8', errors='replace'))
                shapes = []
                for path in logs.glob('*.ndjson'):
                    for line in path.read_text(encoding='utf-8').splitlines():
                        row = json.loads(line)
                        message = row.get('message', '')
                        if 'Cannot index event' not in message:
                            continue
                        shape = {'logger': row.get('log.logger'), 'modern_quoted_json': message.startswith("Cannot index event '{"),
                                 'legacy_fields': 'Fields:{' in message, 'status_400': "' (status=400):" in message,
                                 'outer_keys': sorted(row), 'event_object': isinstance(row.get('event'), dict)}
                        if message.startswith("Cannot index event '{"):
                            payload = message[len("Cannot index event '"):]
                            data, end = json.JSONDecoder().raw_decode(payload)
                            shape['suffix_character_codes'] = [ord(c) for c in payload[end:end+18]]
                            shape.update({'data_keys': sorted(data), 'fraction_digits': len(data.get('@timestamp', '').split('.')[1].split('Z')[0]) if '.' in data.get('@timestamp', '') else 0,
                                'winlog_keys': sorted(data.get('winlog', {})), 'event_keys': sorted(data.get('event', {}))})
                        shapes.append(shape)
                print(json.dumps({'synthetic_diagnostic_shapes': shapes}))
            assert result.returncode == 0, 'Actual diagnostic parser verification failed.'
            print('Filebeat 9.5.2 synthetic 400 -> protected projection/HMAC capture: passed. No installed agent or central server changed.')
    finally:
        if process is not None:
            process.terminate()
            process.wait(timeout=10)
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == '__main__':
    main()
