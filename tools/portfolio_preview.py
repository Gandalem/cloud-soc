"""Loopback-only synthetic demo portal with production detail and SQLite cases.

python tools/portfolio_preview.py --port 8770; never expose or deploy this helper.
"""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
from http.server import ThreadingHTTPServer
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'tests')]
from preview_cases import Preview
import test_portal
from cloud_soc.portal.app import create_app
from cloud_soc.portal.operations import Operations
from portfolio_eval import demo


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8770)
    args = parser.parse_args()
    samples = demo()
    documents = {}
    for sample in samples:
        raw, norm = sample['raw'], deepcopy(sample['normalized'])
        meta = norm.pop('_cloud_soc_meta')
        documents[(raw['_index'], raw['_id'])] = raw['_source']
        documents[(meta['index'], meta['document_id'])] = norm
        documents[('security-alerts', sample['alert_id'])] = sample['alert']
    reader = Operations(Mock())
    original_detail = reader.detail
    reader.get = lambda index, doc_id, fields: documents.get((index, doc_id))

    def detail(_reader, pairs):
        return original_detail(pairs)

    def summary(_reader, pairs):
        values = dict(pairs)
        rows = [json.loads(original_detail([('id', sample['alert_id'])]))['alert'] for sample in samples]
        def part(count):
            return {'state': 'ok', 'count': count, 'rows': [], 'statuses': [],
                    'buckets': [{'time': values['start'], 'count': count}]}
        sections = {name: part(count) for name, count in [('intake', 3), ('processing', 3), ('alerts', 3), ('quality', 0)]}
        sections['alerts']['rows'] = rows
        sections['processing']['statuses'] = [{'key': 'normalized', 'doc_count': 3}]
        sections['pipeline'] = {'state': 'success', 'last_success': values['end'], 'checkpoint': values['end'],
                                'detector': {'state': 'success', 'detection': 'AUTH-001,cloud', 'last_success': values['end']}}
        return json.dumps({'start': values['start'], 'end': values['end'], 'sections': sections}).encode()

    class PortfolioPreview(Preview):
        def dispatch(self):
            if self.path.split('?')[0] == '/api/auth/me':
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"mode":"basic","user":"SYNTHETIC DEMO","role":"admin"}')
                return
            super().dispatch()
        do_GET = do_POST = do_PATCH = dispatch

    with tempfile.TemporaryDirectory(prefix='soc-portfolio-preview-') as directory:
        settings = {'STATE_DIR': Path(directory), 'AGENT_SOURCE': ROOT / 'deploy/agents',
                    'CA_BYTES': test_portal.CA, 'PUBLIC_URL': 'http://localhost',
                    'ENDPOINT': 'https://example.test:9200', 'ADMIN_USER': 'admin', 'ADMIN_HASH': test_portal.HASH}
        with patch('cloud_soc.portal.operations.Operations.detail', detail), patch('cloud_soc.portal.operations.Operations.summary', summary):
            server = ThreadingHTTPServer(('127.0.0.1', args.port), PortfolioPreview)
            server.app = create_app(settings, issuer=Mock())
            print('Synthetic only; no Elasticsearch. http://127.0.0.1:' + str(args.port), flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()


if __name__ == '__main__':
    main()
