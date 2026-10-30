#!/usr/bin/env python3
"""Explicitly provision dedicated real scenario intake. Never print credentials."""
import argparse
import base64
import json
import os
from pathlib import Path
import ssl
from urllib.error import HTTPError
from urllib.request import Request, build_opener, ProxyHandler, HTTPSHandler

INDEX = 'soc-host-raw-security-scenarios-local-v1'
PIPELINE = 'soc-security-scenarios-local-receipt-v1'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--es-url', default='https://192.168.1.159:9200')
    p.add_argument('--ca-file', required=True, type=Path)
    p.add_argument('--password-file', required=True, type=Path)
    p.add_argument('--key-file', required=True, type=Path)
    a = p.parse_args()
    if not a.es_url.startswith('https://'):
        raise ValueError('HTTPS required')
    # Exclusive reservation prevents accidental overwrite or duplicate key issuance.
    fd = os.open(a.key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as out:
        auth = base64.b64encode(b'elastic:' + a.password_file.read_bytes().strip()).decode()
        opener = build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context(cafile=str(a.ca_file))))
        def api(method, path, body=None, missing=False):
            req = Request(a.es_url.rstrip('/') + path, method=method,
                          data=json.dumps(body).encode() if body is not None else None,
                          headers={'Authorization': 'Basic ' + auth, 'Content-Type': 'application/json'})
            try:
                with opener.open(req, timeout=30) as response:
                    return json.load(response)
            except HTTPError as error:
                if missing and error.code == 404:
                    return None
                raise RuntimeError('Elasticsearch HTTP ' + str(error.code)) from None
        pipeline = {'processors': [
            {'set': {'field': 'event.ingested', 'value': '{{{_ingest.timestamp}}}', 'override': True}},
            {'set': {'field': 'labels.log_source', 'value': 'security_scenario', 'override': True}},
        ]}
        old = api('GET', '/_ingest/pipeline/' + PIPELINE, missing=True)
        if old is None:
            api('PUT', '/_ingest/pipeline/' + PIPELINE, pipeline)
        elif old[PIPELINE].get('processors') != pipeline['processors']:
            raise ValueError('Existing pipeline differs; preserved')
        old = api('GET', '/' + INDEX, missing=True)
        if old is None:
            api('PUT', '/' + INDEX, {'settings': {'number_of_shards': 1, 'number_of_replicas': 0,
                'index.final_pipeline': PIPELINE}, 'mappings': {'dynamic': False, 'properties': {
                    '@timestamp': {'type': 'date'},
                    'organization': {'properties': {'id': {'type': 'keyword'}}},
                    'host': {'properties': {'id': {'type': 'keyword'}}},
                    'service': {'properties': {'name': {'type': 'keyword'}}},
                    'labels': {'properties': {'log_source': {'type': 'keyword'}}},
                    'user': {'properties': {'name': {'type': 'keyword'}}},
                    'source': {'properties': {'ip': {'type': 'ip'}}},
                    'destination': {'properties': {'ip': {'type': 'ip'}}},
                    'security_scenario': {'type': 'object', 'dynamic': False, 'properties': {
                        'schema': {'type': 'keyword'}, 'kind': {'type': 'keyword'},
                        'action': {'type': 'keyword'}, 'outcome': {'type': 'keyword'}}},
                    'event': {'properties': {'ingested': {'type': 'date'}, 'id': {'type': 'keyword'},
                                             'action': {'type': 'keyword'}, 'outcome': {'type': 'keyword'}}}}}})
        elif old[INDEX]['settings']['index'].get('final_pipeline') != PIPELINE:
            raise ValueError('Existing index differs; preserved')
        key = api('POST', '/_security/api_key', {'name': 'soc-real-nine-scenarios', 'expiration': '30d',
            'role_descriptors': {'scenario_writer': {'cluster': [], 'indices': [
                {'names': [INDEX], 'privileges': ['create_doc']}]}}})
        out.write(key['encoded'] + '\n')
        out.flush()
        os.fsync(out.fileno())
    print('Scenario intake prepared; protected writer key written; expires in 30 days; collectors not started')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Intake preparation stopped: ' + type(error).__name__ + '; existing files preserved; no automatic reissue')
        raise SystemExit(1)
