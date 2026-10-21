"""Opt-in managed worker. No existing service, deployment policy or key is changed."""
import argparse
import json
from pathlib import Path
import time

from elasticsearch import Elasticsearch

from cloud_soc.aws.__main__ import endpoint, protected_key
from cloud_soc.detection.managed import ManagedWorker
from cloud_soc.processing.mall_runtime import private_json


def main(argv=None):
    parser = argparse.ArgumentParser(description='Versioned rule worker')
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--library', required=True, type=Path)
    parser.add_argument('--es-url', required=True)
    parser.add_argument('--ca-file', required=True, type=Path)
    parser.add_argument('--api-key-file', required=True)
    parser.add_argument('--interval', type=int, default=5)
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args(argv)
    try:
        if not 1 <= args.interval <= 30 or not args.ca_file.is_file():
            raise ValueError('worker_options_invalid')
        worker = ManagedWorker(args.library, private_json(args.config), source_id=endpoint(args.es_url))
        with Elasticsearch(endpoint(args.es_url), api_key=protected_key(args.api_key_file),
                           ca_certs=str(args.ca_file), verify_certs=True,
                           request_timeout=15, max_retries=0, retry_on_timeout=False) as client:
            while True:
                result = worker.run(client)
                print(json.dumps(result), flush=True)
                if args.once:
                    return int(bool(result['failed']))
                time.sleep(args.interval)
    except KeyboardInterrupt:
        return 130
    except Exception:
        print(json.dumps({'state': 'failed', 'code': 'managed_worker_failed'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
