"""python -m cloud_soc.aws.cloudwatch: offline validation unless --run is explicit."""

import argparse
from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import sys
import time

from cloud_soc.aws.__main__ import endpoint, protected_key
from cloud_soc.aws.collector import CollectionError, ElasticsearchSink, State
from cloud_soc.aws.cloudtrail import _object, _reject_constant
from cloud_soc.aws.log_collector import LogSettings, run_cycle


def main(argv=None):
    parser = argparse.ArgumentParser(description='Read explicitly configured CloudWatch service logs; default: offline')
    parser.add_argument('--config', required=True)
    parser.add_argument('--state', default='state/aws-service-logs.sqlite')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--run', action='store_true')
    modes.add_argument('--status', action='store_true')
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--interval', type=int, default=300)
    parser.add_argument('--max-pages', type=int, default=100)
    parser.add_argument('--es-url')
    parser.add_argument('--ca-file')
    parser.add_argument('--api-key-file')
    args = parser.parse_args(argv)
    state = None
    try:
        config = Path(args.config)
        if config.stat().st_size > 32768:
            raise CollectionError('invalid_cloudwatch_config')
        settings = LogSettings.parse(json.loads(config.read_text(encoding='utf-8'), object_pairs_hook=_object,
                                               parse_constant=_reject_constant))
        if not 60 <= args.interval <= 3600 or not 1 <= args.max_pages <= 1000 or (args.once and not args.run):
            raise CollectionError('invalid_run_options')
        if not args.run and not args.status:
            print(json.dumps({'status': 'config_valid', 'sources': list(settings.regions),
                              'aws_contacted': False, 'es_contacted': False}))
            return 0
        if args.status:
            path = Path(args.state)
            if path.is_symlink() or not path.is_file():
                raise CollectionError('state_not_initialized')
            with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True)) as db:
                row = db.execute('SELECT fingerprint FROM identity WHERE id=1').fetchone()
                if not row or row[0] != settings.fingerprint():
                    raise CollectionError('state_scope_mismatch')
                keys = ('source', 'floor', 'watermark', 'last_attempt', 'last_success', 'error', 'created', 'duplicates')
                rows = [dict(zip(keys, r)) for r in db.execute('SELECT region,floor,watermark,last_attempt,last_success,error,created,duplicates FROM progress ORDER BY region')]
            print(json.dumps({'sources': rows, 'live_ingestion_verified': False}))
            return 0
        url = endpoint(args.es_url)
        if not args.ca_file or not Path(args.ca_file).is_file() or not args.api_key_file:
            raise CollectionError('missing_tls_or_key_file')
        key = protected_key(args.api_key_file)
        import boto3
        from botocore.config import Config
        from elasticsearch import Elasticsearch
        sdk = Config(connect_timeout=5, read_timeout=20, retries={'mode': 'standard', 'total_max_attempts': 3},
                     ignore_configured_endpoint_urls=True)
        session = boto3.Session()
        regions = sorted({s.region for s in settings.sources})
        sts = session.client('sts', region_name=regions[0], config=sdk)
        clients = {region: session.client('logs', region_name=region, config=sdk) for region in regions}
        state = State(args.state, settings, now=datetime.now(timezone.utc))
        with Elasticsearch(url, ca_certs=args.ca_file, api_key=key, request_timeout=20, max_retries=0) as es:
            sink = ElasticsearchSink(es)
            while True:
                try:
                    results = run_cycle(settings, state, sts, clients, sink, max_pages=args.max_pages)
                except CollectionError as error:
                    results = [{'status': 'error', 'code': str(error)}]
                print(json.dumps({'sources': results}), flush=True)
                if args.once:
                    return 1 if any(r['status'] == 'error' for r in results) else 0
                time.sleep(args.interval)
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        code = str(error) if isinstance(error, CollectionError) else 'configuration_or_runtime_failed'
        print(json.dumps({'status': 'error', 'code': code}), file=sys.stderr)
        return 1
    finally:
        if state is not None:
            state.close()


if __name__ == '__main__':
    raise SystemExit(main())
