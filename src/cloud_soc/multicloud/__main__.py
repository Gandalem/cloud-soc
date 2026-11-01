"""Run one isolated source per process: python -m cloud_soc.multicloud collect ..."""
import argparse
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import re
import signal
import threading

from cloud_soc.elastic.client import create_elasticsearch_client
from .collectors import AWS, Naver, receive_azure
from .storage import Sink, State, install


def load(path, identifier):
    data = json.loads(Path(path).read_text())
    sources = data['sources']
    ids = [s['id'] for s in sources]
    if len(ids) != len(set(ids)):
        raise ValueError('Duplicate source id')
    scope = next(s for s in sources if s['id'] == identifier)
    for key in ('id', 'organization', 'account'):
        if not isinstance(scope[key], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', scope[key]):
            raise ValueError('Invalid source scope')
    if scope['provider'] not in ('aws', 'azure', 'naver'):
        raise ValueError('Unsupported cloud provider')
    from datetime import datetime
    if datetime.fromisoformat(scope['start'].replace('Z', '+00:00')).utcoffset() is None:
        raise ValueError('Timezone required')
    return scope


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['install', 'collect'])
    parser.add_argument('--config', default='config/multicloud.example.json')
    parser.add_argument('--source')
    parser.add_argument('--state-dir', default='state/multicloud')
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    es = create_elasticsearch_client()
    state, collector, lock = None, None, None
    try:
        if args.command == 'install':
            install(es)
            return
        scope = load(args.config, args.source)
        sink = Sink(es, scope)
        # The process lock protects ownership while ES network I/O occurs.
        import portalocker
        directory = Path(args.state_dir)
        directory.mkdir(parents=True, exist_ok=True)
        lock = portalocker.Lock(str(directory / (scope['id'] + '.lock')), timeout=0)
        lock.acquire()
        if scope['provider'] == 'azure':
            receive_azure(scope, sink)
            return
        state = State(directory / (scope['id'] + '.sqlite'), scope)
        collector = {'aws': AWS, 'naver': Naver}[scope['provider']](scope)
        stopped = threading.Event()
        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, lambda *_: stopped.set())
        failures = 0
        while not stopped.is_set():
            try:
                before = (state.get('watermark'), state.get('naver_late_watermark_v1'))
                collector.poll(scope, state, sink)
                after = (state.get('watermark'), state.get('naver_late_watermark_v1'))
                failures = 0
                now = datetime.now(timezone.utc).isoformat()
                state.put('last_attempt', now)
                state.put('poll_state', 'processed' if after != before else 'waiting')
                if after != before:
                    state.put('last_success', now)
                state.put('last_error', '')
                delay = 30
            except Exception as exc:
                # Never print SDK errors, URLs, raw records, or credentials.
                failures += 1
                state.put('last_attempt', datetime.now(timezone.utc).isoformat())
                state.put('poll_state', 'failed')
                state.put('last_error', type(exc).__name__)
                logging.error('source=%s collection_failed type=%s checkpoint_preserved', scope['id'], type(exc).__name__)
                delay = min(300, 5 * 2 ** min(failures, 6))
            stopped.wait(delay)
    finally:
        if collector:
            collector.close()
        if state:
            state.close()
        if lock:
            lock.release()
        es.close()


if __name__ == '__main__':
    main()
