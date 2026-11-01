"""Run inside the existing normalizer: copied SQLite + read-only ES facade.
No event/status/bulk writes; no original cursor changes; temporary PITs only.
"""
import ast
import json
from pathlib import Path
import signal
import sqlite3
import sys
import tempfile
from elasticsearch import Elasticsearch
from cloud_soc.processing import worker
from cloud_soc.processing.errors import error_code
from cloud_soc.deployment.contract import command, options

class WriteBoundary(BaseException):
    pass

class ReadOnlyClient:
    def __init__(self, client):
        self.client = client
        self.pits = set()
        self.pending_indices = set()
        self.bulk_batches = 0
        self.document_count = 0
    def options(self, **kwargs):
        self.client = self.client.options(**kwargs)
        return self
    @property
    def indices(self):
        # Worker uses only resolve_index on this interface.
        class IndexReads:
            def resolve_index(_, **kwargs):
                return self.client.indices.resolve_index(**kwargs)
        return IndexReads()
    def field_caps(self, **kwargs):
        return self.client.field_caps(**kwargs)
    def index(self, **kwargs):
        if kwargs.get('index') != worker.STATUS or kwargs.get('id') != 'normalizer':
            raise WriteBoundary()
        return {}  # Suppress telemetry writes too.
    def bulk(self, **kwargs):
        self.pending_indices.update(row['create']['_index'] for row in kwargs['operations'][::2])
        # Exercise exactly the serializers selected by this runtime, without transport.
        serializer = self.client.transport.serializers.get_serializer('application/json')
        for document in kwargs['operations']:
            serializer.dumps(document)
        self.bulk_batches += 1
        self.document_count += len(kwargs['operations']) // 2
        return {'items': [{'create': {'status': 201}} for _ in kwargs['operations'][::2]]}
    def open_point_in_time(self, **kwargs):
        result = self.client.open_point_in_time(**kwargs)
        self.pits.add(result['id'])
        return result
    def search(self, **kwargs):
        result = self.client.search(**kwargs)
        if result.get('pit_id'):
            self.pits.discard(kwargs['pit']['id'])
            self.pits.add(result['pit_id'])
        return result
    def close_point_in_time(self, **kwargs):
        if kwargs['id'] in self.pits:
            result = self.client.close_point_in_time(**kwargs)
            self.pits.discard(kwargs['id'])
            return result
        return {}  # Never close an existing worker's PIT.
    def close_owned_pits(self):
        for pit in list(self.pits):
            try:
                self.close_point_in_time(id=pit)
            except Exception:
                pass


def main():
    signal.alarm(90)
    contract = json.loads(Path('/run/runtime/contract.json').read_text())
    row = contract['workers']['normalizer']
    if row['module'] != 'cloud_soc.processing':
        raise ValueError('unexpected_worker_module')
    args = options(command(row['module'], row['options']), row['module'])
    source = Path(args['--state'])
    if not source.is_file() or source.is_symlink():
        raise ValueError('checkpoint_unavailable')
    # Only source-code string literals may be printed as a known error detail.
    literals = set()
    for name in ('worker.py', 'continuation.py', 'contract.py'):
        for node in ast.walk(ast.parse((Path(worker.__file__).parent / name).read_text())):
            if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
                for item in node.exc.args:
                    if isinstance(item, ast.Constant) and isinstance(item.value, str):
                        literals.add(item.value)
    events = []
    def trace(frame, event, arg):
        if event == 'exception' and '/cloud_soc/' in frame.f_code.co_filename:
            kind, value, _ = arg
            if kind.__name__ not in ('StopIteration', 'GeneratorExit'):
                safe = value.args[0] if value.args and type(value.args[0]) is str and value.args[0] in literals else None
                events.append({'type':kind.__name__, 'file':Path(frame.f_code.co_filename).name,
                               'function':frame.f_code.co_name, 'line':frame.f_lineno,
                               'known_detail':safe})
                del events[:-16]
        return trace
    with tempfile.TemporaryDirectory(prefix='normalizer-read-probe-') as tmp:
        target = Path(tmp)/'checkpoint.sqlite'
        with sqlite3.connect(source.as_uri()+'?mode=ro', uri=True, timeout=2) as original:
            with sqlite3.connect(target) as copied:
                original.backup(copied)
                if copied.execute("SELECT 1 FROM sqlite_master WHERE name='scan_progress'").fetchone():
                    saved = copied.execute('SELECT body FROM scan_progress WHERE id=1').fetchone()
                    if saved:
                        meta = json.loads(saved[0]);meta['pit']=None;meta['after']=None
                        copied.execute('UPDATE scan_progress SET body=? WHERE id=1',(json.dumps(meta),))
        target.chmod(0o600)
        from cloud_soc.aws.__main__ import protected_key
        with Elasticsearch(args['--es-url'],api_key=protected_key(args['--api-key-file']),
                           ca_certs=args['--ca-file'], request_timeout=12, max_retries=0) as es:
            facade=ReadOnlyClient(es)
            result={'original_checkpoint_changed':False,'elasticsearch_document_writes':False,
                    'probe_page_limit':25,'copied_scan_uses_new_pit':True}
            try:
                sys.settrace(trace)
                answer=worker.run_once(facade,target,args['--start'],max_pages=25,
                    window_minutes=int(args.get('--window-minutes',5)),
                    ssh_v2_start=args.get('--linux-ssh-v2-start'),web_site_v2_start=args.get('--web-site-v2-start'))
                result['probe_result']='dry_read_completed';result['state']=answer['state'];result['counts']=answer.get('counts')
            except WriteBoundary:
                result['probe_result']='reached_bulk_boundary_no_write'
            except Exception as failure:
                result['probe_result']='failed';result['code']=error_code(failure)
            finally:
                sys.settrace(None)
                facade.close_owned_pits()
            result['bulk_batches_serialized']=facade.bulk_batches
            result['documents_serialized']=facade.document_count
            result['bulk_responses_simulated']=True
            if facade.pending_indices:
                try:
                    grants=es.security.has_privileges(index=[{'names':sorted(facade.pending_indices),'privileges':['create_doc']}])
                    result['bulk_destination_create_doc_granted']=grants.get('has_all_requested')
                except Exception as failure:
                    result['privilege_probe_code']=error_code(failure)
            result['exception_locations']=events
            print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=='__main__':
    try:
        main()
    except Exception as failure:
        print(json.dumps({'probe_setup_failed':True,'type':type(failure).__name__,'code':error_code(failure)}))
        sys.exit(1)
