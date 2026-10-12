"""Transport paths and failure boundaries for large concrete index scopes."""
from copy import deepcopy
from contextlib import closing
import sqlite3
import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from elastic_transport import ApiResponseMeta, HttpHeaders, NodeConfig
from elasticsearch import Elasticsearch

from cloud_soc.elastic.index_scope import index_batches
from cloud_soc.processing.worker import scan, run_once
from test_processing import START, NOW, fixture


def names():
    return [f'soc-host-raw-synthetic-{i:03d}-2026.10.12' for i in range(233)]


def client_for_scope():
    client = Mock()
    client.options.return_value = client
    client.indices.resolve_index.return_value = {'indices': [{'name': name} for name in names()]}
    client.field_caps.return_value = {'fields': {'event.ingested': {'date': {}}}}
    client.open_point_in_time.return_value = {'id': 'pit'}
    client.search.return_value = {'hits': {'hits': []}}
    client.bulk.side_effect = lambda **kw: {'items': [
        {'create': {'status': 201}} for _ in range(len(kw['operations']) // 2)]}
    return client


class WorkerBatchTests(unittest.TestCase):
    def test_real_sdk_encoded_paths_stay_below_server_http_line_limit(self):
        meta = ApiResponseMeta(200, '1.1', HttpHeaders({'x-elastic-product': 'Elasticsearch'}),
                               0, NodeConfig('http', 'localhost', 9200))
        paths, observed = [], []

        def response(method, target, **kwargs):
            paths.append(target)
            if '_resolve/index' in target:
                return meta, {'indices': [{'name': name} for name in names()]}
            if '_field_caps' in target:
                return meta, {'fields': {'event.ingested': {'date': {}}}}
            if method == 'POST' and '/_pit' in target:
                observed.append(target)
                return meta, {'id': str(len(observed))}
            if '/_search' in target:
                return meta, {'hits': {'hits': []}}
            return meta, {'succeeded': True}

        with Elasticsearch('http://localhost:9200') as es, patch.object(es.transport, 'perform_request', side_effect=response):
            self.assertEqual(list(scan(es, START, '2026-09-22T01:05:00Z')), [])
        self.assertGreater(len(observed), 1)
        self.assertTrue(all(len(path.encode()) + len('POST  HTTP/1.1\r\n') < 4096 for path in paths))
        encoded = ','.join(names())
        self.assertGreater(len(encoded), 4096)

    def test_all_mappings_checked_before_first_write(self):
        client = client_for_scope()
        client.field_caps.side_effect = [client.field_caps.return_value, {'fields': {'event.ingested': {'keyword': {}}}}]
        with self.assertRaisesRegex(RuntimeError, 'receipt_mapping_missing'):
            list(scan(client, START, START))
        client.open_point_in_time.assert_not_called()

    def test_each_batch_read_once_rotated_pits_closed(self):
        client = client_for_scope()
        batches = list(index_batches(names()))
        pages = []
        for i, batch in enumerate(batches):
            hit = fixture()
            hit.update(_id=str(i), _index=batch[0], sort=[i])
            pages.extend([{'pit_id': f'rotated-{i}', 'hits': {'hits': [hit]}}, {'hits': {'hits': []}}])
        client.search.side_effect = pages
        hits = list(scan(client, START, START))
        self.assertEqual(len(hits), len(batches))
        self.assertEqual([c.kwargs['index'] for c in client.open_point_in_time.call_args_list], batches)
        self.assertEqual([c.kwargs['id'] for c in client.close_point_in_time.call_args_list],
                         [f'rotated-{i}' for i in range(len(batches))])

    def test_later_batch_failure_retains_checkpoint_and_can_replay(self):
        client = client_for_scope()
        sample = fixture()
        sample.update(_index=names()[0], sort=[0])
        client.search.side_effect = [{'hits': {'hits': [sample]}}, {'hits': {'hits': []}},
                                     {'pit_id': 'failed-pit', 'timed_out': True}]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'state.sqlite'
            with self.assertRaisesRegex(RuntimeError, 'checkpoint retained'):
                run_once(client, path, START, now=NOW)
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(db.execute('SELECT count(*) FROM state').fetchone()[0], 0)
            self.assertEqual(client.close_point_in_time.call_args.kwargs['id'], 'failed-pit')
            client.search.side_effect = None
            self.assertEqual(run_once(client, path, START, now=NOW)['state'], 'success')

    def test_global_page_limit_does_not_reset_per_batch(self):
        client = client_for_scope()
        sample = deepcopy(fixture()); sample['sort'] = [1]
        client.search.side_effect = [{'hits': {'hits': [sample]}}, {'hits': {'hits': []}},
                                     {'hits': {'hits': [sample]}}]
        with self.assertRaisesRegex(RuntimeError, 'window_page_limit'):
            list(scan(client, START, START, max_pages=2))
        self.assertEqual(client.search.call_count, 3)

    def test_invalid_names_and_duplicate_scope(self):
        self.assertEqual(list(index_batches(['soc-host-raw-a', 'soc-host-raw-a'])), [['soc-host-raw-a']])
        for name in ('*', 'a,b', '', 'a/b', 'x' * 256):
            with self.assertRaises(ValueError): list(index_batches([name]))
        self.assertEqual(list(index_batches(['one', 'two'], byte_budget=3)), [['one'], ['two']])

    def test_cleanup_does_not_mask_read_error(self):
        client = client_for_scope()
        client.search.return_value = {'pit_id': 'rotated', 'timed_out': True}
        client.close_point_in_time.side_effect = RuntimeError('cleanup')
        with self.assertRaisesRegex(RuntimeError, 'partial_search'):
            list(scan(client, START, START))
        client.close_point_in_time.assert_called_once_with(id='rotated')

    def test_partial_pit_open_is_closed_without_reading(self):
        client = client_for_scope()
        client.open_point_in_time.return_value = {'id': 'partial', '_shards': {'failed': 1}}
        with self.assertRaisesRegex(RuntimeError, 'partial_search'):
            list(scan(client, START, START))
        client.search.assert_not_called()
        client.close_point_in_time.assert_called_once_with(id='partial')
