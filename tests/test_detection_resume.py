"""Dense receipt windows, durable restart, expired PIT and transactional retry."""
from contextlib import closing
from copy import deepcopy
from datetime import timedelta
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

from elasticsearch import NotFoundError

from cloud_soc.detection.incremental import run_incremental, utc
from test_intake_detection import raw, normalized, client_for
from test_pipeline_reliability import api_error


class ResumeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'runtime.sqlite'
        self.base = utc(raw(0)['_source']['@timestamp'])
        self.hits = [normalized(raw(i)) for i in range(10)]
        for hit in self.hits:
            hit['_source']['cloud_soc']['normalized_at'] = (self.base + timedelta(seconds=10)).isoformat()
        self.client = client_for([])
        self.client.count.return_value = {'count': 0}
        self.client.field_caps.return_value = {'fields': {'cloud_soc.normalized_at': {'date': {}}}}
        self.pits, self.ordinal, self.ids = {}, 0, []
        self.client.open_point_in_time.side_effect = self.open
        self.client.search.side_effect = self.search
        self.client.close_point_in_time.side_effect = self.close
        self.writer = patch('cloud_soc.detection.incremental.save_security_alert', side_effect=self.write)
        self.writer.start(); self.addCleanup(self.writer.stop)

    def write(self, *args, **kwargs):
        key = kwargs['document_id']
        if key in self.ids:
            return {'result': 'existing'}
        self.ids.append(key)
        return {'result': 'created'}

    def open(self, **kwargs):
        self.ordinal += 1
        key = f'pit-{self.ordinal}'
        self.pits[key] = deepcopy(self.hits if self.ordinal == 1 else self.hits[::-1])
        return {'id': key, '_shards': {'failed': 0}}

    def search(self, **kwargs):
        key = kwargs['pit']['id']
        if key not in self.pits:
            raise api_error(404, NotFoundError)
        bounds = kwargs['query']['range']['cloud_soc.normalized_at']
        snapshot = [h for h in self.pits[key] if utc(bounds['gte']) <= utc(h['_source']['cloud_soc']['normalized_at']) < utc(bounds['lt'])]
        start = kwargs['search_after'][0] + 1 if kwargs.get('search_after') else 0
        page = deepcopy(snapshot[start:start + kwargs['size']])
        for number, hit in enumerate(page, start):
            hit['sort'] = [number]
        rotated = key + '-r'
        self.pits[rotated] = self.pits.pop(key)
        return {'pit_id': rotated, 'hits': {'hits': page}, '_shards': {'failed': 0}}

    def close(self, *, id):
        self.pits.pop(id, None)
        return {'succeeded': True}

    def cycle(self, seconds=140, budget=3, **kwargs):
        return run_incremental(self.client, state_path=self.path, start=self.base,
            now=self.base + timedelta(seconds=seconds), max_documents=budget, lateness_seconds=60, **kwargs)

    def stored(self):
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute('SELECT body FROM runtime').fetchone()
            return json.loads(row[0]) if row else None

    def spool(self):
        with closing(sqlite3.connect(self.path)) as db:
            if not db.execute("SELECT 1 FROM sqlite_master WHERE name='input_scan'").fetchone():
                return None, 0
            meta = db.execute('SELECT body FROM input_scan').fetchone()
            return (json.loads(meta[0]) if meta else None,
                    db.execute('SELECT count(*) FROM input_hits').fetchone()[0])

    def test_identical_receipt_restart_dense_window_finishes_and_matches_batch(self):
        for seconds, pending in ((140, 3), (200, 6), (260, 9)):
            result = self.cycle(seconds)
            self.assertEqual(result['input_pending'], pending)
            self.assertIsNone(self.stored())
            self.assertEqual(self.spool()[0]['end'], (self.base + timedelta(seconds=110)).isoformat())
        result = self.cycle(320)
        self.assertEqual(result['events'], 10)
        self.assertEqual(result['created'], 1)
        self.assertEqual(len(self.ids), 1)
        self.assertEqual(self.spool(), (None, 0))
        first_id = self.ids[0]
        self.path = self.path.with_name('unbounded.sqlite')
        self.assertEqual(self.cycle(140, budget=100)['existing'], 1)
        self.assertEqual(self.ids, [first_id])

    def test_expired_pit_reopens_fixed_range_skips_spooled_hits_after_reorder(self):
        self.cycle()
        self.pits.clear()
        self.assertEqual(self.cycle(200)['input_pending'], 6)
        self.pits.clear()
        self.assertEqual(self.cycle(260)['input_pending'], 9)
        self.pits.clear()
        self.assertEqual(self.cycle(320)['created'], 1)
        self.assertEqual(self.stored()['checkpoint'], (self.base + timedelta(seconds=110)).isoformat())
        self.assertFalse(self.pits)

    def test_committed_overlap_duplicates_do_not_consume_next_window_budget(self):
        self.cycle(budget=100)
        extra = normalized(raw(10))
        extra['_source']['cloud_soc']['normalized_at'] = (self.base + timedelta(seconds=120)).isoformat()
        self.hits.append(extra)
        self.assertEqual(self.cycle(210, budget=2)['events'], 1)
        self.assertEqual(len(self.ids), 1)

    def test_partial_shards_rollback_only_current_scan_and_close_rotated_pit(self):
        self.cycle()
        old = self.spool()
        self.client.search.side_effect = lambda **kw: {'pit_id': 'partial-rotated', 'timed_out': True}
        with self.assertRaisesRegex(RuntimeError, 'checkpoint retained'): self.cycle(200)
        self.assertEqual(self.spool(), old)
        self.client.close_point_in_time.assert_called_with(id='partial-rotated')
        self.client.search.side_effect = self.search
        self.pits.clear()
        self.assertEqual(self.cycle(260)['input_pending'], 6)

    def test_status_failure_keeps_read_position_not_false_complete(self):
        self.cycle()
        old = self.spool()
        self.client.index.side_effect = [None, RuntimeError('status unavailable'), None]
        with self.assertRaises(RuntimeError): self.cycle(200)
        self.assertEqual(self.spool(), old)
        self.assertIsNone(self.stored())
        self.client.index.side_effect = None
        self.assertEqual(self.cycle(260)['input_pending'], 6)

    def test_alert_failure_after_full_input_can_retry_without_checkpoint_loss(self):
        self.cycle(budget=9)
        old = self.spool()
        with patch('cloud_soc.detection.incremental.save_security_alert', side_effect=RuntimeError('write unavailable')):
            with self.assertRaises(RuntimeError): self.cycle(200)
        self.assertEqual(self.spool(), old)
        self.assertIsNone(self.stored())
        self.assertEqual(self.cycle(260)['created'], 1)

    def test_uncommitted_initial_scan_identity_cannot_change(self):
        self.cycle()
        old = self.spool()
        with self.assertRaises(ValueError): self.cycle(200, source_id='other-server')
        self.assertEqual(self.spool(), old)

    def test_active_capacity_is_explicit_recoverable_and_not_read_budget(self):
        self.cycle(budget=9)
        with self.assertRaises(RuntimeError): self.cycle(200, max_active_events=1)
        self.assertIsNone(self.stored())
        self.assertEqual(self.client.index.call_args.kwargs['document']['error'], 'active_state_limit')
        self.assertEqual(self.cycle(260, max_active_events=100)['events'], 10)

    def test_partial_open_closes_and_does_not_scan(self):
        self.client.open_point_in_time.side_effect = None
        self.client.open_point_in_time.return_value = {'id': 'partial', '_shards': {'failed': 1}}
        with self.assertRaises(RuntimeError): self.cycle()
        self.client.search.assert_not_called()
        self.client.close_point_in_time.assert_called_once_with(id='partial')

    @unittest.skipIf(os.name == 'nt', 'POSIX state permission validation')
    def test_existing_public_state_is_rejected_before_reading(self):
        self.cycle()
        self.path.chmod(0o644)
        self.client.search.reset_mock()
        with self.assertRaises(ValueError): self.cycle(200)
        self.client.search.assert_not_called()

    def test_limits_bad_references_and_stuck_cursor_fail_closed(self):
        for response in ({'hits': {'hits': [{'_index': 'foreign', '_id': 'bad', 'sort': [1]}]}},
                         {'hits': {'hits': [{**self.hits[0], 'sort': None}]}},
                         {'_shards': {'failed': 1}}):
            with self.subTest(response=response):
                self.client.search.side_effect = Mock(return_value=response)
                with self.assertRaises(RuntimeError): self.cycle()
                self.assertIsNone(self.stored())
        self.client.search.side_effect = self.search
        with patch('cloud_soc.detection.staging.MAX_STAGED', 2):
            with self.assertRaises(RuntimeError): self.cycle()
        self.assertEqual(self.spool()[1], 0)

    def test_native_reads_above_default_twenty_thousand_without_raising_capacity(self):
        original = deepcopy(self.hits[0])
        original['_source']['event']['outcome'] = 'success'
        self.hits = [{**deepcopy(original), '_id': str(i)} for i in range(20001)]
        self.assertEqual(self.cycle(budget=20000)['input_pending'], 20000)
        self.assertIsNone(self.stored())
        self.assertEqual(self.cycle(200, budget=20000)['events'], 20001)
        self.assertEqual(self.stored()['pending'], {})
