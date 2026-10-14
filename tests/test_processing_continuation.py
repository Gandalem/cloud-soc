"""Bounded production scans resume across cycles, crashes and PIT expiration."""
from copy import deepcopy
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock

from elasticsearch import NotFoundError

from cloud_soc.processing.worker import run_once
from test_processing import START, NOW, fixture
from test_worker_index_batches import client_for_scope


class ContinuationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'state.sqlite'
        self.client = client_for_scope()
        self.client.indices.resolve_index.return_value = {'indices': [{'name': 'soc-host-raw-test'}]}
        self.stored = {}

        def bulk(**kwargs):
            items = []
            for action, body in zip(kwargs['operations'][::2], kwargs['operations'][1::2]):
                assert set(action) == {'create'}
                key = tuple(action['create'][name] for name in ('_index', '_id'))
                if key in self.stored:
                    items.append({'create': {'status': 409, 'error': {'type': 'version_conflict_engine_exception'}}})
                else:
                    self.stored[key] = deepcopy(body); items.append({'create': {'status': 201}})
            return {'items': items}

        self.client.bulk.side_effect = bulk

    def page(self, first=0, size=200, pit='rotated'):
        hits = []
        for i in range(first, first + size):
            hit = fixture(); hit.update(_id=str(i), sort=[i]); hits.append(hit)
        return {'pit_id': pit, 'hits': {'hits': hits}}

    def checkpoint(self):
        with closing(sqlite3.connect(self.path)) as db:
            return db.execute('SELECT checkpoint FROM state').fetchall()

    def test_budget_is_not_a_permanent_window_limit_and_resume_survives_restart(self):
        self.client.search.side_effect = [self.page()]
        first = run_once(self.client, self.path, START, now=NOW, max_pages=1)
        self.assertEqual(first['state'], 'running')
        self.assertEqual(first['progress']['processed'], 200)
        self.assertEqual(self.checkpoint(), [])
        # A fresh call/connection retains the fixed range and rotated PIT cursor.
        self.client.search.side_effect = [self.page(200, 1)]
        second = run_once(self.client, self.path, START, now=NOW, max_pages=1)
        self.assertEqual(self.client.search.call_args.kwargs['search_after'], [199])
        self.assertEqual(second['counts']['normalized'], 201)
        self.assertEqual(self.checkpoint(), [])
        self.client.search.side_effect = [{'hits': {'hits': []}}]
        final = run_once(self.client, self.path, START, now=NOW, max_pages=1)
        self.assertEqual(final['state'], 'success')
        self.assertEqual(final['checkpoint'], '2026-09-22T01:05:00Z')
        self.assertEqual(len(self.stored), 402)
        self.assertEqual(self.client.open_point_in_time.call_count, 1)
        self.client.close_point_in_time.assert_called_once_with(id='rotated')
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM scan_seen').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT count(*) FROM scan_progress').fetchone()[0], 0)

    def test_expired_pit_replay_deduplicates_counts_and_never_saves_event_contents(self):
        self.client.search.side_effect = [self.page(0, 2)]
        run_once(self.client, self.path, START, now=NOW, max_pages=1)
        self.client.search.side_effect = [NotFoundError('expired', meta=Mock(status=404), body={}),
                                        self.page(0, 3), {'hits': {'hits': []}}]
        result = run_once(self.client, self.path, START, now=NOW, max_pages=3)
        self.assertEqual(result['counts']['normalized'], 3)
        self.assertEqual(len(self.stored), 6)
        self.assertNotIn(b'PRIVATE_CANARY', self.path.read_bytes())

    def test_failed_later_page_preserves_prior_progress_and_existing_documents(self):
        self.client.search.side_effect = [self.page(0, 1)]
        run_once(self.client, self.path, START, now=NOW, max_pages=1)
        self.client.search.side_effect = [self.page(1, 1), {'pit_id': 'bad', 'timed_out': True}]
        with self.assertRaisesRegex(RuntimeError, 'checkpoint retained'):
            run_once(self.client, self.path, START, now=NOW, max_pages=2)
        with closing(sqlite3.connect(self.path)) as db:
            meta = json.loads(db.execute('SELECT body FROM scan_progress').fetchone()[0])
        self.assertEqual(meta['after'], [0]); self.assertEqual(meta['counts']['normalized'], 1)
        self.assertEqual(self.checkpoint(), [])
        saved = deepcopy(self.stored)
        self.client.search.side_effect = [self.page(1, 1), {'hits': {'hits': []}}]
        result = run_once(self.client, self.path, START, now=NOW, max_pages=2)
        self.assertEqual(result['state'], 'success'); self.assertEqual(result['counts']['normalized'], 2)
        self.assertEqual(self.stored, saved)

    def test_new_cycle_does_not_move_saved_receipt_window(self):
        from datetime import timedelta
        self.client.search.side_effect = [self.page(0, 1)]
        first = run_once(self.client, self.path, START, now=NOW, max_pages=1)
        self.client.search.side_effect = [{'hits': {'hits': []}}]
        final = run_once(self.client, self.path, START, now=NOW + timedelta(hours=1), max_pages=1,
                         window_minutes=60)
        self.assertEqual(final['range'], first['range'])
        self.assertEqual(final['checkpoint'], first['range']['end'])

    def test_bad_page_mapping_and_partial_open_never_advance_checkpoint(self):
        for result in ({'hits': {'hits': [dict(fixture(), sort=None)]}},
                       {'hits': {'hits': [dict(fixture(), _index='soc-host-raw-other', sort=[0])]}}):
            with self.subTest(result=result):
                self.client.search.side_effect = [result]
                with self.assertRaisesRegex(RuntimeError, 'checkpoint retained'):
                    run_once(self.client, self.path, START, now=NOW, max_pages=1)
                self.assertEqual(self.checkpoint(), [])
