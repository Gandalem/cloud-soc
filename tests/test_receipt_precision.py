"""Date-mapping bucket edges must not poison or silently truncate exact windows."""
from copy import deepcopy
from datetime import timedelta
import sqlite3
import unittest
from unittest.mock import Mock

from cloud_soc.detection import staging
from cloud_soc.processing import receipt
from cloud_soc.portal.agent_status import parse_time

LOWER = '2026-10-19T07:41:47.618125Z'
END = '2026-10-19T08:01:47.618125Z'


def hit(identifier, stamp):
    return {'_index': 'soc-normalized-v1', '_id': identifier,
            '_source': {'cloud_soc': {'normalized_at': stamp}}}


class ReceiptPrecisionTests(unittest.TestCase):
    def test_bucket_query_and_exact_filter(self):
        self.assertEqual(receipt.query('t', LOWER, END), {'range': {'t': {
            'gte': '2026-10-19T07:41:47.618000Z', 'lt': '2026-10-19T08:01:47.619000Z'}}})
        self.assertFalse(receipt.contains('2026-10-19T07:41:47.618105Z', LOWER, END))
        self.assertTrue(receipt.contains(LOWER, LOWER, END))
        self.assertTrue(receipt.contains('2026-10-19T08:01:47.618124Z', LOWER, END))
        self.assertFalse(receipt.contains(END, LOWER, END))
        with self.assertRaisesRegex(ValueError, 'outside_receipt_range'):
            receipt.contains('2026-10-19T07:41:47.617999Z', LOWER, END)

    def test_millisecond_search_then_spool_preserves_exact_membership(self):
        # Model a date index independently: both indexed values and bounds are
        # integers in milliseconds, while _source retains its original precision.
        rows = [hit('before', '2026-10-19T07:41:47.618105Z'), hit('first', LOWER),
                hit('last', '2026-10-19T08:01:47.618124Z'), hit('next', END)]
        epoch = parse_time('1970-01-01T00:00:00Z')
        def millis(value):
            return (parse_time(value) - epoch) // timedelta(milliseconds=1)
        client = Mock()
        client.open_point_in_time.return_value = {'id': 'pit'}
        def search(**kw):
            if kw['search_after'] is not None:
                return {'hits': {'hits': []}}
            limits = kw['query']['range']['cloud_soc.normalized_at']
            matches = [deepcopy(row) for row in rows if
                       millis(limits['gte']) <= millis(row['_source']['cloud_soc']['normalized_at']) < millis(limits['lt'])]
            for i, row in enumerate(matches): row['sort'] = [i]
            return {'hits': {'hits': matches}}
        client.search.side_effect = search
        with sqlite3.connect(':memory:') as db:
            meta = staging.prepare(db, 'identity', LOWER, LOWER, END)
            self.assertTrue(staging.read_window(client, db, meta, budget=10, seen={}))
            self.assertEqual([h['_id'] for h in staging.staged_hits(db)], ['first', 'last'])
            self.assertEqual(meta['lower'], LOWER)
            self.assertEqual(meta['end'], END)

    def test_old_cursor_replays_fixed_window_and_keeps_staged_events(self):
        client = Mock(); client.open_point_in_time.return_value = {'id': 'new'}
        client.search.return_value = {'hits': {'hits': []}}
        with sqlite3.connect(':memory:') as db:
            meta = staging.prepare(db, 'identity', LOWER, LOWER, END)
            staging.add(db, hit('retained', LOWER), meta, {})
            meta.update(pit='old', after=[100], complete=True)
            self.assertTrue(staging.read_window(client, db, meta, budget=10, seen={}))
            self.assertIsNone(client.search.call_args.kwargs['search_after'])
            self.assertEqual([h['_id'] for h in staging.staged_hits(db)], ['retained'])
            self.assertEqual(meta['receipt_query_version'], 2)
            client.close_point_in_time.assert_any_call(id='old')
