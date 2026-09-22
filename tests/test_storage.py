import copy
from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from cloud_soc.portal.storage import survey, growth


class StorageTests(unittest.TestCase):
    def client(self):
        es = Mock()
        es.options.return_value = es
        primary = {'docs': {'count': 3}, 'store': {'size_in_bytes': 100}, 'indexing': {'index_total': 3}}
        es.indices.stats.return_value = {'indices': {'soc-host-raw-test': {'uuid': 'one', 'primaries': primary, 'total': primary}}}
        es.search.return_value = {'aggregations': {'last_received': {'value_as_string': '2026-01-01T00:00:00Z'}, 'missing_received': {'doc_count': 0}}}
        es.nodes.stats.return_value = {'nodes': {'one': {'fs': {'total': {'total_in_bytes': 100, 'available_in_bytes': 10}}}}}
        return es

    def test_candidates_are_only_advice_and_legacy_is_kept(self):
        es = self.client()
        report = survey(es, days=30, now=datetime(2026, 9, 22, tzinfo=timezone.utc))
        self.assertTrue(report['indices'][0]['review_candidate'])
        self.assertFalse(report['automatic_deletion'])
        self.assertFalse(report['approved'])
        self.assertEqual(report['disks'][0]['advisory'], 'critical')
        es.search.return_value['aggregations']['missing_received']['doc_count'] = 1
        self.assertFalse(survey(es, days=30)['indices'][0]['review_candidate'])
        es.indices.delete.assert_not_called()
        es.ilm.put_lifecycle.assert_not_called()

    def test_incomplete_stats_and_invalid_policy_fail(self):
        for days in (True, 0, 366):
            with self.assertRaises(ValueError):
                survey(self.client(), days=days)
        es = self.client()
        es.indices.stats.return_value['_shards'] = {'failed': 1}
        with self.assertRaises(ValueError):
            survey(es, days=30)

    def test_growth_is_explicitly_net_and_resets_are_unknown(self):
        first = survey(self.client(), days=30, now=datetime(2026, 9, 21, tzinfo=timezone.utc))
        second = copy.deepcopy(first)
        second['measured_at'] = '2026-09-22T00:00:00Z'
        second['indices'][0]['primary_bytes'] = 200
        self.assertEqual(growth(first, second)['net_primary_bytes_per_day'], 100)
        second['indices'][0]['uuid'] = 'recreated'
        self.assertEqual(growth(first, second)['status'], 'unknown')
