from copy import deepcopy
from datetime import timedelta
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
from test_intake_detection import raw, normalized, client_for
from cloud_soc.detection.incremental import run_incremental, utc
from cloud_soc.detection.telemetry import RUNS, EXCLUSIONS, evaluate
from cloud_soc.detection.worker import approved_rules
from cloud_soc.portal.operations import Operations
from cloud_soc.portal.detection_history import history
from cloud_soc.portal.log_query import LogQueryError


class DetectionQualityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)/'state.sqlite'
        self.base = utc(raw(0)['_source']['@timestamp'])
        self.hits = []
        self.client = client_for([])
        self.client.field_caps.return_value = {'fields': {'cloud_soc.normalized_at': {'date': {}}}}
        self.client.count.return_value = {'count': 0}
        self.client.create.return_value = {'result': 'created'}

    def add(self, number=0, receipt=10):
        hit = normalized(raw(number))
        hit['_source']['cloud_soc']['normalized_at'] = (self.base+timedelta(seconds=receipt)).isoformat()
        self.hits.append(hit)
        return hit

    def run_at(self, seconds=140, **extra):
        def scan(*args, **kwargs):
            bounds = kwargs['query']['range']['cloud_soc.normalized_at']
            return deepcopy([h for h in self.hits if utc(bounds['gte']) <= utc(h['_source']['cloud_soc']['normalized_at']) < utc(bounds['lt'])])
        return run_incremental(self.client, state_path=self.path, start=self.base,
                              now=self.base+timedelta(seconds=seconds), lateness_seconds=60, scanner=scan, **extra)

    def records(self, index):
        return [call.kwargs for call in self.client.create.call_args_list if call.kwargs.get('index') == index]

    def test_committed_history_retry_does_not_rewind_checkpoint(self):
        import sqlite3
        from contextlib import closing
        self.add()
        def delivery(**kwargs):
            if kwargs.get('index') == RUNS and kwargs['document']['state'] == 'committed':
                raise RuntimeError('delivery unavailable')
            return {'result': 'created'}
        self.client.create.side_effect = delivery
        self.run_at()
        with closing(sqlite3.connect(self.path)) as db:
            checkpoint = json.loads(db.execute('SELECT body FROM runtime').fetchone()[0])['checkpoint']
            self.assertEqual(db.execute('SELECT count(*) FROM telemetry_outbox').fetchone()[0], 1)
        self.client.create.side_effect = None
        self.run_at()
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(json.loads(db.execute('SELECT body FROM runtime').fetchone()[0])['checkpoint'], checkpoint)
            self.assertEqual(db.execute('SELECT count(*) FROM telemetry_outbox').fetchone()[0], 0)
        self.assertTrue(any(r['document']['state'] == 'committed' for r in self.records(RUNS)))

    def test_unknown_is_distinct_from_nonmatch(self):
        rule = approved_rules()[0]
        row = self.add()['_source']
        row['event'].pop('outcome')
        self.run_at()
        counters = self.records(RUNS)[0]['document']['counts']
        self.assertEqual(counters['unknown'], 1)
        self.assertEqual(counters['excluded'], 1)
        self.assertEqual(counters['not_matched'], 0)
        excluded = self.records(EXCLUSIONS)[0]['document']
        self.assertEqual(excluded['reason'], 'missing_condition_fields')
        self.assertEqual(excluded['missing_fields'], ['event.outcome'])
        self.assertNotIn('message', excluded)
        row['network']['protocol'] = 'http'
        self.assertEqual(evaluate(row, rule)[0], 'not_matched')

    def test_late_reference_is_durable_and_retry_id_is_stable(self):
        self.run_at(140)
        self.add(receipt=120)
        self.client.index.side_effect = [None, RuntimeError('status failure'), None]
        with self.assertRaises(RuntimeError): self.run_at(210)
        identifier = self.records(EXCLUSIONS)[0]['id']
        self.client.index.side_effect = None
        self.run_at(210)
        excluded = self.records(EXCLUSIONS)
        self.assertEqual(excluded[1]['id'], identifier)
        self.assertEqual(excluded[0]['document']['reason'], 'late_event')
        self.assertEqual(excluded[0]['document']['normalized']['id'], self.hits[0]['_id'])
        self.assertTrue(any(row['document']['state'] == 'failed' for row in self.records(RUNS)))

    def test_bad_time_is_excluded_without_echoing_input(self):
        self.add()['_source']['@timestamp'] = 'password=PRIVATE_CANARY'
        self.run_at()
        record = self.records(EXCLUSIONS)[0]['document']
        self.assertEqual(record['reason'], 'invalid_event_time')
        self.assertIsNone(record['event_time'])
        self.assertNotIn('PRIVATE_CANARY', json.dumps(record))

    def test_sequence_missing_host_is_recorded(self):
        self.add()
        self.run_at(include_sequence=True)
        exclusions = self.records(EXCLUSIONS)
        self.assertEqual(len(exclusions), 1)
        self.assertEqual(exclusions[0]['document']['rule']['id'], 'AUTH-SEQ-001')
        self.assertIn('host.id', exclusions[0]['document']['missing_fields'])

    def test_history_write_failure_does_not_advance_checkpoint(self):
        self.add()
        self.client.create.side_effect = RuntimeError('history storage down')
        with self.assertRaises(RuntimeError): self.run_at()
        self.client.create.side_effect = None
        self.assertEqual(self.run_at()['events'], 1)

    def test_per_rule_counts_and_matches_from_pending_are_separate(self):
        for i in range(10): self.add(i)
        self.run_at(70)
        self.client.create.reset_mock()
        self.run_at(140)
        metrics = self.records(RUNS)[0]['document']['counts']
        self.assertEqual(metrics['input_events'], 0)
        self.assertEqual(metrics['evaluated_events'], 10)
        self.assertEqual(metrics['detection_matches'], 1)
        self.assertEqual(metrics['alerts_created'], 1)


class HistoryReaderTests(unittest.TestCase):
    def setUp(self):
        self.client = Mock()
        self.client.options.return_value = self.client
        self.client.indices.resolve_index.return_value = {'indices': [{'name': RUNS}]}
        self.reader = Operations(self.client)
        self.args = [('start', '2026-10-01T00:00:00Z'), ('end', '2026-10-02T00:00:00Z'), ('limit', '1')]

    def test_seek_page_and_payload_allowlist(self):
        self.client.search.return_value = {'hits': {'hits': [
            {'_source': {'rule': {'id': 'AUTH-001'}, 'state': 'evaluated', 'payload': 'PRIVATE_CANARY'}, 'sort': [1790899200000, 'record-a']},
            {'_source': {'state': 'failed'}, 'sort': [1790899199000, 'record-b']}]}}
        first = json.loads(history(self.reader, self.args))
        self.assertNotIn('PRIVATE_CANARY', json.dumps(first))
        self.assertEqual(first['rows'][0]['state'], 'evaluated')
        self.client.search.return_value = {'hits': {'hits': []}}
        second = json.loads(history(self.reader, self.args + [('after', first['next'])]))
        self.assertIsNone(second['next'])
        self.assertEqual(self.client.search.call_args.kwargs['search_after'], [1790899200000, 'record-a'])

    def test_partial_search_is_not_empty_success(self):
        self.client.search.return_value = {'timed_out': True}
        with self.assertRaises(LogQueryError) as caught: history(self.reader, self.args)
        self.assertEqual(caught.exception.status, 503)

    def test_invalid_queries_are_rejected_before_es(self):
        for args in ([('kind', 'arbitrary-index')], [('limit', '101')], [('after', 'invalid')], [('rule', '*')], [('kind', 'runs'), ('kind', 'runs')]):
            with self.assertRaises(LogQueryError) as caught: history(self.reader, args)
            self.assertEqual(caught.exception.status, 400)
        self.client.search.assert_not_called()


if __name__ == '__main__': unittest.main()
