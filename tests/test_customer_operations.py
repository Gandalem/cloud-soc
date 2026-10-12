from copy import deepcopy
import unittest
from unittest.mock import Mock, patch
from elastic_transport import ApiResponseMeta, HttpHeaders, NodeConfig
from elasticsearch import Elasticsearch

from cloud_soc.portal.operations import analysis_coverage
from cloud_soc.portal.detection_history import latest_runs
from cloud_soc.detection.telemetry import RUNS


class CustomerStatusTests(unittest.TestCase):
    def test_upstream_failure_never_inherits_detector_success(self):
        detector = {'state': 'success', 'health': 'healthy'}
        self.assertEqual(analysis_coverage({'state': 'failed'}, detector),
                         {'state': 'blocked', 'reason': 'normalizer_failed'})
        for state, expected in [('stale', 'unknown'), ('unavailable', 'unknown'), ('not_started', 'not_started')]:
            self.assertEqual(analysis_coverage({'state': state}, detector)['state'], expected)

    def test_backlog_exclusions_and_observed_execution_are_distinct(self):
        good = {'state': 'success', 'health': 'healthy'}
        self.assertEqual(analysis_coverage(good, good)['state'], 'observed')
        self.assertEqual(analysis_coverage(good, {'state': 'success', 'health': 'warning'})['state'], 'warning')
        self.assertEqual(analysis_coverage({'state': 'running', 'progress': {'state': 'catching_up'}}, good)['state'], 'catching_up')
        self.assertEqual(analysis_coverage({'state': 'success', 'health': 'delayed'}, good)['state'], 'delayed')


class RunSummaryTests(unittest.TestCase):
    def source(self, phase):
        return {'run_id': 'run-1', 'record_id': 'run-1:AUTH-001:' + phase,
                'rule': {'id': 'AUTH-001'}, 'state': phase, '@timestamp': '2026-10-12T09:00:00Z',
                'counts': {'input_events': 0, 'alerts_created': 0}}

    def client(self, phases):
        client = Mock()
        def mget(**kwargs):
            return {'docs': [{'found': identifier.rsplit(':', 1)[1] in phases,
                             '_id': identifier, '_index': RUNS,
                             '_source': self.source(identifier.rsplit(':', 1)[1])}
                            for identifier in kwargs['ids']]}
        client.mget.side_effect = mget
        return client

    def test_terminal_phase_found_outside_raw_page_and_records_remain_unchanged(self):
        evaluated = self.source('evaluated'); original = deepcopy(evaluated)
        client = self.client(['committed', 'evaluated'])
        rows = latest_runs(client, [evaluated])
        self.assertEqual(len(rows), 1); self.assertEqual(rows[0]['state'], 'committed')
        self.assertEqual(evaluated, original)
        self.assertEqual(client.mget.call_args.kwargs['index'], RUNS)
        self.assertIn('committed', rows[0]['phases'])

    def test_incomplete_pending_failure_and_legacy_are_not_silently_completed(self):
        self.assertEqual(latest_runs(self.client(['evaluated']), [self.source('evaluated')])[0]['state'], 'evaluated')
        self.assertEqual(latest_runs(self.client(['failed', 'evaluated']), [self.source('evaluated')])[0]['state'], 'failed')
        legacy = {'rule': {'id': 'AUTH-001'}, 'state': 'evaluated'}
        client = Mock(); self.assertEqual(latest_runs(client, [legacy])[0]['state'], 'evaluated')
        client.mget.assert_not_called()

    def test_mget_partial_errors_and_mismatched_scope_are_rejected(self):
        for docs in ([], [{'error': {'type': 'security_exception'}}],
                     [{'_id': 'bad', '_index': 'foreign', 'found': True}] * 4):
            with self.subTest(docs=docs):
                client = Mock(); client.mget.return_value = {'docs': docs}
                with self.assertRaises(RuntimeError): latest_runs(client, [self.source('evaluated')])

    def test_real_sdk_uses_only_the_fixed_index_and_bounded_phase_ids(self):
        meta = ApiResponseMeta(200, '1.1', HttpHeaders({'x-elastic-product': 'Elasticsearch'}),
                               0, NodeConfig('http', 'localhost', 9200))
        calls = []
        def transport(method, target, **kwargs):
            calls.append((method, target, kwargs['body']))
            return meta, {'docs': [{'_index': RUNS, '_id': value, 'found': False}
                                  for value in kwargs['body']['ids']]}
        with Elasticsearch('http://localhost:9200') as client, patch.object(client.transport, 'perform_request', side_effect=transport):
            rows = latest_runs(client, [self.source('evaluated')])
        self.assertEqual(rows[0]['state'], 'evaluated')
        self.assertEqual(calls[0][0], 'POST')
        self.assertTrue(calls[0][1].startswith('/' + RUNS + '/_mget'))
        self.assertEqual(len(calls[0][2]['ids']), 4)
