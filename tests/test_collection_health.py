import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from cloud_soc.portal.collection_health import project, snapshot

NOW = datetime(2026, 9, 22, 1, 5, tzinfo=timezone.utc)
KEY = {'organization': 'test', 'agent_id': 'test-agent', 'agent_type': 'filebeat'}
SOURCE = {'host': {'name': 'host'}, 'event': {'ingested': '2026-09-22T01:04:00Z'},
          'cloud_soc': {'discovery': {'schema': 1, 'generated_at': '2026-09-22T01:03:30Z', 'policy_version': 0,
                                    'selected': 1, 'excluded': 1, 'errors': 1, 'total': 3,
                                    'sources': [{'id': 'a' * 64, 'status': 'unreadable'}]}}}


class HealthTests(unittest.TestCase):
    def metrics_source(self, **changes):
        source = copy.deepcopy(SOURCE)
        source['cloud_soc']['discovery']['collector_metrics'] = {
            'schema': 1, 'state': 'observed', 'sampled_at': '2026-09-22T01:03:20Z',
            'interval_seconds': 30, 'counter_scope': 'logged_interval_delta', 'scan_partial': True,
            'queue_pct': .9, 'queue_events': 900, 'output_total': 100, 'output_acked': 99,
            'output_failed': 1, **changes}
        return source

    def test_numeric_metrics_preserve_unknown_and_distinguish_delta_from_loss(self):
        row = project(self.metrics_source(), KEY, NOW)
        sample = row['collector_metrics']
        self.assertEqual(row['queue_state'], 'high')
        self.assertEqual(row['transport_state'], 'error_observed')
        self.assertEqual(sample['output_acked'], 99)
        self.assertIsNone(sample['output_dropped'])
        self.assertEqual(sample['counter_scope'], 'logged_interval_delta')
        self.assertEqual(row['source_success'], 'not_measured')

    def test_old_and_future_metrics_do_not_claim_current_health(self):
        for at, state in [('2026-09-22T00:00:00Z', 'stale'), ('2026-09-22T01:07:00Z', 'clock_warning')]:
            with self.subTest(at=at):
                row = project(self.metrics_source(sampled_at=at), KEY, NOW)
                self.assertEqual(row['collector_metrics']['state'], state)
                self.assertEqual(row['queue_state'], 'unknown')
                self.assertEqual(row['transport_state'], 'unknown')

    def test_bad_metrics_do_not_erase_discovery_or_echo_input(self):
        for key, value in [('queue_events', True), ('queue_pct', float('nan')), ('queue_pct', 1.1), ('queue_pct', 10**500),
                           ('output_dropped', -1), ('output_acked', 1.5), ('output_total', 2**53),
                           ('sampled_at', 'SECRET'), ('schema', True), ('interval_seconds', 0),
                           ('scan_partial', 'SECRET'), ('last_problem_at', 'SECRET')]:
            with self.subTest(key=key, value=value):
                row = project(self.metrics_source(**{key: value}), KEY, NOW)
                self.assertEqual(row['collector_metrics']['state'], 'invalid')
                self.assertEqual(row['selected'], 1)
                self.assertNotIn('SECRET', json.dumps(row))

    def test_recent_problem_survives_later_good_sample_without_claiming_total(self):
        row = project(self.metrics_source(output_failed=None, output_acked=100,
                      last_problem_at='2026-09-22T01:00:00Z', password='PRIVATE_CANARY',
                      message='PRIVATE_CANARY', ephemeral_id='PRIVATE_CANARY'), KEY, NOW)
        self.assertEqual(row['transport_state'], 'error_observed')
        self.assertNotIn('PRIVATE_CANARY', json.dumps(row))
        row = project(self.metrics_source(output_failed=None, last_problem_at=None), KEY, NOW)
        self.assertEqual(row['transport_state'], 'observed')  # not "healthy"

    def test_states_are_not_receipt_or_queue_success(self):
        result = project(SOURCE, KEY, NOW)
        self.assertEqual(result['report_state'], 'recent')
        self.assertEqual(result['delay_seconds'], 30)
        self.assertEqual(result['omitted_sources'], 2)
        self.assertEqual(result['queue_state'], 'unknown')
        self.assertEqual(result['source_success'], 'not_measured')
        source = copy.deepcopy(SOURCE)
        source['cloud_soc']['discovery']['generated_at'] = '2026-09-22T01:06:00Z'
        self.assertTrue(project(source, KEY, NOW)['clock_warning'])
        self.assertEqual(project(SOURCE, KEY, NOW.replace(hour=2))['report_state'], 'stale')

    def test_malformed_counts_sources_and_times_fail_closed(self):
        for name, value in [('selected', -1), ('total', 100), ('errors', True), ('generated_at', 'bad'),
                            ('sources', [{'id': 'password=CANARY', 'status': 'selected'}])]:
            source = copy.deepcopy(SOURCE)
            source['cloud_soc']['discovery'][name] = value
            with self.assertRaises(ValueError):
                project(source, KEY, NOW)

    def test_report_projection_never_returns_paths_or_claimed_queue_health(self):
        source = copy.deepcopy(SOURCE)
        report = source['cloud_soc']['discovery']
        report['queue_state'] = 'healthy'
        report['password'] = 'CANARY'
        report['sources'][0]['path'] = 'CANARY'
        source['host']['name'] = 'password=CANARY'
        self.assertNotIn('CANARY', json.dumps(project(source, KEY, NOW)))
        self.assertEqual(project(source, KEY, NOW)['queue_state'], 'unknown')

    def test_query_is_separate_bounded_and_rejects_partial_results(self):
        es = Mock(); es.options.return_value = es
        es.search.return_value = {'aggregations': {'agents': {'buckets': [{'key': KEY, 'latest': {'hits': {'hits': [{'_source': SOURCE}]}}}]}}}
        self.assertEqual(len(json.loads(snapshot(es, now=NOW))['rows']), 1)
        self.assertEqual(es.search.call_args.kwargs['index'], 'soc-agent-health-*')
        self.assertFalse(es.search.call_args.kwargs['allow_partial_search_results'])
        es.search.return_value['timed_out'] = True
        with self.assertRaises(ValueError):
            snapshot(es, now=NOW)
        es.search.return_value = {'_shards': {'total': 0}}
        self.assertEqual(json.loads(snapshot(es, now=NOW))['rows'], [])
