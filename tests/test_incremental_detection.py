from copy import deepcopy
from contextlib import closing
from datetime import timedelta
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from test_intake_detection import raw, normalized, client_for
from cloud_soc.detection.incremental import run_incremental, utc
from cloud_soc.portal.operations import Operations


class IncrementalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'state.sqlite'
        self.base = utc(raw(0)['_source']['@timestamp'])
        self.hits = []
        self.client = client_for([])
        self.client.field_caps.return_value = {'fields': {'cloud_soc.normalized_at': {'date': {}}}}
        self.client.count.return_value = {'count': 0}
        self.ids = []
        def write(*args, **kwargs):
            key = kwargs['document_id']
            result = 'existing' if key in self.ids else 'created'
            if result == 'created': self.ids.append(key)
            return {'result': result}
        self.writer = patch('cloud_soc.detection.incremental.save_security_alert', side_effect=write).start()
        self.addCleanup(patch.stopall)

    def add(self, count, receipt, offset=0, organization='team-a'):
        for i in range(count):
            hit = normalized(raw(i + offset, organization=organization))
            hit['_source']['cloud_soc']['normalized_at'] = (self.base + timedelta(seconds=receipt)).isoformat()
            self.hits.append(hit)

    def scan(self, client, **kwargs):
        bounds = kwargs['query']['range']['cloud_soc.normalized_at']
        return deepcopy([h for h in self.hits if utc(bounds['gte']) <= utc(h['_source']['cloud_soc']['normalized_at']) < utc(bounds['lt'])])

    def run_at(self, seconds, **kwargs):
        return run_incremental(self.client, state_path=self.path, start=self.base,
            now=self.base + timedelta(seconds=seconds), lateness_seconds=60, scanner=self.scan, **kwargs)

    def stored(self):
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute('SELECT body FROM runtime').fetchone()
            return json.loads(row[0]) if row else None

    def test_millisecond_boundary_candidate_does_not_stall_checkpoint(self):
        # The real failing checkpoint has microseconds while the ES date index
        # returns an older _source from the very same millisecond bucket.
        self.base = utc('2026-10-19T07:41:47.618125Z')
        before = normalized(raw(0))
        before['_source']['cloud_soc']['normalized_at'] = '2026-10-19T07:41:47.618105Z'
        valid = normalized(raw(1))
        valid['_source']['cloud_soc']['normalized_at'] = self.base.isoformat()
        with patch.object(self, 'scan', return_value=[before, valid]):
            result = self.run_at(70)
        self.assertEqual(result['events'], 1)
        self.assertEqual(utc(self.stored()['checkpoint']), self.base + timedelta(seconds=40))
        self.assertNotIn(before['_id'], self.stored()['seen'])
        self.assertIn(valid['_id'], self.stored()['seen'])
        with patch.object(self, 'scan', return_value=[]):
            self.run_at(140)
        self.assertEqual(utc(self.stored()['checkpoint']), self.base + timedelta(seconds=110))

    def test_server_denial_reports_safe_reason_and_recovers_without_reset(self):
        from elasticsearch import ApiError
        from unittest.mock import Mock
        from cloud_soc.processing.errors import WorkerFailure
        self.run_at(70)
        old = self.stored()
        self.client.field_caps.side_effect = ApiError(
            'PRIVATE_CANARY', meta=Mock(status=403), body={'reason': 'PRIVATE_CANARY'})
        with self.assertRaises(WorkerFailure) as caught:
            self.run_at(140)
        self.assertEqual(caught.exception.code, 'authorization_denied')
        status = self.client.index.call_args.kwargs['document']
        self.assertEqual(status['state'], 'failed')
        self.assertEqual(status['error'], 'authorization_denied')
        self.assertNotIn('PRIVATE_CANARY', json.dumps(status))
        self.assertEqual(self.stored(), old)
        self.client.field_caps.side_effect = None
        self.run_at(140)
        self.assertGreater(self.stored()['checkpoint'], old['checkpoint'])

    def test_cross_batch_restart_overlap_and_cooldown(self):
        self.add(9, 10)
        self.assertEqual(self.run_at(70)['created'], 0)
        self.add(1, 60, offset=9)
        self.assertEqual(self.run_at(140)['created'], 1)
        self.add(10, 130, offset=10)
        self.assertEqual(self.run_at(210)['created'], 0)
        self.assertEqual(len(self.ids), 1)
        self.assertEqual(self.run_at(280)['events'], 0)

    def test_separate_organizations(self):
        self.add(5, 10)
        self.add(5, 10, offset=5, organization='other')
        self.assertEqual(self.run_at(140)['created'], 0)

    def test_write_failure_retains_checkpoint_and_retry_id(self):
        self.add(10, 10)
        self.run_at(70)
        old = self.stored()
        self.writer.side_effect = RuntimeError('unavailable')
        with self.assertRaises(RuntimeError): self.run_at(140)
        attempted = self.writer.call_args.kwargs['document_id']
        self.assertEqual(self.stored(), old)
        self.writer.side_effect = None
        self.writer.return_value = {'result': 'created'}
        self.assertEqual(self.run_at(140)['created'], 1)
        self.assertEqual(attempted, self.writer.call_args.kwargs['document_id'])

    def test_status_failure_after_alert_retries_without_duplicate(self):
        self.add(10, 10)
        self.run_at(70)
        old = self.stored()
        self.client.index.side_effect = [None, RuntimeError('status unavailable'), None]
        with self.assertRaises(RuntimeError): self.run_at(140)
        self.assertEqual(self.stored(), old)
        self.client.index.side_effect = None
        self.assertEqual(self.run_at(140)['existing'], 1)

    def test_late_input_is_visible(self):
        self.run_at(140)
        self.add(10, 120)
        result = self.run_at(210)
        self.assertEqual(result['late'], 10)
        status = self.client.index.call_args.kwargs['document']
        self.assertEqual(status['health'], 'warning')
        self.assertEqual(status['late_total'], 10)

    def test_partial_read_and_limit_retain_state(self):
        self.run_at(70)
        old = self.stored()
        self.add(10, 60)
        self.assertEqual(self.run_at(140, max_documents=5)['input_pending'], 5)
        self.assertEqual(self.stored(), old)
        with patch.object(self, 'scan', side_effect=RuntimeError('partial')):
            with self.assertRaises(RuntimeError): self.run_at(140)
        self.assertEqual(self.stored(), old)
        self.assertEqual(self.run_at(200, max_documents=5)['input_pending'], 10)
        self.assertEqual(self.stored(), old)
        self.assertEqual(self.run_at(260, max_documents=5)['events'], 10)
        self.assertGreater(self.stored()['checkpoint'], old['checkpoint'])

    def test_source_identity_change_rejected(self):
        self.run_at(70)
        with self.assertRaises(ValueError): self.run_at(140, source_id='other-cluster')

    def test_second_window_after_cooldown(self):
        self.add(10, 10)
        self.run_at(140)
        self.add(10, 360, offset=310)
        self.run_at(390)
        self.assertEqual(self.run_at(470)['created'], 1)
        self.assertEqual(len(self.ids), 2)

    def test_reordered_arrival_inside_lateness_window(self):
        self.add(5, 10, offset=5)
        self.run_at(70)
        self.add(5, 60)
        self.assertEqual(self.run_at(140)['created'], 1)

    def test_concurrent_owner_is_rejected(self):
        self.run_at(70)
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('BEGIN IMMEDIATE')
            with self.assertRaises(sqlite3.OperationalError): self.run_at(140)

    def test_old_active_groups_expire(self):
        self.add(10, 10)
        self.run_at(140)
        for stamp in (400, 700, 1000): self.run_at(stamp)
        self.assertEqual(self.stored()['groups'], {})

    def test_missing_mapping_rejected(self):
        self.client.field_caps.return_value = {'fields': {}}
        with self.assertRaises(RuntimeError): self.run_at(70)
        self.assertIsNone(self.stored())

    def test_legacy_exclusion_requires_explicit_choice(self):
        self.client.count.return_value = {'count': 12}
        with self.assertRaises(RuntimeError): self.run_at(70)
        self.assertIsNone(self.stored())
        self.run_at(70, accept_legacy_exclusion=True)
        self.assertEqual(self.stored()['legacy_excluded'], 12)

    def test_stopped_worker_surfaces_health_alarm(self):
        reader = Operations(self.client)
        with patch.object(reader, 'get', return_value={'@timestamp': self.base.isoformat(), 'state': 'success'}):
            self.assertEqual(reader.worker_status('detector')['health'], 'stale')


if __name__ == '__main__':
    unittest.main()
