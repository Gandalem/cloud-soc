from copy import deepcopy
from datetime import timedelta
import json
from pathlib import Path
import tempfile
import unittest
from test_intake_detection import raw, normalized, client_for
from cloud_soc.detection.engine import detect_events
from cloud_soc.detection.worker import approved_rules
from cloud_soc.detection.incremental import run_incremental, utc
from cloud_soc.main import make_alert_id


def ssh(number, seconds=None, *, outcome='failure', host='host-a', user='fixture', org='team-a', ip='192.0.2.10'):
    source = raw(number, seconds=seconds, organization=org)
    source['_source']['host'] = {'id': host, 'name': host}
    if outcome == 'success':
        source['_source']['message'] = source['_source']['message'].replace('Failed password', 'Accepted password')
    hit = normalized(source)
    hit['_source']['user']['name'] = user
    hit['_source']['source']['ip'] = ip
    row = deepcopy(hit['_source'])
    row['_cloud_soc_meta'] = {'index': hit['_index'], 'document_id': hit['_id']}
    return row


class SequenceDetectionTests(unittest.TestCase):
    def setUp(self):
        self.rules = [rule for rule in approved_rules(include_sequence=True) if rule.get('type') == 'sequence']

    def detect(self, rows): return detect_events(rows, self.rules)

    def test_five_failures_then_success_has_exact_six_refs(self):
        result = self.detect([ssh(i) for i in range(5)] + [ssh(5, outcome='success')])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['rule_id'], 'AUTH-SEQ-001')
        self.assertEqual(len(result[0]['evidence']), 6)
        self.assertEqual(result[0]['engine_version'], 'failure-success-v1')

    def test_insufficient_failures_and_success_before_failures(self):
        self.assertEqual(self.detect([ssh(i) for i in range(4)] + [ssh(4, outcome='success')]), [])
        self.assertEqual(self.detect([ssh(0, outcome='success')] + [ssh(i) for i in range(1, 6)]), [])

    def test_scope_host_user_and_source_cannot_mix(self):
        failures = [ssh(i) for i in range(5)]
        for changed in ({'host': 'other'}, {'user': 'other'}, {'org': 'other'}, {'ip': '192.0.2.11'}):
            self.assertEqual(self.detect(failures + [ssh(6, outcome='success', **changed)]), [])

    def test_window_boundary_and_same_timestamp_ambiguity(self):
        self.assertEqual(len(self.detect([ssh(i, seconds=0) for i in range(5)] + [ssh(6, seconds=300, outcome='success')])), 1)
        self.assertEqual(self.detect([ssh(i, seconds=0) for i in range(5)] + [ssh(6, seconds=301, outcome='success')]), [])
        self.assertEqual(self.detect([ssh(i, seconds=5) for i in range(5)] + [ssh(6, seconds=5, outcome='success')]), [])

    def test_success_resets_sequence(self):
        result = self.detect([ssh(i) for i in range(5)] + [ssh(5, outcome='success'), ssh(6, outcome='success')])
        self.assertEqual(len(result), 1)

    def test_out_of_order_batch_has_same_alert_id(self):
        rows = [ssh(i) for i in range(5)] + [ssh(5, outcome='success')]
        self.assertEqual(make_alert_id(self.detect(rows)[0]), make_alert_id(self.detect(list(reversed(rows)))[0]))

    def test_durable_batch_boundary_and_restart(self):
        rows = [ssh(i) for i in range(5)] + [ssh(5, seconds=60, outcome='success')]
        base = utc(rows[0]['@timestamp'])
        hits = []
        for i, row in enumerate(rows):
            meta = row.pop('_cloud_soc_meta')
            row['cloud_soc']['normalized_at'] = (base+timedelta(seconds=10 if i < 5 else 130)).isoformat()
            hits.append({'_index': meta['index'], '_id': meta['document_id'], '_source': row})
        client = client_for([])
        client.field_caps.return_value = {'fields': {'cloud_soc.normalized_at': {'date': {}}}}
        client.count.return_value = {'count': 0}
        def scan(*args, **kwargs):
            bounds = kwargs['query']['range']['cloud_soc.normalized_at']
            return deepcopy([h for h in hits if utc(bounds['gte']) <= utc(h['_source']['cloud_soc']['normalized_at']) < utc(bounds['lt'])])
        with tempfile.TemporaryDirectory() as folder:
            options = dict(state_path=Path(folder)/'state.sqlite', start=base, lateness_seconds=60,
                           include_sequence=True, scanner=scan)
            self.assertEqual(run_incremental(client, now=base+timedelta(seconds=140), **options)['created'], 0)
            self.assertEqual(run_incremental(client, now=base+timedelta(seconds=230), **options)['created'], 1)
            self.assertEqual(run_incremental(client, now=base+timedelta(seconds=300), **options)['created'], 0)


if __name__ == '__main__': unittest.main()
