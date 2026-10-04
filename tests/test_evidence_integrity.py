from copy import deepcopy
import json
import unittest
from unittest.mock import patch
from test_intake_detection import raw, normalized, client_for
from cloud_soc.detection.worker import run_once
from cloud_soc.portal.operations import Operations
from cloud_soc.portal.log_query import LogQueryError


class EvidenceIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.raw = [raw(i) for i in range(10)]
        self.hits = [normalized(hit) for hit in self.raw]
        self.client = client_for(self.hits)
        run_once(self.client)
        self.alert = self.client.create.call_args.kwargs['document']
        self.alert_id = self.client.create.call_args.kwargs['id']
        self.reader = Operations(self.client)
        self.store = {(hit['_index'], hit['_id']): hit['_source'] for hit in self.raw + self.hits}
        self.store[('security-alerts', self.alert_id)] = self.alert
        self.getter = patch.object(self.reader, 'get', side_effect=lambda index, identifier, fields: deepcopy(self.store.get((index, identifier)))).start()
        self.addCleanup(patch.stopall)

    def detail(self, **params):
        return json.loads(self.reader.detail([('id', self.alert_id), *[(k, str(v)) for k, v in params.items()]]))

    def test_matching_hash_and_no_full_source_leak(self):
        result = self.detail(evidence=0)['evidence']
        self.assertEqual(result['integrity'], 'normalized_hash_verified')
        self.assertEqual(result['raw_integrity'], 'not_hashed_at_detection')
        self.assertNotIn('normalizer_version', json.dumps(result))
        self.assertIsNone(self.getter.call_args_list[1].args[2])

    def test_content_change_detected_before_raw_read(self):
        hit = self.hits[0]
        self.store[(hit['_index'], hit['_id'])]['event']['outcome'] = 'success'
        self.assertEqual(self.detail(evidence=0)['evidence']['state'], 'normalized_hash_mismatch')
        self.assertEqual(self.getter.call_count, 2)

    def test_hash_key_order_does_not_change_integrity(self):
        hit = self.hits[0]
        self.store[(hit['_index'], hit['_id'])] = dict(reversed(list(hit['_source'].items())))
        self.assertEqual(self.detail(evidence=0)['evidence']['integrity'], 'normalized_hash_verified')

    def test_legacy_hash_is_unverified(self):
        self.alert['cloud_soc']['provenance']['evidence'][0].pop('event_hash')
        self.assertEqual(self.detail(evidence=0)['evidence']['integrity'], 'unverified_legacy')

    def test_malformed_hash_is_distinct(self):
        self.alert['cloud_soc']['provenance']['evidence'][0]['event_hash'] = 'wrong'
        self.assertEqual(self.detail(evidence=0)['evidence']['state'], 'invalid_evidence_hash')

    def test_all_positions_over_100_are_accessible(self):
        evidence = self.alert['cloud_soc']['provenance']['evidence']
        self.alert['cloud_soc']['provenance']['evidence'] = [deepcopy(evidence[0]) for _ in range(251)]
        seen = []
        offset = 0
        while offset is not None:
            page = self.detail(offset=offset, limit=100)['evidence_page']
            seen.extend(page['positions'])
            offset = page['next_offset']
        self.assertEqual(seen, list(range(251)))
        self.assertEqual(self.detail(evidence=250)['evidence']['integrity'], 'normalized_hash_verified')

    def test_invalid_page_and_out_of_bounds(self):
        for values in ({'offset': -1}, {'limit': 101}, {'limit': 0}, {'offset': 11}, {'evidence': 10}):
            with self.assertRaises(LogQueryError): self.detail(**values)

    def test_missing_document_and_reference_mismatch_stay_distinct(self):
        hit = self.hits[0]
        key = (hit['_index'], hit['_id'])
        original = self.store.pop(key)
        self.assertEqual(self.detail(evidence=0)['evidence']['state'], 'normalized_missing_or_expired')
        self.store[key] = original
        original['cloud_soc']['provenance']['raw']['id'] = 'different'
        self.assertEqual(self.detail(evidence=0)['evidence']['state'], 'provenance_mismatch')


if __name__ == '__main__': unittest.main()
