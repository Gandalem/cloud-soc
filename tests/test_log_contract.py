"""Contract tests only: synthetic fixtures, no server, agents or packet capture."""

from copy import deepcopy
from dataclasses import FrozenInstanceError, asdict
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from cloud_soc.portal.log_contract import (
    DEFAULT_PAGE_SIZE, INDICES, MAX_CURSOR_LENGTH, MAX_DETAIL_BYTES,
    MAX_RESPONSE_BYTES, MAX_WINDOW, SEARCH_TIMEOUT, SOURCE_FIELDS,
    document_reference, operating_system, parse_filters, project_hit,
)

NOW = datetime(2026, 9, 22, 2, tzinfo=timezone.utc)
FIXTURE = json.loads((ROOT / "tests/fixtures/log_intake.json").read_text(encoding="utf-8"))
HITS = {hit["_id"]: hit for hit in FIXTURE["hits"]}


class FilterTests(unittest.TestCase):
    def test_defaults_are_bounded_and_explicit(self):
        result = parse_filters([], now=NOW)
        self.assertEqual(result.start, "2026-09-22T01:00:00Z")
        self.assertEqual(result.end, "2026-09-22T02:00:00Z")
        self.assertEqual(result.time_field, "event.ingested")
        self.assertEqual(result.page_size, DEFAULT_PAGE_SIZE)
        self.assertEqual(MAX_WINDOW, timedelta(days=30))
        self.assertEqual((SEARCH_TIMEOUT, MAX_RESPONSE_BYTES, MAX_DETAIL_BYTES, MAX_CURSOR_LENGTH),
                         ("4s", 262144, 65536, 8192))
        with self.assertRaises(FrozenInstanceError):
            result.host = "changed"

    def test_explicit_timezone_window_and_exact_filters(self):
        result = parse_filters([
            ("start", "2026-09-22T10:00:00+09:00"), ("end", "2026-09-22T11:00:00+09:00"),
            ("time_basis", "event"), ("page_size", "50"), ("host", "win.example.test"),
            ("os", "windows"), ("collector", "filebeat"), ("ip", "2001:0db8::1"),
        ], now=NOW)
        self.assertEqual(result.time_field, "@timestamp")
        self.assertEqual(result.start, "2026-09-22T01:00:00Z")
        self.assertEqual(result.end, "2026-09-22T02:00:00Z")
        self.assertEqual(result.ip, "2001:db8::1")
        self.assertEqual(result.host, "win.example.test")

    def test_duplicates_unknown_filters_and_query_injection_rejected(self):
        for pairs in ([('host', 'a'), ('host', 'b')], [('index', '*')], [('query', '{}')],
                      [('q', '*:*')], [('sort', '_script')], [('cursor', 'unsigned')],
                      [('page_size', '100000')], [('organization', 'not-a-tenant-boundary')]):
            with self.subTest(pairs=pairs), self.assertRaises(ValueError):
                parse_filters(pairs, now=NOW)

    def test_invalid_types_lengths_enums_and_ips(self):
        for key, values in {
            'host': [None, [], '', 'x' * 254, ' padded', 'line\nbreak'],
            'os': ['ubuntu', 'Windows'], 'collector': ['elastic-agent'],
            'time_basis': ['automatic', 'event.ingested'],
            'page_size': ['0', '-1', '025', '25.0', '51'],
            'ip': ['192.0.2.0/24', 'bad-address', '2130706433', 'fe80::1%eth0'],
        }.items():
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    parse_filters([(key, value)], now=NOW)

    def test_invalid_time_ranges(self):
        for start, end in [
            ('2026-09-22T01:00:00', '2026-09-22T02:00:00Z'),
            ('bad', '2026-09-22T02:00:00Z'),
            ('2026-09-22T02:00:00Z', '2026-09-22T02:00:00Z'),
            ('2026-09-22T03:00:00Z', '2026-09-22T02:00:00Z'),
            ('2026-08-22T02:00:00Z', '2026-09-22T02:00:00Z'),
        ]:
            with self.subTest(start=start), self.assertRaises(ValueError):
                parse_filters([('start', start), ('end', end)], now=NOW)
        for key in ('start', 'end'):
            with self.assertRaises(ValueError):
                parse_filters([(key, '2026-09-22T02:00:00Z')], now=NOW)
        with self.assertRaises(ValueError):
            parse_filters([], now=NOW.replace(tzinfo=None))

    def test_historical_window_and_exact_thirty_day_boundary(self):
        result = parse_filters([('start', '2020-01-01T00:00:00Z'), ('end', '2020-01-31T00:00:00Z')], now=NOW)
        self.assertEqual(result.start, '2020-01-01T00:00:00Z')
        for size in ('10', '25', '50'):
            self.assertEqual(parse_filters([('page_size', size)], now=NOW).page_size, int(size))

    def test_literal_host_name_is_not_interpreted_as_a_query(self):
        result = parse_filters([('host', 'host:* OR *')], now=NOW)
        self.assertEqual(result.host, 'host:* OR *')
        self.assertNotIn('query', asdict(result))


class ProjectionTests(unittest.TestCase):
    def test_eight_synthetic_sources_share_contract_without_mutation(self):
        original = deepcopy(HITS)
        rows = [project_hit(hit) for hit in HITS.values()]
        self.assertEqual(len(rows), 8)
        self.assertTrue(all(set(row) == set(rows[0]) for row in rows))
        self.assertTrue(all(row['parse_status'] == 'not_evaluated' for row in rows))
        self.assertEqual(HITS, original)
        self.assertEqual({row['stream'] for row in rows}, {'host', 'network'})
        self.assertEqual(len({(row['reference']['index'], row['reference']['id']) for row in rows}), 8)

    def test_receipt_time_is_not_event_time_and_legacy_has_no_fallback(self):
        row = project_hit(HITS['windows-event'])
        self.assertEqual(row['received_at'], '2026-09-22T01:00:03Z')
        self.assertEqual(row['event_at'], '2026-09-22T01:00:00Z')
        legacy = project_hit(HITS['legacy'])
        self.assertIsNone(legacy['received_at'])
        self.assertEqual(legacy['event_at'], '2020-01-01T00:00:00Z')
        self.assertEqual(legacy['source_kind'], 'unknown')
        self.assertEqual(legacy['os'], 'unknown')

    def test_no_inference_from_text_event_code_or_network_observation(self):
        for key in ('windows-event', 'windows-file', 'linux-file', 'flow'):
            row = project_hit(HITS[key])
            self.assertEqual(row['outcome'], 'unknown')
            self.assertIsNone(row['user'])
            self.assertIsNone(row['action'])
        self.assertIsNone(project_hit(HITS['linux-file'])['source_ip'])
        self.assertEqual(project_hit(HITS['flow'])['source_ip'], '192.0.2.10')
        self.assertEqual(project_hit(HITS['flow'])['destination_ip'], '198.51.100.20')
        self.assertTrue(project_hit(HITS['flow'])['flow_final'])

    def test_os_evidence_and_sensor_not_peer(self):
        expected = {
            'windows-event': ('windows', 'host.os.type'), 'windows-file': ('windows', 'labels.log_source'),
            'linux-file': ('linux', 'host.os.type'), 'linux-journal': ('linux', 'labels.log_source'),
            'flow': ('windows', 'labels.sensor_platform'), 'dns': ('linux', 'labels.sensor_platform'),
        }
        for key, values in expected.items():
            row = project_hit(HITS[key])
            self.assertEqual((row['os'], row['os_basis']), values)
        self.assertEqual(project_hit(HITS['flow'])['host_name'], 'win.example.test')
        self.assertEqual(operating_system({'host': {'os': {'name': 'Windows'}}}), ('unknown', None))
        self.assertEqual(operating_system({'host': {'name': 'linux-production'}}), ('unknown', None))

    def test_nested_values_private_payloads_and_unknown_fields_are_not_forwarded(self):
        hit = deepcopy(HITS['windows-event'])
        hit['_source'].update({'api_key': 'PRIVATE_CANARY', 'message': 'MESSAGE_CANARY',
                               'process': {'command_line': 'COMMAND_CANARY'}})
        hit['_source']['event']['original'] = 'ORIGINAL_CANARY'
        hit['_source']['winlog']['event_data']['Secret'] = 'NESTED_CANARY'
        result = json.dumps(project_hit(hit))
        for marker in ('PRIVATE_CANARY', 'MESSAGE_CANARY', 'COMMAND_CANARY', 'ORIGINAL_CANARY', 'NESTED_CANARY'):
            self.assertNotIn(marker, result)
        for path in ('message', 'event.original', 'process.command_line', 'winlog.event_data'):
            self.assertNotIn(path, SOURCE_FIELDS)

    def test_sparse_and_malformed_values_are_not_stringified(self):
        hit = deepcopy(HITS['legacy'])
        hit['_source'] = {
            '@timestamp': 'not-a-time', 'event': {'ingested': '2026-09-22T01:00:00', 'outcome': 'safe'},
            'host': {'name': {'unexpected': 'value'}, 'ip': ['bad', '192.0.2.1', '192.0.2.1', 123]},
            'user': {'name': ['alice']}, 'source': {'ip': ['192.0.2.1']}, 'flow': {'final': 'false'},
        }
        row = project_hit(hit)
        self.assertIsNone(row['host_name'])
        self.assertIsNone(row['received_at'])
        self.assertIsNone(row['event_at'])
        self.assertIsNone(row['user'])
        self.assertIsNone(row['source_ip'])
        self.assertIsNone(row['flow_final'])
        self.assertEqual(row['outcome'], 'unknown')
        self.assertEqual(row['host_ips'], ['192.0.2.1'])
        self.assertEqual(row['quality']['invalid_fields'], sorted([
            '@timestamp', 'event.ingested', 'event.outcome', 'host.name', 'host.ip', 'user.name', 'source.ip', 'flow.final',
        ]))

    def test_bounded_strings_ips_and_loss_indicators(self):
        hit = deepcopy(HITS['legacy'])
        hit['_source']['host'] = {'name': 'a' * 600, 'ip': ['192.0.2.1'] * 17}
        row = project_hit(hit)
        self.assertEqual(len(row['host_name']), 512)
        self.assertEqual(row['host_ips'], ['192.0.2.1'])
        self.assertEqual(row['quality']['truncated_fields'], ['host.ip', 'host.name'])

    def test_ipv6_is_canonicalized_and_scoped_addresses_rejected(self):
        hit = deepcopy(HITS['dns'])
        hit['_source']['source']['ip'] = '2001:0db8:0:0::1'
        hit['_source']['destination']['ip'] = 'fe80::1%eth0'
        row = project_hit(hit)
        self.assertEqual(row['source_ip'], '2001:db8::1')
        self.assertIsNone(row['destination_ip'])

    def test_unknown_source_and_contradictory_stream_are_not_recategorized(self):
        hit = deepcopy(HITS['legacy'])
        hit['_source']['labels'] = {'log_source': 'future-cloud-source'}
        row = project_hit(hit)
        self.assertEqual(row['source_label'], 'future-cloud-source')
        self.assertEqual(row['source_kind'], 'unknown')
        hit['_source']['labels']['log_source'] = 'network_packetbeat'
        self.assertEqual(project_hit(hit)['source_kind'], 'unknown')

    def test_false_flow_final_and_explicit_outcome_survive(self):
        hit = deepcopy(HITS['flow'])
        hit['_source']['flow']['final'] = False
        hit['_source']['event']['outcome'] = 'failure'
        hit['_source']['user'] = {'name': 'fixture-user'}
        row = project_hit(hit)
        self.assertIs(row['flow_final'], False)
        self.assertEqual(row['outcome'], 'failure')
        self.assertEqual(row['user'], 'fixture-user')
        self.assertEqual(row['parse_status'], 'not_evaluated')

    def test_missing_source_is_not_a_successful_empty_document(self):
        for value in (None, [], 'invalid'):
            with self.assertRaises(ValueError):
                project_hit({**HITS['legacy'], '_source': value})


class ReferenceTests(unittest.TestCase):
    def test_reference_preserves_identity_without_truncation(self):
        identifier = 'doc/with+symbols?and#unicode-한글'
        self.assertEqual(document_reference('soc-host-raw-test', identifier),
                         {'index': 'soc-host-raw-test', 'id': identifier})

    def test_non_intake_wildcard_url_multiindex_and_oversized_references_rejected(self):
        for index in ('*', '.security', 'security-alerts', 'raw-logs-1', 'soc-host-raw-*',
                      'soc-network-a,soc-network-b', 'soc-network-', 'soc-network-../secret',
                      'https://example.test', 'soc-network-' + 'a' * 250, None):
            with self.subTest(index=index), self.assertRaises(ValueError):
                document_reference(index, 'id')
        for identifier in ('', None, 1, 'bad\nid', '한' * 171):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                document_reference('soc-network-test', identifier)

    def test_index_scopes_match_existing_reader_without_expanding_permissions(self):
        from cloud_soc.portal.agent_status import INDICES as MONITOR_INDICES
        self.assertEqual(INDICES, (*MONITOR_INDICES.split(','), 'soc-cloud-aws-*', 'soc-cloud-oci-*'))
        for name, pattern in [('index-template.json', INDICES[0]), ('network-index-template.json', INDICES[1])]:
            template = json.loads((ROOT / 'deploy/agents' / name).read_text(encoding='utf-8'))
            self.assertEqual(template['index_patterns'], [pattern])

    def test_packetbeat_os_contract_tracks_actual_allowlist(self):
        config = json.loads((ROOT / 'deploy/agents/packetbeat.base.json').read_text(encoding='utf-8'))
        included = next(p['include_fields']['fields'] for p in config['processors'] if 'include_fields' in p)
        self.assertNotIn('host.os.type', included)
        self.assertIn('labels', included)
        self.assertIn('sensor_platform', config['processors'][2]['add_fields']['fields'])


if __name__ == '__main__':
    unittest.main()
