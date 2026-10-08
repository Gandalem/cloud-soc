"""Pinned central pipelines and minimum network permissions; no live capture."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from cloud_soc.portal.network_setup import install_network_pipelines
from cloud_soc.portal.status_setup import SetupConflict


class Ingest:
    def __init__(self, existing=None):
        self.saved = deepcopy(existing or {})
        self.writes = []

    def get_pipeline(self, **kwargs):
        # Keep the real v9 method contract instead of silently accepting invalid options.
        if set(kwargs) != {'id'}:
            raise TypeError('Unsupported pipeline query option')
        return deepcopy(self.saved)

    def put_pipeline(self, *, id, body):
        self.writes.append(id)
        self.saved[id] = deepcopy(body)


class Client:
    def __init__(self, existing=None):
        self.ingest = Ingest(existing)


class NetworkSetupTests(unittest.TestCase):
    source = ROOT / 'deploy/agents/packetbeat-pipelines-9.5.2.json'

    def test_pinned_definitions_install_and_repeat_without_overwrite(self):
        definitions = json.loads(self.source.read_text())
        self.assertEqual(len(definitions), 17)
        self.assertIn('packetbeat-9.5.2-routing', definitions)
        client = Client()
        self.assertEqual(install_network_pipelines(client, self.source), 17)
        self.assertEqual(len(client.ingest.writes), 17)
        self.assertEqual(install_network_pipelines(client, self.source), 17)
        self.assertEqual(len(client.ingest.writes), 17)

    def test_server_date_metadata_does_not_trigger_replacement(self):
        definitions = json.loads(self.source.read_text())
        for body in definitions.values():
            body.update(created_date_millis=1, modified_date_millis=2)
        client = Client(definitions)
        install_network_pipelines(client, self.source)
        self.assertEqual(client.ingest.writes, [])

    def test_any_conflict_blocks_all_writes(self):
        definitions = json.loads(self.source.read_text())
        identifier = sorted(definitions)[-1]
        client = Client({identifier: {'processors': [{'set': {'field': 'admin.custom', 'value': True}}]}})
        with self.assertRaises(SetupConflict):
            install_network_pipelines(client, self.source)
        self.assertEqual(client.ingest.writes, [])

    def test_invalid_definitions_fail_without_writes(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / 'bad.json'
            source.write_text('{"unrelated-v1": {"processors": []}}')
            client = Client()
            with self.assertRaises(SetupConflict):
                install_network_pipelines(client, source)
            self.assertEqual(client.ingest.writes, [])

    def test_network_key_has_no_pipeline_management_or_host_write(self):
        role = json.loads((ROOT / 'deploy/agents/network-publisher-role.json').read_text())
        self.assertEqual(set(role['cluster']), {'monitor', 'read_pipeline'})
        self.assertEqual(role['indices'], [{'names': ['soc-network-*'], 'privileges': ['auto_configure', 'create_doc']}])
        base = json.loads((ROOT / 'deploy/agents/packetbeat.base.json').read_text())
        fields = next(p['include_fields']['fields'] for p in base['processors'] if 'include_fields' in p)
        self.assertNotIn('@timestamp', fields)


if __name__ == '__main__':
    unittest.main()
