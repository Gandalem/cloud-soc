"""Synthetic-only collector fixtures; no agents or network are started."""
import copy
from datetime import datetime, timezone
import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tarfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
SPEC = importlib.util.spec_from_file_location('p2_metrics', ROOT / 'deploy/agents/collector-metrics.py')
METRICS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(METRICS)
NOW = datetime(2026, 10, 7, 6, 0, tzinfo=timezone.utc)


def line(service='filebeat', timestamp='2026-10-07T05:59:30Z', **changes):
    entry = {'@timestamp': timestamp, 'log.logger': 'monitoring', 'service.name': service,
             'message': 'Non-zero metrics in the last 30s', 'secret': 'PRIVATE_CANARY',
             'monitoring': {'metrics': {'libbeat': {'pipeline': {'queue': {'filled': {
                 'bytes': 900, 'events': 9, 'pct': .9}}}, 'output': {'events': {'total': 10,
                 'acked': 8, 'failed': 2}, 'read': {'errors': 1}}}}}, **changes}
    return json.dumps(entry).encode()


class MetricsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.host = Path(self.temp.name) / 'host'
        self.network = Path(self.temp.name) / 'network'
        for root in (self.host, self.network):
            (root / 'logs').mkdir(parents=True)
            if os.name == 'posix':
                root.chmod(0o700)
                (root / 'logs').chmod(0o700)

    def write(self, data, name='filebeat-20261007.ndjson', root=None):
        path = (root or self.host) / 'logs' / name
        path.write_bytes(data)
        if os.name == 'posix':
            path.chmod(0o600)
        return path

    def config(self, root, service, organization='test', endpoint='https://soc.test:9200', ca=b'fixture-ca'):
        config = {'processors': [{'add_fields': {'target': 'organization', 'fields': {'id': organization}}}],
                  'output.elasticsearch': {'hosts': [endpoint], 'api_key': 'PRIVATE_CANARY',
                  'ssl.verification_mode': 'full', 'ssl.certificate_authorities': [str(root / 'ca.crt')]}}
        (root / (service + '.yml')).write_text(json.dumps(config))
        (root / 'ca.crt').write_bytes(ca)
        if os.name == 'posix':
            (root / (service + '.yml')).chmod(0o600)
            (root / 'ca.crt').chmod(0o600)

    def test_allowlist_nulls_and_privacy_for_both_services(self):
        for service in ('filebeat', 'packetbeat'):
            sample = METRICS.parse(line(service), service)
            self.assertEqual(sample['output_acked'], 8)
            self.assertEqual(sample['queue_pct'], .9)
            self.assertIsNone(sample['output_dropped'])
            self.assertNotIn('PRIVATE_CANARY', json.dumps(sample))

    def test_bad_numbers_do_not_turn_missing_into_zero(self):
        for value in (True, '3', -1, 1.5, 2**53, float('nan'), float('inf')):
            entry = json.loads(line())
            entry['monitoring']['metrics']['libbeat']['output']['events']['failed'] = value
            sample = METRICS.parse(json.dumps(entry).encode(), 'filebeat')
            self.assertIsNone(sample['output_failed'])
        for value in (-.1, 1.1, True, float('inf')):
            self.assertIsNone(METRICS.number(value, True))

    def test_wrong_identity_shutdown_timestamp_interval_and_json_rejected(self):
        for record in (line('packetbeat'), line(message='Total metrics'), line(timestamp='2026-10-07'),
                       line(message=True), line(message='Non-zero metrics in the last 86401s'),
                       b'{"monitoring":invalid}', b'{"monitoring":{},"monitoring":{}}', b'\xff"monitoring"',
                       b'x' * (METRICS.MAX_LINE + 1)):
            self.assertIsNone(METRICS.parse(record, 'filebeat'))
        self.assertIsNotNone(METRICS.parse(line(timestamp='2026-10-07T14:59:30.123456789+0900'), 'filebeat'))
        self.assertEqual(METRICS.timestamp('2026-10-07T14:59:30.12+0900').isoformat(), '2026-10-07T05:59:30.120000+00:00')
        self.assertEqual(METRICS.timestamp('2026-10-07T14:59:30.123456789+0900').microsecond, 123456)

    def test_latest_complete_record_and_recent_problem(self):
        self.write(line() + b'\n' + line(timestamp='2026-10-07T06:00:00Z', monitoring={'metrics': {}}) + b'\n' + line(timestamp='2026-10-07T07:00:00Z'))
        result = METRICS.read(self.host, now=NOW)
        self.assertEqual(result['sampled_at'], '2026-10-07T06:00:00Z')
        self.assertIsNone(result['output_failed'])
        self.assertEqual(result['last_problem_at'], '2026-10-07T05:59:30Z')
        self.assertTrue(result['scan_partial'])
        self.assertIsNone(METRICS.read(self.host, now=NOW.replace(hour=7))['last_problem_at'])

    def test_event_data_other_collectors_and_unfinished_records_are_never_samples(self):
        self.write(line() + b'\n', 'filebeat-events-data-20261007.ndjson')
        self.write(line('packetbeat') + b'\n', 'packetbeat-20261007.ndjson')
        self.write(line())
        self.assertEqual(METRICS.read(self.host)['state'], 'unavailable')

    def test_tail_file_count_and_line_limits_are_visible(self):
        self.write(b'x' * (METRICS.MAX_TAIL + 100) + b'\n' + line() + b'\n')
        result = METRICS.read(self.host, now=NOW)
        self.assertEqual(result['state'], 'observed')
        self.assertTrue(result['scan_partial'])
        for suffix in range(5):
            self.write(line() + b'\n', f'filebeat-20261007-{suffix}.ndjson')
        self.assertTrue(METRICS.read(self.host)['scan_partial'])
        for suffix in range(130):
            self.write(b'', f'ignore-{suffix}')
        self.assertEqual(METRICS.read(self.host)['reason'], 'too_many_files')

    def test_missing_failed_and_linked_reads_do_not_leak_errors(self):
        self.assertEqual(METRICS.read(self.host / 'absent')['state'], 'unavailable')
        with patch.object(METRICS.Path, 'is_symlink', return_value=True):
            result = METRICS.read(self.host)
        self.assertEqual(result['state'], 'unavailable')
        self.assertNotIn(str(self.host), json.dumps(result))
        self.write(line() + b'\n')
        with patch.object(METRICS, 'open_checked', side_effect=PermissionError('PRIVATE_CANARY')):
            result = METRICS.read(self.host)
        self.assertTrue(result['scan_partial'])
        self.assertNotIn('PRIVATE_CANARY', json.dumps(result))

    @unittest.skipUnless(os.name == 'posix', 'Linux filesystem permissions required')
    def test_fifo_hardlink_symlink_and_untrusted_writer_are_rejected(self):
        path = self.write(line() + b'\n')
        os.link(path, path.with_name('hardlink'))
        self.assertEqual(METRICS.read(self.host)['state'], 'unavailable')
        path.with_name('hardlink').unlink()
        path.chmod(0o666)
        self.assertEqual(METRICS.read(self.host)['state'], 'unavailable')
        path.unlink()
        os.mkfifo(path)
        self.assertEqual(METRICS.read(self.host)['state'], 'unavailable')
        path.unlink()
        path.symlink_to(self.host / 'ca.crt')
        self.assertEqual(METRICS.read(self.host)['state'], 'unavailable')

    def test_network_binding_matches_server_organization_and_ca(self):
        self.config(self.host, 'filebeat')
        self.config(self.network, 'packetbeat')
        self.write(line('packetbeat') + b'\n', 'packetbeat-20261007.ndjson', self.network)
        result = METRICS.read_network(self.host, self.network, now=NOW)
        self.assertEqual(result['state'], 'observed')
        self.assertNotIn('PRIVATE_CANARY', json.dumps(result))
        for changes in ({'organization': 'different'}, {'endpoint': 'https://else.test:9200'}, {'ca': b'else-ca'}):
            self.config(self.network, 'packetbeat', **changes)
            self.assertEqual(METRICS.read_network(self.host, self.network)['reason'], 'identity_mismatch')

    def test_missing_corrupt_or_unbounded_config_is_unknown(self):
        self.assertEqual(METRICS.read_network(self.host, self.network)['state'], 'unavailable')
        self.config(self.host, 'filebeat')
        self.config(self.network, 'packetbeat')
        for data in ('null', '{}', '"PRIVATE_CANARY"', 'x' * 262145):
            (self.network / 'packetbeat.yml').write_text(data)
            self.assertEqual(METRICS.read_network(self.host, self.network)['state'], 'unavailable')

    def test_reader_output_uses_existing_server_validation(self):
        from cloud_soc.portal.collection_health import collector_metrics
        self.write(line() + b'\n')
        sample = METRICS.read(self.host, now=NOW)
        projected = collector_metrics(sample, NOW, NOW)
        self.assertEqual(projected['queue_state'], 'high')
        self.assertEqual(projected['transport_state'], 'error_observed')
        self.assertEqual(collector_metrics(sample, NOW, NOW.replace(hour=7))['state'], 'stale')

    def test_linux_spool_integration_and_reader_failure_fallback(self):
        bash = 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else shutil.which('bash')
        if not bash:
            self.skipTest('bash unavailable')
        (self.host / 'inputs').mkdir()
        shutil.copy(ROOT / 'deploy/agents/collector-metrics.py', self.host)
        self.write(line() + b'\n')
        script = '''source ./discover-linux.sh
root=$FIXTURE_ROOT
python=$FIXTURE_PYTHON
if command -v cygpath >/dev/null; then root=$(cygpath -u "$root"); python=$(cygpath -u "$python"); fi
python3() { "$python" "$@"; }
# Replace only the subprocess launcher in this rendering fixture.
timeout() { shift 2; "$python" "$@"; }
HEALTH_SELECTED=0 HEALTH_EXCLUDED=0 HEALTH_ERRORS=0 HEALTH_SOURCES=()
publish_health_report "$root"
timeout() { return 1; }
publish_health_report "$root"
'''
        process = subprocess.run([bash, '-c', script], cwd=ROOT / 'deploy/agents', text=True,
                                 capture_output=True, timeout=30,
                                 env={**os.environ, 'FIXTURE_ROOT': str(self.host), 'FIXTURE_PYTHON': sys.executable})
        self.assertEqual(process.returncode, 0, process.stderr)
        rows = [json.loads(row) for row in (self.host / 'health.ndjson').read_text().splitlines()]
        self.assertEqual(rows[0]['collector_metrics']['state'], 'observed')
        self.assertEqual(rows[1]['collector_metrics']['state'], 'unavailable')
        self.assertNotIn('PRIVATE_CANARY', json.dumps(rows))
        self.assertNotIn(str(self.host), json.dumps(rows))


class NetworkProjectionTests(unittest.TestCase):
    def test_old_report_and_independent_invalid_network_sample(self):
        from cloud_soc.portal.collection_health import project
        from test_collection_health import SOURCE, KEY
        old = project(copy.deepcopy(SOURCE), KEY, NOW)
        self.assertEqual(old['network_collector_metrics']['state'], 'unavailable')
        source = copy.deepcopy(SOURCE)
        source['cloud_soc']['discovery']['network_collector_metrics'] = {'schema': 1, 'state': 'observed', 'password': 'PRIVATE_CANARY'}
        row = project(source, KEY, NOW)
        self.assertEqual(row['network_collector_metrics']['state'], 'invalid')
        self.assertEqual(row['selected'], old['selected'])
        self.assertNotIn('PRIVATE_CANARY', json.dumps(row))

    def test_host_and_network_counters_are_not_merged(self):
        from cloud_soc.portal.collection_health import project
        from test_collection_health import HealthTests, KEY
        source = HealthTests().metrics_source()
        network = METRICS.parse(line('packetbeat'), 'packetbeat')
        network.update(scan_partial=False, last_problem_at=None)
        source['cloud_soc']['discovery']['generated_at'] = '2026-10-07T06:00:00Z'
        source['event']['ingested'] = '2026-10-07T06:00:00Z'
        source['cloud_soc']['discovery']['network_collector_metrics'] = network
        row = project(source, KEY, NOW)
        self.assertEqual(row['network_collector_metrics']['output_failed'], 2)
        self.assertEqual(row['collector_metrics']['output_failed'], 1)
        self.assertEqual(row['source_success'], 'not_measured')

    def test_generated_ubuntu_bundle_contains_reader(self):
        from cloud_soc.portal.packages import FILES, build_bundle
        self.assertIn('collector-metrics.py', FILES['ubuntu'])
        spec = {'os': 'ubuntu', 'network': True, 'endpoint': 'https://soc.test:9200',
                'organization': 'test', 'name': 'p2-test', 'description': ''}
        data, _ = build_bundle(spec, ROOT / 'deploy/agents', b'fixture-ca')
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            reader = archive.extractfile('collector-metrics.py').read()
            self.assertEqual(reader, (ROOT / 'deploy/agents/collector-metrics.py').read_bytes())
            hashes = archive.extractfile('SHA256SUMS').read().decode().splitlines()
            self.assertIn(hashlib.sha256(reader).hexdigest() + '  collector-metrics.py', hashes)


@unittest.skipUnless(os.name == 'nt', 'Windows .NET Framework required')
class NativeMetricsTests(unittest.TestCase):
    def test_compiled_packetbeat_contract_and_existing_native_worker(self):
        framework = Path(os.environ['WINDIR']) / 'Microsoft.NET/Framework64/v4.0.30319'
        (ROOT / 'state').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='p2-metrics-', dir=ROOT / 'state') as scratch:
            exe = Path(scratch) / 'metrics-test.exe'
            result = subprocess.run([str(framework / 'csc.exe'), '/noconfig', '/nologo', '/target:exe',
                '/platform:x64', '/main:P2MetricsTests',
                *['/reference:' + str(framework / name) for name in ('System.dll', 'System.Core.dll', 'System.Web.Extensions.dll')],
                '/out:' + str(exe), str(ROOT / 'deploy/agents/discovery-native.cs'),
                str(ROOT / 'deploy/agents/tests/collector-metrics-tests.cs'),
                str(ROOT / 'deploy/agents/tests/discovery-native-tests.cs')], capture_output=True, text=True, errors='replace', timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(exe), scratch], capture_output=True, text=True, errors='replace', timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('P2 metrics checks passed', result.stdout)


if __name__ == '__main__':
    unittest.main()
