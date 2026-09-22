import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('agent_policy', ROOT / 'deploy/agents/policy.py')
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        (ROOT / 'state').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / 'state', prefix='policy-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'agent'
        self.root.mkdir(); (self.root / 'inputs').mkdir(); (self.root / 'data').mkdir()
        self.logs = Path(self.temp.name) / 'logs'; self.logs.mkdir()
        self.platform = 'windows' if os.name == 'nt' else 'linux'
        script = 'discover-windows.ps1' if os.name == 'nt' else 'discover-linux.sh'
        (self.root / script).write_bytes((ROOT / 'deploy/agents' / script).read_bytes())
        self.base = {'roots': [str(self.logs)], 'exclusions': []}
        if os.name == 'nt':
            (self.root / 'discovery-settings.json').write_text(json.dumps({'log_roots': self.base['roots'], 'required_channels': ['Security']}))
        else:
            (self.root / 'discovery-roots.txt').write_text(str(self.logs) + '\n')
        for filename in ('registry', 'diskqueue', 'filebeat.keystore'):
            (self.root / 'data' / filename).write_bytes(b'PROTECTED_CANARY')

    def test_dry_run_conflict_apply_rollback_preserve_state(self):
        proposal = {**self.base, 'exclusions': [str(self.logs / 'private.log')]}
        preview = policy.update(self.root, self.platform, proposal)
        self.assertFalse(preview['applied'])
        self.assertFalse((self.root / 'collection-policy.txt').exists())
        self.assertEqual(policy.update(self.root, self.platform, proposal, apply=True, expected=0)['version'], 1)
        with self.assertRaises(ValueError):
            policy.update(self.root, self.platform, self.base, apply=True, expected=0)
        result = policy.update(self.root, self.platform, apply=True, expected=1, rollback=0)
        self.assertEqual(result['version'], 2)
        self.assertEqual(policy.current(self.root, self.platform), (policy.validate(self.base, self.platform), 2))
        for item in (self.root / 'data').iterdir():
            self.assertEqual(item.read_bytes(), b'PROTECTED_CANARY')

    def test_failed_publication_keeps_prior_policy_and_allows_retry(self):
        policy.update(self.root, self.platform, self.base, apply=True, expected=0)
        before = (self.root / 'collection-policy.txt').read_bytes()
        with patch.object(policy.os, 'replace', side_effect=OSError('synthetic failure')):
            with self.assertRaises(OSError):
                policy.update(self.root, self.platform, self.base, apply=True, expected=1)
        self.assertEqual((self.root / 'collection-policy.txt').read_bytes(), before)
        self.assertEqual(policy.update(self.root, self.platform, self.base, apply=True, expected=1)['version'], 2)

    def test_lock_prevents_concurrent_discovery_and_policy_update(self):
        with policy.locked(self.root):
            with self.assertRaises((ValueError, BlockingIOError)):
                policy.update(self.root, self.platform, self.base, apply=True, expected=0)

    def test_no_commands_globs_personal_roots_or_external_exclusions(self):
        for platform, roots in [('linux', ['/', '/home/user/logs', '/etc/app', '/var/log/../secret', '/var/log/*']),
                                ('windows', ['C:\\', 'C:\\Users\\person', 'C:\\logs\\..\\secret', '\\\\server\\share'])]:
            for root in roots:
                with self.subTest(root=root), self.assertRaises(ValueError):
                    policy.validate({'roots': [root], 'exclusions': []}, platform)
        with self.assertRaises(ValueError):
            policy.validate({'roots': ['/var/log'], 'exclusions': ['/srv/logs']}, 'linux')
        with self.assertRaises(ValueError):
            policy.validate({**self.base, 'command': 'do not execute'}, self.platform)

    def test_old_agents_are_not_reported_as_updated(self):
        script = 'discover-windows.ps1' if os.name == 'nt' else 'discover-linux.sh'
        (self.root / script).write_text('# older discovery script')
        with self.assertRaises(ValueError):
            policy.update(self.root, self.platform, self.base, apply=True, expected=0)
        self.assertFalse((self.root / 'collection-policy.txt').exists())
