"""Local tool guards only. Never stops or installs a host service."""
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


def load(relative):
    spec = importlib.util.spec_from_file_location(relative.replace('/', '_'), ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class InstallToolsTests(unittest.TestCase):
    def test_help_never_checks_host_or_mutates_services(self):
        tool = load('deploy/server/soc.py')
        with patch.object(tool, 'require_host') as host, patch.object(tool, 'command') as command:
            with patch('sys.argv', ['soc', '--help']), patch('sys.stdout', new=io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    tool.main()
        self.assertEqual(error.exception.code, 0)
        host.assert_not_called()
        command.assert_not_called()

    def test_install_rejects_existing_state_before_any_external_command(self):
        tool = load('deploy/server/soc.py')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'state/server').mkdir(parents=True)
            sentinel = root / 'state/server/keep'
            sentinel.write_bytes(b'original-key-and-state-canary')
            with patch.object(tool, 'ROOT', root), patch.object(tool, 'command') as command:
                with self.assertRaises(RuntimeError):
                    tool.install(ask=Mock(side_effect=AssertionError('no prompt expected')))
            command.assert_not_called()
            self.assertEqual(sentinel.read_bytes(), b'original-key-and-state-canary')

    def test_cloud_install_keeps_public_and_private_addresses_separate(self):
        tool = load('deploy/server/soc.py')
        answers = iter(['3', 'soc.example.test', '', 'ingest.example.test'])
        calls = []
        def command(args, **kwargs):
            calls.append([str(a) for a in args])
            if args[0] == 'ip':
                return SimpleNamespace(returncode=0, stdout=json.dumps([{'addr_info': [{'scope': 'global', 'local': '10.0.0.8'}]}]))
            return SimpleNamespace(returncode=0, stdout='yes\n')
        with tempfile.TemporaryDirectory() as temporary, patch.object(tool, 'ROOT', Path(temporary)), patch.object(tool, 'command', side_effect=command), patch('sys.stdout', new=io.StringIO()):
            self.assertEqual(tool.install(ask=lambda _: next(answers)), 0)
        self.assertEqual(calls[-1][-6:], ['--host', 'soc.example.test', '--bind-ip', '10.0.0.8', '--agent-host', 'ingest.example.test'])
        self.assertNotIn('--yes', calls[-1])

    def test_purge_requires_explicit_delete_and_never_removes_shared_docker(self):
        tool = load('deploy/server/soc.py')
        with patch.object(tool, 'command') as command, patch('sys.stdout', new=io.StringIO()):
            answers = iter(['2', 'no'])
            tool.uninstall(ask=lambda _: next(answers))
            command.assert_not_called()
            answers = iter(['1'])
            command.return_value.returncode = 0
            tool.uninstall(ask=lambda _: next(answers))
            args = [str(a) for a in command.call_args.args[0]]
            self.assertNotIn('--purge-data', args)
            self.assertNotIn('--remove-docker', args)
            self.assertIn('--apply', args)

    def test_agent_cancel_preserves_queue_without_service_commands(self):
        tool = load('deploy/agents/agent-manager.py')
        module = SimpleNamespace(system=Mock())
        with patch.object(tool, 'receipt', return_value={'session': 'synthetic'}), patch('sys.stdout', new=io.StringIO()):
            tool.manage(module, {}, 'uninstall', confirm=lambda _: '0')
        module.system.assert_not_called()

    def test_agent_refuses_computed_removal_outside_fixed_roots_before_stopping_services(self):
        tool = load('deploy/agents/agent-manager.py')
        module = SimpleNamespace(system=Mock(), ROOTS={'host': ROOT}, roles=lambda _: ['host'])
        with patch.object(tool, 'receipt', return_value={'session': 'synthetic'}), patch('sys.stdout', new=io.StringIO()):
            with self.assertRaises(RuntimeError):
                tool.manage(module, {}, 'uninstall', confirm=lambda _: '1')
        module.system.assert_not_called()


if __name__ == '__main__':
    unittest.main()
