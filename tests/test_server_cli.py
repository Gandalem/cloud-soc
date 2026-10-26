"""Server CLI boundaries with disposable files and an explicit Docker double."""
from contextlib import redirect_stdout, redirect_stderr
from copy import deepcopy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from cloud_soc.deployment.contract import SERVICES

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location('server_test_' + name, ROOT / 'deploy/server' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def container(root, service, *, running=True):
    return {'Id': 'id-' + service, 'Config': {'Labels': {
        'com.docker.compose.project': 'cloud-soc-central',
        'com.docker.compose.service': service,
        'com.docker.compose.project.config_files': str(root / 'deploy/server/compose.yaml')}},
        'State': {'Running': running, 'Status': 'running' if running else 'exited',
                  'ExitCode': 0, 'Restarting': False, 'OOMKilled': False, 'Paused': False},
        'Mounts': [], 'NetworkSettings': {'Networks': {}}}


class ServerMenuTests(unittest.TestCase):
    def test_python_workers_receive_signals_through_init(self):
        import yaml
        fragment = yaml.safe_load((ROOT / 'deploy/server/runtime.compose.yaml').read_text(encoding='utf-8'))
        central = yaml.safe_load((ROOT / 'deploy/server/compose.yaml').read_text(encoding='utf-8'))
        for name, row in fragment['services'].items():
            with self.subTest(service=name):
                self.assertIs(row.get('init'), True)
                self.assertEqual(row['command'][0], 'python')
                self.assertNotIn('stop_signal', row)
        self.assertIs(central['services']['enrollment-cleanup'].get('init'), True)

    def test_help_and_invalid_command_are_korean_without_echoing_secret(self):
        tool = load('soc')
        for action, expected in (('--help', 0), ('accidental-secret-canary', 2)):
            with self.subTest(action=action), patch('sys.argv', ['soc', action]), \
                    patch.object(tool, 'require_host') as host, patch.object(tool, 'command') as command, \
                    redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()) as error:
                with self.assertRaises(SystemExit) as result:
                    tool.main()
                self.assertEqual(result.exception.code, expected)
                text = output.getvalue() + error.getvalue()
                self.assertIn('사용법:', text)
                self.assertNotIn('usage:', text)
                self.assertNotIn('accidental-secret-canary', text)
                host.assert_not_called()
                command.assert_not_called()

    def test_invalid_menu_input_help_and_failed_action_return_to_menu(self):
        tool = load('soc')
        ask = Mock(side_effect=['wrong', 'help', 'status', 'exit'])
        with patch('sys.argv', ['soc']), patch.object(tool, 'require_host') as host, \
                patch.object(tool, 'status', side_effect=RuntimeError('조회 실패')), \
                redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()) as error:
            self.assertEqual(tool.main(ask=ask), 0)
        self.assertIn('입력할 수 있는 값', output.getvalue())
        self.assertIn('조회 실패', error.getvalue())
        host.assert_called_once()
        self.assertEqual(ask.call_count, 4)

    def test_install_retries_only_invalid_fields_and_passes_explicit_addresses(self):
        tool = load('soc')
        answers = Mock(side_effect=['bad-mode', 'cloud', 'https://wrong', 'SOC.EXAMPLE.TEST',
                                    'broken', '203.0.113.4', '10.0.0.8', 'bad:9200', 'ingest.example.test'])
        def command(args, **kwargs):
            if args[0] == 'ip':
                return SimpleNamespace(returncode=0, stdout=json.dumps([{'addr_info': [
                    {'scope': 'global', 'local': '10.0.0.8'}]}]))
            return SimpleNamespace(returncode=0, stdout='yes\n')
        with tempfile.TemporaryDirectory() as temporary, patch.object(tool, 'ROOT', Path(temporary)), \
                patch.object(tool, 'command', side_effect=command) as execute, redirect_stdout(io.StringIO()):
            self.assertEqual(tool.install(ask=answers), 0)
        call = list(map(str, execute.call_args.args[0]))
        self.assertEqual(call[-6:], ['--host', 'soc.example.test', '--bind-ip', '10.0.0.8',
                                     '--agent-host', 'ingest.example.test'])
        self.assertNotIn('--yes', call)
        self.assertEqual(answers.call_count, 9)


class ServerStatusTests(unittest.TestCase):
    def setUp(self):
        self.tool = load('soc')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def show(self, rows):
        remove = load('uninstall')
        with patch.object(self.tool, 'ROOT', self.root), patch.object(self.tool, 'removal_tool', return_value=remove), \
                patch.object(remove, 'objects', return_value=rows), redirect_stdout(io.StringIO()) as output:
            result = self.tool.status()
        return result, output.getvalue()

    def test_required_services_no_health_and_successful_one_shot_are_distinct(self):
        rows = [container(self.root, name) for name in SERVICES]
        rows.append(container(self.root, 'bootstrap', running=False))
        result, output = self.show(rows)
        self.assertEqual(result, 0)
        self.assertIn('상태 점검 미설정', output)
        self.assertIn('초기 준비 작업: 완료', output)
        self.assertIn(f'필수 서비스 {len(SERVICES)}개', output)
        self.assertIn('장치 로그 수신과 경보 생성은 포털', output)
        rows[0]['State']['Health'] = {'Status': 'unhealthy'}
        self.assertEqual(self.show(rows)[0], 1)
        rows[0]['State']['Health'] = {'Status': 'starting'}
        self.assertEqual(self.show(rows)[0], 1)

    def test_missing_paused_restarting_and_failed_bootstrap_require_attention(self):
        for status in ('paused', 'restarting', 'exited'):
            with self.subTest(status=status):
                row = container(self.root, 'portal', running=status == 'paused')
                row['State']['Status'] = status
                result, output = self.show([row])
                self.assertEqual(result, 1)
                self.assertIn('없음', output)
                self.assertNotIn('portal: 실행 중', output)
        row = container(self.root, 'bootstrap', running=False)
        row['State']['ExitCode'] = 1
        self.assertEqual(self.show([row])[0], 1)

    def test_preserved_data_is_not_reported_as_running_or_healthy(self):
        (self.root / 'state/server').mkdir(parents=True)
        result, output = self.show([])
        self.assertEqual(result, 0)
        self.assertIn('실행 서비스 없음 · 보존된 서버 자료 있음', output)
        self.assertIn('복구 절차', output)
        self.assertNotIn('상태 점검 통과', output)

    def test_foreign_checkout_duplicate_service_and_query_failure_do_not_become_empty_success(self):
        with self.assertRaises(RuntimeError):
            self.show([container(self.root / 'different', 'portal')])
        with self.assertRaises(RuntimeError):
            self.show([container(self.root, 'portal')] * 2)
        remove = load('uninstall')
        with patch.object(self.tool, 'removal_tool', return_value=remove), \
                patch.object(remove, 'objects', side_effect=remove.RemovalError('조회 실패')), \
                redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(remove.RemovalError):
                self.tool.status()
        self.assertNotIn('실행 서비스 없음', output.getvalue())


class RemovalWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tool = load('uninstall')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'deploy/server').mkdir(parents=True)
        (self.root / 'deploy/server/install-ubuntu.sh').touch()
        self.state = self.root / 'state/server'
        self.state.mkdir(parents=True)
        (self.state / 'compose.env').write_text('synthetic-settings-canary', encoding='utf-8')
        self.args = SimpleNamespace(workspace=self.root, component='central', purge_data=True,
                                    remove_images=False, remove_docker=False, select_mode=True,
                                    apply=True, yes=False)
        self.rows = {row['Id']: row for row in [container(self.root, name) for name in
                                               ('elasticsearch', 'portal', 'normalizer', 'gateway')]}
        self.calls = []
        self.failure = None
        self.changed = False
        self.foreign = container(self.root, 'foreign')
        self.foreign['Config']['Labels']['com.docker.compose.project'] = 'other-project'
        self.patches = [patch.object(self.tool.shutil, 'which', return_value='/usr/bin/docker'),
                        patch.object(self.tool, 'KERNEL_FILE', self.root / '90-cloud-soc.conf'),
                        patch.object(self.tool, 'objects', side_effect=self.objects),
                        patch.object(self.tool, 'docker', side_effect=self.docker),
                        patch.object(self.tool.subprocess, 'run', side_effect=self.stop)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def objects(self, kind):
        if kind == 'container':
            return deepcopy([*self.rows.values(), self.foreign])
        return []

    def docker(self, *args):
        self.calls.append(args)
        if args[0] == 'inspect':
            return json.dumps([self.rows[key] for key in args[1:]])
        if args[0] == 'rm':
            for key in args[1:]:
                if self.rows[key]['State']['Running']:
                    raise self.tool.RemovalError('still running')
                del self.rows[key]
            return ''
        raise AssertionError('Unexpected mutation: ' + repr(args))

    def stop(self, args, **kwargs):
        self.calls.append(tuple(args))
        self.assertEqual(args[:6], ['docker', '--host', 'unix:///var/run/docker.sock', 'stop', '-t', '-1'])
        self.assertGreater(kwargs['timeout'], 0)
        self.assertLessEqual(kwargs['timeout'], self.tool.STOP_TIMEOUT)
        for name in kwargs['env']:
            self.assertFalse(name.startswith(('DOCKER_', 'COMPOSE_', 'SOC_')))
        if self.failure == 'timeout':
            raise subprocess.TimeoutExpired(args, kwargs['timeout'], output='secret-output-canary')
        if self.failure == 'error':
            return SimpleNamespace(returncode=1, stderr='secret-output-canary')
        for key in args[6:]:
            self.rows[key]['State'].update(Running=False, Status='exited')
            if self.failure == 'running':
                self.rows[key]['State']['Running'] = True
            if self.failure == '137':
                self.rows[key]['State']['ExitCode'] = 137
            if self.failure == 'oom':
                self.rows[key]['State']['OOMKilled'] = True
        if self.changed:
            self.rows['id-unexpected'] = container(self.root / 'other-checkout', 'kibana')
            self.rows['id-unexpected']['Id'] = 'id-unexpected'
        return SimpleNamespace(returncode=0)

    def apply(self):
        expected = self.tool.plan(self.args)
        with redirect_stdout(io.StringIO()):
            self.tool.apply(self.args, expected)

    def test_graceful_order_nonforce_removal_and_exact_purge_leave_neighbor_intact(self):
        neighbor = self.root / 'state/neighbor'
        neighbor.mkdir()
        (neighbor / 'keep').write_text('KEEP')
        with patch.dict(os.environ, {'DOCKER_HOST': 'tcp://elsewhere', 'SOC_SECRET': 'canary'}):
            self.apply()
        stops = [call[6:] for call in self.calls if len(call) > 3 and call[3] == 'stop']
        self.assertEqual(stops, [('id-gateway',), ('id-normalizer',), ('id-portal',), ('id-elasticsearch',)])
        removes = [call for call in self.calls if call[0] == 'rm']
        self.assertEqual(len(removes), 1)
        self.assertNotIn('-f', removes[0])
        self.assertFalse(self.state.exists())
        self.assertEqual((neighbor / 'keep').read_text(), 'KEEP')
        self.assertTrue((self.root / 'deploy/server/install-ubuntu.sh').is_file())
        self.assertEqual(self.foreign['State']['Running'], True)

    def test_keep_stops_services_and_preserves_original_settings(self):
        self.args.purge_data = False
        self.apply()
        self.assertEqual((self.state / 'compose.env').read_text(), 'synthetic-settings-canary')
        self.assertEqual(self.rows, {})

    def test_timeout_error_running_137_and_oom_never_remove_data_or_leak_output(self):
        original = deepcopy(self.rows)
        for failure in ('timeout', 'error', 'running', '137', 'oom'):
            with self.subTest(failure=failure):
                self.rows = deepcopy(original)
                self.calls.clear()
                self.failure = failure
                with self.assertRaises(self.tool.RemovalError) as error:
                    self.apply()
                self.assertNotIn('secret-output-canary', str(error.exception))
                self.assertFalse(any(call[0] == 'rm' for call in self.calls))
                self.assertEqual((self.state / 'compose.env').read_text(), 'synthetic-settings-canary')

    def test_preexisting_forced_exit_does_not_become_graceful_success(self):
        for row in self.rows.values():
            row['State'].update(Running=False, Status='exited', ExitCode=137)
        with self.assertRaises(self.tool.RemovalError):
            self.apply()
        self.assertTrue(self.state.exists())
        self.assertFalse(any(call[0] == 'rm' for call in self.calls))

    def test_paused_and_ownership_change_during_stop_block_removal(self):
        self.rows['id-gateway']['State']['Paused'] = True
        with self.assertRaises(self.tool.RemovalError):
            self.apply()
        self.rows['id-gateway']['State']['Paused'] = False
        self.changed = True
        with self.assertRaises(self.tool.RemovalError):
            self.apply()
        self.assertTrue(self.state.exists())
        self.assertFalse(any(call[0] == 'rm' for call in self.calls))

    def test_kill_stop_signal_and_foreign_volume_user_are_refused(self):
        self.rows['id-gateway']['Config']['StopSignal'] = 'SIGKILL'
        with self.assertRaises(self.tool.RemovalError):
            self.apply()
        self.assertFalse(any(call[0] == 'docker' for call in self.calls))
        self.rows['id-gateway']['Config'].pop('StopSignal')
        volume = self.tool.PROJECT + '_es-data'
        self.foreign['Mounts'] = [{'Name': volume}]
        with patch.object(self.tool, 'objects', side_effect=lambda kind:
                deepcopy([*self.rows.values(), self.foreign]) if kind == 'container' else
                [{'Name': volume}] if kind == 'volume' else []):
            with self.assertRaises(self.tool.RemovalError):
                self.apply()
        self.assertTrue(self.state.exists())
        self.assertFalse(any(call[0] == 'rm' for call in self.calls))

    def test_one_confirmation_keep_purge_and_cancel_default(self):
        for mode, token in (('keep', 'yes'), ('purge', 'DELETE')):
            with self.subTest(mode=mode), patch.object(self.tool, 'apply') as apply, redirect_stdout(io.StringIO()) as output:
                ask = Mock(side_effect=[mode, token])
                self.tool.confirm_removal(self.args, ask)
                self.assertEqual(ask.call_count, 2)  # one mode selection, one destructive confirmation
                apply.assert_called_once()
                self.assertEqual(self.args.purge_data, mode == 'purge')
                self.assertIn('컨테이너: 4개', output.getvalue())
                self.assertNotIn('synthetic-settings-canary', output.getvalue())
        for answers in ([''], ['bad', 'cancel'], ['keep', ''], ['purge', 'yes'], ['purge', 'delete']):
            with self.subTest(answers=answers), patch.object(self.tool, 'apply') as apply, redirect_stdout(io.StringIO()):
                self.tool.confirm_removal(self.args, Mock(side_effect=answers))
                apply.assert_not_called()
        self.assertTrue(self.state.exists())


if __name__ == '__main__':
    unittest.main()
