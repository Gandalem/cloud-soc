"""Fresh-image preparation, private-output boundaries and scoped removal."""
from contextlib import redirect_stdout
from copy import deepcopy
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from cloud_soc.deployment.host import Docker, DockerCommandError
from cloud_soc.deployment.dependencies import DependencyError, check as check_dependencies

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


manage = module('install_lifecycle_manage', 'deploy/server/manage.py')
remove = module('install_lifecycle_remove', 'deploy/server/uninstall.py')
maintenance = module('install_lifecycle_maintenance', 'deploy/server/enrollment-maintenance.py')


class ImagePreparationTests(unittest.TestCase):
    def setUp(self):
        checker = patch.object(manage, 'check_dependencies')
        checker.start()
        self.addCleanup(checker.stop)

    def test_disabled_enrollment_cleanup_idles_without_connecting(self):
        class IdleReached(Exception):
            pass
        with patch.dict(maintenance.os.environ, {'SOC_ENROLLMENT_ENABLED': '0'}), \
                patch.object(maintenance, 'Elasticsearch') as client, \
                patch.object(maintenance.time, 'sleep', side_effect=IdleReached), \
                redirect_stdout(io.StringIO()):
            with self.assertRaises(IdleReached):
                maintenance.main()
        client.assert_not_called()

    def test_install_prepares_missing_infrastructure_before_activation(self):
        events = []
        engine = Mock()
        engine.run.side_effect = lambda args, **kw: events.append((args, kw)) or ''
        plan = {'fresh': True, 'resources': {'ok': True}, 'compose_environment': {'SOC_STATE_DIR': '/lab/state/server'}}
        with patch.object(sys, 'argv', ['manage.py', 'install', '--build']), \
                patch.object(manage.os, 'geteuid', return_value=0, create=True), \
                patch.object(manage, 'Docker', return_value=engine), \
                patch.object(manage, 'snapshot', return_value=plan), \
                patch.object(manage, 'apply', side_effect=lambda *_a, **_kw: events.append(('activate', {})) or {}), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(manage.main(), 0)
        self.assertEqual(events[0][0][0], 'build')
        self.assertIn('--progress=plain', events[0][0])
        pull = next(event for event in events if event[0][0] == 'compose')
        self.assertEqual(pull[0][-6:], ['pull', '--policy', 'missing', 'elasticsearch', 'kibana', 'gateway'])
        self.assertTrue(pull[1]['stream'])
        self.assertEqual(pull[1]['env'], plan['compose_environment'])
        self.assertLess(events.index(pull), next(i for i, event in enumerate(events) if event[0] == 'activate'))

    def test_failed_pull_never_activates_or_changes_prepared_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / 'state/server'
            (state / 'secrets').mkdir(parents=True)
            secret = state / 'secrets/admin_hash'
            secret.write_bytes(b'SYNTHETIC_PRESERVE')
            engine = Mock()
            def fail_pull(args, **_kw):
                if args[0] == 'compose':
                    raise DockerCommandError(args, returncode=1)
                return ''
            engine.run.side_effect = fail_pull
            plan = {'fresh': True, 'resources': {'ok': True}, 'compose_environment': {}}
            with patch.object(sys, 'argv', ['manage.py', 'install', '--state', str(state)]), \
                    patch.object(manage.os, 'geteuid', return_value=0, create=True), \
                    patch.object(manage, 'Docker', return_value=engine), \
                    patch.object(manage, 'snapshot', return_value=plan), \
                    patch.object(manage, 'apply') as activate, redirect_stdout(io.StringIO()):
                with self.assertRaises(DockerCommandError):
                    manage.main()
            activate.assert_not_called()
            self.assertEqual(secret.read_bytes(), b'SYNTHETIC_PRESERVE')

    def test_existing_install_or_insufficient_budget_does_not_pull(self):
        for fresh, enough in ((False, True), (True, False)):
            with self.subTest(fresh=fresh, enough=enough):
                engine = Mock()
                plan = {'fresh': fresh, 'resources': {'ok': enough}, 'compose_environment': {}}
                with patch.object(sys, 'argv', ['manage.py', 'install']), \
                        patch.object(manage.os, 'geteuid', return_value=0, create=True), \
                        patch.object(manage, 'Docker', return_value=engine), \
                        patch.object(manage, 'snapshot', return_value=plan), \
                        redirect_stdout(io.StringIO()):
                    with self.assertRaises(ValueError):
                        manage.main()
                engine.run.assert_not_called()

    def test_private_command_keeps_output_captured_and_reports_only_safe_reason(self):
        output = SimpleNamespace(returncode=1, stdout='PRIVATE_RESPONSE', stderr='no space left on device PRIVATE_KEY')
        with patch('cloud_soc.deployment.host.subprocess.run', return_value=output) as call:
            with self.assertRaises(DockerCommandError) as caught:
                Docker().run(['run', 'fixture'], input='PRIVATE_PASSWORD')
        self.assertTrue(call.call_args.kwargs['capture_output'])
        self.assertIn('디스크', str(caught.exception))
        self.assertNotIn('PRIVATE', str(caught.exception))

    def test_only_public_operations_may_stream(self):
        for args, payload in ((['run', 'fixture'], None), (['compose', 'config'], None), (['build'], 'PRIVATE')):
            with self.subTest(args=args, payload=payload), patch('cloud_soc.deployment.host.subprocess.run') as command:
                with self.assertRaises(ValueError):
                    Docker().run(args, input=payload, stream=True)
                command.assert_not_called()
        with patch('cloud_soc.deployment.host.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout=None)) as command:
            self.assertEqual(Docker().run(['build', '.'], stream=True), '')
            self.assertFalse(command.call_args.kwargs['capture_output'])

    def test_timeout_does_not_reveal_stdin_or_captured_output(self):
        error = subprocess.TimeoutExpired(['run', 'PRIVATE'], 5, output='PRIVATE_OUTPUT', stderr='PRIVATE_KEY')
        with patch('cloud_soc.deployment.host.subprocess.run', side_effect=error):
            with self.assertRaises(DockerCommandError) as caught:
                Docker().run(['run', 'fixture'], input='PRIVATE_PASSWORD')
        self.assertIn('시간 초과', str(caught.exception))
        self.assertNotIn('PRIVATE', str(caught.exception))


class DependencyTests(unittest.TestCase):
    def engine(self, client='29.0.0', server='29.0.0', compose='v2.40.0', capabilities=True):
        engine = Mock()
        engine.json.return_value = {'Client': {'Version': client}, 'Server': {'Version': server}}
        engine.run.side_effect = lambda args: compose if args == ['compose', 'version', '--short'] else (
            '--policy --progress' if capabilities else '')
        return engine

    def test_compatible_existing_versions_are_reused_without_mutation(self):
        for compose in ('v2.24.0', '2.40.0', 'v5.2.1'):
            engine = self.engine(compose=compose)
            with redirect_stdout(io.StringIO()):
                check_dependencies(engine)
            self.assertTrue(all('pull' not in call.args[0] or '--help' in call.args[0] for call in engine.run.call_args_list))

    def test_old_unknown_or_incapable_versions_stop_with_update_guidance(self):
        for options in ({'client':'23.0.6'}, {'server':'20.10.0'}, {'compose':'2.23.3'},
                        {'compose':'unknown'}, {'capabilities':False}):
            with self.subTest(options=options):
                with self.assertRaises(DependencyError) as error:
                    check_dependencies(self.engine(**options))
                self.assertTrue('업데이트' in str(error.exception) or '확인' in str(error.exception))


class RemovalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        kernel = patch.object(remove, 'KERNEL_FILE', self.root / '90-cloud-soc.conf')
        kernel.start()
        self.addCleanup(kernel.stop)
        (self.root / 'deploy/server').mkdir(parents=True)
        (self.root / 'deploy/server/install-ubuntu.sh').touch()
        self.state = self.root / 'state/server'
        self.state.mkdir(parents=True)
        (self.state / 'compose.env').write_text('SYNTHETIC')
        self.args = SimpleNamespace(workspace=self.root, component='central', purge_data=False,
                                    remove_images=False, remove_docker=False)

    def row(self, *, project=remove.PROJECT, workspace=None):
        return {'Id': 'fixture-container', 'Name': '/fixture-container', 'Image': 'fixture-image',
                'Config': {'Labels': {'com.docker.compose.project': project,
                    'com.docker.compose.service': 'portal',
                    'com.docker.compose.project.config_files': str((workspace or self.root) / 'deploy/server/compose.yaml')}},
                'Mounts': [], 'NetworkSettings': {'Networks': {}}}

    def test_default_plan_preserves_data_and_does_not_mutate(self):
        with patch.object(remove.shutil, 'which', return_value='/usr/bin/docker'), \
                patch.object(remove, 'objects', side_effect=lambda kind: [self.row()] if kind == 'container' else []), \
                patch.object(remove, 'run') as mutate:
            result = remove.plan(self.args)
        self.assertEqual(result['containers'], ['fixture-container'])
        self.assertEqual(result['paths'], [])
        self.assertTrue(result['data_preserved'])
        mutate.assert_not_called()
        self.assertTrue((self.state / 'compose.env').is_file())

    def test_same_project_different_checkout_is_refused(self):
        with patch.object(remove.shutil, 'which', return_value='/usr/bin/docker'), \
                patch.object(remove, 'objects', return_value=[self.row(workspace=Path('/other'))]):
            with self.assertRaises(remove.RemovalError):
                remove.plan(self.args)

    def test_other_projects_are_preserved_and_block_docker_purge(self):
        foreign = self.row(project='other-project')
        with patch.object(remove.shutil, 'which', return_value='/usr/bin/docker'), \
                patch.object(remove, 'objects', side_effect=lambda kind: [foreign] if kind == 'container' else []):
            self.assertEqual(remove.plan(self.args)['containers'], [])
            self.args.remove_docker = True
            with self.assertRaises(remove.RemovalError):
                remove.plan(self.args)

    def test_purge_only_targets_owned_state_and_refuses_symlink(self):
        self.args.purge_data = True
        with patch.object(remove.shutil, 'which', return_value=None):
            result = remove.plan(self.args)
            self.assertEqual(result['paths'], [str(self.state)])
            (self.state / 'compose.env').unlink()
            (self.state / 'compose.env').symlink_to(self.root / 'foreign')
            with self.assertRaises(remove.RemovalError):
                remove.plan(self.args)

    def test_purge_is_repeatable_and_does_not_delete_checkout_or_neighbor(self):
        self.args.purge_data = True
        neighbor = self.root / 'state/other'
        neighbor.mkdir()
        (neighbor / 'keep').write_text('KEEP')
        with patch.object(remove.shutil, 'which', return_value=None), redirect_stdout(io.StringIO()):
            remove.apply(self.args, remove.plan(self.args))
            remove.apply(self.args, remove.plan(self.args))
        self.assertFalse(self.state.exists())
        self.assertEqual((neighbor / 'keep').read_text(), 'KEEP')
        self.assertTrue((self.root / 'deploy/server/install-ubuntu.sh').is_file())

    def test_changed_plan_aborts_before_first_mutation(self):
        expected = {'containers': []}
        with patch.object(remove, 'plan', return_value={'containers': ['changed']}), \
                patch.object(remove, 'docker') as mutate:
            with self.assertRaises(remove.RemovalError):
                remove.apply(self.args, deepcopy(expected))
            mutate.assert_not_called()


if __name__ == '__main__':
    unittest.main()
