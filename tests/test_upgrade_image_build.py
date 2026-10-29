"""Upgrade candidate builds share installer retries without deployment side effects."""
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from cloud_soc.deployment.host import DockerCommandError

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('upgrade_build_manage', ROOT / 'deploy/server/manage.py')
manage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manage)


class UpgradeBuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.workspace = Path(self.tmp.name)
        source = self.workspace / 'deploy/server'
        source.mkdir(parents=True)
        (source / 'Dockerfile').write_text('FROM python:3.12-slim-bookworm\nRUN true\n')
        self.protected = self.workspace / 'state/server/runtime/current.json'
        self.protected.parent.mkdir(parents=True)
        self.protected.write_bytes(b'SYNTHETIC_EXISTING_RECEIPT')
        self.engine = Mock()
        self.engine.json.return_value = [{'Id': 'sha256:candidate'}]
        self.calls = []
        guard = patch('cloud_soc.deployment.downloads.check_disk_budget')
        guard.start()
        self.addCleanup(guard.stop)
        retained = patch('cloud_soc.deployment.downloads.retain_images')
        retained.start()
        self.addCleanup(retained.stop)

    def invoke(self, effect, *, extra=(), image=True):
        def command(args, **kw):
            self.calls.append((args, kw))
            return effect(args, **kw)
        self.engine.run.side_effect = command
        argv = ['manage.py', 'build', '--workspace', str(self.workspace)]
        if image:
            argv += ['--image', 'cloud-soc-runtime:reviewed-test']
        argv += list(extra)
        with patch.object(sys, 'argv', argv), \
                patch.object(manage, 'os', SimpleNamespace(name='posix', geteuid=lambda: 0)), \
                patch.object(manage, 'Docker', return_value=self.engine), \
                patch.object(manage, 'snapshot') as plan, patch.object(manage, 'apply') as activate, \
                patch.object(manage, 'recover') as recover, \
                patch('cloud_soc.deployment.downloads.time.sleep') as sleep, \
                redirect_stdout(io.StringIO()) as output:
            try:
                result = manage.main()
                return result, output.getvalue(), sleep.call_args_list
            finally:
                plan.assert_not_called()
                activate.assert_not_called()
                recover.assert_not_called()
                self.assertEqual(self.protected.read_bytes(), b'SYNTHETIC_EXISTING_RECEIPT')
                self.assertTrue(all(c[0][0] in ('image', 'pull', 'build') for c in self.calls))

    def test_upgrade_build_retries_connection_error_and_reports_candidate_only(self):
        attempts = 0
        def effect(args, **kw):
            nonlocal attempts
            if args[0] == 'build':
                attempts += 1
                if attempts == 1:
                    raise DockerCommandError(args, returncode=1, stderr='connection reset by peer')
            return 'cached' if args[0] == 'image' else ''
        result, output, sleeps = self.invoke(effect)
        self.assertEqual(result, 0)
        self.assertEqual(attempts, 2)
        self.assertEqual([c.args[0] for c in sleeps], [5])
        receipt = json.loads(output.splitlines()[-1])
        self.assertEqual(receipt['image_id'], 'sha256:candidate')
        self.assertIs(receipt['activation_performed'], False)
        builds = [c for c in self.calls if c[0][0] == 'build']
        self.assertEqual(builds[0], builds[1])
        self.assertEqual(builds[0][1], {'timeout': 900, 'idle_timeout': 180, 'stream': True})

    def test_failed_base_download_is_retried_before_the_build(self):
        pulls = 0
        def effect(args, **kw):
            nonlocal pulls
            if args[0] == 'pull':
                pulls += 1
                if pulls == 1:
                    raise DockerCommandError(args, timed_out=True)
            return ''
        self.assertEqual(self.invoke(effect)[0], 0)
        self.assertEqual([c[0][0] for c in self.calls], ['image', 'pull', 'pull', 'build'])

    def test_build_timeout_exhausts_retry_without_activation_or_success_receipt(self):
        def effect(args, **kw):
            if args[0] == 'build':
                raise DockerCommandError(args, timed_out=True)
            return 'cached'
        with self.assertRaises(DockerCommandError):
            self.invoke(effect)
        self.assertEqual(sum(c[0][0] == 'build' for c in self.calls), 3)
        self.engine.json.assert_not_called()

    def test_terminal_failure_does_not_retry(self):
        for reason in ('unauthorized', 'no space left on device', 'x509: unknown CA'):
            with self.subTest(reason=reason):
                self.calls.clear()
                def effect(args, **kw):
                    if args[0] == 'build':
                        raise DockerCommandError(args, returncode=1, stderr=reason)
                    return 'cached'
                with self.assertRaises(DockerCommandError):
                    self.invoke(effect)
                self.assertEqual(sum(c[0][0] == 'build' for c in self.calls), 1)

    def test_candidate_tag_is_required_before_any_download(self):
        with self.assertRaises(ValueError):
            self.invoke(lambda *_a, **_kw: '', image=False)
        self.engine.run.assert_not_called()

    def test_build_refuses_activation_and_verification_options(self):
        for option in (['--build'], ['--plan', '/nonexistent-plan'], ['--startup-only'], ['--wait-seconds', '1']):
            with self.subTest(option=option), self.assertRaises(ValueError):
                self.invoke(lambda *_a, **_kw: '', extra=option)
        self.engine.run.assert_not_called()

    def test_invalid_dockerfile_fails_before_download(self):
        (self.workspace / 'deploy/server/Dockerfile').write_text('FROM other:fixture\n')
        with self.assertRaises(ValueError):
            self.invoke(lambda *_a, **_kw: '')
        self.engine.run.assert_not_called()

