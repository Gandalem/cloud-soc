"""Network retry boundaries and real Linux streaming process lifecycle."""
from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from cloud_soc.deployment.downloads import ensure_image, public_operation
from cloud_soc.deployment.host import Docker, DockerCommandError


class DownloadTests(unittest.TestCase):
    def test_temporary_failure_then_success_reuses_identical_command(self):
        engine = Mock()
        args = ['pull', 'caddy:2.11.4-alpine']
        engine.run.side_effect = [DockerCommandError(args, returncode=1, stderr='connection reset by peer'), '']
        with patch('cloud_soc.deployment.downloads.time.sleep') as sleep, redirect_stdout(io.StringIO()):
            public_operation(engine, args, timeout=30)
        self.assertEqual(engine.run.call_count, 2)
        self.assertEqual(engine.run.call_args_list[0], engine.run.call_args_list[1])
        sleep.assert_called_once_with(5)

    def test_stalled_transfer_has_three_attempts_and_bounded_backoff(self):
        engine = Mock()
        args = ['pull', 'fixture:1']
        engine.run.side_effect = DockerCommandError(args, timed_out=True)
        with patch('cloud_soc.deployment.downloads.time.sleep') as sleep, redirect_stdout(io.StringIO()):
            with self.assertRaises(DockerCommandError):
                public_operation(engine, args, timeout=30)
        self.assertEqual(engine.run.call_count, 3)
        self.assertEqual([c.args[0] for c in sleep.call_args_list], [5, 10])

    def test_terminal_errors_never_retry_or_echo_upstream_secret(self):
        for reason in ('manifest unknown', 'unauthorized', 'x509: certificate signed by unknown authority',
                       'no space left on device', 'permission denied', 'invalid reference format'):
            with self.subTest(reason=reason):
                error = DockerCommandError(['pull', 'fixture'], returncode=1, stderr=reason + ' SECRET i/o timeout')
                engine = Mock()
                engine.run.side_effect = error
                with patch('cloud_soc.deployment.downloads.time.sleep') as sleep:
                    with self.assertRaises(DockerCommandError):
                        public_operation(engine, ['pull', 'fixture'], timeout=30)
                self.assertEqual(engine.run.call_count, 1)
                self.assertNotIn('SECRET', str(error))
                sleep.assert_not_called()

    def test_exact_cached_version_does_not_contact_registry(self):
        engine = Mock()
        engine.run.return_value = 'sha256:local-image'
        with redirect_stdout(io.StringIO()):
            ensure_image(engine, 'fixture:1', '시험')
        engine.run.assert_called_once_with(['image', 'ls', '--filter', 'reference=fixture:1', '--format', '{{.ID}}'])

    def test_user_cancel_is_not_retried(self):
        engine = Mock()
        engine.run.side_effect = KeyboardInterrupt
        with patch('cloud_soc.deployment.downloads.time.sleep') as sleep:
            with self.assertRaises(KeyboardInterrupt):
                public_operation(engine, ['pull', 'fixture'], timeout=30)
        self.assertEqual(engine.run.call_count, 1)
        sleep.assert_not_called()


@unittest.skipUnless(os.name == 'posix', '실제 프로세스 그룹/파이프 검사는 Linux에서 실행')
class PublicStreamTests(unittest.TestCase):
    def execute(self, code, *, timeout=3, idle=1):
        engine = Docker()
        # Substitute a local fixture for the public Docker command; no daemon,
        # registry, credentials, services or sockets are used here.
        engine.prefix = [sys.executable, '-u', '-c', code]
        return engine.run(['pull', 'fixture'], stream=True, timeout=timeout, idle_timeout=idle)

    def test_real_output_streams_and_nonzero_error_is_classified(self):
        with redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(DockerCommandError) as caught:
                self.execute("import sys; print('connection reset by peer'); sys.exit(1)")
        self.assertIn('connection reset', output.getvalue())
        self.assertTrue(caught.exception.retryable)

    def test_silent_process_is_killed_and_reaped(self):
        with tempfile.TemporaryDirectory() as tmp:
            pid_file = Path(tmp) / 'pid'
            code = f'import os,time; open({str(pid_file)!r},"w").write(str(os.getpid())); time.sleep(60)'
            began = time.monotonic()
            with self.assertRaises(DockerCommandError) as caught:
                self.execute(code, idle=.25)
            self.assertLess(time.monotonic() - began, 3)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pid_file.read_text()), 0)
            self.assertTrue(caught.exception.retryable)

    def test_total_deadline_applies_even_to_continuous_output(self):
        began = time.monotonic()
        with redirect_stdout(io.StringIO()), self.assertRaises(DockerCommandError):
            self.execute('import time\nwhile True: print("working"); time.sleep(.03)', timeout=.3, idle=1)
        self.assertLess(time.monotonic() - began, 3)

    def test_repeated_status_is_idle_but_advancing_byte_counts_are_progress(self):
        with redirect_stdout(io.StringIO()), self.assertRaises(DockerCommandError):
            self.execute('import time\nwhile True: print("waiting"); time.sleep(.03)', timeout=2, idle=.2)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(self.execute('import time,sys\nassert sys.stdout.isatty()\n'
                'for n in range(8): print(f"Downloading {n} bytes", flush=True); time.sleep(.06)',
                timeout=2, idle=.2), '')

    def test_failed_build_does_not_retry_syntax_error(self):
        with redirect_stdout(io.StringIO()):
            with self.assertRaises(DockerCommandError) as caught:
                self.execute('raise SyntaxError("fixture")')
        self.assertFalse(caught.exception.retryable)

