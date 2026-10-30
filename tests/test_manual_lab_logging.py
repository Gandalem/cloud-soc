"""The opt-in lab controller must keep working with non-UTF-8 process output."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


class LabLoggingTests(unittest.TestCase):
    def test_non_utf8_output_and_redaction_are_saved_as_utf8(self):
        path = Path(__file__).resolve().parent / 'manual' / 'device_os_live.py'
        spec = importlib.util.spec_from_file_location('device_os_live_logging_test', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            lab = module.Lab.__new__(module.Lab)
            lab.log_dir = Path(directory)
            lab.secret_values = ['TEST_SECRET']
            result = subprocess.CompletedProcess(['synthetic'], 0, b'\xff TEST_SECRET', b'')
            with patch.object(module.subprocess, 'run', return_value=result):
                lab.command(['synthetic'], name='trial')
            self.assertEqual((lab.log_dir / 'trial.log').read_text(encoding='utf-8'), '\ufffd [REDACTED]')
            result.returncode = 1
            with patch.object(module.subprocess, 'run', return_value=result):
                with self.assertRaises(RuntimeError):
                    lab.command(['synthetic'])
            self.assertEqual((lab.log_dir / 'last-failure.log').read_text(encoding='utf-8'), '\ufffd [REDACTED]')


if __name__ == '__main__':
    unittest.main()
