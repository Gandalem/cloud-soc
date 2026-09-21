"""Password and failure handling without real certificates, credentials or services."""

import argparse
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import warnings


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("server_prepare_tests", ROOT / "deploy/server/prepare.py")
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)
PASSWORD = "synthetic-password-for-tests"


class ServerPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cloud-soc-preparation-test-")
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / "server"

    def run_main(self, entries, error=None):
        args = argparse.Namespace(host="soc.example.test", bind_ip="10.0.0.5", state=self.state)
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(prepare.argparse.ArgumentParser, "parse_args", return_value=args), \
                patch.object(prepare, "os", SimpleNamespace(name="posix", geteuid=lambda: 0)), \
                patch.object(prepare.getpass, "getpass", side_effect=entries) as prompt, \
                patch.object(prepare, "prepare", side_effect=error) as action, \
                redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                prepare.main()
                code = 0
            except SystemExit as result:
                code = result.code
        return code, stdout.getvalue() + stderr.getvalue(), prompt, action

    def test_short_password_retries_before_confirmation_and_creates_no_state(self):
        code, output, prompt, action = self.run_main(["short-canary", PASSWORD, PASSWORD])
        self.assertEqual(code, 0)
        self.assertIn("at least 16 characters", output)
        self.assertNotIn("short-canary", output)
        self.assertNotIn(PASSWORD, output)
        self.assertEqual(prompt.call_args_list[1].args[0], "Portal admin password (16+ characters): ")
        action.assert_called_once_with("soc.example.test", "10.0.0.5", self.state, PASSWORD)
        self.assertFalse(self.state.exists())

    def test_confirmation_mismatch_retries_both_inputs(self):
        code, output, prompt, action = self.run_main([PASSWORD, "different-canary", PASSWORD, PASSWORD])
        self.assertEqual(code, 0)
        self.assertEqual(prompt.call_count, 4)
        self.assertIn("Passwords do not match", output)
        self.assertNotIn("different-canary", output)
        self.assertNotIn(PASSWORD, output)
        action.assert_called_once()

    def test_exhausted_retries_stop_before_preparation(self):
        for entries in (["short-canary"] * 3, [PASSWORD, "different-canary"] * 3):
            with self.subTest(entries=len(entries)):
                code, output, _prompt, action = self.run_main(entries)
                self.assertEqual(code, 1)
                self.assertIn("failed after 3 attempts", output)
                self.assertNotIn("short-canary", output)
                self.assertNotIn("different-canary", output)
                self.assertNotIn(PASSWORD, output)
                action.assert_not_called()

    def test_boundary_password_length(self):
        with self.assertRaisesRegex(prepare.PreparationError, "at least 16"):
            prepare.validate_password("x" * 15)
        prepare.validate_password("x" * 16)

    def test_direct_short_password_does_not_hash_or_write(self):
        with patch.object(prepare, "password_hash") as hash_password:
            with self.assertRaisesRegex(prepare.PreparationError, "at least 16"):
                prepare.prepare("soc.example.test", "10.0.0.5", self.state, "short-canary")
            hash_password.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_existing_state_is_preserved(self):
        self.state.mkdir()
        marker = self.state / "existing.txt"
        marker.write_text("existing state", encoding="ascii")
        with self.assertRaisesRegex(prepare.PreparationError, "never overwritten"):
            prepare.prepare("soc.example.test", "10.0.0.5", self.state, PASSWORD)
        self.assertEqual(marker.read_text(encoding="ascii"), "existing state")
        self.assertEqual(list(self.state.iterdir()), [marker])

    def test_state_symlink_is_rejected_before_resolving_or_writing(self):
        with patch.object(type(self.state), "is_symlink", return_value=True), \
                patch.object(prepare, "password_hash") as hash_password:
            with self.assertRaisesRegex(prepare.PreparationError, "must not be a symlink"):
                prepare.prepare("soc.example.test", "10.0.0.5", self.state, PASSWORD)
            hash_password.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_missing_openssl_is_actionable_before_writing(self):
        with patch.object(prepare.shutil, "which", return_value=None):
            with self.assertRaisesRegex(prepare.PreparationError, "Install OpenSSL"):
                prepare.prepare("soc.example.test", "10.0.0.5", self.state, PASSWORD)
        self.assertFalse(self.state.exists())

    def test_invalid_bind_ip_is_static_and_does_not_create_state(self):
        with self.assertRaises(prepare.PreparationError) as result:
            prepare.prepare("soc.example.test", "invalid-bind-canary", self.state, PASSWORD)
        self.assertIn("valid server-local IPv4", str(result.exception))
        self.assertNotIn("invalid-bind-canary", str(result.exception))
        self.assertFalse(self.state.exists())

    def test_hash_failure_does_not_leave_a_partial_state_directory(self):
        with patch.object(prepare.shutil, "which", return_value="openssl"), \
                patch.object(prepare, "password_hash", side_effect=ValueError("HASH_FAILURE_CANARY")):
            with self.assertRaises(ValueError):
                prepare.prepare("soc.example.test", "10.0.0.5", self.state, PASSWORD)
        self.assertFalse(self.state.exists())

    def test_known_validation_error_is_actionable(self):
        error = prepare.PreparationError("Existing server state is never overwritten; review it manually")
        code, output, _prompt, _action = self.run_main([PASSWORD, PASSWORD], error)
        self.assertEqual(code, 1)
        self.assertIn("Existing server state is never overwritten", output)
        self.assertNotIn(PASSWORD, output)

    def test_unknown_errors_remain_redacted(self):
        errors = [ValueError("SECRET_CANARY"), OSError("SECRET_CANARY"),
                  subprocess.CalledProcessError(1, ["openssl", "SECRET_CANARY"], stderr="SECRET_CANARY")]
        for error in errors:
            with self.subTest(error=type(error).__name__):
                code, output, _prompt, _action = self.run_main([PASSWORD, PASSWORD], error)
                self.assertEqual(code, 1)
                self.assertIn(f"Preparation failed ({type(error).__name__})", output)
                self.assertNotIn("SECRET_CANARY", output)
                self.assertNotIn(PASSWORD, output)

    def test_canceled_input_never_prepares_state(self):
        for error, expected in [(EOFError(), 1), (KeyboardInterrupt(), 130), (prepare.getpass.GetPassWarning(), 1)]:
            with self.subTest(error=type(error).__name__):
                code, _output, _prompt, action = self.run_main([error])
                self.assertEqual(code, expected)
                action.assert_not_called()

    def test_getpass_insecure_fallback_warning_becomes_an_error(self):
        def insecure_input(_prompt):
            warnings.warn("Cannot control terminal echo", prepare.getpass.GetPassWarning)
            self.fail("Password fallback must never be read")

        with patch.object(prepare.getpass, "getpass", side_effect=insecure_input):
            with self.assertRaises(prepare.getpass.GetPassWarning):
                prepare.read_admin_password()


if __name__ == "__main__":
    unittest.main()
