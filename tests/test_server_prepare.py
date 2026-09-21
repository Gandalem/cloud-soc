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

    def test_empty_password_retries_before_confirmation_and_creates_no_state(self):
        code, output, prompt, action = self.run_main(["", PASSWORD, PASSWORD])
        self.assertEqual(code, 0)
        self.assertIn("password must not be empty", output)
        self.assertNotIn(PASSWORD, output)
        self.assertEqual(prompt.call_args_list[1].args[0], "Portal admin password: ")
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
        for entries in ([""] * 3, [PASSWORD, "different-canary"] * 3):
            with self.subTest(entries=len(entries)):
                code, output, _prompt, action = self.run_main(entries)
                self.assertEqual(code, 1)
                self.assertIn("failed after 3 attempts", output)
                self.assertNotIn("different-canary", output)
                self.assertNotIn(PASSWORD, output)
                action.assert_not_called()

    def test_boundary_password_length(self):
        with self.assertRaisesRegex(prepare.PreparationError, "must not be empty"):
            prepare.validate_password("")
        for length in (1, 4, 8, 11, 12, 15, 16, 64):
            prepare.validate_password("x" * length)

    def test_short_password_reaches_preparation_without_retries(self):
        password = "x"
        code, output, prompt, action = self.run_main([password, password])
        self.assertEqual(code, 0)
        self.assertEqual(prompt.call_count, 2)
        self.assertNotIn(password, output)
        action.assert_called_once_with("soc.example.test", "10.0.0.5", self.state, password)

    def test_direct_empty_password_does_not_hash_or_write(self):
        with patch.object(prepare, "password_hash") as hash_password:
            with self.assertRaisesRegex(prepare.PreparationError, "must not be empty"):
                prepare.prepare("soc.example.test", "10.0.0.5", self.state, "")
            hash_password.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_short_password_hash_still_verifies_without_plaintext_storage(self):
        from werkzeug.security import check_password_hash

        digest = prepare.password_hash("x")
        self.assertTrue(digest.startswith("pbkdf2:sha256:600000$"))
        self.assertTrue(check_password_hash(digest, "x"))
        self.assertFalse(check_password_hash(digest, "y"))

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

    def test_generated_elastic_secret_has_allowed_mode_and_shared_container_owner(self):
        def fake_openssl(command, **_kwargs):
            for option in ("-keyout", "-out"):
                if option in command:
                    Path(command[command.index(option) + 1]).write_text("synthetic certificate", encoding="ascii")

        output = io.StringIO()
        with patch.object(prepare.shutil, "which", return_value="openssl"), \
                patch.object(prepare.subprocess, "run", side_effect=fake_openssl), \
                patch.object(prepare, "password_hash", return_value="SYNTHETIC_HASH"), \
                patch.object(prepare.secrets, "token_urlsafe", return_value="SYNTHETIC_CREDENTIAL"), \
                patch.object(prepare.os, "umask"), \
                patch.object(prepare.os, "chown", create=True) as chown, \
                patch.object(Path, "chmod", autospec=True) as chmod, redirect_stdout(output):
            prepare.prepare("soc.example.test", "10.0.0.5", self.state, PASSWORD)

        secret = self.state / "secrets/elastic_password"
        chown.assert_any_call(secret, 1000, 0)
        modes = [call.args[1] for call in chmod.call_args_list if call.args[0] == secret]
        self.assertEqual(modes, [0o400])
        self.assertIn(modes[0], (0o400, 0o440, 0o600, 0o640))
        self.assertEqual(secret.read_text(encoding="utf-8"), "SYNTHETIC_CREDENTIAL")
        owner_uid, owner_gid = next(call.args[1:] for call in chown.call_args_list if call.args[0] == secret)
        for uid, gid in ((1000, 0), (1000, 1000)):
            read_bit = 0o400 if uid == owner_uid else 0o040 if gid == owner_gid else 0o004
            self.assertTrue(modes[0] & read_bit)
        self.assertEqual(modes[0] & 0o077, 0)
        chown.assert_any_call(self.state / "secrets/monitor_password", 1000, 0)
        chmod.assert_any_call(self.state / "secrets/monitor_password", 0o400)
        for name in ("kibana_password", "issuer_password", "analyst_password", "admin_hash"):
            chmod.assert_any_call(self.state / "secrets" / name, 0o644)
        chmod.assert_any_call(self.state / "tls", 0o750)
        chown.assert_any_call(self.state / "portal", 1000, 1000)
        self.assertNotIn("SYNTHETIC_CREDENTIAL", output.getvalue())
        self.assertNotIn("SYNTHETIC_HASH", output.getvalue())
        self.assertNotIn(PASSWORD, output.getvalue())

    def test_elastic_secret_ownership_failure_preserves_state_without_weakening_mode(self):
        with patch.object(prepare.shutil, "which", return_value="openssl"), \
                patch.object(prepare, "password_hash", return_value="SYNTHETIC_HASH"), \
                patch.object(prepare.os, "umask"), \
                patch.object(prepare.os, "chown", create=True, side_effect=PermissionError("denied")), \
                patch.object(Path, "chmod", autospec=True) as chmod, \
                patch.object(prepare.subprocess, "run") as openssl:
            with self.assertRaises(PermissionError):
                prepare.prepare("soc.example.test", "10.0.0.5", self.state, PASSWORD)
        self.assertTrue((self.state / "secrets/elastic_password").is_file())
        chmod.assert_not_called()
        openssl.assert_not_called()
        self.assertFalse((self.state / "compose.env").exists())

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
