"""Migration safety tests; POSIX file metadata is simulated on Windows."""

from contextlib import ExitStack
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("monitor_prepare", ROOT / "deploy/server/prepare-monitor.py")
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)


class MonitorPreparationTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="soc-monitor-migration-")
        self.addCleanup(folder.cleanup)
        self.state = Path(folder.name)
        (self.state / "secrets").mkdir()
        (self.state / "compose.env").write_text("EXISTING_STATE", encoding="ascii")
        (self.state / "secrets/issuer_password").write_text("EXISTING_CANARY", encoding="ascii")
        self.target = self.state / "secrets/monitor_password"
        self.overrides = {}
        original = Path.lstat

        def metadata(path):
            actual = original(path)
            kind = stat.S_IFDIR if stat.S_ISDIR(actual.st_mode) else stat.S_IFREG
            expected = {"st_mode": kind | (0o700 if kind == stat.S_IFDIR else 0o400),
                        "st_uid": 1000 if path == self.target else 0, "st_gid": 0, "st_size": actual.st_size}
            return SimpleNamespace(**{**expected, **self.overrides.get(path, {})})

        stack = self.enterContext(ExitStack())
        stack.enter_context(patch.object(Path, "lstat", metadata))
        stack.enter_context(patch.object(prepare.os, "O_NOFOLLOW", getattr(os, "O_NOFOLLOW", 0), create=True))
        self.chown = stack.enter_context(patch.object(prepare.os, "fchown", create=True))
        self.chmod = stack.enter_context(patch.object(prepare.os, "fchmod", create=True))

    def test_create_and_reuse_never_change_existing_state(self):
        self.assertTrue(prepare.prepare_monitor(self.state))
        value = self.target.read_bytes()
        self.assertGreaterEqual(len(value), 32)
        self.chown.assert_called_once()
        self.assertEqual(self.chown.call_args.args[1:], (1000, 0))
        self.chmod.assert_called_once()
        self.assertEqual(self.chmod.call_args.args[1:], (0o400,))
        self.assertFalse(prepare.prepare_monitor(self.state))
        self.assertEqual(self.target.read_bytes(), value)
        self.assertEqual((self.state / "compose.env").read_text(), "EXISTING_STATE")
        self.assertEqual((self.state / "secrets/issuer_password").read_text(), "EXISTING_CANARY")

    def test_unsafe_parent_or_symlink_never_creates_secret(self):
        for path, changes in [(self.state, {"st_mode": stat.S_IFDIR | 0o755}),
                              (self.state, {"st_uid": 1000}),
                              (self.state / "secrets", {"st_mode": stat.S_IFLNK | 0o700}),
                              (self.state / "compose.env", {"st_mode": stat.S_IFLNK | 0o400})]:
            self.overrides = {path: changes}
            with self.assertRaises(ValueError):
                prepare.prepare_monitor(self.state)
            self.assertFalse(self.target.exists())

    def test_partial_or_unsafe_existing_secret_is_not_replaced(self):
        self.target.write_text("partial", encoding="ascii")
        with self.assertRaises(ValueError):
            prepare.prepare_monitor(self.state)
        self.assertEqual(self.target.read_text(), "partial")
        self.target.write_text("x" * 48, encoding="ascii")
        for changes in ({"st_mode": stat.S_IFLNK | 0o400}, {"st_mode": stat.S_IFREG | 0o644}, {"st_uid": 0}):
            self.overrides = {self.target: changes}
            with self.assertRaises(ValueError):
                prepare.prepare_monitor(self.state)
            self.assertEqual(self.target.read_text(), "x" * 48)

    def test_failure_preserves_protected_partial_file(self):
        self.chown.side_effect = PermissionError("SECRET_CANARY")
        with self.assertRaises(RuntimeError) as error:
            prepare.prepare_monitor(self.state)
        self.assertNotIn("CANARY", str(error.exception))
        self.assertTrue(self.target.exists())
        self.chmod.assert_not_called()


if __name__ == "__main__":
    unittest.main()
