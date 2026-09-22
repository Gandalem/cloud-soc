"""Stdlib-only Linux recovery checks in a disposable, offline Python container."""
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cloud_soc.portal import backup as recovery


@unittest.skipUnless(os.name == "posix", "POSIX permissions and symlinks")
class PosixBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="soc-posix-backup-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "portal"
        self.source.mkdir(mode=0o700)
        with closing(sqlite3.connect(self.source / "packages.sqlite3")) as db:
            for table, columns in recovery.SCHEMAS["packages.sqlite3"].items():
                db.execute(f'CREATE TABLE "{table}" (' + ",".join(f'"{column}" TEXT' for column in columns) + ")")
            db.execute("INSERT INTO issued_keys VALUES ('synthetic-key', 'synthetic-package', '2026-09-22')")
            db.commit()

    def test_actual_linux_permissions_wal_and_restore(self):
        with closing(sqlite3.connect(self.source / "packages.sqlite3")) as writer:
            writer.execute("PRAGMA journal_mode=WAL")
            writer.execute("PRAGMA wal_autocheckpoint=0")
            writer.execute("INSERT INTO issued_keys VALUES ('committed', 'p', 't')")
            writer.commit()
            writer.execute("INSERT INTO issued_keys VALUES ('not-committed', 'p', 't')")
            backup = self.root / "backup"
            report = recovery.backup(self.source, backup)
            self.assertEqual(report["files"][0]["counts"]["issued_keys"], 2)
            self.assertEqual(backup.stat().st_mode & 0o777, 0o700)
            for file in backup.iterdir(): self.assertEqual(file.stat().st_mode & 0o777, 0o600)
            restored = self.root / "restored"
            recovery.restore(backup, restored)
            with closing(sqlite3.connect(restored / "packages.sqlite3")) as db:
                self.assertEqual(db.execute("SELECT count(*) FROM issued_keys").fetchone()[0], 2)
            writer.rollback()

    def test_real_symlink_parent_and_sidecar_are_rejected(self):
        link = self.root / "link"
        link.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(recovery.BackupError): recovery.backup(link, self.root / "backup")
        with self.assertRaises(recovery.BackupError): recovery.backup(self.source, link / "backup")
        sidecar = self.source / "packages.sqlite3-wal"
        sidecar.symlink_to(self.source / "packages.sqlite3")
        with self.assertRaises(recovery.BackupError): recovery.backup(self.source, self.root / "backup")


if __name__ == "__main__":
    unittest.main(verbosity=2)
