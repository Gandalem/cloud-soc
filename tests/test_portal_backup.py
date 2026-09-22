"""Synthetic local recovery drills; never access the deployed portal state."""
from contextlib import closing, redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from cloud_soc.portal import backup as recovery
from cloud_soc.portal.cases import CaseStore
from cloud_soc.portal.packages import PackageStore
from cloud_soc.portal.app import create_app
import test_portal


class PortalBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="soc-backup-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "portal"
        self.copy = self.root / "backup"
        self.restored = self.root / "restored"
        self.packages = PackageStore(self.source, ROOT / "deploy/agents", test_portal.CA, "https://soc.example.test:9200")
        self.package = self.packages.create(test_portal.SPEC)
        self.packages.record_keys(self.package["id"], [{"id": "synthetic-key-id"}])
        self.cases = CaseStore(self.source / "cases.sqlite", "admin")
        self.fetch = Mock(return_value={"id": "fixture", "organization": "school", "rule": "SYNTHETIC", "title": "Synthetic"})
        self.body = {"title": "Test case", "priority": "high", "alert_id": "fixture"}
        self.token = str(uuid.uuid4())
        self.case = self.cases.create(self.body, "admin", self.token, self.fetch)
        self.case = self.cases.update(self.case["id"], {"version": 1, "status": "investigating", "owner": "admin", "note": "Synthetic review"},
                                      "admin", str(uuid.uuid4()), self.fetch)

    def test_backup_restore_real_app_history_bundles_and_idempotency(self):
        original = {p.name: p.read_bytes() for p in self.source.iterdir()}
        report = recovery.backup(self.source, self.copy)
        self.assertEqual(report["missing"], [])
        self.assertEqual(recovery.verify(self.copy), report)
        self.assertEqual(recovery.restore(self.copy, self.restored), report)
        self.assertEqual(original, {p.name: p.read_bytes() for p in self.source.iterdir()})
        restored_cases = CaseStore(self.restored / "cases.sqlite", "admin")
        self.fetch.side_effect = RuntimeError("Should not query ES")
        self.assertEqual(restored_cases.create(self.body, "admin", self.token, self.fetch)["id"], self.case["id"])
        restored_packages = PackageStore(self.restored, ROOT / "deploy/agents", test_portal.CA, "https://soc.example.test:9200")
        self.assertEqual(restored_packages.get(self.package["id"], archive=True), self.packages.get(self.package["id"], archive=True))
        settings = {"STATE_DIR": self.restored, "AGENT_SOURCE": ROOT / "deploy/agents", "CA_BYTES": test_portal.CA,
                    "PUBLIC_URL": "http://localhost", "ENDPOINT": "https://soc.example.test:9200", "ADMIN_USER": "admin", "ADMIN_HASH": test_portal.HASH}
        app = create_app(settings, issuer=Mock(), monitor=Mock())
        with app.test_client() as client:
            detail = client.get("/api/cases/" + self.case["id"], headers={"Authorization": test_portal.AUTH})
            self.assertEqual(detail.status_code, 200)
            self.assertEqual(detail.json["history"][0]["note"], "Synthetic review")
            self.assertEqual(detail.json["case"]["owner"], "admin")
            self.assertEqual(client.get("/api/cases?status=investigating", headers={"Authorization": test_portal.AUTH}).json["counts"]["total"], 1)
        with restored_packages.connect() as db:
            self.assertEqual(db.execute("SELECT id FROM issued_keys").fetchone()[0], "synthetic-key-id")
        # Only the isolated restored copy is changed; source and backup stay intact.
        restored_cases.update(self.case["id"], {"version": 2, "note": "Recovery drill"}, "admin", str(uuid.uuid4()), self.fetch)
        self.assertEqual(self.cases.detail(self.case["id"], "admin")["case"]["version"], 2)
        self.assertEqual(recovery.verify(self.copy), report)

    def test_wal_committed_pages_included_uncommitted_changes_excluded(self):
        writer = sqlite3.connect(self.source / "cases.sqlite")
        self.addCleanup(writer.close)
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("UPDATE cases SET title='Committed WAL title'")
        writer.commit()
        self.assertGreater((self.source / "cases.sqlite-wal").stat().st_size, 0)
        writer.execute("UPDATE cases SET title='Uncommitted title'")
        recovery.backup(self.source, self.copy)
        with closing(sqlite3.connect(self.copy / "cases.sqlite")) as db:
            self.assertEqual(db.execute("SELECT title FROM cases").fetchone()[0], "Committed WAL title")
            self.assertEqual(db.execute("PRAGMA journal_mode").fetchone()[0], "delete")
        writer.rollback()
        self.assertFalse((self.copy / "cases.sqlite-wal").exists())
        recovery.verify(self.copy)

    def test_pre_p6_backup_explicitly_reports_missing_case_database(self):
        (self.source / "cases.sqlite").unlink()
        report = recovery.backup(self.source, self.copy)
        self.assertEqual(report["missing"], ["cases.sqlite"])
        recovery.restore(self.copy, self.restored)
        self.assertFalse((self.restored / "cases.sqlite").exists())

    def test_missing_required_package_database_does_not_create_output(self):
        (self.source / "packages.sqlite3").unlink()
        with self.assertRaises(recovery.BackupError): recovery.backup(self.source, self.copy)
        self.assertFalse(self.copy.exists())

    def test_existing_and_nested_destinations_are_never_modified(self):
        self.copy.mkdir()
        marker = self.copy / "keep"
        marker.write_bytes(b"unchanged")
        for target in (self.copy, self.source, self.source / "nested"):
            with self.assertRaises(recovery.BackupError): recovery.backup(self.source, target)
        self.assertEqual(marker.read_bytes(), b"unchanged")
        fresh = self.root / "good-backup"
        recovery.backup(self.source, fresh)
        with self.assertRaises(recovery.BackupError): recovery.restore(fresh, self.source)
        with self.assertRaises(recovery.BackupError): recovery.restore(fresh, fresh / "nested")

    def test_tampering_and_unexpected_sidecars_are_rejected(self):
        recovery.backup(self.source, self.copy)
        path = self.copy / "cases.sqlite"
        original = path.read_bytes()
        path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        with self.assertRaises(recovery.BackupError): recovery.restore(self.copy, self.restored)
        self.assertFalse(self.restored.exists())
        path.write_bytes(original)
        (self.copy / "cases.sqlite-wal").write_bytes(b"unexpected")
        with self.assertRaises(recovery.BackupError): recovery.verify(self.copy)

    def test_manifest_rejects_paths_duplicates_incomplete_and_counts(self):
        recovery.backup(self.source, self.copy)
        path = self.copy / recovery.MANIFEST
        original = path.read_text()
        for mutate in (
            lambda r: r["files"][0].update(name="../packages.sqlite3"),
            lambda r: r["files"].append(r["files"][0]),
            lambda r: r.update(missing=["cases.sqlite"]),
            lambda r: r["files"][0]["counts"].update(packages=99),
            lambda r: r.update(format=True),
        ):
            report = json.loads(original); mutate(report); path.write_text(json.dumps(report))
            with self.assertRaises(recovery.BackupError): recovery.verify(self.copy)
        path.write_text("{")
        with self.assertRaises(recovery.BackupError): recovery.verify(self.copy)

    def test_integrity_checked_even_when_manifest_hash_matches(self):
        recovery.backup(self.source, self.copy)
        path = self.copy / "cases.sqlite"
        path.write_bytes(b"NOT A SQLITE DATABASE" + bytes(4096))
        manifest = self.copy / recovery.MANIFEST
        report = json.loads(manifest.read_text())
        entry = next(e for e in report["files"] if e["name"] == path.name)
        entry.update(bytes=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        manifest.write_text(json.dumps(report))
        with self.assertRaises(sqlite3.Error): recovery.verify(self.copy)

    def test_foreign_key_corruption_and_unknown_schema_prevent_completion(self):
        with self.cases.connect() as db:
            db.execute("CREATE VIEW unexpected AS SELECT title FROM cases")
        with self.assertRaises(recovery.BackupError): recovery.backup(self.source, self.copy)
        self.assertFalse((self.copy / recovery.MANIFEST).exists())
        with self.cases.connect() as db:
            db.execute("DROP VIEW unexpected")
            db.execute("PRAGMA foreign_keys=OFF")
            db.execute("UPDATE case_alerts SET case_id='missing'")
        with self.assertRaises(recovery.BackupError): recovery.backup(self.source, self.root / "second")
        self.assertFalse((self.root / "second" / recovery.MANIFEST).exists())

    def test_low_disk_size_limit_and_time_budget(self):
        with patch.object(recovery.shutil, "disk_usage", return_value=Mock(free=0)):
            with self.assertRaises(recovery.BackupError): recovery.backup(self.source, self.copy)
        self.assertFalse(self.copy.exists())
        with self.assertRaises(recovery.BackupError): recovery.backup(self.source, self.copy, max_bytes=4096)
        with patch.object(recovery.time, "monotonic", side_effect=[0, 2]):
            with self.assertRaises(recovery.BackupError): recovery.Budget(seconds=1).check()

    def test_failure_retains_partial_output_and_never_leaks_exception(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(recovery, "inspect_database", side_effect=sqlite3.DatabaseError("PRIVATE_CANARY")), redirect_stdout(stdout), redirect_stderr(stderr):
            code = recovery.main(["backup", "--source", str(self.source), "--destination", str(self.copy)])
        self.assertEqual(code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn("PRIVATE_CANARY", stderr.getvalue())
        self.assertTrue(self.copy.exists())
        self.assertFalse((self.copy / recovery.MANIFEST).exists())
        with self.assertRaises(recovery.BackupError): recovery.verify(self.copy)

    def test_source_hardlink_and_symlink_rejected(self):
        target = self.root / "linked-db"
        os.link(self.source / "cases.sqlite", target)
        with self.assertRaises(recovery.BackupError): recovery.backup(self.source, self.copy)
        target.unlink()
        # Windows CI may not grant symlink privileges; exercise link detection too.
        info = Mock(st_mode=stat.S_IFLNK | 0o777, st_file_attributes=0)
        with patch.object(Path, "lstat", return_value=info):
            with self.assertRaises(recovery.BackupError): recovery.checked_path(self.source)

    def test_busy_database_fails_without_hanging_or_success_report(self):
        with closing(sqlite3.connect(self.source / "packages.sqlite3")) as writer:
            writer.execute("BEGIN EXCLUSIVE")
            with self.assertRaises(sqlite3.OperationalError):
                recovery.backup(self.source, self.copy, seconds=1)
            writer.rollback()
        self.assertFalse(self.copy.exists())

    def test_restore_rechecks_bytes_after_source_changes(self):
        recovery.backup(self.source, self.copy)
        original_verify = recovery.verify
        def changed(*args, **kwargs):
            report = original_verify(*args, **kwargs)
            path = self.copy / "cases.sqlite"
            with path.open("ab") as stream: stream.write(b"changed")
            return report
        with patch.object(recovery, "verify", side_effect=changed):
            with self.assertRaises(recovery.BackupError): recovery.restore(self.copy, self.restored)
        self.assertTrue(self.restored.exists())
        self.assertFalse((self.restored / recovery.MANIFEST).exists())

    def test_cli_standard_library_only_exit_codes_and_safe_output(self):
        script = str(ROOT / "deploy/server/portal-backup.py")
        def run(*args):
            return subprocess.run([sys.executable, "-S", script, *args], capture_output=True, text=True, timeout=15)
        result = run("backup", "--source", str(self.source), "--destination", str(self.copy))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)["production_restored"])
        self.assertNotIn("Synthetic review", result.stdout)
        self.assertEqual(run("verify", "--source", str(self.copy)).returncode, 0)
        self.assertEqual(run("restore", "--source", str(self.copy), "--destination", str(self.restored)).returncode, 0)
        self.assertEqual(run("restore", "--source", str(self.copy), "--destination", str(self.restored)).returncode, 1)
        self.assertEqual(run("backup", "--source", str(self.source)).returncode, 2)
        if os.name != "nt":
            self.assertEqual(self.copy.stat().st_mode & 0o777, 0o700)
            for path in self.copy.iterdir(): self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
