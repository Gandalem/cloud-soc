"""Local, bounded SQLite backups. Never restore over an existing path."""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import sys
import time


SCHEMAS = {
    "packages.sqlite3": {
        "packages": "id name os spec filename sha256 created_at archive".split(),
        "issued_keys": "id package_id created_at".split(),
    },
    "cases.sqlite": {
        "cases": "id title organization priority status owner verdict version created_at updated_at".split(),
        "case_alerts": "alert_id case_id linked_at snapshot".split(),
        "case_history": "seq case_id actor at version action changes note".split(),
        "case_requests": "token actor fingerprint response".split(),
    },
}
MAX_BYTES = 1024 ** 3
MANIFEST = "manifest.json"


class BackupError(Exception):
    """Static messages only: database content and filesystem paths are private."""


def checked_path(value, *, directory=False, new=False):
    path = Path(value).absolute()
    if ".." in path.parts:
        raise BackupError("Parent traversal is not allowed.")
    for entry in (*reversed(path.parents), path):
        try:
            info = entry.lstat()
        except FileNotFoundError:
            if entry == path and new:
                return path
            raise BackupError("Required path does not exist.") from None
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise BackupError("Symlinks and reparse points are not allowed.")
        if entry != path and not stat.S_ISDIR(info.st_mode):
            raise BackupError("Parent must be a directory.")
    if new:
        raise BackupError("Destination already exists; nothing was overwritten.")
    if directory:
        if not path.is_dir():
            raise BackupError("Expected a directory.")
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise BackupError("Expected a regular file with one link.")
    return path


class Budget:
    def __init__(self, seconds=60, max_bytes=MAX_BYTES):
        if type(seconds) is not int or not 1 <= seconds <= 600 or type(max_bytes) is not int or max_bytes < 4096:
            raise BackupError("Invalid time or size limit.")
        self.deadline = time.monotonic() + seconds
        self.max_bytes = max_bytes

    def check(self, size=0):
        if time.monotonic() >= self.deadline:
            raise BackupError("Time limit exceeded; incomplete output is not a backup.")
        if size > self.max_bytes:
            raise BackupError("Database size limit exceeded.")


@contextmanager
def read_db(path, budget):
    checked_path(path)
    # No immutable=1: committed WAL pages must be included in a live backup.
    db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=0.1)
    try:
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA query_only=ON")
        db.set_progress_handler(lambda: int(time.monotonic() >= budget.deadline), 1000)
        yield db
    finally:
        db.close()


def inspect_database(path, name, budget):
    budget.check(path.stat().st_size)
    with read_db(path, budget) as db:
        db.execute("BEGIN")
        objects = db.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
        if any(kind not in ("table", "index") for kind, _ in objects):
            raise BackupError("Unexpected database schema objects.")
        if {name for kind, name in objects if kind == "table"} != set(SCHEMAS[name]):
            raise BackupError("Unsupported database schema; use the matching application version.")
        counts = {}
        for table, columns in SCHEMAS[name].items():
            if [row[1] for row in db.execute(f'PRAGMA table_info("{table}")')] != columns:
                raise BackupError("Unsupported database columns.")
            counts[table] = db.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]
        if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)] or db.execute("PRAGMA foreign_key_check").fetchone():
            raise BackupError("Database integrity check failed.")
    budget.check()
    return counts


def digest(path, budget):
    checked_path(path)
    result, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            budget.check(size)
            result.update(chunk)
    return size, result.hexdigest()


def exclusive_file(path):
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")


def sync_dir(path):
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def publish(directory, report):
    pending = directory / "manifest.incomplete"
    with exclusive_file(pending) as stream:
        stream.write(json.dumps(report, ensure_ascii=True, indent=2).encode())
        stream.flush()
        os.fsync(stream.fileno())
    pending.rename(directory / MANIFEST)
    sync_dir(directory)


def destination(value, source, required_bytes):
    path = checked_path(value, new=True)
    if source == path or source in path.parents or path in source.parents:
        raise BackupError("Source and destination must be separate directories.")
    if shutil.disk_usage(path.parent).free < required_bytes + 16 * 1024 * 1024:
        raise BackupError("Insufficient destination disk space.")
    path.mkdir(mode=0o700)
    sync_dir(path.parent)
    return path


def backup(source, target, *, seconds=60, max_bytes=MAX_BYTES):
    budget = Budget(seconds, max_bytes)
    source = checked_path(source, directory=True)
    names = ["packages.sqlite3"]
    checked_path(source / names[0])
    if os.path.lexists(source / "cases.sqlite"):
        names.append("cases.sqlite")
    sizes = []
    for name in names:
        path = checked_path(source / name)
        # Reject linked sidecars too; SQLite may read them even with mode=ro.
        for suffix in ("-wal", "-shm", "-journal"):
            if os.path.lexists(str(path) + suffix):
                checked_path(str(path) + suffix)
        with read_db(path, budget) as db:
            size = db.execute("PRAGMA page_count").fetchone()[0] * db.execute("PRAGMA page_size").fetchone()[0]
        budget.check(size)
        sizes.append(size)
    target = destination(target, source, sum(sizes) * 2)
    report = {"format": 1, "kind": "portal-sqlite-backup", "created_at": datetime.now(timezone.utc).isoformat(),
              "consistency": "per_database", "missing": sorted(set(SCHEMAS) - set(names)), "files": []}
    for name in names:
        output = target / name
        with exclusive_file(output):
            pass
        with read_db(source / name, budget) as src:
            page_size = src.execute("PRAGMA page_size").fetchone()[0]
            dst = sqlite3.connect(output, timeout=0.1)
            try:
                src.backup(dst, pages=128, sleep=0.05,
                           progress=lambda status, remaining, total: budget.check(total * page_size))
                # Make a self-contained file, not a backup dependent on WAL sidecars.
                if dst.execute("PRAGMA journal_mode=DELETE").fetchone()[0] != "delete":
                    raise BackupError("Could not finalize standalone backup.")
            finally:
                dst.close()
        with output.open("r+b") as stream:
            os.fsync(stream.fileno())
        counts = inspect_database(output, name, budget)
        size, sha256 = digest(output, budget)
        report["files"].append({"name": name, "bytes": size, "sha256": sha256, "counts": counts})
    budget.check()
    publish(target, report)
    return report


def verify(source, *, seconds=60, max_bytes=MAX_BYTES):
    budget = Budget(seconds, max_bytes)
    source = checked_path(source, directory=True)
    manifest = checked_path(source / MANIFEST)
    if manifest.stat().st_size > 16384:
        raise BackupError("Invalid backup manifest size.")
    try:
        report = json.loads(manifest.read_text(encoding="utf-8"))
        if (set(report) != {"format", "kind", "created_at", "consistency", "missing", "files"}
                or type(report["format"]) is not int or report["format"] != 1
                or report["kind"] != "portal-sqlite-backup" or report["consistency"] != "per_database"
                or not isinstance(report["created_at"], str)
                or datetime.fromisoformat(report["created_at"]).tzinfo is None
                or not isinstance(report["files"], list) or not 1 <= len(report["files"]) <= 2):
            raise ValueError
        names = [entry["name"] for entry in report["files"]]
        if (len(names) != len(set(names)) or "packages.sqlite3" not in names or set(names) - set(SCHEMAS)
                or report["missing"] != sorted(set(SCHEMAS) - set(names))):
            raise ValueError
        if {path.name for path in source.iterdir()} != set(names) | {MANIFEST}:
            raise ValueError
        for entry in report["files"]:
            if (set(entry) != {"name", "bytes", "sha256", "counts"} or type(entry["bytes"]) is not int
                    or not 4096 <= entry["bytes"] <= max_bytes or not re.fullmatch("[0-9a-f]{64}", entry["sha256"])
                    or set(entry["counts"]) != set(SCHEMAS[entry["name"]])
                    or any(type(n) is not int or n < 0 for n in entry["counts"].values())):
                raise ValueError
    except (ValueError, TypeError, KeyError, AttributeError):
        raise BackupError("Invalid or incomplete backup manifest.") from None
    for entry in report["files"]:
        path = checked_path(source / entry["name"])
        if digest(path, budget) != (entry["bytes"], entry["sha256"]):
            raise BackupError("Backup hash or size mismatch.")
        if inspect_database(path, entry["name"], budget) != entry["counts"]:
            raise BackupError("Backup table counts mismatch.")
    return report


def restore(source, target, *, seconds=60, max_bytes=MAX_BYTES):
    # A restore is only a drill/staging directory, never an in-place promotion.
    budget = Budget(seconds, max_bytes)
    source = checked_path(source, directory=True)
    report = verify(source, seconds=seconds, max_bytes=max_bytes)
    budget.check()
    target = destination(target, source, sum(entry["bytes"] for entry in report["files"]))
    for entry in report["files"]:
        path = checked_path(source / entry["name"])
        with path.open("rb") as src, exclusive_file(target / entry["name"]) as dst:
            size = 0
            while chunk := src.read(1024 * 1024):
                size += len(chunk)
                budget.check(size)
                dst.write(chunk)
            dst.flush()
            os.fsync(dst.fileno())
        if digest(target / entry["name"], budget) != (entry["bytes"], entry["sha256"]):
            raise BackupError("Backup changed during restore.")
        if inspect_database(target / entry["name"], entry["name"], budget) != entry["counts"]:
            raise BackupError("Restored database validation failed.")
    budget.check()
    publish(target, report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Local portal DB backup/verify/isolated restore; no network or overwrite")
    parser.add_argument("command", choices=("backup", "verify", "restore"))
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--timeout-seconds", default=60, type=int)
    args = parser.parse_args(argv)
    if (args.command == "verify") == bool(args.destination):
        parser.error("backup/restore require --destination; verify does not accept it")
    try:
        options = {"seconds": args.timeout_seconds}
        if args.command == "verify":
            report = verify(args.source, **options)
        else:
            report = {"backup": backup, "restore": restore}[args.command](args.source, args.destination, **options)
        print(json.dumps({"status": "ok", "operation": args.command, "consistency": report["consistency"],
                          "databases": [{"name": entry["name"], "counts": entry["counts"]} for entry in report["files"]],
                          "missing": report["missing"], "production_restored": False}))
        return 0
    except (BackupError, OSError, sqlite3.Error):
        print("Portal DB operation failed. Check paths, permissions, limits and integrity. "
              "Partial output is retained; do not use it. No existing destination was overwritten.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
