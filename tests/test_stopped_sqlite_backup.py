"""Real abruptly terminated SQLite writers; restore committed data without touching originals."""
from contextlib import closing
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest
from cloud_soc.deployment.host import backup_stopped_database, portal_rows


def journal_files(source):
    return {p.name:p.read_bytes() for p in source.parent.glob(source.name+'*') if p.is_file()}


def make_hot_rollback(source):
    with closing(sqlite3.connect(source)) as db:
        db.execute('create table samples(id integer primary key,value text)')
        db.executemany('insert into samples(value) values(?)', [('committed-'+'x'*3000,)]*100)
        db.commit()
    result = subprocess.run([sys.executable,'-c',
        "import sqlite3,sys,os;db=sqlite3.connect(sys.argv[1]);"
        "db.execute('pragma cache_size=5');db.execute('begin immediate');"
        "db.execute(\"update samples set value='not-committed'\");os._exit(0)",str(source)])
    assert result.returncode == 0
    assert Path(str(source)+'-journal').stat().st_size > 512


def test_hot_rollback_journal_recovers_only_in_staged_copy(tmp_path):
    source = tmp_path/'source.sqlite';make_hot_rollback(source)
    original = journal_files(source)
    # Reproduce the stopped deployment's read-only opening failure.
    with closing(sqlite3.connect(source.as_uri()+'?mode=ro',uri=True)) as db:
        with pytest.raises(sqlite3.OperationalError):
            db.execute('select count(*) from samples').fetchall()
    target = tmp_path/'backup.sqlite'
    backup_stopped_database(source,target)
    assert journal_files(source) == original
    with closing(sqlite3.connect(target.as_uri()+'?mode=ro',uri=True)) as db:
        assert db.execute('select count(*) from samples').fetchone() == (100,)
        assert db.execute("select count(*) from samples where value like 'committed-%'").fetchone() == (100,)
        assert db.execute('pragma journal_mode').fetchone() == ('delete',)
    assert not list(tmp_path.glob('.stopped-sqlite-*'))


def test_unclean_wal_shutdown_preserves_latest_commit_and_original_files(tmp_path):
    source = tmp_path/'wal.sqlite'
    result = subprocess.run([sys.executable,'-c',
        "import sqlite3,sys,os;db=sqlite3.connect(sys.argv[1]);"
        "db.execute('pragma journal_mode=wal');db.execute('pragma wal_autocheckpoint=0');"
        "db.execute('create table samples(value integer)');db.commit();"
        "db.execute('insert into samples values(731)');db.commit();os._exit(0)",str(source)])
    assert result.returncode == 0
    assert Path(str(source)+'-wal').stat().st_size > 0
    original = journal_files(source)
    target = tmp_path/'backup.sqlite'
    backup_stopped_database(source,target)
    assert journal_files(source) == original
    with closing(sqlite3.connect(target)) as db:
        assert db.execute('select value from samples').fetchall() == [(731,)]
        assert db.execute('pragma integrity_check').fetchall() == [('ok',)]


def test_stopped_portal_preservation_handles_hot_journal_without_live_recovery(tmp_path):
    portal = tmp_path/'portal';portal.mkdir()
    source = portal/'dashboards.sqlite';make_hot_rollback(source)
    before = journal_files(source)
    rows = portal_rows(tmp_path,stopped=True)
    assert len(rows['dashboards.sqlite']) == 101  # Schema plus committed records only.
    assert journal_files(source) == before


def test_backup_refuses_existing_destination(tmp_path):
    source = tmp_path/'source.sqlite';target=tmp_path/'copy.sqlite'
    with closing(sqlite3.connect(source)) as db:
        db.execute('create table sample(id integer)');db.commit()
    target.write_bytes(b'original-backup')
    with pytest.raises(ValueError,match='already exists'):
        backup_stopped_database(source,target)
    assert target.read_bytes() == b'original-backup'
