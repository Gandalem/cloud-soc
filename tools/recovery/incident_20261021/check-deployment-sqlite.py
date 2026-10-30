#!/usr/bin/env python3
"""Inspect upgrade receipts and verify disposable SQLite backups; no apply/recovery."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time

REPO = Path('/home/lyn/Documents/Codex/2026-10-21/cd-ubuntu-school-web-agent/outputs/cloud-soc')
STATE = Path('/home/lyn/cloud-soc/state/server')
sys.path.insert(0,str(REPO/'src'))
from cloud_soc.deployment.host import databases

if os.geteuid() != 0:
    raise SystemExit('Run with sudo python3.')

runtime = STATE/'runtime'
print(json.dumps({'pending_upgrade':(runtime/'pending.json').exists()}),flush=True)
runs = sorted((runtime/'upgrades').glob('*')) if (runtime/'upgrades').exists() else []
for run in runs[-2:]:
    row = {'run':run.name, 'files':[name for name in ('plan.json','recovery.json','preservation-before.json',
           'applied.json','failed.json','recovered.json') if (run/name).exists()]}
    for phase in ('online','stopped'):
        row[phase+'_backup_count'] = sum(1 for p in (run/phase).rglob('*') if p.suffix in ('.sqlite','.sqlite3'))
    if (run/'failed.json').exists():
        failed = json.loads((run/'failed.json').read_text())
        row['failure'] = {key:failed.get(key) for key in ('state','error_type','old_execution_restored','databases_rewound')}
    print(json.dumps(row),flush=True)

result = subprocess.run(['docker','--host','unix:///var/run/docker.sock','ps','-a','--format','{{.Names}} {{.State}}'],
                        text=True,capture_output=True,timeout=20)
print(json.dumps({'containers':[line for line in result.stdout.splitlines() if line.startswith('cloud-soc-central-')]}),flush=True)

for source in databases(STATE):
    stage = 'open_readonly'
    started = time.monotonic()
    row = {'database':source.relative_to(STATE).as_posix()}
    try:
        with tempfile.TemporaryDirectory(prefix='soc-sqlite-check-') as folder:
            target = Path(folder)/'copy.sqlite'
            with closing(sqlite3.connect(source.as_uri()+'?mode=ro',uri=True,timeout=2)) as original, closing(sqlite3.connect(target,timeout=2)) as copy:
                stage = 'online_backup'
                def progress(*_):
                    if time.monotonic()-started > 15:
                        raise TimeoutError('backup_deadline')
                original.backup(copy,pages=256,progress=progress,sleep=.01)
                stage = 'standalone_journal'
                copy.execute('pragma journal_mode=delete').fetchall()
                stage = 'integrity'
                row['integrity_ok'] = copy.execute('pragma integrity_check').fetchall() == [('ok',)]
                stage = 'restore'
                with closing(sqlite3.connect(':memory:')) as restored:
                    copy.backup(restored)
                    row['restore_ok'] = restored.execute('pragma integrity_check').fetchall() == [('ok',)]
        row['status'] = 'ok'
    except Exception as error:
        text = str(error).lower()
        reasons = {'database is locked':'database_locked','database table is locked':'table_locked',
                   'database disk image is malformed':'database_malformed','unable to open database file':'database_open_failed',
                   'no such table':'schema_table_missing','disk i/o error':'disk_io_error',
                   'attempt to write a readonly database':'readonly_write_attempt'}
        row.update(status='failed',stage=stage,exception=type(error).__name__,
                   sqlite_error=getattr(error,'sqlite_errorname',None),
                   reason=next((code for phrase,code in reasons.items() if phrase in text),'unclassified_sqlite_error'))
    print(json.dumps(row),flush=True)
print('Read-only diagnosis completed. No deployment or recovery was performed.')
